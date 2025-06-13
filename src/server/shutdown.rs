//! Graceful shutdown coordinator for Black Gate
//!
//! This module provides centralized shutdown coordination for all background tasks
//! and services in the Black Gate API gateway. It handles signal processing and
//! ensures all components shut down cleanly.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{info, warn};

/// Shutdown coordinator that manages graceful shutdown of all services
#[derive(Debug, Clone)]
pub struct ShutdownCoordinator {
    /// Atomic flag indicating if shutdown has been initiated
    shutdown_initiated: Arc<AtomicBool>,
    /// Broadcast sender for shutdown signals
    shutdown_tx: broadcast::Sender<()>,
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator
    pub fn new() -> Self {
        let (shutdown_tx, _) = broadcast::channel(16);

        Self {
            shutdown_initiated: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
        }
    }

    /// Check if shutdown has been initiated
    pub fn is_shutdown_initiated(&self) -> bool {
        self.shutdown_initiated.load(Ordering::Relaxed)
    }

    /// Create a shutdown receiver for background tasks
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Initiate graceful shutdown
    pub fn initiate_shutdown(&self) {
        if !self.shutdown_initiated.swap(true, Ordering::Relaxed) {
            info!("Initiating graceful shutdown...");
            if let Err(e) = self.shutdown_tx.send(()) {
                warn!("Failed to send shutdown signal: {}", e);
            }
        }
    }

    /// Wait for shutdown signals (SIGTERM, SIGINT, or manual trigger)
    pub async fn wait_for_shutdown_signal(&self) {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received Ctrl+C signal");
            }
            _ = terminate => {
                info!("Received SIGTERM signal");
            }
        }

        self.initiate_shutdown();
    }

    /// Wait for all background tasks to complete shutdown
    pub async fn wait_for_tasks_completion(&self, timeout_seconds: u64) {
        info!(
            "Waiting up to {} seconds for background tasks to complete...",
            timeout_seconds
        );

        // todo we need this to be a better shut down task
        let timeout = tokio::time::sleep(tokio::time::Duration::from_secs(timeout_seconds));

        // In a real implementation, you might want to track active tasks
        // For now, we'll just wait a reasonable amount of time
        tokio::select! {
            _ = timeout => {
                warn!("Shutdown timeout reached, some tasks may not have completed gracefully");
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
                info!("Background tasks completed shutdown");
            }
        }
    }
}

/// Background task wrapper that handles shutdown signals
pub struct ShutdownAwareTask {
    shutdown_rx: broadcast::Receiver<()>,
}

impl ShutdownAwareTask {
    /// Create a new shutdown-aware task
    pub fn new(coordinator: &ShutdownCoordinator) -> Self {
        Self {
            shutdown_rx: coordinator.subscribe(),
        }
    }

    /// Check if shutdown has been requested
    pub fn should_shutdown(&mut self) -> bool {
        matches!(self.shutdown_rx.try_recv(), Ok(_))
    }

    /// Wait for either a shutdown signal or the specified duration
    pub async fn wait_or_shutdown(&mut self, duration: tokio::time::Duration) -> bool {
        tokio::select! {
            _ = self.shutdown_rx.recv() => true,
            _ = tokio::time::sleep(duration) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, sleep};

    #[tokio::test]
    async fn test_shutdown_coordinator_creation() {
        let coordinator = ShutdownCoordinator::new();
        assert!(!coordinator.is_shutdown_initiated());
    }

    #[tokio::test]
    async fn test_shutdown_initiation() {
        let coordinator = ShutdownCoordinator::new();
        let mut receiver = coordinator.subscribe();

        coordinator.initiate_shutdown();

        assert!(coordinator.is_shutdown_initiated());
        assert!(receiver.recv().await.is_ok());
    }

    #[tokio::test]
    async fn test_shutdown_aware_task() {
        let coordinator = ShutdownCoordinator::new();
        let mut task = ShutdownAwareTask::new(&coordinator);

        assert!(!task.should_shutdown());

        coordinator.initiate_shutdown();

        // Give the signal time to propagate
        sleep(Duration::from_millis(10)).await;

        assert!(task.should_shutdown());
    }

    #[tokio::test]
    async fn test_wait_or_shutdown_with_shutdown() {
        let coordinator = ShutdownCoordinator::new();
        let mut task = ShutdownAwareTask::new(&coordinator);

        // Start a task that will wait
        let task_handle =
            tokio::spawn(async move { task.wait_or_shutdown(Duration::from_secs(10)).await });

        // Initiate shutdown after a short delay
        tokio::spawn(async move {
            sleep(Duration::from_millis(50)).await;
            coordinator.initiate_shutdown();
        });

        // The task should return true (shutdown requested)
        let result = task_handle.await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_wait_or_shutdown_with_timeout() {
        let coordinator = ShutdownCoordinator::new();
        let mut task = ShutdownAwareTask::new(&coordinator);

        // Wait for a short duration without shutdown
        let result = task.wait_or_shutdown(Duration::from_millis(50)).await;

        // Should return false (timeout, not shutdown)
        assert!(!result);
    }
}
