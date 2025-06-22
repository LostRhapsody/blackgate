//! Server module for the Black Gate API gateway.
//!
//! This module contains the core server functionality for running the Black Gate API gateway,
//! including standard server startup, graceful shutdown support, and OAuth testing capabilities.
//!
//! # Features
//!
//! - **Standard Server**: Basic server startup with blocking operation
//! - **Graceful Shutdown**: Server with shutdown signal handling for clean termination
//! - **OAuth Testing**: Combined server setup with OAuth test server for development/testing
//!
//! # Server Configuration
//!
//! All servers bind to `0.0.0.0:3000` by default and include:
//! - SQLite database connection pool
//! - OAuth token caching with thread-safe access
//! - Rate limiting functionality
//! - Web dashboard interface at `/dashboard`
//!
//! # Usage
//!
//! ```rust
//! // Basic server startup
//! start_server(pool).await;
//!
//! // Server with graceful shutdown
//! let (tx, rx) = tokio::sync::oneshot::channel();
//! start_server_with_shutdown(pool, rx).await;
//!
//! // OAuth testing environment
//! start_oauth_test_server(pool, 8080).await;
//! ```

pub mod shutdown;

use self::shutdown::ShutdownCoordinator;
use crate::AppState;
use crate::auth::oauth::OAuthTokenCache;
use crate::cache::ResponseCache;
use crate::database::backup::BackupManager;
use crate::database::queries::get_setting_by_key;
use crate::env::AppConfig;
use crate::health::HealthChecker;
use crate::logging::errors::cleanup_old_error_logs;
use crate::rate_limiter::RateLimiter;
use crate::routing::router::create_router;
use crate::security::SecretManager;
use sqlx::{Row, sqlite::SqlitePool};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Start the API gateway server with graceful shutdown support
pub async fn start_server(pool: SqlitePool, config: AppConfig) {
    let shutdown_coordinator = Arc::new(ShutdownCoordinator::new());

    let token_cache = Arc::new(Mutex::new(OAuthTokenCache::new()));
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));
    let route_cache = Arc::new(RwLock::new(HashMap::new()));
    let http_client = reqwest::Client::new();

    // Create shared health checker
    let health_checker = Arc::new(HealthChecker::new(Arc::new(pool.clone())));

    // Create a shared response cache
    let default_ttl: u64 = get_response_cache_default_ttl(&pool);
    let response_cache = Arc::new(ResponseCache::new(default_ttl));

    // Initialize secret manager if Infisical is configured
    let secret_manager =
        if let (Ok(url), Ok(client_id), Ok(client_secret), Ok(project_id), Ok(environment)) = (
            std::env::var("INFISICAL_URL"),
            std::env::var("INFISICAL_CLIENT_ID"),
            std::env::var("INFISICAL_CLIENT_SECRET"),
            std::env::var("INFISICAL_PROJECT_ID"),
            std::env::var("INFISICAL_ENVIRONMENT"),
        ) {
            match SecretManager::new(url, client_id, client_secret, project_id, environment).await {
                Ok(manager) => {
                    info!("Infisical secret manager initialized successfully");
                    Some(Arc::new(manager))
                }
                Err(e) => {
                    warn!("Failed to initialize Infisical secret manager: {}", e);
                    None
                }
            }
        } else {
            info!("Infisical not configured, secret management disabled");
            None
        };

    let app_state = AppState {
        db: pool.clone(),
        token_cache,
        rate_limiter,
        route_cache,
        http_client,
        health_checker: health_checker.clone(),
        response_cache,
        secret_manager,
        config: config.clone(),
    };

    let app = create_router(app_state);

    // Start background services with shutdown awareness
    start_background_services(
        Arc::new(pool.clone()),
        default_ttl,
        shutdown_coordinator.clone(),
    )
    .await;

    let listener = tokio::net::TcpListener::bind(config.bind_address)
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    info!("Black Gate running on http://{}", addr);
    info!("Web interface: http://{}:{}/", config.host, config.port);

    // Start the server with graceful shutdown
    let shutdown_for_server = shutdown_coordinator.clone();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        shutdown_for_server.wait_for_shutdown_signal().await;
    });

    if let Err(err) = server.await {
        error!("Black Gate server error: {}", err);
    }

    // Wait for background tasks to complete
    shutdown_coordinator.wait_for_tasks_completion(10).await;
    info!("Black Gate shutdown complete");
}

/// Start the API gateway server with graceful shutdown support, used for oAuth testing
pub async fn start_server_with_shutdown(
    pool: SqlitePool,
    config: AppConfig,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) {
    let token_cache = Arc::new(Mutex::new(OAuthTokenCache::new()));
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));
    let route_cache = Arc::new(RwLock::new(HashMap::new()));
    let http_client = reqwest::Client::new();

    // Create shared health checker
    let health_checker = Arc::new(HealthChecker::new(Arc::new(pool.clone())));

    // Create a shared response cache
    let default_ttl: u64 = get_response_cache_default_ttl(&pool);
    let response_cache = Arc::new(ResponseCache::new(default_ttl));

    // Initialize secret manager if Infisical is configured
    let secret_manager =
        if let (Ok(url), Ok(client_id), Ok(client_secret), Ok(project_id), Ok(environment)) = (
            std::env::var("INFISICAL_URL"),
            std::env::var("INFISICAL_CLIENT_ID"),
            std::env::var("INFISICAL_CLIENT_SECRET"),
            std::env::var("INFISICAL_PROJECT_ID"),
            std::env::var("INFISICAL_ENVIRONMENT"),
        ) {
            match SecretManager::new(url, client_id, client_secret, project_id, environment).await {
                Ok(manager) => {
                    info!("Infisical secret manager initialized successfully");
                    Some(Arc::new(manager))
                }
                Err(e) => {
                    warn!("Failed to initialize Infisical secret manager: {}", e);
                    None
                }
            }
        } else {
            info!("Infisical not configured, secret management disabled");
            None
        };

    let app_state = AppState {
        db: pool.clone(),
        token_cache,
        rate_limiter,
        route_cache,
        http_client,
        health_checker: health_checker.clone(),
        response_cache,
        secret_manager,
        config: config.clone(),
    };

    let app = create_router(app_state);

    // Create a new health checker for the background service Start the health check background service
    let background_health_checker = HealthChecker::new(Arc::new(pool.clone()));
    background_health_checker.start_background_checks();

    // Start the database backup background service
    let backup_manager = BackupManager::new(Arc::new(pool.clone()));
    backup_manager.start_background_backups();

    // Start the response cache background service
    // TODO move the tokio spawn into the response cache new function
    // Create a new response cache for the background service
    let background_response_cache = Arc::new(ResponseCache::new(default_ttl));

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60)); // Run every minute
        loop {
            interval.tick().await;
            background_response_cache.cleanup().await;
        }
    });

    let listener = tokio::net::TcpListener::bind(config.bind_address)
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    info!("Black Gate running on http://{}", addr);

    let server = axum::serve(listener, app).with_graceful_shutdown(async {
        shutdown_rx.await.ok();
        info!("Black Gate server shutting down...");
    });

    if let Err(err) = server.await {
        error!("Black Gate server error: {}", err);
    }
    info!("Black Gate server shutdown complete");
}

/// Start the OAuth test server and the main Black Gate server, used for oAuth testing
pub async fn start_oauth_test_server(pool: SqlitePool, config: AppConfig, _port: u16) {
    let (_addr, oauth_shutdown_tx) = crate::oauth_test_server::spawn_oauth_test_server().await;

    // Create shutdown channel for the main server
    let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();

    // Start the main Black Gate server with graceful shutdown
    let server_pool = pool.clone();
    let server_config = config.clone();
    let server_handle = tokio::spawn(async move {
        start_server_with_shutdown(server_pool, server_config, server_shutdown_rx).await;
    });

    // Wait for Ctrl+C signal
    info!("Both servers are running. Press Ctrl+C to shutdown...");
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            info!("Received shutdown signal, stopping servers...");

            // Shutdown both servers gracefully
            let _ = oauth_shutdown_tx.send(());
            let _ = server_shutdown_tx.send(());

            // Wait for the server to shut down properly
            let _ = server_handle.await;

            info!("All servers shutdown complete");
        }
        Err(err) => {
            error!("Failed to listen for shutdown signal: {}", err);
        }
    }
}

fn get_response_cache_default_ttl(pool: &SqlitePool) -> u64 {
    let default_ttl: u64 = match get_setting_by_key(pool, "response_cache_default_ttl") {
        Ok(Some(row)) => {
            let value_str: String = row.get("value");
            value_str.parse().unwrap_or_else(|e| {
                warn!(
                    "Failed to parse response_cache_default_ttl setting '{}': {}, using default",
                    value_str, e
                );
                crate::cache::DEFAULT_RESPONSE_CACHE_TTL
            })
        }
        Ok(None) => {
            info!(
                "No response_cache_default_ttl setting found, using default: {}",
                crate::cache::DEFAULT_RESPONSE_CACHE_TTL
            );
            crate::cache::DEFAULT_RESPONSE_CACHE_TTL
        }
        Err(e) => {
            warn!(
                "Failed to fetch response_cache_default_ttl setting, using default: {}",
                e
            );
            crate::cache::DEFAULT_RESPONSE_CACHE_TTL
        }
    };
    default_ttl
}

/// Start all background services with shutdown awareness
async fn start_background_services(
    pool: Arc<SqlitePool>,
    response_cache_ttl: u64,
    shutdown_coordinator: Arc<ShutdownCoordinator>,
) {
    // Start health check background service
    let health_pool = pool.clone();
    let health_shutdown = shutdown_coordinator.clone();
    tokio::spawn(async move {
        let health_checker = HealthChecker::new(health_pool);
        health_checker
            .start_background_checks_with_shutdown(health_shutdown)
            .await;
    });

    // Start database backup background service
    let backup_pool = pool.clone();
    let backup_shutdown = shutdown_coordinator.clone();
    tokio::spawn(async move {
        let backup_manager = BackupManager::new(backup_pool);
        backup_manager
            .start_background_backups_with_shutdown(backup_shutdown)
            .await;
    });

    // Start response cache cleanup background service
    let cache_shutdown = shutdown_coordinator.clone();
    tokio::spawn(async move {
        let response_cache = Arc::new(ResponseCache::new(response_cache_ttl));
        let mut shutdown_task = shutdown::ShutdownAwareTask::new(&cache_shutdown);

        info!("Starting response cache cleanup background service");
        loop {
            // Wait for 60 seconds or shutdown signal
            if shutdown_task
                .wait_or_shutdown(tokio::time::Duration::from_secs(60))
                .await
            {
                info!("Response cache cleanup service shutting down");
                break;
            }

            response_cache.cleanup().await;
        }
    });

    // Start error log cleanup background service
    let error_pool = pool.clone();
    let error_shutdown = shutdown_coordinator.clone();
    tokio::spawn(async move {
        let mut shutdown_task = shutdown::ShutdownAwareTask::new(&error_shutdown);

        info!("Starting error log cleanup background service");
        loop {
            // Wait for 1 hour or shutdown signal
            if shutdown_task
                .wait_or_shutdown(tokio::time::Duration::from_secs(3600))
                .await
            {
                info!("Error log cleanup service shutting down");
                break;
            }

            // Get retention days from settings or use default
            let retention_days = match get_setting_by_key(&error_pool, "error_log_retention_days") {
                Ok(Some(row)) => {
                    let value_str: String = row.get("value");
                    value_str.parse::<u32>().unwrap_or_else(|e| {
                        warn!(
                            "Failed to parse error_log_retention_days setting '{}': {}, using default 7",
                            value_str, e
                        );
                        7
                    })
                }
                Ok(None) => {
                    info!("No error_log_retention_days setting found, using default: 7");
                    7
                }
                Err(e) => {
                    warn!(
                        "Failed to fetch error_log_retention_days setting, using default 7: {}",
                        e
                    );
                    7
                }
            };

            // Clean up old error logs
            match cleanup_old_error_logs(&error_pool, retention_days).await {
                Ok(deleted_count) => {
                    if deleted_count > 0 {
                        info!(
                            "Cleaned up {} old error log entries (retention: {} days)",
                            deleted_count, retention_days
                        );
                    }
                }
                Err(e) => {
                    error!("Failed to cleanup old error logs: {}", e);
                }
            }
        }
    });
}
