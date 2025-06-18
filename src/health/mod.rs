//! # Health Check Module
//!
//! This module provides health checking functionality for routes in the Blackgate API Gateway.
//! It monitors the health of upstream services by periodically checking configured health endpoints
//! or falling back to HEAD requests.
//!
//! ## Features
//!
//! - **Periodic Health Checks**: Runs health checks every 60 seconds in a background thread, or whatever DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS is set to
//! - **Multiple Check Methods**: Supports dedicated health endpoints or fallback HEAD requests
//! - **Health Status Tracking**: Records health status in the database for monitoring
//! - **Intelligent Fallback**: Automatically flags routes as "Health Check Unavailable" when appropriate
//! - **Non-blocking Operation**: Runs in a separate thread to avoid blocking main application
//!
//! ## Health Check Strategy
//!
//! 1. **Primary Method**: Use dedicated health endpoint if configured in route
//! 2. **Fallback Method**: Use HEAD request to the main upstream URL
//! 3. **Failure Handling**: Mark as "Health Check Unavailable" if HEAD returns 405 (Method Not Allowed)
//!
//! ## Usage
//!
//! The health checker starts automatically when the server starts and runs continuously
//! in the background. Health status can be monitored through the web interface or CLI.

use crate::database::queries;
use crate::server::shutdown::{ShutdownAwareTask, ShutdownCoordinator};
use chrono::Utc;
use reqwest::Client;
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, error, info, warn};
///////////////////////////////////////////////////////////////////////////////
//****                      Health Status Cache                          ****//
///////////////////////////////////////////////////////////////////////////////

/// Cached health status entry with timestamp
#[derive(Debug, Clone)]
pub struct CachedHealthStatus {
    pub status: HealthStatus,
    pub timestamp: i64, // Unix timestamp when cached (chrono::Utc::now().timestamp())
}

/// Shared health status cache
pub type HealthStatusCache = Arc<RwLock<HashMap<String, CachedHealthStatus>>>;

/// Cache TTL in seconds (health status considered stale after this time)
const HEALTH_CACHE_TTL_SECONDS: i64 = 90; // Slightly longer than check interval

///////////////////////////////////////////////////////////////////////////////
//****                         Public Structs                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Health check status for a route
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unavailable, // Health check is not possible (405 Method Not Allowed, etc.)
    Unknown,     // Not yet checked
}

impl HealthStatus {
    pub fn to_string(&self) -> String {
        match self {
            HealthStatus::Healthy => "Healthy".to_string(),
            HealthStatus::Unhealthy => "Unhealthy".to_string(),
            HealthStatus::Unavailable => "Unavailable".to_string(),
            HealthStatus::Unknown => "Unknown".to_string(),
        }
    }

    pub fn from_string(status: &str) -> Self {
        match status {
            "Healthy" => HealthStatus::Healthy,
            "Unhealthy" => HealthStatus::Unhealthy,
            "Unavailable" => HealthStatus::Unavailable,
            _ => HealthStatus::Unknown,
        }
    }
}

/// Method used for health checking
#[derive(Debug, Clone, PartialEq)]
pub enum HealthCheckMethod {
    HealthEndpoint,
    HeadRequest,
    Skipped,
    Manual,
}

impl HealthCheckMethod {
    pub fn to_string(&self) -> String {
        match self {
            HealthCheckMethod::HealthEndpoint => "health_endpoint".to_string(),
            HealthCheckMethod::HeadRequest => "head_request".to_string(),
            HealthCheckMethod::Skipped => "skipped".to_string(),
            HealthCheckMethod::Manual => "manual".to_string(),
        }
    }
}

/// Health check result for a single route
#[derive(Debug)]
pub struct HealthCheckResult {
    pub path: String,
    pub health_check_status: HealthStatus,
    pub response_time_ms: Option<u64>,
    pub error_message: Option<String>,
    pub checked_at: chrono::DateTime<Utc>,
    pub method_used: HealthCheckMethod,
}

/// Health check manager that coordinates all health checking activities
#[derive(Clone)]
pub struct HealthChecker {
    db_pool: Arc<SqlitePool>,
    http_client: Client,
    check_interval_seconds: u64,
    health_cache: HealthStatusCache,
}

/// Route information needed for health checking
#[derive(Debug)]
pub struct RouteHealthInfo {
    pub path: String,
    pub upstream: String,
    pub health_endpoint: Option<String>,
    pub health_check_status: HealthStatus,
}

/// Default health check interval in seconds
const DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS: u64 = 60;
/// Default health check time out in seconds
const DEFAULT_HEALTH_CHECK_TIMEOUT_SECONDS: u64 = 10;

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

impl HealthChecker {
    /// Create a new health checker instance
    pub fn new(db_pool: Arc<SqlitePool>) -> Self {
        // Fetch health check interval from settings, fallback to default
        let check_interval_seconds: u64 = match queries::get_setting_by_key(
            &db_pool,
            "health_check_interval_seconds",
        ) {
            Ok(Some(row)) => {
                let value_str: String = row.get("value");
                value_str.parse().unwrap_or_else(|e| {
                    warn!("Failed to parse health_check_interval_seconds setting '{}': {}, using default", value_str, e);
                    DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS
                })
            }
            Ok(None) => {
                info!(
                    "No health_check_interval_seconds setting found, using default: {}",
                    DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS
                );
                DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS
            }
            Err(e) => {
                warn!(
                    "Failed to fetch health_check_interval_seconds setting, using default: {}",
                    e
                );
                DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS
            }
        };
        Self {
            db_pool,
            http_client: Client::builder()
                .timeout(Duration::from_secs(DEFAULT_HEALTH_CHECK_TIMEOUT_SECONDS))
                .build()
                .unwrap(),
            check_interval_seconds,
            health_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start the health checking background task
    /// This function spawns a tokio task that runs indefinitely
    pub fn start_background_checks(self) {
        let checker = Arc::new(self);

        tokio::spawn(async move {
            info!(
                "Starting health check background task with {} second intervals",
                checker.check_interval_seconds
            );

            let mut interval = time::interval(Duration::from_secs(checker.check_interval_seconds));

            loop {
                interval.tick().await;

                debug!("Running periodic health checks");

                if let Err(e) = checker.run_health_checks().await {
                    error!("Health check cycle failed: {}", e);
                }
            }
        });
    }

    /// Start background health checks with graceful shutdown support
    pub async fn start_background_checks_with_shutdown(
        self,
        shutdown_coordinator: Arc<ShutdownCoordinator>,
    ) {
        let checker = Arc::new(self);
        let mut shutdown_task = ShutdownAwareTask::new(&shutdown_coordinator);

        info!(
            "Starting health check background task with {} second intervals",
            checker.check_interval_seconds
        );

        loop {
            // Wait for the check interval or shutdown signal
            if shutdown_task
                .wait_or_shutdown(Duration::from_secs(checker.check_interval_seconds))
                .await
            {
                info!("Health check background task shutting down");
                break;
            }

            debug!("Running periodic health checks");

            if let Err(e) = checker.run_health_checks().await {
                error!("Health check cycle failed: {}", e);
            }
        }
    }

    /// Run health checks for all routes
    pub async fn run_health_checks(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Clean up stale cache entries before running health checks
        self.cleanup_stale_cache_entries().await;

        // Fetch all routes that need health checking
        let routes = self.fetch_routes_for_health_check().await?;

        if routes.is_empty() {
            debug!("No routes found for health checking");
            return Ok(());
        }

        info!("Running health checks for {} routes", routes.len());

        // Check each route
        for route in routes {
            let result = self.check_route_health(&route).await;

            match result {
                Ok(health_result) => {
                    // Store the health check result in database and update cache
                    if let Err(e) = self.store_health_result(&health_result).await {
                        error!(
                            "Failed to store health result for route {}: {}",
                            health_result.path, e
                        );
                    }

                    info!(
                        "Health check for {} completed: {} ({}ms, method: {})",
                        health_result.path,
                        health_result.health_check_status.to_string(),
                        health_result.response_time_ms.unwrap_or(0),
                        health_result.method_used.to_string()
                    );
                }
                Err(e) => {
                    error!("Health check failed for route {}: {}", route.path, e);
                }
            }
        }

        Ok(())
    }

    /// Check the health of a single route
    pub async fn check_route_health(
        &self,
        route: &RouteHealthInfo,
    ) -> Result<HealthCheckResult, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = std::time::Instant::now();

        // First, try the dedicated health endpoint if available
        if let Some(health_endpoint) = &route.health_endpoint {
            if !health_endpoint.is_empty() {
                info!(
                    "Checking health endpoint for route {}: {}",
                    route.path, health_endpoint
                );

                match self.check_health_endpoint(health_endpoint).await {
                    Ok(health_check_status) => {
                        let response_time = start_time.elapsed().as_millis() as u64;
                        return Ok(HealthCheckResult {
                            path: route.path.clone(),
                            health_check_status,
                            response_time_ms: Some(response_time),
                            error_message: None,
                            checked_at: Utc::now(),
                            method_used: HealthCheckMethod::HealthEndpoint,
                        });
                    }
                    Err(e) => {
                        warn!(
                            "Health endpoint check failed for {}, falling back to HEAD request: {}",
                            route.path, e
                        );
                    }
                }
            }
        }

        // Fallback to HEAD request if health endpoint is not available or failed
        if route.health_check_status != HealthStatus::Unavailable {
            debug!(
                "Checking upstream with HEAD request for route {}: {}",
                route.path, route.upstream
            );

            match self.check_with_head_request(&route.upstream).await {
                Ok(health_check_status) => {
                    let response_time = start_time.elapsed().as_millis() as u64;
                    Ok(HealthCheckResult {
                        path: route.path.clone(),
                        health_check_status,
                        response_time_ms: Some(response_time),
                        error_message: None,
                        checked_at: Utc::now(),
                        method_used: HealthCheckMethod::HeadRequest,
                    })
                }
                Err(e) => {
                    // Check if this is a 405 Method Not Allowed error
                    if e.to_string().contains("405") || e.to_string().contains("Method Not Allowed")
                    {
                        warn!(
                            "HEAD method not allowed for route {}, marking as unavailable",
                            route.path
                        );

                        // Update the route to mark health checking as unavailable
                        if let Err(update_err) =
                            self.mark_route_health_unavailable(&route.path).await
                        {
                            error!("Failed to update route health status: {}", update_err);
                        }

                        let response_time = start_time.elapsed().as_millis() as u64;
                        Ok(HealthCheckResult {
                            path: route.path.clone(),
                            health_check_status: HealthStatus::Unavailable,
                            response_time_ms: Some(response_time),
                            error_message: Some("HEAD method not allowed".to_string()),
                            checked_at: Utc::now(),
                            method_used: HealthCheckMethod::HeadRequest,
                        })
                    } else {
                        let response_time = start_time.elapsed().as_millis() as u64;
                        Ok(HealthCheckResult {
                            path: route.path.clone(),
                            health_check_status: HealthStatus::Unhealthy,
                            response_time_ms: Some(response_time),
                            error_message: Some(e.to_string()),
                            checked_at: Utc::now(),
                            method_used: HealthCheckMethod::HeadRequest,
                        })
                    }
                }
            }
        } else {
            // Route is marked as health check unavailable, skip it
            debug!(
                "Skipping health check for route {} (marked as unavailable)",
                route.path
            );
            Ok(HealthCheckResult {
                path: route.path.clone(),
                health_check_status: HealthStatus::Unavailable,
                response_time_ms: None,
                error_message: Some("Health check unavailable".to_string()),
                checked_at: Utc::now(),
                method_used: HealthCheckMethod::Skipped,
            })
        }
    }

    /// Check a dedicated health endpoint
    async fn check_health_endpoint(
        &self,
        health_endpoint: &str,
    ) -> Result<HealthStatus, Box<dyn std::error::Error + Send + Sync>> {
        let response = self.http_client.get(health_endpoint).send().await?;

        if response.status().is_success() {
            Ok(HealthStatus::Healthy)
        } else {
            Ok(HealthStatus::Unhealthy)
        }
    }

    /// Check upstream service with HEAD request
    async fn check_with_head_request(
        &self,
        upstream_url: &str,
    ) -> Result<HealthStatus, Box<dyn std::error::Error + Send + Sync>> {
        let response = self.http_client.head(upstream_url).send().await?;

        if response.status().is_success() {
            Ok(HealthStatus::Healthy)
        } else if response.status().as_u16() == 405 {
            Err("405 Method Not Allowed".to_string().into())
        } else {
            Ok(HealthStatus::Unhealthy)
        }
    }

    /// Get health status from cache (non-blocking, fast)
    /// Returns None if not cached or cache is stale, falls back to database
    pub async fn get_cached_health_status(&self, path: &str) -> Option<HealthStatus> {
        // First, try to get from cache
        {
            let cache = self.health_cache.read().await;

            if let Some(cached) = cache.get(path) {
                let current_time = Utc::now().timestamp();
                if current_time - cached.timestamp <= HEALTH_CACHE_TTL_SECONDS {
                    debug!("Cache hit for route '{}': {:?}", path, cached.status);
                    return Some(cached.status.clone());
                } else {
                    debug!(
                        "Cache entry for route '{}' is stale (age: {}s)",
                        path,
                        current_time - cached.timestamp
                    );
                }
            } else {
                debug!("No cache entry found for route '{}'", path);
            }
        } // Release read lock

        // Cache miss or stale - fetch from database and update cache
        debug!("Fetching health status from database for route '{}'", path);
        match self.fetch_route_for_health_check(path).await {
            Ok(health_routes) => {
                if let Some(health_route) = health_routes.first() {
                    let status = health_route.health_check_status.clone();

                    // Update cache with fresh data from database
                    self.update_cached_health_status(path, status.clone()).await;

                    debug!(
                        "Database lookup successful for route '{}': {:?}",
                        path, status
                    );
                    Some(status)
                } else {
                    debug!("No health data found in database for route '{}'", path);
                    None
                }
            }
            Err(e) => {
                warn!(
                    "Failed to fetch health status from database for route '{}': {}",
                    path, e
                );
                None
            }
        }
    }

    /// Update health status in cache
    pub async fn update_cached_health_status(&self, path: &str, status: HealthStatus) {
        let mut cache = self.health_cache.write().await;
        let timestamp = Utc::now().timestamp();

        cache.insert(
            path.to_string(),
            CachedHealthStatus {
                status: status.clone(),
                timestamp,
            },
        );

        debug!("Updated cache for route '{}': {:?}", path, status);
    }

    /// Clear stale entries from cache (housekeeping)
    pub async fn cleanup_stale_cache_entries(&self) {
        let mut cache = self.health_cache.write().await;
        let current_time = Utc::now().timestamp();

        let initial_size = cache.len();
        cache.retain(|path, cached| {
            let is_fresh = current_time - cached.timestamp <= HEALTH_CACHE_TTL_SECONDS;
            if !is_fresh {
                debug!(
                    "Removing stale cache entry for route '{}' (age: {}s)",
                    path,
                    current_time - cached.timestamp
                );
            }
            is_fresh
        });

        let final_size = cache.len();
        if final_size < initial_size {
            debug!(
                "Cleaned up {} stale cache entries ({} -> {})",
                initial_size - final_size,
                initial_size,
                final_size
            );
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
//****                      Database Functions                           ****//
///////////////////////////////////////////////////////////////////////////////

impl HealthChecker {
    /// Fetch all routes that need health checking
    async fn fetch_routes_for_health_check(&self) -> Result<Vec<RouteHealthInfo>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT r.path, r.upstream, r.health_endpoint,
            rhc.health_check_status
            FROM routes r
            LEFT JOIN route_health_checks rhc ON r.path = rhc.path",
        )
        .fetch_all(self.db_pool.as_ref())
        .await?;

        let mut routes = Vec::new();
        for row in rows {
            routes.push(RouteHealthInfo {
                path: row.get("path"),
                upstream: row.get("upstream"),
                health_endpoint: row.get("health_endpoint"),
                health_check_status: HealthStatus::from_string(row.get("health_check_status")),
            });
        }

        Ok(routes)
    }

    pub async fn fetch_route_for_health_check(
        &self,
        path: &str,
    ) -> Result<Vec<RouteHealthInfo>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT r.path, r.upstream, r.health_endpoint,
            rhc.health_check_status
            FROM routes r
            LEFT JOIN route_health_checks rhc ON r.path = rhc.path
            WHERE r.path = ?",
        )
        .bind(path)
        .fetch_all(self.db_pool.as_ref())
        .await?;

        let mut routes = Vec::new();
        for row in rows {
            routes.push(RouteHealthInfo {
                path: row.get("path"),
                upstream: row.get("upstream"),
                health_endpoint: row.get("health_endpoint"),
                health_check_status: HealthStatus::from_string(row.get("health_check_status")),
            });
        }

        Ok(routes)
    }

    /// Store health check result in the database and update cache
    pub async fn store_health_result(&self, result: &HealthCheckResult) -> Result<(), sqlx::Error> {
        // Store in database
        sqlx::query(
            "INSERT OR REPLACE INTO route_health_checks
             (path, health_check_status, response_time_ms, error_message, checked_at, method_used)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&result.path)
        .bind(result.health_check_status.to_string())
        .bind(result.response_time_ms.map(|t| t as i64))
        .bind(&result.error_message)
        .bind(result.checked_at.to_rfc3339())
        .bind(result.method_used.to_string())
        .execute(self.db_pool.as_ref())
        .await?;

        // Update cache
        self.update_cached_health_status(&result.path, result.health_check_status.clone())
            .await;

        Ok(())
    }

    /// Mark a route as health check unavailable
    async fn mark_route_health_unavailable(&self, path: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE route_health_checks SET health_check_status = ? WHERE path = ?")
            .bind(HealthStatus::Unavailable.to_string())
            .bind(path)
            .execute(self.db_pool.as_ref())
            .await?;

        // Update cache
        self.update_cached_health_status(path, HealthStatus::Unavailable)
            .await;

        Ok(())
    }
}

///////////////////////////////////////////////////////////////////////////////
//****                              Tests                                ****//
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn create_test_db() -> SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("Failed to create in-memory database")
    }

    #[tokio::test]
    async fn test_health_status_conversion() {
        assert_eq!(HealthStatus::Healthy.to_string(), "Healthy");
        assert_eq!(HealthStatus::from_string("Healthy"), HealthStatus::Healthy);
        assert_eq!(HealthStatus::from_string("Invalid"), HealthStatus::Unknown);
    }

    #[tokio::test]
    async fn test_health_checker_creation() {
        let pool = create_test_db().await;
        let checker = HealthChecker::new(Arc::new(pool));
        assert_eq!(
            checker.check_interval_seconds,
            checker.check_interval_seconds
        );
    }

    // Note: More comprehensive tests would require actual HTTP servers
    // and database setup, which would be implemented as integration tests
}
