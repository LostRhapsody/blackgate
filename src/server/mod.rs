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

use sqlx::{sqlite::SqlitePool, Row};
use tracing::{info, error, warn};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tokio::sync::RwLock;
use crate::AppState;
use crate::auth::oauth::OAuthTokenCache;
use crate::rate_limiter::RateLimiter;
use crate::routing::router::create_router;
use crate::health::HealthChecker;
use crate::database::{
    get_database_url,
    backup::BackupManager,
};
use crate::database::queries::get_setting_by_key;
use crate::cache::ResponseCache;

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Start the API gateway server, waits for incoming requests
pub async fn start_server(pool: SqlitePool) {
    let token_cache = Arc::new(Mutex::new(OAuthTokenCache::new()));
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));
    let route_cache = Arc::new(RwLock::new(HashMap::new()));
    let http_client = reqwest::Client::new();
    
    // Create shared health checker
    let health_checker = Arc::new(HealthChecker::new(Arc::new(pool.clone())));

    // Create a shared response cache
    let default_ttl: u64 = get_response_cache_default_ttl(&pool);
    let response_cache = Arc::new(ResponseCache::new(default_ttl));

    let app_state = AppState {
        db: pool.clone(),
        token_cache,
        rate_limiter,
        route_cache,
        http_client,
        health_checker: health_checker.clone(),
        response_cache,
    };

    let app = create_router(app_state);

    // Create a new health checker for the background service Start the health check background service
    let background_health_checker = HealthChecker::new(Arc::new(pool.clone()));
    background_health_checker.start_background_checks();

    let database_url = get_database_url();
    
    // Start the database backup background service
    let backup_manager = BackupManager::new(Arc::new(pool.clone()), database_url);
    backup_manager.start_background_backups();
    
    // Create a new response cache for the background service
    let background_response_cache = Arc::new(ResponseCache::new(default_ttl));

    // Start background task to clean up expired cache entries
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60)); // Run every minute
        loop {
            interval.tick().await;
            background_response_cache.cleanup().await;
        }
    });

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    let addr = listener.local_addr().unwrap();
    info!("Black Gate running on http://{}", addr);
    info!("Web interface: http://localhost:3000/");
    axum::serve(listener, app).await.unwrap();
}

/// Start the API gateway server with graceful shutdown support, used for oAuth testing
pub async fn start_server_with_shutdown(
    pool: SqlitePool,
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
    
    let app_state = AppState {
        db: pool.clone(),
        token_cache,
        rate_limiter,
        route_cache,
        http_client,
        health_checker: health_checker.clone(),
        response_cache,
    };

    let app = create_router(app_state);

    // Create a new health checker for the background service Start the health check background service
    let background_health_checker = HealthChecker::new(Arc::new(pool.clone()));
    background_health_checker.start_background_checks();

    // Start the database backup background service
    let backup_manager = BackupManager::new(Arc::new(pool.clone()), "blackgate.db");
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

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
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
pub async fn start_oauth_test_server(pool: SqlitePool, _port: u16) {
    let (_addr, oauth_shutdown_tx) = crate::oauth_test_server::spawn_oauth_test_server().await;

    // Create shutdown channel for the main server
    let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel();

    // Start the main Black Gate server with graceful shutdown
    let server_pool = pool.clone();
    let server_handle = tokio::spawn(async move {
        start_server_with_shutdown(server_pool, server_shutdown_rx).await;
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
    let default_ttl: u64 = match get_setting_by_key(&pool, "response_cache_default_ttl") {
        Ok(Some(row)) => {
            let value_str: String = row.get("value");
            value_str.parse().unwrap_or_else(|e| {
                warn!("Failed to parse response_cache_default_ttl setting '{}': {}, using default", value_str, e);
                crate::cache::DEFAULT_RESPONSE_CACHE_TTL
            })
        }
        Ok(None) => {
            info!("No response_cache_default_ttl setting found, using default: {}", crate::cache::DEFAULT_RESPONSE_CACHE_TTL);
            crate::cache::DEFAULT_RESPONSE_CACHE_TTL
        }
        Err(e) => {
            warn!("Failed to fetch response_cache_default_ttl setting, using default: {}", e);
            crate::cache::DEFAULT_RESPONSE_CACHE_TTL
        }
    };
    default_ttl
}