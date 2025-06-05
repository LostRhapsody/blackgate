//! module structure:
//! auth
//! routing
//! metrics
//! rate_limiter
//! cli
//! server
//! database
//! web
//! oauth_test_server
//! tests
//! main.rs

mod web;
mod auth;
mod oauth_test_server;
mod rate_limiter;
mod cli;
mod metrics;
mod routing;

#[cfg(test)]
mod tests;
use sqlx::sqlite::SqlitePool;
use std::sync::{Arc, Mutex};
use tracing::{info, error};

use auth::{
    oauth::OAuthTokenCache,
    types::AuthType,
};

use rate_limiter::RateLimiter;

use metrics::RequestMetrics;

use routing::router::create_router;

/// Application state shared across routes, contains DB pool and token cache
#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    token_cache: Arc<Mutex<OAuthTokenCache>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

/// Start the API gateway server, waits for incoming requests
async fn start_server(pool: SqlitePool) {
    let token_cache = Arc::new(Mutex::new(OAuthTokenCache::new()));
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));
    let app_state = AppState {
        db: pool.clone(),
        token_cache,
        rate_limiter,
    };

    let app = create_router(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    let addr = listener.local_addr().unwrap();
    info!("Black Gate running on http://{}", addr);
    info!("Web interface: http://localhost:3000/dashboard");
    axum::serve(listener, app).await.unwrap();
}

/// Start the API gateway server with graceful shutdown support, used for oAuth testing
async fn start_server_with_shutdown(
    pool: SqlitePool,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) {
    let token_cache = Arc::new(Mutex::new(OAuthTokenCache::new()));
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));
    let app_state = AppState {
        db: pool.clone(),
        token_cache,
        rate_limiter,
    };

    let app = create_router(app_state);

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
async fn start_oauth_test_server(pool: SqlitePool, _port: u16) {
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

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "blackgate=info,tower_http=debug".into()),
        )
        .init();

    info!("Starting Black Gate API Gateway");

    // Initialize SQLite database
    let pool = SqlitePool::connect("sqlite://blackgate.db")
        .await
        .expect("Failed to connect to SQLite");

    // Create routes table if it doesn't exist
    sqlx::query(
        /*
        drop table if exists routes;
        drop table if exists request_metrics;
        */
        "
        CREATE TABLE IF NOT EXISTS routes (
            path TEXT PRIMARY KEY,
            auth_type TEXT,
            auth_value TEXT,
            allowed_methods TEXT,
            upstream TEXT NOT NULL,
            oauth_token_url TEXT,
            oauth_client_id TEXT,
            oauth_client_secret TEXT,
            oauth_scope TEXT,
            jwt_secret TEXT,
            jwt_algorithm TEXT,
            jwt_issuer TEXT,
            jwt_audience TEXT,
            jwt_required_claims TEXT,
            oidc_issuer TEXT,
            oidc_client_id TEXT,
            oidc_client_secret TEXT,
            oidc_audience TEXT,
            oidc_scope TEXT,
            rate_limit_per_minute INTEGER DEFAULT 60,
            rate_limit_per_hour INTEGER DEFAULT 1000
        );

        CREATE TABLE IF NOT EXISTS request_metrics (
            id TEXT PRIMARY KEY,
            path TEXT NOT NULL,
            method TEXT NOT NULL,
            request_timestamp TEXT NOT NULL,
            response_timestamp TEXT,
            duration_ms INTEGER,
            request_size_bytes INTEGER NOT NULL,
            response_size_bytes INTEGER,
            response_status_code INTEGER,
            upstream_url TEXT,
            auth_type TEXT NOT NULL,
            client_ip TEXT,
            user_agent TEXT,
            error_message TEXT
        );

        ",
        /*
        INSERT INTO routes (path, upstream, auth_type, auth_value, allowed_methods)
        VALUES ('/post-test', 'https://httpbin.org/post', 'api-key', 'Bearer warehouse_key','POST');
        INSERT INTO routes (path, upstream, auth_type, auth_value, allowed_methods)
        VALUES ('/get-test', 'https://httpbin.org/post', 'api-key', 'Bearer warehouse_key','GET');
        INSERT INTO routes (path, upstream, auth_type, auth_value, allowed_methods)
        VALUES ('/no-method-test', 'https://httpbin.org/post', 'api-key', 'Bearer warehouse_key','');
        INSERT INTO routes (path, upstream, auth_type, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope)
        VALUES ('/oauth-test', 'https://httpbin.org/anything', 'oauth2', 'GET', 'http://localhost:3001/oauth/token', 'test_client', 'test_secret', 'read:all');
        */
    )
    .execute(&pool)
    .await
    .expect("Failed to create routes table");

    cli::parse_cli_commands(Arc::new(&pool)).await;

}
