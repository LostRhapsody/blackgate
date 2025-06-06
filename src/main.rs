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
mod server;

#[cfg(test)]
mod tests;
use sqlx::sqlite::SqlitePool;
use std::sync::{Arc, Mutex};
use tracing::info;
use auth::{
    oauth::OAuthTokenCache,
    types::AuthType,
};
use rate_limiter::RateLimiter;
use metrics::RequestMetrics;

/// Application state shared across routes, contains DB pool and token cache
#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    token_cache: Arc<Mutex<OAuthTokenCache>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
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
