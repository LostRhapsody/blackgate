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
//! health
//! open_api
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
mod database;
mod health;
mod open_api;

#[cfg(test)]
mod tests;
use sqlx::sqlite::SqlitePool;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::info;
use auth::{
    oauth::OAuthTokenCache,
    types::AuthType,
};
use rate_limiter::RateLimiter;
use metrics::RequestMetrics;
use database::{initialize_database, BLACKGATE_DB_URL};
use routing::handlers::RouteConfig;
use health::HealthChecker;

/// Application state shared across routes, contains DB pool and token cache
#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    token_cache: Arc<Mutex<OAuthTokenCache>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    route_cache: Arc<RwLock<HashMap<String, RouteConfig>>>,
    http_client: reqwest::Client,
    health_checker: Arc<HealthChecker>,
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

    let pool = initialize_database(BLACKGATE_DB_URL)
        .await
        .expect("Failed to initialize database");

    cli::parse_cli_commands(Arc::new(&pool)).await;

}
