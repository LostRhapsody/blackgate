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

mod auth;
mod cache;
mod cli;
mod database;
mod env;
mod health;
mod logging;
mod metrics;
mod oauth_test_server;
mod open_api;
mod rate_limiter;
mod routing;
mod server;
mod web;
mod webhook;

#[cfg(test)]
mod tests;
use crate::cache::ResponseCache;
use auth::{oauth::OAuthTokenCache, types::AuthType};
use database::initialize_database;
use health::HealthChecker;
use metrics::RequestMetrics;
use rate_limiter::RateLimiter;
use routing::handlers::RouteConfig;
use sqlx::sqlite::SqlitePool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tracing::info;

/// Application state shared across routes, contains DB pool and token cache
#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    token_cache: Arc<Mutex<OAuthTokenCache>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    route_cache: Arc<RwLock<HashMap<String, RouteConfig>>>,
    http_client: reqwest::Client,
    health_checker: Arc<HealthChecker>,
    response_cache: Arc<ResponseCache>,
}

#[tokio::main]
async fn main() {
    // Validate environment variables before starting
    let validation_result = env::validate_environment();

    // Initialize tracing using the validated config
    let log_level = match &validation_result {
        Ok(config) => config.log_level.clone(),
        Err(_) => "blackgate=info,tower_http=debug".to_string(),
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| log_level.into()),
        )
        .init();

    info!("Starting Black Gate API Gateway");

    // Print validation results
    env::print_validation_results(&validation_result);

    // Get validated configuration or exit
    let config = match validation_result {
        Ok(config) => config,
        Err(errors) => {
            let has_critical = errors
                .iter()
                .any(|e| e.severity == env::ErrorSeverity::Critical);
            if has_critical {
                eprintln!("Critical environment validation errors found. Cannot start server.");
                std::process::exit(1);
            } else {
                // If only warnings/info, proceed with defaults
                env::get_config()
            }
        }
    };

    info!("Using database: {}", config.database_url);

    let pool = initialize_database(&config.database_url)
        .await
        .expect("Failed to initialize database");

    cli::parse_cli_commands(Arc::new(&pool)).await;
}
