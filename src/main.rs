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

use axum::{Router, extract::OriginalUri, http::Method, routing::{get, post, put, delete, patch, head}};

mod web;
mod auth;
mod oauth_test_server;
mod rate_limiter;
mod cli;
mod metrics;

#[cfg(test)]
mod tests;
use sqlx::{Row, sqlite::SqlitePool};
use std::sync::{Arc, Mutex};
use tokio::time::Instant;
use tracing::{info, warn, error};
use tower_http::trace::TraceLayer;

use auth::{
    oauth::OAuthTokenCache,
    apply_authentication,
    types::AuthType,
};

use rate_limiter::{
    RateLimiter,
    check_rate_limit,
};

use metrics::{
    RequestMetrics,
    store_metrics,
};

/// Application state shared across routes, contains DB pool and token cache
#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    token_cache: Arc<Mutex<OAuthTokenCache>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

/// Route configuration structure to hold authentication details
#[derive(Debug)]
struct RouteConfig {
    upstream: String,
    auth_type: AuthType,
    auth_value: Option<String>,
    oauth_token_url: Option<String>,
    oauth_client_id: Option<String>,
    oauth_client_secret: Option<String>,
    oauth_scope: Option<String>,
    // JWT specific fields
    jwt_secret: Option<String>,
    jwt_algorithm: Option<String>,
    jwt_issuer: Option<String>,
    jwt_audience: Option<String>,
    jwt_required_claims: Option<String>,
    // OIDC specific fields
    oidc_issuer: Option<String>,
    oidc_client_id: Option<String>,
    oidc_client_secret: Option<String>,
    oidc_audience: Option<String>,
    oidc_scope: Option<String>,
}

/// Handles GET requests
async fn handle_get_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> axum::response::Response {
    handle_request_core(state, Method::GET, uri.path().to_string(), None).await
}

/// Handles HEAD requests
async fn handle_head_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> axum::response::Response {
    handle_request_core(state, Method::HEAD, uri.path().to_string(), None).await
}

/// Handles DELETE requests
async fn handle_delete_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> axum::response::Response {
    handle_request_core(state, Method::DELETE, uri.path().to_string(), None).await
}

/// Handles POST requests
async fn handle_post_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
    payload: axum::body::Bytes,
) -> axum::response::Response {
    let body_string = String::from_utf8_lossy(&payload).to_string();
    handle_request_core(
        state,
        Method::POST,
        uri.path().to_string(),
        Some(body_string),
    )
    .await
}

/// Handles PUT requests
async fn handle_put_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
    payload: axum::body::Bytes,
) -> axum::response::Response {
    let body_string = String::from_utf8_lossy(&payload).to_string();
    handle_request_core(
        state,
        Method::PUT,
        uri.path().to_string(),
        Some(body_string),
    )
    .await
}

/// Handles PATCH requests
async fn handle_patch_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
    payload: axum::body::Bytes,
) -> axum::response::Response {
    let body_string = String::from_utf8_lossy(&payload).to_string();
    handle_request_core(
        state,
        Method::PATCH,
        uri.path().to_string(),
        Some(body_string),
    )
    .await
}

/// Core handler logic, shared by both body/no-body handlers
async fn handle_request_core(
    state: axum::extract::State<AppState>,
    method: Method,
    path: String,
    body: Option<String>,
) -> axum::response::Response {
    // Initialize metrics
    let request_size = body.as_ref().map_or(0, |b| b.len() as i64);
    let mut metrics = RequestMetrics::new(path.clone(), method.to_string(), request_size);

    info!(
        request_id = %metrics.id,
        method = %method,
        path = %path,
        request_size_bytes = request_size,
        "Incoming request"
    );

    // Query the database for the route
    let row = sqlx::query("SELECT upstream, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, oidc_issuer, oidc_client_id, oidc_client_secret, oidc_audience, oidc_scope, rate_limit_per_minute, rate_limit_per_hour FROM routes WHERE path = ?")
        .bind(&path)
        .fetch_optional(&state.db)
        .await
        .expect("Database query failed");

    let response = match row {
        Some(row) => {
            // confirm the method is allowed
            let allowed_methods: String = row.get("allowed_methods");

            // If allowed_methods is empty, all methods are allowed
            if !allowed_methods.is_empty() {
                let allowed_methods: Vec<&str> = allowed_methods.split(',').collect();
                if !allowed_methods.contains(&method.as_str()) {
                    warn!(
                        request_id = %metrics.id,
                        method = %method,
                        path = %path,
                        allowed_methods = %row.get::<String, _>("allowed_methods"),
                        "Method not allowed"
                    );

                    metrics.set_error("Method Not Allowed".to_string());
                    store_metrics(&state.db, &metrics).await;

                    return axum::response::Response::builder()
                        .status(405)
                        .body(axum::body::Body::from("Method Not Allowed"))
                        .unwrap();
                }
            }

            // Extract rate limiting configuration
            let rate_limit_per_minute: i64 = row.get("rate_limit_per_minute");
            let rate_limit_per_hour: i64 = row.get("rate_limit_per_hour");

            // Check rate limits
            if let Err(response) = check_rate_limit(
                &path,
                rate_limit_per_minute,
                rate_limit_per_hour,
                state.rate_limiter.clone(),
                &mut metrics,
            ).await {
                store_metrics(&state.db, &metrics).await;
                return response;
            }

            // Extract route configuration from the database row
            let auth_type_str: String = row.get("auth_type");
            let route_config = RouteConfig {
                upstream: row.get("upstream"),
                auth_type: AuthType::from_str(&auth_type_str),
                auth_value: row.get("auth_value"),
                oauth_token_url: row.get("oauth_token_url"),
                oauth_client_id: row.get("oauth_client_id"),
                oauth_client_secret: row.get("oauth_client_secret"),
                oauth_scope: row.get("oauth_scope"),
                jwt_secret: row.get("jwt_secret"),
                jwt_algorithm: row.get("jwt_algorithm"),
                jwt_issuer: row.get("jwt_issuer"),
                jwt_audience: row.get("jwt_audience"),
                jwt_required_claims: row.get("jwt_required_claims"),
                // OIDC specific fields
                oidc_issuer: row.get("oidc_issuer"),
                oidc_client_id: row.get("oidc_client_id"),
                oidc_client_secret: row.get("oidc_client_secret"),
                oidc_audience: row.get("oidc_audience"),
                oidc_scope: row.get("oidc_scope"),
            };

            info!(
                request_id = %metrics.id,
                upstream = %route_config.upstream,
                auth_type = %route_config.auth_type.to_string(),
                "Routing to upstream"
            );

            // Create the request builder
            let client = reqwest::Client::new();
            let builder = client.request(method, &route_config.upstream);

            // Apply authentication
            let builder = match apply_authentication(
                builder,
                &route_config,
                &path,
                state.token_cache.clone(),
            )
            .await
            {
                Ok(builder) => builder,
                Err(response) => {
                    error!(
                        request_id = %metrics.id,
                        path = %path,
                        "Authentication failed"
                    );

                    metrics.set_error("Authentication failed".to_string());
                    store_metrics(&state.db, &metrics).await;

                    return response;
                }
            };

            // Add request body if present
            let builder = if let Some(body) = body {
                builder.body(body)
            } else {
                builder
            };

            // Record start time for upstream request
            let upstream_start = Instant::now();

            // Send the request
            let response = match builder.send().await {
                Ok(response) => response,
                Err(e) => {
                    error!(
                        request_id = %metrics.id,
                        upstream = %route_config.upstream,
                        error = %e,
                        "Upstream request failed"
                    );

                    metrics.set_error(format!("Upstream request failed: {}", e));
                    store_metrics(&state.db, &metrics).await;

                    return axum::response::Response::builder()
                        .status(502)
                        .body(axum::body::Body::from("Bad Gateway"))
                        .unwrap();
                }
            };

            let upstream_duration = upstream_start.elapsed();
            let response_status = response.status();

            let response_body = match response.text().await {
                Ok(body) => body,
                Err(e) => {
                    error!(
                        request_id = %metrics.id,
                        error = %e,
                        "Failed to read response body"
                    );

                    metrics.set_error(format!("Failed to read response body: {}", e));
                    store_metrics(&state.db, &metrics).await;

                    return axum::response::Response::builder()
                        .status(502)
                        .body(axum::body::Body::from("Bad Gateway"))
                        .unwrap();
                }
            };

            let response_size = response_body.len() as i64;

            // Complete metrics tracking
            metrics.complete_request(
                response_size,
                response_status.as_u16(),
                Some(route_config.upstream.clone()),
                route_config.auth_type.to_string().to_string(),
            );

            info!(
                request_id = %metrics.id,
                response_status = response_status.as_u16(),
                response_size_bytes = response_size,
                upstream_duration_ms = upstream_duration.as_millis(),
                total_duration_ms = metrics.duration_ms.unwrap_or(0),
                "Request completed successfully"
            );

            // Store metrics in database
            store_metrics(&state.db, &metrics).await;

            axum::response::Response::builder()
                .status(response_status)
                .body(response_body.into())
                .unwrap()
        }
        None => {
            warn!(
                request_id = %metrics.id,
                path = %path,
                "Route not found"
            );

            metrics.set_error("Route not found".to_string());
            store_metrics(&state.db, &metrics).await;

            axum::response::Response::builder()
                .status(404)
                .body(axum::body::Body::from("No route found"))
                .unwrap()
        }
    };

    response
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
    let app = Router::new()
        .merge(web::create_web_router())
        // HTTP method specific routes
        .route("/{*path}", get(handle_get_request))
        .route("/{*path}", head(handle_head_request))
        .route("/{*path}", delete(handle_delete_request))
        .route("/{*path}", post(handle_post_request))
        .route("/{*path}", put(handle_put_request))
        .route("/{*path}", patch(handle_patch_request))
        .with_state(app_state)
        .layer(TraceLayer::new_for_http());

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
    let app = Router::new()
        .merge(web::create_web_router())
        // HTTP method specific routes
        .route("/{*path}", get(handle_get_request))
        .route("/{*path}", head(handle_head_request))
        .route("/{*path}", delete(handle_delete_request))
        .route("/{*path}", post(handle_post_request))
        .route("/{*path}", put(handle_put_request))
        .route("/{*path}", patch(handle_patch_request))
        .with_state(app_state)
        .layer(TraceLayer::new_for_http());

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
