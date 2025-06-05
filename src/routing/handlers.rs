
//! # Routing Handlers Module
//!
//! This module provides HTTP request handlers for the Blackgate API gateway.
//! It implements a flexible routing system that supports multiple authentication
//! methods and upstream request forwarding.
//!
//! ## Features
//!
//! - **Multi-method support**: Handles GET, POST, PUT, PATCH, DELETE, and HEAD requests
//! - **Authentication**: Supports multiple authentication types including OAuth, JWT, and OIDC
//! - **Rate limiting**: Per-minute and per-hour rate limiting based on route configuration
//! - **Metrics collection**: Comprehensive request/response metrics tracking
//! - **Database-driven routing**: Route configuration stored in database with dynamic lookup
//! - **Upstream forwarding**: Proxies requests to configured upstream services
//!
//! ## Request Flow
//!
//! 1. Extract request details (method, path, body)
//! 2. Query database for route configuration
//! 3. Validate HTTP method is allowed for the route
//! 4. Apply rate limiting checks
//! 5. Apply authentication based on route configuration
//! 6. Forward request to upstream service
//! 7. Collect and store metrics
//! 8. Return response to client
//!
//! ## Error Handling
//!
//! The module provides comprehensive error handling for:
//! - Route not found (404)
//! - Method not allowed (405)
//! - Rate limit exceeded (429)
//! - Authentication failures (401/403)
//! - Upstream service errors (502)
//!
//! ## Database Schema
//!
//! Routes are expected to have the following database columns:
//! - `path`: Route path pattern
//! - `upstream`: Target upstream URL
//! - `auth_type`: Authentication method
//! - `allowed_methods`: Comma-separated list of allowed HTTP methods
//! - `rate_limit_per_minute`: Requests per minute limit
//! - `rate_limit_per_hour`: Requests per hour limit
//! - Various auth-specific configuration fields (OAuth, JWT, OIDC)
//!
//! ## Usage
//!
//! This module is typically used by the main router to handle incoming requests:
//!
//! ```rust
//! use axum::Router;
//! use crate::routing::handlers::*;
//!
//! let app = Router::new()
//!     .route("/*path", axum::routing::get(handle_get_request))
//!     .route("/*path", axum::routing::post(handle_post_request))
//!     // ... other methods
//!     .with_state(app_state);
//! ```

use axum::{extract::OriginalUri, http::Method};
use sqlx::Row;
use tokio::time::Instant;
use tracing::{info, warn, error};
use crate::{
    auth::{apply_authentication, types::AuthType}, metrics::{
    store_metrics, RequestMetrics
    }, rate_limiter::check_rate_limit, AppState
};

///////////////////////////////////////////////////////////////////////////////
//****                         Public Structs                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Route configuration structure to hold authentication details, shared between handlers and routes
#[derive(Debug)]
pub struct RouteConfig {
    pub upstream: String,
    pub auth_type: AuthType,
    pub auth_value: Option<String>,
    pub oauth_token_url: Option<String>,
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret: Option<String>,
    pub oauth_scope: Option<String>,
    // JWT specific fields
    pub jwt_secret: Option<String>,
    pub jwt_algorithm: Option<String>,
    pub jwt_issuer: Option<String>,
    pub jwt_audience: Option<String>,
    pub jwt_required_claims: Option<String>,
    // OIDC specific fields
    pub oidc_issuer: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_audience: Option<String>,
    pub oidc_scope: Option<String>,
}

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Handles GET requests
pub async fn handle_get_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> axum::response::Response {
    handle_request_core(state, Method::GET, uri.path().to_string(), None).await
}

/// Handles HEAD requests
pub async fn handle_head_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> axum::response::Response {
    handle_request_core(state, Method::HEAD, uri.path().to_string(), None).await
}

/// Handles DELETE requests
pub async fn handle_delete_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> axum::response::Response {
    handle_request_core(state, Method::DELETE, uri.path().to_string(), None).await
}

/// Handles POST requests
pub async fn handle_post_request(
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
pub async fn handle_put_request(
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
pub async fn handle_patch_request(
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
pub async fn handle_request_core(
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

///////////////////////////////////////////////////////////////////////////////
//****                              Tests                                ****//
///////////////////////////////////////////////////////////////////////////////
// Tests for these are handled in the tests module for now