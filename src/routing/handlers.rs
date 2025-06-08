
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
//! - **Health checking**: Monitors route health and implements fallback logic for unhealthy routes
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
//! 5. Check route health status and implement fallback logic if unhealthy
//! 6. Apply authentication based on route configuration
//! 7. Forward request to upstream service
//! 8. Collect and store metrics
//! 9. Return response to client
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

use axum::{extract::OriginalUri, http::{HeaderMap, Method}};
use sqlx::Row;
use std::sync::Arc;
use tokio::time::Instant;
use tracing::{info, warn, error};
use crate::{
    auth::{apply_authentication, types::AuthType}, 
    health::{HealthChecker, HealthStatus},
    metrics::{store_metrics, RequestMetrics}, 
    rate_limiter::check_rate_limit, 
    AppState, 
    database::queries
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
    headers: HeaderMap,
) -> axum::response::Response {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok().map(|s| s.to_string()));
    handle_request_core(state, Method::GET, uri.path().to_string(), None, auth_header).await
}

/// Handles HEAD requests
pub async fn handle_head_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> axum::response::Response {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok().map(|s| s.to_string()));
    handle_request_core(state, Method::HEAD, uri.path().to_string(), None, auth_header).await
}

/// Handles DELETE requests
pub async fn handle_delete_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> axum::response::Response {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok().map(|s| s.to_string()));
    handle_request_core(state, Method::DELETE, uri.path().to_string(), None, auth_header).await
}

/// Handles POST requests
pub async fn handle_post_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    payload: axum::body::Bytes,
) -> axum::response::Response {
    let body_string = String::from_utf8_lossy(&payload).to_string();
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok().map(|s| s.to_string()));
    handle_request_core(
        state,
        Method::POST,
        uri.path().to_string(),
        Some(body_string),
        auth_header,
    )
    .await
}

/// Handles PUT requests
pub async fn handle_put_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    payload: axum::body::Bytes,
) -> axum::response::Response {
    let body_string = String::from_utf8_lossy(&payload).to_string();
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok().map(|s| s.to_string()));
    handle_request_core(
        state,
        Method::PUT,
        uri.path().to_string(),
        Some(body_string),
        auth_header,
    )
    .await
}

/// Handles PATCH requests
pub async fn handle_patch_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    payload: axum::body::Bytes,
) -> axum::response::Response {
    let body_string = String::from_utf8_lossy(&payload).to_string();
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok().map(|s| s.to_string()));
    handle_request_core(
        state,
        Method::PATCH,
        uri.path().to_string(),
        Some(body_string),
        auth_header,
    )
    .await
}

/// Core handler logic, shared by both body/no-body handlers
pub async fn handle_request_core(
    state: axum::extract::State<AppState>,
    method: Method,
    path: String,
    body: Option<String>,
    auth_header: Option<String>,
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
    );    // Query the database for the route with collection data
    let row = queries::fetch_route_config_with_collection_by_path(&state.db, &path)
        .await
        .expect("Database query failed");

    let response = match row {
        Some(row) => {
            // confirm the method is allowed
            let allowed_methods: String = row.get("allowed_methods");

            // If allowed_methods is empty, all methods are allowed
            if !allowed_methods.is_empty() && method.as_str() != "HEAD" {
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

            // Check route health status for the backup route fallback
            let health_checker = HealthChecker::new(Arc::new(state.db.clone()));
            let current_route = row;
            
            // Try to get a healthy route (either the primary or backup)
            let final_route = match health_checker.fetch_route_for_health_check(&path).await {
                Ok(health_routes) => {
                    // If we have health check data, check the primary route first
                    if let Some(health_route) = health_routes.first() {
                        // Check the health status of the primary route
                        if health_route.health_check_status == HealthStatus::Unhealthy {
                            // If primary route is unhealthy, check for backup route
                            warn!(
                                request_id = %metrics.id,
                                path = %path,
                                "Primary route is unhealthy, checking for backup route"
                            );

                            // Check if this route has a backup_route_path configured
                            let backup_route_path: String = current_route.get("backup_route_path");
                            if !backup_route_path.is_empty() {
                                // backup is configured, attempt to use it
                                info!(
                                    request_id = %metrics.id,
                                    path = %path,
                                    backup_path = %backup_route_path,
                                    "Attempting to use backup route"
                                );

                                // Fetch the backup route configuration
                                match queries::fetch_route_config_by_path(&state.db, &backup_route_path).await {
                                    Ok(Some(backup_row)) => {
                                        // Check if backup route is healthy
                                        match health_checker.fetch_route_for_health_check(&backup_route_path).await {
                                            Ok(backup_health_routes) => {
                                                // we have backup health data, check the backup route's health status
                                                if let Some(backup_health_route) = backup_health_routes.first() {                                                    
                                                    if backup_health_route.health_check_status == HealthStatus::Healthy {
                                                        // backup is healthy, switch to it
                                                        info!(
                                                            request_id = %metrics.id,
                                                            path = %path,
                                                            backup_path = %backup_route_path,
                                                            "Backup route is healthy, switching to backup"
                                                        );
                                                        backup_row
                                                    } else {
                                                        // backup is unhealthy, log it and use the primary route
                                                        warn!(
                                                            request_id = %metrics.id,
                                                            path = %path,
                                                            backup_path = %backup_route_path,
                                                            "Backup route is also unhealthy, using primary anyway"
                                                        );
                                                        current_route
                                                    }
                                                } else {
                                                    // if we have no health data for the backup route, log it and use the backup anyway
                                                    info!(
                                                        request_id = %metrics.id,
                                                        path = %path,
                                                        backup_path = %backup_route_path,
                                                        "No health data for backup route, using backup anyway"
                                                    );
                                                    backup_row
                                                }
                                            }
                                            Err(e) => {
                                                // if backup route's health check fails we'll log it but still use the backup route
                                                warn!(
                                                    request_id = %metrics.id,
                                                    path = %path,
                                                    backup_path = %backup_route_path,
                                                    error = %e,
                                                    "Failed to check backup route health, using backup anyway"
                                                );
                                                backup_row
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        // if backup route is not found in the database, log it and use the primary route
                                        error!(
                                            request_id = %metrics.id,
                                            path = %path,
                                            backup_path = %backup_route_path,
                                            "Backup route not found in database, using unhealthy primary"
                                        );
                                        current_route
                                    }
                                    Err(e) => {
                                        // if there's an error fetching the backup route, log it and use the primary route
                                        error!(
                                            request_id = %metrics.id,
                                            path = %path,
                                            backup_path = %backup_route_path,
                                            error = %e,
                                            "Failed to fetch backup route, using unhealthy primary"
                                        );
                                        current_route
                                    }
                                }
                            } else {
                                // tried to use a backup route but none is configured
                                warn!(
                                    request_id = %metrics.id,
                                    path = %path,
                                    "No backup route configured, using unhealthy primary"
                                );
                                current_route
                            }
                        } else {
                            // if not unhealthy, use the primary route
                            info!(
                                request_id = %metrics.id,
                                path = %path,
                                health_status = %health_route.health_check_status.to_string(),
                                "Primary route health check passed"
                            );
                            current_route
                        }
                    } else {
                        // if no health check data is found, use the primary route
                        info!(
                            request_id = %metrics.id,
                            path = %path,
                            "No health check data found for route, using primary"
                        );
                        current_route
                    }
                }
                Err(e) => {
                    // if health check fails, log the error and use the primary route
                    warn!(
                        request_id = %metrics.id,
                        path = %path,
                        error = %e,
                        "Failed to fetch route health status, using primary anyway"
                    );
                    current_route
                }
            };

            // Extract route configuration from the final selected route (primary or backup)
            let auth_type_str: String = final_route.get("auth_type");
            let route_auth_type = AuthType::from_str(&auth_type_str);
            
            // Check if route uses collection authentication (route auth is None and has collection)
            let collection_id: Option<i64> = final_route.get("collection_id");
            let use_collection_auth = route_auth_type == AuthType::None && collection_id.is_some();
            
            // Determine which auth settings to use
            let (final_auth_type, final_auth_value, final_oauth_token_url, final_oauth_client_id, 
                 final_oauth_client_secret, final_oauth_scope, final_jwt_secret, final_jwt_algorithm,
                 final_jwt_issuer, final_jwt_audience, final_jwt_required_claims, final_oidc_issuer,
                 final_oidc_client_id, final_oidc_client_secret, final_oidc_audience, final_oidc_scope) = if use_collection_auth {
                // Use collection defaults
                info!(
                    request_id = %metrics.id,
                    path = %path,
                    collection_id = collection_id.unwrap_or(0),
                    "Using collection authentication for route"
                );
                
                let collection_auth_type_str: String = final_route.get("default_auth_type");
                (
                    AuthType::from_str(&collection_auth_type_str),
                    final_route.get("default_auth_value"),
                    final_route.get("default_oauth_token_url"),
                    final_route.get("default_oauth_client_id"),
                    final_route.get("default_oauth_client_secret"),
                    final_route.get("default_oauth_scope"),
                    final_route.get("default_jwt_secret"),
                    final_route.get("default_jwt_algorithm"),
                    final_route.get("default_jwt_issuer"),
                    final_route.get("default_jwt_audience"),
                    final_route.get("default_jwt_required_claims"),
                    final_route.get("default_oidc_issuer"),
                    final_route.get("default_oidc_client_id"),
                    final_route.get("default_oidc_client_secret"),
                    final_route.get("default_oidc_audience"),
                    final_route.get("default_oidc_scope"),
                )
            } else {
                // Use route-specific auth
                (
                    route_auth_type,
                    final_route.get("auth_value"),
                    final_route.get("oauth_token_url"),
                    final_route.get("oauth_client_id"),
                    final_route.get("oauth_client_secret"),
                    final_route.get("oauth_scope"),
                    final_route.get("jwt_secret"),
                    final_route.get("jwt_algorithm"),
                    final_route.get("jwt_issuer"),
                    final_route.get("jwt_audience"),
                    final_route.get("jwt_required_claims"),
                    final_route.get("oidc_issuer"),
                    final_route.get("oidc_client_id"),
                    final_route.get("oidc_client_secret"),
                    final_route.get("oidc_audience"),
                    final_route.get("oidc_scope"),
                )
            };
            
            let route_config = RouteConfig {
                upstream: final_route.get("upstream"),
                auth_type: final_auth_type,
                auth_value: final_auth_value,
                oauth_token_url: final_oauth_token_url,
                oauth_client_id: final_oauth_client_id,
                oauth_client_secret: final_oauth_client_secret,
                oauth_scope: final_oauth_scope,
                jwt_secret: final_jwt_secret,
                jwt_algorithm: final_jwt_algorithm,
                jwt_issuer: final_jwt_issuer,
                jwt_audience: final_jwt_audience,
                jwt_required_claims: final_jwt_required_claims,
                // OIDC specific fields
                oidc_issuer: final_oidc_issuer,
                oidc_client_id: final_oidc_client_id,
                oidc_client_secret: final_oidc_client_secret,
                oidc_audience: final_oidc_audience,
                oidc_scope: final_oidc_scope,
            };

            info!(
                request_id = %metrics.id,
                upstream = %route_config.upstream,
                auth_type = %route_config.auth_type.to_string(),
                "Routing to upstream"
            );

            // Create the request builder
            let client = reqwest::Client::new();
            let builder = client.request(method, &route_config.upstream);            // Apply authentication
            let builder = match apply_authentication(
                builder,
                &route_config,
                &path,
                state.token_cache.clone(),
                auth_header.as_deref(),
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