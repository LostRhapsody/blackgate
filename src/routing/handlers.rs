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

use crate::{
    AppState,
    auth::{apply_authentication, types::AuthType},
    cache::{CachedResponse, UpstreamResponseCacheKey},
    database::queries,
    health::HealthStatus,
    metrics::{RequestMetrics, store_metrics},
    rate_limiter::check_rate_limit,
};
use axum::{
    extract::OriginalUri,
    http::{HeaderMap, Method},
};
use sqlx::Row;
use tokio::time::Instant;
use tracing::{error, info, warn};

///////////////////////////////////////////////////////////////////////////////
//****                         Public Structs                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Route configuration structure to hold authentication details, shared between handlers and routes
/// Note: There are quite a few fields we don't really use here, but they are required so we can
/// cache the RouteConfig and avoid additional database queries.
#[derive(Debug, Clone)]
pub struct RouteConfig {
    pub upstream: String,
    pub auth_type: AuthType,
    pub auth_value: Option<String>,
    pub allowed_methods: String,
    pub rate_limit_per_minute: i64,
    pub rate_limit_per_hour: i64,
    pub backup_path: Option<String>,
    pub collection_id: Option<i64>,
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
    // Collection auth fields
    pub default_auth_type: Option<String>,
    pub default_auth_value: Option<String>,
    pub default_oauth_token_url: Option<String>,
    pub default_oauth_client_id: Option<String>,
    pub default_oauth_client_secret: Option<String>,
    pub default_oauth_scope: Option<String>,
    pub default_jwt_secret: Option<String>,
    pub default_jwt_algorithm: Option<String>,
    pub default_jwt_issuer: Option<String>,
    pub default_jwt_audience: Option<String>,
    pub default_jwt_required_claims: Option<String>,
    pub default_oidc_issuer: Option<String>,
    pub default_oidc_client_id: Option<String>,
    pub default_oidc_client_secret: Option<String>,
    pub default_oidc_audience: Option<String>,
    pub default_oidc_scope: Option<String>,
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            upstream: "http://test.example.com".to_string(),
            auth_type: AuthType::Jwt,
            auth_value: None,
            allowed_methods: "GET,POST,PUT,PATCH,DELETE,HEAD".to_string(),
            rate_limit_per_minute: 0,
            rate_limit_per_hour: 0,
            backup_path: None,
            collection_id: None,
            oauth_token_url: None,
            oauth_client_id: None,
            oauth_client_secret: None,
            oauth_scope: None,
            jwt_secret: Some("secret123".to_string()),
            jwt_algorithm: Some("HS256".to_string()),
            jwt_issuer: Some("example.com".to_string()),
            jwt_audience: Some("example.com".to_string()),
            jwt_required_claims: Some("sub".to_string()),
            oidc_issuer: Some("https://example.com".to_string()),
            oidc_client_id: Some("client_id".to_string()),
            oidc_client_secret: Some("client_secret".to_string()),
            oidc_audience: Some("example.com".to_string()),
            oidc_scope: Some("openid profile email".to_string()),
            default_auth_type: None,
            default_auth_value: None,
            default_oauth_token_url: None,
            default_oauth_client_id: None,
            default_oauth_client_secret: None,
            default_oauth_scope: None,
            default_jwt_secret: Some("secret123".to_string()),
            default_jwt_algorithm: Some("HS256".to_string()),
            default_jwt_issuer: Some("example.com".to_string()),
            default_jwt_audience: Some("example.com".to_string()),
            default_jwt_required_claims: Some("sub".to_string()),
            default_oidc_issuer: Some("https://example.com".to_string()),
            default_oidc_client_id: Some("client_id".to_string()),
            default_oidc_client_secret: Some("client_secret".to_string()),
            default_oidc_audience: Some("example.com".to_string()),
            default_oidc_scope: Some("openid profile email".to_string()),
        }
    }
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
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok().map(|s| s.to_string()));
    handle_request_core(
        state,
        Method::GET,
        uri.path().to_string(),
        None,
        auth_header,
    )
    .await
}

/// Handles HEAD requests
pub async fn handle_head_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> axum::response::Response {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok().map(|s| s.to_string()));
    handle_request_core(
        state,
        Method::HEAD,
        uri.path().to_string(),
        None,
        auth_header,
    )
    .await
}

/// Handles DELETE requests
pub async fn handle_delete_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> axum::response::Response {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok().map(|s| s.to_string()));
    handle_request_core(
        state,
        Method::DELETE,
        uri.path().to_string(),
        None,
        auth_header,
    )
    .await
}

/// Handles POST requests
pub async fn handle_post_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    payload: axum::body::Bytes,
) -> axum::response::Response {
    let body_string = String::from_utf8_lossy(&payload).to_string();
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok().map(|s| s.to_string()));
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
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok().map(|s| s.to_string()));
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
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok().map(|s| s.to_string()));
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
    );

    // Generate cache key from request
    let cache_key = UpstreamResponseCacheKey::new(
        &path,
        method.as_str(),
        None, // TODO: Parse query params if needed
        body.as_ref().map(|b| b.as_bytes()),
    );

    info!("cache key: {}", cache_key);

    // Check cache for existing response
    if let Some(cached) = state.response_cache.get(&cache_key).await {
        info!(
            request_id = %metrics.id,
            path = %path,
            "Serving response from cache"
        );

        // Update metrics for cache hit
        metrics.cache_hit = true;
        store_metrics(state.db.clone(), metrics);

        // Convert cached response back to axum response
        return convert_cached_response(cached);
    } else {
        info!(
            request_id = %metrics.id,
            path = %path,
            "Cache miss"
        );
    }

    // Get route configuration from cache or database
    let route_config = match get_cached_route_config(&state, &path).await {
        Some(config) => config,
        None => {
            warn!(
                request_id = %metrics.id,
                path = %path,
                "Route not found"
            );

            metrics.set_error("Route not found".to_string());
            store_metrics(state.db.clone(), metrics);

            return axum::response::Response::builder()
                .status(404)
                .body(axum::body::Body::from("No route found"))
                .unwrap();
        }
    };

    // check if method is allowed
    if !is_method_allowed(&method, &route_config.allowed_methods) {
        warn!(
            request_id = %metrics.id,
            method = %method,
            path = %path,
            allowed_methods = %route_config.allowed_methods,
            "Method not allowed"
        );

        metrics.set_error("Method Not Allowed".to_string());
        store_metrics(state.db.clone(), metrics);

        return axum::response::Response::builder()
            .status(405)
            .body(axum::body::Body::from("Method Not Allowed"))
            .unwrap();
    }

    // Check rate limits. If both limits are 0, skip rate limiting
    if route_config.rate_limit_per_minute > 0 || route_config.rate_limit_per_hour > 0 {
        if let Err(response) = check_rate_limit(
            &path,
            route_config.rate_limit_per_minute,
            route_config.rate_limit_per_hour,
            state.rate_limiter.clone(),
            &mut metrics,
        )
        .await
        {
            store_metrics(state.db.clone(), metrics);
            return response;
        }
    }

    // Check route health status for the backup route fallback using cache
    let current_route = route_config;

    // Try to get health status from cache (fast, non-blocking)
    let primary_health_status = state
        .health_checker
        .get_cached_health_status(&path)
        .await
        .unwrap_or(HealthStatus::Unknown); // Default to Unknown if not cached

    // Try to get a healthy route (either the primary or backup)
    let route_config = if primary_health_status == HealthStatus::Unhealthy {
        // If primary route is unhealthy, check for backup route
        warn!(
            request_id = %metrics.id,
            path = %path,
            "Primary route is unhealthy, checking for backup route"
        );

        // Check if this route has a backup_route_path configured
        let backup_route_path: String = current_route.backup_path.clone().unwrap_or_default();
        if !backup_route_path.is_empty() {
            // backup is configured, attempt to use it
            info!(
                request_id = %metrics.id,
                path = %path,
                backup_path = %backup_route_path,
                "Attempting to use backup route"
            );

            // Fetch the backup route configuration
            match get_cached_route_config(&state, &backup_route_path).await {
                Some(backup_route) => {
                    // Check if backup route is healthy (from cache)
                    let backup_health_status = state
                        .health_checker
                        .get_cached_health_status(&backup_route_path)
                        .await
                        .unwrap_or(HealthStatus::Unknown); // Default to Unknown if not cached

                    if backup_health_status == HealthStatus::Healthy {
                        // backup is healthy, switch to it
                        info!(
                            request_id = %metrics.id,
                            path = %path,
                            backup_path = %backup_route_path,
                            "Backup route is healthy, switching to backup"
                        );
                        metrics.path = backup_route_path.clone();
                        backup_route
                    } else if backup_health_status == HealthStatus::Unhealthy {
                        // backup is unhealthy, log it and use the primary route
                        warn!(
                            request_id = %metrics.id,
                            path = %path,
                            backup_path = %backup_route_path,
                            "Backup route is also unhealthy, using primary anyway"
                        );
                        current_route
                    } else {
                        // backup health status is unknown, use backup anyway (fallback)
                        info!(
                            request_id = %metrics.id,
                            path = %path,
                            backup_path = %backup_route_path,
                            "Backup route health status unknown, using backup anyway"
                        );
                        metrics.path = backup_route_path.clone();
                        backup_route
                    }
                }
                None => {
                    // if backup route is not found in the database, log it and use the primary route
                    error!(
                        request_id = %metrics.id,
                        path = %path,
                        backup_path = %backup_route_path,
                        "Backup route not found in database, using unhealthy primary"
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
        // Primary route is healthy, unknown, or unavailable - use it
        if primary_health_status != HealthStatus::Unknown {
            info!(
                request_id = %metrics.id,
                path = %path,
                health_status = %primary_health_status.to_string(),
                "Primary route health check passed (from cache)"
            );
        } else {
            info!(
                request_id = %metrics.id,
                path = %path,
                "No cached health status for primary route, using primary anyway"
            );
        }
        current_route
    };

    // Determine final authentication configuration
    // Check if route uses collection authentication (route auth is None and has collection)
    let use_collection_auth =
        route_config.auth_type == AuthType::None && route_config.collection_id.is_some();

    let (
        final_auth_type,
        final_auth_value,
        final_oauth_token_url,
        final_oauth_client_id,
        final_oauth_client_secret,
        final_oauth_scope,
        final_jwt_secret,
        final_jwt_algorithm,
        final_jwt_issuer,
        final_jwt_audience,
        final_jwt_required_claims,
        final_oidc_issuer,
        final_oidc_client_id,
        final_oidc_client_secret,
        final_oidc_audience,
        final_oidc_scope,
    ) = if use_collection_auth {
        // Use collection defaults
        info!(
            request_id = %metrics.id,
            path = %path,
            collection_id = route_config.collection_id.unwrap_or(0),
            "Using collection authentication for route"
        );

        let collection_auth_type_str = route_config.default_auth_type.as_deref().unwrap_or("none");
        (
            AuthType::from_str(collection_auth_type_str),
            route_config.default_auth_value.clone(),
            route_config.default_oauth_token_url.clone(),
            route_config.default_oauth_client_id.clone(),
            route_config.default_oauth_client_secret.clone(),
            route_config.default_oauth_scope.clone(),
            route_config.default_jwt_secret.clone(),
            route_config.default_jwt_algorithm.clone(),
            route_config.default_jwt_issuer.clone(),
            route_config.default_jwt_audience.clone(),
            route_config.default_jwt_required_claims.clone(),
            route_config.default_oidc_issuer.clone(),
            route_config.default_oidc_client_id.clone(),
            route_config.default_oidc_client_secret.clone(),
            route_config.default_oidc_audience.clone(),
            route_config.default_oidc_scope.clone(),
        )
    } else {
        // Use route-specific auth
        (
            route_config.auth_type.clone(),
            route_config.auth_value.clone(),
            route_config.oauth_token_url.clone(),
            route_config.oauth_client_id.clone(),
            route_config.oauth_client_secret.clone(),
            route_config.oauth_scope.clone(),
            route_config.jwt_secret.clone(),
            route_config.jwt_algorithm.clone(),
            route_config.jwt_issuer.clone(),
            route_config.jwt_audience.clone(),
            route_config.jwt_required_claims.clone(),
            route_config.oidc_issuer.clone(),
            route_config.oidc_client_id.clone(),
            route_config.oidc_client_secret.clone(),
            route_config.oidc_audience.clone(),
            route_config.oidc_scope.clone(),
        )
    };

    // Create simplified route config for authentication
    let auth_route_config = RouteConfig {
        upstream: route_config.upstream.clone(),
        auth_type: final_auth_type,
        auth_value: final_auth_value,
        allowed_methods: route_config.allowed_methods.clone(),
        rate_limit_per_minute: route_config.rate_limit_per_minute,
        rate_limit_per_hour: route_config.rate_limit_per_hour,
        backup_path: route_config.backup_path.clone(),
        collection_id: route_config.collection_id,
        oauth_token_url: final_oauth_token_url,
        oauth_client_id: final_oauth_client_id,
        oauth_client_secret: final_oauth_client_secret,
        oauth_scope: final_oauth_scope,
        jwt_secret: final_jwt_secret,
        jwt_algorithm: final_jwt_algorithm,
        jwt_issuer: final_jwt_issuer,
        jwt_audience: final_jwt_audience,
        jwt_required_claims: final_jwt_required_claims,
        oidc_issuer: final_oidc_issuer,
        oidc_client_id: final_oidc_client_id,
        oidc_client_secret: final_oidc_client_secret,
        oidc_audience: final_oidc_audience,
        oidc_scope: final_oidc_scope,
        // Copy over the default values (not used for auth but needed for struct)
        default_auth_type: route_config.default_auth_type,
        default_auth_value: route_config.default_auth_value,
        default_oauth_token_url: route_config.default_oauth_token_url,
        default_oauth_client_id: route_config.default_oauth_client_id,
        default_oauth_client_secret: route_config.default_oauth_client_secret,
        default_oauth_scope: route_config.default_oauth_scope,
        default_jwt_secret: route_config.default_jwt_secret,
        default_jwt_algorithm: route_config.default_jwt_algorithm,
        default_jwt_issuer: route_config.default_jwt_issuer,
        default_jwt_audience: route_config.default_jwt_audience,
        default_jwt_required_claims: route_config.default_jwt_required_claims,
        default_oidc_issuer: route_config.default_oidc_issuer,
        default_oidc_client_id: route_config.default_oidc_client_id,
        default_oidc_client_secret: route_config.default_oidc_client_secret,
        default_oidc_audience: route_config.default_oidc_audience,
        default_oidc_scope: route_config.default_oidc_scope,
    };

    info!(
        request_id = %metrics.id,
        upstream = %route_config.upstream,
        auth_type = %route_config.auth_type.to_string(),
        "Routing to upstream"
    );

    // Use the pooled HTTP client
    let builder = state
        .http_client
        .request(method.clone(), &auth_route_config.upstream);

    // Apply authentication
    let builder = match apply_authentication(
        builder,
        &auth_route_config,
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
            store_metrics(state.db.clone(), metrics);

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
                upstream = %auth_route_config.upstream,
                error = %e,
                "Upstream request failed"
            );

            metrics.set_error(format!("Upstream request failed: {}", e));
            store_metrics(state.db.clone(), metrics);

            return axum::response::Response::builder()
                .status(502)
                .body(axum::body::Body::from("Bad Gateway"))
                .unwrap();
        }
    };

    let upstream_duration = upstream_start.elapsed();
    let response_status = response.status();
    let response_headers = response.headers().clone();
    let response_body = match response.text().await {
        Ok(body) => body,
        Err(e) => {
            error!(
                request_id = %metrics.id,
                error = %e,
                "Failed to read response body"
            );

            metrics.set_error(format!("Failed to read response body: {}", e));
            store_metrics(state.db.clone(), metrics);

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
        Some(auth_route_config.upstream.clone()),
        auth_route_config.auth_type.to_string().to_string(),
    );

    info!(
        request_id = %metrics.id,
        response_status = response_status.as_u16(),
        response_size_bytes = response_size,
        upstream_duration_ms = upstream_duration.as_millis(),
        total_duration_ms = metrics.duration_ms.unwrap_or(0),
        "Request completed successfully"
    );

    // Store metrics in database asynchronously (non-blocking)
    store_metrics(state.db.clone(), metrics);

    // Cache successful responses (2xx status codes)
    if response_status.is_success() {
        info!("Caching response for {} {}", method, path);

        let response_body_bytes = response_body.as_bytes().to_vec();

        // Spawn a task to cache the response asynchronously
        let cache = state.response_cache.clone();
        let cache_key = cache_key.clone();

        tokio::spawn(async move {
            // Only cache if the response is not too large (e.g., < 10MB)
            const MAX_CACHE_SIZE: usize = 10 * 1024 * 1024; // 10MB
            if response_body_bytes.len() < MAX_CACHE_SIZE {
                cache
                    .set(
                        cache_key,
                        response_status,
                        response_headers,
                        response_body_bytes,
                    )
                    .await;
                info!("Response cached for {} {}", method, path);
            } else {
                warn!(
                    "Response too large to cache ({} bytes)",
                    response_body_bytes.len()
                );
            }
        });
    }

    // Return the response to the client
    axum::response::Response::builder()
        .status(response_status)
        .body(response_body.into())
        .unwrap()
}

///////////////////////////////////////////////////////////////////////////////
//****                     Route Caching Functions                       ****//
///////////////////////////////////////////////////////////////////////////////

/// Build RouteConfig from a database row
fn build_route_config_from_row(row: &sqlx::sqlite::SqliteRow) -> RouteConfig {
    RouteConfig {
        upstream: row.get("upstream"),
        auth_type: AuthType::from_str(&row.get::<String, _>("auth_type")),
        auth_value: row.get("auth_value"),
        allowed_methods: row.get("allowed_methods"),
        rate_limit_per_minute: row.get("rate_limit_per_minute"),
        rate_limit_per_hour: row.get("rate_limit_per_hour"),
        backup_path: {
            let backup_path: String = row.get("backup_route_path");
            if backup_path.is_empty() {
                None
            } else {
                Some(backup_path)
            }
        },
        collection_id: row.get("collection_id"),
        oauth_token_url: row.get("oauth_token_url"),
        oauth_client_id: row.get("oauth_client_id"),
        oauth_client_secret: row.get("oauth_client_secret"),
        oauth_scope: row.get("oauth_scope"),
        jwt_secret: row.get("jwt_secret"),
        jwt_algorithm: row.get("jwt_algorithm"),
        jwt_issuer: row.get("jwt_issuer"),
        jwt_audience: row.get("jwt_audience"),
        jwt_required_claims: row.get("jwt_required_claims"),
        oidc_issuer: row.get("oidc_issuer"),
        oidc_client_id: row.get("oidc_client_id"),
        oidc_client_secret: row.get("oidc_client_secret"),
        oidc_audience: row.get("oidc_audience"),
        oidc_scope: row.get("oidc_scope"),
        default_auth_type: row.get("default_auth_type"),
        default_auth_value: row.get("default_auth_value"),
        default_oauth_token_url: row.get("default_oauth_token_url"),
        default_oauth_client_id: row.get("default_oauth_client_id"),
        default_oauth_client_secret: row.get("default_oauth_client_secret"),
        default_oauth_scope: row.get("default_oauth_scope"),
        default_jwt_secret: row.get("default_jwt_secret"),
        default_jwt_algorithm: row.get("default_jwt_algorithm"),
        default_jwt_issuer: row.get("default_jwt_issuer"),
        default_jwt_audience: row.get("default_jwt_audience"),
        default_jwt_required_claims: row.get("default_jwt_required_claims"),
        default_oidc_issuer: row.get("default_oidc_issuer"),
        default_oidc_client_id: row.get("default_oidc_client_id"),
        default_oidc_client_secret: row.get("default_oidc_client_secret"),
        default_oidc_audience: row.get("default_oidc_audience"),
        default_oidc_scope: row.get("default_oidc_scope"),
    }
}

/// Get route configuration from cache or database
async fn get_cached_route_config(state: &AppState, path: &str) -> Option<RouteConfig> {
    // Try cache first
    {
        let cache = state.route_cache.read().await;
        if let Some(config) = cache.get(path) {
            return Some(config.clone());
        }
    }

    // Cache miss - load from database and cache result
    load_and_cache_route_config(state, path).await
}

/// Load route config from database and cache it
async fn load_and_cache_route_config(state: &AppState, path: &str) -> Option<RouteConfig> {
    match queries::fetch_route_config_with_collection_by_path(&state.db, path).await {
        Ok(Some(row)) => {
            let config = build_route_config_from_row(&row);

            // Cache the result
            {
                let mut cache = state.route_cache.write().await;
                cache.insert(path.to_string(), config.clone());
            }

            Some(config)
        }
        Ok(None) => None,
        Err(e) => {
            error!("Database query failed for path {}: {}", path, e);
            None
        }
    }
}

/// Check if HTTP method is allowed for the route
fn is_method_allowed(method: &Method, allowed_methods: &str) -> bool {
    // If allowed_methods is empty, all methods are allowed
    if allowed_methods.is_empty() || method.as_str() == "HEAD" {
        return true;
    }

    let allowed_methods: Vec<&str> = allowed_methods.split(',').collect();
    allowed_methods.contains(&method.as_str())
}

/// Convert a CachedResponse back to an Axum response
fn convert_cached_response(cached: CachedResponse) -> axum::response::Response {
    let mut response = axum::response::Response::builder().status(cached.status);

    // Add all headers from the cached response
    let response_headers = response.headers_mut().unwrap();
    for (key, value) in cached.headers.iter() {
        if let Ok(value_str) = value.to_str() {
            if let Ok(header_value) = axum::http::HeaderValue::from_str(value_str) {
                response_headers.insert(key, header_value);
            }
        }
    }

    // Add cache hit header
    response_headers.insert("X-Cache", "HIT".parse().unwrap());

    // Set the response body
    response.body(axum::body::Body::from(cached.body)).unwrap()
}

///////////////////////////////////////////////////////////////////////////////
//****                              Tests                                ****//
///////////////////////////////////////////////////////////////////////////////
// Tests for these are handled in the tests module for now
