//! # Database Queries Module
//!
//! This module centralizes all database queries used throughout the Black Gate API Gateway.
//! It provides well-named functions for each database operation, making it easier to
//! maintain and reuse queries across different parts of the application.
//!
//! ## Query Categories
//!
//! - **Route Queries**: Add, update, delete, and list routes
//! - **Metrics Queries**: Fetch request metrics and statistics
//! - **General Queries**: Utility queries for counts and other operations

use sqlx::{sqlite::SqlitePool, Row};
use tracing::info;
use crate::{auth::types::AuthType, health::{HealthCheckMethod, HealthStatus}};

///////////////////////////////////////////////////////////////////////////////
//****                         Route Queries                             ****//
///////////////////////////////////////////////////////////////////////////////

/// Insert or replace a route with all configuration options
pub async fn insert_or_replace_route(
    pool: &SqlitePool,
    path: &str,
    upstream: &str,
    backup_route_path: &str,
    auth_type: &AuthType,
    auth_value: &str,
    allowed_methods: &str,
    oauth_token_url: &str,
    oauth_client_id: &str,
    oauth_client_secret: &str,
    oauth_scope: &str,
    jwt_secret: &str,
    jwt_algorithm: &str,
    jwt_issuer: &str,
    jwt_audience: &str,
    jwt_required_claims: &str,
    rate_limit_per_minute: u32,
    rate_limit_per_hour: u32,
    oidc_issuer: &str,
    oidc_client_id: &str,
    oidc_client_secret: &str,
    oidc_audience: &str,
    oidc_scope: &str,
    health_endpoint: &str,
) -> Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT OR REPLACE INTO routes
        (path, upstream, backup_route_path, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, rate_limit_per_minute, rate_limit_per_hour, oidc_issuer, oidc_client_id, oidc_client_secret, oidc_audience, oidc_scope, health_endpoint)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(path)
    .bind(upstream)
    .bind(backup_route_path)
    .bind(auth_type.to_string())
    .bind(auth_value)
    .bind(allowed_methods)
    .bind(oauth_token_url)
    .bind(oauth_client_id)
    .bind(oauth_client_secret)
    .bind(oauth_scope)
    .bind(jwt_secret)
    .bind(jwt_algorithm)
    .bind(jwt_issuer)
    .bind(jwt_audience)
    .bind(jwt_required_claims)
    .bind(rate_limit_per_minute)
    .bind(rate_limit_per_hour)
    .bind(oidc_issuer)
    .bind(oidc_client_id)
    .bind(oidc_client_secret)
    .bind(oidc_audience)
    .bind(oidc_scope)
    .bind(health_endpoint)
    .execute(pool)
    .await
}

/// Delete a route by path
pub async fn delete_route_by_path(
    pool: &SqlitePool,
    path: &str,
) -> Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error> {
    sqlx::query("DELETE FROM routes WHERE path = ?")
        .bind(path)
        .execute(pool)
        .await
}

/// Fetch all routes with selected fields for listing
pub async fn fetch_all_routes_for_listing(
    pool: &SqlitePool,
) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query("SELECT path, upstream, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, rate_limit_per_minute, rate_limit_per_hour FROM routes")
        .fetch_all(pool)
        .await
}

/// Fetch routes with basic fields for web UI
pub async fn fetch_routes_basic_info(
    pool: &SqlitePool,
) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query(
        "SELECT r.path, r.upstream, r.auth_type, r.rate_limit_per_minute, r.rate_limit_per_hour, h.health_check_status
         FROM routes r
         LEFT JOIN (
             SELECT path, health_check_status,
                    ROW_NUMBER() OVER (PARTITION BY path ORDER BY checked_at DESC) as rn
             FROM route_health_checks
         ) h ON r.path = h.path AND h.rn = 1"
    )
    .fetch_all(pool)
    .await
}

/// Fetch a single route by path with all fields for editing
pub async fn fetch_route_by_path_for_edit(
    pool: &SqlitePool,
    path: &str,
) -> Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query(
        "SELECT path, upstream, backup_route_path, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, oidc_issuer, oidc_client_id, oidc_client_secret, oidc_audience, oidc_scope, rate_limit_per_minute, rate_limit_per_hour, health_endpoint FROM routes WHERE path = ?"
    )
    .bind(path)
    .fetch_optional(pool)
    .await
}

/// Update an existing route by path
pub async fn update_route_by_path(
    pool: &SqlitePool,
    new_path: &str,
    upstream: &str,
    backup_route_path: &str,
    auth_type: &AuthType,
    auth_value: &str,
    allowed_methods: &str,
    oauth_token_url: &str,
    oauth_client_id: &str,
    oauth_client_secret: &str,
    oauth_scope: &str,
    jwt_secret: &str,
    jwt_algorithm: &str,
    jwt_issuer: &str,
    jwt_audience: &str,
    jwt_required_claims: &str,
    oidc_issuer: &str,
    oidc_client_id: &str,
    oidc_client_secret: &str,
    oidc_audience: &str,
    oidc_scope: &str,
    rate_limit_per_minute: u32,
    rate_limit_per_hour: u32,
    health_endpoint: &str,
    original_path: &str,
) -> Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error> {
    sqlx::query(
        "UPDATE routes SET
        path = ?, upstream = ?, backup_route_path = ?, auth_type = ?, auth_value = ?, allowed_methods = ?,
        oauth_token_url = ?, oauth_client_id = ?, oauth_client_secret = ?, oauth_scope = ?,
        jwt_secret = ?, jwt_algorithm = ?, jwt_issuer = ?, jwt_audience = ?, jwt_required_claims = ?,
        oidc_issuer = ?, oidc_client_id = ?, oidc_client_secret = ?, oidc_audience = ?, oidc_scope = ?,
        rate_limit_per_minute = ?, rate_limit_per_hour = ?, health_endpoint = ?
        WHERE path = ?"
    )
    .bind(new_path)
    .bind(upstream)
    .bind(backup_route_path)
    .bind(auth_type.to_string())
    .bind(auth_value)
    .bind(allowed_methods)
    .bind(oauth_token_url)
    .bind(oauth_client_id)
    .bind(oauth_client_secret)
    .bind(oauth_scope)
    .bind(jwt_secret)
    .bind(jwt_algorithm)
    .bind(jwt_issuer)
    .bind(jwt_audience)
    .bind(jwt_required_claims)
    .bind(oidc_issuer)
    .bind(oidc_client_id)
    .bind(oidc_client_secret)
    .bind(oidc_audience)
    .bind(oidc_scope)
    .bind(rate_limit_per_minute)
    .bind(rate_limit_per_hour)
    .bind(health_endpoint)
    .bind(original_path)
    .execute(pool)
    .await
}

/// Get count of all configured routes
pub async fn count_routes(
    pool: &SqlitePool,
) -> Result<i64, sqlx::Error> {
    let row = sqlx::query("SELECT COUNT(*) as count FROM routes")
        .fetch_one(pool)
        .await?;
    Ok(row.get("count"))
}

///////////////////////////////////////////////////////////////////////////////
//****                        Metrics Queries                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Fetch comprehensive metrics statistics
pub async fn fetch_metrics_statistics(
    pool: &SqlitePool,
) -> Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query(
        "SELECT
        COUNT(*) as total_requests,
        AVG(duration_ms) as avg_duration_ms,
        MIN(duration_ms) as min_duration_ms,
        MAX(duration_ms) as max_duration_ms,
        COUNT(CASE WHEN response_status_code >= 200 AND response_status_code < 300 THEN 1 END) as success_count,
        COUNT(CASE WHEN response_status_code >= 400 THEN 1 END) as error_count,
        SUM(request_size_bytes) as total_request_bytes,
        SUM(response_size_bytes) as total_response_bytes
    FROM request_metrics
    WHERE response_timestamp IS NOT NULL"
    )
    .fetch_optional(pool)
    .await
}

/// Fetch basic metrics summary for dashboard
pub async fn fetch_basic_metrics_summary(
    pool: &SqlitePool,
) -> Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query(
        "SELECT
            COUNT(*) as total_requests,
            AVG(duration_ms) as avg_duration_ms,
            COUNT(CASE WHEN response_status_code >= 200 AND response_status_code < 300 THEN 1 END) as success_count
        FROM request_metrics
        WHERE response_timestamp IS NOT NULL"
    )
    .fetch_optional(pool)
    .await
}

/// Fetch recent request metrics with limit
pub async fn fetch_recent_request_metrics(
    pool: &SqlitePool,
    limit: i32,
) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query(
        "SELECT id, path, method, request_timestamp, duration_ms, response_status_code,
            request_size_bytes, response_size_bytes, upstream_url, auth_type, error_message
     FROM request_metrics
     ORDER BY request_timestamp DESC
     LIMIT ?"
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Fetch recent requests with basic fields for dashboard
pub async fn fetch_recent_requests_for_dashboard(
    pool: &SqlitePool,
    limit: i32,
) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query(
        "SELECT path, method, request_timestamp, duration_ms, response_status_code
         FROM request_metrics
         ORDER BY request_timestamp DESC
         LIMIT ?"
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

///////////////////////////////////////////////////////////////////////////////
//****                      Routing Queries                              ****//
///////////////////////////////////////////////////////////////////////////////

/// Fetch route configuration by path for request routing
pub async fn fetch_route_config_by_path(
    pool: &SqlitePool,
    path: &str,
) -> Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query("SELECT upstream, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, oidc_issuer, oidc_client_id, oidc_client_secret, oidc_audience, oidc_scope, rate_limit_per_minute, rate_limit_per_hour FROM routes WHERE path = ?")
        .bind(path)
        .fetch_optional(pool)
        .await
}

///////////////////////////////////////////////////////////////////////////////
//****                      Metrics Storage Queries                      ****//
///////////////////////////////////////////////////////////////////////////////

/// Store request metrics in the database
pub async fn store_request_metrics(
    pool: &SqlitePool,
    id: &str,
    path: &str,
    method: &str,
    request_timestamp: &str,
    response_timestamp: Option<&str>,
    duration_ms: Option<i64>,
    request_size_bytes: i64,
    response_size_bytes: Option<i64>,
    response_status_code: Option<u16>,
    upstream_url: &str,
    auth_type: &str,
    client_ip: &str,
    user_agent: &str,
    error_message: Option<&str>,
) -> Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO request_metrics (
            id, path, method, request_timestamp, response_timestamp, duration_ms,
            request_size_bytes, response_size_bytes, response_status_code,
            upstream_url, auth_type, client_ip, user_agent, error_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(path)
    .bind(method)
    .bind(request_timestamp)
    .bind(response_timestamp)
    .bind(duration_ms)
    .bind(request_size_bytes)
    .bind(response_size_bytes)
    .bind(response_status_code)
    .bind(upstream_url)
    .bind(auth_type)
    .bind(client_ip)
    .bind(user_agent)
    .bind(error_message)
    .execute(pool)
    .await
}

///////////////////////////////////////////////////////////////////////////////
//****                      Health Check Queries                         ****//
///////////////////////////////////////////////////////////////////////////////

/// Clear health status for a route by setting it to "Unknown"
pub async fn clear_route_health_status(
    pool: &SqlitePool,
    path: &str,
) -> Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error> {
    info!("Clearing health status for route: {}", path);

    // Use INSERT OR REPLACE to handle both insert and update in one query
    sqlx::query(
        "INSERT OR REPLACE INTO route_health_checks (path, health_check_status, checked_at, method_used)
        VALUES (?, ?, datetime('now'), ?)"
    )
    .bind(path)
    .bind(HealthStatus::Unknown.to_string())
    .bind(HealthCheckMethod::Manual.to_string())
    .execute(pool)
    .await
}

///////////////////////////////////////////////////////////////////////////////
//****                        Settings Queries                           ****//
///////////////////////////////////////////////////////////////////////////////

pub fn get_setting_by_key(
    pool: &SqlitePool,
    key: &str,
) -> Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            sqlx::query("SELECT key, value, description, created_at, updated_at FROM settings WHERE key = ?")
                .bind(key)
                .fetch_optional(pool)
                .await
        })
    })
}

pub async fn get_all_settings(pool: &SqlitePool) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query("SELECT key, value, description, created_at, updated_at FROM settings ORDER BY key")
        .fetch_all(pool)
        .await
}