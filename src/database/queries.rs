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
    collection_id: Option<i64>,
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
        (path, upstream, backup_route_path, collection_id, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, rate_limit_per_minute, rate_limit_per_hour, oidc_issuer, oidc_client_id, oidc_client_secret, oidc_audience, oidc_scope, health_endpoint)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(path)
    .bind(upstream)
    .bind(backup_route_path)
    .bind(collection_id)
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
        "SELECT path, upstream, backup_route_path, collection_id, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, oidc_issuer, oidc_client_id, oidc_client_secret, oidc_audience, oidc_scope, rate_limit_per_minute, rate_limit_per_hour, health_endpoint FROM routes WHERE path = ?"
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
    collection_id: Option<i64>,
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
        path = ?, upstream = ?, backup_route_path = ?, collection_id = ?, auth_type = ?, auth_value = ?, allowed_methods = ?,
        oauth_token_url = ?, oauth_client_id = ?, oauth_client_secret = ?, oauth_scope = ?,
        jwt_secret = ?, jwt_algorithm = ?, jwt_issuer = ?, jwt_audience = ?, jwt_required_claims = ?,
        oidc_issuer = ?, oidc_client_id = ?, oidc_client_secret = ?, oidc_audience = ?, oidc_scope = ?,
        rate_limit_per_minute = ?, rate_limit_per_hour = ?, health_endpoint = ?
        WHERE path = ?"
    )
    .bind(new_path)
    .bind(upstream)
    .bind(backup_route_path)
    .bind(collection_id)
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
    sqlx::query("SELECT upstream, backup_route_path, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, oidc_issuer, oidc_client_id, oidc_client_secret, oidc_audience, oidc_scope, rate_limit_per_minute, rate_limit_per_hour FROM routes WHERE path = ?")
        .bind(path)
        .fetch_optional(pool)
        .await
}

/// Fetch route configuration by path for request routing, including collection defaults
pub async fn fetch_route_config_with_collection_by_path(
    pool: &SqlitePool,
    path: &str,
) -> Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query("
        SELECT 
            r.upstream, 
            r.backup_route_path, 
            r.auth_type, 
            r.auth_value, 
            r.allowed_methods, 
            r.oauth_token_url, 
            r.oauth_client_id, 
            r.oauth_client_secret, 
            r.oauth_scope, 
            r.jwt_secret, 
            r.jwt_algorithm, 
            r.jwt_issuer, 
            r.jwt_audience, 
            r.jwt_required_claims, 
            r.oidc_issuer, 
            r.oidc_client_id, 
            r.oidc_client_secret, 
            r.oidc_audience, 
            r.oidc_scope, 
            r.rate_limit_per_minute, 
            r.rate_limit_per_hour,
            r.collection_id,
            c.default_auth_type,
            c.default_auth_value,
            c.default_oauth_token_url,
            c.default_oauth_client_id,
            c.default_oauth_client_secret,
            c.default_oauth_scope,
            c.default_jwt_secret,
            c.default_jwt_algorithm,
            c.default_jwt_issuer,
            c.default_jwt_audience,
            c.default_jwt_required_claims,
            c.default_oidc_issuer,
            c.default_oidc_client_id,
            c.default_oidc_client_secret,
            c.default_oidc_audience,
            c.default_oidc_scope
        FROM routes r 
        LEFT JOIN route_collections c ON r.collection_id = c.id 
        WHERE r.path = ?")
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

///////////////////////////////////////////////////////////////////////////////
//****                    Route Collections Queries                      ****//
///////////////////////////////////////////////////////////////////////////////

/// Fetch all route collections
pub async fn fetch_all_route_collections(
    pool: &SqlitePool,
) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query("SELECT id, name, description, default_auth_type, default_rate_limit_per_minute, default_rate_limit_per_hour, created_at FROM route_collections ORDER BY name")
        .fetch_all(pool)
        .await
}

/// Fetch a single route collection by ID
pub async fn fetch_route_collection_by_id(
    pool: &SqlitePool,
    collection_id: i64,
) -> Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query("SELECT * FROM route_collections WHERE id = ?")
        .bind(collection_id)
        .fetch_optional(pool)
        .await
}

/// Fetch a single route collection by name
#[allow(dead_code)]
pub async fn fetch_route_collection_by_name(
    pool: &SqlitePool,
    name: &str,
) -> Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query("SELECT * FROM route_collections WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await
}

/// Insert a new route collection
pub async fn insert_route_collection(
    pool: &SqlitePool,
    name: &str,
    description: &str,
    default_auth_type: &AuthType,
    default_auth_value: &str,
    default_oauth_token_url: &str,
    default_oauth_client_id: &str,
    default_oauth_client_secret: &str,
    default_oauth_scope: &str,
    default_jwt_secret: &str,
    default_jwt_algorithm: &str,
    default_jwt_issuer: &str,
    default_jwt_audience: &str,
    default_jwt_required_claims: &str,
    default_oidc_issuer: &str,
    default_oidc_client_id: &str,
    default_oidc_client_secret: &str,
    default_oidc_audience: &str,
    default_oidc_scope: &str,
    default_rate_limit_per_minute: u32,
    default_rate_limit_per_hour: u32,
) -> Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO route_collections (
            name, description, default_auth_type, default_auth_value,
            default_oauth_token_url, default_oauth_client_id, default_oauth_client_secret, default_oauth_scope,
            default_jwt_secret, default_jwt_algorithm, default_jwt_issuer, default_jwt_audience, default_jwt_required_claims,
            default_oidc_issuer, default_oidc_client_id, default_oidc_client_secret, default_oidc_audience, default_oidc_scope,
            default_rate_limit_per_minute, default_rate_limit_per_hour
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(name)
    .bind(description)
    .bind(default_auth_type.to_string())
    .bind(default_auth_value)
    .bind(default_oauth_token_url)
    .bind(default_oauth_client_id)
    .bind(default_oauth_client_secret)
    .bind(default_oauth_scope)
    .bind(default_jwt_secret)
    .bind(default_jwt_algorithm)
    .bind(default_jwt_issuer)
    .bind(default_jwt_audience)
    .bind(default_jwt_required_claims)
    .bind(default_oidc_issuer)
    .bind(default_oidc_client_id)
    .bind(default_oidc_client_secret)
    .bind(default_oidc_audience)
    .bind(default_oidc_scope)
    .bind(default_rate_limit_per_minute)
    .bind(default_rate_limit_per_hour)
    .execute(pool)
    .await
}

/// Insert a new route collection and return the collection ID
pub async fn insert_route_collection_with_id(
    pool: &SqlitePool,
    name: &str,
    description: &str,
    default_auth_type: &AuthType,
    default_auth_value: &str,
    default_oauth_token_url: &str,
    default_oauth_client_id: &str,
    default_oauth_client_secret: &str,
    default_oauth_scope: &str,
    default_jwt_secret: &str,
    default_jwt_algorithm: &str,
    default_jwt_issuer: &str,
    default_jwt_audience: &str,
    default_jwt_required_claims: &str,
    default_oidc_issuer: &str,
    default_oidc_client_id: &str,
    default_oidc_client_secret: &str,
    default_oidc_audience: &str,
    default_oidc_scope: &str,
    default_rate_limit_per_minute: u32,
    default_rate_limit_per_hour: u32,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO route_collections (
            name, description, default_auth_type, default_auth_value,
            default_oauth_token_url, default_oauth_client_id, default_oauth_client_secret, default_oauth_scope,
            default_jwt_secret, default_jwt_algorithm, default_jwt_issuer, default_jwt_audience, default_jwt_required_claims,
            default_oidc_issuer, default_oidc_client_id, default_oidc_client_secret, default_oidc_audience, default_oidc_scope,
            default_rate_limit_per_minute, default_rate_limit_per_hour
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(name)
    .bind(description)
    .bind(default_auth_type.to_string())
    .bind(default_auth_value)
    .bind(default_oauth_token_url)
    .bind(default_oauth_client_id)
    .bind(default_oauth_client_secret)
    .bind(default_oauth_scope)
    .bind(default_jwt_secret)
    .bind(default_jwt_algorithm)
    .bind(default_jwt_issuer)
    .bind(default_jwt_audience)
    .bind(default_jwt_required_claims)
    .bind(default_oidc_issuer)
    .bind(default_oidc_client_id)
    .bind(default_oidc_client_secret)
    .bind(default_oidc_audience)
    .bind(default_oidc_scope)
    .bind(default_rate_limit_per_minute)
    .bind(default_rate_limit_per_hour)
    .execute(pool)
    .await?;
    
    Ok(result.last_insert_rowid())
}

/// Update a route collection
pub async fn update_route_collection(
    pool: &SqlitePool,
    collection_id: i64,
    name: &str,
    description: &str,
    default_auth_type: &AuthType,
    default_auth_value: &str,
    default_oauth_token_url: &str,
    default_oauth_client_id: &str,
    default_oauth_client_secret: &str,
    default_oauth_scope: &str,
    default_jwt_secret: &str,
    default_jwt_algorithm: &str,
    default_jwt_issuer: &str,
    default_jwt_audience: &str,
    default_jwt_required_claims: &str,
    default_oidc_issuer: &str,
    default_oidc_client_id: &str,
    default_oidc_client_secret: &str,
    default_oidc_audience: &str,
    default_oidc_scope: &str,
    default_rate_limit_per_minute: u32,
    default_rate_limit_per_hour: u32,
) -> Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error> {
    sqlx::query(
        "UPDATE route_collections SET
            name = ?, description = ?, default_auth_type = ?, default_auth_value = ?,
            default_oauth_token_url = ?, default_oauth_client_id = ?, default_oauth_client_secret = ?, default_oauth_scope = ?,
            default_jwt_secret = ?, default_jwt_algorithm = ?, default_jwt_issuer = ?, default_jwt_audience = ?, default_jwt_required_claims = ?,
            default_oidc_issuer = ?, default_oidc_client_id = ?, default_oidc_client_secret = ?, default_oidc_audience = ?, default_oidc_scope = ?,
            default_rate_limit_per_minute = ?, default_rate_limit_per_hour = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?"
    )
    .bind(name)
    .bind(description)
    .bind(default_auth_type.to_string())
    .bind(default_auth_value)
    .bind(default_oauth_token_url)
    .bind(default_oauth_client_id)
    .bind(default_oauth_client_secret)
    .bind(default_oauth_scope)
    .bind(default_jwt_secret)
    .bind(default_jwt_algorithm)
    .bind(default_jwt_issuer)
    .bind(default_jwt_audience)
    .bind(default_jwt_required_claims)
    .bind(default_oidc_issuer)
    .bind(default_oidc_client_id)
    .bind(default_oidc_client_secret)
    .bind(default_oidc_audience)
    .bind(default_oidc_scope)
    .bind(default_rate_limit_per_minute)
    .bind(default_rate_limit_per_hour)
    .bind(collection_id)
    .execute(pool)
    .await
}

/// Delete a route collection
pub async fn delete_route_collection(
    pool: &SqlitePool,
    collection_id: i64,
) -> Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error> {
    sqlx::query("DELETE FROM route_collections WHERE id = ?")
        .bind(collection_id)
        .execute(pool)
        .await
}

/// Fetch routes grouped by collection
#[allow(dead_code)]
pub async fn fetch_routes_by_collection(
    pool: &SqlitePool,
) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query(
        "SELECT 
            r.path, r.upstream, r.auth_type, r.rate_limit_per_minute, r.rate_limit_per_hour,
            r.collection_id,
            c.name as collection_name,
            c.description as collection_description,
            h.health_check_status
         FROM routes r
         LEFT JOIN route_collections c ON r.collection_id = c.id
         LEFT JOIN (
             SELECT path, health_check_status,
                    ROW_NUMBER() OVER (PARTITION BY path ORDER BY checked_at DESC) as rn
             FROM route_health_checks
         ) h ON r.path = h.path AND h.rn = 1
         ORDER BY c.name, r.path"
    )
    .fetch_all(pool)
    .await
}

/// Fetch routes for a specific collection
pub async fn fetch_routes_in_collection(
    pool: &SqlitePool,
    collection_id: i64,
) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query(
        "SELECT r.path, r.upstream, r.auth_type, r.rate_limit_per_minute, r.rate_limit_per_hour,
                h.health_check_status
         FROM routes r
         LEFT JOIN (
             SELECT path, health_check_status,
                    ROW_NUMBER() OVER (PARTITION BY path ORDER BY checked_at DESC) as rn
             FROM route_health_checks
         ) h ON r.path = h.path AND h.rn = 1
         WHERE r.collection_id = ?
         ORDER BY r.path"
    )
    .bind(collection_id)
    .fetch_all(pool)
    .await
}

/// Assign a route to a collection
#[allow(dead_code)]
pub async fn assign_route_to_collection(
    pool: &SqlitePool,
    route_path: &str,
    collection_id: i64,
) -> Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error> {
    sqlx::query("UPDATE routes SET collection_id = ? WHERE path = ?")
        .bind(collection_id)
        .bind(route_path)
        .execute(pool)
        .await
}

/// Remove a route from its collection
#[allow(dead_code)]
pub async fn remove_route_from_collection(
    pool: &SqlitePool,
    route_path: &str,
) -> Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error> {
    sqlx::query("UPDATE routes SET collection_id = NULL WHERE path = ?")
        .bind(route_path)
        .execute(pool)
        .await
}

/// Apply collection defaults to routes without specific auth configured
pub async fn apply_collection_defaults_to_routes(
    pool: &SqlitePool,
    collection_id: i64,
) -> Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error> {
    sqlx::query(
        "UPDATE routes SET
            auth_type = (SELECT default_auth_type FROM route_collections WHERE id = ?),
            auth_value = (SELECT default_auth_value FROM route_collections WHERE id = ?),
            oauth_token_url = (SELECT default_oauth_token_url FROM route_collections WHERE id = ?),
            oauth_client_id = (SELECT default_oauth_client_id FROM route_collections WHERE id = ?),
            oauth_client_secret = (SELECT default_oauth_client_secret FROM route_collections WHERE id = ?),
            oauth_scope = (SELECT default_oauth_scope FROM route_collections WHERE id = ?),
            jwt_secret = (SELECT default_jwt_secret FROM route_collections WHERE id = ?),
            jwt_algorithm = (SELECT default_jwt_algorithm FROM route_collections WHERE id = ?),
            jwt_issuer = (SELECT default_jwt_issuer FROM route_collections WHERE id = ?),
            jwt_audience = (SELECT default_jwt_audience FROM route_collections WHERE id = ?),
            jwt_required_claims = (SELECT default_jwt_required_claims FROM route_collections WHERE id = ?),
            oidc_issuer = (SELECT default_oidc_issuer FROM route_collections WHERE id = ?),
            oidc_client_id = (SELECT default_oidc_client_id FROM route_collections WHERE id = ?),
            oidc_client_secret = (SELECT default_oidc_client_secret FROM route_collections WHERE id = ?),
            oidc_audience = (SELECT default_oidc_audience FROM route_collections WHERE id = ?),
            oidc_scope = (SELECT default_oidc_scope FROM route_collections WHERE id = ?),
            rate_limit_per_minute = (SELECT default_rate_limit_per_minute FROM route_collections WHERE id = ?),
            rate_limit_per_hour = (SELECT default_rate_limit_per_hour FROM route_collections WHERE id = ?)
        WHERE collection_id = ? AND (auth_type = 'none' OR auth_type = '')"
    )
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .bind(collection_id)
    .execute(pool)
    .await
}

/// Insert routes from OpenAPI spec data
pub async fn insert_routes_from_openapi(
    pool: &SqlitePool,
    collection_id: i64,
    routes: &[crate::open_api::OpenApiRoute],
    default_upstream_prefix: &str,
) -> Result<(), sqlx::Error> {
    for route in routes {
        // Convert auth_type string to AuthType enum
        let auth_type = AuthType::from_str(&route.auth_type);
        
        // Use the existing insert_or_replace_route function
        // For OpenAPI routes, we'll use defaults for many fields
        insert_or_replace_route(
            pool,
            &route.path,
            &format!("{}{}", default_upstream_prefix, route.path), // upstream
            "", // backup_route_path
            Some(collection_id),
            &auth_type,
            "", // auth_value - empty for now
            &route.allowed_methods,
            "", // oauth_token_url - empty for now
            "", // oauth_client_id - empty for now
            "", // oauth_client_secret - empty for now
            "", // oauth_scope - empty for now
            "", // jwt_secret - empty for now
            "HS256", // jwt_algorithm - default
            "", // jwt_issuer - empty for now
            "", // jwt_audience - empty for now
            "", // jwt_required_claims - empty for now
            route.rate_limit_per_minute,
            route.rate_limit_per_hour,
            "", // oidc_issuer - empty for now
            "", // oidc_client_id - empty for now
            "", // oidc_client_secret - empty for now
            "", // oidc_audience - empty for now
            "", // oidc_scope - empty for now
            "", // health_endpoint - empty for now
        ).await?;
    }
    Ok(())
}