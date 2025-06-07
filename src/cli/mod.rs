//! # CLI Module
//! 
//! This module provides command-line interface functionality for the Black Gate API Gateway.
//! It handles parsing and execution of various CLI commands including route management,
//! metrics viewing, and server operations.
//! 
//! ## Features
//! 
//! - **Route Management**: Add, remove, and list API gateway routes
//! - **Authentication Support**: Configure various authentication types (OAuth, JWT, OIDC, Basic, Bearer)
//! - **Rate Limiting**: Set per-minute and per-hour request limits for routes
//! - **Metrics**: View request statistics and recent request history
//! - **Server Operations**: Start the main server or OAuth test server
//! 
//! ## Commands
//! 
//! ### Route Management
//! - `add-route`: Add a new route with comprehensive configuration options
//! - `remove-route`: Remove an existing route by path
//! - `list-routes`: Display all configured routes in a formatted table
//! 
//! ### Metrics and Monitoring
//! - `metrics`: View request metrics with optional statistics summary and recent request history
//! 
//! ### Server Operations
//! - `start`: Launch the main API gateway server
//! - `start-oauth`: Start both OAuth test server and API gateway for testing
//! 
//! ## Authentication Types Supported
//! 
//! - **None**: No authentication required
//! - **Basic**: HTTP Basic authentication
//! - **Bearer**: Bearer token authentication
//! - **OAuth**: OAuth 2.0 with configurable client credentials and token endpoints
//! - **JWT**: JSON Web Token validation with configurable secrets, algorithms, and claims
//! - **OIDC**: OpenID Connect with issuer discovery and client configuration
//! 
//! ## Rate Limiting
//! 
//! Routes can be configured with rate limits:
//! - Per-minute limit (default: 60 requests)
//! - Per-hour limit (default: 1000 requests)
//! 
//! ## Database Integration
//! 
//! All route configurations and metrics are stored in SQLite database tables:
//! - `routes`: Stores route configuration and authentication settings
//! - `request_metrics`: Stores request/response metrics and performance data
//! 
//! ## Usage Example
//! 
//! ```bash
//! # Add a route with JWT authentication
//! blackgate add-route --path /api/users --upstream http://localhost:3000 \
//!   --auth-type JWT --jwt-secret mysecret --jwt-algorithm HS256
//! 
//! # List all routes
//! blackgate list-routes
//! 
//! # View metrics with statistics
//! blackgate metrics --stats --limit 20
//! 
//! # Start the server
//! blackgate start
//! ```

use clap::{Parser, Subcommand};
use sqlx::{Row, sqlite::SqlitePool};
use std::sync::Arc;
use tracing::{error, info};
use crate::auth::types::AuthType;
use crate::database::{
    DatabaseManager,
    MigrationCli,
    queries,
};

///////////////////////////////////////////////////////////////////////////////
//****                        Private Structs                            ****//
///////////////////////////////////////////////////////////////////////////////

#[derive(Parser)]
#[command(name = "blackgate")]
#[command(about = "The Black Gate API Gateway CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

///////////////////////////////////////////////////////////////////////////////
//****                         Private Types                             ****//
///////////////////////////////////////////////////////////////////////////////


#[derive(Subcommand)]
enum Commands {
    /// Add a new route to the API gateway
    #[command(name = "add-route")]
    AddRoute {
        #[arg(long)]
        path: String,
        #[arg(long)]
        upstream: String,
        #[arg(long, help = "Backup route path (optional)")]
        backup_route_path: Option<String>,
        #[arg(long)]
        auth_type: Option<String>,
        #[arg(long)]
        auth_value: Option<String>,
        #[arg(long)]
        allowed_methods: Option<String>,
        // OAuth specific fields
        #[arg(long)]
        oauth_token_url: Option<String>,
        #[arg(long)]
        oauth_client_id: Option<String>,
        #[arg(long)]
        oauth_client_secret: Option<String>,
        #[arg(long)]
        oauth_scope: Option<String>,
        // JWT specific fields
        #[arg(long)]
        jwt_secret: Option<String>,
        #[arg(long)]
        jwt_algorithm: Option<String>,
        #[arg(long)]
        jwt_issuer: Option<String>,
        #[arg(long)]
        jwt_audience: Option<String>,
        #[arg(long)]
        jwt_required_claims: Option<String>,
        // OIDC specific fields
        #[arg(long)]
        oidc_issuer: Option<String>,
        #[arg(long)]
        oidc_client_id: Option<String>,
        #[arg(long)]
        oidc_client_secret: Option<String>,
        #[arg(long)]
        oidc_audience: Option<String>,
        #[arg(long)]
        oidc_scope: Option<String>,
        // Rate limiting fields
        #[arg(long, help = "Maximum requests per minute (default: 60)")]
        rate_limit_per_minute: Option<u32>,
        #[arg(long, help = "Maximum requests per hour (default: 1000)")]
        rate_limit_per_hour: Option<u32>,
        // health endpoint (optional)
        #[arg(long, help = "Health check endpoint (optional)")]
        health_endpoint: Option<String>,
    },
    /// Remove a route from the API gateway
    #[command(name = "remove-route")]
    RemoveRoute {
        #[arg(long)]
        path: String,
    },
    /// List all routes loaded into the API gateway
    #[command(name = "list-routes")]
    ListRoutes,
    /// View request metrics and statistics
    #[command(name = "metrics")]
    Metrics {
        #[arg(long, help = "Number of recent requests to show")]
        limit: Option<i32>,
        #[arg(long, help = "Show statistics summary")]
        stats: bool,
    },
    /// Start the API gateway server
    #[command(name = "start")]
    Start,
    /// Starts an OAuth test server for authentication testing and the Black Gate API Gateway server
    #[command(name = "start-oauth")]
    StartOAuthTestServer {
        #[arg(long)]
        port: Option<u16>,
    },
    /// Database migration commands
    #[command(name = "migrate")]
    Migrate {
        #[command(subcommand)]
        action: MigrateAction,
    },
    /// View health status of all routes
    #[command(name = "health")]
    Health {
        #[arg(long, help = "Show detailed health check history")]
        detailed: bool,
        #[arg(long, help = "Show only unhealthy routes")]
        unhealthy_only: bool,
    },
}

#[derive(Subcommand)]
enum MigrateAction {
    /// Show migration status
    Status,
    /// Apply all pending migrations
    ApplyAll,
    /// Apply a specific migration version
    Apply {
        #[arg(help = "Migration version to apply")]
        version: u32,
    },
    /// Initialize database without applying migrations
    Create {
        #[arg(help = "Migration name to create")]
        name: String,
    },
    ViewSchema,
}

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

pub async fn parse_cli_commands(pool: Arc<&SqlitePool>) -> () {
    // Parse CLI commands
    let cli = Cli::parse();

    match cli.command {
        Commands::AddRoute {
            path,
            upstream,
            backup_route_path,
            auth_type,
            auth_value,
            allowed_methods,
            oauth_token_url,
            oauth_client_id,
            oauth_client_secret,
            oauth_scope,
            jwt_secret,
            jwt_algorithm,
            jwt_issuer,
            jwt_audience,
            jwt_required_claims,
            rate_limit_per_minute,
            rate_limit_per_hour,
            oidc_issuer,
            oidc_client_id,
            oidc_client_secret,
            oidc_audience,
            oidc_scope,
            health_endpoint,
        } => {
                // Parse the auth type and convert to enum
                let auth_type_enum = match auth_type.as_ref() {
                    Some(auth_str) => AuthType::from_str(auth_str),
                    None => AuthType::None,
                };
    
                queries::insert_or_replace_route(
                    *pool,
                    &path,
                    &upstream,
                    &backup_route_path.unwrap_or_else(|| "".into()),
                    &auth_type_enum,
                    &auth_value.unwrap_or_else(|| "".into()),
                    &allowed_methods.unwrap_or_else(|| "".into()),
                    &oauth_token_url.unwrap_or_else(|| "".into()),
                    &oauth_client_id.unwrap_or_else(|| "".into()),
                    &oauth_client_secret.unwrap_or_else(|| "".into()),
                    &oauth_scope.unwrap_or_else(|| "".into()),
                    &jwt_secret.unwrap_or_else(|| "".into()),
                    &jwt_algorithm.unwrap_or_else(|| "HS256".into()),
                    &jwt_issuer.unwrap_or_else(|| "".into()),
                    &jwt_audience.unwrap_or_else(|| "".into()),
                    &jwt_required_claims.unwrap_or_else(|| "".into()),
                    rate_limit_per_minute.unwrap_or(60),
                    rate_limit_per_hour.unwrap_or(1000),
                    &oidc_issuer.unwrap_or_else(|| "".into()),
                    &oidc_client_id.unwrap_or_else(|| "".into()),
                    &oidc_client_secret.unwrap_or_else(|| "".into()),
                    &oidc_audience.unwrap_or_else(|| "".into()),
                    &oidc_scope.unwrap_or_else(|| "".into()),
                    &health_endpoint.unwrap_or_else(|| "".into()),
                )
                .await
                .expect("Failed to add route");
    
                // Print OAuth details if this is OAuth authentication
                println!("Added route: {} -> {} with {} authentication",
                    path, upstream, auth_type_enum.to_display_string()
                );
            }
        Commands::RemoveRoute { path } => {
                let path_copy = path.clone();
                queries::delete_route_by_path(*pool, &path)
                    .await
                    .expect("Failed to remove route");
                println!("Removed route: {}", path_copy);
            }
        Commands::ListRoutes => {
                let rows = queries::fetch_all_routes_for_listing(*pool)
                    .await
                    .expect("Failed to list routes");
    
                // Header
                println!(
                    "\n{:<15} | {:<25} | {:<10} | {:<15} | {:<20} | {:<15} | {:<15} | {:<15} | {:<15} | {:<15}",
                    "Path", "Upstream", "Auth Type", "Methods", "OAuth Client ID", "Rate/Min", "Rate/Hour", "Algorithm", "Issuer", "Required Claims"
                );
                println!("{:-<120}", "");
    
                for row in rows {
                    let path = row.get::<String, _>("path");
                    let upstream = row.get::<String, _>("upstream");
                    let auth_type_str = row.get::<String, _>("auth_type");
                    let auth_type = AuthType::from_str(&auth_type_str);
                    let allowed_methods = row.get::<String, _>("allowed_methods");
                    let oauth_client_id = row.get::<String, _>("oauth_client_id");
                    let rate_limit_per_minute: i64 = row.get("rate_limit_per_minute");
                    let rate_limit_per_hour: i64 = row.get("rate_limit_per_hour");
                    let algorithm = row.get::<String, _>("jwt_algorithm");
                    let issuer = row.get::<String, _>("jwt_issuer");
                    let required_claims = row.get::<String, _>("jwt_required_claims");
    
                    println!(
                        "{:<15} | {:<25} | {:<10} | {:<15} | {:<20} | {:<15} | {:<15} | {:<15} | {:<15} | {:<15}",
                        path, upstream, auth_type.to_display_string(), allowed_methods, oauth_client_id, rate_limit_per_minute, rate_limit_per_hour, algorithm, issuer, required_claims
                    );
                }
            }
        Commands::Metrics { limit, stats } => {
                if stats {
                    // Show statistics summary
                    let stats_query = queries::fetch_metrics_statistics(*pool)
                        .await
                        .expect("Failed to fetch metrics statistics");
    
                    if let Some(row) = stats_query {
                        println!("\n=== Request Metrics Summary ===");
                        println!("Total Requests: {}", row.get::<i64, _>("total_requests"));
                        println!("Success Rate: {:.1}%",
                            (row.get::<i64, _>("success_count") as f64 / row.get::<i64, _>("total_requests") as f64) * 100.0);
                        println!("Average Duration: {:.2}ms", row.get::<Option<f64>, _>("avg_duration_ms").unwrap_or(0.0));
                        println!("Min Duration: {}ms", row.get::<Option<i64>, _>("min_duration_ms").unwrap_or(0));
                        println!("Max Duration: {}ms", row.get::<Option<i64>, _>("max_duration_ms").unwrap_or(0));
                        println!("Total Request Bytes: {}", row.get::<Option<i64>, _>("total_request_bytes").unwrap_or(0));
                        println!("Total Response Bytes: {}", row.get::<Option<i64>, _>("total_response_bytes").unwrap_or(0));
                        println!("Error Count: {}", row.get::<i64, _>("error_count"));
                    } else {
                        println!("No metrics data available");
                    }
                }
    
                // Show recent requests
                let limit_value = limit.unwrap_or(10);
                let rows = queries::fetch_recent_request_metrics(*pool, limit_value)
                    .await
                    .expect("Failed to fetch recent metrics");
    
                if !rows.is_empty() {
                    println!("\n=== Recent Requests (Last {}) ===", limit_value);
                    println!(
                        "{:<8} | {:<15} | {:<6} | {:<20} | {:<8} | {:<6} | {:<10} | {:<12} | {:<10}",
                        "ID", "Path", "Method", "Timestamp", "Duration", "Status", "Req Size", "Resp Size", "Auth Type"
                    );
                    println!("{:-<120}", "");
    
                    for row in rows {
                        let id = row.get::<String, _>("id");
                        let short_id = &id[..8]; // Show first 8 characters of UUID
                        let path = row.get::<String, _>("path");
                        let method = row.get::<String, _>("method");
                        let timestamp = row.get::<String, _>("request_timestamp");
                        let duration = row.get::<Option<i64>, _>("duration_ms")
                            .map(|d| format!("{}ms", d))
                            .unwrap_or_else(|| "N/A".to_string());
                        let status = row.get::<Option<u16>, _>("response_status_code")
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "N/A".to_string());
                        let req_size = row.get::<i64, _>("request_size_bytes");
                        let resp_size = row.get::<Option<i64>, _>("response_size_bytes")
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "N/A".to_string());
                        let auth_type_str = row.get::<String, _>("auth_type");
                        let auth_type = AuthType::from_str(&auth_type_str);
    
                        println!(
                            "{:<8} | {:<15} | {:<6} | {:<20} | {:<8} | {:<6} | {:<10} | {:<12} | {:<10}",
                            short_id, path, method, &timestamp[..19], duration, status, req_size, resp_size, auth_type.to_display_string()
                        );
    
                        // Show error message if present
                        if let Some(error) = row.get::<Option<String>, _>("error_message") {
                            println!("         Error: {}", error);
                        }
                    }
                } else {
                    println!("No metrics data available");
                }
            }
        Commands::Start => {
                crate::server::start_server((**pool).clone()).await;
            }
        Commands::StartOAuthTestServer { port } => {
                crate::server::start_oauth_test_server((**pool).clone(), port.unwrap_or(3001)).await;
            }
        Commands::Migrate {
            action,
        } => {
            let db_manager = DatabaseManager::new((*pool).clone());
            let migration_cli = MigrationCli::new(db_manager);
            match action {
                MigrateAction::Status => {
                    match migration_cli.list_migrations().await {
                        Ok(_) => (),
                        Err(e) => error!("Failed to list migrations: {}", e),
                    }
                }
                MigrateAction::ApplyAll => {
                    match migration_cli.apply_migrations().await {
                        Ok(_) => (),
                        Err(e) => error!("Failed to apply migrations: {}", e),
                    }
                }
                MigrateAction::Apply { version } => {
                    match migration_cli.apply_migration(version).await {
                        Ok(_) => (),
                        Err(e) => error!("Failed to apply migration {}: {}", version, e),
                    }
                }
                MigrateAction::Create { name } => {
                    info!("Creating new migration: {}", name);
                    migration_cli.create_migration(&name)
                }
                MigrateAction::ViewSchema => {
                    match migration_cli.view_schema().await {
                        Ok(_) => (),
                        Err(e) => error!("Failed to view schema: {}", e),
                    }
                }
            }
        }
        Commands::Health { detailed, unhealthy_only } => {
            if detailed {
                // Show detailed health check history
                // TODO turn this into a query function in queries.rs
                let rows = sqlx::query(
                    "SELECT * FROM route_health_checks ORDER BY checked_at DESC LIMIT 50"
                )
                .fetch_all(*pool)
                .await
                .expect("Failed to fetch health check history");

                if !rows.is_empty() {
                    println!("\n{:<20} | {:<12} | {:<12} | {:<25} | {:<15} | {:<50}",
                        "Path", "Status", "Time (ms)", "Checked At", "Method", "Error"
                    );
                    println!("{:-<140}", "");

                    for row in rows {
                        let path: String = row.get("path");
                        let status: String = row.get("status");
                        let response_time: Option<i64> = row.get("response_time_ms");
                        let checked_at: String = row.get("checked_at");
                        let method_used: String = row.get("method_used");
                        let error_message: Option<String> = row.get("error_message");

                        let time_str = response_time.map(|t| format!("{}ms", t)).unwrap_or_else(|| "N/A".to_string());
                        let error_str = error_message.unwrap_or_else(|| "".to_string());
                        let error_display = if error_str.len() > 50 {
                            format!("{}...", &error_str[..47])
                        } else {
                            error_str
                        };

                        println!("{:<20} | {:<12} | {:<12} | {:<25} | {:<15} | {:<50}",
                            path, status, time_str, &checked_at[..19], method_used, error_display
                        );
                    }
                } else {
                    println!("No health check history available");
                }
            } else {
                // Show current health status for all routes
                // TODO turn this into a query function in queries.rs
                let rows = sqlx::query(
                    "SELECT r.path, r.upstream, r.health_endpoint,
                     h.health_check_status as last_health_status, h.response_time_ms, h.checked_at, h.method_used
                     FROM routes r
                     LEFT JOIN (
                         SELECT path, status, response_time_ms, checked_at, method_used,
                                ROW_NUMBER() OVER (PARTITION BY path ORDER BY checked_at DESC) as rn
                         FROM route_health_checks
                     ) h ON r.path = h.path AND h.rn = 1
                     ORDER BY r.path"
                )
                .fetch_all(*pool)
                .await
                .expect("Failed to fetch route health status");

                if !rows.is_empty() {
                    println!("\n{:<20} | {:<30} | {:<12} | {:<12} | {:<15} | {:<25} | {:<20}",
                        "Path", "Upstream", "Status", "Time (ms)", "Method", "Last Checked", "Health Endpoint"
                    );
                    println!("{:-<140}", "");

                    for row in rows {
                        let path: String = row.get("path");
                        let upstream: String = row.get("upstream");
                        let last_health_status: Option<String> = row.get("last_health_status");
                        let response_time: Option<i64> = row.get("response_time_ms");
                        let checked_at: Option<String> = row.get("checked_at");
                        let method_used: Option<String> = row.get("method_used");
                        let health_endpoint: Option<String> = row.get("health_endpoint");

                        let status_display = last_health_status.unwrap_or_else(|| "Unknown".to_string());
                        let time_str = response_time.map(|t| format!("{}ms", t)).unwrap_or_else(|| "N/A".to_string());
                        let method_str = method_used.unwrap_or_else(|| "N/A".to_string());
                        let checked_str = checked_at.map(|c| c[..19].to_string()).unwrap_or_else(|| "Never".to_string());
                        let endpoint_str = health_endpoint.unwrap_or_else(|| "None".to_string());

                        // Filter unhealthy routes if requested
                        if unhealthy_only && status_display != "Unhealthy" && status_display != "Unavailable" {
                            continue;
                        }

                        let upstream_display = if upstream.len() > 30 {
                            format!("{}...", &upstream[..27])
                        } else {
                            upstream
                        };

                        let endpoint_display = if endpoint_str.len() > 20 {
                            format!("{}...", &endpoint_str[..17])
                        } else {
                            endpoint_str
                        };

                        println!("{:<20} | {:<30} | {:<12} | {:<12} | {:<15} | {:<25} | {:<20}",
                            path, upstream_display, status_display, time_str, method_str, checked_str, endpoint_display
                        );
                    }
                } else {
                    println!("No routes configured");
                }
            }
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
//****                              Tests                                ****//
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod test {
    use super::*;
    use sqlx::{sqlite::SqlitePoolOptions};

    async fn setup_test_db() -> Arc<SqlitePool> {
        // Create an in-memory SQLite database for testing
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        
        // Use the database module to initialize and apply all migrations
        let db_manager = DatabaseManager::new(pool);
        db_manager.initialize().await.unwrap();
        db_manager.apply_pending_migrations().await.unwrap();
        
        Arc::new(db_manager.pool().clone())
    }

    #[tokio::test]
    async fn test_setup_db() {
        let _pool = setup_test_db().await;
        // Add actual test logic here
    }
}