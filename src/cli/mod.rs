use clap::{Parser, Subcommand};
use sqlx::{Row, sqlite::SqlitePool};
use std::sync::Arc;
use crate::auth::types::AuthType;

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
        oidc_scope
    } => {
            // Parse the auth type and convert to enum
            let auth_type_enum = match auth_type.as_ref() {
                Some(auth_str) => AuthType::from_str(auth_str),
                None => AuthType::None,
            };

            sqlx::query(
                "INSERT OR REPLACE INTO routes
                (path, upstream, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, rate_limit_per_minute, rate_limit_per_hour, oidc_issuer, oidc_client_id, oidc_client_secret, oidc_audience, oidc_scope)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
                .bind(path.clone())
                .bind(upstream.clone())
                .bind(auth_type_enum.to_string())
                .bind(auth_value.unwrap_or_else(|| "".into()))
                .bind(allowed_methods.unwrap_or_else(|| "".into()))
                .bind(oauth_token_url.unwrap_or_else(|| "".into()))
                .bind(oauth_client_id.unwrap_or_else(|| "".into()))
                .bind(oauth_client_secret.unwrap_or_else(|| "".into()))
                .bind(oauth_scope.unwrap_or_else(|| "".into()))
                .bind(jwt_secret.unwrap_or_else(|| "".into()))
                .bind(jwt_algorithm.unwrap_or_else(|| "HS256".into()))
                .bind(jwt_issuer.unwrap_or_else(|| "".into()))
                .bind(jwt_audience.unwrap_or_else(|| "".into()))
                .bind(jwt_required_claims.unwrap_or_else(|| "".into()))
                .bind(rate_limit_per_minute.unwrap_or(60))
                .bind(rate_limit_per_hour.unwrap_or(1000))
                .bind(oidc_issuer.unwrap_or_else(|| "".into()))
                .bind(oidc_client_id.unwrap_or_else(|| "".into()))
                .bind(oidc_client_secret.unwrap_or_else(|| "".into()))
                .bind(oidc_audience.unwrap_or_else(|| "".into()))
                .bind(oidc_scope.unwrap_or_else(|| "".into()))
                .execute(*pool)
                .await
                .expect("Failed to add route");

            // Print OAuth details if this is OAuth authentication
            println!("Added route: {} -> {} with {} authentication",
                path, upstream, auth_type_enum.to_display_string()
            );
        }
        Commands::RemoveRoute { path } => {
            let path_copy = path.clone();
            sqlx::query("DELETE FROM routes WHERE path = ?")
                .bind(path)
                .execute(*pool)
                .await
                .expect("Failed to remove route");
            println!("Removed route: {}", path_copy);
        }
        Commands::ListRoutes => {
            let rows = sqlx::query("SELECT path, upstream, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, rate_limit_per_minute, rate_limit_per_hour FROM routes")
                .fetch_all(*pool)
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
                let stats_query = sqlx::query(
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
                .fetch_optional(*pool)
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
            let rows = sqlx::query(
                "SELECT id, path, method, request_timestamp, duration_ms, response_status_code,
                        request_size_bytes, response_size_bytes, upstream_url, auth_type, error_message
                 FROM request_metrics
                 ORDER BY request_timestamp DESC
                 LIMIT ?"
            )
            .bind(limit_value)
            .fetch_all(*pool)
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
            crate::start_server((**pool).clone()).await;
        }
        Commands::StartOAuthTestServer { port } => {
            crate::start_oauth_test_server((**pool).clone(), port.unwrap_or(3001)).await;
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
//****                              Test                                 ****//
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod test {
    use super::*;
    use sqlx::{
        sqlite::{
            SqlitePoolOptions, 
            SqliteConnectOptions,
        },
        Row,
    };

    // TODO - fix this, it doesn't create an in-memory database
    async fn setup_test_db() -> Arc<SqlitePool> {

        // Create an in-memory SQLite database for testing
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory")
            .await
            .unwrap();
        
        // Create tables
        // TODO replace with calls to the database module
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS routes (
                path TEXT PRIMARY KEY,
                upstream TEXT NOT NULL,
                auth_type TEXT DEFAULT 'None',
                auth_value TEXT DEFAULT '',
                allowed_methods TEXT DEFAULT '',
                oauth_token_url TEXT DEFAULT '',
                oauth_client_id TEXT DEFAULT '',
                oauth_client_secret TEXT DEFAULT '',
                oauth_scope TEXT DEFAULT '',
                jwt_secret TEXT DEFAULT '',
                jwt_algorithm TEXT DEFAULT 'HS256',
                jwt_issuer TEXT DEFAULT '',
                jwt_audience TEXT DEFAULT '',
                jwt_required_claims TEXT DEFAULT '',
                rate_limit_per_minute INTEGER DEFAULT 60,
                rate_limit_per_hour INTEGER DEFAULT 1000,
                oidc_issuer TEXT DEFAULT '',
                oidc_client_id TEXT DEFAULT '',
                oidc_client_secret TEXT DEFAULT '',
                oidc_audience TEXT DEFAULT '',
                oidc_scope TEXT DEFAULT ''
            )"
        )
        .execute(&pool)
        .await
        .unwrap();
        
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS request_metrics (
                id TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                method TEXT NOT NULL,
                request_timestamp TEXT NOT NULL,
                response_timestamp TEXT,
                duration_ms INTEGER,
                response_status_code INTEGER,
                request_size_bytes INTEGER NOT NULL,
                response_size_bytes INTEGER,
                upstream_url TEXT,
                auth_type TEXT,
                error_message TEXT
            )"
        )
        .execute(&pool)
        .await
        .unwrap();
        
        Arc::new(pool)
    }

    #[tokio::test]
    async fn test_add_route_basic() {
        let pool = setup_test_db().await;
        
        // Test basic add route functionality
        let rows = sqlx::query("SELECT COUNT(*) as count FROM routes")
            .fetch_one(&*pool)
            .await
            .unwrap();
        
        let initial_count: i64 = rows.get("count");
        assert_eq!(initial_count, 0);
    }

    #[tokio::test]
    async fn test_add_route_with_oauth() {
        let pool = setup_test_db().await;
        
        // Insert a route with OAuth
        sqlx::query(
            "INSERT INTO routes (path, upstream, auth_type, oauth_client_id, oauth_client_secret, oauth_token_url, oauth_scope)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("/test")
        .bind("http://localhost:8080")
        .bind("OAuth")
        .bind("client123")
        .bind("secret456")
        .bind("http://oauth.example.com/token")
        .bind("read write")
        .execute(&*pool)
        .await
        .unwrap();
        
        let rows = sqlx::query("SELECT COUNT(*) as count FROM routes WHERE auth_type = 'OAuth'")
            .fetch_one(&*pool)
            .await
            .unwrap();
        
        let count: i64 = rows.get("count");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_add_route_with_jwt() {
        let pool = setup_test_db().await;
        
        // Insert a route with JWT
        sqlx::query(
            "INSERT INTO routes (path, upstream, auth_type, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("/jwt-test")
        .bind("http://localhost:9000")
        .bind("JWT")
        .bind("my-secret-key")
        .bind("HS256")
        .bind("my-issuer")
        .bind("my-audience")
        .execute(&*pool)
        .await
        .unwrap();
        
        let rows = sqlx::query("SELECT COUNT(*) as count FROM routes WHERE auth_type = 'JWT'")
            .fetch_one(&*pool)
            .await
            .unwrap();
        
        let count: i64 = rows.get("count");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_add_route_with_oidc() {
        let pool = setup_test_db().await;
        
        // Insert a route with OIDC
        sqlx::query(
            "INSERT INTO routes (path, upstream, auth_type, oidc_issuer, oidc_client_id, oidc_client_secret, oidc_audience, oidc_scope)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("/oidc-test")
        .bind("http://localhost:7000")
        .bind("OIDC")
        .bind("https://oidc.example.com")
        .bind("oidc-client-123")
        .bind("oidc-secret-456")
        .bind("my-app")
        .bind("openid profile email")
        .execute(&*pool)
        .await
        .unwrap();
        
        let rows = sqlx::query("SELECT COUNT(*) as count FROM routes WHERE auth_type = 'OIDC'")
            .fetch_one(&*pool)
            .await
            .unwrap();
        
        let count: i64 = rows.get("count");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_remove_route() {
        let pool = setup_test_db().await;
        
        // First add a route
        sqlx::query("INSERT INTO routes (path, upstream) VALUES (?, ?)")
            .bind("/to-remove")
            .bind("http://localhost:8080")
            .execute(&*pool)
            .await
            .unwrap();
        
        // Verify it exists
        let rows = sqlx::query("SELECT COUNT(*) as count FROM routes WHERE path = '/to-remove'")
            .fetch_one(&*pool)
            .await
            .unwrap();
        let count: i64 = rows.get("count");
        assert_eq!(count, 1);
        
        // Remove it
        sqlx::query("DELETE FROM routes WHERE path = ?")
            .bind("/to-remove")
            .execute(&*pool)
            .await
            .unwrap();
        
        // Verify it's gone
        let rows = sqlx::query("SELECT COUNT(*) as count FROM routes WHERE path = '/to-remove'")
            .fetch_one(&*pool)
            .await
            .unwrap();
        let count: i64 = rows.get("count");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_list_routes() {
        let pool = setup_test_db().await;
        
        // Add multiple routes
        sqlx::query("INSERT INTO routes (path, upstream, auth_type) VALUES (?, ?, ?)")
            .bind("/route1")
            .bind("http://localhost:8001")
            .bind("None")
            .execute(&*pool)
            .await
            .unwrap();
        
        sqlx::query("INSERT INTO routes (path, upstream, auth_type) VALUES (?, ?, ?)")
            .bind("/route2")
            .bind("http://localhost:8002")
            .bind("JWT")
            .execute(&*pool)
            .await
            .unwrap();
        
        // List all routes
        let rows = sqlx::query("SELECT path, upstream, auth_type FROM routes")
            .fetch_all(&*pool)
            .await
            .unwrap();
        
        assert_eq!(rows.len(), 2);
        
        let paths: Vec<String> = rows.iter().map(|row| row.get::<String, _>("path")).collect();
        assert!(paths.contains(&"/route1".to_string()));
        assert!(paths.contains(&"/route2".to_string()));
    }

    #[tokio::test]
    async fn test_metrics_with_data() {
        let pool = setup_test_db().await;
        
        // Insert test metrics data
        sqlx::query(
            "INSERT INTO request_metrics 
             (id, path, method, request_timestamp, response_timestamp, duration_ms, response_status_code, request_size_bytes, response_size_bytes, upstream_url, auth_type)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind("test-id-1")
        .bind("/test")
        .bind("GET")
        .bind("2023-01-01 12:00:00")
        .bind("2023-01-01 12:00:01")
        .bind(100)
        .bind(200)
        .bind(1024)
        .bind(2048)
        .bind("http://localhost:8080")
        .bind("None")
        .execute(&*pool)
        .await
        .unwrap();
        
        // Test metrics query
        let rows = sqlx::query("SELECT COUNT(*) as count FROM request_metrics")
            .fetch_one(&*pool)
            .await
            .unwrap();
        
        let count: i64 = rows.get("count");
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_metrics_statistics() {
        let pool = setup_test_db().await;
        
        // Insert multiple metrics entries
        for i in 0..5 {
            sqlx::query(
                "INSERT INTO request_metrics 
                 (id, path, method, request_timestamp, response_timestamp, duration_ms, response_status_code, request_size_bytes, response_size_bytes, upstream_url, auth_type)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(format!("test-id-{}", i))
            .bind("/test")
            .bind("GET")
            .bind("2023-01-01 12:00:00")
            .bind("2023-01-01 12:00:01")
            .bind(100 + i * 10)
            .bind(if i < 4 { 200 } else { 500 }) // 4 success, 1 error
            .bind(1024)
            .bind(2048)
            .bind("http://localhost:8080")
            .bind("None")
            .execute(&*pool)
            .await
            .unwrap();
        }
        
        // Test statistics query
        let stats = sqlx::query(
            "SELECT
                COUNT(*) as total_requests,
                AVG(duration_ms) as avg_duration_ms,
                COUNT(CASE WHEN response_status_code >= 200 AND response_status_code < 300 THEN 1 END) as success_count,
                COUNT(CASE WHEN response_status_code >= 400 THEN 1 END) as error_count
            FROM request_metrics
            WHERE response_timestamp IS NOT NULL"
        )
        .fetch_one(&*pool)
        .await
        .unwrap();
        
        let total: i64 = stats.get("total_requests");
        let success: i64 = stats.get("success_count");
        let errors: i64 = stats.get("error_count");
        
        assert_eq!(total, 5);
        assert_eq!(success, 4);
        assert_eq!(errors, 1);
    }

    #[tokio::test]
    async fn test_rate_limiting_defaults() {
        let pool = setup_test_db().await;
        
        // Insert route without specifying rate limits
        sqlx::query("INSERT INTO routes (path, upstream) VALUES (?, ?)")
            .bind("/rate-test")
            .bind("http://localhost:8080")
            .execute(&*pool)
            .await
            .unwrap();
        
        // Check default rate limits
        let row = sqlx::query("SELECT rate_limit_per_minute, rate_limit_per_hour FROM routes WHERE path = '/rate-test'")
            .fetch_one(&*pool)
            .await
            .unwrap();
        
        let per_minute: i64 = row.get("rate_limit_per_minute");
        let per_hour: i64 = row.get("rate_limit_per_hour");
        
        assert_eq!(per_minute, 60);
        assert_eq!(per_hour, 1000);
    }

    #[tokio::test]
    async fn test_auth_type_parsing() {
        let pool = setup_test_db().await;
        
        // Test different auth types
        let auth_types = vec!["None", "Basic", "Bearer", "OAuth", "JWT", "OIDC"];
        
        for (i, auth_type) in auth_types.iter().enumerate() {
            sqlx::query("INSERT INTO routes (path, upstream, auth_type) VALUES (?, ?, ?)")
                .bind(format!("/auth-test-{}", i))
                .bind("http://localhost:8080")
                .bind(auth_type)
                .execute(&*pool)
                .await
                .unwrap();
        }
        
        let rows = sqlx::query("SELECT COUNT(*) as count FROM routes WHERE path LIKE '/auth-test-%'")
            .fetch_one(&*pool)
            .await
            .unwrap();
        
        let count: i64 = rows.get("count");
        assert_eq!(count, 6);
    }
}