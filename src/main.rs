use axum::{routing::get, Router, Json, http::Method, extract::OriginalUri};

#[cfg(test)]
mod tests;
mod test_server;
mod oauth_test_server;
use clap::{Parser, Subcommand};
use sqlx::{sqlite::SqlitePool, Row};
use serde::{
    Deserialize,
    Serialize,
};
use tokio::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Structure to store OAuth tokens with expiration
struct OAuthTokenCache {
    tokens: HashMap<String, (String, Instant)>,
}

impl OAuthTokenCache {
    fn new() -> Self {
        OAuthTokenCache {
            tokens: HashMap::new(),
        }
    }

    fn get_token(&self, key: &str) -> Option<String> {
        if let Some((token, expiry)) = self.tokens.get(key) {
            if Instant::now() < *expiry {
                return Some(token.clone());
            }
        }
        None
    }

    fn set_token(&mut self, key: String, token: String, expires_in: u64) {
        let expiry = Instant::now() + Duration::from_secs(expires_in);
        self.tokens.insert(key, (token, expiry));
    }
}

#[derive(Parser)]
#[command(name = "blackgate")]
#[command(about = "The Black Gate API Gateway CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new route
    AddRoute {
        #[arg(long)] path: String,
        #[arg(long)] upstream: String,
        #[arg(long)] auth_type: Option<String>,
        #[arg(long)] auth_value: Option<String>,
        #[arg(long)] allowed_methods: Option<String>,
        // OAuth specific fields
        #[arg(long)] oauth_token_url: Option<String>,
        #[arg(long)] oauth_client_id: Option<String>,
        #[arg(long)] oauth_client_secret: Option<String>,
        #[arg(long)] oauth_scope: Option<String>,
    },
    /// Remove a route
    RemoveRoute {
        #[arg(long)] path: String,
    },
    /// List all routes
    ListRoutes,
    /// Start the API gateway server
    Start,
    /// Starts an OAuth test server for authentication testing
    ///
    /// This command launches a local server to simulate OAuth authentication flows for development and testing.
    ///
    /// # Arguments
    /// * `--port <PORT>` - NOT IMPLEMENTED - Optional port number to run the server on. If not specified, a default port will be used. 
    StartOAuthTestServer {
        #[arg(long)] port: Option<u16>,
    },
}

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    token_cache: Arc<Mutex<OAuthTokenCache>>,
}

#[derive(Serialize)]
struct TokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    scope: String,
}

async fn root() -> &'static str {
    "Welcome to Black Gate"
}

/// Handles requests with a JSON body (POST, PUT, etc)
async fn handle_request_with_body(
    state: axum::extract::State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    Json(payload): Json<String>
) -> axum::response::Response {
    handle_request_core(state, method, uri.path().to_string(), Some(payload)).await
}

/// Handles requests with no body (GET, HEAD, etc)
async fn handle_request_no_body(
    state: axum::extract::State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
) -> axum::response::Response {
    handle_request_core(state, method, uri.path().to_string(), None).await
}

// Response structure for OAuth token
#[derive(Deserialize, Debug)]
struct OAuthTokenResponse {
    access_token: String,
    expires_in: Option<u64>,
    // Other fields may be present but we don't need them for now
}

/// Get OAuth token from token endpoint
async fn get_oauth_token(
    token_url: &str, 
    client_id: &str, 
    client_secret: &str, 
    scope: &str
) -> Result<(String, u64), Box<dyn std::error::Error + Send + Sync>> {
    println!("Requesting OAuth token from {}", token_url);
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()?;
    let request_body = TokenRequest {
        grant_type: "client_credentials".into(),
        client_id: client_id.into(),
        client_secret: client_secret.into(),
        scope: scope.into(),
    };

    // Send the request and log the response
    let response = client
        .post(token_url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_string(&request_body)?)
        .send()
        .await;

    match response {
        Ok(resp) => {
            let token_response: OAuthTokenResponse = resp.json::<OAuthTokenResponse>().await?;
            let expires_in = token_response.expires_in.unwrap_or(3600); // Default to 1 hour
    
            Ok((token_response.access_token, expires_in))
        }
        Err(e) => {
            return Err(format!("OAuth token request failed: {}", e).into());
        }
    }
}

/// Core handler logic, shared by both body/no-body handlers
async fn handle_request_core(
    state: axum::extract::State<AppState>,
    method: Method,
    path: String,
    body: Option<String>,
) -> axum::response::Response {
    // Query the database for the route
    let row = sqlx::query("SELECT upstream, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope FROM routes WHERE path = ?")
        .bind(&path)
        .fetch_optional(&state.db)
        .await
        .expect("Database query failed");

    match row {
        Some(row) => {
            // confirm the method is allowed
            let allowed_methods: String = row.get("allowed_methods");

            // If allowed_methods is empty, all methods are allowed
            if !allowed_methods.is_empty() {
                let allowed_methods: Vec<&str> = allowed_methods.split(',').collect();
                if !allowed_methods.contains(&method.as_str()) {
                    return axum::response::Response::builder()
                        .status(405)
                        .body(axum::body::Body::from("Method Not Allowed"))
                        .unwrap();
                }
            }

            // Set the upstream and auth from the record
            let upstream: String = row.get("upstream");
            let auth_type: Option<String> = row.get("auth_type");
            let auth_value: Option<String> = row.get("auth_value");

            // OAuth specific fields
            let oauth_token_url: Option<String> = row.get("oauth_token_url");
            let oauth_client_id: Option<String> = row.get("oauth_client_id");
            let oauth_client_secret: Option<String> = row.get("oauth_client_secret");
            let oauth_scope: Option<String> = row.get("oauth_scope");

            // Forward request to upstream
            let client = reqwest::Client::new();
            let mut builder = client.request(method, &upstream);

            // Handle authentication
            if let Some(auth_type) = auth_type.clone() {
                match auth_type.as_str() {
                    "api-key" => {
                        if let Some(auth_value) = auth_value {
                            println!("Using API key authentication for route {}", path);
                            builder = builder.header("Authorization", auth_value);
                        } else {
                            eprintln!("Missing API key for route {}", path);
                            return axum::response::Response::builder()
                                .status(500)
                                .body(axum::body::Body::from("API key is required"))
                                .unwrap();
                        }
                    },
                    "oauth2" => {
                        println!("Using OAuth 2.0 authentication for route {}", path);
                        // Check for required OAuth fields
                        if let (Some(token_url), Some(client_id), Some(client_secret), Some(scope)) = 
                            (oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope) {
                            
                            // Create a cache key for this specific OAuth configuration
                            let cache_key = format!("{}:{}:{}:{}", token_url, client_id, client_secret, scope);
                            println!("Using OAuth token cache key: {}", cache_key);
                            
                            // Try to get token from cache
                            let token = {
                                let token_cache = state.token_cache.lock().unwrap();
                                token_cache.get_token(&cache_key)
                            };
                            println!("Cached token: {:?}", token);
                            
                            let token = match token {
                                Some(token) => token,
                                None => {
                                    // No valid token in cache, fetch a new one
                                    match get_oauth_token(&token_url, &client_id, &client_secret, &scope).await {
                                        Ok((token, expires_in)) => {
                                            println!("Fetched new OAuth token: {}", token);
                                            // Store the token in cache
                                            let mut token_cache = state.token_cache.lock().unwrap();
                                            token_cache.set_token(cache_key, token.clone(), expires_in);
                                            token
                                        },
                                        Err(e) => {
                                            eprintln!("OAuth token error: {:?}", e);
                                            return axum::response::Response::builder()
                                                .status(500)
                                                .body(axum::body::Body::from("OAuth authentication failed"))
                                                .unwrap();
                                        }
                                    }
                                }
                            };
                            
                            // Add the token to the request
                            builder = builder.header("Authorization", format!("Bearer {}", token));
                        } else {
                            eprintln!("Missing OAuth configuration for route {}", path);
                            return axum::response::Response::builder()
                                .status(500)
                                .body(axum::body::Body::from("OAuth configuration is incomplete"))
                                .unwrap();
                        }
                    },
                    _ => {
                        eprintln!("Unsupported auth type: {}", auth_type);
                    }
                }
            } else {
                println!("No authentication required for route {}", path);
            }

            if let Some(body) = body {
                builder = builder.body(body);
            }

            let response = builder
                .send()
                .await
                .expect("Upstream request failed");

            let response_status = response.status();
            let response_body = response
                .text()
                .await
                .expect("Failed to read response body");
            axum::response::Response::builder()
                .status(response_status)
                .body(response_body.into())
                .unwrap()
        }
        None => axum::response::Response::builder()
            .status(404)
            .body(axum::body::Body::from("No route found"))
            .unwrap(),
    }
}

/// test POST request
/// curl -X POST http://localhost:3000/warehouse -d '{"payload": "test"}' -H "Content-Type: application/json"
/// test GET request
/// curl -X GET http://localhost:3000/warehouse-get
/// test OAuth request
/// curl -X GET http://localhost:3000/oauth-test
/// test OAuth request directly on the oauth test server
/// curl -X POST http://localhost:3001/oauth/token -d '{"grant_type":"client_credentials","client_id":"test","client_secret":"test","scope":"test"}' -H "content-type: application/json"
async fn start_server(pool: SqlitePool) {
    let token_cache = Arc::new(Mutex::new(OAuthTokenCache::new()));
    let app_state = AppState { db: pool.clone(), token_cache };
    let app = Router::new()
        .route("/", get(root))
        // GET/HEAD/OPTIONS/DELETE: no body
        .route("/{*path}", get(handle_request_no_body))
        .route("/{*path}", axum::routing::head(handle_request_no_body))
        .route("/{*path}", axum::routing::delete(handle_request_no_body))
        // POST/PUT/PATCH: expect body
        .route("/{*path}", axum::routing::post(handle_request_with_body))
        .route("/{*path}", axum::routing::put(handle_request_with_body))
        .route("/{*path}", axum::routing::patch(handle_request_with_body))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Black Gate running on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[tokio::main]
async fn main() {
    // Initialize SQLite database
    let pool = SqlitePool::connect("sqlite://blackgate.db")
        .await
        .expect("Failed to connect to SQLite");

    // Create routes table if it doesn't exist
    sqlx::query(
        "drop table if exists routes;
        CREATE TABLE IF NOT EXISTS routes (
            path TEXT PRIMARY KEY,
            auth_type TEXT,
            auth_value TEXT,
            allowed_methods TEXT,
            upstream TEXT NOT NULL,
            oauth_token_url TEXT,
            oauth_client_id TEXT,
            oauth_client_secret TEXT,
            oauth_scope TEXT
        );
        INSERT INTO routes (path, upstream, auth_type, auth_value, allowed_methods) 
        VALUES ('/warehouse', 'https://httpbin.org/post', 'api-key', 'Bearer warehouse_key','POST');
        INSERT INTO routes (path, upstream, auth_type, auth_value, allowed_methods) 
        VALUES ('/warehouse-get', 'https://httpbin.org/post', 'api-key', 'Bearer warehouse_key','GET');
        INSERT INTO routes (path, upstream, auth_type, auth_value, allowed_methods) 
        VALUES ('/warehouse-none', 'https://httpbin.org/post', 'api-key', 'Bearer warehouse_key','');
        INSERT INTO routes (path, upstream, auth_type, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope) 
        VALUES ('/oauth-test', 'https://httpbin.org/anything', 'oauth2', 'GET', 'http://localhost:3001/oauth/token', 'test_client', 'test_secret', 'read:all');
        ",
    )
    .execute(&pool)
    .await
    .expect("Failed to create routes table");

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
            oauth_scope
        } => {
            sqlx::query(
                "INSERT OR REPLACE INTO routes 
                (path, upstream, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
                .bind(path.clone())
                .bind(upstream.clone())
                .bind(auth_type.clone().unwrap_or_else(|| "none".into()))
                .bind(auth_value.unwrap_or_else(|| "".into()))
                .bind(allowed_methods.unwrap_or_else(|| "".into()))
                .bind(oauth_token_url.unwrap_or_else(|| "".into()))
                .bind(oauth_client_id.unwrap_or_else(|| "".into()))
                .bind(oauth_client_secret.unwrap_or_else(|| "".into()))
                .bind(oauth_scope.unwrap_or_else(|| "".into()))
                .execute(&pool)
                .await
                .expect("Failed to add route");
            
            // Print OAuth details if this is OAuth authentication
            if let Some(auth_type) = auth_type {
                if auth_type == "oauth2" {
                    println!("Added route: {} -> {} with OAuth 2.0 authentication", path, upstream);
                } else {
                    println!("Added route: {} -> {}", path, upstream);
                }
            } else {
                println!("Added route: {} -> {}", path, upstream);
            }
        }
        Commands::RemoveRoute { path } => {
            let path_copy = path.clone();
            sqlx::query("DELETE FROM routes WHERE path = ?")
                .bind(path)
                .execute(&pool)
                .await
                .expect("Failed to remove route");
            println!("Removed route: {}", path_copy);
        }
        Commands::ListRoutes => {
            let rows = sqlx::query("SELECT path, upstream, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope FROM routes")
                .fetch_all(&pool)
                .await
                .expect("Failed to list routes");
            
            // Header
            println!("\n{:<15} | {:<25} | {:<10} | {:<15} | {:<20} | {:<20}", 
                     "Path", "Upstream", "Auth Type", "Methods", "OAuth Client ID", "OAuth Scope");
            println!("{:-<110}", "");
            
            for row in rows {
                let path = row.get::<String, _>("path");
                let upstream = row.get::<String, _>("upstream");
                let auth_type = row.get::<String, _>("auth_type");
                let allowed_methods = row.get::<String, _>("allowed_methods");
                let oauth_client_id = row.get::<String, _>("oauth_client_id");
                let oauth_scope = row.get::<String, _>("oauth_scope");
                
                println!("{:<15} | {:<25} | {:<10} | {:<15} | {:<20} | {:<20}", 
                         path, upstream, auth_type, allowed_methods, oauth_client_id, oauth_scope);
            }
        }
        Commands::Start => {
            start_server(pool).await;
        }
        Commands::StartOAuthTestServer { port } => {
            let _port = port.unwrap_or(3001);
            let (_addr, shutdown_tx) = crate::oauth_test_server::spawn_oauth_test_server().await;
            start_server(pool).await;
            // Wait for shutdown signal
            tokio::signal::ctrl_c().await.expect("Failed to listen for shutdown signal");
            let _ = shutdown_tx.send(());
            println!("OAuth Test Server shutting down");
        }
    }
}