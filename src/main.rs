use axum::{Router, extract::OriginalUri, http::Method, routing::{get, post, put, delete, patch, head}};

mod oauth_test_server;
#[cfg(test)]
mod tests;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sqlx::{Row, sqlite::SqlitePool};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, Instant};
use tracing::{info, warn, error, debug};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use jsonwebtoken::{decode, Algorithm, Validation, DecodingKey};

/// Structure to store OAuth tokens with expiration
struct OAuthTokenCache {
    tokens: HashMap<String, (String, Instant)>,
}

impl OAuthTokenCache {
    /// Create a new OAuth token cache
    fn new() -> Self {
        OAuthTokenCache {
            tokens: HashMap::new(),
        }
    }

    /// Get a token from the cache if it is still valid
    fn get_token(&self, key: &str) -> Option<String> {
        if let Some((token, expiry)) = self.tokens.get(key) {
            if Instant::now() < *expiry {
                return Some(token.clone());
            }
        }
        None
    }

    /// Set a token in the cache with an expiration time
    fn set_token(&mut self, key: String, token: String, expires_in: u64) {
        let expiry = Instant::now() + Duration::from_secs(expires_in);
        self.tokens.insert(key, (token, expiry));
    }
}

/// Rate limiting structure to track requests per client/route
struct RateLimiter {
    requests: HashMap<String, Vec<Instant>>, // key -> timestamps of requests
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    /// Check if request is allowed based on rate limits
    /// Returns true if allowed, false if rate limited
    fn is_allowed(&mut self, key: &str, requests_per_minute: u32, requests_per_hour: u32) -> bool {
        let now = Instant::now();
        
        // Clean up old entries and get current requests for this key
        let requests = self.requests.entry(key.to_string()).or_insert_with(Vec::new);
        
        // Remove requests older than 1 hour
        requests.retain(|&timestamp| now.duration_since(timestamp) < Duration::from_secs(3600));
        
        // Check hourly limit
        if requests.len() >= requests_per_hour as usize {
            debug!("Rate limit exceeded for key: {} (hourly limit: {})", key, requests_per_hour);
            return false;
        }
        
        // Check minute limit - count requests in the last minute
        let minute_requests = requests.iter()
            .filter(|&&timestamp| now.duration_since(timestamp) < Duration::from_secs(60))
            .count();
            
        if minute_requests >= requests_per_minute as usize {
            debug!("Rate limit exceeded for key: {} (minute limit: {})", key, requests_per_minute);
            return false;
        }
        
        // Add this request
        requests.push(now);
        true
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

/// Application state shared across routes, contains DB pool and token cache
#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    token_cache: Arc<Mutex<OAuthTokenCache>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

/// Metrics data structure for tracking request/response information
#[derive(Debug, Serialize, Deserialize)]
struct RequestMetrics {
    id: String,
    path: String,
    method: String,
    request_timestamp: DateTime<Utc>,
    response_timestamp: Option<DateTime<Utc>>,
    duration_ms: Option<i64>,
    request_size_bytes: i64,
    response_size_bytes: Option<i64>,
    response_status_code: Option<u16>,
    upstream_url: Option<String>,
    auth_type: String,
    client_ip: Option<String>,
    user_agent: Option<String>,
    error_message: Option<String>,
}

impl RequestMetrics {
    fn new(path: String, method: String, request_size: i64) -> Self {
        RequestMetrics {
            id: Uuid::new_v4().to_string(),
            path,
            method,
            request_timestamp: Utc::now(),
            response_timestamp: None,
            duration_ms: None,
            request_size_bytes: request_size,
            response_size_bytes: None,
            response_status_code: None,
            upstream_url: None,
            auth_type: "none".to_string(),
            client_ip: None,
            user_agent: None,
            error_message: None,
        }
    }

    fn complete_request(&mut self, response_size: i64, status_code: u16, upstream_url: Option<String>, auth_type: String) {
        let now = Utc::now();
        self.response_timestamp = Some(now);
        self.duration_ms = Some((now - self.request_timestamp).num_milliseconds());
        self.response_size_bytes = Some(response_size);
        self.response_status_code = Some(status_code);
        self.upstream_url = upstream_url;
        self.auth_type = auth_type;
    }

    fn set_error(&mut self, error: String) {
        let now = Utc::now();
        self.response_timestamp = Some(now);
        self.duration_ms = Some((now - self.request_timestamp).num_milliseconds());
        self.error_message = Some(error);
    }
}

/// Token request structure for OAuth
#[derive(Serialize)]
struct TokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    scope: String,
}

// Response structure for OAuth token
#[derive(Deserialize, Debug)]
struct OAuthTokenResponse {
    access_token: String,
    expires_in: Option<u64>,
    // Other fields may be present but we don't need them for now
}

/// JWT Claims structure for token validation
#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,  // Subject (user identifier)
    exp: usize,   // Expiration time (as UTC timestamp)
    iat: usize,   // Issued at (as UTC timestamp) 
    iss: Option<String>,  // Issuer
    aud: Option<String>,  // Audience
    // Custom claims can be added here
    #[serde(flatten)]
    custom: HashMap<String, serde_json::Value>,
}

/// JWT Configuration structure
#[derive(Debug, Clone)]
struct JwtConfig {
    secret: String,
    algorithm: Algorithm,
    issuer: Option<String>,
    audience: Option<String>,
    required_claims: Vec<String>,
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
}

/// Authentication types supported by the gateway
#[derive(Debug, Clone, PartialEq)]
enum AuthType {
    None,
    ApiKey,
    OAuth2,
    Jwt,
    Oidc,
}

impl AuthType {
    /// Parse authentication type from string
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "api-key" | "apikey" => AuthType::ApiKey,
            "oauth2" | "oauth" => AuthType::OAuth2,
            "jwt" => AuthType::Jwt,
            "oidc" => AuthType::Oidc,
            "none" | "" => AuthType::None,
            _ => {
                eprintln!("Unknown auth type '{}', defaulting to None", s);
                AuthType::None
            }
        }
    }

    /// Convert authentication type to string for database storage
    fn to_string(&self) -> &'static str {
        match self {
            AuthType::None => "none",
            AuthType::ApiKey => "api-key",
            AuthType::OAuth2 => "oauth2",
            AuthType::Jwt => "jwt",
            AuthType::Oidc => "oidc",
        }
    }

    /// Convert authentication type to a user-friendly display string
    fn to_display_string(&self) -> String {
        match self {
            AuthType::None => "No".to_string(),
            AuthType::ApiKey => "API Key".to_string(),
            AuthType::OAuth2 => "OAuth 2.0".to_string(),
            AuthType::Jwt => "JWT".to_string(),
            AuthType::Oidc => "OIDC".to_string(),
        }
    }
}

/// Root handler for the API gateway
async fn root() -> &'static str {
    "Welcome to Black Gate"
}

/// Store request metrics in the database
async fn store_metrics(pool: &SqlitePool, metrics: &RequestMetrics) {
    let result = sqlx::query(
        "INSERT INTO request_metrics (
            id, path, method, request_timestamp, response_timestamp, duration_ms,
            request_size_bytes, response_size_bytes, response_status_code,
            upstream_url, auth_type, client_ip, user_agent, error_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&metrics.id)
    .bind(&metrics.path)
    .bind(&metrics.method)
    .bind(metrics.request_timestamp.to_rfc3339())
    .bind(metrics.response_timestamp.map(|t| t.to_rfc3339()))
    .bind(metrics.duration_ms)
    .bind(metrics.request_size_bytes)
    .bind(metrics.response_size_bytes)
    .bind(metrics.response_status_code)
    .bind(&metrics.upstream_url)
    .bind(&metrics.auth_type)
    .bind(&metrics.client_ip)
    .bind(&metrics.user_agent)
    .bind(&metrics.error_message)
    .execute(pool)
    .await;

    if let Err(e) = result {
        error!("Failed to store metrics: {}", e);
    } else {
        debug!("Stored metrics for request {}", metrics.id);
    }
}

/// Get OAuth token from token endpoint
async fn get_oauth_token(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    scope: &str,
) -> Result<(String, u64), Box<dyn std::error::Error + Send + Sync>> {
    info!("Requesting OAuth token from {}", token_url);
    let client = reqwest::Client::builder().use_rustls_tls().build()?;
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
            debug!("Successfully received OAuth token, expires in {}s", expires_in);
            Ok((token_response.access_token, expires_in))
        }
        Err(e) => {
            error!("OAuth token request failed: {}", e);
            Err(format!("OAuth token request failed: {}", e).into())
        }
    }
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
    handle_request_core(state, Method::POST, uri.path().to_string(), Some(body_string)).await
}

/// Handles PUT requests
async fn handle_put_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
    payload: axum::body::Bytes,
) -> axum::response::Response {
    let body_string = String::from_utf8_lossy(&payload).to_string();
    handle_request_core(state, Method::PUT, uri.path().to_string(), Some(body_string)).await
}

/// Handles PATCH requests
async fn handle_patch_request(
    state: axum::extract::State<AppState>,
    OriginalUri(uri): OriginalUri,
    payload: axum::body::Bytes,
) -> axum::response::Response {
    let body_string = String::from_utf8_lossy(&payload).to_string();
    handle_request_core(state, Method::PATCH, uri.path().to_string(), Some(body_string)).await
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
    let row = sqlx::query("SELECT upstream, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, rate_limit_per_minute, rate_limit_per_hour FROM routes WHERE path = ?")
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
                route_config.auth_type.to_string().to_string()
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
        .route("/", get(root))
        // HTTP method specific routes
        .route("/{*path}", get(handle_get_request))
        .route("/{*path}", head(handle_head_request))
        .route("/{*path}", delete(handle_delete_request))
        .route("/{*path}", post(handle_post_request))
        .route("/{*path}", put(handle_put_request))
        .route("/{*path}", patch(handle_patch_request))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    let addr = listener.local_addr().unwrap();
    info!("Black Gate running on http://{}", addr);
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
        .route("/", get(root))
        // HTTP method specific routes
        .route("/{*path}", get(handle_get_request))
        .route("/{*path}", head(handle_head_request))
        .route("/{*path}", delete(handle_delete_request))
        .route("/{*path}", post(handle_post_request))
        .route("/{*path}", put(handle_put_request))
        .route("/{*path}", patch(handle_patch_request))
        .with_state(app_state);

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
async fn start_oauth_test_server(
    pool: SqlitePool,
    _port: u16
) {
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

/// Validate JWT token and extract claims
fn validate_jwt_token(
    token: &str,
    jwt_config: &JwtConfig,
) -> Result<JwtClaims, Box<dyn std::error::Error + Send + Sync>> {
    // Parse algorithm
    let algorithm = match jwt_config.algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => jwt_config.algorithm,
        _ => {
            return Err("Unsupported JWT algorithm. Only HMAC algorithms (HS256, HS384, HS512) are currently supported.".into());
        }
    };

    // Create validation
    let mut validation = Validation::new(algorithm);
    
    // Set issuer validation if provided
    if let Some(ref issuer) = jwt_config.issuer {
        validation.iss = Some(std::collections::HashSet::from([issuer.clone()]));
    }
    
    // Set audience validation if provided  
    if let Some(ref audience) = jwt_config.audience {
        validation.aud = Some(std::collections::HashSet::from([audience.clone()]));
    }

    // Create decoding key
    let decoding_key = DecodingKey::from_secret(jwt_config.secret.as_ref());
    
    // Decode and validate token
    let token_data = decode::<JwtClaims>(token, &decoding_key, &validation)?;
    let claims = token_data.claims;
    
    // Validate required claims if specified
    for required_claim in &jwt_config.required_claims {
        if !claims.custom.contains_key(required_claim) {
            return Err(format!("Missing required claim: {}", required_claim).into());
        }
    }
    
    debug!("JWT token validated successfully for subject: {}", claims.sub);
    Ok(claims)
}

/// Create JWT configuration from route config
fn create_jwt_config(route_config: &RouteConfig) -> Result<JwtConfig, String> {
    let secret = route_config.jwt_secret.as_ref()
        .ok_or("JWT secret is required")?;
    
    let algorithm = match route_config.jwt_algorithm.as_deref().unwrap_or("HS256") {
        "HS256" => Algorithm::HS256,
        "HS384" => Algorithm::HS384, 
        "HS512" => Algorithm::HS512,
        alg => return Err(format!("Unsupported JWT algorithm: {}", alg)),
    };
    
    let required_claims = route_config.jwt_required_claims
        .as_ref()
        .map(|claims| claims.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();
    
    Ok(JwtConfig {
        secret: secret.clone(),
        algorithm,
        issuer: route_config.jwt_issuer.clone(),
        audience: route_config.jwt_audience.clone(),
        required_claims,
    })
}

/// Apply authentication to a request builder based on the route configuration
async fn apply_authentication(
    builder: reqwest::RequestBuilder,
    route_config: &RouteConfig,
    path: &str,
    token_cache: Arc<Mutex<OAuthTokenCache>>,
) -> Result<reqwest::RequestBuilder, axum::response::Response> {
    match route_config.auth_type {
        AuthType::ApiKey => {
            if let Some(auth_value) = &route_config.auth_value {
                debug!("Using API key authentication for route {}", path);
                Ok(builder.header("Authorization", auth_value))
            } else {
                error!("Missing API key for route {}", path);
                Err(axum::response::Response::builder()
                    .status(500)
                    .body(axum::body::Body::from("API key is required"))
                    .unwrap())
            }
        }
        AuthType::OAuth2 => {
            debug!("Using OAuth 2.0 authentication for route {}", path);
            // Check for required OAuth fields
            if let (
                Some(token_url),
                Some(client_id),
                Some(client_secret),
                Some(scope),
            ) = (
                &route_config.oauth_token_url,
                &route_config.oauth_client_id,
                &route_config.oauth_client_secret,
                &route_config.oauth_scope,
            ) {
                // Create a cache key for this specific OAuth configuration
                let cache_key =
                    format!("{}:{}:{}:{}", token_url, client_id, client_secret, scope);
                debug!("Using OAuth token cache key: {}", cache_key);

                // Try to get token from cache
                let token = {
                    let token_cache = token_cache.lock().unwrap();
                    token_cache.get_token(&cache_key)
                };

                let token = match token {
                    Some(token) => {
                        debug!("Using cached OAuth token for route {}", path);
                        token
                    }
                    None => {
                        info!("Fetching new OAuth token for route {}", path);
                        // No valid token in cache, fetch a new one
                        match get_oauth_token(token_url, client_id, client_secret, scope).await {
                            Ok((token, expires_in)) => {
                                info!("Successfully fetched OAuth token for route {}, expires in {}s", path, expires_in);
                                // Store the token in cache
                                let mut token_cache = token_cache.lock().unwrap();
                                token_cache.set_token(cache_key, token.clone(), expires_in);
                                token
                            }
                            Err(e) => {
                                error!("OAuth token error for route {}: {:?}", path, e);
                                return Err(axum::response::Response::builder()
                                    .status(500)
                                    .body(axum::body::Body::from(
                                        "OAuth authentication failed",
                                    ))
                                    .unwrap());
                            }
                        }
                    }
                };

                // Add the token to the request
                Ok(builder.header("Authorization", format!("Bearer {}", token)))
            } else {
                error!("Missing OAuth configuration for route {}", path);
                Err(axum::response::Response::builder()
                    .status(500)
                    .body(axum::body::Body::from("OAuth configuration is incomplete"))
                    .unwrap())
            }
        }
        AuthType::Jwt => {
            debug!("Using JWT authentication for route {}", path);
            
            // Create JWT configuration from route config
            let jwt_config = match create_jwt_config(route_config) {
                Ok(config) => config,
                Err(e) => {
                    error!("Invalid JWT configuration for route {}: {}", path, e);
                    return Err(axum::response::Response::builder()
                        .status(500)
                        .body(axum::body::Body::from(format!("JWT configuration error: {}", e)))
                        .unwrap());
                }
            };
            
            // TODO - update this to extact the JWT token from headers or query params
            if let Some(auth_value) = &route_config.auth_value {
                // If auth_value contains a JWT token, validate it
                let token = if auth_value.starts_with("Bearer ") {
                    &auth_value[7..] // Remove "Bearer " prefix
                } else {
                    auth_value // Assume it's the raw JWT token
                };
                
                match validate_jwt_token(token, &jwt_config) {
                    Ok(claims) => {
                        debug!("JWT token validated for route {} with subject: {}", path, claims.sub);
                        // Forward the original token
                        Ok(builder.header("Authorization", auth_value))
                    }
                    Err(e) => {
                        warn!("JWT token validation failed for route {}: {}", path, e);
                        Err(axum::response::Response::builder()
                            .status(401)
                            .body(axum::body::Body::from("Invalid JWT token"))
                            .unwrap())
                    }
                }
            } else {
                // No token provided - this might be acceptable if JWT validation happens upstream
                debug!("No JWT token provided for route {}, forwarding request without token", path);
                Ok(builder)
            }
        }
        AuthType::Oidc => {
            // OIDC authentication logic would go here
            debug!("Using OIDC authentication for route {}", path);
            // For now, just return the builder without modification
            Ok(builder)
        }
        AuthType::None => {
            debug!("No authentication required for route {}", path);
            Ok(builder)
        }
    }
}

/// Check rate limits for a request
/// Returns Ok(()) if allowed, Err(response) if rate limited
async fn check_rate_limit(
    path: &str,
    rate_limit_per_minute: i64,
    rate_limit_per_hour: i64,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    metrics: &mut RequestMetrics,
) -> Result<(), axum::response::Response> {
    // Use path as the rate limiting key
    // In production, you might want to use client IP or user ID instead
    let rate_limit_key = format!("path:{}", path);
    
    // Check rate limits
    let rate_limit_exceeded = {
        let mut rate_limiter = rate_limiter.lock().unwrap();
        !rate_limiter.is_allowed(&rate_limit_key, rate_limit_per_minute as u32, rate_limit_per_hour as u32)
    };
    
    if rate_limit_exceeded {
        warn!(
            request_id = %metrics.id,
            path = %path,
            rate_limit_per_minute = rate_limit_per_minute,
            rate_limit_per_hour = rate_limit_per_hour,
            "Rate limit exceeded"
        );
        
        metrics.set_error("Rate limit exceeded".to_string());
        
        return Err(axum::response::Response::builder()
            .status(429)
            .header("Retry-After", "60") // Tell client to retry after 60 seconds
            .body(axum::body::Body::from("Too Many Requests"))
            .unwrap());
    }
    
    debug!(
        request_id = %metrics.id,
        path = %path,
        rate_limit_per_minute = rate_limit_per_minute,
        rate_limit_per_hour = rate_limit_per_hour,
        "Rate limit check passed"
    );
    
    Ok(())
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
    } => {
            // Parse the auth type and convert to enum
            let auth_type_enum = match auth_type.as_ref() {
                Some(auth_str) => AuthType::from_str(auth_str),
                None => AuthType::None,
            };
            
            sqlx::query(
                "INSERT OR REPLACE INTO routes 
                (path, upstream, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, rate_limit_per_minute, rate_limit_per_hour) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
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
                .execute(&pool)
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
                .execute(&pool)
                .await
                .expect("Failed to remove route");
            println!("Removed route: {}", path_copy);
        }
        Commands::ListRoutes => {
            let rows = sqlx::query("SELECT path, upstream, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, rate_limit_per_minute, rate_limit_per_hour FROM routes")
                .fetch_all(&pool)
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
                let auth_type = row.get::<String, _>("auth_type");
                let allowed_methods = row.get::<String, _>("allowed_methods");
                let oauth_client_id = row.get::<String, _>("oauth_client_id");
                let rate_limit_per_minute: i64 = row.get("rate_limit_per_minute");
                let rate_limit_per_hour: i64 = row.get("rate_limit_per_hour");
                let algorithm = row.get::<String, _>("jwt_algorithm");
                let issuer = row.get::<String, _>("jwt_issuer");
                let required_claims = row.get::<String, _>("jwt_required_claims");

                println!(
                    "{:<15} | {:<25} | {:<10} | {:<15} | {:<20} | {:<15} | {:<15} | {:<15} | {:<15} | {:<15}",
                    path, upstream, auth_type, allowed_methods, oauth_client_id, rate_limit_per_minute, rate_limit_per_hour, algorithm, issuer, required_claims
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
                .fetch_optional(&pool)
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
            .fetch_all(&pool)
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
                    let auth_type = row.get::<String, _>("auth_type");

                    println!(
                        "{:<8} | {:<15} | {:<6} | {:<20} | {:<8} | {:<6} | {:<10} | {:<12} | {:<10}",
                        short_id, path, method, &timestamp[..19], duration, status, req_size, resp_size, auth_type
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
            start_server(pool).await;
        }
        Commands::StartOAuthTestServer { port } => {
            start_oauth_test_server(pool, port.unwrap_or(3001)).await;
        }
    }
}
