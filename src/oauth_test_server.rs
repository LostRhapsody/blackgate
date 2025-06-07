use axum::{
    extract::Json,
    http::{StatusCode, Request},
    routing::{get, post},
    Router,
    response::Response,
    middleware::Next,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;
use tracing::info;

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: Option<String>,
}

// Middleware to log full request details
async fn log_request(req: Request<axum::body::Body>, next: Next) -> Result<Response, StatusCode> {
    println!("Received request: {} {}", req.method(), req.uri());
    println!("HTTP Version: {:?}", req.version());
    println!("Headers: {:?}", req.headers());
    if let Some(content_type) = req.headers().get("content-type") {
        println!("Content-Type: {:?}", content_type.to_str().unwrap_or("Invalid"));
    } else {
        println!("Content-Type: None");
    }

    // Note: We can't easily log the body without consuming it, so we rely on Json extractor
    let response = next.run(req).await;
    println!("Response status: {:?}", response.status());
    println!("Response headers: {:?}", response.headers());
    Ok(response)
}

// Function to handle token endpoint requests
async fn token_endpoint(Json(request): Json<TokenRequest>) -> (StatusCode, Json<TokenResponse>) {
    // Log the request details for debugging
    println!("OAuth Test Server - Token request received:");
    println!("  grant_type: {}", request.grant_type);
    println!("  client_id: {}", request.client_id);
    println!("  scope: {:?}", request.scope);

    // Simple validation - in a real server we would validate the client credentials
    if request.grant_type != "client_credentials" {
        // Only client_credentials grant type is supported in this simple test server
        return (
            StatusCode::BAD_REQUEST,
            Json(TokenResponse {
                access_token: "invalid_grant_type".to_string(),
                token_type: "bearer".to_string(),
                expires_in: 0,
                scope: None,
            }),
        );
    }

    // Check if client_id and client_secret are valid
    // For testing purposes, we'll accept any non-empty values
    if request.client_id.is_empty() || request.client_secret.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(TokenResponse {
                access_token: "invalid_client".to_string(),
                token_type: "bearer".to_string(),
                expires_in: 0,
                scope: None,
            }),
        );
    }

    // Generate a random token (using UUID v4)
    let token = Uuid::new_v4().to_string();

    // Return successful response
    (
        StatusCode::OK,
        Json(TokenResponse {
            access_token: token,
            token_type: "bearer".to_string(),
            expires_in: 3600, // Token valid for 1 hour
            scope: request.scope,
        }),
    )
}

// A simple info endpoint to test with the token
async fn info_endpoint() -> &'static str {
    "OAuth 2.0 Test Server - Info Endpoint"
}

// Function to spawn the test OAuth server
pub async fn spawn_oauth_test_server() -> (SocketAddr, oneshot::Sender<()>) {
    let app = Router::new()
        .route("/oauth/token", post(token_endpoint))
        .route("/oauth/info", get(info_endpoint))
        .layer(axum::middleware::from_fn(log_request));

    // Create a shutdown channel
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    let addr = listener.local_addr().unwrap();

    info!("OAuth Test Server running on http://{}", addr);

    let server = axum::serve(
        listener,
        app.into_make_service(),
    ).with_graceful_shutdown(async {
        shutdown_rx.await.ok();
    });

    // Spawn the server on a new task
    tokio::spawn(async move {
        if let Err(err) = server.await {
            eprintln!("OAuth Test Server error: {}", err);
        }
        println!("OAuth Test Server shutdown");
    });

    (addr, shutdown_tx)
}
