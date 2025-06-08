use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::time::{sleep, Duration};
use tracing::info;

#[derive(Serialize, Deserialize)]
struct TestResponse {
    message: String,
    timestamp: chrono::DateTime<chrono::Utc>,
    endpoint: String,
    delay_ms: Option<u64>,
}

#[derive(Deserialize)]
struct DelayParams {
    delay: Option<u64>,
}

// Fast endpoint - minimal processing
async fn fast_endpoint() -> Json<TestResponse> {
    Json(TestResponse {
        message: "Fast response".to_string(),
        timestamp: chrono::Utc::now(),
        endpoint: "fast".to_string(),
        delay_ms: None,
    })
}

// Slow endpoint - simulates processing delay
async fn slow_endpoint(Query(params): Query<DelayParams>) -> Json<TestResponse> {
    let delay = params.delay.unwrap_or(100);
    sleep(Duration::from_millis(delay)).await;
    
    Json(TestResponse {
        message: "Slow response".to_string(),
        timestamp: chrono::Utc::now(),
        endpoint: "slow".to_string(),
        delay_ms: Some(delay),
    })
}

// Echo endpoint - returns the path parameter
async fn echo_endpoint(Path(param): Path<String>) -> Json<TestResponse> {
    Json(TestResponse {
        message: format!("Echo: {}", param),
        timestamp: chrono::Utc::now(),
        endpoint: "echo".to_string(),
        delay_ms: None,
    })
}

// JSON payload endpoint
async fn json_endpoint(Json(payload): Json<Value>) -> Json<Value> {
    Json(json!({
        "received": payload,
        "timestamp": chrono::Utc::now(),
        "endpoint": "json"
    }))
}

// Error simulation endpoint
async fn error_endpoint(Path(code): Path<u16>) -> Result<Json<Value>, StatusCode> {
    match code {
        200..=299 => Ok(Json(json!({
            "message": "Success response",
            "code": code,
            "timestamp": chrono::Utc::now()
        }))),
        400 => Err(StatusCode::BAD_REQUEST),
        404 => Err(StatusCode::NOT_FOUND),
        500 => Err(StatusCode::INTERNAL_SERVER_ERROR),
        503 => Err(StatusCode::SERVICE_UNAVAILABLE),
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

// Health check endpoint
async fn health_endpoint() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now(),
        "uptime": "unknown"
    }))
}

// Large response endpoint - for testing payload sizes
async fn large_response_endpoint(Path(size_kb): Path<usize>) -> Json<Value> {
    let size_bytes = size_kb * 1024;
    let data = "x".repeat(size_bytes);
    
    Json(json!({
        "data": data,
        "size_kb": size_kb,
        "timestamp": chrono::Utc::now()
    }))
}

// CRUD-like endpoints for testing different HTTP methods
async fn get_resource(Path(id): Path<String>) -> Json<Value> {
    Json(json!({
        "id": id,
        "method": "GET",
        "timestamp": chrono::Utc::now()
    }))
}

async fn create_resource(Json(payload): Json<Value>) -> (StatusCode, Json<Value>) {
    (
        StatusCode::CREATED,
        Json(json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "method": "POST",
            "data": payload,
            "timestamp": chrono::Utc::now()
        }))
    )
}

async fn update_resource(Path(id): Path<String>, Json(payload): Json<Value>) -> Json<Value> {
    Json(json!({
        "id": id,
        "method": "PUT",
        "data": payload,
        "timestamp": chrono::Utc::now()
    }))
}

async fn delete_resource(Path(id): Path<String>) -> StatusCode {
    info!("Deleting resource: {}", id);
    StatusCode::NO_CONTENT
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("upstream_test_server=info")
        .init();

    let app = Router::new()
        // Basic test endpoints
        .route("/health", get(health_endpoint))
        .route("/fast", get(fast_endpoint))
        .route("/slow", get(slow_endpoint))
        .route("/echo/{param}", get(echo_endpoint))
        .route("/json", post(json_endpoint))
        
        // Error simulation
        .route("/error/{code}", get(error_endpoint))
        
        // Large response testing
        .route("/large/{size_kb}", get(large_response_endpoint))
        
        // CRUD endpoints
        .route("/resource/{id}", get(get_resource))
        .route("/resource", post(create_resource))
        .route("/resource/{id}", put(update_resource))
        .route("/resource/{id}", delete(delete_resource));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("Failed to bind to port 8080");

    info!("🚀 Upstream test server running on http://0.0.0.0:8080");
    info!("Available endpoints:");
    info!("  GET  /health          - Health check");
    info!("  GET  /fast            - Fast response");
    info!("  GET  /slow?delay=100  - Slow response with configurable delay");
    info!("  GET  /echo/<param>    - Echo parameter");
    info!("  POST /json            - Accept JSON payload");
    info!("  GET  /error/<code>    - Return specific HTTP status code");
    info!("  GET  /large/<size_kb> - Return large response");
    info!("  GET  /resource/<id>   - Get resource");
    info!("  POST /resource        - Create resource");
    info!("  PUT  /resource/<id>   - Update resource");
    info!("  DELETE /resource/<id> - Delete resource");

    axum::serve(listener, app)
        .await
        .expect("Server failed to start");
}
