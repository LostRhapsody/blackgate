use axum::{routing::get, Router, Json, http::Method, extract::OriginalUri};
use clap::{Parser, Subcommand};
use sqlx::{sqlite::SqlitePool, Row};
use serde::Deserialize;


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
    },
    /// List all routes
    ListRoutes,
    /// Start the API gateway server
    Start,
}

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
}

#[derive(Deserialize)]
struct PostRequest {
    payload: String,
}

async fn root() -> &'static str {
    "Welcome to Black Gate"
}

/// Handles incoming HTTP requests by forwarding them to configured upstream services.
/// Performs route lookup in the database and applies any configured authentication.
async fn handle_request(
    state: axum::extract::State<AppState>,  
    method: Method, 
    OriginalUri(uri): OriginalUri,
    Json(payload): Json<PostRequest>
) -> axum::response::Response {

    // Extract the method, URI, and body from the request
    let method = method.clone();
    let path = uri.path().to_string();
    let body = payload.payload;

    // metric code I commented out for now
    // let start = std::time::Instant::now();

    // Query the database for the route
    let row = sqlx::query("SELECT upstream, auth_type, auth_value, allowed_methods FROM routes WHERE path = ?")
        .bind(path)
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

            // Forward request to upstream
            let client = reqwest::Client::new();
            let mut builder = client.request(method, &upstream);
            if let (Some(auth_type), Some(auth_value)) = (auth_type, auth_value) {
                if auth_type == "api-key" {
                    builder = builder.header("Authorization", auth_value);
                }
            }

            let response = builder
                .body(body)
                .send()
                .await
                .expect("Upstream request failed");

            // Log metrics
            // let latency_ms = start.elapsed().as_millis() as i64;
            // let status = response.status().as_u16() as i32;
            // sqlx::query("INSERT INTO metrics (path, latency_ms, status) VALUES (?, ?, ?)")
            //     .bind(path)
            //     .bind(latency_ms)
            //     .bind(status)
            //     .execute(&state.db)
            //     .await
            //     .expect("Failed to log metrics");

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

async fn start_server(pool: SqlitePool) {
    let app_state = AppState { db: pool.clone() };
    let app = Router::new()
        .route("/", get(root))
        .fallback(handle_request)
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
            upstream TEXT NOT NULL
        )
        ;
        INSERT INTO routes (path, upstream, auth_type, auth_value, allowed_methods) 
        VALUES ('/warehouse', 'https://httpbin.org/post', 'api-key', 'Bearer warehouse_key','GET')
        ",
    )
    .execute(&pool)
    .await
    .expect("Failed to create routes table");

    // Parse CLI commands
    let cli = Cli::parse();

    match cli.command {
        Commands::AddRoute { path, upstream, auth_type, auth_value, allowed_methods } => {
            sqlx::query("INSERT OR REPLACE INTO routes (path, upstream, auth_type, auth_value, allowed_methods) VALUES (?, ?, ?, ?, ?)")
                .bind(path.clone())
                .bind(upstream.clone())
                .bind(auth_type.unwrap_or_else(|| "none".into()))
                .bind(auth_value.unwrap_or_else(|| "".into()))
                .bind(allowed_methods.unwrap_or_else(|| "".into()))
                .execute(&pool)
                .await
                .expect("Failed to add route");
            println!("Added route: {} -> {}", path, upstream);
        }
        Commands::ListRoutes => {
            let rows = sqlx::query("SELECT path, upstream, auth_type, auth_value, allowed_methods FROM routes")
                .fetch_all(&pool)
                .await
                .expect("Failed to list routes");
            for row in rows {
                println!("{} -> {} | {} | {} | {}", row.get::<String, _>("path"), row.get::<String, _>("upstream"), row.get::<String, _>("auth_type"), row.get::<String, _>("auth_value"), row.get::<String, _>("allowed_methods"));
            }
        }
        Commands::Start => {
            start_server(pool).await;
        }
    }
}