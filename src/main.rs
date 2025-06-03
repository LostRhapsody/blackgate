use axum::{routing::get, Router, Json, http::Method, extract::OriginalUri};

#[cfg(test)]
mod tests;
mod test_server;
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
    /// Remove a route
    RemoveRoute {
        #[arg(long)] path: String,
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


/// Handles requests with a JSON body (POST, PUT, etc)
async fn handle_request_with_body(
    state: axum::extract::State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    Json(payload): Json<PostRequest>
) -> axum::response::Response {
    handle_request_core(state, method, uri.path().to_string(), Some(payload.payload)).await
}

/// Handles requests with no body (GET, HEAD, etc)
async fn handle_request_no_body(
    state: axum::extract::State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
) -> axum::response::Response {
    handle_request_core(state, method, uri.path().to_string(), None).await
}

/// Core handler logic, shared by both body/no-body handlers
async fn handle_request_core(
    state: axum::extract::State<AppState>,
    method: Method,
    path: String,
    body: Option<String>,
) -> axum::response::Response {
    // Query the database for the route
    let row = sqlx::query("SELECT upstream, auth_type, auth_value, allowed_methods FROM routes WHERE path = ?")
        .bind(&path)
        .fetch_optional(&state.db)
        .await
        .expect("Database query failed");

    match row {
        Some(row) => {
            // confirm the method is allowed
            let allowed_methods: String = row.get("allowed_methods");
            println!("Allowed methods: {}", allowed_methods);
            println!("Request method: {}", method.as_str());
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
async fn start_server(pool: SqlitePool) {
    let app_state = AppState { db: pool.clone() };
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
            upstream TEXT NOT NULL
        );
        INSERT INTO routes (path, upstream, auth_type, auth_value, allowed_methods) 
        VALUES ('/warehouse', 'https://httpbin.org/post', 'api-key', 'Bearer warehouse_key','POST');
        INSERT INTO routes (path, upstream, auth_type, auth_value, allowed_methods) 
        VALUES ('/warehouse-get', 'https://httpbin.org/post', 'api-key', 'Bearer warehouse_key','GET');
        INSERT INTO routes (path, upstream, auth_type, auth_value, allowed_methods) 
        VALUES ('/warehouse-none', 'https://httpbin.org/post', 'api-key', 'Bearer warehouse_key','');
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
        Commands::RemoveRoute { path } => {
            sqlx::query("DELETE FROM routes WHERE path = ?")
                .bind(path)
                .execute(&pool)
                .await
                .expect("Failed to remove route");
            println!("Removed route: {}", path);
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