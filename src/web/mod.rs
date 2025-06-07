pub mod handlers;
pub mod routes;
pub mod forms;
pub mod views;

use axum::Router;
use tower_http::services::ServeDir;

pub fn create_web_router() -> Router<crate::AppState> {
    Router::new()
        .merge(routes::create_routes())
        // Serve static assets (CSS, JS, images)
        .nest_service("/static", ServeDir::new("static"))
        // Serve HTML templates
        .nest_service("/templates", ServeDir::new("templates"))
}