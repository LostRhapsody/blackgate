use axum::{routing::get, Router};
use super::handlers;
use crate::AppState;

pub fn create_routes() -> Router<AppState> {
    Router::new()
        // Root redirects to dashboard
        .route("/", axum::routing::get(|| async { 
            axum::response::Redirect::permanent("/templates/dashboard.html") 
        }))
        .route("/dashboard", axum::routing::get(|| async { 
            axum::response::Redirect::permanent("/templates/dashboard.html") 
        }))
        // HTMX dynamic content endpoints
        .route("/web/routes", get(handlers::routes_list))
        .route("/web/metrics", get(handlers::metrics_view))
}