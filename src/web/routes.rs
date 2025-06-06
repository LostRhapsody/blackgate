use axum::{routing::{get, post, delete}, Router};
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
        .route("/web/routes/add-form", get(handlers::add_route_form))
        .route("/web/routes/auth-fields", get(handlers::auth_fields_form))
        .route("/web/routes/add", post(handlers::add_route_submit))
        .route("/web/routes/edit/{*path}", get(handlers::edit_route_form))
        .route("/web/routes/edit/{*path}", post(handlers::edit_route_submit))
        .route("/web/routes/{*path}", delete(handlers::delete_route))
        .route("/web/metrics", get(handlers::metrics_view))
}