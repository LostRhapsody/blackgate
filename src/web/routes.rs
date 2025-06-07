use axum::{routing::{get, post, delete}, Router};
use super::handlers;
use crate::AppState;

pub fn create_routes() -> Router<AppState> {
    Router::new()
        // Root redirects to dashboard
        .route("/", get(handlers::home_page))
        // HTMX dynamic content endpoints
        .route("/web/dashboard", get(handlers::dashboard_view))
        .route("/web/routes", get(handlers::routes_list))
        .route("/web/routes/add-form", get(handlers::add_route_form))
        .route("/web/routes/auth-fields", get(handlers::auth_fields_form))
        .route("/web/routes/add", post(handlers::add_route_submit))
        .route("/web/routes/edit/{*path}", get(handlers::edit_route_form))
        .route("/web/routes/edit/{*path}", post(handlers::edit_route_submit))
        .route("/web/routes/{*path}", delete(handlers::delete_route))
        .route("/web/routes/clear-health/{*path}", post(handlers::clear_route_health_status))
        .route("/web/routes/trigger-health/", post(handlers::trigger_all_routes_health_check))
        .route("/web/routes/trigger-health/{*path}", post(handlers::trigger_route_health_check))
        .route("/web/metrics", get(handlers::metrics_view))
        // Settings routes
        .route("/web/settings", get(handlers::settings_view))
        .route("/web/settings/add-form", get(handlers::add_setting_form))
        .route("/web/settings/add", post(handlers::add_setting_submit))
        .route("/web/settings/edit/{key}", get(handlers::edit_setting_form))
        .route("/web/settings/edit/{key}", post(handlers::edit_setting_submit))
        .route("/web/settings/{key}", delete(handlers::delete_setting))
}