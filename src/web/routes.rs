use super::handlers;
use crate::{
    AppState,
    web::forms::{
        collections::add_collection_form, collections::edit_collection_form,
        settings::add_setting_form, settings::edit_setting_form,
    },
    web::views::{
        collections::collection_routes_view, collections::collections_list,
        dashboard::dashboard_view, metrics::metrics_view, routes::routes_list,
        settings::settings_view,
    },
};
use axum::{
    Router,
    routing::{delete, get, post},
};

pub fn create_routes() -> Router<AppState> {
    Router::new()
        // Root redirects to dashboard
        .route("/", get(handlers::home_page))
        // HTMX dynamic content endpoints
        .route("/web/dashboard", get(dashboard_view))
        .route("/web/routes", get(routes_list))
        .route("/web/routes/add-form", get(handlers::add_route_form))
        .route("/web/routes/auth-fields", get(handlers::auth_fields_form))
        .route("/web/routes/add", post(handlers::add_route_submit))
        .route("/web/routes/edit/{*path}", get(handlers::edit_route_form))
        .route(
            "/web/routes/edit/{*path}",
            post(handlers::edit_route_submit),
        )
        .route("/web/routes/{*path}", delete(handlers::delete_route))
        .route(
            "/web/routes/clear-health/{*path}",
            post(handlers::clear_route_health_status),
        )
        .route(
            "/web/routes/trigger-health",
            post(handlers::trigger_all_routes_health_check),
        )
        .route(
            "/web/routes/trigger-health/{*path}",
            post(handlers::trigger_route_health_check),
        )
        .route("/web/metrics", get(metrics_view))
        // Collection routes
        .route("/web/collections", get(collections_list))
        .route("/web/collections/add-form", get(add_collection_form))
        .route(
            "/web/collections/auth-fields",
            get(handlers::collection_auth_fields_form),
        )
        .route(
            "/web/collections/toggle-fields",
            get(handlers::toggle_collection_fields),
        )
        .route(
            "/web/collections/add",
            post(handlers::add_collection_submit),
        )
        .route("/web/collections/edit/{id}", get(edit_collection_form))
        .route(
            "/web/collections/edit/{id}",
            post(handlers::edit_collection_submit),
        )
        .route("/web/collections/{id}", delete(handlers::delete_collection))
        .route("/web/collections/{id}/routes", get(collection_routes_view))
        // Settings routes
        .route("/web/settings", get(settings_view))
        .route("/web/settings/add-form", get(add_setting_form))
        .route("/web/settings/add", post(handlers::add_setting_submit))
        .route("/web/settings/edit/{key}", get(edit_setting_form))
        .route(
            "/web/settings/edit/{key}",
            post(handlers::edit_setting_submit),
        )
        .route("/web/settings/{key}", delete(handlers::delete_setting))
}
