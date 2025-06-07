//! View functions for route collections

use crate::{
    AppState, auth::types::AuthType, database::queries, health::HealthStatus,
    web::handlers::generate_health_indicator,
};
use axum::{
    extract::{Path, State},
    response::Html,
};
use sqlx::Row;
use tracing::error;

// Provides a list view of all route collections.
pub async fn collections_list(State(state): State<AppState>) -> Html<String> {
    let collections = match queries::fetch_all_route_collections(&state.db).await {
        Ok(collections) => collections,
        Err(e) => {
            error!("Failed to fetch collections: {}", e);
            return Html("<div class='error'>Failed to load collections</div>".to_string());
        }
    };

    let mut html = String::new();
    html.push_str(r##"
        <h2>Route Collections</h2>
        <div class="header-section">
            <button hx-get="/web/collections/add-form" hx-target="#content" hx-swap="innerHTML">Add Collection</button>
        </div>
        <div class="table-container">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Description</th>
                        <th>Default Auth</th>
                        <th>Rate Limits</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
    "##);

    for collection in collections {
        let id: i64 = collection.get("id");
        let name: String = collection.get("name");
        let description: String = collection
            .get::<Option<String>, _>("description")
            .unwrap_or_default();
        let default_auth_type: String = collection.get("default_auth_type");
        let default_rate_limit_per_minute: i64 = collection.get("default_rate_limit_per_minute");
        let default_rate_limit_per_hour: i64 = collection.get("default_rate_limit_per_hour");
        let created_at: String = collection.get("created_at");

        html.push_str(&format!(
            r##"
                <tr>
                    <td><strong>{}</strong></td>
                    <td>{}</td>
                    <td><span class="auth-type">{}</span></td>
                    <td>{}/min, {}/hr</td>
                    <td>{}</td>
                    <td class="action-buttons">
                        <button hx-get="/web/collections/{}/routes" hx-target="#content" hx-swap="innerHTML">Routes</button>
                        <button hx-get="/web/collections/edit/{}" hx-target="#content" hx-swap="innerHTML">Edit</button>
                        <button hx-delete="/web/collections/{}" hx-target="#content" hx-swap="innerHTML" hx-confirm="Are you sure you want to delete this collection?">Delete</button>
                    </td>
                </tr>
            "##,
            name, description, default_auth_type, default_rate_limit_per_minute, default_rate_limit_per_hour, created_at, id, id, id
        ));
    }

    html.push_str("</tbody></table></div>");
    Html(html)
}

/// Provides a list view of all the routes in a specific collection.
pub async fn collection_routes_view(
    State(state): State<AppState>,
    Path(collection_id): Path<i64>,
) -> Html<String> {
    // Fetch collection information
    let collection = queries::fetch_route_collection_by_id(&state.db, collection_id)
        .await
        .unwrap_or(None);

    let collection_name = if let Some(ref collection_row) = collection {
        let name: String = collection_row.get("name");
        name
    } else {
        format!("Collection {}", collection_id)
    };

    // Fetch routes in this collection
    let rows = queries::fetch_routes_in_collection(&state.db, collection_id)
        .await
        .unwrap_or_default();

    let mut html = format!(
        r##"
        <h2>Routes in Collection: {}</h2>
        <div class="dashboard-container">
            <button hx-get="/web/collections" hx-target="#content" hx-swap="innerHTML">← Back to Collections</button>
            <button hx-get="/web/routes/add-form?collection_id={}" hx-target="#content" hx-swap="innerHTML">Add Route to Collection</button>
            <div class="dashboard-section">
                <h3>Routes in this Collection</h3>
    "##,
        collection_name, collection_id
    );

    if !rows.is_empty() {
        html.push_str(
            r##"
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Path</th>
                            <th>Upstream</th>
                            <th>Auth</th>
                            <th>Rate/Min</th>
                            <th>Rate/Hour</th>
                            <th>Health Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
        "##,
        );
        for row in rows {
            let path: String = row.get("path");
            let upstream: String = row.get("upstream");
            let auth_type_str: String = row.get("auth_type");
            let auth_type = AuthType::from_str(&auth_type_str);
            let rate_min: i64 = row.get("rate_limit_per_minute");
            let rate_hour: i64 = row.get("rate_limit_per_hour");

            // unwrap that health status
            let health_status: Option<String> = row.get("health_check_status");
            let health_status = health_status.unwrap_or_else(|| HealthStatus::Unknown.to_string());
            let health_indicator = generate_health_indicator(&health_status);

            html.push_str(&format!(r##"
                        <tr>
                            <td>{} {}</td>
                            <td>{}</td>
                            <td>{}</td>
                            <td>{}</td>
                            <td>{}</td>
                            <td>{}</td>
                            <td>
                                <button hx-get="/web/routes/edit/{}" hx-target="#content" hx-swap="innerHTML">Edit</button>
                                <button hx-post="/web/routes/trigger-health/{}" hx-target="#content" hx-swap="innerHTML" hx-confirm="Trigger health check for this route?">Check</button>
                                <button hx-post="/web/routes/clear-health/{}" hx-target="#content" hx-swap="innerHTML" hx-confirm="Clear health status for this route?">Clear</button>
                                <button hx-delete="/web/routes/{}" hx-target="closest tr" hx-swap="outerHTML" hx-confirm="Delete this route?">Delete</button>
                            </td>
                        </tr>
            "##, health_indicator, path, upstream, auth_type.to_display_string(), rate_min, rate_hour, health_status, path, path, path, path));
        }

        html.push_str("</tbody></table>");
    } else {
        html.push_str(&format!(r##"<p>No routes found in this collection. <a href="#" hx-get="/web/routes/add-form?collection_id={}" hx-target="#content" hx-swap="innerHTML">Add a route</a> to get started.</p>"##, collection_id));
    }

    html.push_str("</div></div>");
    Html(html)
}
