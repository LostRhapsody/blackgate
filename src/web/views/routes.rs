//! Routes view for the web application.
use crate::{
    AppState, auth::types::AuthType, database::queries, health::HealthStatus,
    web::handlers::generate_health_indicator,
};
use axum::{extract::State, response::Html};
use sqlx::Row;

pub async fn routes_list(State(state): State<AppState>) -> Html<String> {
    let rows = queries::fetch_routes_basic_info(&state.db)
        .await
        .unwrap_or_default();

    let mut html = String::from(
        r##"
        <h2>Routes</h2>
        <div class="dashboard-container">
            <button hx-get="/web/routes/add-form" hx-target="#routes-content">Add Route</button>
            <button hx-post="/web/routes/trigger-health" hx-target="#content" hx-swap="innerHTML" hx-confirm="Trigger health check for all routes?">Check Health</button>
            <div id="routes-content" class="dashboard-section">
                <h3>Configured Routes</h3>
    "##,
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
                                <button hx-get="/web/routes/edit/{}" hx-target="#routes-content" hx-swap="innerHTML">Edit</button>
                                <button hx-post="/web/routes/trigger-health/{}" hx-target="#content" hx-swap="innerHTML" hx-confirm="Trigger health check for this route?">Check</button>
                                <button hx-post="/web/routes/clear-health/{}" hx-target="#content" hx-swap="innerHTML" hx-confirm="Clear health status for this route?">Clear</button>
                                <button hx-delete="/web/routes/{}" hx-target="closest tr" hx-swap="outerHTML" hx-confirm="Delete this route?">Delete</button>
                            </td>
                        </tr>
            "##, health_indicator, path, upstream, auth_type.to_display_string(), rate_min, rate_hour, health_status, path, path, path, path));
        }

        html.push_str("</tbody></table>");
    } else {
        html.push_str("<p>No routes configured</p>");
    }

    html.push_str("</div></div>");
    Html(html)
}
