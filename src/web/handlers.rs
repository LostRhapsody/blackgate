use axum::{response::Html, extract::State};
use sqlx::Row;
use crate::AppState;

// Only handle dynamic HTMX responses now
pub async fn routes_list(State(state): State<AppState>) -> Html<String> {
    let rows = sqlx::query("SELECT path, upstream, auth_type, rate_limit_per_minute, rate_limit_per_hour FROM routes")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let mut html = String::from(r#"
        <h2>Routes</h2>
        <button hx-get="/web/routes/add-form" hx-target="\#routes-content">Add Route</button>
        <div id="routes-content">
        <table>
            <thead>
                <tr><th>Path</th><th>Upstream</th><th>Auth</th><th>Rate/Min</th><th>Actions</th></tr>
            </thead>
            <tbody>
    "#);

    for row in rows {
        let path: String = row.get("path");
        let upstream: String = row.get("upstream");
        let auth_type: String = row.get("auth_type");
        let rate_min: i64 = row.get("rate_limit_per_minute");

        html.push_str(&format!(r#"
            <tr>
                <td>{}</td><td>{}</td><td>{}</td><td>{}</td>
                <td><button hx-delete="/web/routes/{}" hx-target="closest tr" hx-swap="outerHTML">Delete</button></td>
            </tr>
        "#, path, upstream, auth_type, rate_min, path));
    }

    html.push_str("</tbody></table></div>");
    Html(html)
}

pub async fn metrics_view(State(_state): State<AppState>) -> Html<String> {
    // Similar dynamic content only...
    Html("<h2>Metrics will go here</h2>".to_string())
}