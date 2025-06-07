//! This module provides the dashboard view for the web application.

use crate::{AppState, database::queries};
use axum::{extract::State, response::Html};
use sqlx::Row;

pub async fn dashboard_view(State(state): State<AppState>) -> Html<String> {
    // Get recent metrics for last 5 requests
    let recent_requests = queries::fetch_recent_requests_for_dashboard(&state.db, 5)
        .await
        .unwrap_or_default();

    // Get basic metrics summary
    let stats_query = queries::fetch_basic_metrics_summary(&state.db)
        .await
        .unwrap_or_default();

    // Get configured routes count
    let routes_count = queries::count_routes(&state.db).await.unwrap_or(0);

    let mut html = String::from(
        r##"
        <h2>Dashboard</h2>
        <div class="dashboard-container">
            <div id="dashboard-content">
    "##,
    );

    // Add metrics summary
    html.push_str(r##"
                <div class="dashboard-section">
                    <div class="dashboard-header">
                        <h3>Metrics Summary</h3>
                        <button hx-get="/web/metrics" hx-target="#content" hx-swap="innerHTML">View Full Metrics</button>
                    </div>
    "##);

    if let Some(row) = stats_query {
        let total_requests: i64 = row.get("total_requests");
        let success_count: i64 = row.get("success_count");
        let avg_duration: f64 = row.get::<Option<f64>, _>("avg_duration_ms").unwrap_or(0.0);

        let success_rate = if total_requests > 0 {
            (success_count as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        html.push_str(&format!(
            r##"
                    <div class="stats-grid">
                        <div class="stat-item">
                            <label>Total Requests:</label>
                            <span>{}</span>
                        </div>
                        <div class="stat-item">
                            <label>Success Rate:</label>
                            <span>{:.1}%</span>
                        </div>
                        <div class="stat-item">
                            <label>Average Duration:</label>
                            <span>{:.2}ms</span>
                        </div>
                        <div class="stat-item">
                            <label>Configured Routes:</label>
                            <span>{}</span>
                        </div>
                    </div>
        "##,
            total_requests, success_rate, avg_duration, routes_count
        ));
    } else {
        html.push_str("<p>No metrics data available</p>");
    }

    html.push_str("</div>");

    // Add recent requests section
    html.push_str(r##"
                <div class="dashboard-section">
                    <div class="dashboard-header">
                        <h3>Recent Requests (Last 5)</h3>
                        <button hx-get="/web/metrics" hx-target="#content" hx-swap="innerHTML">View All Requests</button>
                    </div>
    "##);

    if !recent_requests.is_empty() {
        html.push_str(
            r##"
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Path</th>
                                <th>Method</th>
                                <th>Timestamp</th>
                                <th>Duration</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
        "##,
        );

        for row in recent_requests {
            let path: String = row.get("path");
            let method: String = row.get("method");
            let timestamp: String = row.get("request_timestamp");
            let duration = row
                .get::<Option<i64>, _>("duration_ms")
                .map(|d| format!("{}ms", d))
                .unwrap_or_else(|| "N/A".to_string());
            let status = row
                .get::<Option<u16>, _>("response_status_code")
                .map(|s| s.to_string())
                .unwrap_or_else(|| "N/A".to_string());

            html.push_str(&format!(
                r##"
                            <tr>
                                <td>{}</td>
                                <td>{}</td>
                                <td>{}</td>
                                <td>{}</td>
                                <td>{}</td>
                            </tr>
            "##,
                path,
                method,
                &timestamp[..19],
                duration,
                status
            ));
        }

        html.push_str("</tbody></table>");
    } else {
        html.push_str("<p>No recent requests available</p>");
    }

    html.push_str(r##"
                </div>
                <div class="dashboard-section">
                    <div class="dashboard-header">
                        <h3>Quick Actions</h3>
                    </div>
                    <p>
                        <button hx-get="/web/routes" hx-target="#content" hx-swap="innerHTML">Manage Routes</button>
                        <button hx-get="/web/routes/add-form" hx-target="#content" hx-swap="innerHTML">Add New Route</button>
                    </p>
                </div>
            </div>
        </div>
    "##);

    Html(html)
}
