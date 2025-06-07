//! Metrics view for displaying request metrics and statistics.

use crate::{AppState, auth::types::AuthType, database::queries, web::handlers::MetricsQuery};
use axum::{
    extract::{Query, State},
    response::Html,
};
use sqlx::Row;

pub async fn metrics_view(
    State(state): State<AppState>,
    Query(query): Query<MetricsQuery>,
) -> Html<String> {
    let limit = query.limit.unwrap_or(20);

    // Get metrics statistics
    let stats_query = queries::fetch_metrics_statistics(&state.db)
        .await
        .unwrap_or_default();
    let mut html = String::from(
        r##"
        <h2>Metrics Dashboard</h2>
        <div class="dashboard-container">
    "##,
    );

    // Add statistics summary
    if let Some(row) = stats_query {
        let total_requests: i64 = row.get("total_requests");
        let success_count: i64 = row.get("success_count");
        let error_count: i64 = row.get("error_count");
        let avg_duration: f64 = row.get::<Option<f64>, _>("avg_duration_ms").unwrap_or(0.0);
        let min_duration: i64 = row.get::<Option<i64>, _>("min_duration_ms").unwrap_or(0);
        let max_duration: i64 = row.get::<Option<i64>, _>("max_duration_ms").unwrap_or(0);
        let total_request_bytes: i64 = row
            .get::<Option<i64>, _>("total_request_bytes")
            .unwrap_or(0);
        let total_response_bytes: i64 = row
            .get::<Option<i64>, _>("total_response_bytes")
            .unwrap_or(0);

        let success_rate = if total_requests > 0 {
            (success_count as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        html.push_str(&format!(
            r##"
            <div class="dashboard-summary">
                <h3>Statistics Summary</h3>
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
                        <label>Error Count:</label>
                        <span>{}</span>
                    </div>
                    <div class="stat-item">
                        <label>Average Duration:</label>
                        <span>{:.2}ms</span>
                    </div>
                    <div class="stat-item">
                        <label>Min Duration:</label>
                        <span>{}ms</span>
                    </div>
                    <div class="stat-item">
                        <label>Max Duration:</label>
                        <span>{}ms</span>
                    </div>
                    <div class="stat-item">
                        <label>Total Request Bytes:</label>
                        <span>{}</span>
                    </div>
                    <div class="stat-item">
                        <label>Total Response Bytes:</label>
                        <span>{}</span>
                    </div>
                </div>
            </div>
        "##,
            total_requests,
            success_rate,
            error_count,
            avg_duration,
            min_duration,
            max_duration,
            total_request_bytes,
            total_response_bytes
        ));
    } else {
        html.push_str(
            r##"
            <div class="dashboard-summary">
                <h3>Statistics Summary</h3>
                <p>No metrics data available</p>
            </div>
        "##,
        );
    }
    // Get recent requests
    let rows = queries::fetch_recent_request_metrics(&state.db, limit as i32)
        .await
        .unwrap_or_default();

    html.push_str(&format!(r##"
        <div class="dashboard-section">
            <div class="dashboard-header">
                <h3>Recent Requests (Last {})</h3>
                <div>
                    <label for="log-limit">Show:</label>
                    <select id="log-limit" name="limit" hx-get="/web/metrics" hx-target="#content" hx-swap="innerHTML" hx-include="this">
                        <option value="10"{}>10 logs</option>
                        <option value="20"{}>20 logs</option>
                        <option value="50"{}>50 logs</option>
                        <option value="100"{}>100 logs</option>
                        <option value="200"{}>200 logs</option>
                    </select>
                    <button hx-get="/web/metrics?limit={}" hx-target="#content" hx-swap="innerHTML" style="margin-left: 10px;">Refresh</button>
                </div>
            </div>
    "##,
        limit,
        if limit == 10 { " selected" } else { "" },
        if limit == 20 { " selected" } else { "" },
        if limit == 50 { " selected" } else { "" },
        if limit == 100 { " selected" } else { "" },
        if limit == 200 { " selected" } else { "" },
        limit
    ));

    if !rows.is_empty() {
        html.push_str(
            r##"
            <table class="data-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Path</th>
                        <th>Method</th>
                        <th>Timestamp</th>
                        <th>Duration</th>
                        <th>Status</th>
                        <th>Req Size</th>
                        <th>Resp Size</th>
                        <th>Auth Type</th>
                    </tr>
                </thead>
                <tbody>
        "##,
        );

        for row in rows {
            let id: String = row.get("id");
            let short_id = &id[..8]; // Show first 8 characters of UUID
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
            let req_size: i64 = row.get("request_size_bytes");
            let resp_size = row
                .get::<Option<i64>, _>("response_size_bytes")
                .map(|s| s.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let auth_type_str: String = row.get("auth_type");
            let auth_type = AuthType::from_str(&auth_type_str);

            html.push_str(&format!(
                r##"
                <tr>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{}</td>
                </tr>
            "##,
                short_id,
                path,
                method,
                &timestamp[..19],
                duration,
                status,
                req_size,
                resp_size,
                auth_type.to_display_string()
            ));

            // Show error message if present
            if let Some(error) = row.get::<Option<String>, _>("error_message") {
                html.push_str(&format!(
                    r##"
                <tr class="error-row">
                    <td colspan="9">Error: {}</td>
                </tr>
                "##,
                    error
                ));
            }
        }

        html.push_str("</tbody></table>");
    } else {
        html.push_str("<p>No recent requests available</p>");
    }

    html.push_str("</div></div>");
    Html(html)
}
