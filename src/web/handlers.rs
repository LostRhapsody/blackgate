use axum::{response::Html, extract::{State, Form, Path, Query}, http::StatusCode};
use serde::Deserialize;
use sqlx::Row;
use crate::{AppState, AuthType};

///////////////////////////////////////////////////////////////////////////////
//****                         Public Structs                            ****//
///////////////////////////////////////////////////////////////////////////////

#[derive(Deserialize)]
pub struct MetricsQuery {
    limit: Option<u32>,
}

#[derive(Deserialize, Default)]
pub struct RouteFormData {
    path: String,
    upstream: String,
    auth_type: String,
    auth_value: Option<String>,
    allowed_methods: Option<String>,
    oauth_token_url: Option<String>,
    oauth_client_id: Option<String>,
    oauth_client_secret: Option<String>,
    oauth_scope: Option<String>,
    jwt_secret: Option<String>,
    jwt_algorithm: Option<String>,
    jwt_issuer: Option<String>,
    jwt_audience: Option<String>,
    jwt_required_claims: Option<String>,
    oidc_issuer: Option<String>,
    oidc_client_id: Option<String>,
    oidc_client_secret: Option<String>,
    oidc_audience: Option<String>,
    oidc_scope: Option<String>,
    rate_limit_per_minute: Option<u32>,
    rate_limit_per_hour: Option<u32>,
}

///////////////////////////////////////////////////////////////////////////////
//****                       Helper Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

fn generate_auth_fields(auth_type: AuthType, form_data: &RouteFormData) -> String {
    match auth_type {
        AuthType::ApiKey => format!(
            r##"
                <div>
                    <label for="auth_value">API Key (with Bearer prefix if needed):</label><br>
                    <input type="text" id="auth_value" name="auth_value" value="{}">
                </div>
            "##,
            form_data.auth_value.as_deref().unwrap_or("")
        ),
        AuthType::OAuth2 => format!(
            r##"
                <div>
                    <label for="oauth_token_url">OAuth Token URL:</label><br>
                    <input type="url" id="oauth_token_url" name="oauth_token_url" value="{}">
                </div>
                <div>
                    <label for="oauth_client_id">OAuth Client ID:</label><br>
                    <input type="text" id="oauth_client_id" name="oauth_client_id" value="{}">
                </div>
                <div>
                    <label for="oauth_client_secret">OAuth Client Secret:</label><br>
                    <input type="password" id="oauth_client_secret" name="oauth_client_secret" value="{}">
                </div>
                <div>
                    <label for="oauth_scope">OAuth Scope:</label><br>
                    <input type="text" id="oauth_scope" name="oauth_scope" value="{}">
                </div>
            "##,
            form_data.oauth_token_url.as_deref().unwrap_or(""),
            form_data.oauth_client_id.as_deref().unwrap_or(""),
            form_data.oauth_client_secret.as_deref().unwrap_or(""),
            form_data.oauth_scope.as_deref().unwrap_or("")
        ),
        AuthType::Jwt => format!(
            r##"
                <div>
                    <label for="jwt_secret">JWT Secret:</label><br>
                    <input type="password" id="jwt_secret" name="jwt_secret" value="{}">
                </div>
                <div>
                    <label for="jwt_algorithm">JWT Algorithm:</label><br>
                    <select id="jwt_algorithm" name="jwt_algorithm">
                        <option value="HS256"{}>HS256</option>
                        <option value="HS384"{}>HS384</option>
                        <option value="HS512"{}>HS512</option>
                    </select>
                </div>
                <div>
                    <label for="jwt_issuer">JWT Issuer (optional):</label><br>
                    <input type="text" id="jwt_issuer" name="jwt_issuer" value="{}">
                </div>
                <div>
                    <label for="jwt_audience">JWT Audience (optional):</label><br>
                    <input type="text" id="jwt_audience" name="jwt_audience" value="{}">
                </div>
                <div>
                    <label for="jwt_required_claims">JWT Required Claims (comma-separated, optional):</label><br>
                    <input type="text" id="jwt_required_claims" name="jwt_required_claims" value="{}">
                </div>
                <div>
                    <label for="auth_value">JWT Token for testing (optional):</label><br>
                    <input type="text" id="auth_value" name="auth_value" value="{}">
                </div>
            "##,
            form_data.jwt_secret.as_deref().unwrap_or(""),
            if form_data.jwt_algorithm.as_deref() == Some("HS256") { " selected" } else { "" },
            if form_data.jwt_algorithm.as_deref() == Some("HS384") { " selected" } else { "" },
            if form_data.jwt_algorithm.as_deref() == Some("HS512") { " selected" } else { "" },
            form_data.jwt_issuer.as_deref().unwrap_or(""),
            form_data.jwt_audience.as_deref().unwrap_or(""),
            form_data.jwt_required_claims.as_deref().unwrap_or(""),
            form_data.auth_value.as_deref().unwrap_or("")
        ),
        AuthType::Oidc => format!(
            r##"
                <div>
                    <label for="oidc_issuer">OIDC Issuer URL:</label><br>
                    <input type="url" id="oidc_issuer" name="oidc_issuer" value="{}">
                </div>
                <div>
                    <label for="oidc_client_id">OIDC Client ID:</label><br>
                    <input type="text" id="oidc_client_id" name="oidc_client_id" value="{}">
                </div>
                <div>
                    <label for="oidc_client_secret">OIDC Client Secret:</label><br>
                    <input type="password" id="oidc_client_secret" name="oidc_client_secret" value="{}">
                </div>
                <div>
                    <label for="oidc_audience">OIDC Audience (optional):</label><br>
                    <input type="text" id="oidc_audience" name="oidc_audience" value="{}">
                </div>
                <div>
                    <label for="oidc_scope">OIDC Scope:</label><br>
                    <input type="text" id="oidc_scope" name="oidc_scope" value="{}">
                </div>
                <div>
                    <label for="auth_value">OIDC Token for testing (optional):</label><br>
                    <input type="text" id="auth_value" name="auth_value" value="{}">
                </div>
            "##,
            form_data.oidc_issuer.as_deref().unwrap_or(""),
            form_data.oidc_client_id.as_deref().unwrap_or(""),
            form_data.oidc_client_secret.as_deref().unwrap_or(""),
            form_data.oidc_audience.as_deref().unwrap_or(""),
            form_data.oidc_scope.as_deref().unwrap_or(""),
            form_data.auth_value.as_deref().unwrap_or("")
        ),
        AuthType::None => "".to_string(),
    }
}

fn generate_route_form(is_edit: bool, path: &str, form_data: RouteFormData) -> String {
    let (title, action, submit_text) = if is_edit {
        (
            format!("Edit Route: {}", path),
            format!("/web/routes/edit/{}", path),
            "Update Route",
        )
    } else {
        (
            "Add New Route".to_string(),
            "/web/routes/add".to_string(),
            "Add Route",
        )
    };

    let auth_fields = generate_auth_fields(AuthType::from_str(&form_data.auth_type), &form_data);
    let auth_type = AuthType::from_str(&form_data.auth_type);

    format!(
        r##"
            <h3>{}</h3>
            <form hx-post="{}" hx-target="#content" hx-swap="innerHTML">
                <div>
                    <label for="path">Path:</label><br>
                    <input type="text" id="path" name="path" required value="{}" placeholder="/api/example">
                </div>
                
                <div>
                    <label for="upstream">Upstream URL:</label><br>
                    <input type="url" id="upstream" name="upstream" required value="{}" placeholder="https://api.example.com">
                </div>

                <div>
                    <label for="auth_type">Authentication Type:</label><br>
                    <select id="auth_type" name="auth_type" hx-trigger="change" hx-target="#auth-fields" hx-get="/web/routes/auth-fields?auth_type={}" hx-swap="innerHTML">
                        <option value="none"{}>None</option>
                        <option value="api-key"{}>API Key</option>
                        <option value="oauth2"{}>OAuth 2.0</option>
                        <option value="jwt"{}>JWT</option>
                        <option value="oidc"{}>OIDC</option>
                    </select>
                </div>

                <div id="auth-fields">
                    {}
                </div>

                <div>
                    <label for="allowed_methods">Allowed Methods (comma-separated, leave blank for all):</label><br>
                    <input type="text" id="allowed_methods" name="allowed_methods" value="{}" placeholder="GET,POST,PUT">
                </div>

                <div>
                    <label for="rate_limit_per_minute">Rate Limit Per Minute:</label><br>
                    <input type="number" id="rate_limit_per_minute" name="rate_limit_per_minute" value="{}">
                </div>

                <div>
                    <label for="rate_limit_per_hour">Rate Limit Per Hour:</label><br>
                    <input type="number" id="rate_limit_per_hour" name="rate_limit_per_hour" value="{}">
                </div>

                <div>
                    <button type="submit">{}</button>
                    <button type="button" hx-get="/web/routes" hx-target="#content" hx-swap="innerHTML">Cancel</button>
                </div>
            </form>
        "##,
        title,
        action,
        form_data.path,
        form_data.upstream,
        form_data.auth_type,
        if auth_type == AuthType::None { " selected" } else { "" },
        if auth_type == AuthType::ApiKey { " selected" } else { "" },
        if auth_type == AuthType::OAuth2 { " selected" } else { "" },
        if auth_type == AuthType::Jwt { " selected" } else { "" },
        if auth_type == AuthType::Oidc { " selected" } else { "" },
        auth_fields,
        form_data.allowed_methods.as_deref().unwrap_or(""),
        form_data.rate_limit_per_minute.unwrap_or(60),
        form_data.rate_limit_per_hour.unwrap_or(1000),
        submit_text
    )
}

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

pub async fn dashboard_view(State(state): State<AppState>) -> Html<String> {
    // Get recent metrics for last 5 requests
    let recent_requests = sqlx::query(
        "SELECT path, method, request_timestamp, duration_ms, response_status_code
         FROM request_metrics
         ORDER BY request_timestamp DESC
         LIMIT 5"
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    // Get basic metrics summary
    let stats_query = sqlx::query(
        "SELECT
            COUNT(*) as total_requests,
            AVG(duration_ms) as avg_duration_ms,
            COUNT(CASE WHEN response_status_code >= 200 AND response_status_code < 300 THEN 1 END) as success_count
        FROM request_metrics
        WHERE response_timestamp IS NOT NULL"
    )
    .fetch_optional(&state.db)
    .await
    .unwrap_or_default();

    // Get configured routes count
    let routes_count = sqlx::query("SELECT COUNT(*) as count FROM routes")
        .fetch_optional(&state.db)
        .await
        .unwrap_or_default()
        .map(|row| row.get::<i64, _>("count"))
        .unwrap_or(0);

    let mut html = String::from(r##"
        <h2>Dashboard</h2>
        <div class="dashboard-container">
            <div id="dashboard-content">
                <p>This is your central management dashboard for all API routes and metrics.</p>
    "##);

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

        html.push_str(&format!(r##"
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
        "##, total_requests, success_rate, avg_duration, routes_count));
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
        html.push_str(r##"
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
        "##);

        for row in recent_requests {
            let path: String = row.get("path");
            let method: String = row.get("method");
            let timestamp: String = row.get("request_timestamp");
            let duration = row.get::<Option<i64>, _>("duration_ms")
                .map(|d| format!("{}ms", d))
                .unwrap_or_else(|| "N/A".to_string());
            let status = row.get::<Option<u16>, _>("response_status_code")
                .map(|s| s.to_string())
                .unwrap_or_else(|| "N/A".to_string());

            html.push_str(&format!(r##"
                            <tr>
                                <td>{}</td>
                                <td>{}</td>
                                <td>{}</td>
                                <td>{}</td>
                                <td>{}</td>
                            </tr>
            "##, path, method, &timestamp[..19], duration, status));
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

pub async fn routes_list(State(state): State<AppState>) -> Html<String> {
    let rows = sqlx::query("SELECT path, upstream, auth_type, rate_limit_per_minute, rate_limit_per_hour FROM routes")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let mut html = String::from(r##"
        <h2>Routes</h2>
        <div class="dashboard-container">
            <button hx-get="/web/routes/add-form" hx-target="#routes-content">Add Route</button>
            <div id="routes-content" class="dashboard-section">
                <h3>Configured Routes</h3>
    "##);

    if !rows.is_empty() {
        html.push_str(r##"
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Path</th>
                            <th>Upstream</th>
                            <th>Auth</th>
                            <th>Rate/Min</th>
                            <th>Rate/Hour</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
        "##);
        for row in rows {
            let path: String = row.get("path");
            let upstream: String = row.get("upstream");
            let auth_type_str: String = row.get("auth_type");
            let auth_type = AuthType::from_str(&auth_type_str);
            let rate_min: i64 = row.get("rate_limit_per_minute");
            let rate_hour: i64 = row.get("rate_limit_per_hour");

            html.push_str(&format!(r##"
                        <tr>
                            <td>{}</td>
                            <td>{}</td>
                            <td>{}</td>
                            <td>{}</td>
                            <td>{}</td>
                            <td>
                                <button hx-get="/web/routes/edit/{}" hx-target="#routes-content" hx-swap="innerHTML">Edit</button>
                                <button hx-delete="/web/routes/{}" hx-target="closest tr" hx-swap="outerHTML" hx-confirm="Delete this route?">Delete</button>
                            </td>
                        </tr>
            "##, path, upstream, auth_type.to_display_string(), rate_min, rate_hour, path, path));
        }

        html.push_str("</tbody></table>");
    } else {
        html.push_str("<p>No routes configured</p>");
    }

    html.push_str("</div></div>");
    Html(html)
}

pub async fn metrics_view(State(state): State<AppState>, Query(query): Query<MetricsQuery>) -> Html<String> {
    let limit = query.limit.unwrap_or(20);
    
    // Get metrics statistics
    let stats_query = sqlx::query(
        "SELECT
            COUNT(*) as total_requests,
            AVG(duration_ms) as avg_duration_ms,
            MIN(duration_ms) as min_duration_ms,
            MAX(duration_ms) as max_duration_ms,
            COUNT(CASE WHEN response_status_code >= 200 AND response_status_code < 300 THEN 1 END) as success_count,
            COUNT(CASE WHEN response_status_code >= 400 THEN 1 END) as error_count,
            SUM(request_size_bytes) as total_request_bytes,
            SUM(response_size_bytes) as total_response_bytes
        FROM request_metrics
        WHERE response_timestamp IS NOT NULL"
    )
    .fetch_optional(&state.db)
    .await
    .unwrap_or_default();
    let mut html = String::from(r##"
        <h2>Metrics Dashboard</h2>
        <div class="dashboard-container">
    "##);

    // Add statistics summary
    if let Some(row) = stats_query {
        let total_requests: i64 = row.get("total_requests");
        let success_count: i64 = row.get("success_count");
        let error_count: i64 = row.get("error_count");
        let avg_duration: f64 = row.get::<Option<f64>, _>("avg_duration_ms").unwrap_or(0.0);
        let min_duration: i64 = row.get::<Option<i64>, _>("min_duration_ms").unwrap_or(0);
        let max_duration: i64 = row.get::<Option<i64>, _>("max_duration_ms").unwrap_or(0);
        let total_request_bytes: i64 = row.get::<Option<i64>, _>("total_request_bytes").unwrap_or(0);
        let total_response_bytes: i64 = row.get::<Option<i64>, _>("total_response_bytes").unwrap_or(0);
        
        let success_rate = if total_requests > 0 {
            (success_count as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        html.push_str(&format!(r##"
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
        "##, total_requests, success_rate, error_count, avg_duration, min_duration, max_duration, total_request_bytes, total_response_bytes));
    } else {
        html.push_str(r##"
            <div class="dashboard-summary">
                <h3>Statistics Summary</h3>
                <p>No metrics data available</p>
            </div>
        "##);
    }    
    // Get recent requests
    let rows = sqlx::query(
        "SELECT id, path, method, request_timestamp, duration_ms, response_status_code,
                request_size_bytes, response_size_bytes, upstream_url, auth_type, error_message
         FROM request_metrics
         ORDER BY request_timestamp DESC
         LIMIT ?"
    )
    .bind(limit as i64)
    .fetch_all(&state.db)
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
        html.push_str(r##"
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
        "##);

        for row in rows {
            let id: String = row.get("id");
            let short_id = &id[..8]; // Show first 8 characters of UUID
            let path: String = row.get("path");
            let method: String = row.get("method");
            let timestamp: String = row.get("request_timestamp");
            let duration = row.get::<Option<i64>, _>("duration_ms")
                .map(|d| format!("{}ms", d))
                .unwrap_or_else(|| "N/A".to_string());
            let status = row.get::<Option<u16>, _>("response_status_code")
                .map(|s| s.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let req_size: i64 = row.get("request_size_bytes");
            let resp_size = row.get::<Option<i64>, _>("response_size_bytes")
                .map(|s| s.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let auth_type_str: String = row.get("auth_type");
            let auth_type = AuthType::from_str(&auth_type_str);

            html.push_str(&format!(r##"
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
            "##, short_id, path, method, &timestamp[..19], duration, status, req_size, resp_size, auth_type.to_display_string()));

            // Show error message if present
            if let Some(error) = row.get::<Option<String>, _>("error_message") {
                html.push_str(&format!(r##"
                <tr class="error-row">
                    <td colspan="9">Error: {}</td>
                </tr>
                "##, error));
            }
        }

        html.push_str("</tbody></table>");
    } else {
        html.push_str("<p>No recent requests available</p>");
    }

    html.push_str("</div></div>");
    Html(html)
}

pub async fn auth_fields_form(Query(params): Query<std::collections::HashMap<String, String>>) -> Html<String> {
    let default_auth_type = "none".to_string();
    let auth_type_str = params.get("auth_type").unwrap_or(&default_auth_type);
    let auth_type = AuthType::from_str(auth_type_str);
    let form_data = RouteFormData::default();
    let html = generate_auth_fields(auth_type, &form_data);
    Html(html)
}

pub async fn add_route_form() -> Html<String> {
    let form_data = RouteFormData {
        auth_type: "none".to_string(),
        rate_limit_per_minute: Some(60),
        rate_limit_per_hour: Some(1000),
        ..Default::default()
    };
    Html(generate_route_form(false, "", form_data))
}

pub async fn edit_route_form(State(state): State<AppState>, Path(path): Path<String>) -> Result<Html<String>, StatusCode> {
    let row = sqlx::query(
        "SELECT path, upstream, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, oidc_issuer, oidc_client_id, oidc_client_secret, oidc_audience, oidc_scope, rate_limit_per_minute, rate_limit_per_hour FROM routes WHERE path = ?"
    )
    .bind(&path)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let row = match row {
        Some(row) => row,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let form_data = RouteFormData {
        path: row.get("path"),
        upstream: row.get("upstream"),
        auth_type: row.get("auth_type"),
        auth_value: Some(row.get("auth_value")),
        allowed_methods: Some(row.get("allowed_methods")),
        oauth_token_url: Some(row.get("oauth_token_url")),
        oauth_client_id: Some(row.get("oauth_client_id")),
        oauth_client_secret: Some(row.get("oauth_client_secret")),
        oauth_scope: Some(row.get("oauth_scope")),
        jwt_secret: Some(row.get("jwt_secret")),
        jwt_algorithm: Some(row.get("jwt_algorithm")),
        jwt_issuer: Some(row.get("jwt_issuer")),
        jwt_audience: Some(row.get("jwt_audience")),
        jwt_required_claims: Some(row.get("jwt_required_claims")),
        oidc_issuer: Some(row.get("oidc_issuer")),
        oidc_client_id: Some(row.get("oidc_client_id")),
        oidc_client_secret: Some(row.get("oidc_client_secret")),
        oidc_audience: Some(row.get("oidc_audience")),
        oidc_scope: Some(row.get("oidc_scope")),
        rate_limit_per_minute: Some(row.get::<i64, _>("rate_limit_per_minute") as u32),
        rate_limit_per_hour: Some(row.get::<i64, _>("rate_limit_per_hour") as u32),
    };

    Ok(Html(generate_route_form(true, &path, form_data)))
}

pub async fn add_route_submit(State(state): State<AppState>, Form(form): Form<RouteFormData>) -> Result<Html<String>, StatusCode> {
    let auth_type_enum = AuthType::from_str(&form.auth_type);

    let result = sqlx::query(
        "INSERT OR REPLACE INTO routes
        (path, upstream, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, oidc_issuer, oidc_client_id, oidc_client_secret, oidc_audience, oidc_scope, rate_limit_per_minute, rate_limit_per_hour)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&form.path)
    .bind(&form.upstream)
    .bind(auth_type_enum.to_string())
    .bind(form.auth_value.unwrap_or_default())
    .bind(form.allowed_methods.unwrap_or_default())
    .bind(form.oauth_token_url.unwrap_or_default())
    .bind(form.oauth_client_id.unwrap_or_default())
    .bind(form.oauth_client_secret.unwrap_or_default())
    .bind(form.oauth_scope.unwrap_or_default())
    .bind(form.jwt_secret.unwrap_or_default())
    .bind(form.jwt_algorithm.unwrap_or_else(|| "HS256".to_string()))
    .bind(form.jwt_issuer.unwrap_or_default())
    .bind(form.jwt_audience.unwrap_or_default())
    .bind(form.jwt_required_claims.unwrap_or_default())
    .bind(form.oidc_issuer.unwrap_or_default())
    .bind(form.oidc_client_id.unwrap_or_default())
    .bind(form.oidc_client_secret.unwrap_or_default())
    .bind(form.oidc_audience.unwrap_or_default())
    .bind(form.oidc_scope.unwrap_or_default())
    .bind(form.rate_limit_per_minute.unwrap_or(60))
    .bind(form.rate_limit_per_hour.unwrap_or(1000))
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => Ok(routes_list(State(state)).await),
        Err(e) => {
            eprintln!("Failed to add route: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn delete_route(State(state): State<AppState>, Path(path): Path<String>) -> Result<Html<String>, StatusCode> {
    let result = sqlx::query("DELETE FROM routes WHERE path = ?")
        .bind(&path)
        .execute(&state.db)
        .await;

    match result {
        Ok(_) => Ok(Html("".to_string())),
        Err(e) => {
            eprintln!("Failed to delete route: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn edit_route_submit(State(state): State<AppState>, Path(path): Path<String>, Form(form): Form<RouteFormData>) -> Result<Html<String>, StatusCode> {
    let auth_type_enum = AuthType::from_str(&form.auth_type);

    let result = sqlx::query(
        "UPDATE routes SET 
        path = ?, upstream = ?, auth_type = ?, auth_value = ?, allowed_methods = ?, 
        oauth_token_url = ?, oauth_client_id = ?, oauth_client_secret = ?, oauth_scope = ?,
        jwt_secret = ?, jwt_algorithm = ?, jwt_issuer = ?, jwt_audience = ?, jwt_required_claims = ?,
        oidc_issuer = ?, oidc_client_id = ?, oidc_client_secret = ?, oidc_audience = ?, oidc_scope = ?,
        rate_limit_per_minute = ?, rate_limit_per_hour = ?
        WHERE path = ?"
    )
    .bind(&form.path)
    .bind(&form.upstream)
    .bind(auth_type_enum.to_string())
    .bind(form.auth_value.unwrap_or_default())
    .bind(form.allowed_methods.unwrap_or_default())
    .bind(form.oauth_token_url.unwrap_or_default())
    .bind(form.oauth_client_id.unwrap_or_default())
    .bind(form.oauth_client_secret.unwrap_or_default())
    .bind(form.oauth_scope.unwrap_or_default())
    .bind(form.jwt_secret.unwrap_or_default())
    .bind(form.jwt_algorithm.unwrap_or_else(|| "HS256".to_string()))
    .bind(form.jwt_issuer.unwrap_or_default())
    .bind(form.jwt_audience.unwrap_or_default())
    .bind(form.jwt_required_claims.unwrap_or_default())
    .bind(form.oidc_issuer.unwrap_or_default())
    .bind(form.oidc_client_id.unwrap_or_default())
    .bind(form.oidc_client_secret.unwrap_or_default())
    .bind(form.oidc_audience.unwrap_or_default())
    .bind(form.oidc_scope.unwrap_or_default())
    .bind(form.rate_limit_per_minute.unwrap_or(60))
    .bind(form.rate_limit_per_hour.unwrap_or(1000))
    .bind(&path)
    .execute(&state.db)
    .await;

    match result {
        Ok(result) => {
            if result.rows_affected() == 0 {
                Err(StatusCode::NOT_FOUND)
            } else {
                Ok(routes_list(State(state)).await)
            }
        }
        Err(e) => {
            eprintln!("Failed to update route: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}