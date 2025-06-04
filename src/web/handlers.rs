use axum::{response::Html, extract::{State, Form, Path, Query}, http::StatusCode};
use serde::Deserialize;
use sqlx::Row;
use crate::{AppState, AuthType};

#[derive(Deserialize)]
pub struct AddRouteForm {
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
    rate_limit_per_minute: Option<u32>,
    rate_limit_per_hour: Option<u32>,
}

// Only handle dynamic HTMX responses now
pub async fn routes_list(State(state): State<AppState>) -> Html<String> {
    let rows = sqlx::query("SELECT path, upstream, auth_type, rate_limit_per_minute, rate_limit_per_hour FROM routes")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let mut html = String::from(r##"
        <h2>Routes</h2>
        <button hx-get="/web/routes/add-form" hx-target="#routes-content">Add Route</button>
        <div id="routes-content">
        <table>
            <thead>
                <tr><th>Path</th><th>Upstream</th><th>Auth</th><th>Rate/Min</th><th>Rate/Hour</th><th>Actions</th></tr>
            </thead>
            <tbody>
    "##);

    for row in rows {
        let path: String = row.get("path");
        let upstream: String = row.get("upstream");
        let auth_type: String = row.get("auth_type");
        let rate_min: i64 = row.get("rate_limit_per_minute");
        let rate_hour: i64 = row.get("rate_limit_per_hour");

        html.push_str(&format!(r##"            <tr>
                <td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>
                <td><button hx-delete="/web/routes/{}" hx-target="closest tr" hx-swap="outerHTML" hx-confirm="Delete this route?">Delete</button></td>
            </tr>
        "##, path, upstream, auth_type, rate_min, rate_hour, path));
    }

    html.push_str("</tbody></table></div>");
    Html(html)
}

pub async fn metrics_view(State(_state): State<AppState>) -> Html<String> {
    // Similar dynamic content only...
    Html("<h2>Metrics will go here</h2>".to_string())
}

pub async fn add_route_form() -> Html<String> {
    let html = r##"
        <h3>Add New Route</h3>
        <form hx-post="/web/routes/add" hx-target="#routes-content" hx-swap="outerHTML">
            <div style="margin-bottom: 10px;">
                <label for="path">Path:</label><br>
                <input type="text" id="path" name="path" required style="width: 300px;" placeholder="/api/example">
            </div>
            
            <div style="margin-bottom: 10px;">
                <label for="upstream">Upstream URL:</label><br>
                <input type="url" id="upstream" name="upstream" required style="width: 300px;" placeholder="https://api.example.com">
            </div>

            <div style="margin-bottom: 10px;">
                <label for="auth_type">Authentication Type:</label><br>
                <select id="auth_type" name="auth_type" style="width: 300px;" hx-trigger="change" hx-target="#auth-fields" hx-get="/web/routes/auth-fields">
                    <option value="none">None</option>
                    <option value="api-key">API Key</option>
                    <option value="oauth2">OAuth 2.0</option>
                    <option value="jwt">JWT</option>
                    <option value="oidc">OIDC</option>
                </select>
            </div>

            <div id="auth-fields">
                <!-- Auth-specific fields will be loaded here dynamically -->
            </div>

            <div style="margin-bottom: 10px;">
                <label for="allowed_methods">Allowed Methods (comma-separated, leave blank for all):</label><br>
                <input type="text" id="allowed_methods" name="allowed_methods" style="width: 300px;" placeholder="GET,POST,PUT">
            </div>

            <div style="margin-bottom: 10px;">
                <label for="rate_limit_per_minute">Rate Limit Per Minute:</label><br>
                <input type="number" id="rate_limit_per_minute" name="rate_limit_per_minute" value="60" style="width: 300px;">
            </div>

            <div style="margin-bottom: 10px;">
                <label for="rate_limit_per_hour">Rate Limit Per Hour:</label><br>
                <input type="number" id="rate_limit_per_hour" name="rate_limit_per_hour" value="1000" style="width: 300px;">
            </div>

            <div style="margin-bottom: 10px;">
                <button type="submit">Add Route</button>
                <button type="button" hx-get="/web/routes" hx-target="#content" hx-swap="innerHTML">Cancel</button>
            </div>
        </form>
    "##;
    Html(html.to_string())
}

pub async fn auth_fields_form(Query(params): Query<std::collections::HashMap<String, String>>) -> Html<String> {
    let default_auth_type = "none".to_string();
    let auth_type = params.get("auth_type").unwrap_or(&default_auth_type);
    let html = match auth_type.as_str() {
        "api-key" => r##"
            <div style="margin-bottom: 10px;">
                <label for="auth_value">API Key (with Bearer prefix if needed):</label><br>
                <input type="text" id="auth_value" name="auth_value" style="width: 300px;" placeholder="Bearer your-api-key">
            </div>
        "##,
        "oauth2" => r##"
            <div style="margin-bottom: 10px;">
                <label for="oauth_token_url">OAuth Token URL:</label><br>
                <input type="url" id="oauth_token_url" name="oauth_token_url" style="width: 300px;" placeholder="https://oauth.example.com/token">
            </div>
            <div style="margin-bottom: 10px;">
                <label for="oauth_client_id">OAuth Client ID:</label><br>
                <input type="text" id="oauth_client_id" name="oauth_client_id" style="width: 300px;">
            </div>
            <div style="margin-bottom: 10px;">
                <label for="oauth_client_secret">OAuth Client Secret:</label><br>
                <input type="password" id="oauth_client_secret" name="oauth_client_secret" style="width: 300px;">
            </div>
            <div style="margin-bottom: 10px;">
                <label for="oauth_scope">OAuth Scope:</label><br>
                <input type="text" id="oauth_scope" name="oauth_scope" style="width: 300px;" placeholder="read:all">
            </div>
        "##,
        "jwt" => r##"
            <div style="margin-bottom: 10px;">
                <label for="jwt_secret">JWT Secret:</label><br>
                <input type="password" id="jwt_secret" name="jwt_secret" style="width: 300px;">
            </div>
            <div style="margin-bottom: 10px;">
                <label for="jwt_algorithm">JWT Algorithm:</label><br>
                <select id="jwt_algorithm" name="jwt_algorithm" style="width: 300px;">
                    <option value="HS256">HS256</option>
                    <option value="HS384">HS384</option>
                    <option value="HS512">HS512</option>
                </select>
            </div>
            <div style="margin-bottom: 10px;">
                <label for="jwt_issuer">JWT Issuer (optional):</label><br>
                <input type="text" id="jwt_issuer" name="jwt_issuer" style="width: 300px;">
            </div>
            <div style="margin-bottom: 10px;">
                <label for="jwt_audience">JWT Audience (optional):</label><br>
                <input type="text" id="jwt_audience" name="jwt_audience" style="width: 300px;">
            </div>
            <div style="margin-bottom: 10px;">
                <label for="jwt_required_claims">JWT Required Claims (comma-separated, optional):</label><br>
                <input type="text" id="jwt_required_claims" name="jwt_required_claims" style="width: 300px;" placeholder="role,permissions">
            </div>
            <div style="margin-bottom: 10px;">
                <label for="auth_value">JWT Token for testing (optional):</label><br>
                <input type="text" id="auth_value" name="auth_value" style="width: 300px;" placeholder="Bearer your-jwt-token">
            </div>
        "##,
        "oidc" => r##"
            <div style="margin-bottom: 10px;">
                <label for="auth_value">OIDC Configuration (placeholder - not fully implemented):</label><br>
                <input type="text" id="auth_value" name="auth_value" style="width: 300px;">
            </div>
        "##,
        _ => "",
    };
    
    Html(html.to_string())
}

pub async fn add_route_submit(State(state): State<AppState>, Form(form): Form<AddRouteForm>) -> Result<Html<String>, StatusCode> {
    // Parse the auth type
    let auth_type_enum = AuthType::from_str(&form.auth_type);
    
    // Insert the route into the database
    let result = sqlx::query(
        "INSERT OR REPLACE INTO routes
        (path, upstream, auth_type, auth_value, allowed_methods, oauth_token_url, oauth_client_id, oauth_client_secret, oauth_scope, jwt_secret, jwt_algorithm, jwt_issuer, jwt_audience, jwt_required_claims, rate_limit_per_minute, rate_limit_per_hour)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
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
    .bind(form.rate_limit_per_minute.unwrap_or(60))
    .bind(form.rate_limit_per_hour.unwrap_or(1000))
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            // Return the updated routes list
            Ok(routes_list(State(state)).await)
        }
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
        Ok(_) => Ok(Html("".to_string())), // Return empty content to remove the row
        Err(e) => {
            eprintln!("Failed to delete route: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}