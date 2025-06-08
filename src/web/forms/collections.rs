//! Forms for managing collections in the web interface.

use axum::{extract::{Path, State}, response::Html};
use hyper::StatusCode;
use sqlx::Row;

use crate::{AppState, AuthType, web::forms::auth::generate_collection_auth_fields, web::handlers::RouteCollectionFormData, database::queries};

pub async fn add_collection_form() -> Html<String> {
    let form_data = RouteCollectionFormData::default();
    let auth_type = AuthType::from_str(&form_data.default_auth_type.clone().unwrap_or_else(|| "none".into()));
    let auth_fields = generate_collection_auth_fields(auth_type.clone(), &form_data);
    
    let html = format!(r##"
        <h3>Add New Collection</h3>
        <form hx-post="/web/collections/add" hx-target="#content" hx-swap="innerHTML">
            <div>
                <label for="openapi_spec_url">OpenAPI v3.0 Specification URL (Optional):</label><br>
                <input type="url" id="openapi_spec_url" name="openapi_spec_url" placeholder="https://example.com/api/openapi.json" 
                       hx-trigger="input delay:500ms" hx-target="#form-fields" hx-get="/web/collections/toggle-fields" hx-swap="outerHTML">
                <small>Generate a route collection using an OpenAPI v3.0 Document</small>
            </div>

            <div id="form-fields">
                <div>
                    <label for="name">Collection Name:</label><br>
                    <input type="text" id="name" name="name" placeholder="e.g., api_v1" required>
                </div>
                
                <div>
                    <label for="description">Description:</label><br>
                    <input type="text" id="description" name="description" placeholder="Brief description of this collection">
                </div>
                
                <div>
                    <label for="base_upstream_url">Base Upstream URL:</label><br>
                    <input type="url" id="base_upstream_url" name="base_upstream_url" placeholder="https://api.example.com" required>
                    <small>Base URL that will be prepended to all route paths</small>
                </div>
                
                <div>
                    <label for="default_auth_type">Default Authentication Type:</label><br>
                    <select id="default_auth_type" name="default_auth_type" hx-trigger="change" hx-target="#auth-fields" hx-get="/web/collections/auth-fields" hx-swap="innerHTML">
                        <option value="none"{}>None</option>
                        <option value="basic-auth"{}>Basic Auth</option>
                        <option value="api-key"{}>API Key</option>
                        <option value="oauth2"{}>OAuth 2.0</option>
                        <option value="jwt"{}>JWT</option>
                        <option value="oidc"{}>OIDC</option>
                    </select>
                </div>
                
                <div id="auth-fields">
                    {}
                </div>
            </div>
            
            <div>
                <label for="default_rate_limit_per_minute">Default Rate Limit (per minute):</label><br>
                <input type="number" id="default_rate_limit_per_minute" name="default_rate_limit_per_minute" value="60" min="1">
            </div>
            
            <div>
                <label for="default_rate_limit_per_hour">Default Rate Limit (per hour):</label><br>
                <input type="number" id="default_rate_limit_per_hour" name="default_rate_limit_per_hour" value="1000" min="1">
            </div>

            <div>
                <button type="submit">Add Collection</button>
                <button type="button" hx-get="/web/collections" hx-target="#content" hx-swap="innerHTML">Cancel</button>
            </div>
        </form>
    "##,
        if auth_type == AuthType::None {
            " selected"
        } else {
            ""
        },
        if auth_type == AuthType::BasicAuth {
            " selected"
        } else {
            ""
        },
        if auth_type == AuthType::ApiKey {
            " selected"
        } else {
            ""
        },
        if auth_type == AuthType::OAuth2 {
            " selected"
        } else {
            ""
        },
        if auth_type == AuthType::Jwt {
            " selected"
        } else {
            ""
        },
        if auth_type == AuthType::Oidc {
            " selected"
        } else {
            ""
        },
        auth_fields
    );
    Html(html)
}

pub async fn edit_collection_form(State(state): State<AppState>, Path(id): Path<i64>) -> Result<Html<String>, StatusCode> {
    // Fetch the collection data
    let row = queries::fetch_route_collection_by_id(&state.db, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let row = match row {
        Some(row) => row,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Extract data from the row
    let form_data = RouteCollectionFormData {
        name: row.get("name"),
        description: Some(row.get("description")),
        openapi_spec_url: None, // Edit form doesn't use OpenAPI URL
        base_upstream_url: None, // Edit form doesn't show base URL for now
        default_auth_type: row.get("default_auth_type"),
        default_auth_value: Some(row.get("default_auth_value")),
        default_oauth_token_url: Some(row.get("default_oauth_token_url")),
        default_oauth_client_id: Some(row.get("default_oauth_client_id")),
        default_oauth_client_secret: Some(row.get("default_oauth_client_secret")),
        default_oauth_scope: Some(row.get("default_oauth_scope")),
        default_jwt_secret: Some(row.get("default_jwt_secret")),
        default_jwt_algorithm: Some(row.get("default_jwt_algorithm")),
        default_jwt_issuer: Some(row.get("default_jwt_issuer")),
        default_jwt_audience: Some(row.get("default_jwt_audience")),
        default_jwt_required_claims: Some(row.get("default_jwt_required_claims")),
        default_oidc_issuer: Some(row.get("default_oidc_issuer")),
        default_oidc_client_id: Some(row.get("default_oidc_client_id")),
        default_oidc_client_secret: Some(row.get("default_oidc_client_secret")),
        default_oidc_audience: Some(row.get("default_oidc_audience")),
        default_oidc_scope: Some(row.get("default_oidc_scope")),
        default_rate_limit_per_minute: Some(row.get::<i64, _>("default_rate_limit_per_minute") as u32),
        default_rate_limit_per_hour: Some(row.get::<i64, _>("default_rate_limit_per_hour") as u32),
    };

    let auth_type = AuthType::from_str(&form_data.default_auth_type.clone().unwrap_or_else(|| "none".into()));
    let auth_fields = generate_collection_auth_fields(auth_type.clone(), &form_data);
    
    let html = format!(r##"
        <h3>Edit Collection</h3>
        <form hx-post="/web/collections/edit/{}" hx-target="#content" hx-swap="innerHTML">
            <div>
                <label for="name">Collection Name:</label><br>
                <input type="text" id="name" name="name" value="{}" required>
            </div>
            
            <div>
                <label for="description">Description:</label><br>
                <input type="text" id="description" name="description" value="{}">
            </div>
            
            <div>
                <label for="default_auth_type">Default Authentication Type:</label><br>
                <select id="default_auth_type" name="default_auth_type" hx-trigger="change" hx-target="#auth-fields" hx-get="/web/collections/auth-fields" hx-swap="innerHTML">
                    <option value="none"{}>None</option>
                    <option value="basic-auth"{}>Basic Auth</option>
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
                <label for="default_rate_limit_per_minute">Default Rate Limit (per minute):</label><br>
                <input type="number" id="default_rate_limit_per_minute" name="default_rate_limit_per_minute" value="{}" min="1">
            </div>
            
            <div>
                <label for="default_rate_limit_per_hour">Default Rate Limit (per hour):</label><br>
                <input type="number" id="default_rate_limit_per_hour" name="default_rate_limit_per_hour" value="{}" min="1">
            </div>

            <div>
                <button type="submit">Update Collection</button>
                <button type="button" hx-get="/web/collections" hx-target="#content" hx-swap="innerHTML">Cancel</button>
            </div>
        </form>
    "##,
        id,
        form_data.name.unwrap_or_default(),
        form_data.description.unwrap_or_default(),
        if auth_type == AuthType::None { " selected" } else { "" },
        if auth_type == AuthType::BasicAuth { " selected" } else { "" },
        if auth_type == AuthType::ApiKey { " selected" } else { "" },
        if auth_type == AuthType::OAuth2 { " selected" } else { "" },
        if auth_type == AuthType::Jwt { " selected" } else { "" },
        if auth_type == AuthType::Oidc { " selected" } else { "" },
        auth_fields,
        form_data.default_rate_limit_per_minute.unwrap_or(60),
        form_data.default_rate_limit_per_hour.unwrap_or(1000)
    );
    
    Ok(Html(html))
}