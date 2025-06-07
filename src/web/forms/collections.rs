//! Forms for managing collections in the web interface.

use axum::{extract::{Path, State}, response::Html};
use hyper::StatusCode;

use crate::AppState;

pub async fn add_collection_form() -> Html<String> {
    let html = r##"
        <h3>Add New Collection</h3>
        <form hx-post="/web/collections/add" hx-target="#content" hx-swap="innerHTML">
            <div>
                <label for="name">Collection Name:</label><br>
                <input type="text" id="name" name="name" placeholder="e.g., api_v1" required>
            </div>
            
            <div>
                <label for="description">Description:</label><br>
                <input type="text" id="description" name="description" placeholder="Brief description of this collection">
            </div>
            
            <div>
                <label for="default_auth_type">Default Authentication Type:</label><br>
                <select id="default_auth_type" name="default_auth_type">
                    <option value="none">None</option>
                    <option value="basic-auth">Basic Auth</option>
                    <option value="api-key">API Key</option>
                    <option value="oauth2">OAuth 2.0</option>
                    <option value="jwt">JWT</option>
                    <option value="oidc">OIDC</option>
                </select>
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
    "##;
    Html(html.to_string())
}

// Stub implementations for remaining handlers
pub async fn edit_collection_form(State(_state): State<AppState>, Path(_id): Path<i64>) -> Result<Html<String>, StatusCode> {
    Ok(Html("<div>Edit Collection Form - To be implemented</div>".to_string()))
}