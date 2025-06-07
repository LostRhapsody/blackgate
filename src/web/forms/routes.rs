//! This module generates HTML inputs for forms that require route fields.

use sqlx::Row;

use crate::{
    auth::types::AuthType,
    rate_limiter::{DEFAULT_RATE_LIMIT_PER_HOUR, DEFAULT_RATE_LIMIT_PER_MINUTE},
    web::{forms::auth::generate_auth_fields, handlers::RouteFormData},
};

pub fn generate_route_form(
    is_edit: bool,
    path: &str,
    form_data: RouteFormData,
    collections: Vec<sqlx::sqlite::SqliteRow>,
) -> String {
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

    // Generate collection options HTML
    let mut collection_options = String::from("<option value=\"\">No Collection</option>");
    for collection in collections {
        let id: i64 = collection.get("id");
        let name: String = collection.get("name");
        let selected = if form_data.collection_id == Some(id) {
            " selected"
        } else {
            ""
        };
        collection_options.push_str(&format!(
            "<option value=\"{}\"{}>{}</option>",
            id, selected, name
        ));
    }

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
                    <label for="backup_route_path">Backup Route Path (optional):</label><br>
                    <input type="text" id="backup_route_path" name="backup_route_path" value="{}" placeholder="/api/backup">
                </div>

                <div>
                    <label for="collection_id">Collection (optional):</label><br>
                    <select id="collection_id" name="collection_id">
                        {}
                    </select>
                </div>

                <div>
                    <label for="auth_type">Authentication Type:</label><br>
                    <select id="auth_type" name="auth_type" hx-trigger="change" hx-target="#auth-fields" hx-get="/web/routes/auth-fields?auth_type={}" hx-swap="innerHTML">
                        <option value="none"{}>None</option>
                        <option value="api-key"{}>API Key</option>
                        <option value="basic-auth"{}>Basic Auth</option>
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
        form_data.backup_route_path.as_deref().unwrap_or(""),
        collection_options,
        form_data.auth_type,
        if auth_type == AuthType::None {
            " selected"
        } else {
            ""
        },
        if auth_type == AuthType::ApiKey {
            " selected"
        } else {
            ""
        },
        if auth_type == AuthType::BasicAuth {
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
        auth_fields,
        form_data.allowed_methods.as_deref().unwrap_or(""),
        form_data
            .rate_limit_per_minute
            .unwrap_or(DEFAULT_RATE_LIMIT_PER_MINUTE),
        form_data
            .rate_limit_per_hour
            .unwrap_or(DEFAULT_RATE_LIMIT_PER_HOUR),
        submit_text
    )
}
