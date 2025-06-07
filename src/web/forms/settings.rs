//! This module provides the HTML forms for managing settings in the web application.

use crate::AppState;
use axum::{
    extract::{Path, State},
    response::Html,
};
use hyper::StatusCode;
use sqlx::Row;

pub async fn add_setting_form() -> Html<String> {
    Html(String::from(
        r##"
        <div class="form-container">
            <h3>Add New Setting</h3>
            <form hx-post="/web/settings/add" hx-target="#settings-content">
                <div>
                    <label for="key">Setting Key:</label><br>
                    <input type="text" id="key" name="key" required placeholder="e.g., default_rate_limit">
                </div>
                <div>
                    <label for="value">Setting Value:</label><br>
                    <input type="text" id="value" name="value" required placeholder="e.g., 100">
                </div>
                <div>
                    <label for="description">Description (optional):</label><br>
                    <input type="text" id="description" name="description" placeholder="What this setting controls">
                </div>
                <div>
                    <button type="submit">Add Setting</button>
                    <button type="button" hx-get="/web/settings" hx-target="#settings-content">Cancel</button>
                </div>
            </form>
        </div>
    "##,
    ))
}

pub async fn edit_setting_form(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<Html<String>, StatusCode> {
    // Fetch the setting by key
    let row = sqlx::query("SELECT key, value, description FROM settings WHERE key = ?")
        .bind(&key)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match row {
        Some(setting) => {
            let current_key: String = setting.get("key");
            let current_value: String = setting.get("value");
            let current_description: Option<String> = setting.get("description");

            let html = format!(
                r##"
                <div class="form-container">
                    <h3>Edit Setting</h3>
                    <form hx-post="/web/settings/edit/{}" hx-target="#settings-content">
                        <div>
                            <label for="key">Setting Key:</label><br>
                            <input type="text" id="key" name="key" value="{}" required>
                        </div>
                        <div>
                            <label for="value">Setting Value:</label><br>
                            <input type="text" id="value" name="value" value="{}" required>
                        </div>
                        <div>
                            <label for="description">Description (optional):</label><br>
                            <input type="text" id="description" name="description" value="{}">
                        </div>
                        <div>
                            <button type="submit">Update Setting</button>
                            <button type="button" hx-get="/web/settings" hx-target="#settings-content">Cancel</button>
                        </div>
                    </form>
                </div>
            "##,
                key,
                current_key,
                current_value,
                current_description.unwrap_or_default()
            );

            Ok(Html(html))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}
