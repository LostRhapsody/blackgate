//! Settings management view for the web application.

use axum::{extract::State, response::Html};
use sqlx::Row;
use crate::{database::queries, AppState};

pub async fn settings_view(State(state): State<AppState>) -> Html<String> {
    // Fetch all settings from database
    let settings_rows = queries::get_all_settings(&state.db)
        .await
        .unwrap_or_default();

    let mut html = String::from(r##"
        <h2>Gateway Settings</h2>
        <div class="dashboard-container">
            <button hx-get="/web/settings/add-form" hx-target="#settings-content">Add Setting</button>
            <div id="settings-content" class="dashboard-section">
                <h3>Current Settings</h3>
    "##);

    if !settings_rows.is_empty() {
        html.push_str(r##"
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Key</th>
                            <th>Value</th>
                            <th>Description</th>
                            <th>Updated</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
        "##);

        for row in settings_rows {
            let key: String = row.get("key");
            let value: String = row.get("value");
            let description: Option<String> = row.get("description");
            let updated_at: String = row.get("updated_at");

            html.push_str(&format!(
                r##"
                        <tr>
                            <td><code>{}</code></td>
                            <td>{}</td>
                            <td>{}</td>
                            <td>{}</td>
                            <td>
                                <button hx-get="/web/settings/edit/{}" hx-target="#settings-content">Edit</button>
                                <button hx-delete="/web/settings/{}" hx-target="#settings-content" hx-confirm="Are you sure you want to delete this setting?">Delete</button>
                            </td>
                        </tr>
                "##,
                key,
                value,
                description.unwrap_or_else(|| "—".to_string()),
                updated_at,
                key,
                key
            ));
        }

        html.push_str(r##"
                    </tbody>
                </table>
        "##);
    } else {
        html.push_str(r##"
                <p>No settings configured. <a href="#" hx-get="/web/settings/add-form" hx-target="#settings-content">Add your first setting</a>.</p>
        "##);
    }

    html.push_str(r##"
            </div>
        </div>
    "##);

    Html(html)
}
