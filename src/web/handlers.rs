use std::sync::Arc;

use crate::{
    AppState, AuthType,
    database::queries,
    health::HealthChecker,
    rate_limiter::{DEFAULT_RATE_LIMIT_PER_HOUR, DEFAULT_RATE_LIMIT_PER_MINUTE},
    web::forms::{auth::generate_auth_fields, routes::generate_route_form},
    web::views::{collections::collections_list, routes::routes_list, settings::settings_view},
};
use axum::{
    extract::{Form, Path, Query, State},
    http::StatusCode,
    response::Html,
};
use serde::Deserialize;
use sqlx::Row;
use tracing::{error, info, warn};

///////////////////////////////////////////////////////////////////////////////
//****                         Public Structs                            ****//
///////////////////////////////////////////////////////////////////////////////

#[derive(Deserialize)]
pub struct MetricsQuery {
    pub limit: Option<u32>,
}

#[derive(Deserialize, Default)]
pub struct RouteFormQuery {
    collection_id: Option<i64>,
}

#[derive(Deserialize, Default)]
pub struct RouteFormData {
    pub path: String,
    pub upstream: String,
    pub backup_route_path: Option<String>,
    pub collection_id: Option<i64>,
    pub auth_type: String,
    pub auth_value: Option<String>,
    pub allowed_methods: Option<String>,
    pub oauth_token_url: Option<String>,
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret: Option<String>,
    pub oauth_scope: Option<String>,
    pub jwt_secret: Option<String>,
    pub jwt_algorithm: Option<String>,
    pub jwt_issuer: Option<String>,
    pub jwt_audience: Option<String>,
    pub jwt_required_claims: Option<String>,
    pub oidc_issuer: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_audience: Option<String>,
    pub oidc_scope: Option<String>,
    pub rate_limit_per_minute: Option<u32>,
    pub rate_limit_per_hour: Option<u32>,
    pub health_endpoint: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct RouteCollectionFormData {
    pub name: Option<String>,
    pub description: Option<String>,
    pub openapi_spec_url: Option<String>,
    pub base_upstream_url: Option<String>,
    pub default_auth_type: Option<String>,
    pub default_auth_value: Option<String>,
    pub default_oauth_token_url: Option<String>,
    pub default_oauth_client_id: Option<String>,
    pub default_oauth_client_secret: Option<String>,
    pub default_oauth_scope: Option<String>,
    pub default_jwt_secret: Option<String>,
    pub default_jwt_algorithm: Option<String>,
    pub default_jwt_issuer: Option<String>,
    pub default_jwt_audience: Option<String>,
    pub default_jwt_required_claims: Option<String>,
    pub default_oidc_issuer: Option<String>,
    pub default_oidc_client_id: Option<String>,
    pub default_oidc_client_secret: Option<String>,
    pub default_oidc_audience: Option<String>,
    pub default_oidc_scope: Option<String>,
    pub default_rate_limit_per_minute: Option<u32>,
    pub default_rate_limit_per_hour: Option<u32>,
}

#[derive(Deserialize)]
pub struct SettingsFormData {
    key: String,
    value: String,
    description: Option<String>,
}

///////////////////////////////////////////////////////////////////////////////
//****                       Helper Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

pub fn generate_health_indicator(health_status: &str) -> String {
    let (color, title) = match health_status {
        "Healthy" => ("green", "Healthy - Service is responding normally"),
        "Unhealthy" => ("red", "Unhealthy - Service is not responding properly"),
        "Unavailable" => ("yellow", "Unavailable - Health check cannot be performed"),
        _ => ("purple", "Unknown - Health status not yet determined"),
    };

    format!(
        r##"<span class="health-indicator health-{}" title="{}">●</span>"##,
        color, title
    )
}

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

pub async fn home_page() -> Html<String> {
    Html(
        std::fs::read_to_string("templates/home.html").unwrap_or_else(|_| {
            String::from("<h1>Welcome to BlackGate</h1><p>API Gateway Dashboard</p>")
        }),
    )
}

pub async fn auth_fields_form(
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Html<String> {
    let default_auth_type = "none".to_string();
    let auth_type_str = params.get("auth_type").unwrap_or(&default_auth_type);
    let auth_type = AuthType::from_str(auth_type_str);
    let form_data = RouteFormData::default();
    let html = generate_auth_fields(auth_type, &form_data);
    Html(html)
}

pub async fn collection_auth_fields_form(
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Html<String> {
    let default_auth_type = "none".to_string();
    let auth_type_str = params
        .get("default_auth_type")
        .unwrap_or(&default_auth_type);
    let auth_type = AuthType::from_str(auth_type_str);
    let form_data = RouteCollectionFormData::default();
    let html = crate::web::forms::auth::generate_collection_auth_fields(auth_type, &form_data);
    Html(html)
}

pub async fn toggle_collection_fields(
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Html<String> {
    let empty_string = String::new();
    let openapi_url = params.get("openapi_spec_url").unwrap_or(&empty_string);
    let is_openapi_mode = !openapi_url.trim().is_empty();

    let form_data = RouteCollectionFormData::default();
    let auth_type = AuthType::from_str(
        &form_data
            .default_auth_type
            .clone()
            .unwrap_or_else(|| "none".into()),
    );
    let auth_fields =
        crate::web::forms::auth::generate_collection_auth_fields(auth_type.clone(), &form_data);

    let disabled = if is_openapi_mode { " disabled" } else { "" };
    let disabled_note = if is_openapi_mode {
        "<small><em style=\"color: #ffb366;\">These fields will be automatically filled from the OpenAPI specification</em></small>"
    } else {
        ""
    };

    // Handle base URL field based on OpenAPI servers
    let base_url_field = if is_openapi_mode {
        // Try to fetch and extract servers from the OpenAPI spec
        match crate::open_api::fetch_and_extract_servers(openapi_url).await {
            Ok(servers) => {
                if servers.is_empty() {
                    // No servers defined - show manual input with message
                    r##"
                        <div>
                            <label for="base_upstream_url">Base Upstream URL:</label><br>
                            <input type="url" id="base_upstream_url" name="base_upstream_url" placeholder="https://api.example.com" required>
                            <small style="color: orange;"><em>No upstream servers are defined in the OpenAPI document, please provide a base URL for this collection to use for its paths</em></small>
                        </div>
                    "##.to_string()
                } else if servers.len() == 1 {
                    // Single server - auto-select it
                    let server = &servers[0];
                    let description = server
                        .description
                        .as_deref()
                        .unwrap_or("Server from OpenAPI spec");
                    format!(
                        r##"
                        <div>
                            <label for="base_upstream_url">Base Upstream URL:</label><br>
                            <input type="url" id="base_upstream_url" name="base_upstream_url" value="{}" readonly>
                            <small style="color: green;"><em>Automatically selected from OpenAPI spec: {}</em></small>
                        </div>
                    "##,
                        server.url, description
                    )
                } else {
                    // Multiple servers - show dropdown
                    let mut options = String::new();
                    for server in &servers {
                        let description = server.description.as_deref().unwrap_or("No description");
                        options.push_str(&format!(
                            r##"<option value="{}">{} - {}</option>"##,
                            server.url, server.url, description
                        ));
                    }
                    format!(
                        r##"
                        <div>
                            <label for="base_upstream_url">Base Upstream URL:</label><br>
                            <select id="base_upstream_url" name="base_upstream_url" required>
                                <option value="">Select a server from the OpenAPI spec...</option>
                                {}
                            </select>
                            <small style="color: #ffb366;"><em>Multiple servers found in OpenAPI spec, please select one</em></small>
                        </div>
                    "##,
                        options
                    )
                }
            }
            Err(e) => {
                warn!("Failed to fetch servers from OpenAPI spec: {}", e);
                // Fallback to manual input
                r##"
                    <div>
                        <label for="base_upstream_url">Base Upstream URL:</label><br>
                        <input type="url" id="base_upstream_url" name="base_upstream_url" placeholder="https://api.example.com" required>
                        <small style="color: orange;"><em>Could not fetch server information from OpenAPI spec, please provide a base URL manually</em></small>
                    </div>
                "##.to_string()
            }
        }
    } else {
        // Manual mode - show normal input
        r##"
            <div>
                <label for="base_upstream_url">Base Upstream URL:</label><br>
                <input type="url" id="base_upstream_url" name="base_upstream_url" placeholder="https://api.example.com" required>
                <small>Base URL that will be prepended to all route paths</small>
            </div>
        "##.to_string()
    };

    let html = format!(
        r##"
        <div id="form-fields">
            {}
            <div>
                <label for="name">Collection Name:</label><br>
                <input type="text" id="name" name="name" placeholder="e.g., api_v1" required{}>
            </div>

            <div>
                <label for="description">Description:</label><br>
                <input type="text" id="description" name="description" placeholder="Brief description of this collection"{}>
            </div>

            {}

            <div>
                <label for="default_auth_type">Default Authentication Type:</label><br>
                <select id="default_auth_type" name="default_auth_type" hx-trigger="change" hx-target="#auth-fields" hx-get="/web/collections/auth-fields" hx-swap="innerHTML"{}>
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
    "##,
        disabled_note,
        disabled,
        disabled,
        base_url_field,
        disabled,
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

pub async fn add_route_form(
    State(state): State<AppState>,
    Query(query): Query<RouteFormQuery>,
) -> Html<String> {
    // Fetch available collections
    let collections = queries::fetch_all_route_collections(&state.db)
        .await
        .unwrap_or_default();

    // fetch the rate limit defaults from the DB
    let row = queries::get_setting_by_key(&state.db, "default_rate_limit_per_hour")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);

    let default_rate_limit_per_hour: u32 = match row {
        Ok(Some(row)) => {
            let value_str: String = row.get("value");
            value_str.parse().unwrap_or_else(|e| {
                warn!(
                    "Failed to parse default_rate_limit_per_hour setting '{}': {}, using default",
                    value_str, e
                );
                DEFAULT_RATE_LIMIT_PER_HOUR
            })
        }
        Ok(None) => {
            warn!("Default rate limit setting not found, using fallback value");
            DEFAULT_RATE_LIMIT_PER_HOUR // Fallback value if setting not found
        }
        Err(e) => {
            error!("Failed to fetch default rate limit setting: {}", e);
            DEFAULT_RATE_LIMIT_PER_HOUR // Fallback value if setting not found
        }
    };

    // fetch the rate limit defaults from the DB
    let row = queries::get_setting_by_key(&state.db, "default_rate_limit_per_minute")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);

    let default_rate_limit_per_minute: u32 = match row {
        Ok(Some(row)) => {
            let value_str: String = row.get("value");
            value_str.parse().unwrap_or_else(|e| {
                warn!(
                    "Failed to parse default_rate_limit_per_minute setting '{}': {}, using default",
                    value_str, e
                );
                DEFAULT_RATE_LIMIT_PER_MINUTE
            })
        }
        Ok(None) => {
            warn!("Default rate limit setting not found, using fallback value");
            DEFAULT_RATE_LIMIT_PER_MINUTE // Fallback value if setting not found
        }
        Err(e) => {
            error!("Failed to fetch default rate limit setting: {}", e);
            DEFAULT_RATE_LIMIT_PER_MINUTE // Fallback value if setting not found
        }
    };

    let form_data = RouteFormData {
        auth_type: "none".to_string(),
        collection_id: query.collection_id,
        rate_limit_per_minute: Some(default_rate_limit_per_minute),
        rate_limit_per_hour: Some(default_rate_limit_per_hour),
        ..Default::default()
    };
    Html(generate_route_form(false, "", form_data, collections))
}

pub async fn edit_route_form(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Result<Html<String>, StatusCode> {
    // Fetch available collections
    let collections = queries::fetch_all_route_collections(&state.db)
        .await
        .unwrap_or_default();

    let row = queries::fetch_route_by_path_for_edit(&state.db, &path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let row = match row {
        Some(row) => row,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let form_data = RouteFormData {
        path: row.get("path"),
        upstream: row.get("upstream"),
        backup_route_path: Some(row.get("backup_route_path")),
        collection_id: row.get("collection_id"),
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
        health_endpoint: Some(row.get("health_endpoint")),
    };

    Ok(Html(generate_route_form(
        true,
        &path,
        form_data,
        collections,
    )))
}

pub async fn add_route_submit(
    State(state): State<AppState>,
    Form(form): Form<RouteFormData>,
) -> Result<Html<String>, StatusCode> {
    let auth_type_enum = AuthType::from_str(&form.auth_type);

    let result = queries::insert_or_replace_route(
        &state.db,
        &form.path,
        &form.upstream,
        &form.backup_route_path.unwrap_or_default(),
        // Column is nullable, for "no collection", we just pass in None to make it null and not connected to any collections
        if form.collection_id == Some(0) {
            None
        } else {
            form.collection_id
        },
        &auth_type_enum,
        &form.auth_value.unwrap_or_default(),
        &form.allowed_methods.unwrap_or_default(),
        &form.oauth_token_url.unwrap_or_default(),
        &form.oauth_client_id.unwrap_or_default(),
        &form.oauth_client_secret.unwrap_or_default(),
        &form.oauth_scope.unwrap_or_default(),
        &form.jwt_secret.unwrap_or_default(),
        &form.jwt_algorithm.unwrap_or_else(|| "HS256".to_string()),
        &form.jwt_issuer.unwrap_or_default(),
        &form.jwt_audience.unwrap_or_default(),
        &form.jwt_required_claims.unwrap_or_default(),
        form.rate_limit_per_minute
            .unwrap_or(DEFAULT_RATE_LIMIT_PER_MINUTE),
        form.rate_limit_per_hour
            .unwrap_or(DEFAULT_RATE_LIMIT_PER_HOUR),
        &form.oidc_issuer.unwrap_or_default(),
        &form.oidc_client_id.unwrap_or_default(),
        &form.oidc_client_secret.unwrap_or_default(),
        &form.oidc_audience.unwrap_or_default(),
        &form.oidc_scope.unwrap_or_default(),
        &form.health_endpoint.unwrap_or_default(),
    )
    .await;

    match result {
        Ok(_) => Ok(routes_list(State(state)).await),
        Err(e) => {
            eprintln!("Failed to add route: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn delete_route(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Result<Html<String>, StatusCode> {
    let result = queries::delete_route_by_path(&state.db, &path).await;

    match result {
        Ok(_) => Ok(Html("".to_string())),
        Err(e) => {
            eprintln!("Failed to delete route: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn edit_route_submit(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Form(form): Form<RouteFormData>,
) -> Result<Html<String>, StatusCode> {
    let auth_type_enum = AuthType::from_str(&form.auth_type);

    let result = queries::update_route_by_path(
        &state.db,
        &form.path,
        &form.upstream,
        &form.backup_route_path.unwrap_or_default(),
        // Column is nullable, for "no collection", we just pass in None to make it null and not connected to any collections
        if form.collection_id == Some(0) {
            None
        } else {
            form.collection_id
        },
        &auth_type_enum,
        &form.auth_value.unwrap_or_default(),
        &form.allowed_methods.unwrap_or_default(),
        &form.oauth_token_url.unwrap_or_default(),
        &form.oauth_client_id.unwrap_or_default(),
        &form.oauth_client_secret.unwrap_or_default(),
        &form.oauth_scope.unwrap_or_default(),
        &form.jwt_secret.unwrap_or_default(),
        &form.jwt_algorithm.unwrap_or_else(|| "HS256".to_string()),
        &form.jwt_issuer.unwrap_or_default(),
        &form.jwt_audience.unwrap_or_default(),
        &form.jwt_required_claims.unwrap_or_default(),
        &form.oidc_issuer.unwrap_or_default(),
        &form.oidc_client_id.unwrap_or_default(),
        &form.oidc_client_secret.unwrap_or_default(),
        &form.oidc_audience.unwrap_or_default(),
        &form.oidc_scope.unwrap_or_default(),
        form.rate_limit_per_minute.unwrap_or(60),
        form.rate_limit_per_hour.unwrap_or(1000),
        &form.health_endpoint.unwrap_or_default(),
        &path,
    )
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

pub async fn clear_route_health_status(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Result<Html<String>, StatusCode> {
    let result = queries::clear_route_health_status(&state.db, &path).await;

    match result {
        Ok(_) => Ok(routes_list(State(state)).await),
        Err(e) => {
            eprintln!("Failed to clear health status for route: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn trigger_all_routes_health_check(
    State(state): State<AppState>,
) -> Result<Html<String>, StatusCode> {
    info!("Triggering health checks for all routes");
    match HealthChecker::new(Arc::new(state.db.clone()))
        .run_health_checks()
        .await
    {
        Ok(_) => {
            info!("Health checks completed successfully for all routes");
            // If health checks were successful, return the routes list
            Ok(routes_list(State(state)).await)
        }
        Err(e) => {
            eprintln!("Failed to trigger health checks for all routes: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn trigger_route_health_check(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Result<Html<String>, StatusCode> {
    info!("Triggering health check for route: {}", path);
    let health_checker = HealthChecker::new(Arc::new(state.db.clone()));
    let route = health_checker.fetch_route_for_health_check(&path).await;
    match route {
        Ok(route) => {
            info!("Found route for health check: {}", path);
            let result = health_checker.check_route_health(&route[0]).await;
            match result {
                Ok(health_result) => {
                    // Store the health check result in database
                    if let Err(e) = health_checker.store_health_result(&health_result).await {
                        error!(
                            "Failed to store health result for route {}: {}",
                            health_result.path, e
                        );
                    }

                    info!(
                        "Health check for {} completed: {} ({}ms, method: {})",
                        health_result.path,
                        health_result.health_check_status.to_string(),
                        health_result.response_time_ms.unwrap_or(0),
                        health_result.method_used.to_string()
                    );
                    Ok(routes_list(State(state)).await)
                }
                Err(e) => {
                    error!("Health check failed for route {}: {}", route[0].path, e);
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to fetch route for health check: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn add_setting_submit(
    State(state): State<AppState>,
    Form(form): Form<SettingsFormData>,
) -> Result<Html<String>, StatusCode> {
    // Insert new setting
    let result = sqlx::query(
        "INSERT INTO settings (key, value, description, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)"
    )
    .bind(&form.key)
    .bind(&form.value)
    .bind(&form.description)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => Ok(settings_view(State(state)).await),
        Err(e) => {
            eprintln!("Failed to add setting: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn edit_setting_submit(
    State(state): State<AppState>,
    Path(original_key): Path<String>,
    Form(form): Form<SettingsFormData>,
) -> Result<Html<String>, StatusCode> {
    // Update setting
    let result = sqlx::query(
        "UPDATE settings SET key = ?, value = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?"
    )
    .bind(&form.key)
    .bind(&form.value)
    .bind(&form.description)
    .bind(&original_key)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => Ok(settings_view(State(state)).await),
        Err(e) => {
            eprintln!("Failed to update setting: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn delete_setting(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<Html<String>, StatusCode> {
    let result = sqlx::query("DELETE FROM settings WHERE key = ?")
        .bind(&key)
        .execute(&state.db)
        .await;

    match result {
        Ok(_) => Ok(settings_view(State(state)).await),
        Err(e) => {
            eprintln!("Failed to delete setting: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
//****                   Collection Management Handlers                  ****//
///////////////////////////////////////////////////////////////////////////////

pub async fn add_collection_submit(
    State(state): State<AppState>,
    Form(form): Form<RouteCollectionFormData>,
) -> Result<Html<String>, StatusCode> {
    // Check if OpenAPI spec URL is provided
    let (name, description, auth_type, openapi_spec) =
        if let Some(openapi_url) = &form.openapi_spec_url {
            if !openapi_url.trim().is_empty() {
                // Fetch and extract metadata from OpenAPI spec
                match crate::open_api::fetch_and_extract_metadata(openapi_url).await {
                    Ok(metadata) => {
                        info!(
                            "Successfully extracted metadata from OpenAPI spec: {}",
                            metadata.title
                        );

                        // Also fetch the OpenAPI spec for route extraction
                        let spec = match crate::open_api::fetch_and_parse_spec(openapi_url).await {
                            Ok(spec) => Some(spec),
                            Err(e) => {
                                warn!(
                                    "Could not re-parse OpenAPI spec for route extraction: {}",
                                    e
                                );
                                None
                            }
                        };

                        (
                            metadata.title,
                            metadata.description.unwrap_or_default(),
                            AuthType::from_str(&metadata.auth_type),
                            spec,
                        )
                    }
                    Err(e) => {
                        error!(
                            "Failed to fetch or parse OpenAPI spec from {}: {}",
                            openapi_url, e
                        );
                        return Err(StatusCode::BAD_REQUEST);
                    }
                }
            } else {
                // Use form data
                (
                    form.name.clone().unwrap_or_default(),
                    form.description.clone().unwrap_or_default(),
                    AuthType::from_str(
                        &form
                            .default_auth_type
                            .clone()
                            .unwrap_or_else(|| "none".into()),
                    ),
                    None,
                )
            }
        } else {
            // Use form data
            (
                form.name.clone().unwrap_or_default(),
                form.description.clone().unwrap_or_default(),
                AuthType::from_str(
                    &form
                        .default_auth_type
                        .clone()
                        .unwrap_or_else(|| "none".into()),
                ),
                None,
            )
        };

    // Create the collection and get the ID
    let collection_id = queries::insert_route_collection_with_id(
        &state.db,
        &name,
        &description,
        &auth_type,
        &form.default_auth_value.unwrap_or_default(),
        &form.default_oauth_token_url.unwrap_or_default(),
        &form.default_oauth_client_id.unwrap_or_default(),
        &form.default_oauth_client_secret.unwrap_or_default(),
        &form.default_oauth_scope.unwrap_or_default(),
        &form.default_jwt_secret.unwrap_or_default(),
        &form
            .default_jwt_algorithm
            .unwrap_or_else(|| "HS256".to_string()),
        &form.default_jwt_issuer.unwrap_or_default(),
        &form.default_jwt_audience.unwrap_or_default(),
        &form.default_jwt_required_claims.unwrap_or_default(),
        &form.default_oidc_issuer.unwrap_or_default(),
        &form.default_oidc_client_id.unwrap_or_default(),
        &form.default_oidc_client_secret.unwrap_or_default(),
        &form.default_oidc_audience.unwrap_or_default(),
        &form.default_oidc_scope.unwrap_or_default(),
        form.default_rate_limit_per_minute
            .unwrap_or(DEFAULT_RATE_LIMIT_PER_MINUTE),
        form.default_rate_limit_per_hour
            .unwrap_or(DEFAULT_RATE_LIMIT_PER_HOUR),
    )
    .await;

    match collection_id {
        Ok(id) => {
            info!("Collection '{}' added successfully with ID: {}", name, id);

            // If we have an OpenAPI spec, extract and create routes
            if let Some(spec) = openapi_spec {
                let base_url = form.base_upstream_url.as_deref().unwrap_or("");
                match crate::open_api::extract_routes_from_spec(
                    &spec,
                    base_url, // Use the base URL from the form
                    form.default_rate_limit_per_minute
                        .unwrap_or(DEFAULT_RATE_LIMIT_PER_MINUTE),
                    form.default_rate_limit_per_hour
                        .unwrap_or(DEFAULT_RATE_LIMIT_PER_HOUR),
                ) {
                    Ok(routes) => {
                        info!("Extracted {} routes from OpenAPI spec", routes.len());

                        // Insert routes with the collection ID
                        match queries::insert_routes_from_openapi(&state.db, id, &routes).await {
                            Ok(_) => {
                                info!(
                                    "Successfully created {} routes for collection '{}'",
                                    routes.len(),
                                    name
                                );
                            }
                            Err(e) => {
                                error!("Failed to create routes for collection '{}': {}", name, e);
                                // Collection was created but routes failed - log but don't fail the request
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to extract routes from OpenAPI spec: {}", e);
                        // Collection was created but route extraction failed - log but don't fail the request
                    }
                }
            }

            Ok(collections_list(State(state)).await)
        }
        Err(e) => {
            error!("Failed to add collection: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn edit_collection_submit(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Form(form): Form<RouteCollectionFormData>,
) -> Result<Html<String>, StatusCode> {
    let auth_type = AuthType::from_str(
        &form
            .default_auth_type
            .clone()
            .unwrap_or_else(|| "none".into()),
    );

    let result = queries::update_route_collection(
        &state.db,
        id,
        &form.name.clone().unwrap_or_default(),
        &form.description.unwrap_or_default(),
        &auth_type,
        &form.default_auth_value.unwrap_or_default(),
        &form.default_oauth_token_url.unwrap_or_default(),
        &form.default_oauth_client_id.unwrap_or_default(),
        &form.default_oauth_client_secret.unwrap_or_default(),
        &form.default_oauth_scope.unwrap_or_default(),
        &form.default_jwt_secret.unwrap_or_default(),
        &form
            .default_jwt_algorithm
            .unwrap_or_else(|| "HS256".to_string()),
        &form.default_jwt_issuer.unwrap_or_default(),
        &form.default_jwt_audience.unwrap_or_default(),
        &form.default_jwt_required_claims.unwrap_or_default(),
        &form.default_oidc_issuer.unwrap_or_default(),
        &form.default_oidc_client_id.unwrap_or_default(),
        &form.default_oidc_client_secret.unwrap_or_default(),
        &form.default_oidc_audience.unwrap_or_default(),
        &form.default_oidc_scope.unwrap_or_default(),
        form.default_rate_limit_per_minute
            .unwrap_or(DEFAULT_RATE_LIMIT_PER_MINUTE),
        form.default_rate_limit_per_hour
            .unwrap_or(DEFAULT_RATE_LIMIT_PER_HOUR),
    )
    .await;

    match result {
        Ok(_) => {
            info!("Successfully updated collection with ID: {}", id);
            Ok(collections_list(State(state)).await)
        }
        Err(e) => {
            error!("Failed to update collection with ID {}: {}", id, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// TODO When you try and delete one but there is a route attached, SQLite will throw an error, we should handle that gracefully
pub async fn delete_collection(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Html<String>, StatusCode> {
    let result = queries::delete_route_collection(&state.db, id).await;

    match result {
        Ok(_) => {
            info!("Collection deleted successfully");
            Ok(collections_list(State(state)).await)
        }
        Err(e) => {
            error!("Failed to delete collection: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
