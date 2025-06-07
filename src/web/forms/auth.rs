//! This module generates HTML inputs for forms that require authentication fields.

use crate::{auth::types::AuthType, web::handlers::RouteFormData};

/// Generate HTML input fields for different authentication types.
pub fn generate_auth_fields(auth_type: AuthType, form_data: &RouteFormData) -> String {
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
        AuthType::BasicAuth => format!(
            r##"
                <div>
                    <label for="auth_value">Basic Auth Credentials (username:password):</label><br>
                    <input type="text" id="auth_value" name="auth_value" value="{}" placeholder="username:password">
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