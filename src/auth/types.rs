/// Authentication types supported by the gateway
#[derive(Debug, Clone, PartialEq)]
pub enum AuthType {
    None,
    ApiKey,
    BasicAuth,
    OAuth2,
    Jwt,
    Oidc,
}

impl AuthType {
    /// Parse authentication type from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "api-key" | "apikey" => AuthType::ApiKey,
            "basic-auth" | "basicauth" | "basic" => AuthType::BasicAuth,
            "oauth2" | "oauth" => AuthType::OAuth2,
            "jwt" => AuthType::Jwt,
            "oidc" => AuthType::Oidc,
            "none" | "" => AuthType::None,
            _ => {
                eprintln!("Unknown auth type '{}', defaulting to None", s);
                AuthType::None
            }
        }
    }

    /// Convert authentication type to string for database storage
    pub fn to_string(&self) -> &'static str {
        match self {
            AuthType::None => "none",
            AuthType::ApiKey => "api-key",
            AuthType::BasicAuth => "basic-auth",
            AuthType::OAuth2 => "oauth2",
            AuthType::Jwt => "jwt",
            AuthType::Oidc => "oidc",
        }
    }

    /// Convert authentication type to a user-friendly display string
    pub fn to_display_string(&self) -> String {
        match self {
            AuthType::None => "No".to_string(),
            AuthType::ApiKey => "API Key".to_string(),
            AuthType::BasicAuth => "Basic Auth".to_string(),
            AuthType::OAuth2 => "OAuth 2.0".to_string(),
            AuthType::Jwt => "JWT".to_string(),
            AuthType::Oidc => "OIDC".to_string(),
        }
    }
}