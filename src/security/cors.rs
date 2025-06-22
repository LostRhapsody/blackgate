//! # CORS Security Module
//!
//! This module provides Cross-Origin Resource Sharing (CORS) security functionality
//! for the Blackgate API gateway. It implements secure CORS policies to control
//! which domains can access the API gateway and what operations they can perform.
//!
//! ## Features
//!
//! - **Origin Validation**: Configurable allowed origins with wildcard support
//! - **Method Control**: Granular control over allowed HTTP methods
//! - **Header Management**: Secure handling of allowed and exposed headers
//! - **Credentials Support**: Configurable credential handling for cross-origin requests
//! - **Preflight Handling**: Automatic OPTIONS preflight request processing
//! - **Security Headers**: Automatic injection of CORS security headers
//!
//! ## Security Considerations
//!
//! - Restricts origins to prevent unauthorized cross-origin access
//! - Validates HTTP methods to prevent unwanted operations
//! - Controls header exposure to minimize information leakage
//! - Implements secure defaults with explicit opt-in for permissive settings
//!
//! ## Usage
//!
//! ```rust
//! use crate::security::cors::{CorsConfig, create_cors_layer};
//!
//! let config = CorsConfig::new()
//!     .allow_origin("https://example.com")
//!     .allow_methods(vec!["GET", "POST"])
//!     .allow_credentials(false);
//!
//! let cors_layer = create_cors_layer(config);
//! ```

use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use std::collections::HashSet;
use tracing::{debug, warn};

/// Default maximum age for preflight cache in seconds (24 hours)
const DEFAULT_MAX_AGE: usize = 86400;

/// Configuration for CORS security policies
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins for cross-origin requests
    pub allowed_origins: HashSet<String>,
    /// Whether to allow all origins (use with caution)
    pub allow_all_origins: bool,
    /// Allowed HTTP methods
    pub allowed_methods: HashSet<String>,
    /// Allowed request headers
    pub allowed_headers: HashSet<String>,
    /// Headers to expose in responses
    pub exposed_headers: HashSet<String>,
    /// Whether to allow credentials in cross-origin requests
    pub allow_credentials: bool,
    /// Maximum age for preflight cache in seconds
    pub max_age: usize,
    /// Whether CORS is enabled
    pub enabled: bool,
}

impl Default for CorsConfig {
    fn default() -> Self {
        let mut allowed_methods = HashSet::new();
        allowed_methods.insert("GET".to_string());
        allowed_methods.insert("POST".to_string());
        allowed_methods.insert("PUT".to_string());
        allowed_methods.insert("PATCH".to_string());
        allowed_methods.insert("DELETE".to_string());
        allowed_methods.insert("HEAD".to_string());
        allowed_methods.insert("OPTIONS".to_string());

        let mut allowed_headers = HashSet::new();
        allowed_headers.insert("accept".to_string());
        allowed_headers.insert("accept-language".to_string());
        allowed_headers.insert("content-language".to_string());
        allowed_headers.insert("content-type".to_string());
        allowed_headers.insert("authorization".to_string());
        allowed_headers.insert("x-api-key".to_string());

        let mut exposed_headers = HashSet::new();
        exposed_headers.insert("x-total-count".to_string());
        exposed_headers.insert("x-page-count".to_string());

        Self {
            allowed_origins: HashSet::new(),
            allow_all_origins: false,
            allowed_methods,
            allowed_headers,
            exposed_headers,
            allow_credentials: false,
            max_age: DEFAULT_MAX_AGE,
            enabled: true,
        }
    }
}

impl CorsConfig {
    /// Create a new CORS configuration with secure defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a permissive CORS configuration (use only in development)
    pub fn permissive() -> Self {
        warn!("Creating permissive CORS configuration - use only in development!");

        let mut config = Self::default();
        config.allow_all_origins = true;
        config.allow_credentials = true;
        config
    }

    /// Create a restrictive CORS configuration for production
    pub fn restrictive() -> Self {
        let mut config = Self::default();
        config.allow_credentials = false;
        config.allowed_origins.clear();
        config
    }

    /// Add an allowed origin
    pub fn allow_origin(mut self, origin: &str) -> Self {
        self.allowed_origins.insert(origin.to_string());
        self.allow_all_origins = false;
        self
    }

    /// Allow all origins (use with extreme caution)
    pub fn allow_all_origins(mut self) -> Self {
        warn!("Allowing all origins - this should only be used in development!");
        self.allow_all_origins = true;
        self.allowed_origins.clear();
        self
    }

    /// Set allowed HTTP methods
    pub fn allow_methods(mut self, methods: Vec<&str>) -> Self {
        self.allowed_methods = methods.iter().map(|m| m.to_string()).collect();
        self
    }

    /// Add an allowed HTTP method
    pub fn allow_method(mut self, method: &str) -> Self {
        self.allowed_methods.insert(method.to_string());
        self
    }

    /// Set allowed request headers
    pub fn allow_headers(mut self, headers: Vec<&str>) -> Self {
        self.allowed_headers = headers.iter().map(|h| h.to_lowercase()).collect();
        self
    }

    /// Add an allowed request header
    pub fn allow_header(mut self, header: &str) -> Self {
        self.allowed_headers.insert(header.to_lowercase());
        self
    }

    /// Set exposed response headers
    pub fn expose_headers(mut self, headers: Vec<&str>) -> Self {
        self.exposed_headers = headers.iter().map(|h| h.to_lowercase()).collect();
        self
    }

    /// Add an exposed response header
    pub fn expose_header(mut self, header: &str) -> Self {
        self.exposed_headers.insert(header.to_lowercase());
        self
    }

    /// Set whether to allow credentials
    pub fn allow_credentials(mut self, allow: bool) -> Self {
        if allow && self.allow_all_origins {
            warn!("Allowing credentials with all origins is a security risk!");
        }
        self.allow_credentials = allow;
        self
    }

    /// Set preflight cache max age
    pub fn max_age(mut self, max_age: usize) -> Self {
        self.max_age = max_age;
        self
    }

    /// Enable or disable CORS
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// CORS validation result
#[derive(Debug, PartialEq)]
pub enum CorsValidation {
    /// Request is allowed
    Allowed,
    /// Request is not allowed
    Forbidden(String),
    /// Preflight request that should be handled
    Preflight,
}

/// Validate a CORS request against the configuration
pub fn validate_cors_request(
    config: &CorsConfig,
    method: &Method,
    origin: Option<&str>,
    headers: &HeaderMap,
) -> CorsValidation {
    if !config.enabled {
        return CorsValidation::Allowed;
    }

    // Handle preflight requests
    if method == Method::OPTIONS {
        return validate_preflight_request(config, origin, headers);
    }

    // Validate origin
    if let Some(origin_str) = origin {
        if !is_origin_allowed(config, origin_str) {
            return CorsValidation::Forbidden(format!("Origin not allowed: {}", origin_str));
        }
    }

    // Validate method
    if !config.allowed_methods.contains(method.as_str()) {
        return CorsValidation::Forbidden(format!("Method not allowed: {}", method));
    }

    CorsValidation::Allowed
}

/// Validate a preflight request
fn validate_preflight_request(
    config: &CorsConfig,
    origin: Option<&str>,
    headers: &HeaderMap,
) -> CorsValidation {
    // Check origin
    if let Some(origin_str) = origin {
        if !is_origin_allowed(config, origin_str) {
            return CorsValidation::Forbidden(format!("Origin not allowed: {}", origin_str));
        }
    }

    // Check requested method
    if let Some(method_header) = headers.get("access-control-request-method") {
        if let Ok(method_str) = method_header.to_str() {
            if !config.allowed_methods.contains(method_str) {
                return CorsValidation::Forbidden(format!("Method not allowed: {}", method_str));
            }
        }
    }

    // Check requested headers
    if let Some(headers_header) = headers.get("access-control-request-headers") {
        if let Ok(headers_str) = headers_header.to_str() {
            let requested_headers: Vec<&str> = headers_str.split(',').map(|h| h.trim()).collect();
            for header in requested_headers {
                if !config.allowed_headers.contains(&header.to_lowercase()) {
                    return CorsValidation::Forbidden(format!("Header not allowed: {}", header));
                }
            }
        }
    }

    CorsValidation::Preflight
}

/// Check if an origin is allowed
fn is_origin_allowed(config: &CorsConfig, origin: &str) -> bool {
    if config.allow_all_origins {
        return true;
    }

    // Check exact matches
    if config.allowed_origins.contains(origin) {
        return true;
    }

    // Check wildcard matches
    for allowed_origin in &config.allowed_origins {
        if allowed_origin.contains('*') && origin_matches_pattern(origin, allowed_origin) {
            return true;
        }
    }

    false
}

/// Check if an origin matches a wildcard pattern
fn origin_matches_pattern(origin: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Simple wildcard matching for subdomains
    if pattern.starts_with("*.") {
        let domain = &pattern[2..];
        return origin.ends_with(domain) || origin == domain;
    }

    false
}

/// Add CORS headers to a response
pub fn add_cors_headers(
    headers: &mut HeaderMap,
    config: &CorsConfig,
    origin: Option<&str>,
    is_preflight: bool,
) {
    if !config.enabled {
        return;
    }

    // Add Access-Control-Allow-Origin
    if let Some(origin_str) = origin {
        if is_origin_allowed(config, origin_str) {
            if config.allow_all_origins && !config.allow_credentials {
                headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
            } else if let Ok(origin_value) = HeaderValue::from_str(origin_str) {
                headers.insert("access-control-allow-origin", origin_value);
            }
        }
    } else if config.allow_all_origins && !config.allow_credentials {
        headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    }

    // Add Access-Control-Allow-Credentials
    if config.allow_credentials {
        headers.insert(
            "access-control-allow-credentials",
            HeaderValue::from_static("true"),
        );
    }

    // Add preflight-specific headers
    if is_preflight {
        // Add Access-Control-Allow-Methods
        let methods_str = config
            .allowed_methods
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if let Ok(methods_value) = HeaderValue::from_str(&methods_str) {
            headers.insert("access-control-allow-methods", methods_value);
        }

        // Add Access-Control-Allow-Headers
        let headers_str = config
            .allowed_headers
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if let Ok(headers_value) = HeaderValue::from_str(&headers_str) {
            headers.insert("access-control-allow-headers", headers_value);
        }

        // Add Access-Control-Max-Age
        let max_age_str = config.max_age.to_string();
        if let Ok(max_age_value) = HeaderValue::from_str(&max_age_str) {
            headers.insert("access-control-max-age", max_age_value);
        }
    } else {
        // Add Access-Control-Expose-Headers for actual requests
        if !config.exposed_headers.is_empty() {
            let exposed_str = config
                .exposed_headers
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            if let Ok(exposed_value) = HeaderValue::from_str(&exposed_str) {
                headers.insert("access-control-expose-headers", exposed_value);
            }
        }
    }

    // Add Vary header to indicate that the response varies based on the Origin header
    headers.insert("vary", HeaderValue::from_static("Origin"));
}

/// Create a preflight response
pub fn create_preflight_response(
    config: &CorsConfig,
    origin: Option<&str>,
) -> axum::response::Response {
    let mut headers = HeaderMap::new();
    add_cors_headers(&mut headers, config, origin, true);

    let mut response = axum::response::Response::builder().status(StatusCode::NO_CONTENT);

    // Add all headers to the response
    let response_headers = response.headers_mut().unwrap();
    for (key, value) in headers {
        if let Some(key) = key {
            response_headers.insert(key, value);
        }
    }

    response.body(axum::body::Body::empty()).unwrap()
}

/// Parse CORS configuration from environment variables
pub fn parse_cors_config_from_env() -> CorsConfig {
    let mut config = CorsConfig::new();

    // Parse allowed origins
    if let Ok(origins_str) = std::env::var("BLACKGATE_CORS_ALLOWED_ORIGINS") {
        if origins_str.trim() == "*" {
            config = config.allow_all_origins();
        } else {
            for origin in origins_str.split(',') {
                let origin = origin.trim();
                if !origin.is_empty() {
                    config = config.allow_origin(origin);
                }
            }
        }
    }

    // Parse allowed methods
    if let Ok(methods_str) = std::env::var("BLACKGATE_CORS_ALLOWED_METHODS") {
        let methods: Vec<&str> = methods_str.split(',').map(|m| m.trim()).collect();
        config = config.allow_methods(methods);
    }

    // Parse allowed headers
    if let Ok(headers_str) = std::env::var("BLACKGATE_CORS_ALLOWED_HEADERS") {
        let headers: Vec<&str> = headers_str.split(',').map(|h| h.trim()).collect();
        config = config.allow_headers(headers);
    }

    // Parse allow credentials
    if let Ok(credentials_str) = std::env::var("BLACKGATE_CORS_ALLOW_CREDENTIALS") {
        config = config.allow_credentials(credentials_str.to_lowercase() == "true");
    }

    // Parse max age
    if let Ok(max_age_str) = std::env::var("BLACKGATE_CORS_MAX_AGE") {
        if let Ok(max_age) = max_age_str.parse::<usize>() {
            config = config.max_age(max_age);
        }
    }

    // Parse enabled flag
    if let Ok(enabled_str) = std::env::var("BLACKGATE_CORS_ENABLED") {
        config = config.enabled(enabled_str.to_lowercase() != "false");
    }

    debug!("CORS configuration loaded from environment: {:?}", config);
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn test_default_config() {
        let config = CorsConfig::default();
        assert!(!config.allow_all_origins);
        assert!(!config.allow_credentials);
        assert!(config.enabled);
        assert_eq!(config.max_age, DEFAULT_MAX_AGE);
    }

    #[test]
    fn test_permissive_config() {
        let config = CorsConfig::permissive();
        assert!(config.allow_all_origins);
        assert!(config.allow_credentials);
    }

    #[test]
    fn test_restrictive_config() {
        let config = CorsConfig::restrictive();
        assert!(!config.allow_all_origins);
        assert!(!config.allow_credentials);
        assert!(config.allowed_origins.is_empty());
    }

    #[test]
    fn test_origin_validation() {
        let mut config = CorsConfig::new();
        config = config.allow_origin("https://example.com");

        assert!(is_origin_allowed(&config, "https://example.com"));
        assert!(!is_origin_allowed(&config, "https://malicious.com"));
    }

    #[test]
    fn test_wildcard_origin_validation() {
        let mut config = CorsConfig::new();
        config = config.allow_origin("*.example.com");

        assert!(is_origin_allowed(&config, "api.example.com"));
        assert!(is_origin_allowed(&config, "www.example.com"));
        assert!(!is_origin_allowed(&config, "example.com"));
        assert!(!is_origin_allowed(&config, "malicious.com"));
    }

    #[test]
    fn test_cors_validation_allowed() {
        let config = CorsConfig::new().allow_origin("https://example.com");
        let headers = HeaderMap::new();

        let result =
            validate_cors_request(&config, &Method::GET, Some("https://example.com"), &headers);

        assert_eq!(result, CorsValidation::Allowed);
    }

    #[test]
    fn test_cors_validation_forbidden_origin() {
        let config = CorsConfig::new().allow_origin("https://example.com");
        let headers = HeaderMap::new();

        let result = validate_cors_request(
            &config,
            &Method::GET,
            Some("https://malicious.com"),
            &headers,
        );

        match result {
            CorsValidation::Forbidden(msg) => assert!(msg.contains("Origin not allowed")),
            _ => panic!("Expected Forbidden result"),
        }
    }

    #[test]
    fn test_cors_validation_forbidden_method() {
        let mut config = CorsConfig::new();
        config = config.allow_origin("https://example.com");
        config.allowed_methods.clear();
        config.allowed_methods.insert("GET".to_string());

        let headers = HeaderMap::new();

        let result = validate_cors_request(
            &config,
            &Method::POST,
            Some("https://example.com"),
            &headers,
        );

        match result {
            CorsValidation::Forbidden(msg) => assert!(msg.contains("Method not allowed")),
            _ => panic!("Expected Forbidden result"),
        }
    }

    #[test]
    fn test_preflight_validation() {
        let config = CorsConfig::new().allow_origin("https://example.com");
        let headers = HeaderMap::new();

        let result = validate_cors_request(
            &config,
            &Method::OPTIONS,
            Some("https://example.com"),
            &headers,
        );

        assert_eq!(result, CorsValidation::Preflight);
    }

    #[test]
    fn test_add_cors_headers() {
        let config = CorsConfig::new().allow_origin("https://example.com");
        let mut headers = HeaderMap::new();

        add_cors_headers(&mut headers, &config, Some("https://example.com"), false);

        assert_eq!(
            headers.get("access-control-allow-origin").unwrap(),
            "https://example.com"
        );
        assert_eq!(headers.get("vary").unwrap(), "Origin");
    }

    #[test]
    fn test_create_preflight_response() {
        let config = CorsConfig::new().allow_origin("https://example.com");
        let response = create_preflight_response(&config, Some("https://example.com"));

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            response
                .headers()
                .contains_key("access-control-allow-origin")
        );
    }
}
