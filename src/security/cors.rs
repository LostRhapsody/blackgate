//! # CORS Configuration Module
//!
//! This module provides Cross-Origin Resource Sharing (CORS) configuration
//! for the Blackgate API gateway. It defines CORS policies and provides
//! utilities for CORS header management.
//!
//! ## Features
//!
//! - **Origin Configuration**: Configurable allowed origins with wildcard support
//! - **Header Management**: CORS header configuration and utilities
//! - **Credentials Support**: Configurable credential handling for cross-origin requests
//! - **Environment Configuration**: Load CORS settings from environment variables
//!
//! ## Usage
//!
//! ```rust
//! use crate::security::cors::CorsConfig;
//!
//! let config = CorsConfig::new()
//!     .allow_origin("https://example.com")
//!     .allow_credentials(false);
//! ```

use axum::http::{HeaderMap, HeaderValue};
use std::collections::HashSet;
use tracing::{debug, warn};

/// Default maximum age for preflight cache in seconds (24 hours)
const DEFAULT_MAX_AGE: usize = 86400;

/// Configuration for CORS policies
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins for cross-origin requests
    pub allowed_origins: HashSet<String>,
    /// Whether to allow all origins (use with caution)
    pub allow_all_origins: bool,
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

/// Validate a CORS origin against the configuration
pub fn validate_cors_origin(config: &CorsConfig, origin: Option<&str>) -> bool {
    if !config.enabled {
        return true;
    }

    if let Some(origin_str) = origin {
        is_origin_allowed(config, origin_str)
    } else {
        true
    }
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
pub fn add_cors_headers(headers: &mut HeaderMap, config: &CorsConfig, origin: Option<&str>) {
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

    // Add Access-Control-Expose-Headers
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

    // Add Vary header to indicate that the response varies based on the Origin header
    headers.insert("vary", HeaderValue::from_static("Origin"));
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
    fn test_cors_origin_validation() {
        let config = CorsConfig::new().allow_origin("https://example.com");

        assert!(validate_cors_origin(&config, Some("https://example.com")));
        assert!(!validate_cors_origin(&config, Some("https://malicious.com")));
        assert!(validate_cors_origin(&config, None));
    }

    #[test]
    fn test_add_cors_headers() {
        let config = CorsConfig::new().allow_origin("https://example.com");
        let mut headers = HeaderMap::new();

        add_cors_headers(&mut headers, &config, Some("https://example.com"));

        assert_eq!(
            headers.get("access-control-allow-origin").unwrap(),
            "https://example.com"
        );
        assert_eq!(headers.get("vary").unwrap(), "Origin");
    }
}
