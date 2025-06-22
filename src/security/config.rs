//! # Security Configuration Module
//!
//! This module provides comprehensive security configuration for the Blackgate API gateway.
//! It centralizes all security-related settings including CORS, rate limiting, request
//! validation, and various security policies.
//!
//! ## Features
//!
//! - **Centralized Security Config**: Single source of truth for all security settings
//! - **Environment Integration**: Load configuration from environment variables
//! - **Validation**: Comprehensive validation of security settings
//! - **Secure Defaults**: Security-first default values for all settings
//! - **Runtime Updates**: Support for runtime configuration updates
//! - **Audit Logging**: Security configuration change logging
//!
//! ## Security Domains
//!
//! - **Request Security**: Body size limits, path validation, timeout controls
//! - **CORS Policy**: Cross-origin resource sharing configuration
//! - **Rate Limiting**: Request rate and burst controls
//! - **Authentication**: Auth method configuration and validation
//! - **TLS/SSL**: Transport layer security settings
//! - **Headers**: Security header injection and validation
//!
//! ## Usage
//!
//! ```rust
//! use crate::security::config::SecurityConfig;
//!
//! let config = SecurityConfig::from_env()?;
//! config.validate()?;
//! ```

use crate::security::cors::CorsConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use tracing::{error, info, warn};

/// Maximum request body size in bytes (default: 10MB)
pub const DEFAULT_MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024;

/// Maximum path length (default: 2048 characters)
pub const DEFAULT_MAX_PATH_LENGTH: usize = 2048;

/// Default request timeout in seconds
pub const DEFAULT_REQUEST_TIMEOUT: u64 = 30;

/// Default connection pool size
pub const DEFAULT_CONNECTION_POOL_SIZE: usize = 100;

/// Default rate limit burst size
pub const DEFAULT_RATE_LIMIT_BURST: u32 = 10;

/// Comprehensive security configuration for Blackgate
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Request security settings
    pub request: RequestSecurityConfig,

    /// CORS configuration
    pub cors: CorsConfig,

    /// Rate limiting configuration
    pub rate_limiting: RateLimitingConfig,

    /// Authentication security settings
    pub authentication: AuthenticationConfig,

    /// TLS/SSL configuration
    pub tls: TlsConfig,

    /// Security headers configuration
    pub headers: SecurityHeadersConfig,

    /// Input validation configuration
    pub validation: ValidationConfig,

    /// Logging and monitoring security
    pub logging: LoggingSecurityConfig,
}

/// Request-level security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSecurityConfig {
    /// Maximum request body size in bytes
    pub max_body_size: usize,

    /// Maximum path length
    pub max_path_length: usize,

    /// Request timeout duration
    pub timeout: Duration,

    /// Maximum number of headers per request
    pub max_headers: usize,

    /// Maximum header value size
    pub max_header_size: usize,

    /// Maximum query string length
    pub max_query_length: usize,

    /// Blocked user agents (regex patterns)
    pub blocked_user_agents: Vec<String>,

    /// Blocked IP addresses/CIDR ranges
    pub blocked_ips: Vec<String>,

    /// Enable request size validation
    pub validate_request_size: bool,

    /// Enable path traversal protection
    pub validate_path_traversal: bool,
}

/// Rate limiting security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    /// Global rate limiting enabled
    pub enabled: bool,

    /// Default requests per minute limit
    pub default_rpm: u32,

    /// Default requests per hour limit
    pub default_rph: u32,

    /// Burst allowance for rate limiting
    pub burst_size: u32,

    /// Rate limit by IP address
    pub limit_by_ip: bool,

    /// Rate limit by API key
    pub limit_by_api_key: bool,

    /// Rate limit by route
    pub limit_by_route: bool,

    /// Whitelist of IPs exempt from rate limiting
    pub whitelist_ips: Vec<String>,

    /// Rate limit window size in seconds
    pub window_size: u64,
}

/// Authentication security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationConfig {
    /// Require authentication for all routes
    pub require_auth_default: bool,

    /// JWT token expiration time in seconds
    pub jwt_expiration: u64,

    /// JWT secret rotation interval in seconds
    pub jwt_secret_rotation: u64,

    /// OAuth token cache TTL in seconds
    pub oauth_cache_ttl: u64,

    /// Maximum number of failed authentication attempts
    pub max_auth_failures: u32,

    /// Authentication failure lockout duration in seconds
    pub auth_lockout_duration: u64,

    /// Require secure auth headers (HTTPS only)
    pub require_secure_headers: bool,

    /// Allowed authentication methods
    pub allowed_auth_methods: HashSet<String>,
}

/// TLS/SSL security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enforce HTTPS for all requests
    pub enforce_https: bool,

    /// TLS certificate file path
    pub cert_path: Option<String>,

    /// TLS private key file path
    pub key_path: Option<String>,

    /// Minimum TLS version (e.g., "1.2", "1.3")
    pub min_tls_version: String,

    /// Allowed cipher suites
    pub allowed_ciphers: Vec<String>,

    /// Enable HTTP Strict Transport Security
    pub enable_hsts: bool,

    /// HSTS max age in seconds
    pub hsts_max_age: u64,

    /// Include subdomains in HSTS
    pub hsts_include_subdomains: bool,
}

/// Security headers configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeadersConfig {
    /// Enable security headers injection
    pub enabled: bool,

    /// Content Security Policy header value
    pub content_security_policy: Option<String>,

    /// X-Frame-Options header value
    pub frame_options: String,

    /// X-Content-Type-Options header value
    pub content_type_options: String,

    /// Referrer-Policy header value
    pub referrer_policy: String,

    /// Remove server identification headers
    pub remove_server_headers: bool,

    /// Custom security headers to add
    pub custom_headers: std::collections::HashMap<String, String>,
}

/// Input validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    /// Enable input sanitization
    pub sanitize_input: bool,

    /// Enable SQL injection protection
    pub sql_injection_protection: bool,

    /// Enable XSS protection
    pub xss_protection: bool,

    /// Enable path traversal protection
    pub path_traversal_protection: bool,

    /// Blocked file extensions
    pub blocked_extensions: Vec<String>,

    /// Blocked content types
    pub blocked_content_types: Vec<String>,

    /// Maximum file upload size
    pub max_upload_size: usize,

    /// Allowed file upload types
    pub allowed_upload_types: Vec<String>,
}

/// Logging security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSecurityConfig {
    /// Log security events
    pub log_security_events: bool,

    /// Log authentication attempts
    pub log_auth_attempts: bool,

    /// Log rate limit violations
    pub log_rate_limit_violations: bool,

    /// Log blocked requests
    pub log_blocked_requests: bool,

    /// Exclude sensitive data from logs
    pub exclude_sensitive_data: bool,

    /// Security log retention days
    pub security_log_retention_days: u32,

    /// Enable audit logging
    pub enable_audit_logging: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            request: RequestSecurityConfig::default(),
            cors: CorsConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
            authentication: AuthenticationConfig::default(),
            tls: TlsConfig::default(),
            headers: SecurityHeadersConfig::default(),
            validation: ValidationConfig::default(),
            logging: LoggingSecurityConfig::default(),
        }
    }
}

impl Default for RequestSecurityConfig {
    fn default() -> Self {
        Self {
            max_body_size: DEFAULT_MAX_REQUEST_SIZE,
            max_path_length: DEFAULT_MAX_PATH_LENGTH,
            timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT),
            max_headers: 50,
            max_header_size: 8192,
            max_query_length: 4096,
            blocked_user_agents: vec![
                r"(?i).*bot.*".to_string(),
                r"(?i).*crawler.*".to_string(),
                r"(?i).*spider.*".to_string(),
            ],
            blocked_ips: Vec::new(),
            validate_request_size: true,
            validate_path_traversal: true,
        }
    }
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        let mut allowed_methods = HashSet::new();
        allowed_methods.insert("jwt".to_string());
        allowed_methods.insert("oauth".to_string());
        allowed_methods.insert("api_key".to_string());

        Self {
            enabled: true,
            default_rpm: 60,
            default_rph: 1000,
            burst_size: DEFAULT_RATE_LIMIT_BURST,
            limit_by_ip: true,
            limit_by_api_key: true,
            limit_by_route: true,
            whitelist_ips: Vec::new(),
            window_size: 60,
        }
    }
}

impl Default for AuthenticationConfig {
    fn default() -> Self {
        let mut allowed_methods = HashSet::new();
        allowed_methods.insert("jwt".to_string());
        allowed_methods.insert("oauth".to_string());
        allowed_methods.insert("api_key".to_string());
        allowed_methods.insert("basic".to_string());
        allowed_methods.insert("oidc".to_string());

        Self {
            require_auth_default: true,
            jwt_expiration: 3600,       // 1 hour
            jwt_secret_rotation: 86400, // 24 hours
            oauth_cache_ttl: 300,       // 5 minutes
            max_auth_failures: 5,
            auth_lockout_duration: 900, // 15 minutes
            require_secure_headers: true,
            allowed_auth_methods: allowed_methods,
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enforce_https: true,
            cert_path: None,
            key_path: None,
            min_tls_version: "1.2".to_string(),
            allowed_ciphers: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
            ],
            enable_hsts: true,
            hsts_max_age: 31536000, // 1 year
            hsts_include_subdomains: true,
        }
    }
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        let mut custom_headers = std::collections::HashMap::new();
        custom_headers.insert("X-Gateway".to_string(), "Blackgate".to_string());

        Self {
            enabled: true,
            content_security_policy: Some(
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'".to_string()
            ),
            frame_options: "DENY".to_string(),
            content_type_options: "nosniff".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            remove_server_headers: true,
            custom_headers,
        }
    }
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            sanitize_input: true,
            sql_injection_protection: true,
            xss_protection: true,
            path_traversal_protection: true,
            blocked_extensions: vec![
                ".exe".to_string(),
                ".bat".to_string(),
                ".cmd".to_string(),
                ".scr".to_string(),
                ".pif".to_string(),
            ],
            blocked_content_types: vec![
                "application/x-executable".to_string(),
                "application/x-dosexec".to_string(),
            ],
            max_upload_size: 50 * 1024 * 1024, // 50MB
            allowed_upload_types: vec![
                "image/jpeg".to_string(),
                "image/png".to_string(),
                "image/gif".to_string(),
                "text/plain".to_string(),
                "application/json".to_string(),
            ],
        }
    }
}

impl Default for LoggingSecurityConfig {
    fn default() -> Self {
        Self {
            log_security_events: true,
            log_auth_attempts: true,
            log_rate_limit_violations: true,
            log_blocked_requests: true,
            exclude_sensitive_data: true,
            security_log_retention_days: 90,
            enable_audit_logging: true,
        }
    }
}

impl SecurityConfig {
    /// Create a new security configuration with secure defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a permissive configuration for development
    pub fn development() -> Self {
        warn!("Creating development security configuration - NOT FOR PRODUCTION!");

        let mut config = Self::default();
        config.cors = crate::security::cors::CorsConfig::permissive();
        config.tls.enforce_https = false;
        config.authentication.require_auth_default = false;
        config.rate_limiting.enabled = false;
        config.validation.sanitize_input = false;

        config
    }

    /// Create a production-ready configuration with strict security
    pub fn production() -> Self {
        let mut config = Self::default();
        config.cors = crate::security::cors::CorsConfig::restrictive();
        config.tls.enforce_https = true;
        config.authentication.require_auth_default = true;
        config.rate_limiting.enabled = true;
        config.validation.sanitize_input = true;
        config.headers.enabled = true;

        config
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, SecurityConfigError> {
        let mut config = Self::default();

        // Load request security config
        if let Ok(max_size) = std::env::var("BLACKGATE_MAX_REQUEST_SIZE") {
            config.request.max_body_size = max_size.parse().map_err(|_| {
                SecurityConfigError::InvalidValue("BLACKGATE_MAX_REQUEST_SIZE".to_string())
            })?;
        }

        if let Ok(max_path) = std::env::var("BLACKGATE_MAX_PATH_LENGTH") {
            config.request.max_path_length = max_path.parse().map_err(|_| {
                SecurityConfigError::InvalidValue("BLACKGATE_MAX_PATH_LENGTH".to_string())
            })?;
        }

        if let Ok(timeout) = std::env::var("BLACKGATE_REQUEST_TIMEOUT") {
            let timeout_secs: u64 = timeout.parse().map_err(|_| {
                SecurityConfigError::InvalidValue("BLACKGATE_REQUEST_TIMEOUT".to_string())
            })?;
            config.request.timeout = Duration::from_secs(timeout_secs);
        }

        // Load CORS config
        config.cors = crate::security::cors::parse_cors_config_from_env();

        // Load rate limiting config
        if let Ok(enabled) = std::env::var("BLACKGATE_RATE_LIMITING_ENABLED") {
            config.rate_limiting.enabled = enabled.to_lowercase() == "true";
        }

        if let Ok(rpm) = std::env::var("BLACKGATE_DEFAULT_RPM") {
            config.rate_limiting.default_rpm = rpm.parse().map_err(|_| {
                SecurityConfigError::InvalidValue("BLACKGATE_DEFAULT_RPM".to_string())
            })?;
        }

        // Load TLS config
        if let Ok(enforce) = std::env::var("BLACKGATE_ENFORCE_HTTPS") {
            config.tls.enforce_https = enforce.to_lowercase() == "true";
        }

        config.tls.cert_path = std::env::var("BLACKGATE_TLS_CERT_PATH").ok();
        config.tls.key_path = std::env::var("BLACKGATE_TLS_KEY_PATH").ok();

        // Load headers config
        if let Ok(enabled) = std::env::var("BLACKGATE_SECURITY_HEADERS_ENABLED") {
            config.headers.enabled = enabled.to_lowercase() == "true";
        }

        if let Ok(csp) = std::env::var("BLACKGATE_CONTENT_SECURITY_POLICY") {
            config.headers.content_security_policy = Some(csp);
        }

        info!("Security configuration loaded from environment");
        Ok(config)
    }

    /// Validate the security configuration
    pub fn validate(&self) -> Result<(), SecurityConfigError> {
        // Validate request config
        if self.request.max_body_size == 0 {
            return Err(SecurityConfigError::ValidationError(
                "Max body size cannot be zero".to_string(),
            ));
        }

        if self.request.max_path_length == 0 {
            return Err(SecurityConfigError::ValidationError(
                "Max path length cannot be zero".to_string(),
            ));
        }

        if self.request.timeout.as_secs() == 0 {
            return Err(SecurityConfigError::ValidationError(
                "Request timeout cannot be zero".to_string(),
            ));
        }

        // Validate TLS config
        if self.tls.enforce_https {
            if self.tls.cert_path.is_none() || self.tls.key_path.is_none() {
                warn!("HTTPS enforcement enabled but TLS cert/key paths not configured");
            }
        }

        // Validate authentication config
        if self.authentication.max_auth_failures == 0 {
            return Err(SecurityConfigError::ValidationError(
                "Max auth failures cannot be zero".to_string(),
            ));
        }

        // Validate rate limiting
        if self.rate_limiting.enabled {
            if self.rate_limiting.default_rpm == 0 && self.rate_limiting.default_rph == 0 {
                return Err(SecurityConfigError::ValidationError(
                    "Rate limiting enabled but no limits configured".to_string(),
                ));
            }
        }

        info!("Security configuration validation passed");
        Ok(())
    }

    /// Get a summary of the security configuration
    pub fn summary(&self) -> String {
        format!(
            "SecurityConfig {{ \
                max_body_size: {}MB, \
                enforce_https: {}, \
                cors_enabled: {}, \
                rate_limiting: {}, \
                auth_required: {}, \
                security_headers: {} \
            }}",
            self.request.max_body_size / (1024 * 1024),
            self.tls.enforce_https,
            self.cors.enabled,
            self.rate_limiting.enabled,
            self.authentication.require_auth_default,
            self.headers.enabled
        )
    }
}

/// Security configuration errors
#[derive(Debug, thiserror::Error)]
pub enum SecurityConfigError {
    #[error("Invalid configuration value for {0}")]
    InvalidValue(String),

    #[error("Configuration validation failed: {0}")]
    ValidationError(String),

    #[error("Missing required configuration: {0}")]
    MissingRequired(String),

    #[error("Environment variable error: {0}")]
    EnvironmentError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SecurityConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.request.max_body_size, DEFAULT_MAX_REQUEST_SIZE);
        assert_eq!(config.request.max_path_length, DEFAULT_MAX_PATH_LENGTH);
        assert!(config.rate_limiting.enabled);
        assert!(config.authentication.require_auth_default);
    }

    #[test]
    fn test_development_config() {
        let config = SecurityConfig::development();
        assert!(config.validate().is_ok());
        assert!(!config.tls.enforce_https);
        assert!(!config.authentication.require_auth_default);
        assert!(!config.rate_limiting.enabled);
    }

    #[test]
    fn test_production_config() {
        let config = SecurityConfig::production();
        assert!(config.validate().is_ok());
        assert!(config.tls.enforce_https);
        assert!(config.authentication.require_auth_default);
        assert!(config.rate_limiting.enabled);
        assert!(config.headers.enabled);
    }

    #[test]
    fn test_invalid_config() {
        let mut config = SecurityConfig::default();
        config.request.max_body_size = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_summary() {
        let config = SecurityConfig::default();
        let summary = config.summary();
        assert!(summary.contains("max_body_size"));
        assert!(summary.contains("enforce_https"));
    }
}
