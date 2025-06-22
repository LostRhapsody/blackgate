//! # HTTP Security Configuration Module
//!
//! This module provides HTTP security configuration for the Blackgate API gateway.
//! It defines configuration structures and validation utilities for secure HTTP
//! communication, but does not create HTTP clients directly.
//!
//! ## Features
//!
//! - **URL Validation**: Validates upstream URLs for security
//! - **Header Sanitization**: Utilities for sanitizing request/response headers
//! - **Security Configuration**: Configuration structures for HTTP client security
//!
//! ## Usage
//!
//! ```rust
//! use crate::security::http::{HttpClientConfig, validate_upstream_url};
//!
//! let config = HttpClientConfig::default();
//! validate_upstream_url("https://api.example.com")?;
//! ```

use std::time::Duration;
use tracing::warn;
use url;

/// Default request timeout in seconds
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default connection timeout in seconds
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Default read timeout in seconds
const DEFAULT_READ_TIMEOUT_SECS: u64 = 30;

/// Maximum number of redirects to follow
const MAX_REDIRECTS: usize = 5;

/// Maximum number of idle connections per host
const MAX_IDLE_CONNECTIONS_PER_HOST: usize = 10;

/// Pool idle timeout in seconds
const POOL_IDLE_TIMEOUT_SECS: u64 = 90;

/// User agent string for Blackgate requests
const USER_AGENT: &str = "Blackgate-API-Gateway/1.0";

/// Configuration for secure HTTP client
#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    /// Request timeout in seconds
    pub request_timeout: Duration,
    /// Connection timeout in seconds
    pub connect_timeout: Duration,
    /// Read timeout in seconds
    pub read_timeout: Duration,
    /// Maximum redirects to follow
    pub max_redirects: usize,
    /// Maximum idle connections per host
    pub max_idle_connections_per_host: usize,
    /// Pool idle timeout
    pub pool_idle_timeout: Duration,
    /// User agent string
    pub user_agent: String,
    /// Whether to verify TLS certificates
    pub verify_tls: bool,
    /// Enable HTTP/2
    pub enable_http2: bool,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            read_timeout: Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS),
            max_redirects: MAX_REDIRECTS,
            max_idle_connections_per_host: MAX_IDLE_CONNECTIONS_PER_HOST,
            pool_idle_timeout: Duration::from_secs(POOL_IDLE_TIMEOUT_SECS),
            user_agent: USER_AGENT.to_string(),
            verify_tls: true,
            enable_http2: true,
        }
    }
}



/// Validate that a URL is safe to connect to
pub fn validate_upstream_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;

    // Check scheme
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("Unsupported scheme: {}", scheme)),
    }

    // Check for private/local addresses
    if let Some(host) = parsed.host() {
        match host {
            url::Host::Domain(domain) => {
                // Block common local domains
                if domain == "localhost"
                    || domain.ends_with(".local")
                    || domain.ends_with(".localhost")
                {
                    return Err("Local domains not allowed".to_string());
                }
            }
            url::Host::Ipv4(ip) => {
                if ip.is_private() || ip.is_loopback() || ip.is_multicast() {
                    return Err("Private/local IP addresses not allowed".to_string());
                }
            }
            url::Host::Ipv6(ip) => {
                if ip.is_loopback() || ip.is_multicast() {
                    return Err("Local/multicast IPv6 addresses not allowed".to_string());
                }
            }
        }
    }

    // Check port restrictions
    if let Some(port) = parsed.port() {
        // Block common internal/system ports
        if port < 1024 && port != 80 && port != 443 {
            return Err("System ports not allowed".to_string());
        }
    }

    Ok(())
}

/// Sanitize request headers to remove sensitive information
pub fn sanitize_request_headers(headers: &mut axum::http::HeaderMap) {
    // Remove potentially sensitive headers that should not be forwarded
    headers.remove("authorization");
    headers.remove("cookie");
    headers.remove("set-cookie");
    headers.remove("x-api-key");
    headers.remove("x-auth-token");

    // Remove internal/debugging headers
    headers.remove("x-debug");
    headers.remove("x-trace-id");
    headers.remove("x-request-id");

    // Add security headers
    headers.insert("X-Forwarded-By", "Blackgate".parse().unwrap());
    headers.insert("X-Gateway-Version", "1.0".parse().unwrap());
}

/// Sanitize response headers to remove sensitive upstream information
pub fn sanitize_response_headers(headers: &mut axum::http::HeaderMap) {
    // Remove server identification
    headers.remove("server");
    headers.remove("x-powered-by");
    headers.remove("x-aspnet-version");
    headers.remove("x-aspnetmvc-version");

    // Remove internal debugging information
    headers.remove("x-debug");
    headers.remove("x-trace-id");
    headers.remove("x-request-id");

    // Remove cache-related headers that might expose internal architecture
    headers.remove("x-cache");
    headers.remove("x-cache-hits");
    headers.remove("x-served-by");

    // Add security headers
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_upstream_url_valid() {
        assert!(validate_upstream_url("https://api.example.com").is_ok());
        assert!(validate_upstream_url("http://api.example.com:8080").is_ok());
    }

    #[test]
    fn test_validate_upstream_url_invalid_scheme() {
        assert!(validate_upstream_url("ftp://example.com").is_err());
        assert!(validate_upstream_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_validate_upstream_url_localhost() {
        assert!(validate_upstream_url("http://localhost").is_err());
        assert!(validate_upstream_url("https://localhost:8080").is_err());
        assert!(validate_upstream_url("http://127.0.0.1").is_err());
    }

    #[test]
    fn test_validate_upstream_url_private_ip() {
        assert!(validate_upstream_url("http://192.168.1.1").is_err());
        assert!(validate_upstream_url("http://10.0.0.1").is_err());
        assert!(validate_upstream_url("http://172.16.0.1").is_err());
    }

    #[test]
    fn test_validate_upstream_url_system_ports() {
        assert!(validate_upstream_url("http://example.com:22").is_err());
        assert!(validate_upstream_url("http://example.com:25").is_err());
        assert!(validate_upstream_url("http://example.com:80").is_ok());
        assert!(validate_upstream_url("https://example.com:443").is_ok());
    }

    #[test]
    fn test_sanitize_request_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());
        headers.insert("cookie", "session=123".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());

        sanitize_request_headers(&mut headers);

        assert!(!headers.contains_key("authorization"));
        assert!(!headers.contains_key("cookie"));
        assert!(headers.contains_key("content-type"));
        assert!(headers.contains_key("x-forwarded-by"));
    }

    #[test]
    fn test_sanitize_response_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("server", "nginx/1.20".parse().unwrap());
        headers.insert("x-powered-by", "PHP/8.0".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());

        sanitize_response_headers(&mut headers);

        assert!(!headers.contains_key("server"));
        assert!(!headers.contains_key("x-powered-by"));
        assert!(headers.contains_key("content-type"));
        assert!(headers.contains_key("x-content-type-options"));
    }
}
