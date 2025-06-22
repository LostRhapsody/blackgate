//! # Security Middleware Module
//!
//! This module provides comprehensive security middleware for the Blackgate API gateway.
//! It implements multiple layers of security controls including request validation,
//! CORS handling, rate limiting, and security header injection.
//!
//! ## Features
//!
//! - **Request Validation**: Size, path, and content validation
//! - **CORS Handling**: Cross-origin request security
//! - **Rate Limiting**: Request rate controls and burst protection
//! - **Security Headers**: Automatic security header injection
//! - **Input Sanitization**: XSS and injection attack prevention
//! - **IP Blocking**: IP-based access control
//! - **User Agent Filtering**: Bot and crawler blocking
//! - **Attack Detection**: Common attack pattern detection
//!
//! ## Middleware Layers
//!
//! The security middleware is organized into multiple layers that can be
//! applied independently or combined for comprehensive protection:
//!
//! 1. **Request Security Layer**: Basic request validation and sanitization
//! 2. **CORS Layer**: Cross-origin resource sharing controls
//! 3. **Rate Limiting Layer**: Request rate and burst controls
//! 4. **Authentication Layer**: Auth method validation and enforcement
//! 5. **Response Security Layer**: Security header injection and response sanitization
//!
//! ## Usage
//!
//! ```rust
//! use crate::security::middleware::{SecurityMiddleware, create_security_layers};
//! use crate::security::config::SecurityConfig;
//!
//! let config = SecurityConfig::production();
//! let middleware = SecurityMiddleware::new(config);
//! let layers = create_security_layers(middleware);
//!
//! let app = Router::new()
//!     .route("/api/*path", get(handler))
//!     .layer(layers);
//! ```

use crate::security::{
    config::{SecurityConfig, SecurityConfigError},
    cors::{add_cors_headers, validate_cors_origin},
};
use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use regex::Regex;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Security event types for logging and monitoring
#[derive(Debug, Clone)]
pub enum SecurityEvent {
    /// Blocked request due to security policy
    BlockedRequest {
        reason: String,
        ip: String,
        path: String,
        user_agent: Option<String>,
    },
    /// Rate limit violation
    RateLimitViolation {
        ip: String,
        path: String,
        limit_type: String,
    },
    /// Suspicious activity detected
    SuspiciousActivity {
        ip: String,
        path: String,
        pattern: String,
    },
    /// Authentication failure
    AuthenticationFailure {
        ip: String,
        path: String,
        auth_type: String,
    },
    /// CORS violation
    CorsViolation {
        origin: String,
        method: String,
        reason: String,
    },
}

/// Rate limiting tracker for IP addresses
#[derive(Debug, Clone, Default)]
pub struct RateLimitTracker {
    /// Request counts per minute
    pub requests_per_minute: HashMap<String, (u32, Instant)>,
    /// Request counts per hour
    pub requests_per_hour: HashMap<String, (u32, Instant)>,
    /// Failed authentication attempts
    pub auth_failures: HashMap<String, (u32, Instant)>,
}

impl RateLimitTracker {
    /// Check if an IP address is rate limited
    pub fn is_rate_limited(&mut self, ip: &str, rpm_limit: u32, rph_limit: u32) -> bool {
        let now = Instant::now();

        // Check per-minute limit
        if rpm_limit > 0 {
            let entry = self
                .requests_per_minute
                .entry(ip.to_string())
                .or_insert((0, now));
            if now.duration_since(entry.1) >= Duration::from_secs(60) {
                // Reset counter
                entry.0 = 1;
                entry.1 = now;
            } else {
                entry.0 += 1;
                if entry.0 > rpm_limit {
                    return true;
                }
            }
        }

        // Check per-hour limit
        if rph_limit > 0 {
            let entry = self
                .requests_per_hour
                .entry(ip.to_string())
                .or_insert((0, now));
            if now.duration_since(entry.1) >= Duration::from_secs(3600) {
                // Reset counter
                entry.0 = 1;
                entry.1 = now;
            } else {
                entry.0 += 1;
                if entry.0 > rph_limit {
                    return true;
                }
            }
        }

        false
    }

    /// Record an authentication failure
    pub fn record_auth_failure(&mut self, ip: &str) {
        let now = Instant::now();
        let entry = self.auth_failures.entry(ip.to_string()).or_insert((0, now));

        if now.duration_since(entry.1) >= Duration::from_secs(900) {
            // 15 minutes
            entry.0 = 1;
            entry.1 = now;
        } else {
            entry.0 += 1;
        }
    }

    /// Check if an IP is locked out due to auth failures
    pub fn is_auth_locked(&self, ip: &str, max_failures: u32) -> bool {
        if let Some((failures, last_failure)) = self.auth_failures.get(ip) {
            let now = Instant::now();
            if now.duration_since(*last_failure) < Duration::from_secs(900) {
                // 15 minutes
                return *failures >= max_failures;
            }
        }
        false
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();

        self.requests_per_minute
            .retain(|_, (_, timestamp)| now.duration_since(*timestamp) < Duration::from_secs(60));

        self.requests_per_hour
            .retain(|_, (_, timestamp)| now.duration_since(*timestamp) < Duration::from_secs(3600));

        self.auth_failures
            .retain(|_, (_, timestamp)| now.duration_since(*timestamp) < Duration::from_secs(900));
    }
}

/// Main security middleware structure
#[derive(Clone)]
pub struct SecurityMiddleware {
    /// Security configuration
    pub config: SecurityConfig,
    /// Rate limiting tracker
    pub rate_tracker: Arc<RwLock<RateLimitTracker>>,
    /// Compiled regex patterns for user agent blocking
    pub blocked_user_agents: Vec<Regex>,
    /// Security event handler
    pub event_handler: Option<Arc<dyn Fn(SecurityEvent) + Send + Sync>>,
}

impl SecurityMiddleware {
    /// Create a new security middleware with the given configuration
    pub fn new(config: SecurityConfig) -> Result<Self, SecurityConfigError> {
        config.validate()?;

        // Compile user agent regex patterns
        let mut blocked_user_agents = Vec::new();
        for pattern in &config.request.blocked_user_agents {
            match Regex::new(pattern) {
                Ok(regex) => blocked_user_agents.push(regex),
                Err(e) => {
                    warn!("Invalid user agent regex pattern '{}': {}", pattern, e);
                }
            }
        }

        Ok(Self {
            config,
            rate_tracker: Arc::new(RwLock::new(RateLimitTracker::default())),
            blocked_user_agents,
            event_handler: None,
        })
    }

    /// Set a custom security event handler
    pub fn with_event_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(SecurityEvent) + Send + Sync + 'static,
    {
        self.event_handler = Some(Arc::new(handler));
        self
    }

    /// Handle a security event
    fn handle_security_event(&self, event: SecurityEvent) {
        if let Some(handler) = &self.event_handler {
            handler(event.clone());
        }

        // Default logging
        match event {
            SecurityEvent::BlockedRequest {
                reason, ip, path, ..
            } => {
                warn!("Blocked request from {}: {} (path: {})", ip, reason, path);
            }
            SecurityEvent::RateLimitViolation {
                ip,
                path,
                limit_type,
            } => {
                warn!(
                    "Rate limit violation from {}: {} (path: {})",
                    ip, limit_type, path
                );
            }
            SecurityEvent::SuspiciousActivity { ip, path, pattern } => {
                warn!(
                    "Suspicious activity from {}: {} (path: {})",
                    ip, pattern, path
                );
            }
            SecurityEvent::AuthenticationFailure {
                ip,
                path,
                auth_type,
            } => {
                warn!(
                    "Authentication failure from {}: {} (path: {})",
                    ip, auth_type, path
                );
            }
            SecurityEvent::CorsViolation {
                origin,
                method,
                reason,
            } => {
                warn!(
                    "CORS violation from {}: {} (method: {})",
                    origin, reason, method
                );
            }
        }
    }
}

/// Request security validation middleware
pub async fn request_security_middleware(
    security: Arc<SecurityMiddleware>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let ip = addr.ip().to_string();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();

    // Extract path and query
    let path = uri.path();
    let query = uri.query().unwrap_or("");

    // Validate request size (body size is handled by axum's built-in limits)
    if path.len() > security.config.request.max_path_length {
        security.handle_security_event(SecurityEvent::BlockedRequest {
            reason: "Path too long".to_string(),
            ip: ip.clone(),
            path: path.to_string(),
            user_agent: headers
                .get("user-agent")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string()),
        });
        return Err(StatusCode::URI_TOO_LONG);
    }

    // Validate query string length
    if query.len() > security.config.request.max_query_length {
        security.handle_security_event(SecurityEvent::BlockedRequest {
            reason: "Query string too long".to_string(),
            ip: ip.clone(),
            path: path.to_string(),
            user_agent: headers
                .get("user-agent")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string()),
        });
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check for path traversal attempts
    if security.config.validation.path_traversal_protection
        && (path.contains("..") || path.contains("//") || path.contains("\\"))
    {
        security.handle_security_event(SecurityEvent::SuspiciousActivity {
            ip: ip.clone(),
            path: path.to_string(),
            pattern: "Path traversal attempt".to_string(),
        });
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check blocked IPs
    for blocked_ip in &security.config.request.blocked_ips {
        if ip.starts_with(blocked_ip) {
            security.handle_security_event(SecurityEvent::BlockedRequest {
                reason: "IP blocked".to_string(),
                ip: ip.clone(),
                path: path.to_string(),
                user_agent: headers
                    .get("user-agent")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string()),
            });
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Check blocked user agents
    if let Some(user_agent) = headers.get("user-agent").and_then(|h| h.to_str().ok()) {
        for pattern in &security.blocked_user_agents {
            if pattern.is_match(user_agent) {
                security.handle_security_event(SecurityEvent::BlockedRequest {
                    reason: "User agent blocked".to_string(),
                    ip: ip.clone(),
                    path: path.to_string(),
                    user_agent: Some(user_agent.to_string()),
                });
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }

    // Check for common attack patterns
    if security.config.validation.sql_injection_protection {
        let query_lower = path.to_lowercase() + query.to_lowercase().as_str();
        if query_lower.contains("union select")
            || query_lower.contains("drop table")
            || query_lower.contains("' or 1=1")
            || query_lower.contains("'; --")
        {
            security.handle_security_event(SecurityEvent::SuspiciousActivity {
                ip: ip.clone(),
                path: path.to_string(),
                pattern: "SQL injection attempt".to_string(),
            });
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Check for XSS attempts
    if security.config.validation.xss_protection {
        let query_lower = path.to_lowercase() + query.to_lowercase().as_str();
        if query_lower.contains("<script")
            || query_lower.contains("javascript:")
            || query_lower.contains("onload=")
            || query_lower.contains("onerror=")
        {
            security.handle_security_event(SecurityEvent::SuspiciousActivity {
                ip: ip.clone(),
                path: path.to_string(),
                pattern: "XSS attempt".to_string(),
            });
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Authentication lockout check
    {
        let tracker = security.rate_tracker.read().await;
        if tracker.is_auth_locked(&ip, security.config.authentication.max_auth_failures) {
            security.handle_security_event(SecurityEvent::BlockedRequest {
                reason: "Authentication lockout".to_string(),
                ip: ip.clone(),
                path: path.to_string(),
                user_agent: headers
                    .get("user-agent")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string()),
            });
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    // Rate limiting check
    if security.config.rate_limiting.enabled {
        let mut tracker = security.rate_tracker.write().await;
        if tracker.is_rate_limited(
            &ip,
            security.config.rate_limiting.default_rpm,
            security.config.rate_limiting.default_rph,
        ) {
            security.handle_security_event(SecurityEvent::RateLimitViolation {
                ip: ip.clone(),
                path: path.to_string(),
                limit_type: "Global rate limit".to_string(),
            });
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    // Continue to next middleware
    let response = next.run(request).await;
    Ok(response)
}

/// CORS security middleware
pub async fn cors_middleware(
    security: Arc<SecurityMiddleware>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let headers = request.headers().clone();
    let origin = headers.get("origin").and_then(|h| h.to_str().ok());

    // Validate CORS if enabled
    if security.config.cors.enabled {
        match validate_cors_origin(&security.config.cors, origin) {
            true => {
                // Continue with request
                let mut response = next.run(request).await;
                add_cors_headers(response.headers_mut(), &security.config.cors, origin);
                Ok(response)
            }
            false => {
                security.handle_security_event(SecurityEvent::CorsViolation {
                    origin: origin.unwrap_or("unknown").to_string(),
                    method: method.to_string(),
                    reason: "NOT ALLOWED".to_string(),
                });
                Err(StatusCode::FORBIDDEN)
            }
        }
    } else {
        // CORS disabled, continue normally
        Ok(next.run(request).await)
    }
}

/// Security headers middleware
pub async fn security_headers_middleware(
    security: Arc<SecurityMiddleware>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let mut response = next.run(request).await;

    if security.config.headers.enabled {
        let headers = response.headers_mut();

        // Add standard security headers
        headers.insert(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_str(&security.config.headers.content_type_options).unwrap(),
        );

        headers.insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_str(&security.config.headers.frame_options).unwrap(),
        );

        headers.insert(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_str(&security.config.headers.referrer_policy).unwrap(),
        );

        // Add Content Security Policy if configured
        if let Some(ref csp) = security.config.headers.content_security_policy {
            headers.insert(
                HeaderName::from_static("content-security-policy"),
                HeaderValue::from_str(csp).unwrap(),
            );
        }

        // Add HSTS header if HTTPS enforcement is enabled
        if security.config.tls.enable_hsts {
            let hsts_value = if security.config.tls.hsts_include_subdomains {
                format!(
                    "max-age={}; includeSubDomains",
                    security.config.tls.hsts_max_age
                )
            } else {
                format!("max-age={}", security.config.tls.hsts_max_age)
            };
            headers.insert(
                HeaderName::from_static("strict-transport-security"),
                HeaderValue::from_str(&hsts_value).unwrap(),
            );
        }

        // Add custom headers
        for (name, value) in &security.config.headers.custom_headers {
            if let (Ok(header_name), Ok(header_value)) = (
                HeaderName::try_from(name.as_str()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(header_name, header_value);
            }
        }

        // Remove server identification headers if configured
        if security.config.headers.remove_server_headers {
            headers.remove("server");
            headers.remove("x-powered-by");
            headers.remove("x-aspnet-version");
            headers.remove("x-aspnetmvc-version");
        }
    }

    Ok(response)
}

/// Cleanup task for security middleware
pub async fn security_cleanup_task(security: Arc<SecurityMiddleware>) {
    let mut interval = tokio::time::interval(Duration::from_secs(300)); // Run every 5 minutes

    loop {
        interval.tick().await;

        {
            let mut tracker = security.rate_tracker.write().await;
            tracker.cleanup_expired();
        }

        debug!("Security middleware cleanup completed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::config::SecurityConfig;

    #[test]
    fn test_rate_limit_tracker() {
        let mut tracker = RateLimitTracker::default();
        let ip = "192.168.1.1";

        // Should not be rate limited initially
        assert!(!tracker.is_rate_limited(ip, 5, 100));

        // Add requests up to limit
        for _ in 0..4 {
            assert!(!tracker.is_rate_limited(ip, 5, 100));
        }

        // Should be rate limited after exceeding limit
        assert!(tracker.is_rate_limited(ip, 5, 100));
    }

    #[test]
    fn test_auth_lockout() {
        let mut tracker = RateLimitTracker::default();
        let ip = "192.168.1.1";

        // Should not be locked initially
        assert!(!tracker.is_auth_locked(ip, 3));

        // Record failures up to limit
        for _ in 0..2 {
            tracker.record_auth_failure(ip);
            assert!(!tracker.is_auth_locked(ip, 3));
        }

        // Should be locked after exceeding limit
        tracker.record_auth_failure(ip);
        assert!(tracker.is_auth_locked(ip, 3));
    }

    #[tokio::test]
    async fn test_security_middleware_creation() {
        let config = SecurityConfig::default();
        let middleware = SecurityMiddleware::new(config);
        assert!(middleware.is_ok());
    }

    #[tokio::test]
    async fn test_cleanup_task() {
        let config = SecurityConfig::default();
        let middleware = Arc::new(SecurityMiddleware::new(config).unwrap());

        // Add some entries
        {
            let mut tracker = middleware.rate_tracker.write().await;
            tracker.record_auth_failure("192.168.1.1");
        }

        // Run cleanup
        {
            let mut tracker = middleware.rate_tracker.write().await;
            tracker.cleanup_expired();
        }

        // Should still have entries (not expired yet)
        {
            let tracker = middleware.rate_tracker.read().await;
            assert!(!tracker.auth_failures.is_empty());
        }
    }
}
