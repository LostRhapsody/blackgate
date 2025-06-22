//! # HTTP Client Module
//!
//! This module provides HTTP client creation and management for the Blackgate API gateway.
//! It creates configured HTTP clients for making upstream requests with proper security
//! settings, timeouts, and connection pooling.
//!
//! ## Features
//!
//! - **Secure Client Creation**: Creates HTTP clients with security configurations
//! - **Connection Management**: Proper timeout and connection pool settings
//! - **Development Support**: Relaxed security settings for development environments
//!
//! ## Usage
//!
//! ```rust
//! use crate::routing::client::create_secure_client;
//!
//! let client = create_secure_client().await?;
//! let response = client.get("https://api.example.com").send().await?;
//! ```

use crate::security::http::HttpClientConfig;
use reqwest::{Client, ClientBuilder};
use tracing::{info, warn};

/// Create a secure HTTP client with proper security configuration
pub fn create_secure_client() -> Result<Client, Box<dyn std::error::Error + Send + Sync>> {
    create_secure_client_with_config(HttpClientConfig::default())
}

/// Create a secure HTTP client with custom configuration
pub fn create_secure_client_with_config(
    config: HttpClientConfig,
) -> Result<Client, Box<dyn std::error::Error + Send + Sync>> {
    info!("Creating secure HTTP client with timeouts and security settings");

    let mut builder = ClientBuilder::new()
        // Timeout configurations
        .timeout(config.request_timeout)
        .connect_timeout(config.connect_timeout)
        .read_timeout(config.read_timeout)
        // Security configurations
        .user_agent(&config.user_agent)
        .redirect(reqwest::redirect::Policy::limited(config.max_redirects))
        // Connection pool settings
        .pool_idle_timeout(config.pool_idle_timeout)
        .pool_max_idle_per_host(config.max_idle_connections_per_host)
        // Security headers
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert("X-Forwarded-By", "Blackgate".parse().unwrap());
            headers.insert("Cache-Control", "no-cache".parse().unwrap());
            headers
        });

    // TLS configuration
    if !config.verify_tls {
        warn!("TLS certificate verification is disabled - this should only be used in development");
        builder = builder.danger_accept_invalid_certs(true);
    }

    // HTTP/2 configuration
    if config.enable_http2 {
        builder = builder.http2_prior_knowledge();
    } else {
        builder = builder.http1_only();
    }

    let client = builder.build()?;

    info!(
        "Secure HTTP client created - timeout: {}s, connect_timeout: {}s, max_redirects: {}",
        config.request_timeout.as_secs(),
        config.connect_timeout.as_secs(),
        config.max_redirects
    );

    Ok(client)
}

/// Create an HTTP client for internal/development use with relaxed security
pub fn create_development_client() -> Result<Client, Box<dyn std::error::Error + Send + Sync>> {
    warn!("Creating development HTTP client with relaxed security settings");

    let config = HttpClientConfig {
        verify_tls: false,
        request_timeout: std::time::Duration::from_secs(60), // Longer timeout for debugging
        ..Default::default()
    };

    create_secure_client_with_config(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_secure_client() {
        let client = create_secure_client();
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_create_development_client() {
        let client = create_development_client();
        assert!(client.is_ok());
    }
}
