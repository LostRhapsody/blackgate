//! # Metrics Module
//!
//! This module provides a struct for tracking and recording
//! request/response metrics in the blackgate application. It captures detailed
//! information about HTTP requests including timing, sizes, authentication,
//! and error handling.
//!
//! ## Features
//!
//! - **Request Tracking**: Records comprehensive metadata for each HTTP request
//! - **Performance Metrics**: Captures request duration and payload sizes
//! - **Authentication Logging**: Tracks the authentication method used
//! - **Error Handling**: Records error messages when requests fail
//! - **Upstream Integration**: Logs upstream service URLs when proxying requests
//!
//! ## Usage
//!
//! The primary structure `RequestMetrics` is designed to be created at the start
//! of a request and updated as the request progresses through the system.
//!
//! ```rust
//! use crate::metrics::RequestMetrics;
//!
//! // Create metrics for a new request
//! let mut metrics = RequestMetrics::new("/api/users".to_string(), "GET".to_string(), 0);
//!
//! // Complete the request with response data
//! metrics.complete_request(1024, 200, Some("http://backend".to_string()), "ApiKey".to_string());
//!
//! // Or record an error
//! metrics.set_error("Connection timeout".to_string());
//! ```
//!
//! ## Data Structure
//!
//! The `RequestMetrics` struct includes:
//! - Unique request identifier
//! - HTTP method and path
//! - Request/response timestamps and duration
//! - Payload sizes for both request and response
//! - HTTP status code
//! - Authentication type used
//! - Client information (IP, User-Agent)
//! - Upstream service URL (for proxied requests)
//! - Error messages (when applicable)

use crate::{auth::types::AuthType, database::queries};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tracing::{debug, error};
use uuid::Uuid;

///////////////////////////////////////////////////////////////////////////////
//****                         Public Structs                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Metrics data structure for tracking request/response information
/// TODO upadte metric's cache hit logic
#[derive(Debug, Serialize, Deserialize)]
pub struct RequestMetrics {
    pub id: String,
    pub path: String,
    pub method: String,
    pub request_timestamp: DateTime<Utc>,
    pub response_timestamp: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub request_size_bytes: i64,
    pub response_size_bytes: Option<i64>,
    pub response_status_code: Option<u16>,
    pub upstream_url: Option<String>,
    pub auth_type: String,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub cache_hit: bool,
    pub error_message: Option<String>,
}

impl RequestMetrics {
    pub fn new(path: String, method: String, request_size: i64) -> Self {
        RequestMetrics {
            id: Uuid::new_v4().to_string(),
            path,
            method,
            request_timestamp: Utc::now(),
            response_timestamp: None,
            duration_ms: None,
            request_size_bytes: request_size,
            response_size_bytes: None,
            response_status_code: None,
            upstream_url: None,
            auth_type: AuthType::None.to_string().to_string(),
            client_ip: None,
            user_agent: None,
            cache_hit: false,
            error_message: None,
        }
    }

    pub fn complete_request(
        &mut self,
        response_size: i64,
        status_code: u16,
        upstream_url: Option<String>,
        auth_type: String,
    ) {
        let now = Utc::now();
        self.response_timestamp = Some(now);
        self.duration_ms = Some((now - self.request_timestamp).num_milliseconds());
        self.response_size_bytes = Some(response_size);
        self.response_status_code = Some(status_code);
        self.upstream_url = upstream_url;
        self.auth_type = auth_type;
    }

    pub fn set_error(&mut self, error: String) {
        let now = Utc::now();
        self.response_timestamp = Some(now);
        self.duration_ms = Some((now - self.request_timestamp).num_milliseconds());
        self.error_message = Some(error);
    }
}

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Store request metrics in the database asynchronously without blocking the request
pub fn store_metrics(pool: SqlitePool, metrics: RequestMetrics) {
    tokio::spawn(async move {
        let response_timestamp_str = metrics.response_timestamp.map(|t| t.to_rfc3339());
        let result = queries::store_request_metrics(
            &pool,
            &metrics.id,
            &metrics.path,
            &metrics.method,
            &metrics.request_timestamp.to_rfc3339(),
            response_timestamp_str.as_deref(),
            metrics.duration_ms,
            metrics.request_size_bytes,
            metrics.response_size_bytes,
            metrics.response_status_code,
            metrics.upstream_url.as_deref().unwrap_or(""),
            &metrics.auth_type,
            metrics.client_ip.as_deref().unwrap_or(""),
            metrics.user_agent.as_deref().unwrap_or(""),
            metrics.error_message.as_deref(),
        )
        .await;

        if let Err(e) = result {
            error!("Failed to store metrics: {}", e);
        } else {
            debug!("Stored metrics for request {}", metrics.id);
        }
    });
}

///////////////////////////////////////////////////////////////////////////////
//****                              Tests                                ****//
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::types::AuthType;

    #[test]
    fn test_request_metrics() {
        let mut metrics = RequestMetrics::new("/test".to_string(), "GET".to_string(), 100);
        assert_eq!(metrics.path, "/test");
        assert_eq!(metrics.method, "GET");
        assert_eq!(metrics.request_size_bytes, 100);
        assert!(metrics.request_timestamp <= Utc::now());

        metrics.complete_request(
            200,
            200,
            Some("http://upstream".to_string()),
            AuthType::ApiKey.to_string().to_string(),
        );
        assert!(metrics.response_timestamp.is_some());
        assert!(metrics.duration_ms.is_some());
        assert_eq!(metrics.response_size_bytes.unwrap(), 200);
        assert_eq!(metrics.response_status_code.unwrap(), 200);
        assert_eq!(metrics.upstream_url.as_deref(), Some("http://upstream"));
        assert_eq!(metrics.auth_type, AuthType::ApiKey.to_string());
    }
}
