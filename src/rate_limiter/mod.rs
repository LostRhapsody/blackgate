
//! # Rate Limiter Module
//! 
//! This module provides rate limiting functionality for HTTP requests based on configurable
//! per-minute and per-hour limits. It tracks request timestamps for different keys (typically
//! request paths) and enforces sliding window rate limits.
//! 
//! ## Features
//! 
//! - **Sliding Window Rate Limiting**: Uses actual request timestamps rather than fixed time buckets
//! - **Dual Rate Limits**: Supports both per-minute and per-hour rate limiting simultaneously
//! - **Path-based Limiting**: Rate limits are applied per request path
//! - **Memory Management**: Automatically cleans up old request records to prevent memory leaks
//! - **Integration Ready**: Designed to work with Axum web framework and returns appropriate HTTP responses
//! 
//! ## Usage
//! 
//! The main entry point is the `check_rate_limit` function which should be called before
//! processing requests. It returns `Ok(())` if the request is allowed or an HTTP 429 response
//! if rate limits are exceeded.
//! 
//! ## Rate Limiting Strategy
//! 
//! - Requests are tracked using timestamps stored in a HashMap
//! - Old entries (> 1 hour) are automatically cleaned up on each check
//! - Both minute and hour limits are checked independently
//! - If either limit is exceeded, the request is rejected with HTTP 429
//! 
//! ## Thread Safety
//! 
//! The `RateLimiter` struct is designed to be used behind an `Arc<Mutex<>>` for thread-safe
//! access in concurrent environments.

use crate::RequestMetrics;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, Instant};
use std::collections::HashMap;
use tracing::{debug, warn};

///////////////////////////////////////////////////////////////////////////////
//****                         Public Structs                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Rate limiting structure to track requests per client/route
pub struct RateLimiter {
    requests: HashMap<String, Vec<Instant>>, // key -> timestamps of requests
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    /// Check if request is allowed based on rate limits
    /// Returns true if allowed, false if rate limited
    fn is_allowed(&mut self, key: &str, requests_per_minute: u32, requests_per_hour: u32) -> bool {
        let now = Instant::now();

        // Clean up old entries and get current requests for this key
        let requests = self.requests.entry(key.to_string()).or_insert_with(Vec::new);

        // Remove requests older than 1 hour
        requests.retain(|&timestamp| now.duration_since(timestamp) < Duration::from_secs(3600));

        // Check hourly limit
        if requests.len() >= requests_per_hour as usize {
            debug!("Rate limit exceeded for key: {} (hourly limit: {})", key, requests_per_hour);
            return false;
        }

        // Check minute limit - count requests in the last minute
        let minute_requests = requests.iter()
            .filter(|&&timestamp| now.duration_since(timestamp) < Duration::from_secs(60))
            .count();

        if minute_requests >= requests_per_minute as usize {
            debug!("Rate limit exceeded for key: {} (minute limit: {})", key, requests_per_minute);
            return false;
        }

        // Add this request
        requests.push(now);
        true
    }
}

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Check rate limits for a request
/// Returns Ok(()) if allowed, Err(response) if rate limited
pub async fn check_rate_limit(
    path: &str,
    rate_limit_per_minute: i64,
    rate_limit_per_hour: i64,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    metrics: &mut RequestMetrics,
) -> Result<(), axum::response::Response> {
    // Use path as the rate limiting key
    // In production, you might want to use client IP or user ID instead
    let rate_limit_key = format!("path:{}", path);

    // Check rate limits
    let rate_limit_exceeded = {
        let mut rate_limiter = rate_limiter.lock().unwrap();
        !rate_limiter.is_allowed(&rate_limit_key, rate_limit_per_minute as u32, rate_limit_per_hour as u32)
    };

    if rate_limit_exceeded {
        warn!(
            request_id = %metrics.id,
            path = %path,
            rate_limit_per_minute = rate_limit_per_minute,
            rate_limit_per_hour = rate_limit_per_hour,
            "Rate limit exceeded"
        );

        metrics.set_error("Rate limit exceeded".to_string());

        return Err(axum::response::Response::builder()
            .status(429)
            .header("Retry-After", "60") // Tell client to retry after 60 seconds
            .body(axum::body::Body::from("Too Many Requests"))
            .unwrap());
    }

    debug!(
        request_id = %metrics.id,
        path = %path,
        rate_limit_per_minute = rate_limit_per_minute,
        rate_limit_per_hour = rate_limit_per_hour,
        "Rate limit check passed"
    );

    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
//****                              Tests                                ****//
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RequestMetrics;
    use std::sync::{Mutex, Arc};

    #[tokio::test]
    async fn test_rate_limiter() {
        let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));
        let mut metrics = RequestMetrics::new(
            "/test".to_string(),
            "GET".to_string(),
            0,
        );

        // First two requests should pass
        assert!(check_rate_limit("/test", 2, 100, rate_limiter.clone(), &mut metrics).await.is_ok(), "First request should pass rate limit check");
        assert!(check_rate_limit("/test", 2, 100, rate_limiter.clone(), &mut metrics).await.is_ok(), "2nd request should pass rate limit check");

        // 3rd request should be rate limited
        assert!(check_rate_limit("/test", 2, 100, rate_limiter.clone(), &mut metrics).await.is_err(), "3rd request should be rate limited");

        // Wait for a minute and try again
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert!(check_rate_limit("/test", 2, 100, rate_limiter.clone(), &mut metrics).await.is_ok(), "Request should pass rate limit check after waiting");
    }
}