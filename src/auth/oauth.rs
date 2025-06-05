
//! OAuth token management module
//! 
//! This module provides OAuth token management with caching.
//! It includes structures and functions for:
//! - Caching OAuth tokens with automatic expiration handling
//! - Making OAuth token requests using the client credentials grant type
//! - Managing token lifecycles and validation
//! 
//! The module supports OAuth 2.0 client credentials flow and provides an in-memory
//! token cache to avoid unnecessary token requests for unexpired tokens.
//! 
//! # Example
//! 
//! ```rust
//! use crate::auth::oauth::{OAuthTokenCache, get_oauth_token};
//! 
//! let mut cache = OAuthTokenCache::new();
//! 
//! // Get a new token
//! let (token, expires_in) = get_oauth_token(
//!     "https://auth.example.com/token",
//!     "client_id",
//!     "client_secret", 
//!     "read write"
//! ).await?;
//! 
//! // Cache the token
//! cache.set_token("api_key".to_string(), token, expires_in);
//! 
//! // Retrieve from cache
//! if let Some(cached_token) = cache.get_token("api_key") {
//!     // Use cached token
//! }
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

///////////////////////////////////////////////////////////////////////////////
//****                         Public Structs                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Structure to store OAuth tokens with expiration
pub struct OAuthTokenCache {
    tokens: HashMap<String, (String, Instant)>,
}

impl OAuthTokenCache {
    /// Create a new OAuth token cache
    pub fn new() -> Self {
        OAuthTokenCache {
            tokens: HashMap::new(),
        }
    }

    /// Get a token from the cache if it is still valid
    pub fn get_token(&self, key: &str) -> Option<String> {
        if let Some((token, expiry)) = self.tokens.get(key) {
            if Instant::now() < *expiry {
                return Some(token.clone());
            }
        }
        None
    }

    /// Set a token in the cache with an expiration time
    pub fn set_token(&mut self, key: String, token: String, expires_in: u64) {
        let expiry = Instant::now() + Duration::from_secs(expires_in);
        self.tokens.insert(key, (token, expiry));
    }
}

///////////////////////////////////////////////////////////////////////////////
//****                        Private Structs                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Token request structure for OAuth
#[derive(Serialize)]
struct OAuthTokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    scope: String,
}

// Response structure for OAuth token
#[derive(Deserialize, Debug)]
struct OAuthTokenResponse {
    access_token: String,
    expires_in: Option<u64>,
    // Other fields may be present but we don't need them for now
}

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Get OAuth token from token endpoint
pub async fn get_oauth_token(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    scope: &str,
) -> Result<(String, u64), Box<dyn std::error::Error + Send + Sync>> {
    info!("Requesting OAuth token from {}", token_url);
    let client = reqwest::Client::builder().use_rustls_tls().build()?;
    let request_body = OAuthTokenRequest {
        grant_type: "client_credentials".into(),
        client_id: client_id.into(),
        client_secret: client_secret.into(),
        scope: scope.into(),
    };

    // Send the request and log the response
    let response = client
        .post(token_url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_string(&request_body)?)
        .send()
        .await;

    match response {
        Ok(resp) => {
            let token_response: OAuthTokenResponse = resp.json::<OAuthTokenResponse>().await?;
            let expires_in = token_response.expires_in.unwrap_or(3600); // Default to 1 hour
            debug!("Successfully received OAuth token, expires in {}s", expires_in);
            Ok((token_response.access_token, expires_in))
        }
        Err(e) => {
            error!("OAuth token request failed: {}", e);
            Err(format!("OAuth token request failed: {}", e).into())
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
//****                              Tests                                ****//
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod test {
    use reqwest::Client;
    use tokio::runtime::Runtime;
    
    /// Test the OAuth 2.0 client credentials flow
    #[test]
    fn test_oauth_client_credentials_flow() {
        
        // Create a runtime for making async HTTP requests
        let rt = Runtime::new().unwrap();
        
        // First test: try accessing the OAuth info endpoint directly
        let client = Client::new();
        let info_response = rt.block_on(async {
            client.get("http://localhost:3001/oauth/info")
                .send()
                .await
        });
        
        // Ensure the OAuth test server is running
        assert!(info_response.is_ok(), "OAuth test server should be running");
        
        if let Ok(response) = info_response {
            assert_eq!(response.status().as_u16(), 200);
            let text = rt.block_on(async { response.text().await.unwrap_or_default() });
            assert!(text.contains("OAuth 2.0 Test Server - Info Endpoint"));
        }

        // Second test: try accessing a protected route through the gateway
        // test the protected route via the gateway
        let gateway_response = rt.block_on(async {
            client.get("http://localhost:3000/oauth-test")
                .send()
                .await
        });
        
        // Validate the response
        if let Ok(response) = gateway_response {
            assert_eq!(response.status().as_u16(), 200, "Expected 200 OK from gateway");        
        } else {
            panic!("Failed to get a response from the gateway");
        }
    }
}