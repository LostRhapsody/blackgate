//! # Authentication Module
//!
//! This module provides authentication functionality for HTTP requests in the blackgate application.
//! It supports multiple authentication types including API keys, Basic Auth, OAuth 2.0, JWT tokens, and OpenID Connect (OIDC).
//!
//! ## Supported Authentication Types
//!
//! - **API Key**: Simple header-based authentication using a pre-configured API key
//! - **Basic Auth**: HTTP Basic Authentication using username and password
//! - **OAuth 2.0**: Client credentials flow with automatic token caching and refresh
//! - **JWT**: JSON Web Token validation with configurable signing algorithms
//! - **OIDC**: OpenID Connect authentication with token introspection and discovery
//! - **None**: No authentication required
//!
//! ## Features
//!
//! - Thread-safe OAuth token caching to minimize redundant token requests
//! - Configurable JWT validation with support for various signing algorithms
//! - HTTP Basic Authentication with base64 encoding/decoding
//! - Comprehensive error handling with appropriate HTTP status codes
//! - Structured logging for authentication events and errors
//!
//! ## Usage
//!
//! The main entry point is the `apply_authentication` function, which takes a request builder
//! and route configuration, then applies the appropriate authentication method based on the
//! configured authentication type.
//!
//! ## Sub-modules
//!
//! - `types`: Authentication type definitions and enums
//! - `basic`: HTTP Basic Authentication utilities
//! - `oauth`: OAuth 2.0 client credentials implementation with token caching
//! - `jwt`: JWT token creation, validation, and configuration
//! - `oidc`: OpenID Connect authentication utilities

pub mod types;
pub mod basic;
pub mod oauth;
pub mod jwt;

#[allow(dead_code)]
pub mod oidc;

use std::sync::{Arc, Mutex};
use crate::routing::handlers::RouteConfig;
use basic::encode_basic_auth;
use oauth::{get_oauth_token, OAuthTokenCache};
use jwt::{create_jwt_config, validate_jwt_token};
use oidc::{create_oidc_config, fetch_oidc_discovery, validate_oidc_token};
use types::AuthType;
use tracing::{debug, error, info, warn};

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Apply authentication to a request builder based on the route configuration
pub async fn apply_authentication(
    builder: reqwest::RequestBuilder,
    route_config: &RouteConfig,
    path: &str,
    token_cache: Arc<Mutex<OAuthTokenCache>>,
    auth_header: Option<&str>,
) -> Result<reqwest::RequestBuilder, axum::response::Response> {
    match route_config.auth_type {
        AuthType::BasicAuth => {
            debug!("Using Basic Auth for route {}", path);

            // For Basic Auth, we expect auth_value to contain "username:password"
            if let Some(auth_value) = &route_config.auth_value {
                if let Some((username, password)) = auth_value.split_once(':') {
                    // Encode the credentials and add to Authorization header
                    let auth_header = encode_basic_auth(username, password);
                    debug!("Adding Basic Auth header for route {}", path);
                    Ok(builder.header("Authorization", auth_header))
                } else {
                    error!("Invalid Basic Auth format for route {}. Expected 'username:password'", path);
                    Err(axum::response::Response::builder()
                        .status(500)
                        .body(axum::body::Body::from("Invalid Basic Auth configuration"))
                        .unwrap())
                }
            } else {
                error!("Missing Basic Auth credentials for route {}", path);
                Err(axum::response::Response::builder()
                    .status(500)
                    .body(axum::body::Body::from("Basic Auth credentials are required"))
                    .unwrap())
            }
        }
        AuthType::ApiKey => {
            if let Some(auth_value) = &route_config.auth_value {
                debug!("Using API key authentication for route {}", path);
                Ok(builder.header("Authorization", auth_value))
            } else {
                error!("Missing API key for route {}", path);
                Err(axum::response::Response::builder()
                    .status(500)
                    .body(axum::body::Body::from("API key is required"))
                    .unwrap())
            }
        }
        AuthType::OAuth2 => {
            debug!("Using OAuth 2.0 authentication for route {}", path);
            // Check for required OAuth fields
            if let (
                Some(token_url),
                Some(client_id),
                Some(client_secret),
                Some(scope),
            ) = (
                &route_config.oauth_token_url,
                &route_config.oauth_client_id,
                &route_config.oauth_client_secret,
                &route_config.oauth_scope,
            ) {
                // Create a cache key for this specific OAuth configuration
                let cache_key =
                    format!("{}:{}:{}:{}", token_url, client_id, client_secret, scope);
                debug!("Using OAuth token cache key: {}", cache_key);

                // Try to get token from cache
                let token = {
                    let token_cache = token_cache.lock().unwrap();
                    token_cache.get_token(&cache_key)
                };

                let token = match token {
                    Some(token) => {
                        debug!("Using cached OAuth token for route {}", path);
                        token
                    }
                    None => {
                        info!("Fetching new OAuth token for route {}", path);
                        // No valid token in cache, fetch a new one
                        match get_oauth_token(token_url, client_id, client_secret, scope).await {
                            Ok((token, expires_in)) => {
                                info!("Successfully fetched OAuth token for route {}, expires in {}s", path, expires_in);
                                // Store the token in cache
                                let mut token_cache = token_cache.lock().unwrap();
                                token_cache.set_token(cache_key, token.clone(), expires_in);
                                token
                            }
                            Err(e) => {
                                error!("OAuth token error for route {}: {:?}", path, e);
                                return Err(axum::response::Response::builder()
                                    .status(500)
                                    .body(axum::body::Body::from(
                                        "OAuth authentication failed",
                                    ))
                                    .unwrap());
                            }
                        }
                    }
                };

                // Add the token to the request
                Ok(builder.header("Authorization", format!("Bearer {}", token)))
            } else {
                error!("Missing OAuth configuration for route {}", path);
                Err(axum::response::Response::builder()
                    .status(500)
                    .body(axum::body::Body::from("OAuth configuration is incomplete"))
                    .unwrap())
            }
        }
        AuthType::Jwt => {
            debug!("Using JWT authentication for route {}", path);

            // Create JWT configuration from route config
            let jwt_config = match create_jwt_config(route_config) {
                Ok(config) => config,
                Err(e) => {
                    error!("Invalid JWT configuration for route {}: {}", path, e);
                    return Err(axum::response::Response::builder()
                        .status(500)
                        .body(axum::body::Body::from(format!("JWT configuration error: {}", e)))
                        .unwrap());
                }
            };

            // Extract JWT token from Authorization header
            if let Some(auth_header_value) = auth_header {
                let token = if auth_header_value.starts_with("Bearer ") {
                    &auth_header_value[7..] // Remove "Bearer " prefix
                } else {
                    auth_header_value // Assume it's the raw JWT token
                };

                match validate_jwt_token(token, &jwt_config) {
                    Ok(claims) => {
                        debug!("JWT token validated for route {} with subject: {}", path, claims.sub);
                        // Forward the original token
                        Ok(builder.header("Authorization", auth_header_value))
                    }
                    Err(e) => {
                        warn!("JWT token validation failed for route {}: {}", path, e);
                        Err(axum::response::Response::builder()
                            .status(401)
                            .body(axum::body::Body::from("Invalid JWT token"))
                            .unwrap())
                    }
                }
            } else {
                // No token provided in Authorization header
                warn!("No JWT token provided in Authorization header for route {}", path);
                Err(axum::response::Response::builder()
                    .status(401)
                    .body(axum::body::Body::from("Authorization header required"))
                    .unwrap())
            }
        }
        AuthType::Oidc => {
            debug!("Using OIDC authentication for route {}", path);

            // Create OIDC configuration from route config
            let oidc_config = match create_oidc_config(route_config) {
                Ok(config) => config,
                Err(e) => {
                    error!("Invalid OIDC configuration for route {}: {}", path, e);
                    return Err(axum::response::Response::builder()
                        .status(500)
                        .body(axum::body::Body::from(format!("OIDC configuration error: {}", e)))
                        .unwrap());
                }
            };

            // Extract OIDC token from Authorization header
            if let Some(auth_header_value) = auth_header {
                let token = if auth_header_value.starts_with("Bearer ") {
                    &auth_header_value[7..] // Remove "Bearer " prefix
                } else {
                    auth_header_value // Assume it's the raw token
                };

                // Fetch discovery document
                let discovery = match fetch_oidc_discovery(oidc_config.issuer()).await {
                    Ok(doc) => doc,
                    Err(e) => {
                        error!("Failed to fetch OIDC discovery document for route {}: {}", path, e);
                        return Err(axum::response::Response::builder()
                            .status(500)
                            .body(axum::body::Body::from("OIDC discovery failed"))
                            .unwrap());
                    }
                };

                // Validate the token
                match validate_oidc_token(token, &oidc_config, &discovery).await {
                    Ok(()) => {
                        debug!("OIDC token validated successfully for route {}", path);
                        // Forward the original token
                        Ok(builder.header("Authorization", auth_header_value))
                    }
                    Err(e) => {
                        warn!("OIDC token validation failed for route {}: {}", path, e);
                        Err(axum::response::Response::builder()
                            .status(401)
                            .body(axum::body::Body::from("Invalid OIDC token"))
                            .unwrap())
                    }
                }
            } else {
                // No token provided in Authorization header
                warn!("No OIDC token provided in Authorization header for route {}", path);
                Err(axum::response::Response::builder()
                    .status(401)
                    .body(axum::body::Body::from("Authorization header required"))
                    .unwrap())
            }
        }
        AuthType::None => {
            debug!("No authentication required for route {}", path);
            Ok(builder)
        }
    }
}