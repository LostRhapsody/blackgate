pub mod types;
pub mod oauth;
pub mod jwt;
pub mod oidc;

use std::sync::{Arc, Mutex};
use crate::RouteConfig;
use oauth::{get_oauth_token, OAuthTokenCache};
use jwt::{create_jwt_config, validate_jwt_token};
use types::AuthType;
use tracing::{debug, error, info, warn};

/// Apply authentication to a request builder based on the route configuration
pub async fn apply_authentication(
    builder: reqwest::RequestBuilder,
    route_config: &RouteConfig,
    path: &str,
    token_cache: Arc<Mutex<OAuthTokenCache>>,
) -> Result<reqwest::RequestBuilder, axum::response::Response> {
    match route_config.auth_type {
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

            // TODO - update this to extact the JWT token from headers or query params
            if let Some(auth_value) = &route_config.auth_value {
                // If auth_value contains a JWT token, validate it
                let token = if auth_value.starts_with("Bearer ") {
                    &auth_value[7..] // Remove "Bearer " prefix
                } else {
                    auth_value // Assume it's the raw JWT token
                };

                match validate_jwt_token(token, &jwt_config) {
                    Ok(claims) => {
                        debug!("JWT token validated for route {} with subject: {}", path, claims.sub);
                        // Forward the original token
                        Ok(builder.header("Authorization", auth_value))
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
                // No token provided - this might be acceptable if JWT validation happens upstream
                debug!("No JWT token provided for route {}, forwarding request without token", path);
                Ok(builder)
            }
        }
        AuthType::Oidc => {
            // OIDC authentication logic would go here
            debug!("Using OIDC authentication for route {}", path);
            // For now, just return the builder without modification
            Ok(builder)
        }
        AuthType::None => {
            debug!("No authentication required for route {}", path);
            Ok(builder)
        }
    }
}