//! JWT (JSON Web Token) authentication module for Blackgate
//!
//! This module provides JWT token validation and configuration
//! for the Blackgate API gateway.
//!
//! # Supported Features
//!
//! - **Algorithms**: HS256, HS384, HS512 (HMAC-based symmetric key algorithms)
//! - **Standard Claims**: subject (sub), expiration (exp), issued at (iat), issuer (iss), audience (aud)
//! - **Custom Claims**: Arbitrary JSON values with flattened serialization support
//! - **Validation**: Configurable issuer, audience, and required custom claims validation
//! - **Configuration**: Route-based configuration with sensible defaults
//!
//! # Example Usage
//!
//! ```rust
//! use blackgate::auth::jwt::{create_jwt_config, validate_jwt_token};
//! use blackgate::RouteConfig;
//!
//! // Create JWT configuration from route config
//! let jwt_config = create_jwt_config(&route_config)?;
//!
//! // Validate incoming JWT token
//! let claims = validate_jwt_token(&token, &jwt_config)?;
//! println!("Authenticated user: {}", claims.sub);
//! ```
//!
//! # Security Considerations
//!
//! - Only HMAC algorithms are currently supported for security and simplicity
//! - JWT secrets should be cryptographically strong and kept secure
//! - Token expiration is enforced automatically
//! - Custom claims validation helps enforce application-specific authorization rules

use crate::routing::handlers::RouteConfig;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

///////////////////////////////////////////////////////////////////////////////
//****                         Public Structs                            ****//
///////////////////////////////////////////////////////////////////////////////

/// JWT Claims structure for token validation
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,     // Subject (user identifier)
    exp: usize,          // Expiration time (as UTC timestamp)
    iat: usize,          // Issued at (as UTC timestamp)
    iss: Option<String>, // Issuer
    aud: Option<String>, // Audience
    // Custom claims can be added here
    #[serde(flatten)]
    custom: HashMap<String, serde_json::Value>,
}

/// JWT Configuration structure
#[derive(Debug, Clone)]
pub struct JwtConfig {
    secret: String,
    algorithm: Algorithm,
    issuer: Option<String>,
    audience: Option<String>,
    required_claims: Vec<String>,
}

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Validate JWT token and extract claims
pub fn validate_jwt_token(
    token: &str,
    jwt_config: &JwtConfig,
) -> Result<JwtClaims, Box<dyn std::error::Error + Send + Sync>> {
    // Parse algorithm
    let algorithm = match jwt_config.algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => jwt_config.algorithm,
        _ => {
            return Err("Unsupported JWT algorithm. Only HMAC algorithms (HS256, HS384, HS512) are currently supported.".into());
        }
    };

    // Create validation
    let mut validation = Validation::new(algorithm);

    // Set issuer validation if provided
    if let Some(ref issuer) = jwt_config.issuer {
        validation.iss = Some(std::collections::HashSet::from([issuer.clone()]));
    }

    // Set audience validation if provided
    if let Some(ref audience) = jwt_config.audience {
        validation.aud = Some(std::collections::HashSet::from([audience.clone()]));
    }

    // Create decoding key
    let decoding_key = DecodingKey::from_secret(jwt_config.secret.as_ref());

    // Decode and validate token
    let token_data = decode::<JwtClaims>(token, &decoding_key, &validation)?;
    let claims = token_data.claims;

    let check_claims =
        !jwt_config.required_claims.is_empty() && !jwt_config.required_claims[0].is_empty();

    // Validate required claims if specified
    if check_claims {
        for required_claim in &jwt_config.required_claims {
            if !claims.custom.contains_key(required_claim) {
                return Err(format!("Missing required claim: {}", required_claim).into());
            }
        }
    }

    debug!(
        "JWT token validated successfully for subject: {}",
        claims.sub
    );
    Ok(claims)
}

/// Create JWT configuration from route config
pub fn create_jwt_config(route_config: &RouteConfig) -> Result<JwtConfig, String> {
    let secret = route_config
        .jwt_secret
        .as_ref()
        .ok_or("JWT secret is required")?;

    let algorithm = match route_config.jwt_algorithm.as_deref().unwrap_or("HS256") {
        "HS256" => Algorithm::HS256,
        "HS384" => Algorithm::HS384,
        "HS512" => Algorithm::HS512,
        alg => return Err(format!("Unsupported JWT algorithm: {}", alg)),
    };

    let required_claims = route_config
        .jwt_required_claims
        .as_ref()
        .map(|claims| claims.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    Ok(JwtConfig {
        secret: secret.clone(),
        algorithm,
        issuer: route_config.jwt_issuer.clone(),
        audience: route_config.jwt_audience.clone(),
        required_claims,
    })
}

///////////////////////////////////////////////////////////////////////////////
//****                              Tests                                ****//
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use assert_cmd::Command;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json;
    use std::collections::HashMap;
    use tokio::runtime::Runtime;
    use tracing::info;

    // Helper function to create a test JWT token
    fn create_test_jwt(
        secret: &str,
        algorithm: Algorithm,
        issuer: Option<&str>,
        audience: Option<&str>,
        custom_claims: Option<HashMap<String, serde_json::Value>>,
    ) -> String {
        let claims = JwtClaims {
            sub: "test_user".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iat: chrono::Utc::now().timestamp() as usize,
            iss: issuer.map(|s| s.to_string()),
            aud: audience.map(|s| s.to_string()),
            custom: custom_claims.unwrap_or_default(),
        };

        let header = Header::new(algorithm);
        let encoding_key = EncodingKey::from_secret(secret.as_ref());

        encode(&header, &claims, &encoding_key).unwrap()
    }

    #[test]
    fn test_jwt_claims_serialization() {
        let mut custom_claims = HashMap::new();
        custom_claims.insert(
            "role".to_string(),
            serde_json::Value::String("admin".to_string()),
        );
        custom_claims.insert(
            "permissions".to_string(),
            serde_json::Value::Array(vec![
                serde_json::Value::String("read".to_string()),
                serde_json::Value::String("write".to_string()),
            ]),
        );

        let claims = JwtClaims {
            sub: "user123".to_string(),
            exp: 1234567890,
            iat: 1234567800,
            iss: Some("blackgate".to_string()),
            aud: Some("api".to_string()),
            custom: custom_claims,
        };

        // Test serialization
        let serialized = serde_json::to_string(&claims).unwrap();
        assert!(serialized.contains("user123"));
        assert!(serialized.contains("blackgate"));
        assert!(serialized.contains("admin"));
    }

    #[test]
    fn test_jwt_config_creation() {
        // Create a test RouteConfig with JWT settings
        let _route_config = RouteConfig::default();

        let config = create_jwt_config(&_route_config);
        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.secret, "secret123");
        assert_eq!(config.algorithm, Algorithm::HS256);
        assert_eq!(config.issuer, Some("blackgate".to_string()));
        assert_eq!(config.audience, Some("api".to_string()));
        assert_eq!(config.required_claims, vec!["role", "permissions"]);
    }

    #[test]
    fn test_jwt_config_creation_with_invalid_algorithm() {
        let _route_config = RouteConfig::default();

        let config = create_jwt_config(&_route_config);
        assert!(config.is_err());
    }

    #[test]
    fn test_jwt_config_creation_with_missing_secret() {
        let _route_config = RouteConfig::default();

        let config = create_jwt_config(&_route_config);
        assert!(config.is_err());
    }

    #[test]
    fn test_validate_jwt_token_success() {
        let secret = "test_secret_key";
        let token = create_test_jwt(
            secret,
            Algorithm::HS256,
            Some("blackgate"),
            Some("api"),
            None,
        );

        let config = JwtConfig {
            secret: secret.to_string(),
            algorithm: Algorithm::HS256,
            issuer: Some("blackgate".to_string()),
            audience: Some("api".to_string()),
            required_claims: vec![],
        };

        let result = validate_jwt_token(&token, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_jwt_token_invalid_secret() {
        let token = create_test_jwt("correct_secret", Algorithm::HS256, None, None, None);

        let config = JwtConfig {
            secret: "wrong_secret".to_string(),
            algorithm: Algorithm::HS256,
            issuer: None,
            audience: None,
            required_claims: vec![],
        };

        let result = validate_jwt_token(&token, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_jwt_token_issuer_mismatch() {
        let secret = "test_secret";
        let token = create_test_jwt(secret, Algorithm::HS256, Some("wrong_issuer"), None, None);

        let config = JwtConfig {
            secret: secret.to_string(),
            algorithm: Algorithm::HS256,
            issuer: Some("expected_issuer".to_string()),
            audience: None,
            required_claims: vec![],
        };

        let result = validate_jwt_token(&token, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_jwt_token_audience_mismatch() {
        let secret = "test_secret";
        let token = create_test_jwt(secret, Algorithm::HS256, None, Some("wrong_audience"), None);

        let config = JwtConfig {
            secret: secret.to_string(),
            algorithm: Algorithm::HS256,
            issuer: None,
            audience: Some("expected_audience".to_string()),
            required_claims: vec![],
        };

        let result = validate_jwt_token(&token, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_jwt_token_missing_required_claims() {
        let secret = "test_secret";
        let mut custom_claims = HashMap::new();
        custom_claims.insert(
            "role".to_string(),
            serde_json::Value::String("user".to_string()),
        );

        let token = create_test_jwt(secret, Algorithm::HS256, None, None, Some(custom_claims));

        let config = JwtConfig {
            secret: secret.to_string(),
            algorithm: Algorithm::HS256,
            issuer: None,
            audience: None,
            required_claims: vec!["role".to_string(), "permissions".to_string()],
        };

        let result = validate_jwt_token(&token, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_jwt_token_with_all_required_claims() {
        let secret = "test_secret";
        let mut custom_claims = HashMap::new();
        custom_claims.insert(
            "role".to_string(),
            serde_json::Value::String("admin".to_string()),
        );
        custom_claims.insert(
            "permissions".to_string(),
            serde_json::Value::Array(vec![
                serde_json::Value::String("read".to_string()),
                serde_json::Value::String("write".to_string()),
            ]),
        );

        let token = create_test_jwt(secret, Algorithm::HS256, None, None, Some(custom_claims));

        let config = JwtConfig {
            secret: secret.to_string(),
            algorithm: Algorithm::HS256,
            issuer: None,
            audience: None,
            required_claims: vec!["role".to_string(), "permissions".to_string()],
        };

        let result = validate_jwt_token(&token, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_different_algorithms() {
        let secret = "test_secret_key_with_sufficient_length_for_hs512";

        // Test HS256
        let token_hs256 = create_test_jwt(secret, Algorithm::HS256, None, None, None);
        let config_hs256 = JwtConfig {
            secret: secret.to_string(),
            algorithm: Algorithm::HS256,
            issuer: None,
            audience: None,
            required_claims: vec![],
        };
        assert!(validate_jwt_token(&token_hs256, &config_hs256).is_ok());

        // Test HS384
        let token_hs384 = create_test_jwt(secret, Algorithm::HS384, None, None, None);
        let config_hs384 = JwtConfig {
            secret: secret.to_string(),
            algorithm: Algorithm::HS384,
            issuer: None,
            audience: None,
            required_claims: vec![],
        };
        assert!(validate_jwt_token(&token_hs384, &config_hs384).is_ok());

        // Test HS512
        let token_hs512 = create_test_jwt(secret, Algorithm::HS512, None, None, None);
        let config_hs512 = JwtConfig {
            secret: secret.to_string(),
            algorithm: Algorithm::HS512,
            issuer: None,
            audience: None,
            required_claims: vec![],
        };
        assert!(validate_jwt_token(&token_hs512, &config_hs512).is_ok());
    }

    #[test]
    fn test_algorithm_mismatch() {
        let secret = "test_secret_key";
        let token = create_test_jwt(secret, Algorithm::HS256, None, None, None);

        let config = JwtConfig {
            secret: secret.to_string(),
            algorithm: Algorithm::HS384, // Different algorithm
            issuer: None,
            audience: None,
            required_claims: vec![],
        };

        let result = validate_jwt_token(&token, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_expired_token() {
        let secret = "test_secret";
        let claims = JwtClaims {
            sub: "test_user".to_string(),
            exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp() as usize, // Expired
            iat: (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp() as usize,
            iss: None,
            aud: None,
            custom: HashMap::new(),
        };

        let header = Header::new(Algorithm::HS256);
        let encoding_key = EncodingKey::from_secret(secret.as_ref());
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let config = JwtConfig {
            secret: secret.to_string(),
            algorithm: Algorithm::HS256,
            issuer: None,
            audience: None,
            required_claims: vec![],
        };

        let result = validate_jwt_token(&token, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_sending_jwt_request_no_claim() {
        let secret = "test_secret";
        let token = create_test_jwt(secret, Algorithm::HS256, None, None, None);

        let config = JwtConfig {
            secret: secret.to_string(),
            algorithm: Algorithm::HS256,
            issuer: None,
            audience: None,
            required_claims: vec![],
        };

        let result = validate_jwt_token(&token, &config);
        assert!(result.is_ok());

        let mut cmd = Command::cargo_bin("blackgate").unwrap();
        cmd.arg("add-route")
            .arg("--path")
            .arg("/jwt_test")
            .arg("--upstream")
            .arg("http://localhost:9999")
            .arg("--auth-type")
            .arg("jwt")
            .arg("--jwt-secret")
            .arg(secret)
            .arg("--jwt-algorithm")
            .arg("HS256")
            .arg("--allowed-methods")
            .arg("POST");
        let _ = cmd.output();

        // Start test upstream server
        let rt = Runtime::new().unwrap();
        let client = reqwest::Client::new();
        // Attach the JWT token to the Authorization header as a Bearer token
        let builder = client
            .request(reqwest::Method::POST, "http://localhost:3000/jwt_test")
            .bearer_auth(&token)
            .json(&serde_json::json!({"payload": "hello"}));
        let res = rt.block_on(builder.send());
        let res = res.unwrap();
        info!("Response status: {}", res.status());
        assert!(res.status() != 401);
        info!("Response text: {} ", rt.block_on(res.text()).unwrap());
    }

    #[test]
    fn test_sending_jwt_request_with_claim() {
        let secret = "test_secret";
        let mut custom_claims = HashMap::new();
        custom_claims.insert(
            "role".to_string(),
            serde_json::Value::String("admin".to_string()),
        );

        let token = create_test_jwt(secret, Algorithm::HS256, None, None, Some(custom_claims));

        let config = JwtConfig {
            secret: secret.to_string(),
            algorithm: Algorithm::HS256,
            issuer: None,
            audience: None,
            required_claims: vec!["role".to_string()],
        };

        let result = validate_jwt_token(&token, &config);
        assert!(result.is_ok());

        let mut cmd = Command::cargo_bin("blackgate").unwrap();
        cmd.arg("add-route")
            .arg("--path")
            .arg("/jwt_test")
            .arg("--upstream")
            .arg("http://localhost:9999")
            .arg("--auth-type")
            .arg("jwt")
            .arg("--jwt-secret")
            .arg(secret)
            .arg("--jwt-algorithm")
            .arg("HS256")
            .arg("--jwt-required-claims")
            .arg("role")
            .arg("--allowed-methods")
            .arg("POST");
        let _ = cmd.output();

        // Start test upstream server
        let rt = Runtime::new().unwrap();
        let client = reqwest::Client::new();
        // Attach the JWT token to the Authorization header as a Bearer token
        let builder = client
            .request(reqwest::Method::POST, "http://localhost:3000/jwt_test")
            .bearer_auth(&token)
            .json(&serde_json::json!({"payload": "hello"}));
        let res = rt.block_on(builder.send());
        let res = res.unwrap();
        info!("Response status: {}", res.status());
        assert!(res.status() != 401);
        info!("Response text: {} ", rt.block_on(res.text()).unwrap());

        cmd.arg("remove-route").arg("/jwt_test");
        let _ = cmd.output();
    }
}
