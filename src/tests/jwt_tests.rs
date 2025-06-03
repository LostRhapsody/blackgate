#[cfg(test)]
mod jwt_tests {
    use crate::{JwtClaims, JwtConfig, validate_jwt_token, create_jwt_config};
    use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
    use std::collections::HashMap;
    use serde_json;

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
        custom_claims.insert("role".to_string(), serde_json::Value::String("admin".to_string()));
        custom_claims.insert("permissions".to_string(), serde_json::Value::Array(vec![
            serde_json::Value::String("read".to_string()),
            serde_json::Value::String("write".to_string()),
        ]));

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
    }    #[test]
    fn test_jwt_config_creation() {
        // Create a test RouteConfig with JWT settings
        let route_config = crate::RouteConfig {
            upstream: "http://test.example.com".to_string(),
            auth_type: crate::AuthType::Jwt,
            auth_value: None,
            oauth_token_url: None,
            oauth_client_id: None,
            oauth_client_secret: None,
            oauth_scope: None,
            jwt_secret: Some("secret123".to_string()),
            jwt_algorithm: Some("HS256".to_string()),
            jwt_issuer: Some("blackgate".to_string()),
            jwt_audience: Some("api".to_string()),
            jwt_required_claims: Some("role,permissions".to_string()),
        };

        let config = create_jwt_config(&route_config);
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
        let route_config = crate::RouteConfig {
            upstream: "http://test.example.com".to_string(),
            auth_type: crate::AuthType::Jwt,
            auth_value: None,
            oauth_token_url: None,
            oauth_client_id: None,
            oauth_client_secret: None,
            oauth_scope: None,
            jwt_secret: Some("secret123".to_string()),
            jwt_algorithm: Some("INVALID".to_string()),
            jwt_issuer: None,
            jwt_audience: None,
            jwt_required_claims: None,
        };

        let config = create_jwt_config(&route_config);
        assert!(config.is_err());
    }

    #[test]
    fn test_jwt_config_creation_with_missing_secret() {
        let route_config = crate::RouteConfig {
            upstream: "http://test.example.com".to_string(),
            auth_type: crate::AuthType::Jwt,
            auth_value: None,
            oauth_token_url: None,
            oauth_client_id: None,
            oauth_client_secret: None,
            oauth_scope: None,
            jwt_secret: None, // Missing secret
            jwt_algorithm: Some("HS256".to_string()),
            jwt_issuer: None,
            jwt_audience: None,
            jwt_required_claims: None,
        };

        let config = create_jwt_config(&route_config);
        assert!(config.is_err());
    }

    #[test]
    fn test_validate_jwt_token_success() {
        let secret = "test_secret_key";
        let token = create_test_jwt(secret, Algorithm::HS256, Some("blackgate"), Some("api"), None);
        
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
        custom_claims.insert("role".to_string(), serde_json::Value::String("user".to_string()));
        
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
        custom_claims.insert("role".to_string(), serde_json::Value::String("admin".to_string()));
        custom_claims.insert("permissions".to_string(), serde_json::Value::Array(vec![
            serde_json::Value::String("read".to_string()),
            serde_json::Value::String("write".to_string()),
        ]));
        
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
}
