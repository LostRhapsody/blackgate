use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Errors that can occur during security operations
#[derive(Debug)]
pub enum SecurityError {
    InfisicalError(String),
    NetworkError(String),
    AuthenticationError(String),
    CacheError(String),
    SerializationError(String),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::InfisicalError(msg) => write!(f, "Infisical error: {}", msg),
            SecurityError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            SecurityError::AuthenticationError(msg) => write!(f, "Authentication error: {}", msg),
            SecurityError::CacheError(msg) => write!(f, "Cache error: {}", msg),
            SecurityError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for SecurityError {}

/// Reference to a secret stored in Infisical
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SecretReference {
    pub key: String,
    pub project_id: String,
    pub environment: String,
    pub created_at: DateTime<Utc>,
}

impl SecretReference {
    pub fn new(key: String, project_id: String, environment: String) -> Self {
        Self {
            key,
            project_id,
            environment,
            created_at: Utc::now(),
        }
    }

    /// Generate a unique identifier for this secret reference
    pub fn to_reference_string(&self) -> String {
        format!("infisical://{}:{}/{}", self.project_id, self.environment, self.key)
    }

    /// Parse a reference string back into a SecretReference
    pub fn from_reference_string(reference: &str) -> Result<Self, SecurityError> {
        if !reference.starts_with("infisical://") {
            return Err(SecurityError::SerializationError(
                "Invalid reference format".to_string(),
            ));
        }

        let parts: Vec<&str> = reference
            .strip_prefix("infisical://")
            .unwrap()
            .split('/')
            .collect();

        if parts.len() != 2 {
            return Err(SecurityError::SerializationError(
                "Invalid reference format".to_string(),
            ));
        }

        let project_env: Vec<&str> = parts[0].split(':').collect();
        if project_env.len() != 2 {
            return Err(SecurityError::SerializationError(
                "Invalid project:environment format".to_string(),
            ));
        }

        Ok(Self {
            key: parts[1].to_string(),
            project_id: project_env[0].to_string(),
            environment: project_env[1].to_string(),
            created_at: Utc::now(),
        })
    }
}

/// Cached secret value with metadata
#[derive(Debug, Clone)]
pub struct SecretValue {
    pub value: String,
    pub cached_at: DateTime<Utc>,
    pub ttl_seconds: u64,
}

impl SecretValue {
    pub fn new(value: String) -> Self {
        Self {
            value,
            cached_at: Utc::now(),
            ttl_seconds: 300, // 5 minutes default TTL
        }
    }

    pub fn with_ttl(value: String, ttl_seconds: u64) -> Self {
        Self {
            value,
            cached_at: Utc::now(),
            ttl_seconds,
        }
    }

    /// Check if this cached value has expired
    pub fn is_expired(&self) -> bool {
        let now = Utc::now();
        let expiry = self.cached_at + chrono::Duration::seconds(self.ttl_seconds as i64);
        now > expiry
    }

    /// Get remaining TTL in seconds
    pub fn remaining_ttl(&self) -> i64 {
        let now = Utc::now();
        let expiry = self.cached_at + chrono::Duration::seconds(self.ttl_seconds as i64);
        (expiry - now).num_seconds()
    }
}

/// Configuration for Infisical connection
#[derive(Debug, Clone)]
pub struct InfisicalConfig {
    pub url: String,
    pub client_id: String,
    pub client_secret: String,
    pub project_id: String,
    pub environment: String,
}

impl InfisicalConfig {
    pub fn new(
        url: String,
        client_id: String,
        client_secret: String,
        project_id: String,
        environment: String,
    ) -> Self {
        Self {
            url,
            client_id,
            client_secret,
            project_id,
            environment,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_reference_serialization() {
        let reference = SecretReference::new(
            "api-key".to_string(),
            "project-123".to_string(),
            "production".to_string(),
        );

        let reference_string = reference.to_reference_string();
        assert_eq!(reference_string, "infisical://project-123:production/api-key");

        let parsed = SecretReference::from_reference_string(&reference_string).unwrap();
        assert_eq!(parsed.key, reference.key);
        assert_eq!(parsed.project_id, reference.project_id);
        assert_eq!(parsed.environment, reference.environment);
    }

    #[test]
    fn test_secret_value_expiry() {
        let value = SecretValue::with_ttl("secret".to_string(), 1);
        assert!(!value.is_expired());
        
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(value.is_expired());
    }
}