//! # Security Module for BlackGate
//!
//! This module provides security configuration and utilities for the Blackgate API gateway.
//! It handles secure secret management using Infisical, HTTP security configuration,
//! CORS policies, and security middleware.
//!
//! ## Features
//!
//! - **Secret Management**: Secure storage and retrieval using Infisical
//! - **HTTP Security**: Configuration for secure HTTP communication
//! - **CORS Configuration**: Cross-origin resource sharing policies
//! - **Security Middleware**: Authentication and authorization utilities
//! - **Secret Caching**: In-memory caching with TTL for performance
//!
//! ## Usage
//!
//! The module provides configuration structures and utilities for security:
//! - Configure HTTP client security settings
//! - Define CORS policies for cross-origin requests
//! - Manage secrets with Infisical integration
//! - Apply security middleware to requests
//!
//! ## Sub-modules
//!
//! - `client`: Infisical client wrapper and configuration
//! - `cache`: Secret caching implementation with TTL
//! - `config`: Security configuration structures
//! - `cors`: CORS policy configuration and utilities
//! - `http`: HTTP security configuration (not client creation)
//! - `middleware`: Security middleware implementations
//! - `types`: Data structures for security operations

pub mod cache;
pub mod client;
pub mod config;
pub mod cors;
pub mod http;
pub mod middleware;
pub mod types;

use crate::security::{
    cache::SecretCache,
    client::InfisicalClient,
    types::{SecretReference, SecretValue, SecurityError},
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Main secret manager that coordinates Infisical operations and caching
#[derive(Clone)]
pub struct SecretManager {
    client: Arc<InfisicalClient>,
    cache: Arc<RwLock<SecretCache>>,
}

impl SecretManager {
    /// Create a new SecretManager with Infisical configuration
    pub async fn new(
        infisical_url: String,
        client_id: String,
        client_secret: String,
        project_id: String,
        environment: String,
    ) -> Result<Self, SecurityError> {
        let client = InfisicalClient::new(
            infisical_url,
            client_id,
            client_secret,
            project_id,
            environment,
        )
        .await?;

        let cache = SecretCache::new();

        Ok(Self {
            client: Arc::new(client),
            cache: Arc::new(RwLock::new(cache)),
        })
    }

    /// Store a secret in Infisical and return a reference
    pub async fn store_secret(
        &self,
        key: &str,
        value: &str,
        description: Option<&str>,
    ) -> Result<SecretReference, SecurityError> {
        info!("Storing secret with key: {}", key);

        let secret_ref = self.client.create_secret(key, value, description).await?;

        // Cache the secret for immediate use
        let mut cache = self.cache.write().await;
        cache.store(secret_ref.clone(), SecretValue::new(value.to_string()));

        info!("Successfully stored secret: {}", secret_ref.key);
        Ok(secret_ref)
    }

    /// Retrieve a secret value using its reference
    pub async fn get_secret(&self, reference: &SecretReference) -> Result<String, SecurityError> {
        // Try cache first
        {
            let mut cache = self.cache.write().await;
            if let Some(cached_value) = cache.get_cache(reference) {
                return Ok(cached_value.value);
            }
        }

        // Fetch from Infisical if not cached
        info!("Fetching secret from Infisical: {}", reference.key);
        let value = self.client.get_secret(&reference.key).await?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache.store(reference.clone(), SecretValue::new(value.clone()));

        Ok(value)
    }

    /// Update an existing secret in Infisical
    pub async fn update_secret(
        &self,
        reference: &SecretReference,
        new_value: &str,
    ) -> Result<(), SecurityError> {
        info!("Updating secret: {}", reference.key);

        self.client.update_secret(&reference.key, new_value).await?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache.store(reference.clone(), SecretValue::new(new_value.to_string()));

        info!("Successfully updated secret: {}", reference.key);
        Ok(())
    }

    /// Delete a secret from Infisical
    pub async fn delete_secret(&self, reference: &SecretReference) -> Result<(), SecurityError> {
        info!("Deleting secret: {}", reference.key);

        self.client.delete_secret(&reference.key).await?;

        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(reference);

        info!("Successfully deleted secret: {}", reference.key);
        Ok(())
    }

    /// Refresh all cached secrets from Infisical
    pub async fn refresh_cache(&self) -> Result<(), SecurityError> {
        info!("Refreshing secret cache");

        let mut cache = self.cache.write().await;
        let references: Vec<SecretReference> = cache.get_all_references();

        for reference in references {
            match self.client.get_secret(&reference.key).await {
                Ok(value) => {
                    cache.store(reference, SecretValue::new(value));
                }
                Err(e) => {
                    warn!("Failed to refresh secret {}: {}", reference.key, e);
                }
            }
        }

        info!("Cache refresh completed");
        Ok(())
    }

    /// Clear expired secrets from cache
    pub async fn cleanup_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.cleanup_expired();
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read().await;
        cache.get_stats()
    }
}
