use crate::security::types::{InfisicalConfig, SecretReference, SecurityError};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, info, warn};

/// Infisical API request/response types
#[derive(Serialize)]
struct AuthRequest {
    #[serde(rename = "clientId")]
    client_id: String,
    #[serde(rename = "clientSecret")]
    client_secret: String,
}

#[derive(Deserialize)]
struct AuthResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "expiresIn")]
    expires_in: u64,
    #[serde(rename = "tokenType")]
    token_type: String,
}

#[derive(Serialize)]
struct CreateSecretRequest {
    #[serde(rename = "secretName")]
    secret_name: String,
    #[serde(rename = "secretValue")]
    secret_value: String,
    #[serde(rename = "secretComment", skip_serializing_if = "Option::is_none")]
    secret_comment: Option<String>,
    #[serde(rename = "type")]
    secret_type: String,
}

#[derive(Serialize)]
struct UpdateSecretRequest {
    #[serde(rename = "secretValue")]
    secret_value: String,
    #[serde(rename = "type")]
    secret_type: String,
}

#[derive(Deserialize)]
struct SecretResponse {
    #[serde(rename = "secretKey")]
    secret_key: String,
    #[serde(rename = "secretValue")]
    secret_value: String,
    #[serde(rename = "secretComment")]
    secret_comment: Option<String>,
}

#[derive(Deserialize)]
struct SecretsListResponse {
    secrets: Vec<SecretResponse>,
}

/// Wrapper around the Infisical REST API with BlackGate-specific functionality
pub struct InfisicalClient {
    client: Client,
    config: InfisicalConfig,
    access_token: Option<String>,
}

impl InfisicalClient {
    /// Create a new Infisical client and authenticate
    pub async fn new(
        url: String,
        client_id: String,
        client_secret: String,
        project_id: String,
        environment: String,
    ) -> Result<Self, SecurityError> {
        info!("Initializing Infisical client for project: {}", project_id);

        let config = InfisicalConfig::new(
            url.clone(),
            client_id.clone(),
            client_secret.clone(),
            project_id.clone(),
            environment.clone(),
        );

        let client = Client::new();
        let mut infisical_client = Self {
            client,
            config,
            access_token: None,
        };

        // Authenticate and get access token
        infisical_client.authenticate().await?;

        info!("Successfully authenticated with Infisical");
        Ok(infisical_client)
    }

    /// Authenticate with Infisical and get access token
    async fn authenticate(&mut self) -> Result<(), SecurityError> {
        let auth_url = format!("{}/api/v1/auth/universal-auth/login", self.config.url);

        let auth_request = AuthRequest {
            client_id: self.config.client_id.clone(),
            client_secret: self.config.client_secret.clone(),
        };

        let response = self
            .client
            .post(&auth_url)
            .json(&auth_request)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send authentication request: {}", e);
                SecurityError::NetworkError(format!("Authentication request failed: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!(
                "Authentication failed with status {}: {}",
                status, error_text
            );
            return Err(SecurityError::AuthenticationError(format!(
                "Authentication failed: {} - {}",
                status, error_text
            )));
        }

        let auth_response: AuthResponse = response.json().await.map_err(|e| {
            error!("Failed to parse authentication response: {}", e);
            SecurityError::SerializationError(format!("Failed to parse auth response: {}", e))
        })?;

        self.access_token = Some(auth_response.access_token);
        info!("Successfully obtained access token");
        Ok(())
    }

    /// Get the authorization header value
    fn get_auth_header(&self) -> Result<String, SecurityError> {
        match &self.access_token {
            Some(token) => Ok(format!("Bearer {}", token)),
            None => Err(SecurityError::AuthenticationError(
                "No access token available".to_string(),
            )),
        }
    }

    /// Create a new secret in Infisical
    pub async fn create_secret(
        &self,
        key: &str,
        value: &str,
        description: Option<&str>,
    ) -> Result<SecretReference, SecurityError> {
        info!("Creating secret in Infisical: {}", key);

        let create_url = format!("{}/api/v3/secrets/raw/{}", self.config.url, key);

        let create_request = CreateSecretRequest {
            secret_name: key.to_string(),
            secret_value: value.to_string(),
            secret_comment: description.map(|d| d.to_string()),
            secret_type: "shared".to_string(),
        };

        let response = self
            .client
            .post(&create_url)
            .header("Authorization", self.get_auth_header()?)
            .query(&[
                ("workspaceId", &self.config.project_id),
                ("environment", &self.config.environment),
            ])
            .json(&create_request)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to create secret {}: {}", key, e);
                SecurityError::NetworkError(format!("Failed to create secret: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!(
                "Failed to create secret {} with status {}: {}",
                key, status, error_text
            );
            return Err(SecurityError::InfisicalError(format!(
                "Failed to create secret: {} - {}",
                status, error_text
            )));
        }

        info!("Successfully created secret: {}", key);
        Ok(SecretReference::new(
            key.to_string(),
            self.config.project_id.clone(),
            self.config.environment.clone(),
        ))
    }

    /// Get a secret value from Infisical
    pub async fn get_secret(&self, key: &str) -> Result<String, SecurityError> {
        info!("Fetching secret from Infisical: {}", key);

        let get_url = format!("{}/api/v3/secrets/raw/{}", self.config.url, key);

        let response = self
            .client
            .get(&get_url)
            .header("Authorization", self.get_auth_header()?)
            .query(&[
                ("workspaceId", &self.config.project_id),
                ("environment", &self.config.environment),
            ])
            .send()
            .await
            .map_err(|e| {
                error!("Failed to fetch secret {}: {}", key, e);
                SecurityError::NetworkError(format!("Failed to fetch secret: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            if status == 404 {
                return Err(SecurityError::InfisicalError(format!(
                    "Secret not found: {}",
                    key
                )));
            }
            let error_text = response.text().await.unwrap_or_default();
            error!(
                "Failed to fetch secret {} with status {}: {}",
                key, status, error_text
            );
            return Err(SecurityError::InfisicalError(format!(
                "Failed to fetch secret: {} - {}",
                status, error_text
            )));
        }

        let secret_response: SecretResponse = response.json().await.map_err(|e| {
            error!("Failed to parse secret response for {}: {}", key, e);
            SecurityError::SerializationError(format!("Failed to parse secret response: {}", e))
        })?;

        info!("Successfully fetched secret: {}", key);
        Ok(secret_response.secret_value)
    }

    /// Update an existing secret in Infisical
    pub async fn update_secret(&self, key: &str, new_value: &str) -> Result<(), SecurityError> {
        info!("Updating secret in Infisical: {}", key);

        let update_url = format!("{}/api/v3/secrets/raw/{}", self.config.url, key);

        let update_request = UpdateSecretRequest {
            secret_value: new_value.to_string(),
            secret_type: "shared".to_string(),
        };

        let response = self
            .client
            .patch(&update_url)
            .header("Authorization", self.get_auth_header()?)
            .query(&[
                ("workspaceId", &self.config.project_id),
                ("environment", &self.config.environment),
            ])
            .json(&update_request)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to update secret {}: {}", key, e);
                SecurityError::NetworkError(format!("Failed to update secret: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!(
                "Failed to update secret {} with status {}: {}",
                key, status, error_text
            );
            return Err(SecurityError::InfisicalError(format!(
                "Failed to update secret: {} - {}",
                status, error_text
            )));
        }

        info!("Successfully updated secret: {}", key);
        Ok(())
    }

    /// Delete a secret from Infisical
    pub async fn delete_secret(&self, key: &str) -> Result<(), SecurityError> {
        info!("Deleting secret from Infisical: {}", key);

        let delete_url = format!("{}/api/v3/secrets/raw/{}", self.config.url, key);

        let response = self
            .client
            .delete(&delete_url)
            .header("Authorization", self.get_auth_header()?)
            .query(&[
                ("workspaceId", &self.config.project_id),
                ("environment", &self.config.environment),
            ])
            .send()
            .await
            .map_err(|e| {
                error!("Failed to delete secret {}: {}", key, e);
                SecurityError::NetworkError(format!("Failed to delete secret: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!(
                "Failed to delete secret {} with status {}: {}",
                key, status, error_text
            );
            return Err(SecurityError::InfisicalError(format!(
                "Failed to delete secret: {} - {}",
                status, error_text
            )));
        }

        info!("Successfully deleted secret: {}", key);
        Ok(())
    }

    /// List all secrets in the project/environment
    pub async fn list_secrets(&self) -> Result<Vec<String>, SecurityError> {
        info!("Listing secrets from Infisical");

        let list_url = format!("{}/api/v3/secrets/raw", self.config.url);

        let response = self
            .client
            .get(&list_url)
            .header("Authorization", self.get_auth_header()?)
            .query(&[
                ("workspaceId", &self.config.project_id),
                ("environment", &self.config.environment),
            ])
            .send()
            .await
            .map_err(|e| {
                error!("Failed to list secrets: {}", e);
                SecurityError::NetworkError(format!("Failed to list secrets: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!(
                "Failed to list secrets with status {}: {}",
                status, error_text
            );
            return Err(SecurityError::InfisicalError(format!(
                "Failed to list secrets: {} - {}",
                status, error_text
            )));
        }

        let secrets_response: SecretsListResponse = response.json().await.map_err(|e| {
            error!("Failed to parse secrets list response: {}", e);
            SecurityError::SerializationError(format!("Failed to parse secrets list: {}", e))
        })?;

        let secret_keys: Vec<String> = secrets_response
            .secrets
            .into_iter()
            .map(|s| s.secret_key)
            .collect();

        info!("Successfully listed {} secrets", secret_keys.len());
        Ok(secret_keys)
    }

    /// Get multiple secrets at once
    pub async fn get_multiple_secrets(
        &self,
        keys: &[String],
    ) -> Result<HashMap<String, String>, SecurityError> {
        info!("Fetching multiple secrets from Infisical: {:?}", keys);

        let mut results = HashMap::new();

        for key in keys {
            match self.get_secret(key).await {
                Ok(value) => {
                    results.insert(key.clone(), value);
                }
                Err(e) => {
                    warn!("Failed to fetch secret {}: {}", key, e);
                    // Continue with other secrets instead of failing completely
                }
            }
        }

        Ok(results)
    }

    /// Test connection to Infisical
    pub async fn test_connection(&self) -> Result<(), SecurityError> {
        info!("Testing Infisical connection");

        // Try to list secrets as a connection test
        self.list_secrets().await?;

        info!("Infisical connection test successful");
        Ok(())
    }
}
