//! # Database Backup Module
//!
//! This module provides database backup functionality for the Blackgate API Gateway.
//! It handles automated backups of the SQLite database to S3-compatible storage services.
//!
//! ## Features
//!
//! - **Scheduled Backups**: Runs database backups at configurable intervals in a background thread
//! - **S3 Storage**: Uploads compressed database backups to S3-compatible storage
//! - **Backup Retention**: Configurable retention policies for managing backup lifecycle
//! - **Compression**: GZIP compression to reduce backup file sizes
//! - **Error Recovery**: Robust error handling with retry logic
//! - **Non-blocking Operation**: Runs in a separate thread to avoid blocking main application
//!
//! ## Backup Strategy
//!
//! 1. **Database Backup**: Create a copy of the SQLite database using `VACUUM INTO`
//! 2. **Compression**: Compress the backup file using GZIP
//! 3. **S3 Upload**: Upload the compressed backup to S3 with timestamped filename
//! 4. **Cleanup**: Remove old backups based on retention policy
//!
//! ## Configuration
//!
//! Backup settings are stored in the database settings table:
//! - `backup_enabled`: Enable/disable automated backups
//! - `backup_interval_hours`: Hours between backup runs
//! - `backup_retention_days`: Days to keep backups
//! - `s3_bucket`: S3 bucket name for backups
//! - `s3_region`: S3 region
//! - `s3_access_key`: S3 access key ID
//! - `s3_secret_key`: S3 secret access key
//! - `s3_endpoint`: Custom S3 endpoint (optional, for S3-compatible services)

use crate::database::queries;
use chrono::{DateTime, Utc};
use flate2::Compression;
use flate2::write::GzEncoder;
use s3::Bucket;
use s3::Region;
use s3::creds::Credentials;
use sqlx::{Row, SqlitePool};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

///////////////////////////////////////////////////////////////////////////////
//****                         Public Structs                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Backup status for tracking operations
#[derive(Debug, Clone, PartialEq)]
pub enum BackupStatus {
    Success,
    Failed,
    InProgress,
}

impl BackupStatus {
    pub fn to_string(&self) -> String {
        match self {
            BackupStatus::Success => "Success".to_string(),
            BackupStatus::Failed => "Failed".to_string(),
            BackupStatus::InProgress => "InProgress".to_string(),
        }
    }
}

/// S3 configuration for backups
#[derive(Debug, Clone)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub endpoint: Option<String>, // For S3-compatible services
}

/// Backup configuration loaded from database settings
#[derive(Debug, Clone)]
pub struct BackupConfig {
    pub enabled: bool,
    pub interval_hours: u64,
    pub retention_days: u64,
    pub s3_config: Option<S3Config>,
}

/// Result of a backup operation
#[derive(Debug)]
pub struct BackupResult {
    pub status: BackupStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub file_size_bytes: Option<u64>,
    pub s3_key: Option<String>,
    pub error_message: Option<String>,
}

/// Database backup manager that coordinates all backup activities
#[derive(Clone)]
pub struct BackupManager {
    db_pool: Arc<SqlitePool>,
}

/// Default backup interval in hours
const DEFAULT_BACKUP_INTERVAL_HOURS: u64 = 24;
/// Default backup retention in days
const DEFAULT_BACKUP_RETENTION_DAYS: u64 = 30;
/// Backup file prefix
const BACKUP_FILE_PREFIX: &str = "blackgate-backup";

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

impl BackupManager {
    /// Create a new backup manager instance
    pub fn new(db_pool: Arc<SqlitePool>) -> Self {
        Self { db_pool }
    }

    /// Start the backup background task
    /// This function spawns a tokio task that runs indefinitely
    pub fn start_background_backups(self) {
        let manager = Arc::new(self);

        tokio::spawn(async move {
            info!("Starting database backup background task");

            loop {
                // Load configuration from database
                let config = match manager.load_backup_config().await {
                    Ok(config) => config,
                    Err(e) => {
                        error!("Failed to load backup configuration: {}", e);
                        // Wait 1 hour before retrying
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        continue;
                    }
                };

                if !config.enabled {
                    debug!("Database backups are disabled, sleeping for 1 hour");
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    continue;
                }

                debug!(
                    "Running database backup check with {} hour intervals",
                    config.interval_hours
                );

                if let Err(e) = manager.run_backup(&config).await {
                    error!("Database backup cycle failed: {}", e);
                }

                // Sleep until next backup interval
                let sleep_duration = Duration::from_secs(config.interval_hours * 3600);
                tokio::time::sleep(sleep_duration).await;
            }
        });
    }

    /// Run a single backup operation
    pub async fn run_backup(
        &self,
        config: &BackupConfig,
    ) -> Result<BackupResult, Box<dyn std::error::Error + Send + Sync>> {
        let mut result = BackupResult {
            status: BackupStatus::InProgress,
            started_at: Utc::now(),
            completed_at: None,
            file_size_bytes: None,
            s3_key: None,
            error_message: None,
        };

        info!("Starting database backup operation");

        // Check if S3 configuration is available
        let s3_config = match &config.s3_config {
            Some(config) => config,
            None => {
                let error_msg = "S3 configuration not available";
                error!("{}", error_msg);
                result.status = BackupStatus::Failed;
                result.error_message = Some(error_msg.to_string());
                result.completed_at = Some(Utc::now());
                return Ok(result);
            }
        };

        match self.perform_backup(s3_config).await {
            Ok((file_size, s3_key)) => {
                result.status = BackupStatus::Success;
                result.file_size_bytes = Some(file_size);
                result.s3_key = Some(s3_key);
                result.completed_at = Some(Utc::now());

                info!(
                    "Database backup completed successfully: {} bytes uploaded to S3 key '{}'",
                    file_size,
                    result.s3_key.as_ref().unwrap()
                );

                // Clean up old backups
                if let Err(e) = self
                    .cleanup_old_backups(s3_config, config.retention_days)
                    .await
                {
                    warn!("Failed to cleanup old backups: {}", e);
                }
            }
            Err(e) => {
                result.status = BackupStatus::Failed;
                result.error_message = Some(e.to_string());
                result.completed_at = Some(Utc::now());
                error!("Database backup failed: {}", e);
            }
        }

        // Store backup result in database
        if let Err(e) = self.store_backup_result(&result).await {
            error!("Failed to store backup result: {}", e);
        }

        Ok(result)
    }

    /// Perform the actual backup operation
    async fn perform_backup(
        &self,
        s3_config: &S3Config,
    ) -> Result<(u64, String), Box<dyn std::error::Error + Send + Sync>> {
        // Generate backup filename with timestamp
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let backup_filename = format!("{}-{}.db.gz", BACKUP_FILE_PREFIX, timestamp);
        let _temp_backup_path = std::env::temp_dir().join(format!("temp-{}", backup_filename));
        let temp_db_path = std::env::temp_dir().join(format!("temp-backup-{}.db", timestamp));

        // Step 1: Create database backup using VACUUM INTO
        debug!("Creating database backup using VACUUM INTO");
        let vacuum_sql = format!("VACUUM INTO '{}'", temp_db_path.to_string_lossy());
        sqlx::query(&vacuum_sql)
            .execute(self.db_pool.as_ref())
            .await?;

        // Step 2: Compress the backup file
        debug!("Compressing backup file");
        let compressed_data = {
            let db_data = tokio::fs::read(&temp_db_path).await?;
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&db_data)?;
            encoder.finish()?
        };

        // Step 3: Upload to S3
        debug!("Uploading backup to S3");
        let bucket = self.create_s3_bucket(s3_config)?;
        let s3_key = format!("backups/{}", backup_filename);

        bucket.put_object(&s3_key, &compressed_data).await?;

        // Step 4: Cleanup temporary files
        if let Err(e) = tokio::fs::remove_file(&temp_db_path).await {
            warn!("Failed to cleanup temporary database file: {}", e);
        }

        Ok((compressed_data.len() as u64, s3_key))
    }

    /// Create S3 bucket connection
    fn create_s3_bucket(
        &self,
        config: &S3Config,
    ) -> Result<Bucket, Box<dyn std::error::Error + Send + Sync>> {
        let region = if let Some(endpoint) = &config.endpoint {
            Region::Custom {
                region: config.region.clone(),
                endpoint: endpoint.clone(),
            }
        } else {
            config.region.parse()?
        };

        let credentials = Credentials::new(
            Some(&config.access_key),
            Some(&config.secret_key),
            None,
            None,
            None,
        )?;

        let bucket = Bucket::new(&config.bucket, region, credentials)?;
        Ok(*bucket)
    }

    /// Cleanup old backups based on retention policy
    async fn cleanup_old_backups(
        &self,
        s3_config: &S3Config,
        retention_days: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bucket = self.create_s3_bucket(s3_config)?;
        let cutoff_date = Utc::now() - chrono::Duration::days(retention_days as i64);

        debug!("Cleaning up backups older than {} days", retention_days);

        // List objects in the backups/ prefix
        let list_result = bucket.list("backups/".to_string(), None).await?;

        for object_list in list_result {
            for object in object_list.contents {
                // Parse timestamp from filename and check if it's older than retention period
                if let Some(timestamp_str) = self.extract_timestamp_from_key(&object.key) {
                    if let Ok(object_date) =
                        DateTime::parse_from_str(&timestamp_str, "%Y%m%d_%H%M%S")
                    {
                        if object_date.with_timezone(&Utc) < cutoff_date {
                            debug!("Deleting old backup: {}", object.key);
                            if let Err(e) = bucket.delete_object(&object.key).await {
                                warn!("Failed to delete old backup {}: {}", object.key, e);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Extract timestamp from S3 key
    fn extract_timestamp_from_key(&self, key: &str) -> Option<String> {
        // Extract timestamp from key like "backups/blackgate-backup-20231215_143022.db.gz"
        if let Some(filename) = key.split('/').last() {
            if let Some(timestamp_part) = filename.strip_prefix(&format!("{}-", BACKUP_FILE_PREFIX))
            {
                if let Some(timestamp) = timestamp_part.strip_suffix(".db.gz") {
                    return Some(timestamp.to_string());
                }
            }
        }
        None
    }

    /// Load backup configuration from database settings
    async fn load_backup_config(
        &self,
    ) -> Result<BackupConfig, Box<dyn std::error::Error + Send + Sync>> {
        // Helper function to get setting value
        let get_setting = |key: &str| -> Result<Option<String>, sqlx::Error> {
            match queries::get_setting_by_key(&self.db_pool, key) {
                Ok(Some(row)) => Ok(Some(row.get("value"))),
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            }
        };

        // Load backup settings
        let enabled = get_setting("backup_enabled")?
            .map(|v| v.parse().unwrap_or(false))
            .unwrap_or(false);

        let interval_hours = get_setting("backup_interval_hours")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_BACKUP_INTERVAL_HOURS);

        let retention_days = get_setting("backup_retention_days")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_BACKUP_RETENTION_DAYS);

        // Load S3 configuration
        let s3_config = if enabled {
            let bucket = get_setting("s3_bucket")?;
            let region = get_setting("s3_region")?;
            let access_key = get_setting("s3_access_key")?;
            let secret_key = get_setting("s3_secret_key")?;
            let endpoint = get_setting("s3_endpoint")?;

            if let (Some(bucket), Some(region), Some(access_key), Some(secret_key)) =
                (bucket, region, access_key, secret_key)
            {
                Some(S3Config {
                    bucket,
                    region,
                    access_key,
                    secret_key,
                    endpoint,
                })
            } else {
                warn!("Backup is enabled but S3 configuration is incomplete");
                None
            }
        } else {
            None
        };

        Ok(BackupConfig {
            enabled,
            interval_hours,
            retention_days,
            s3_config,
        })
    }

    /// Store backup result in database
    async fn store_backup_result(&self, result: &BackupResult) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO backup_history
             (status, started_at, completed_at, file_size_bytes, s3_key, error_message)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(result.status.to_string())
        .bind(result.started_at.to_rfc3339())
        .bind(result.completed_at.map(|dt| dt.to_rfc3339()))
        .bind(result.file_size_bytes.map(|s| s as i64))
        .bind(&result.s3_key)
        .bind(&result.error_message)
        .execute(self.db_pool.as_ref())
        .await?;

        Ok(())
    }

    /// Run a manual backup (for CLI or admin interface)
    #[allow(dead_code)]
    pub async fn run_manual_backup(
        &self,
    ) -> Result<BackupResult, Box<dyn std::error::Error + Send + Sync>> {
        let config = self.load_backup_config().await?;

        if config.s3_config.is_none() {
            return Err("S3 configuration not available for manual backup".into());
        }

        self.run_backup(&config).await
    }

    /// Get recent backup history
    #[allow(dead_code)]
    pub async fn get_backup_history(&self, limit: i32) -> Result<Vec<BackupResult>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT status, started_at, completed_at, file_size_bytes, s3_key, error_message
             FROM backup_history
             ORDER BY started_at DESC
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(self.db_pool.as_ref())
        .await?;

        let mut results = Vec::new();
        for row in rows {
            let status = match row.get::<String, _>("status").as_str() {
                "Success" => BackupStatus::Success,
                "Failed" => BackupStatus::Failed,
                "InProgress" => BackupStatus::InProgress,
                _ => BackupStatus::Failed,
            };

            let started_at = DateTime::parse_from_rfc3339(&row.get::<String, _>("started_at"))
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
                .with_timezone(&Utc);

            let completed_at = row
                .get::<Option<String>, _>("completed_at")
                .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc));

            results.push(BackupResult {
                status,
                started_at,
                completed_at,
                file_size_bytes: row
                    .get::<Option<i64>, _>("file_size_bytes")
                    .map(|s| s as u64),
                s3_key: row.get("s3_key"),
                error_message: row.get("error_message"),
            });
        }

        Ok(results)
    }
}

///////////////////////////////////////////////////////////////////////////////
//****                              Tests                                ****//
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn create_test_db() -> SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("Failed to create in-memory database")
    }

    #[tokio::test]
    async fn test_backup_status_conversion() {
        assert_eq!(BackupStatus::Success.to_string(), "Success");
        assert_eq!(BackupStatus::Failed.to_string(), "Failed");
        assert_eq!(BackupStatus::InProgress.to_string(), "InProgress");
    }

    #[tokio::test]
    async fn test_timestamp_extraction() {
        let pool = create_test_db().await;
        let manager = BackupManager::new(Arc::new(pool));

        assert_eq!(
            manager.extract_timestamp_from_key("backups/blackgate-backup-20231215_143022.db.gz"),
            Some("20231215_143022".to_string())
        );

        assert_eq!(manager.extract_timestamp_from_key("invalid/path"), None);
    }

    // Note: More comprehensive tests would require S3 credentials and would be implemented as integration tests
}
