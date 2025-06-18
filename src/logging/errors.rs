//! # Error Logging Module
//!
//! This module provides error logging functionality with database persistence.
//! It captures errors and stores them in the database while also logging them
//! through the tracing system for immediate visibility.
//!
//! ## Features
//!
//! - **Database Persistence**: Store errors for later analysis
//! - **Tracing Integration**: Use standard tracing::error! for immediate logging
//! - **Non-blocking**: Async operations that don't slow down request processing
//! - **Automatic Cleanup**: Background cleanup of old error records

use chrono::Utc;
use serde_json::json;
use sqlx::SqlitePool;
use std::collections::HashMap;
use tracing::error;
use uuid::Uuid;

///////////////////////////////////////////////////////////////////////////////
//****                         Public Structs                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Error severity levels for database storage
#[derive(Debug, Clone)]
pub enum ErrorSeverity {
    /// Critical errors that require immediate attention
    Critical,
    /// Error conditions that should be investigated
    Error,
    /// Warning conditions that may lead to errors
    Warning,
    /// Informational messages for debugging
    Info,
}

impl ErrorSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorSeverity::Critical => "critical",
            ErrorSeverity::Error => "error",
            ErrorSeverity::Warning => "warning",
            ErrorSeverity::Info => "info",
        }
    }
}

/// Error context information for better debugging
#[derive(Debug, Clone, Default)]
pub struct ErrorContext {
    pub route_path: Option<String>,
    pub method: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub additional_fields: HashMap<String, String>,
}

impl ErrorContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_route(mut self, route_path: String) -> Self {
        self.route_path = Some(route_path);
        self
    }

    pub fn with_method(mut self, method: String) -> Self {
        self.method = Some(method);
        self
    }

    pub fn with_client_info(mut self, client_ip: String, user_agent: String) -> Self {
        self.client_ip = Some(client_ip);
        self.user_agent = Some(user_agent);
        self
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    pub fn with_field(mut self, key: String, value: String) -> Self {
        self.additional_fields.insert(key, value);
        self
    }

    /// Serialize context to JSON string for database storage
    pub fn to_json(&self) -> String {
        let mut context = json!({});

        if let Some(ref route_path) = self.route_path {
            context["route_path"] = json!(route_path);
        }
        if let Some(ref method) = self.method {
            context["method"] = json!(method);
        }
        if let Some(ref client_ip) = self.client_ip {
            context["client_ip"] = json!(client_ip);
        }
        if let Some(ref user_agent) = self.user_agent {
            context["user_agent"] = json!(user_agent);
        }
        if let Some(ref request_id) = self.request_id {
            context["request_id"] = json!(request_id);
        }

        for (key, value) in &self.additional_fields {
            context[key] = json!(value);
        }

        context.to_string()
    }
}

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Log an error to both the tracing system and the database
///
/// This function provides non-blocking error logging that stores errors
/// in the database for later analysis while also immediately logging
/// them through the tracing system.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `severity` - Error severity level
/// * `message` - Error message to log
/// * `context` - Optional context information
/// * `file` - Source file location (use file!() macro)
/// * `line` - Source line number (use line!() macro)
/// * `function` - Function name (optional, use function_name!() macro)
///
/// # Example
///
/// ```rust
/// use blackgate::logging::errors::{log_error_async, ErrorSeverity, ErrorContext};
///
/// let context = ErrorContext::new()
///     .with_route("/api/test".to_string())
///     .with_method("GET".to_string());
///
/// log_error_async(
///     &pool,
///     ErrorSeverity::Error,
///     "Failed to process request".to_string(),
///     Some(context),
///     file!(),
///     line!(),
///     Some("handle_request".to_string())
/// ).await;
/// ```
pub async fn log_error_async(
    pool: &SqlitePool,
    severity: ErrorSeverity,
    message: String,
    context: Option<ErrorContext>,
    file: &str,
    line: u32,
    function: Option<String>,
) {
    // Log immediately to tracing system
    error!(
        target: "blackgate::error_logging",
        file = file,
        line = line,
        function = function.as_deref().unwrap_or("unknown"),
        severity = severity.as_str(),
        "{}",
        message
    );

    // Store in database asynchronously (non-blocking)
    let pool_clone = pool.clone();
    let severity_str = severity.as_str().to_string();
    let context_json = context.map(|c| c.to_json());
    let file_str = file.to_string();
    let function_str = function;

    tokio::spawn(async move {
        if let Err(e) = store_error_in_database(
            &pool_clone,
            &message,
            &severity_str,
            context_json.as_deref(),
            &file_str,
            line,
            function_str.as_deref(),
        )
        .await
        {
            // If we can't store in database, at least log this failure
            error!(
                target: "blackgate::error_logging",
                "Failed to store error in database: {}. Original error: {}",
                e,
                message
            );
        }
    });
}

/// Store error information in the database
async fn store_error_in_database(
    pool: &SqlitePool,
    message: &str,
    severity: &str,
    context: Option<&str>,
    file: &str,
    line: u32,
    function: Option<&str>,
) -> Result<(), sqlx::Error> {
    let error_id = Uuid::new_v4().to_string();
    let timestamp = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO error_logs 
         (id, error_message, severity, context, file_location, line_number, function_name, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&error_id)
    .bind(message)
    .bind(severity)
    .bind(context)
    .bind(file)
    .bind(line as i64)
    .bind(function)
    .bind(&timestamp)
    .execute(pool)
    .await?;

    Ok(())
}

/// Clean up error logs older than the specified number of days
///
/// This function is called by the background cleanup process to remove
/// old error records from the database to prevent unbounded growth.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `retention_days` - Number of days to keep error logs
///
/// # Returns
///
/// The number of error records that were deleted
pub async fn cleanup_old_error_logs(
    pool: &SqlitePool,
    retention_days: u32,
) -> Result<u64, sqlx::Error> {
    let cutoff_date = Utc::now()
        .checked_sub_signed(chrono::Duration::days(retention_days as i64))
        .unwrap_or_else(Utc::now)
        .to_rfc3339();

    let result = sqlx::query("DELETE FROM error_logs WHERE created_at < ?")
        .bind(&cutoff_date)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

///////////////////////////////////////////////////////////////////////////////
//****                              Tests                                ****//
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn create_test_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");

        // Create the error_logs table for testing
        sqlx::query(
            "CREATE TABLE error_logs (
                id TEXT PRIMARY KEY,
                error_message TEXT NOT NULL,
                severity TEXT NOT NULL,
                context TEXT,
                file_location TEXT,
                line_number INTEGER,
                function_name TEXT,
                created_at TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("Failed to create test table");

        pool
    }

    #[tokio::test]
    async fn test_error_context_serialization() {
        let context = ErrorContext::new()
            .with_route("/api/test".to_string())
            .with_method("GET".to_string())
            .with_request_id("test-123".to_string());

        let json = context.to_json();
        assert!(json.contains("route_path"));
        assert!(json.contains("/api/test"));
        assert!(json.contains("method"));
        assert!(json.contains("GET"));
    }

    #[tokio::test]
    async fn test_store_error_in_database() {
        let pool = create_test_pool().await;

        let result = store_error_in_database(
            &pool,
            "Test error message",
            "error",
            Some(r#"{"test": "context"}"#),
            "test.rs",
            42,
            Some("test_function"),
        )
        .await;

        assert!(result.is_ok());

        // Verify the error was stored
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM error_logs")
            .fetch_one(&pool)
            .await
            .expect("Failed to count error logs");

        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_cleanup_old_error_logs() {
        let pool = create_test_pool().await;

        // Insert a recent error
        let recent_date = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO error_logs (id, error_message, severity, created_at)
             VALUES ('recent', 'Recent error', 'error', ?)",
        )
        .bind(&recent_date)
        .execute(&pool)
        .await
        .expect("Failed to insert recent error");

        // Insert an old error (10 days ago)
        let old_date = (Utc::now() - chrono::Duration::days(10)).to_rfc3339();
        sqlx::query(
            "INSERT INTO error_logs (id, error_message, severity, created_at)
             VALUES ('old', 'Old error', 'error', ?)",
        )
        .bind(&old_date)
        .execute(&pool)
        .await
        .expect("Failed to insert old error");

        // Clean up errors older than 7 days
        let deleted = cleanup_old_error_logs(&pool, 7)
            .await
            .expect("Cleanup failed");
        assert_eq!(deleted, 1);

        // Verify only the recent error remains
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM error_logs")
            .fetch_one(&pool)
            .await
            .expect("Failed to count remaining errors");

        assert_eq!(count, 1);
    }
}
