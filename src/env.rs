//! Environment variable validation and configuration module for Black Gate
//!
//! This module provides centralized validation and configuration management
//! for all environment variables used by the Black Gate API gateway.
//!
//! # Supported Environment Variables
//!
//! ## Database Configuration
//! - `BLACKGATE_DB_URL`: Database connection URL (default: "sqlite://blackgate.db")
//!
//! ## Server Configuration
//! - `BLACKGATE_HOST`: Server bind address (default: "0.0.0.0")
//! - `BLACKGATE_PORT`: Server port (default: "3000")
//!
//! ## Logging Configuration
//! - `RUST_LOG`: Standard Rust logging configuration
//! - `BLACKGATE_LOG_LEVEL`: Application-specific log level override
//! - `BLACKGATE_ERROR_LOG_RETENTION_DAYS`: Days to keep error logs in database (default: "7")
//!
//! ## Cache Configuration
//! - `BLACKGATE_RESPONSE_CACHE_TTL`: Default response cache TTL in seconds (default: "300")
//! - `BLACKGATE_RESPONSE_CACHE_MAX_SIZE`: Maximum cache entries (default: "1000")
//!
//! ## Security Configuration
//! - `BLACKGATE_JWT_DEFAULT_SECRET`: Default JWT secret for routes without explicit configuration
//! - `BLACKGATE_RATE_LIMIT_GLOBAL`: Global rate limit per minute (default: "1000")
//!
//! ## Backup Configuration
//! - `BLACKGATE_BACKUP_ENABLED`: Enable automatic database backups (default: "true")
//! - `BLACKGATE_BACKUP_INTERVAL_HOURS`: Backup interval in hours (default: "24")
//! - `BLACKGATE_S3_BUCKET`: S3 bucket for backup storage (optional)
//! - `BLACKGATE_S3_REGION`: S3 region (optional, default: "us-east-1")
//! - `AWS_ACCESS_KEY_ID`: AWS access key for S3 backups (optional)
//! - `AWS_SECRET_ACCESS_KEY`: AWS secret key for S3 backups (optional)
//!
//! # Usage
//!
//! ```rust
//! use blackgate::env::{validate_environment, get_config};
//!
//! // Validate all environment variables at startup
//! let validation_result = validate_environment();
//! if let Err(errors) = validation_result {
//!     for error in errors {
//!         eprintln!("Environment validation error: {}", error);
//!     }
//!     std::process::exit(1);
//! }
//!
//! // Get validated configuration
//! let config = get_config();
//! println!("Server will bind to {}:{}", config.host, config.port);
//! ```

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tracing::{info, warn};

/// Environment validation errors
#[derive(Debug, Clone)]
pub struct EnvValidationError {
    pub variable: String,
    pub message: String,
    pub severity: ErrorSeverity,
}

/// Severity level for environment validation errors
#[derive(Debug, Clone, PartialEq)]
pub enum ErrorSeverity {
    /// Critical errors that prevent application startup
    Critical,
    /// Warnings about missing optional variables or suboptimal configurations
    Warning,
    /// Informational messages about default values being used
    Info,
}

/// Validated application configuration derived from environment variables
#[derive(Debug, Clone)]
pub struct AppConfig {
    // Database
    pub database_url: String,

    // Server
    pub host: String,
    pub port: u16,
    pub bind_address: SocketAddr,

    // Logging
    pub log_level: String,
    pub error_log_retention_days: u32,

    // Cache
    pub response_cache_ttl: u64,
    pub response_cache_max_size: usize,

    // Security
    pub rate_limit_global: u32,

    // Backup
    pub backup_enabled: bool,
    pub backup_interval_hours: u32,
    pub s3_bucket: Option<String>,
    pub s3_region: String,
    // todo update our backup config to use these
    pub _aws_secret_access_key: Option<String>,
    pub _aws_access_key_id: Option<String>,
}

/// Validate all environment variables and return configuration or errors
pub fn validate_environment() -> Result<AppConfig, Vec<EnvValidationError>> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Database configuration
    let database_url = env::var("BLACKGATE_DB_URL").unwrap_or_else(|_| {
        warnings.push(EnvValidationError {
            variable: "BLACKGATE_DB_URL".to_string(),
            message: "Using default database URL 'sqlite://blackgate.db'".to_string(),
            severity: ErrorSeverity::Info,
        });
        "sqlite://blackgate.db".to_string()
    });

    // Server configuration
    let host = env::var("BLACKGATE_HOST").unwrap_or_else(|_| {
        warnings.push(EnvValidationError {
            variable: "BLACKGATE_HOST".to_string(),
            message: "Using default host '0.0.0.0'".to_string(),
            severity: ErrorSeverity::Info,
        });
        "0.0.0.0".to_string()
    });

    // Validate host is a valid IP address
    if let Err(_) = IpAddr::from_str(&host) {
        errors.push(EnvValidationError {
            variable: "BLACKGATE_HOST".to_string(),
            message: format!("Invalid IP address: {}", host),
            severity: ErrorSeverity::Critical,
        });
    }

    let port = match env::var("BLACKGATE_PORT") {
        Ok(port_str) => {
            match port_str.parse::<u16>() {
                Ok(port) => {
                    if port < 1024 && port != 0 {
                        warnings.push(EnvValidationError {
                            variable: "BLACKGATE_PORT".to_string(),
                            message: format!(
                                "Using privileged port {}, may require root privileges",
                                port
                            ),
                            severity: ErrorSeverity::Warning,
                        });
                    }
                    port
                }
                Err(_) => {
                    errors.push(EnvValidationError {
                        variable: "BLACKGATE_PORT".to_string(),
                        message: format!("Invalid port number: {}", port_str),
                        severity: ErrorSeverity::Critical,
                    });
                    3000 // fallback
                }
            }
        }
        Err(_) => {
            warnings.push(EnvValidationError {
                variable: "BLACKGATE_PORT".to_string(),
                message: "Using default port 3000".to_string(),
                severity: ErrorSeverity::Info,
            });
            3000
        }
    };

    // Create bind address
    let bind_address = match format!("{}:{}", host, port).parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            errors.push(EnvValidationError {
                variable: "BLACKGATE_HOST/BLACKGATE_PORT".to_string(),
                message: format!("Cannot create valid socket address from {}:{}", host, port),
                severity: ErrorSeverity::Critical,
            });
            "0.0.0.0:3000".parse().unwrap() // fallback
        }
    };

    // Logging configuration
    let log_level = env::var("BLACKGATE_LOG_LEVEL")
        .or_else(|_| env::var("RUST_LOG"))
        .unwrap_or_else(|_| {
            warnings.push(EnvValidationError {
                variable: "RUST_LOG/BLACKGATE_LOG_LEVEL".to_string(),
                message: "Using default log level 'blackgate=info,tower_http=debug'".to_string(),
                severity: ErrorSeverity::Info,
            });
            "blackgate=info,tower_http=debug".to_string()
        });

    // Error log retention configuration
    let error_log_retention_days =
        parse_env_var_with_default("BLACKGATE_ERROR_LOG_RETENTION_DAYS", 7, &mut warnings);

    // Cache configuration
    let response_cache_ttl =
        parse_env_var_with_default("BLACKGATE_RESPONSE_CACHE_TTL", 300, &mut warnings);

    let response_cache_max_size =
        parse_env_var_with_default("BLACKGATE_RESPONSE_CACHE_MAX_SIZE", 1000, &mut warnings);

    let rate_limit_global =
        parse_env_var_with_default("BLACKGATE_RATE_LIMIT_GLOBAL", 1000, &mut warnings);

    // Backup configuration
    let backup_enabled =
        parse_bool_env_var_with_default("BLACKGATE_BACKUP_ENABLED", true, &mut warnings);

    let backup_interval_hours =
        parse_env_var_with_default("BLACKGATE_BACKUP_INTERVAL_HOURS", 24, &mut warnings);

    let s3_bucket = env::var("BLACKGATE_S3_BUCKET").ok();
    let s3_region = env::var("BLACKGATE_S3_REGION").unwrap_or_else(|_| {
        if s3_bucket.is_some() {
            warnings.push(EnvValidationError {
                variable: "BLACKGATE_S3_REGION".to_string(),
                message: "Using default S3 region 'us-east-1'".to_string(),
                severity: ErrorSeverity::Info,
            });
        }
        "us-east-1".to_string()
    });

    let _aws_access_key_id = env::var("AWS_ACCESS_KEY_ID").ok();
    let _aws_secret_access_key = env::var("AWS_SECRET_ACCESS_KEY").ok();

    // Validate AWS credentials if S3 backup is configured
    if let Some(ref bucket) = s3_bucket {
        if _aws_access_key_id.is_none() || _aws_secret_access_key.is_none() {
            warnings.push(EnvValidationError {
                variable: "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY".to_string(),
                message: format!("S3 bucket '{}' configured but AWS credentials missing. Backup to S3 will fail.", bucket),
                severity: ErrorSeverity::Warning,
            });
        }
    }

    // Add all warnings to errors for reporting
    errors.extend(warnings);

    // Check if we have any critical errors
    let has_critical_errors = errors.iter().any(|e| e.severity == ErrorSeverity::Critical);

    if has_critical_errors {
        return Err(errors);
    }

    // Log non-critical issues
    for error in &errors {
        match error.severity {
            ErrorSeverity::Warning => warn!("{}: {}", error.variable, error.message),
            ErrorSeverity::Info => info!("{}: {}", error.variable, error.message),
            ErrorSeverity::Critical => {} // Already handled above
        }
    }

    Ok(AppConfig {
        database_url,
        host,
        port,
        bind_address,
        log_level,
        error_log_retention_days,
        response_cache_ttl,
        response_cache_max_size,
        rate_limit_global,
        backup_enabled,
        backup_interval_hours,
        s3_bucket,
        s3_region,
        _aws_access_key_id,
        _aws_secret_access_key,
    })
}

/// Get the validated configuration, panicking if validation fails
pub fn get_config() -> AppConfig {
    match validate_environment() {
        Ok(config) => config,
        Err(errors) => {
            eprintln!("Environment validation failed:");
            for error in errors {
                match error.severity {
                    ErrorSeverity::Critical => {
                        eprintln!("CRITICAL - {}: {}", error.variable, error.message)
                    }
                    ErrorSeverity::Warning => {
                        eprintln!("WARNING - {}: {}", error.variable, error.message)
                    }
                    ErrorSeverity::Info => {
                        eprintln!("INFO - {}: {}", error.variable, error.message)
                    }
                }
            }
            std::process::exit(1);
        }
    }
}

/// Print environment validation results in a user-friendly format
pub fn print_validation_results(result: &Result<AppConfig, Vec<EnvValidationError>>) {
    match result {
        Ok(config) => {
            info!("Environment validation successful");
            info!("Configuration:");
            info!("  Database URL: {}", config.database_url);
            info!("  Server: {}", config.bind_address);
            info!("  Log Level: {}", config.log_level);
            info!("  Response Cache TTL: {}s", config.response_cache_ttl);
            info!(
                "  Response Cache Max Size: {} entries",
                config.response_cache_max_size
            );
            info!(
                "  Global Rate Limit: {} requests/minute",
                config.rate_limit_global
            );
            info!("  Backup Enabled: {}", config.backup_enabled);
            if config.backup_enabled {
                info!("  Backup Interval: {} hours", config.backup_interval_hours);
                if let Some(ref bucket) = config.s3_bucket {
                    info!(
                        "  S3 Backup Bucket: {} (region: {})",
                        bucket, config.s3_region
                    );
                }
            }
        }
        Err(errors) => {
            let critical_count = errors
                .iter()
                .filter(|e| e.severity == ErrorSeverity::Critical)
                .count();
            let warning_count = errors
                .iter()
                .filter(|e| e.severity == ErrorSeverity::Warning)
                .count();
            let info_count = errors
                .iter()
                .filter(|e| e.severity == ErrorSeverity::Info)
                .count();

            if critical_count > 0 {
                eprintln!(
                    "Environment validation failed with {} critical error(s), {} warning(s), {} info message(s):",
                    critical_count, warning_count, info_count
                );
            } else {
                println!(
                    "Environment validation completed with {} warning(s), {} info message(s):",
                    warning_count, info_count
                );
            }

            for error in errors {
                let prefix = match error.severity {
                    ErrorSeverity::Critical => "❌ CRITICAL",
                    ErrorSeverity::Warning => "⚠️  WARNING",
                    ErrorSeverity::Info => "ℹ️  INFO",
                };
                println!("  {} - {}: {}", prefix, error.variable, error.message);
            }
        }
    }
}

/// Generate example environment configuration file
pub fn generate_env_example() -> String {
    format!(
        r#"# Black Gate API Gateway Environment Configuration
# Copy this file to .env and customize the values for your deployment

# =============================================================================
# Database Configuration
# =============================================================================

# Database connection URL
# Default: sqlite://blackgate.db
# Examples:
#   BLACKGATE_DB_URL=sqlite://blackgate.db
#   BLACKGATE_DB_URL=sqlite:///var/lib/blackgate/blackgate.db
BLACKGATE_DB_URL=sqlite://blackgate.db

# =============================================================================
# Server Configuration
# =============================================================================

# Server bind address
# Default: 0.0.0.0 (bind to all interfaces)
# Examples:
#   BLACKGATE_HOST=0.0.0.0    # All interfaces
#   BLACKGATE_HOST=127.0.0.1  # Localhost only
BLACKGATE_HOST=0.0.0.0

# Server port
# Default: 3000
# Note: Ports below 1024 may require root privileges
BLACKGATE_PORT=3000

# =============================================================================
# Logging Configuration
# =============================================================================

# Log level configuration
# Default: blackgate=info,tower_http=debug
# Examples:
#   RUST_LOG=debug                              # Everything at debug level
#   RUST_LOG=blackgate=debug,tower_http=info    # Custom per-module levels
#   BLACKGATE_LOG_LEVEL=info                    # Override for blackgate only
RUST_LOG=blackgate=info,tower_http=debug

# Error log retention in days
# Default: 7 (keep error logs for 7 days)
BLACKGATE_ERROR_LOG_RETENTION_DAYS=7

# =============================================================================
# Cache Configuration
# =============================================================================

# Default response cache TTL in seconds
# Default: 300 (5 minutes)
BLACKGATE_RESPONSE_CACHE_TTL=300

# Maximum number of cached responses
# Default: 1000
BLACKGATE_RESPONSE_CACHE_MAX_SIZE=1000

# =============================================================================
# Security Configuration
# =============================================================================

# Default JWT secret for routes without explicit configuration
# Recommended: Use a cryptographically strong secret (32+ characters)
# Generate with: openssl rand -base64 32
# BLACKGATE_JWT_DEFAULT_SECRET=your-super-secret-jwt-key-here

# Global rate limit per minute
# Default: 1000 requests per minute
BLACKGATE_RATE_LIMIT_GLOBAL=1000

# =============================================================================
# Backup Configuration
# =============================================================================

# Enable automatic database backups
# Default: true
BLACKGATE_BACKUP_ENABLED=true

# Backup interval in hours
# Default: 24 (daily backups)
BLACKGATE_BACKUP_INTERVAL_HOURS=24

# =============================================================================
# S3 Backup Configuration (Optional)
# =============================================================================

# S3 bucket for backup storage
# Leave empty to disable S3 backups
# BLACKGATE_S3_BUCKET=my-blackgate-backups

# S3 region
# Default: us-east-1
# BLACKGATE_S3_REGION=us-east-1

# AWS credentials for S3 access
# Can also be provided via AWS IAM roles or AWS CLI configuration
# AWS_ACCESS_KEY_ID=your-access-key-id
# AWS_SECRET_ACCESS_KEY=your-secret-access-key

# =============================================================================
# Additional AWS Configuration (Optional)
# =============================================================================

# AWS session token (if using temporary credentials)
# AWS_SESSION_TOKEN=your-session-token

# AWS profile (if using AWS CLI profiles)
# AWS_PROFILE=blackgate-profile
"#
    )
}

/// Helper function to parse environment variable with default value
fn parse_env_var_with_default<T>(
    var_name: &str,
    default: T,
    warnings: &mut Vec<EnvValidationError>,
) -> T
where
    T: FromStr + Clone + std::fmt::Display,
    T::Err: std::fmt::Display,
{
    match env::var(var_name) {
        Ok(value_str) => match value_str.parse::<T>() {
            Ok(value) => value,
            Err(e) => {
                warnings.push(EnvValidationError {
                    variable: var_name.to_string(),
                    message: format!(
                        "Invalid value '{}': {}. Using default: {}",
                        value_str, e, default
                    ),
                    severity: ErrorSeverity::Warning,
                });
                default
            }
        },
        Err(_) => {
            warnings.push(EnvValidationError {
                variable: var_name.to_string(),
                message: format!("Using default value: {}", default),
                severity: ErrorSeverity::Info,
            });
            default
        }
    }
}

/// Helper function to parse boolean environment variable with default value
fn parse_bool_env_var_with_default(
    var_name: &str,
    default: bool,
    warnings: &mut Vec<EnvValidationError>,
) -> bool {
    match env::var(var_name) {
        Ok(value_str) => match value_str.to_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => true,
            "false" | "0" | "no" | "off" => false,
            _ => {
                warnings.push(EnvValidationError {
                    variable: var_name.to_string(),
                    message: format!(
                        "Invalid boolean value '{}'. Using default: {}",
                        value_str, default
                    ),
                    severity: ErrorSeverity::Warning,
                });
                default
            }
        },
        Err(_) => {
            warnings.push(EnvValidationError {
                variable: var_name.to_string(),
                message: format!("Using default value: {}", default),
                severity: ErrorSeverity::Info,
            });
            default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_default_configuration() {
        // Clear environment variables
        unsafe {
            env::remove_var("BLACKGATE_DB_URL");
            env::remove_var("BLACKGATE_HOST");
            env::remove_var("BLACKGATE_PORT");
        }

        let result = validate_environment();
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.database_url, "sqlite://blackgate.db");
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 3000);
    }

    #[test]
    fn test_custom_configuration() {
        unsafe {
            env::set_var("BLACKGATE_DB_URL", "sqlite:///tmp/test.db");
            env::set_var("BLACKGATE_HOST", "127.0.0.1");
            env::set_var("BLACKGATE_PORT", "8080");
        }

        let result = validate_environment();
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.database_url, "sqlite:///tmp/test.db");
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8080);

        // Clean up
        unsafe {
            env::remove_var("BLACKGATE_DB_URL");
            env::remove_var("BLACKGATE_HOST");
            env::remove_var("BLACKGATE_PORT");
        }
    }

    #[test]
    fn test_invalid_port() {
        unsafe {
            env::set_var("BLACKGATE_PORT", "invalid");
        }

        let result = validate_environment();
        assert!(result.is_err());

        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.variable == "BLACKGATE_PORT" && e.severity == ErrorSeverity::Critical)
        );

        // Clean up
        unsafe {
            env::remove_var("BLACKGATE_PORT");
        }
    }

    #[test]
    fn test_invalid_host() {
        unsafe {
            env::set_var("BLACKGATE_HOST", "invalid-host");
        }

        let result = validate_environment();
        assert!(result.is_err());

        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.variable == "BLACKGATE_HOST" && e.severity == ErrorSeverity::Critical)
        );

        // Clean up
        unsafe {
            env::remove_var("BLACKGATE_HOST");
        }
    }

    #[test]
    fn test_boolean_parsing() {
        unsafe {
            env::set_var("BLACKGATE_BACKUP_ENABLED", "true");
        }
        let result = validate_environment();
        assert!(result.is_ok());
        assert!(result.unwrap().backup_enabled);

        unsafe {
            env::set_var("BLACKGATE_BACKUP_ENABLED", "false");
        }
        let result = validate_environment();
        assert!(result.is_ok());
        assert!(!result.unwrap().backup_enabled);

        unsafe {
            env::set_var("BLACKGATE_BACKUP_ENABLED", "invalid");
        }
        let result = validate_environment();
        assert!(result.is_ok()); // Should use default with warning

        // Clean up
        unsafe {
            env::remove_var("BLACKGATE_BACKUP_ENABLED");
        }
    }
}
