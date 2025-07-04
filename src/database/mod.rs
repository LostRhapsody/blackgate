//!
//! # Database Module for The Black Gate
//!
//! This module provides database management functionality for the Black Gate API Gateway.
//! It handles database initialization, connection management, and automatic schema migrations.
//!
//! ## Features
//!
//! - **Database Initialization**: Creates the SQLite database file and migrations table if needed.
//! - **Connection Management**: Provides database connection pool management.
//! - **Migration Control**: Tracks and applies migrations manually, never automatically.
//! - **CLI Support**: Commands to create, list, and apply migrations.
//!
//! ## Migration System
//!
//! Migrations are stored in code as `Migration` structs, tracked in a `migrations` table.
//! CLI commands allow creating new migrations, listing pending ones, and applying them.

pub mod backup;
pub mod queries;

use sqlx::{
    Row, Sqlite,
    migrate::MigrateDatabase,
    sqlite::{SqlitePool, SqlitePoolOptions},
};
use std::collections::HashMap;
use tracing::{error, info, warn};

///////////////////////////////////////////////////////////////////////////////
//****                         Public Structs                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Database manager that handles initialization and migrations
pub struct DatabaseManager {
    pool: SqlitePool,
}

/// Represents a database migration with version and SQL
#[derive(Debug, Clone)]
pub struct Migration {
    pub version: u32,
    pub name: String,
    pub sql: String,
}

impl DatabaseManager {
    /// Create a new manager with a connection pool
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Connect to the database with optimized connection pool settings
    pub async fn connect_with_file_creation_optimized(
        database_url: &str,
    ) -> Result<Self, sqlx::Error> {
        info!(
            "Opening the Black Gate to: {} (with optimized connection pool)",
            database_url
        );

        // Create optimized connection pool
        let pool_options = SqlitePoolOptions::new()
            .max_connections(20) // Allow up to 20 concurrent connections
            .min_connections(5) // Keep 5 connections warm at all times
            .acquire_timeout(std::time::Duration::from_secs(5)) // 5 second timeout for acquiring connections
            .idle_timeout(std::time::Duration::from_secs(300)) // Close idle connections after 5 minutes
            .max_lifetime(std::time::Duration::from_secs(1800)); // Recreate connections every 30 minutes

        // if it does not exist, create and apply migrations then leave
        if !Sqlite::database_exists(database_url).await.unwrap_or(false) {
            // create
            info!("Database does not exist at {}, creating it", database_url);
            Sqlite::create_database(database_url).await?;

            // check with optimized pool
            let pool = pool_options.connect(database_url).await?;
            sqlx::query("SELECT 1").execute(&pool).await?;
            info!(
                "Database created successfully at {} with optimized connection pool",
                database_url
            );
            info!("Initializing migrations table...");

            // apply migrations (initialize)
            let db_manager = Self::new(pool);
            db_manager.apply_sqlite_optimizations().await?;
            db_manager.create_migrations_table().await?;
            info!("Migrations table created successfully.");
            db_manager.apply_pending_migrations().await?;

            info!("Initial migrations applied successfully.");
            info!("The Black Gate is ready to serve with optimized database performance.");
            return Ok(db_manager);
        }

        let pool = pool_options.connect(database_url).await?;
        sqlx::query("SELECT 1").execute(&pool).await?;
        info!(
            "Connected to existing database with optimized pool (max: 20, min: 5, warm connections)"
        );
        let db_manager = Self::new(pool);
        db_manager.apply_sqlite_optimizations().await?;
        Ok(db_manager)
    }

    /// Initialize the database by creating the migrations table if needed
    pub async fn initialize(&self) -> Result<(), sqlx::Error> {
        info!("Initializing database...");
        self.create_migrations_table().await?;
        let (_applied, pending) = self.migration_status().await?;
        if !pending.is_empty() {
            warn!("Pending migrations: {:?}", pending);
        } else {
            info!("No pending migrations. The Gate stands ready.");
        }
        Ok(())
    }

    /// Create the migrations tracking table
    async fn create_migrations_table(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get all available migrations in order
    fn get_migrations(&self) -> Vec<Migration> {
        vec![
            Migration {
                version: 1,
                name: "initial_schema".to_string(),
                sql: r#"
                    CREATE TABLE IF NOT EXISTS routes (
                        path TEXT PRIMARY KEY,
                        auth_type TEXT,
                        auth_value TEXT,
                        allowed_methods TEXT,
                        upstream TEXT NOT NULL,
                        backup_route_path TEXT,
                        oauth_token_url TEXT,
                        oauth_client_id TEXT,
                        oauth_client_secret TEXT,
                        oauth_scope TEXT,
                        jwt_secret TEXT,
                        jwt_algorithm TEXT,
                        jwt_issuer TEXT,
                        jwt_audience TEXT,
                        jwt_required_claims TEXT,
                        oidc_issuer TEXT,
                        oidc_client_id TEXT,
                        oidc_client_secret TEXT,
                        oidc_audience TEXT,
                        oidc_scope TEXT,
                        rate_limit_per_minute INTEGER DEFAULT 60,
                        rate_limit_per_hour INTEGER DEFAULT 1000,
                        health_endpoint TEXT
                    );
                    CREATE TABLE IF NOT EXISTS request_metrics (
                        id TEXT PRIMARY KEY,
                        path TEXT NOT NULL,
                        method TEXT NOT NULL,
                        request_timestamp TEXT NOT NULL,
                        response_timestamp TEXT,
                        duration_ms INTEGER,
                        request_size_bytes INTEGER NOT NULL,
                        response_size_bytes INTEGER,
                        response_status_code INTEGER,
                        upstream_url TEXT,
                        auth_type TEXT NOT NULL,
                        client_ip TEXT,
                        user_agent TEXT,
                        error_message TEXT,
                        payload TEXT
                    );
                    CREATE TABLE IF NOT EXISTS route_health_checks (
                        path TEXT PRIMARY KEY,
                        health_check_status TEXT NOT NULL DEFAULT 'Unknown',
                        response_time_ms INTEGER,
                        error_message TEXT,
                        checked_at TEXT NOT NULL,
                        method_used TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        description TEXT,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    -- Default test route
                    INSERT INTO routes (path, upstream, allowed_methods) VALUES
                        ('/api/test', 'https://httpbin.org/get', 'GET');
                    -- Default settings
                    INSERT INTO settings (key, value, description) VALUES
                        ('default_rate_limit_per_minute', '0', 'Default rate limit per minute for new routes'),
                        ('default_rate_limit_per_hour', '0', 'Default rate limit per hour for new routes'),
                        ('health_check_interval_seconds', '60', 'Health check interval in seconds, requries restart');
                "#.to_string(),
            },
            Migration {
                version: 2,
                name: "route_collections".to_string(),
                sql: r#"
                    -- Route Collections table
                    CREATE TABLE IF NOT EXISTS route_collections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        description TEXT,
                        -- Default authentication settings for the collection
                        default_auth_type TEXT DEFAULT 'none',
                        default_auth_value TEXT,
                        -- OAuth defaults
                        default_oauth_token_url TEXT,
                        default_oauth_client_id TEXT,
                        default_oauth_client_secret TEXT,
                        default_oauth_scope TEXT,
                        -- JWT defaults
                        default_jwt_secret TEXT,
                        default_jwt_algorithm TEXT DEFAULT 'HS256',
                        default_jwt_issuer TEXT,
                        default_jwt_audience TEXT,
                        default_jwt_required_claims TEXT,
                        -- OIDC defaults
                        default_oidc_issuer TEXT,
                        default_oidc_client_id TEXT,
                        default_oidc_client_secret TEXT,
                        default_oidc_audience TEXT,
                        default_oidc_scope TEXT,
                        -- Default rate limiting
                        default_rate_limit_per_minute INTEGER,
                        default_rate_limit_per_hour INTEGER,
                        -- Metadata
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );

                    -- Add collection_id to routes table (nullable for backward compatibility)
                    ALTER TABLE routes ADD COLUMN collection_id INTEGER REFERENCES route_collections(id);

                    -- Create index for faster lookups
                    CREATE INDEX IF NOT EXISTS idx_routes_collection_id ON routes(collection_id);

                    -- Example collections
                    INSERT INTO route_collections (name, description, default_auth_type, default_rate_limit_per_minute, default_rate_limit_per_hour) VALUES
                        ('default', 'Default collection for uncategorized routes', 'none', 60, 1000),
                        ('api_v1', 'Version 1 API routes', 'jwt', 100, 5000),
                        ('public_api', 'Public API endpoints', 'api-key', 30, 500);
                "#.to_string(),
            },
            Migration {
                version: 3,
                name: "backup_history".to_string(),
                sql: r#"
                    -- Backup History table
                    CREATE TABLE IF NOT EXISTS backup_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        status TEXT NOT NULL,
                        started_at TEXT NOT NULL,
                        completed_at TEXT,
                        file_size_bytes INTEGER,
                        s3_key TEXT,
                        error_message TEXT,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );

                    -- Create index for faster lookups by status and date
                    CREATE INDEX IF NOT EXISTS idx_backup_history_status ON backup_history(status);
                    CREATE INDEX IF NOT EXISTS idx_backup_history_started_at ON backup_history(started_at);

                    -- Default backup settings
                    INSERT INTO settings (key, value, description) VALUES
                        ('backup_enabled', 'false', 'Enable automated database backups to S3'),
                        ('backup_interval_hours', '24', 'Hours between automated backup runs'),
                        ('backup_retention_days', '30', 'Days to keep backup files in S3');
                "#.to_string(),
            },
            Migration {
                version: 4,
                name: "response_cache_default_ttl".to_string(),
                sql: r#"
                    -- Default response cache settings
                    INSERT INTO settings (key, value, description)
                    VALUES ('response_cache_default_ttl', '15', 'Default TTL in seconds for response cache entries')
                    ON CONFLICT(key) DO UPDATE SET
                        value = EXCLUDED.value,
                        description = EXCLUDED.description,
                        updated_at = CURRENT_TIMESTAMP;
                "#.to_string(),
            },
            Migration {
                version: 5,
                name: "error_logging".to_string(),
                sql: r#"
                    -- Error logging table
                    CREATE TABLE IF NOT EXISTS error_logs (
                        id TEXT PRIMARY KEY,
                        error_message TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        context TEXT,
                        file_location TEXT,
                        line_number INTEGER,
                        function_name TEXT,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );

                    -- Create index for faster lookups by severity and date
                    CREATE INDEX IF NOT EXISTS idx_error_logs_severity ON error_logs(severity);
                    CREATE INDEX IF NOT EXISTS idx_error_logs_created_at ON error_logs(created_at);

                    -- Default error log retention setting
                    INSERT INTO settings (key, value, description)
                    VALUES ('error_log_retention_days', '7', 'Days to keep error log entries in database')
                    ON CONFLICT(key) DO UPDATE SET
                        value = EXCLUDED.value,
                        description = EXCLUDED.description,
                        updated_at = CURRENT_TIMESTAMP;
                "#.to_string(),
            },
        ]
    }

    /// Get applied migrations as a map (version -> name)
    async fn get_applied_migrations(&self) -> Result<HashMap<u32, String>, sqlx::Error> {
        let rows = sqlx::query("SELECT version, name FROM migrations ORDER BY version")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get("version"), row.get("name")))
            .collect())
    }

    /// Check migration status: returns (applied, pending) versions
    pub async fn migration_status(&self) -> Result<(Vec<u32>, Vec<u32>), sqlx::Error> {
        let all_migrations = self.get_migrations();
        let applied_migrations = self.get_applied_migrations().await?;
        let mut applied = Vec::new();
        let mut pending = Vec::new();

        for migration in all_migrations {
            if applied_migrations.contains_key(&migration.version) {
                applied.push(migration.version);
            } else {
                pending.push(migration.version);
            }
        }

        applied.sort();
        pending.sort();
        Ok((applied, pending))
    }

    /// Apply all pending migrations in order
    pub async fn apply_pending_migrations(&self) -> Result<(), sqlx::Error> {
        let migrations = self.get_migrations();
        let applied_migrations = self.get_applied_migrations().await?;

        for migration in migrations {
            if !applied_migrations.contains_key(&migration.version) {
                info!(
                    "Applying migration {}: {}",
                    migration.version, migration.name
                );
                sqlx::query(&migration.sql)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        error!("Failed to apply migration {}: {}", migration.version, e);
                        e
                    })?;
                sqlx::query("INSERT INTO migrations (version, name) VALUES (?, ?)")
                    .bind(migration.version)
                    .bind(&migration.name)
                    .execute(&self.pool)
                    .await?;
                info!(
                    "Applied migration {}: {}",
                    migration.version, migration.name
                );
            }
        }
        Ok(())
    }

    /// Apply a specific migration by version (for manual control)
    pub async fn apply_migration(&self, version: u32) -> Result<(), Box<dyn std::error::Error>> {
        let migrations = self.get_migrations();
        let migration = migrations
            .into_iter()
            .find(|m| m.version == version)
            .ok_or_else(|| format!("Migration version {} not found", version))?;

        let applied_migrations = self.get_applied_migrations().await?;
        if applied_migrations.contains_key(&version) {
            return Err(format!("Migration {} already applied", version).into());
        }

        info!(
            "Applying migration {}: {}",
            migration.version, migration.name
        );
        sqlx::query(&migration.sql).execute(&self.pool).await?;
        sqlx::query("INSERT INTO migrations (version, name) VALUES (?, ?)")
            .bind(migration.version)
            .bind(&migration.name)
            .execute(&self.pool)
            .await?;
        info!(
            "Applied migration {}: {}",
            migration.version, migration.name
        );
        Ok(())
    }

    /// Create a new migration template (for CLI)
    pub fn create_migration_template(&self, name: &str) -> Migration {
        let migrations = self.get_migrations();
        let next_version = migrations.iter().map(|m| m.version).max().unwrap_or(0) + 1;
        Migration {
            version: next_version,
            name: name.to_string(),
            sql: "-- SQL for migration goes here".to_string(),
        }
    }

    /// Warm up the connection pool by creating and testing connections
    pub async fn warm_connection_pool(&self) -> Result<(), sqlx::Error> {
        info!("Warming up database connection pool...");

        // Create several connections in parallel to warm up the pool
        let mut handles = Vec::new();
        for i in 0..5 {
            // Warm up 5 connections (our min_connections setting)
            let pool = self.pool.clone();
            let handle = tokio::spawn(async move {
                let result = sqlx::query("SELECT 1 as warm_check").fetch_one(&pool).await;
                match result {
                    Ok(_) => tracing::debug!("Warm connection {} ready", i),
                    Err(e) => tracing::warn!("Failed to warm connection {}: {}", i, e),
                }
            });
            handles.push(handle);
        }

        // Wait for all connections to be warmed up
        let mut successful = 0;
        for handle in handles {
            if let Ok(_result) = handle.await {
                successful += 1;
            }
        }

        info!(
            "Database connection pool warmed up: {}/5 connections ready",
            successful
        );
        Ok(())
    }

    /// Get the connection pool.
    #[allow(dead_code)]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Apply SQLite performance optimizations
    async fn apply_sqlite_optimizations(&self) -> Result<(), sqlx::Error> {
        info!("Applying SQLite performance optimizations...");

        // Enable WAL mode for better concurrency
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&self.pool)
            .await?;

        // Optimize synchronous mode for better performance
        sqlx::query("PRAGMA synchronous = NORMAL")
            .execute(&self.pool)
            .await?;

        // Increase cache size (negative value means KB, positive means pages)
        sqlx::query("PRAGMA cache_size = -64000")
            .execute(&self.pool)
            .await?; // 64MB cache

        // Optimize temp storage
        sqlx::query("PRAGMA temp_store = MEMORY")
            .execute(&self.pool)
            .await?;

        // Set busy timeout to handle concurrent access
        sqlx::query("PRAGMA busy_timeout = 5000")
            .execute(&self.pool)
            .await?; // 5 seconds

        // Enable query optimization
        sqlx::query("PRAGMA optimize").execute(&self.pool).await?;

        info!("SQLite performance optimizations applied successfully");
        Ok(())
    }
}

/// CLI command implementations for migrations.
pub struct MigrationCli {
    db_manager: DatabaseManager,
}

impl MigrationCli {
    pub fn new(db_manager: DatabaseManager) -> Self {
        Self { db_manager }
    }

    /// CLI command: List migration status
    pub async fn list_migrations(&self) -> Result<(), sqlx::Error> {
        let (applied, pending) = self.db_manager.migration_status().await?;
        println!("Applied migrations: {:?}", applied);
        println!("Pending migrations: {:?}", pending);
        Ok(())
    }

    /// CLI command: Apply all pending migrations
    pub async fn apply_migrations(&self) -> Result<(), sqlx::Error> {
        self.db_manager.apply_pending_migrations().await?;
        println!("All pending migrations applied.");
        Ok(())
    }

    pub async fn apply_migration(&self, version: u32) -> Result<(), Box<dyn std::error::Error>> {
        self.db_manager.apply_migration(version).await?;
        println!("Migration {} applied successfully.", version);
        Ok(())
    }

    /// CLI command: Create a new migration template
    pub fn create_migration(&self, name: &str) {
        let migration = self.db_manager.create_migration_template(name);
        println!(
            "New migration template (add to get_migrations):\n\
            \tMigration {{\n\
            \t\tversion: {},\n\
            \t\tname: \"{}\".to_string(),\n\
            \t\tsql: \"{}\".to_string(),\n\
            \t}},",
            migration.version, migration.name, migration.sql
        );
    }

    /// CLI command: View the schema all tables in the database
    pub async fn view_schema(&self) -> Result<(), sqlx::Error> {
        let tables = sqlx::query("SELECT name FROM sqlite_master WHERE type='table'")
            .fetch_all(&self.db_manager.pool)
            .await?;

        for table in tables {
            let table_name: String = table.get("name");
            println!("Schema for table '{}':", table_name);
            let schema = sqlx::query(&format!("PRAGMA table_info({})", table_name))
                .fetch_all(&self.db_manager.pool)
                .await?;
            for column in schema {
                println!(
                    "\t{}: {} ({})",
                    column.get::<String, _>("name"),
                    column.get::<String, _>("type"),
                    if column.get::<i64, _>("pk") > 0 {
                        "PK"
                    } else {
                        ""
                    }
                );
            }
        }
        Ok(())
    }
}

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Initialize the database with optimized connection pool settings
pub async fn initialize_database(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    let db_manager = DatabaseManager::connect_with_file_creation_optimized(database_url).await?;
    db_manager.initialize().await?;
    db_manager.warm_connection_pool().await?;
    Ok(db_manager.pool)
}

///////////////////////////////////////////////////////////////////////////////
//****                              Tests                                ****//
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn create_test_db() -> DatabaseManager {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("Failed to create in-memory database");
        DatabaseManager::new(pool)
    }

    #[tokio::test]
    async fn test_initialize_creates_migrations_table() {
        let db = create_test_db().await;
        db.initialize().await.unwrap();
        let result = sqlx::query("SELECT COUNT(*) FROM migrations")
            .fetch_one(db.pool())
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_migration_status() {
        let db = create_test_db().await;
        db.initialize().await.unwrap();
        let (applied, pending) = db.migration_status().await.unwrap();
        assert!(applied.is_empty());
        assert_eq!(pending, vec![1]); // Only one migration exists
    }

    #[tokio::test]
    async fn test_apply_migration() {
        let db = create_test_db().await;
        db.initialize().await.unwrap();
        db.apply_migration(1).await.unwrap();
        let (applied, pending) = db.migration_status().await.unwrap();
        assert_eq!(applied, vec![1]);
        assert!(pending.is_empty()); // No pending migrations after applying the only one
    }
}
