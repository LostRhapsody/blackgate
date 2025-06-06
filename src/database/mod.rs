//! # Database Module
//! 
//! This module provides database management functionality for the Black Gate API Gateway.
//! It handles database initialization, connection management, and automatic schema migrations.
//! 
//! ## Features
//! 
//! - **Database Initialization**: Creates database and required tables if they don't exist
//! - **Schema Migrations**: Automatic migration system for database schema updates
//! - **Connection Management**: Provides database connection pool management
//! - **Migration CLI**: Support for CLI-driven database migrations
//! 
//! ## Migration System
//! 
//! The migration system tracks applied migrations in a `migrations` table and applies
//! new migrations in order. Each migration has a version number and SQL statements.

use sqlx::{sqlite::SqlitePool, Row};
use tracing::{info, error};
use std::collections::HashMap;

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
    /// Create a new database manager with the given connection pool
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Initialize the database with required tables and run migrations
    pub async fn initialize(&self) -> Result<(), sqlx::Error> {
        info!("Initializing database...");
        
        // First, create the migrations table to track applied migrations
        self.create_migrations_table().await?;
        
        // Get all available migrations
        let migrations = self.get_migrations();
        
        // Apply any pending migrations
        self.apply_migrations(&migrations).await?;
        
        info!("Database initialization complete");
        Ok(())
    }

    /// Initialize only the migrations table without applying any migrations
    #[allow(dead_code)]
    pub async fn initialize_migrations_table_only(&self) -> Result<(), sqlx::Error> {
        info!("Initializing migrations table only...");
        self.create_migrations_table().await?;
        info!("Migrations table created");
        Ok(())
    }

    /// Create the migrations tracking table
    async fn create_migrations_table(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"
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
                        rate_limit_per_hour INTEGER DEFAULT 1000
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
                        error_message TEXT
                    );
                "#.to_string(),
            },
            // Add future migrations here
            Migration {
                version: 2,
                name: "add_route_description_column".to_string(),
                sql: "ALTER TABLE routes ADD COLUMN description TEXT DEFAULT '';".to_string(),
            },
            Migration {
                version: 3,
                name: "add_route_tags_column".to_string(),
                sql: "ALTER TABLE routes ADD COLUMN tags TEXT DEFAULT '';".to_string(),
            },
            // Migration {
            //     version: 4,
            //     name: "add_new_column".to_string(),
            //     sql: "ALTER TABLE routes ADD COLUMN new_column TEXT;".to_string(),
            // },
        ]
    }

    /// Apply all pending migrations
    async fn apply_migrations(&self, migrations: &[Migration]) -> Result<(), sqlx::Error> {
        // Get applied migrations
        let applied_migrations = self.get_applied_migrations().await?;
        
        for migration in migrations {
            if !applied_migrations.contains_key(&migration.version) {
                info!("Applying migration {} ({})", migration.version, migration.name);
                
                // Execute the migration SQL
                sqlx::query(&migration.sql)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        error!("Failed to apply migration {}: {}", migration.version, e);
                        e
                    })?;
                
                // Record the migration as applied
                sqlx::query(
                    "INSERT INTO migrations (version, name) VALUES (?, ?)"
                )
                .bind(migration.version)
                .bind(&migration.name)
                .execute(&self.pool)
                .await?;
                
                info!("Successfully applied migration {} ({})", migration.version, migration.name);
            }
        }
        
        Ok(())
    }

    /// Get a map of applied migrations (version -> name)
    async fn get_applied_migrations(&self) -> Result<HashMap<u32, String>, sqlx::Error> {
        let rows = sqlx::query("SELECT version, name FROM migrations ORDER BY version")
            .fetch_all(&self.pool)
            .await?;
        
        let mut applied = HashMap::new();
        for row in rows {
            let version: u32 = row.get("version");
            let name: String = row.get("name");
            applied.insert(version, name);
        }
        
        Ok(applied)
    }

    /// Check migration status - returns list of applied and pending migrations
    pub async fn migration_status(&self) -> Result<(Vec<u32>, Vec<u32>), sqlx::Error> {
        let all_migrations = self.get_migrations();
        let applied_migrations = self.get_applied_migrations().await?;
        
        let mut applied_versions = Vec::new();
        let mut pending_versions = Vec::new();
        
        for migration in all_migrations {
            if applied_migrations.contains_key(&migration.version) {
                applied_versions.push(migration.version);
            } else {
                pending_versions.push(migration.version);
            }
        }
        
        applied_versions.sort();
        pending_versions.sort();
        
        Ok((applied_versions, pending_versions))
    }

    /// Force apply a specific migration (use with caution)
    pub async fn apply_migration(&self, version: u32) -> Result<(), Box<dyn std::error::Error>> {
        let migrations = self.get_migrations();
        let migration = migrations
            .iter()
            .find(|m| m.version == version)
            .ok_or(format!("Migration version {} not found", version))?;
        
        let applied_migrations = self.get_applied_migrations().await?;
        
        if applied_migrations.contains_key(&version) {
            return Err(format!("Migration {} is already applied", version).into());
        }
        
        info!("Force applying migration {} ({})", migration.version, migration.name);
        
        // Execute the migration SQL
        sqlx::query(&migration.sql)
            .execute(&self.pool)
            .await?;
        
        // Record the migration as applied
        sqlx::query("INSERT INTO migrations (version, name) VALUES (?, ?)")
            .bind(migration.version)
            .bind(&migration.name)
            .execute(&self.pool)
            .await?;
        
        info!("Successfully applied migration {} ({})", migration.version, migration.name);
        Ok(())
    }

    /// Get the database connection pool
    #[allow(dead_code)]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Create a new database connection and return a DatabaseManager
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        info!("Connecting to database: {}", database_url);
        
        let pool = SqlitePool::connect(database_url).await?;
        
        // Test the connection by executing a simple query
        sqlx::query("SELECT 1").execute(&pool).await?;
        
        Ok(Self::new(pool))
    }

    /// Connect and ensure database file exists with minimal setup
    pub async fn connect_with_file_creation(database_url: &str) -> Result<Self, sqlx::Error> {
        info!("Connecting to database with file creation: {}", database_url);
        
        // Extract the file path from the database URL for SQLite
        if database_url.starts_with("sqlite://") {
            let file_path = &database_url[9..]; // Remove "sqlite://" prefix
            
            // If file doesn't exist, create it by connecting and disconnecting
            if !std::path::Path::new(file_path).exists() {
                info!("Database file doesn't exist, creating: {}", file_path);
                
                // Create a temporary connection to ensure the file is created
                let temp_pool = SqlitePool::connect(database_url).await?;
                
                // Execute a simple query to ensure the database file is created
                sqlx::query("SELECT 1").execute(&temp_pool).await?;
                
                // Close the temporary connection
                temp_pool.close().await;
            }
        }
        
        // Now connect normally
        Self::connect(database_url).await
    }
}

/// Initialize the database with default settings
pub async fn initialize_database(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    let db_manager = DatabaseManager::connect(database_url).await?;
    db_manager.initialize().await?;
    Ok(db_manager.pool)
}

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
    async fn test_database_initialization() {
        let db_manager = create_test_db().await;
        
        // Initialize should work without errors
        assert!(db_manager.initialize().await.is_ok());
        
        // Check that migrations table exists
        let result = sqlx::query("SELECT COUNT(*) as count FROM migrations")
            .fetch_one(db_manager.pool())
            .await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_migration_status() {
        let db_manager = create_test_db().await;
        db_manager.initialize().await.unwrap();
        
        let (applied, _pending) = db_manager.migration_status().await.unwrap();
        
        // Should have at least the initial migration applied
        assert!(!applied.is_empty());
        assert!(applied.contains(&1));
    }

    #[tokio::test]
    async fn test_tables_created() {
        let db_manager = create_test_db().await;
        db_manager.initialize().await.unwrap();
        
        // Check that routes table exists and has expected structure
        let result = sqlx::query("SELECT path, upstream FROM routes LIMIT 0")
            .fetch_all(db_manager.pool())
            .await;
        
        assert!(result.is_ok());
        
        // Check that request_metrics table exists
        let result = sqlx::query("SELECT id, path, method FROM request_metrics LIMIT 0")
            .fetch_all(db_manager.pool())
            .await;
        
        assert!(result.is_ok());
    }
}