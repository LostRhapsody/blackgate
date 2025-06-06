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

use sqlx::{sqlite::SqlitePool, Row};
use tracing::{info, warn, error};
use std::collections::HashMap;

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

    /// Connect to the database, creating the file if it doesn't exist
    pub async fn connect_with_file_creation(database_url: &str) -> Result<Self, sqlx::Error> {
        info!("Opening the Black Gate to: {}", database_url);

        if database_url.starts_with("sqlite://") {
            let file_path = &database_url[9..];
            if !std::path::Path::new(file_path).exists() {
                info!("No database found at {}, forging a new one", file_path);
                let temp_pool = SqlitePool::connect(database_url).await?;
                sqlx::query("SELECT 1").execute(&temp_pool).await?;
                temp_pool.close().await;
            }
        }

        let pool = SqlitePool::connect(database_url).await?;
        sqlx::query("SELECT 1").execute(&pool).await?;
        Ok(Self::new(pool))
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
            Migration {
                version: 5,
                name: "add_route_status".to_string(),
                sql: "ALTER TABLE routes ADD COLUMN status TEXT DEFAULT '';".to_string(),
            },
            Migration {
                version: 6,
                name: "add_request_metrics_payload".to_string(),
                sql: "ALTER TABLE request_metrics ADD COLUMN payload TEXT DEFAULT '';".to_string(),
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
                info!("Applying migration {}: {}", migration.version, migration.name);
                sqlx::query(&migration.sql).execute(&self.pool).await.map_err(|e| {
                    error!("Failed to apply migration {}: {}", migration.version, e);
                    e
                })?;
                sqlx::query("INSERT INTO migrations (version, name) VALUES (?, ?)")
                    .bind(migration.version)
                    .bind(&migration.name)
                    .execute(&self.pool)
                    .await?;
                info!("Applied migration {}: {}", migration.version, migration.name);
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

        info!("Applying migration {}: {}", migration.version, migration.name);
        sqlx::query(&migration.sql).execute(&self.pool).await?;
        sqlx::query("INSERT INTO migrations (version, name) VALUES (?, ?)")
            .bind(migration.version)
            .bind(&migration.name)
            .execute(&self.pool)
            .await?;
        info!("Applied migration {}: {}", migration.version, migration.name);
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

    /// Get the connection pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
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
                    if column.get::<i64, _>("pk") > 0 { "PK" } else { "" }
                );
            }
        }
        Ok(())
    }
}

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Initialize the database with default settings
pub async fn initialize_database(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    let db_manager = DatabaseManager::connect_with_file_creation(database_url).await?;
    db_manager.initialize().await?;
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
        assert_eq!(pending, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_apply_migration() {
        let db = create_test_db().await;
        db.initialize().await.unwrap();
        db.apply_migration(1).await.unwrap();
        let (applied, pending) = db.migration_status().await.unwrap();
        assert_eq!(applied, vec![1]);
        assert_eq!(pending, vec![2, 3]);
    }
}