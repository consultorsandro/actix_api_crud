// Database configuration - Configuração e inicialização do banco de dados

use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

use crate::errors::AppError;

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
}

impl DatabaseConfig {
    pub fn from_url(url: String) -> Self {
        Self {
            url,
            max_connections: 10,
            min_connections: 1,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        }
    }

    pub fn with_max_connections(mut self, max_connections: u32) -> Self {
        self.max_connections = max_connections;
        self
    }

    pub fn with_min_connections(mut self, min_connections: u32) -> Self {
        self.min_connections = min_connections;
        self
    }
}

pub async fn create_connection_pool(config: &DatabaseConfig) -> Result<PgPool, AppError> {
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.connect_timeout)
        .idle_timeout(config.idle_timeout)
        .connect(&config.url)
        .await
        .map_err(|e| AppError::Database(format!("Failed to create connection pool: {}", e)))
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), AppError> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| AppError::Database(format!("Failed to run migrations: {}", e)))
}

pub async fn test_connection(pool: &PgPool) -> Result<(), AppError> {
    sqlx::query("SELECT 1")
        .execute(pool)
        .await
        .map_err(|e| AppError::Database(format!("Database connection test failed: {}", e)))?;
    
    Ok(())
}
