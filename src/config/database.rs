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
    pub fn from_env() -> Self {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| {
                "postgresql://postgres:postgres@localhost:5432/actix_crud_db".to_string()
            });

        Self {
            url: database_url,
            max_connections: std::env::var("DB_MAX_CONNECTIONS")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or(10),
            min_connections: std::env::var("DB_MIN_CONNECTIONS")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or(1),
            connect_timeout: Duration::from_secs(
                std::env::var("DB_CONNECT_TIMEOUT")
                    .ok()
                    .and_then(|val| val.parse().ok())
                    .unwrap_or(30)
            ),
            idle_timeout: Duration::from_secs(
                std::env::var("DB_IDLE_TIMEOUT")
                    .ok()
                    .and_then(|val| val.parse().ok())
                    .unwrap_or(600)
            ),
        }
    }

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
    log::info!("Creating database connection pool...");
    log::info!("Database URL: {}", config.url);
    log::info!("Max connections: {}", config.max_connections);
    log::info!("Min connections: {}", config.min_connections);

    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.connect_timeout)
        .idle_timeout(config.idle_timeout)
        .connect(&config.url)
        .await
        .map_err(|e| {
            log::error!("Failed to create connection pool: {}", e);
            AppError::Database(format!("Failed to create connection pool: {}", e))
        })?;

    log::info!("Database connection pool created successfully");

    // Teste a conexão
    test_connection(&pool).await?;
    
    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), AppError> {
    log::info!("Running database migrations...");
    
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| {
            log::error!("Failed to run migrations: {}", e);
            AppError::Database(format!("Failed to run migrations: {}", e))
        })?;

    log::info!("Database migrations completed successfully");
    Ok(())
}

pub async fn test_connection(pool: &PgPool) -> Result<(), AppError> {
    log::info!("Testing database connection...");
    
    sqlx::query("SELECT 1 as test")
        .fetch_one(pool)
        .await
        .map_err(|e| {
            log::error!("Database connection test failed: {}", e);
            AppError::Database(format!("Database connection test failed: {}", e))
        })?;
    
    log::info!("Database connection test successful");
    Ok(())
}

// Função para verificar se o banco de dados está disponível
pub async fn check_database_availability(database_url: &str) -> Result<(), AppError> {
    log::info!("Checking database availability...");
    
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .map_err(|e| {
            log::error!("Database is not available: {}", e);
            AppError::Database(format!("Database is not available: {}", e))
        })?;

    // Teste simples de conectividade
    sqlx::query("SELECT 1")
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            log::error!("Database connectivity test failed: {}", e);
            AppError::Database(format!("Database connectivity test failed: {}", e))
        })?;

    pool.close().await;
    log::info!("Database is available and responsive");
    Ok(())
}
