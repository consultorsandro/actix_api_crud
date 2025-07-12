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
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
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
                    .unwrap_or(30),
            ),
            idle_timeout: Duration::from_secs(
                std::env::var("DB_IDLE_TIMEOUT")
                    .ok()
                    .and_then(|val| val.parse().ok())
                    .unwrap_or(600),
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

    pub fn validate(&self) -> Result<(), String> {
        if self.max_connections == 0 {
            return Err("max_connections must be greater than 0".to_string());
        }
        if self.min_connections == 0 {
            return Err("min_connections must be greater than 0".to_string());
        }
        if self.min_connections > self.max_connections {
            return Err("min_connections cannot be greater than max_connections".to_string());
        }
        if !self.url.starts_with("postgresql://") && !self.url.starts_with("postgres://") {
            return Err("DATABASE_URL must start with postgresql:// or postgres://".to_string());
        }
        Ok(())
    }

    pub fn development() -> Self {
        Self {
            url: "postgresql://postgres:postgres@localhost:5432/actix_crud_dev".to_string(),
            max_connections: 5,
            min_connections: 1,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        }
    }

    pub fn production() -> Self {
        Self {
            url: std::env::var("DATABASE_URL").expect("DATABASE_URL must be set in production"),
            max_connections: 20,
            min_connections: 5,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        }
    }

    pub fn test() -> Self {
        Self {
            url: "postgresql://postgres:postgres@localhost:5432/test_db".to_string(),
            max_connections: 2,
            min_connections: 1,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    #[test]
    #[serial]
    fn test_database_config_from_env() {
        unsafe {
            env::set_var(
                "DATABASE_URL",
                "postgresql://test:test@localhost:5432/test_db",
            );
            env::set_var("DB_MAX_CONNECTIONS", "20");
            env::set_var("DB_MIN_CONNECTIONS", "5");
            env::set_var("DB_CONNECT_TIMEOUT", "60");
            env::set_var("DB_IDLE_TIMEOUT", "300");
        }

        let config = DatabaseConfig::from_env();

        assert_eq!(config.url, "postgresql://test:test@localhost:5432/test_db");
        assert_eq!(config.max_connections, 20);
        assert_eq!(config.min_connections, 5);
        assert_eq!(config.connect_timeout, Duration::from_secs(60));
        assert_eq!(config.idle_timeout, Duration::from_secs(300));

        unsafe {
            env::remove_var("DATABASE_URL");
            env::remove_var("DB_MAX_CONNECTIONS");
            env::remove_var("DB_MIN_CONNECTIONS");
            env::remove_var("DB_CONNECT_TIMEOUT");
            env::remove_var("DB_IDLE_TIMEOUT");
        }
    }

    #[test]
    #[serial]
    fn test_database_config_default_values() {
        unsafe {
            env::remove_var("DATABASE_URL");
            env::remove_var("DB_MAX_CONNECTIONS");
            env::remove_var("DB_MIN_CONNECTIONS");
            env::remove_var("DB_CONNECT_TIMEOUT");
            env::remove_var("DB_IDLE_TIMEOUT");
        }

        let config = DatabaseConfig::from_env();

        assert_eq!(
            config.url,
            "postgresql://postgres:postgres@localhost:5432/actix_crud_db"
        );
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.min_connections, 1);
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert_eq!(config.idle_timeout, Duration::from_secs(600));
    }

    #[test]
    fn test_database_config_from_url() {
        let test_url = "postgresql://custom:password@example.com:5432/custom_db".to_string();
        let config = DatabaseConfig::from_url(test_url.clone());

        assert_eq!(config.url, test_url);
        assert_eq!(config.max_connections, 10); // Default values
        assert_eq!(config.min_connections, 1);
    }

    #[test]
    #[serial]
    fn test_database_config_invalid_numbers() {
        unsafe {
            env::set_var(
                "DATABASE_URL",
                "postgresql://test:test@localhost:5432/test_db",
            );
            env::set_var("DB_MAX_CONNECTIONS", "invalid");
            env::set_var("DB_MIN_CONNECTIONS", "invalid");
            env::set_var("DB_CONNECT_TIMEOUT", "invalid");
            env::set_var("DB_IDLE_TIMEOUT", "invalid");
        }

        let config = DatabaseConfig::from_env();

        // Should use default values when parsing fails
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.min_connections, 1);
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert_eq!(config.idle_timeout, Duration::from_secs(600));

        unsafe {
            env::remove_var("DATABASE_URL");
            env::remove_var("DB_MAX_CONNECTIONS");
            env::remove_var("DB_MIN_CONNECTIONS");
            env::remove_var("DB_CONNECT_TIMEOUT");
            env::remove_var("DB_IDLE_TIMEOUT");
        }
    }

    #[test]
    fn test_database_config_validation() {
        let valid_config = DatabaseConfig {
            url: "postgresql://user:pass@localhost:5432/db".to_string(),
            max_connections: 10,
            min_connections: 1,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        };

        let result = valid_config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_database_config_validation_invalid_max_connections() {
        let invalid_config = DatabaseConfig {
            url: "postgresql://user:pass@localhost:5432/db".to_string(),
            max_connections: 0, // Invalid
            min_connections: 1,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        };

        let result = invalid_config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max_connections"));
    }

    #[test]
    fn test_database_config_validation_min_greater_than_max() {
        let invalid_config = DatabaseConfig {
            url: "postgresql://user:pass@localhost:5432/db".to_string(),
            max_connections: 5,
            min_connections: 10, // Greater than max
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        };

        let result = invalid_config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("min_connections"));
    }

    #[test]
    fn test_database_config_validation_invalid_url() {
        let invalid_config = DatabaseConfig {
            url: "invalid_url".to_string(), // Invalid URL
            max_connections: 10,
            min_connections: 1,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        };

        let result = invalid_config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("DATABASE_URL"));
    }

    #[test]
    fn test_database_config_development() {
        let config = DatabaseConfig::development();

        assert!(config.url.contains("localhost"));
        assert!(config.url.contains("actix_crud_dev"));
        assert_eq!(config.max_connections, 5);
        assert_eq!(config.min_connections, 1);
    }

    #[test]
    #[serial]
    fn test_database_config_production() {
        unsafe {
            env::set_var(
                "DATABASE_URL",
                "postgresql://prod:secret@prod-server:5432/prod_db",
            );
        }

        let config = DatabaseConfig::production();

        assert_eq!(
            config.url,
            "postgresql://prod:secret@prod-server:5432/prod_db"
        );
        assert_eq!(config.max_connections, 20);
        assert_eq!(config.min_connections, 5);

        unsafe {
            env::remove_var("DATABASE_URL");
        }
    }

    #[test]
    fn test_database_config_test() {
        let config = DatabaseConfig::test();

        assert!(config.url.contains("test"));
        assert_eq!(config.max_connections, 2);
        assert_eq!(config.min_connections, 1);
    }

    // Note: Os testes de conexão real com banco precisariam de um banco de teste
    // Para isso, você configuraria um container Docker ou banco em memória

    #[test]
    fn test_database_url_parsing() {
        let urls = vec![
            "postgresql://user:pass@localhost:5432/database",
            "postgres://user:pass@localhost:5432/database",
            "postgresql://user@localhost/database",
            "postgresql://localhost/database",
        ];

        for url in urls {
            let config = DatabaseConfig::from_url(url.to_string());
            assert_eq!(config.url, url);
        }
    }

    #[test]
    fn test_database_config_clone() {
        let config = DatabaseConfig::development();
        let cloned_config = config.clone();

        assert_eq!(config.url, cloned_config.url);
        assert_eq!(config.max_connections, cloned_config.max_connections);
        assert_eq!(config.min_connections, cloned_config.min_connections);
    }
}
