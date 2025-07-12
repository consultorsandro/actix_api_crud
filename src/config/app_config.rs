// App configuration - Configurações centralizadas da aplicação

use std::env;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub jwt_secret: String,
    pub app_port: u16,
    pub rust_env: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, env::VarError> {
        Ok(AppConfig {
            database_url: env::var("DATABASE_URL")?,
            jwt_secret: env::var("JWT_SECRET")?,
            app_port: env::var("APP_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .unwrap_or(8080),
            rust_env: env::var("RUST_ENV").unwrap_or_else(|_| "development".to_string()),
        })
    }

    pub fn is_production(&self) -> bool {
        self.rust_env == "production"
    }

    pub fn is_development(&self) -> bool {
        self.rust_env == "development"
    }
}
