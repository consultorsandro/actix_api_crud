use std::env;

/// Configurações de segurança da aplicação
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub jwt_secret: String,
    pub jwt_expiration_hours: u64,
    pub bcrypt_cost: u32,
    pub cors_allowed_origins: Vec<String>,
    pub rate_limit_enabled: bool,
    pub security_headers_enabled: bool,
    pub input_sanitization_enabled: bool,
    pub https_only: bool,
    pub session_timeout_minutes: u64,
}

impl SecurityConfig {
    /// Carrega configurações de segurança do ambiente
    pub fn from_env() -> Self {
        Self {
            jwt_secret: env::var("JWT_SECRET")
                .expect("JWT_SECRET must be set"),
            jwt_expiration_hours: env::var("JWT_EXPIRATION_HOURS")
                .unwrap_or_else(|_| "24".to_string())
                .parse()
                .unwrap_or(24),
            bcrypt_cost: env::var("BCRYPT_COST")
                .unwrap_or_else(|_| "12".to_string())
                .parse()
                .unwrap_or(12),
            cors_allowed_origins: env::var("CORS_ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:3000,http://localhost:8080".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            rate_limit_enabled: env::var("RATE_LIMIT_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            security_headers_enabled: env::var("SECURITY_HEADERS_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            input_sanitization_enabled: env::var("INPUT_SANITIZATION_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            https_only: env::var("HTTPS_ONLY")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            session_timeout_minutes: env::var("SESSION_TIMEOUT_MINUTES")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .unwrap_or(60),
        }
    }

    /// Validações de configuração
    pub fn validate(&self) -> Result<(), String> {
        // Validar JWT secret
        if self.jwt_secret.len() < 32 {
            return Err("JWT_SECRET must be at least 32 characters long".to_string());
        }

        // Validar bcrypt cost
        if self.bcrypt_cost < 4 || self.bcrypt_cost > 31 {
            return Err("BCRYPT_COST must be between 4 and 31".to_string());
        }

        // Validar JWT expiration
        if self.jwt_expiration_hours == 0 || self.jwt_expiration_hours > 168 {
            return Err("JWT_EXPIRATION_HOURS must be between 1 and 168 (1 week)".to_string());
        }

        // Validar session timeout
        if self.session_timeout_minutes == 0 || self.session_timeout_minutes > 1440 {
            return Err("SESSION_TIMEOUT_MINUTES must be between 1 and 1440 (24 hours)".to_string());
        }

        Ok(())
    }

    /// Configuração para desenvolvimento
    pub fn development() -> Self {
        Self {
            jwt_secret: "development_secret_key_32_chars_minimum".to_string(),
            jwt_expiration_hours: 24,
            bcrypt_cost: 4, // Mais rápido para desenvolvimento
            cors_allowed_origins: vec![
                "http://localhost:3000".to_string(),
                "http://localhost:8080".to_string(),
                "http://127.0.0.1:3000".to_string(),
                "http://127.0.0.1:8080".to_string(),
            ],
            rate_limit_enabled: false, // Desabilitado para desenvolvimento
            security_headers_enabled: true,
            input_sanitization_enabled: true,
            https_only: false,
            session_timeout_minutes: 480, // 8 horas para desenvolvimento
        }
    }

    /// Configuração para produção
    pub fn production() -> Self {
        let mut config = Self::from_env();
        
        // Configurações mais restritivas para produção
        config.bcrypt_cost = config.bcrypt_cost.max(12);
        config.https_only = true;
        config.rate_limit_enabled = true;
        config.security_headers_enabled = true;
        config.input_sanitization_enabled = true;
        
        config
    }

    /// Verifica se está em modo de desenvolvimento
    pub fn is_development() -> bool {
        matches!(env::var("RUST_ENV").as_deref(), Ok("development") | Err(_))
    }

    /// Verifica se está em modo de produção
    pub fn is_production() -> bool {
        env::var("RUST_ENV").as_deref() == Ok("production")
    }
}

/// Rate limiting configurations
#[derive(Debug, Clone)]
pub struct RateLimitSettings {
    pub general_per_minute: u32,
    pub auth_per_minute: u32,
    pub creation_per_minute: u32,
    pub password_change_per_hour: u32,
}

impl RateLimitSettings {
    pub fn from_env() -> Self {
        Self {
            general_per_minute: env::var("RATE_LIMIT_GENERAL")
                .unwrap_or_else(|_| "100".to_string())
                .parse()
                .unwrap_or(100),
            auth_per_minute: env::var("RATE_LIMIT_AUTH")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .unwrap_or(10),
            creation_per_minute: env::var("RATE_LIMIT_CREATION")
                .unwrap_or_else(|_| "20".to_string())
                .parse()
                .unwrap_or(20),
            password_change_per_hour: env::var("RATE_LIMIT_PASSWORD_CHANGE")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .unwrap_or(5),
        }
    }

    pub fn development() -> Self {
        Self {
            general_per_minute: 1000,    // Mais permissivo
            auth_per_minute: 100,        // Mais permissivo
            creation_per_minute: 200,    // Mais permissivo
            password_change_per_hour: 50, // Mais permissivo
        }
    }

    pub fn production() -> Self {
        Self {
            general_per_minute: 60,      // Mais restritivo
            auth_per_minute: 5,          // Mais restritivo
            creation_per_minute: 10,     // Mais restritivo
            password_change_per_hour: 3, // Mais restritivo
        }
    }
}
