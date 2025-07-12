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
            jwt_secret: env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
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
            return Err(
                "SESSION_TIMEOUT_MINUTES must be between 1 and 1440 (24 hours)".to_string(),
            );
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
            general_per_minute: 1000,     // Mais permissivo
            auth_per_minute: 100,         // Mais permissivo
            creation_per_minute: 200,     // Mais permissivo
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

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    #[test]
    #[serial]
    fn test_security_config_from_env() {
        // Set test environment variables
        unsafe {
            env::set_var("JWT_SECRET", "test_secret_key_with_32_characters");
            env::set_var("JWT_EXPIRATION_HOURS", "48");
            env::set_var("BCRYPT_COST", "10");
            env::set_var(
                "CORS_ALLOWED_ORIGINS",
                "http://localhost:3000,http://localhost:8080",
            );
            env::set_var("RATE_LIMIT_ENABLED", "true");
        }

        let config = SecurityConfig::from_env();

        assert_eq!(config.jwt_secret, "test_secret_key_with_32_characters");
        assert_eq!(config.jwt_expiration_hours, 48);
        assert_eq!(config.bcrypt_cost, 10);
        assert_eq!(config.cors_allowed_origins.len(), 2);
        assert!(config.rate_limit_enabled);

        // Clean up
        unsafe {
            env::remove_var("JWT_SECRET");
            env::remove_var("JWT_EXPIRATION_HOURS");
            env::remove_var("BCRYPT_COST");
            env::remove_var("CORS_ALLOWED_ORIGINS");
            env::remove_var("RATE_LIMIT_ENABLED");
        }
    }

    #[test]
    fn test_security_config_development() {
        let config = SecurityConfig::development();

        assert_eq!(config.jwt_secret, "development_secret_key_32_chars_minimum");
        assert_eq!(config.bcrypt_cost, 4);
        assert!(!config.rate_limit_enabled);
        assert!(!config.https_only);
        assert_eq!(config.session_timeout_minutes, 480);
    }

    #[test]
    #[serial]
    fn test_security_config_production() {
        // Set minimal required environment
        unsafe {
            env::set_var("JWT_SECRET", "production_secret_key_with_32_characters");
        }

        let config = SecurityConfig::production();

        assert!(config.bcrypt_cost >= 12);
        assert!(config.https_only);
        assert!(config.rate_limit_enabled);
        assert!(config.security_headers_enabled);

        // Clean up
        unsafe {
            env::remove_var("JWT_SECRET");
        }
    }

    #[test]
    fn test_security_config_validation_valid() {
        let config = SecurityConfig {
            jwt_secret: "valid_secret_key_with_32_characters".to_string(),
            jwt_expiration_hours: 24,
            bcrypt_cost: 12,
            cors_allowed_origins: vec!["http://localhost:3000".to_string()],
            rate_limit_enabled: true,
            security_headers_enabled: true,
            input_sanitization_enabled: true,
            https_only: false,
            session_timeout_minutes: 60,
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_security_config_validation_short_jwt_secret() {
        let config = SecurityConfig {
            jwt_secret: "short".to_string(), // Too short
            jwt_expiration_hours: 24,
            bcrypt_cost: 12,
            cors_allowed_origins: vec![],
            rate_limit_enabled: true,
            security_headers_enabled: true,
            input_sanitization_enabled: true,
            https_only: false,
            session_timeout_minutes: 60,
        };

        assert!(config.validate().is_err());
        assert!(config.validate().unwrap_err().contains("JWT_SECRET"));
    }

    #[test]
    fn test_security_config_validation_invalid_bcrypt_cost() {
        let config = SecurityConfig {
            jwt_secret: "valid_secret_key_with_32_characters".to_string(),
            jwt_expiration_hours: 24,
            bcrypt_cost: 2, // Too low
            cors_allowed_origins: vec![],
            rate_limit_enabled: true,
            security_headers_enabled: true,
            input_sanitization_enabled: true,
            https_only: false,
            session_timeout_minutes: 60,
        };

        assert!(config.validate().is_err());
        assert!(config.validate().unwrap_err().contains("BCRYPT_COST"));
    }

    #[test]
    fn test_security_config_validation_invalid_jwt_expiration() {
        let config = SecurityConfig {
            jwt_secret: "valid_secret_key_with_32_characters".to_string(),
            jwt_expiration_hours: 0, // Invalid
            bcrypt_cost: 12,
            cors_allowed_origins: vec![],
            rate_limit_enabled: true,
            security_headers_enabled: true,
            input_sanitization_enabled: true,
            https_only: false,
            session_timeout_minutes: 60,
        };

        assert!(config.validate().is_err());
        assert!(
            config
                .validate()
                .unwrap_err()
                .contains("JWT_EXPIRATION_HOURS")
        );
    }

    #[test]
    #[serial]
    fn test_environment_detection() {
        // Test development detection
        unsafe {
            env::remove_var("RUST_ENV");
        }
        assert!(SecurityConfig::is_development());
        assert!(!SecurityConfig::is_production());

        // Test production detection
        unsafe {
            env::set_var("RUST_ENV", "production");
        }
        assert!(!SecurityConfig::is_development());
        assert!(SecurityConfig::is_production());

        // Test explicit development
        unsafe {
            env::set_var("RUST_ENV", "development");
        }
        assert!(SecurityConfig::is_development());
        assert!(!SecurityConfig::is_production());

        // Clean up
        unsafe {
            env::remove_var("RUST_ENV");
        }
    }

    #[test]
    fn test_rate_limit_settings_from_env() {
        unsafe {
            env::set_var("RATE_LIMIT_GENERAL", "50");
            env::set_var("RATE_LIMIT_AUTH", "5");
            env::set_var("RATE_LIMIT_CREATION", "15");
            env::set_var("RATE_LIMIT_PASSWORD_CHANGE", "2");
        }

        let settings = RateLimitSettings::from_env();

        assert_eq!(settings.general_per_minute, 50);
        assert_eq!(settings.auth_per_minute, 5);
        assert_eq!(settings.creation_per_minute, 15);
        assert_eq!(settings.password_change_per_hour, 2);

        // Clean up
        unsafe {
            env::remove_var("RATE_LIMIT_GENERAL");
            env::remove_var("RATE_LIMIT_AUTH");
            env::remove_var("RATE_LIMIT_CREATION");
            env::remove_var("RATE_LIMIT_PASSWORD_CHANGE");
        }
    }

    #[test]
    fn test_rate_limit_settings_development() {
        let settings = RateLimitSettings::development();

        assert_eq!(settings.general_per_minute, 1000);
        assert_eq!(settings.auth_per_minute, 100);
        assert_eq!(settings.creation_per_minute, 200);
        assert_eq!(settings.password_change_per_hour, 50);
    }

    #[test]
    fn test_rate_limit_settings_production() {
        let settings = RateLimitSettings::production();

        assert_eq!(settings.general_per_minute, 60);
        assert_eq!(settings.auth_per_minute, 5);
        assert_eq!(settings.creation_per_minute, 10);
        assert_eq!(settings.password_change_per_hour, 3);
    }
}
