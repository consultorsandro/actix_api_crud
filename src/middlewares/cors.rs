use actix_cors::Cors;
use actix_web::http::header;
use std::env;

/// Configuração de CORS para diferentes ambientes
pub struct CorsConfig;

impl CorsConfig {
    /// Configuração de CORS para desenvolvimento
    pub fn development() -> Cors {
        Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .max_age(3600)
    }

    /// Configuração de CORS para produção
    pub fn production() -> Cors {
        let allowed_origins = Self::get_allowed_origins();
        
        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![
                header::AUTHORIZATION,
                header::ACCEPT,
                header::CONTENT_TYPE,
                header::USER_AGENT,
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
            ])
            .supports_credentials()
            .max_age(3600);

        // Adicionar origens permitidas
        for origin in allowed_origins {
            cors = cors.allowed_origin(&origin);
        }

        cors
    }

    /// Configuração automática baseada no ambiente
    pub fn auto() -> Cors {
        match env::var("RUST_ENV").as_deref() {
            Ok("production") => Self::production(),
            Ok("staging") => Self::staging(),
            _ => Self::development(),
        }
    }

    /// Configuração de CORS para staging
    pub fn staging() -> Cors {
        let allowed_origins = Self::get_allowed_origins();
        
        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![
                header::AUTHORIZATION,
                header::ACCEPT,
                header::CONTENT_TYPE,
                header::USER_AGENT,
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
            ])
            .supports_credentials()
            .max_age(1800); // Menor cache para staging

        // Adicionar origens permitidas
        for origin in allowed_origins {
            cors = cors.allowed_origin(&origin);
        }

        cors
    }

    /// Obter lista de origens permitidas do ambiente
    fn get_allowed_origins() -> Vec<String> {
        let origins_env = env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000,http://localhost:8080".to_string());

        origins_env
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Configuração restritiva para APIs internas
    pub fn internal_api() -> Cors {
        Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_origin("http://localhost:8080")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
            ])
            .max_age(3600)
    }

    /// Configuração para APIs públicas (mais permissiva)
    pub fn public_api() -> Cors {
        Cors::default()
            .allow_any_origin()
            .allowed_methods(vec!["GET", "OPTIONS"])
            .allowed_headers(vec![
                header::ACCEPT,
                header::CONTENT_TYPE,
                header::USER_AGENT,
            ])
            .max_age(86400) // 24 horas
    }
}

/// Utilitários para validação de CORS
pub mod cors_utils {
    /// Verifica se uma origem é válida
    pub fn is_valid_origin(origin: &str) -> bool {
        // Verificações básicas de segurança
        if origin.is_empty() || origin.len() > 253 {
            return false;
        }

        // Deve começar com http:// ou https://
        if !origin.starts_with("http://") && !origin.starts_with("https://") {
            return false;
        }

        // Não deve conter caracteres perigosos
        let dangerous_chars = ['<', '>', '"', '\'', '`', '{', '}'];
        if origin.chars().any(|c| dangerous_chars.contains(&c)) {
            return false;
        }

        true
    }

    /// Extrai o domínio de uma origem
    pub fn extract_domain(origin: &str) -> Option<String> {
        if let Ok(url) = url::Url::parse(origin) {
            url.host_str().map(|host| host.to_string())
        } else {
            None
        }
    }

    /// Lista de domínios sempre bloqueados
    pub fn is_blocked_domain(domain: &str) -> bool {
        let blocked_domains = [
            "suspicious-domain.com",
            "malicious-site.net",
            // Adicione outros domínios conforme necessário
        ];

        blocked_domains.iter().any(|&blocked| domain.contains(blocked))
    }
}
