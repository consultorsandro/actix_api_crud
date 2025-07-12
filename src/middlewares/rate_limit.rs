use actix_web::{HttpRequest, HttpResponse, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Configuração de rate limiting simples
pub struct RateLimitConfig {
    requests_per_minute: u32,
    window_duration: Duration,
}

impl RateLimitConfig {
    /// Rate limiting geral para todas as rotas
    pub fn general() -> Self {
        Self {
            requests_per_minute: 100,
            window_duration: Duration::from_secs(60),
        }
    }

    /// Rate limiting mais restritivo para autenticação
    pub fn auth() -> Self {
        Self {
            requests_per_minute: 10,
            window_duration: Duration::from_secs(60),
        }
    }

    /// Rate limiting para criação de recursos
    pub fn creation() -> Self {
        Self {
            requests_per_minute: 20,
            window_duration: Duration::from_secs(60),
        }
    }
}

/// Rate limiter em memória simples
pub struct SimpleRateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: u32,
    window_duration: Duration,
}

impl SimpleRateLimiter {
    pub fn new(max_requests: u32, window_duration: Duration) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window_duration,
        }
    }

    /// Verifica se a requisição é permitida para o IP
    pub fn check_rate_limit(&self, ip: &str) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();

        // Limpar requisições antigas
        let entry = requests.entry(ip.to_string()).or_insert_with(Vec::new);
        entry.retain(|&time| now.duration_since(time) < self.window_duration);

        // Verificar se pode fazer nova requisição
        if entry.len() < self.max_requests as usize {
            entry.push(now);
            true
        } else {
            false
        }
    }
}

/// Extrai IP real do cliente considerando proxies
pub fn extract_client_ip(req: &HttpRequest) -> String {
    // Verificar headers de proxy primeiro
    if let Some(forwarded_for) = req.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            // Pegar o primeiro IP da lista (cliente original)
            if let Some(first_ip) = forwarded_str.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }

    // Verificar header x-real-ip
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return ip_str.to_string();
        }
    }

    // Fallback para connection info
    req.connection_info()
        .peer_addr()
        .unwrap_or("unknown")
        .to_string()
}

/// Resposta padrão para rate limit excedido
pub fn rate_limit_response() -> Result<HttpResponse> {
    Ok(HttpResponse::TooManyRequests().json(serde_json::json!({
        "error": "Rate limit exceeded",
        "message": "Too many requests. Please try again later.",
        "code": "RATE_LIMIT_EXCEEDED"
    })))
}

/// Configurações de rate limiting por tipo de operação
pub mod limits {
    pub const GENERAL_REQUESTS_PER_MINUTE: u32 = 100;
    pub const AUTH_REQUESTS_PER_MINUTE: u32 = 10;
    pub const CREATION_REQUESTS_PER_MINUTE: u32 = 20;
    pub const PASSWORD_CHANGE_REQUESTS_PER_HOUR: u32 = 5;
}
