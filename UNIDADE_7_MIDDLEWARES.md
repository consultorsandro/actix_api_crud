# ⚫ **UNIDADE VII: MIDDLEWARES E SEGURANÇA**
*"Protegendo a aplicação com middlewares customizados"*

## 📚 **Introdução**

**Middlewares** são componentes essenciais em aplicações web modernas que processam requisições antes de chegarem aos handlers e modificam respostas antes de serem enviadas ao cliente. Nesta unidade, você aprenderá a implementar middlewares robustos de segurança para proteger sua aplicação Actix-Web contra ameaças comuns e aplicar boas práticas de validação e sanitização.

**Objetivos desta Unidade:**
- ✅ Implementar middlewares de autenticação e autorização
- ✅ Configurar headers de segurança avançados
- ✅ Aplicar CORS configurável por ambiente
- ✅ Implementar rate limiting e proteção DDoS
- ✅ Criar validação e sanitização automática de inputs

---

## 📌 **CAPÍTULO 10: MIDDLEWARES DE SEGURANÇA**

### **10.1 Middleware de Autenticação (`middlewares/auth.rs`)**

O middleware de autenticação é a primeira linha de defesa da aplicação, validando tokens JWT e extraindo claims para autorização.

#### **10.1.1 Estrutura do Middleware JWT**

```rust
// src/middlewares/auth.rs
use actix_web::{
    Error, HttpMessage,
    dev::{ServiceRequest, ServiceResponse},
    error::ErrorUnauthorized,
    http::header::AUTHORIZATION,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use futures_util::future::LocalBoxFuture;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::env;

/// Claims JWT para autenticação com informações essenciais
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,          // Subject (user id)
    pub email: String,        // User email
    pub name: String,         // User name
    pub role: Option<String>, // User role (admin, user, moderator)
    pub exp: usize,           // Expiration time (timestamp)
    pub iat: usize,           // Issued at (timestamp)
    pub permissions: Option<Vec<String>>, // User permissions
}

/// Middleware principal de autenticação JWT
pub struct JwtAuthMiddleware;

impl JwtAuthMiddleware {
    /// Valida token JWT e extrai claims com validação rigorosa
    pub fn validate_token(token: &str) -> Result<Claims, Error> {
        let secret = env::var("JWT_SECRET")
            .map_err(|_| ErrorUnauthorized("JWT secret not configured"))?;

        // Configuração de validação rigorosa
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;  // Validar expiração
        validation.validate_nbf = true;  // Validar "not before"
        validation.leeway = 60;          // 60 segundos de tolerância para clock skew

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_ref()),
            &validation,
        )
        .map_err(|e| {
            log::warn!("JWT validation failed: {}", e);
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    ErrorUnauthorized("Token expired")
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    ErrorUnauthorized("Invalid token signature")
                }
                _ => ErrorUnauthorized("Invalid JWT token")
            }
        })?;

        log::debug!("JWT validated successfully for user: {}", token_data.claims.sub);
        Ok(token_data.claims)
    }

    /// Extrai e valida token do header Authorization
    pub fn extract_and_validate_token(req: &ServiceRequest) -> Result<Claims, Error> {
        // Extrair token do header Authorization
        let auth_header = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|header| header.to_str().ok())
            .ok_or_else(|| ErrorUnauthorized("Missing Authorization header"))?;

        // Verificar formato Bearer token
        if !auth_header.starts_with("Bearer ") {
            return Err(ErrorUnauthorized("Invalid Authorization header format"));
        }

        let token = auth_header.trim_start_matches("Bearer ");
        
        // Validar comprimento mínimo do token
        if token.len() < 10 {
            return Err(ErrorUnauthorized("Token too short"));
        }

        Self::validate_token(token)
    }
}
```

#### **10.1.2 Validator Function para Actix-Web-HTTPAuth**

```rust
/// Validator function para actix-web-httpauth integration
pub async fn jwt_validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    match JwtAuthMiddleware::validate_token(credentials.token()) {
        Ok(claims) => {
            log::debug!("Authentication successful for user: {}", claims.sub);
            
            // Adicionar claims às extensões da request para acesso posterior
            req.extensions_mut().insert(claims);
            Ok(req)
        }
        Err(e) => {
            log::warn!("Authentication failed: {}", e);
            Err((e, req))
        }
    }
}

/// Validator com verificação de role específica
pub fn jwt_validator_with_role(required_role: &'static str) -> impl Fn(ServiceRequest, BearerAuth) -> LocalBoxFuture<'static, Result<ServiceRequest, (Error, ServiceRequest)>> {
    move |req, credentials| {
        Box::pin(async move {
            match JwtAuthMiddleware::validate_token(credentials.token()) {
                Ok(claims) => {
                    // Verificar role específica
                    if let Some(ref user_role) = claims.role {
                        if user_role != required_role && user_role != "admin" {
                            log::warn!("Insufficient role for user {}: required {}, has {}", 
                                claims.sub, required_role, user_role);
                            return Err((ErrorUnauthorized("Insufficient permissions"), req));
                        }
                    } else {
                        log::warn!("No role found for user {}", claims.sub);
                        return Err((ErrorUnauthorized("No role assigned"), req));
                    }

                    req.extensions_mut().insert(claims);
                    Ok(req)
                }
                Err(e) => Err((e, req))
            }
        })
    }
}

/// Validator com verificação de permissões granulares
pub fn jwt_validator_with_permission(required_permission: &'static str) -> impl Fn(ServiceRequest, BearerAuth) -> LocalBoxFuture<'static, Result<ServiceRequest, (Error, ServiceRequest)>> {
    move |req, credentials| {
        Box::pin(async move {
            match JwtAuthMiddleware::validate_token(credentials.token()) {
                Ok(claims) => {
                    // Verificar permissão específica
                    if let Some(ref permissions) = claims.permissions {
                        if !permissions.contains(&required_permission.to_string()) {
                            log::warn!("Missing permission for user {}: required {}", 
                                claims.sub, required_permission);
                            return Err((ErrorUnauthorized("Missing required permission"), req));
                        }
                    } else {
                        log::warn!("No permissions found for user {}", claims.sub);
                        return Err((ErrorUnauthorized("No permissions assigned"), req));
                    }

                    req.extensions_mut().insert(claims);
                    Ok(req)
                }
                Err(e) => Err((e, req))
            }
        })
    }
}
```

#### **10.1.3 Extractor para Claims JWT**

```rust
/// Extractor para claims JWT em handlers
pub struct JwtClaims(pub Claims);

impl FromRequest for JwtClaims {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        // Tentar extrair claims das extensões da request
        match req.extensions().get::<Claims>() {
            Some(claims) => {
                log::debug!("Claims extracted for user: {}", claims.sub);
                ready(Ok(JwtClaims(claims.clone())))
            }
            None => {
                log::error!("No JWT claims found in request extensions");
                ready(Err(ErrorUnauthorized("Authentication required")))
            }
        }
    }
}

/// Helper para verificar roles específicas
impl JwtClaims {
    /// Verifica se o usuário tem uma role específica
    pub fn has_role(&self, role: &str) -> bool {
        self.0.role.as_ref().map(|r| r == role).unwrap_or(false)
    }

    /// Verifica se o usuário é admin
    pub fn is_admin(&self) -> bool {
        self.has_role("admin")
    }

    /// Verifica se o usuário tem uma permissão específica
    pub fn has_permission(&self, permission: &str) -> bool {
        self.0.permissions
            .as_ref()
            .map(|perms| perms.contains(&permission.to_string()))
            .unwrap_or(false)
    }

    /// Verifica se o usuário pode acessar recurso próprio ou é admin
    pub fn can_access_user_resource(&self, target_user_id: &str) -> bool {
        self.0.sub == target_user_id || self.is_admin()
    }
}
```

---

### **10.2 Headers de Segurança (`middlewares/security.rs`)**

Headers de segurança são fundamentais para proteger contra ataques comuns como XSS, clickjacking e outras vulnerabilidades web.

#### **10.2.1 Middleware de Security Headers**

```rust
// src/middlewares/security.rs
use actix_web::{
    Error,
    dev::{ServiceRequest, ServiceResponse, Transform},
    http::header::{HeaderName, HeaderValue},
};
use futures_util::future::{Ready, ok};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Middleware de headers de segurança avançados
pub struct SecurityHeaders {
    pub csp_policy: String,
    pub hsts_max_age: u32,
    pub frame_options: String,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            csp_policy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'none';".to_string(),
            hsts_max_age: 31536000, // 1 ano
            frame_options: "DENY".to_string(),
        }
    }
}

impl SecurityHeaders {
    /// Configuração para desenvolvimento (mais permissiva)
    pub fn development() -> Self {
        Self {
            csp_policy: "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https: http:;".to_string(),
            hsts_max_age: 0, // Não usar HSTS em desenvolvimento
            frame_options: "SAMEORIGIN".to_string(),
        }
    }

    /// Configuração para produção (mais restritiva)
    pub fn production() -> Self {
        Self {
            csp_policy: "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'none'; base-uri 'self'; form-action 'self';".to_string(),
            hsts_max_age: 63072000, // 2 anos
            frame_options: "DENY".to_string(),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SecurityHeadersMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(SecurityHeadersMiddleware { 
            service,
            config: self.clone(),
        })
    }
}

#[derive(Clone)]
pub struct SecurityHeadersMiddleware<S> {
    service: S,
    config: SecurityHeaders,
}

impl<S, B> actix_web::dev::Service<ServiceRequest> for SecurityHeadersMiddleware<S>
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);
        let config = self.config.clone();

        Box::pin(async move {
            let mut res = fut.await?;
            let headers = res.headers_mut();

            // 1. Proteção XSS
            headers.insert(
                HeaderName::from_static("x-xss-protection"),
                HeaderValue::from_static("1; mode=block"),
            );

            // 2. Prevenir MIME sniffing
            headers.insert(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );

            // 3. Prevenir clickjacking
            headers.insert(
                HeaderName::from_static("x-frame-options"),
                HeaderValue::from_str(&config.frame_options).unwrap(),
            );

            // 4. Content Security Policy
            headers.insert(
                HeaderName::from_static("content-security-policy"),
                HeaderValue::from_str(&config.csp_policy).unwrap(),
            );

            // 5. Strict Transport Security (apenas se HSTS configurado)
            if config.hsts_max_age > 0 {
                headers.insert(
                    HeaderName::from_static("strict-transport-security"),
                    HeaderValue::from_str(&format!("max-age={}; includeSubDomains; preload", config.hsts_max_age)).unwrap(),
                );
            }

            // 6. Referrer Policy
            headers.insert(
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("strict-origin-when-cross-origin"),
            );

            // 7. Permissions Policy (Feature Policy)
            headers.insert(
                HeaderName::from_static("permissions-policy"),
                HeaderValue::from_static("geolocation=(), microphone=(), camera=(), usb=(), bluetooth=()"),
            );

            // 8. Cross-Origin Policies
            headers.insert(
                HeaderName::from_static("cross-origin-opener-policy"),
                HeaderValue::from_static("same-origin"),
            );

            headers.insert(
                HeaderName::from_static("cross-origin-embedder-policy"),
                HeaderValue::from_static("require-corp"),
            );

            // 9. Cache Control para recursos sensíveis
            if req.path().contains("/api/auth") || req.path().contains("/api/admin") {
                headers.insert(
                    HeaderName::from_static("cache-control"),
                    HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
                );
            }

            log::debug!("Security headers applied to {}", req.path());
            Ok(res)
        })
    }
}
```

#### **10.2.2 Middleware de Sanitização de Input**

```rust
/// Middleware de sanitização e proteção contra ataques
pub struct InputSanitizer {
    pub max_request_size: usize,
    pub blocked_patterns: Vec<String>,
}

impl Default for InputSanitizer {
    fn default() -> Self {
        Self {
            max_request_size: 1024 * 1024, // 1MB
            blocked_patterns: vec![
                // SQL Injection patterns
                r"(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)".to_string(),
                r"(?i)(script|javascript|vbscript|onload|onerror|onclick)".to_string(),
                // XSS patterns
                r"(?i)<script[^>]*>.*?</script>".to_string(),
                r"(?i)javascript:".to_string(),
                r"(?i)data:text/html".to_string(),
                // Path traversal
                r"(\.\./|\.\.\\)".to_string(),
                // Command injection
                r"(?i)(cmd|powershell|bash|sh|exec)".to_string(),
            ],
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for InputSanitizer
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = InputSanitizerMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(InputSanitizerMiddleware { 
            service,
            config: self.clone(),
        })
    }
}

#[derive(Clone)]
pub struct InputSanitizerMiddleware<S> {
    service: S,
    config: InputSanitizer,
}

impl<S, B> actix_web::dev::Service<ServiceRequest> for InputSanitizerMiddleware<S>
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let config = self.config.clone();

        // Verificar query parameters suspeitos
        let query_string = req.query_string();
        if contains_suspicious_patterns(query_string, &config.blocked_patterns) {
            log::warn!("Suspicious query detected from {}: {}", 
                req.connection_info().peer_addr().unwrap_or("unknown"), 
                query_string);
            return Box::pin(async move {
                Err(actix_web::error::ErrorBadRequest("Suspicious input detected"))
            });
        }

        // Verificar tamanho da URL
        if req.uri().to_string().len() > 2048 {
            log::warn!("URL too long from {}: {} chars", 
                req.connection_info().peer_addr().unwrap_or("unknown"),
                req.uri().to_string().len());
            return Box::pin(async move {
                Err(actix_web::error::ErrorBadRequest("URL too long"))
            });
        }

        let fut = self.service.call(req);
        Box::pin(async move { fut.await })
    }
}

/// Verifica se a string contém padrões suspeitos
fn contains_suspicious_patterns(input: &str, patterns: &[String]) -> bool {
    use regex::Regex;
    
    for pattern in patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(input) {
                return true;
            }
        }
    }
    false
}

/// Funções utilitárias de sanitização
pub fn sanitize_string(input: &str) -> String {
    input
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
        .replace('&', "&amp;")
}

pub fn is_valid_email(email: &str) -> bool {
    use regex::Regex;
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    email_regex.is_match(email)
}

pub fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect()
}
```

---

### **10.3 CORS Configurável (`middlewares/cors.rs`)**

CORS (Cross-Origin Resource Sharing) deve ser configurado adequadamente para diferentes ambientes mantendo segurança.

#### **10.3.1 Configuração CORS por Ambiente**

```rust
// src/middlewares/cors.rs
use actix_cors::Cors;
use actix_web::http::header;
use std::env;

/// Configuração de CORS adaptável por ambiente
pub struct CorsConfig;

impl CorsConfig {
    /// Configuração de CORS para desenvolvimento (permissiva)
    pub fn development() -> Cors {
        log::info!("Using development CORS configuration");
        Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .max_age(3600)
    }

    /// Configuração de CORS para produção (restritiva)
    pub fn production() -> Cors {
        let allowed_origins = Self::get_allowed_origins();
        log::info!("Using production CORS configuration with {} allowed origins", allowed_origins.len());

        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
            .allowed_headers(vec![
                header::AUTHORIZATION,
                header::ACCEPT,
                header::CONTENT_TYPE,
                header::USER_AGENT,
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderName::from_static("x-requested-with"),
                HeaderName::from_static("x-api-key"),
            ])
            .expose_headers(vec![
                header::CONTENT_LENGTH,
                header::DATE,
                HeaderName::from_static("x-total-count"),
                HeaderName::from_static("x-rate-limit-remaining"),
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
            Ok("testing") => Self::testing(),
            _ => Self::development(),
        }
    }

    /// Configuração de CORS para staging (intermediária)
    pub fn staging() -> Cors {
        let allowed_origins = Self::get_allowed_origins();
        log::info!("Using staging CORS configuration");

        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
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

        for origin in allowed_origins {
            cors = cors.allowed_origin(&origin);
        }

        cors
    }

    /// Configuração para testes (local)
    pub fn testing() -> Cors {
        log::info!("Using testing CORS configuration");
        Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_origin("http://127.0.0.1:3000")
            .allowed_origin("http://localhost:8080")
            .allowed_origin("http://127.0.0.1:8080")
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .max_age(300) // Cache menor para testes
    }

    /// Obter lista de origens permitidas do ambiente
    fn get_allowed_origins() -> Vec<String> {
        let origins_env = env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| {
                log::warn!("CORS_ALLOWED_ORIGINS not set, using default localhost origins");
                "http://localhost:3000,http://localhost:8080,https://app.exemplo.com".to_string()
            });

        let origins: Vec<String> = origins_env
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        log::debug!("Allowed CORS origins: {:?}", origins);
        origins
    }

    /// Configuração restritiva para APIs internas
    pub fn internal_api() -> Cors {
        log::info!("Using internal API CORS configuration");
        Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_origin("http://localhost:8080")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![header::AUTHORIZATION, header::CONTENT_TYPE])
            .max_age(3600)
    }

    /// Configuração para APIs públicas (controlada)
    pub fn public_api() -> Cors {
        log::info!("Using public API CORS configuration");
        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST", "OPTIONS"])
            .allowed_headers(vec![
                header::ACCEPT,
                header::CONTENT_TYPE,
                HeaderName::from_static("x-api-key"),
            ])
            .max_age(7200);

        // APIs públicas podem aceitar mais origens, mas controladas
        if let Ok(public_origins) = env::var("PUBLIC_CORS_ORIGINS") {
            for origin in public_origins.split(',') {
                cors = cors.allowed_origin(origin.trim());
            }
        } else {
            // Fallback para configuração padrão
            cors = cors
                .allowed_origin("https://api.exemplo.com")
                .allowed_origin("https://app.exemplo.com");
        }

        cors
    }

    /// Configuração para subdomínios (wildcard simulado)
    pub fn subdomain_cors(base_domain: &str) -> Cors {
        let subdomains = vec![
            format!("https://*.{}", base_domain),
            format!("https://{}", base_domain),
            format!("https://www.{}", base_domain),
            format!("https://app.{}", base_domain),
            format!("https://admin.{}", base_domain),
        ];

        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![
                header::AUTHORIZATION,
                header::ACCEPT,
                header::CONTENT_TYPE,
            ])
            .supports_credentials()
            .max_age(3600);

        for subdomain in subdomains {
            cors = cors.allowed_origin(&subdomain);
        }

        cors
    }
}

/// Middleware customizado para CORS dinâmico
pub struct DynamicCors {
    allowed_origins: Vec<String>,
    dev_mode: bool,
}

impl DynamicCors {
    pub fn new() -> Self {
        let dev_mode = env::var("RUST_ENV").as_deref() != Ok("production");
        let allowed_origins = CorsConfig::get_allowed_origins();

        Self {
            allowed_origins,
            dev_mode,
        }
    }

    /// Verifica se a origem é permitida
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.dev_mode && origin.starts_with("http://localhost") {
            return true;
        }

        self.allowed_origins.contains(&origin.to_string())
    }
}
```

---

### **10.4 Rate Limiting e Proteção DDoS**

Rate limiting é essencial para proteger a aplicação contra ataques de força bruta e DDoS.

#### **10.4.1 Sistema de Rate Limiting Configurável**

```rust
// src/middlewares/rate_limit.rs
use actix_web::{HttpRequest, HttpResponse, Result, Error, dev::{ServiceRequest, ServiceResponse}};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Configuração de rate limiting por tipo de operação
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_window: u32,
    pub window_duration: Duration,
    pub burst_size: u32, // Rajadas permitidas
    pub punishment_duration: Duration, // Tempo de bloqueio após violação
}

impl RateLimitConfig {
    /// Rate limiting geral para todas as rotas
    pub fn general() -> Self {
        Self {
            requests_per_window: 100,
            window_duration: Duration::from_secs(60),
            burst_size: 10,
            punishment_duration: Duration::from_secs(300), // 5 minutos
        }
    }

    /// Rate limiting restritivo para autenticação
    pub fn auth() -> Self {
        Self {
            requests_per_window: 5,
            window_duration: Duration::from_secs(60),
            burst_size: 2,
            punishment_duration: Duration::from_secs(900), // 15 minutos
        }
    }

    /// Rate limiting para criação de recursos
    pub fn creation() -> Self {
        Self {
            requests_per_window: 20,
            window_duration: Duration::from_secs(60),
            burst_size: 5,
            punishment_duration: Duration::from_secs(180), // 3 minutos
        }
    }

    /// Rate limiting para mudança de senhas
    pub fn password_change() -> Self {
        Self {
            requests_per_window: 3,
            window_duration: Duration::from_secs(3600), // 1 hora
            burst_size: 1,
            punishment_duration: Duration::from_secs(7200), // 2 horas
        }
    }

    /// Rate limiting para recuperação de senha
    pub fn password_reset() -> Self {
        Self {
            requests_per_window: 3,
            window_duration: Duration::from_secs(900), // 15 minutos
            burst_size: 1,
            punishment_duration: Duration::from_secs(1800), // 30 minutos
        }
    }
}

/// Rate limiter avançado com proteção DDoS
pub struct AdvancedRateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    blocked_ips: Arc<Mutex<HashMap<String, Instant>>>,
    config: RateLimitConfig,
}

impl AdvancedRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            blocked_ips: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// Verifica rate limit considerando bloqueios e rajadas
    pub fn check_rate_limit(&self, ip: &str) -> RateLimitResult {
        let now = Instant::now();

        // 1. Verificar se IP está bloqueado
        {
            let mut blocked = self.blocked_ips.lock().unwrap();
            if let Some(&blocked_until) = blocked.get(ip) {
                if now < blocked_until {
                    return RateLimitResult::Blocked {
                        retry_after: blocked_until.duration_since(now),
                    };
                } else {
                    // Remover bloqueio expirado
                    blocked.remove(ip);
                }
            }
        }

        // 2. Verificar requests na janela atual
        let mut requests = self.requests.lock().unwrap();
        let entry = requests.entry(ip.to_string()).or_insert_with(Vec::new);
        
        // Limpar requests antigas
        entry.retain(|&time| now.duration_since(time) < self.config.window_duration);

        // 3. Verificar se excedeu o limite
        if entry.len() >= self.config.requests_per_window as usize {
            // Bloquear IP
            let mut blocked = self.blocked_ips.lock().unwrap();
            blocked.insert(ip.to_string(), now + self.config.punishment_duration);
            
            log::warn!("Rate limit exceeded for IP: {}. Blocked for {:?}", 
                ip, self.config.punishment_duration);
            
            return RateLimitResult::Blocked {
                retry_after: self.config.punishment_duration,
            };
        }

        // 4. Verificar rajadas (burst)
        let recent_requests = entry.iter()
            .filter(|&&time| now.duration_since(time) < Duration::from_secs(10))
            .count();

        if recent_requests >= self.config.burst_size as usize {
            log::warn!("Burst limit exceeded for IP: {}", ip);
            return RateLimitResult::BurstExceeded {
                retry_after: Duration::from_secs(10),
            };
        }

        // 5. Permitir request
        entry.push(now);
        
        RateLimitResult::Allowed {
            remaining: self.config.requests_per_window - entry.len() as u32,
            reset_time: now + self.config.window_duration,
        }
    }

    /// Limpa dados antigos periodicamente
    pub fn cleanup(&self) {
        let now = Instant::now();
        
        // Limpar requests antigas
        {
            let mut requests = self.requests.lock().unwrap();
            requests.retain(|_, times| {
                times.retain(|&time| now.duration_since(time) < self.config.window_duration);
                !times.is_empty()
            });
        }

        // Limpar bloqueios expirados
        {
            let mut blocked = self.blocked_ips.lock().unwrap();
            blocked.retain(|_, &mut blocked_until| now < blocked_until);
        }
    }
}

/// Resultado do rate limiting
#[derive(Debug)]
pub enum RateLimitResult {
    Allowed {
        remaining: u32,
        reset_time: Instant,
    },
    BurstExceeded {
        retry_after: Duration,
    },
    Blocked {
        retry_after: Duration,
    },
}

/// Extrai IP real do cliente considerando proxies e load balancers
pub fn extract_client_ip(req: &HttpRequest) -> String {
    // Ordem de prioridade para headers de IP
    let ip_headers = [
        "cf-connecting-ip",     // Cloudflare
        "x-forwarded-for",      // Padrão proxy
        "x-real-ip",           // Nginx
        "x-client-ip",         // Apache
        "x-cluster-client-ip", // Cluster
        "forwarded",           // RFC 7239
    ];

    for header_name in &ip_headers {
        if let Some(header_value) = req.headers().get(*header_name) {
            if let Ok(header_str) = header_value.to_str() {
                // Para x-forwarded-for, pegar o primeiro IP (cliente original)
                let ip = if *header_name == "x-forwarded-for" {
                    header_str.split(',').next().unwrap_or(header_str).trim()
                } else {
                    header_str.trim()
                };
                
                // Validar se é um IP válido
                if is_valid_ip(ip) {
                    return ip.to_string();
                }
            }
        }
    }

    // Fallback para connection info
    req.connection_info()
        .peer_addr()
        .unwrap_or("unknown")
        .split(':')
        .next()
        .unwrap_or("unknown")
        .to_string()
}

/// Valida se é um endereço IP válido
fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

/// Resposta padrão para rate limit excedido
pub fn rate_limit_response(result: &RateLimitResult) -> Result<HttpResponse> {
    match result {
        RateLimitResult::Allowed { remaining, .. } => {
            // Não deveria ser chamado para requests permitidos
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "remaining": remaining
            })))
        }
        RateLimitResult::BurstExceeded { retry_after } => {
            Ok(HttpResponse::TooManyRequests()
                .insert_header(("retry-after", retry_after.as_secs().to_string()))
                .json(serde_json::json!({
                    "error": "Rate limit exceeded",
                    "message": "Too many requests in short time. Please slow down.",
                    "code": "BURST_LIMIT_EXCEEDED",
                    "retry_after": retry_after.as_secs()
                })))
        }
        RateLimitResult::Blocked { retry_after } => {
            Ok(HttpResponse::TooManyRequests()
                .insert_header(("retry-after", retry_after.as_secs().to_string()))
                .json(serde_json::json!({
                    "error": "IP blocked",
                    "message": "Your IP has been temporarily blocked due to rate limit violations.",
                    "code": "IP_BLOCKED",
                    "retry_after": retry_after.as_secs()
                })))
        }
    }
}

/// Middleware de rate limiting
pub struct RateLimitMiddleware {
    limiter: Arc<AdvancedRateLimiter>,
}

impl RateLimitMiddleware {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            limiter: Arc::new(AdvancedRateLimiter::new(config)),
        }
    }
}
```

---

## 📌 **CAPÍTULO 11: VALIDAÇÃO E SANITIZAÇÃO**

### **11.1 Middleware de Validação (`middlewares/validation.rs`)**

Validação automática de dados de entrada para garantir integridade e segurança.

#### **11.1.1 ValidatedJson Extractor**

```rust
// src/middlewares/validation.rs
use crate::errors::AppError;
use actix_web::{Error, FromRequest, HttpRequest, dev::Payload, web};
use futures::future::{LocalBoxFuture, ready};
use serde::de::DeserializeOwned;
use std::ops::{Deref, DerefMut};
use validator::Validate;

/// Wrapper para JSON validado automaticamente
/// Extrai, deserializa e valida JSON em uma única operação
#[derive(Debug)]
pub struct ValidatedJson<T>(pub T);

impl<T> ValidatedJson<T> {
    /// Extrai o valor interno
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Referência para o valor interno
    pub fn inner(&self) -> &T {
        &self.0
    }
}

impl<T> Deref for ValidatedJson<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for ValidatedJson<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> FromRequest for ValidatedJson<T>
where
    T: DeserializeOwned + Validate + 'static,
{
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let json_future = web::Json::<T>::from_request(req, payload);

        Box::pin(async move {
            match json_future.await {
                Ok(json) => {
                    // Validar os dados extraídos
                    if let Err(validation_errors) = json.validate() {
                        let error_messages: Vec<String> = validation_errors
                            .field_errors()
                            .iter()
                            .flat_map(|(field, errors)| {
                                errors.iter().map(move |error| {
                                    let message = error.message
                                        .as_ref()
                                        .map(|m| m.to_string())
                                        .unwrap_or_else(|| "Validation failed".to_string());
                                    format!("{}: {}", field, message)
                                })
                            })
                            .collect();

                        let error_msg = error_messages.join(", ");
                        log::warn!("Validation failed: {}", error_msg);
                        
                        return Err(AppError::Validation(error_msg).into());
                    }

                    // Validação customizada adicional
                    if let Err(custom_error) = Self::custom_validation(&json) {
                        log::warn!("Custom validation failed: {}", custom_error);
                        return Err(AppError::Validation(custom_error).into());
                    }

                    log::debug!(
                        "Validation successful for type: {}",
                        std::any::type_name::<T>()
                    );
                    Ok(ValidatedJson(json.into_inner()))
                }
                Err(e) => {
                    log::warn!("JSON deserialization failed: {}", e);
                    Err(AppError::Validation("Invalid JSON format".to_string()).into())
                }
            }
        })
    }
}

impl<T> ValidatedJson<T>
where
    T: Validate,
{
    /// Validação customizada adicional
    fn custom_validation(data: &T) -> Result<(), String> {
        // Aqui você pode adicionar validações específicas do negócio
        // que não são cobertas pelo validator
        
        // Exemplo: verificações específicas da aplicação
        // if some_business_rule_violated(data) {
        //     return Err("Business rule violation".to_string());
        // }
        
        Ok(())
    }
    
    /// Re-valida os dados (útil após modificações)
    pub fn revalidate(&self) -> Result<(), String> {
        self.0.validate()
            .map_err(|e| format!("Validation failed: {:?}", e))
    }
}

/// Validação de query parameters
#[derive(Debug)]
pub struct ValidatedQuery<T>(pub T);

impl<T> ValidatedQuery<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for ValidatedQuery<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> FromRequest for ValidatedQuery<T>
where
    T: DeserializeOwned + Validate + 'static,
{
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let query_future = web::Query::<T>::from_request(req, payload);

        Box::pin(async move {
            match query_future.await {
                Ok(query) => {
                    if let Err(validation_errors) = query.validate() {
                        let error_messages: Vec<String> = validation_errors
                            .field_errors()
                            .iter()
                            .flat_map(|(field, errors)| {
                                errors.iter().map(move |error| {
                                    let message = error.message
                                        .as_ref()
                                        .map(|m| m.to_string())
                                        .unwrap_or_else(|| "Validation failed".to_string());
                                    format!("{}: {}", field, message)
                                })
                            })
                            .collect();

                        let error_msg = error_messages.join(", ");
                        log::warn!("Query validation failed: {}", error_msg);
                        return Err(AppError::Validation(error_msg).into());
                    }

                    Ok(ValidatedQuery(query.into_inner()))
                }
                Err(e) => {
                    log::warn!("Query deserialization failed: {}", e);
                    Err(AppError::Validation("Invalid query parameters".to_string()).into())
                }
            }
        })
    }
}
```

### **11.2 Sanitização de Input**

Sanitização automática e manual de dados de entrada.

#### **11.2.1 Funções de Sanitização**

```rust
use regex::Regex;
use std::collections::HashMap;

/// Sanitizador de strings com diferentes níveis
pub struct StringSanitizer;

impl StringSanitizer {
    /// Sanitização básica para prevenir XSS
    pub fn basic_html_escape(input: &str) -> String {
        input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
            .replace('/', "&#x2F;")
    }

    /// Sanitização agressiva removendo tags HTML
    pub fn strip_html_tags(input: &str) -> String {
        let html_regex = Regex::new(r"<[^>]*>").unwrap();
        html_regex.replace_all(input, "").to_string()
    }

    /// Sanitização para nomes de usuário
    pub fn sanitize_username(input: &str) -> Result<String, String> {
        let username_regex = Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
        
        if input.len() < 3 {
            return Err("Username must be at least 3 characters".to_string());
        }
        
        if input.len() > 30 {
            return Err("Username must be less than 30 characters".to_string());
        }
        
        if !username_regex.is_match(input) {
            return Err("Username contains invalid characters".to_string());
        }
        
        Ok(input.to_lowercase())
    }

    /// Sanitização para emails
    pub fn sanitize_email(input: &str) -> Result<String, String> {
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
        
        let trimmed = input.trim().to_lowercase();
        
        if !email_regex.is_match(&trimmed) {
            return Err("Invalid email format".to_string());
        }
        
        // Verificar domínios suspeitos
        let suspicious_domains = ["tempmail.com", "10minutemail.com", "guerrillamail.com"];
        let domain = trimmed.split('@').nth(1).unwrap_or("");
        
        if suspicious_domains.contains(&domain) {
            return Err("Temporary email addresses are not allowed".to_string());
        }
        
        Ok(trimmed)
    }

    /// Sanitização para URLs
    pub fn sanitize_url(input: &str) -> Result<String, String> {
        use url::Url;
        
        match Url::parse(input) {
            Ok(url) => {
                // Verificar esquemas permitidos
                match url.scheme() {
                    "http" | "https" => {
                        // Verificar se não é um IP privado
                        if let Some(host) = url.host_str() {
                            if is_private_ip_or_localhost(host) {
                                return Err("Private IP addresses are not allowed".to_string());
                            }
                        }
                        Ok(url.to_string())
                    }
                    _ => Err("Only HTTP and HTTPS URLs are allowed".to_string()),
                }
            }
            Err(_) => Err("Invalid URL format".to_string()),
        }
    }

    /// Sanitização para nomes de arquivo
    pub fn sanitize_filename(input: &str) -> String {
        let filename_regex = Regex::new(r"[^a-zA-Z0-9._-]").unwrap();
        let sanitized = filename_regex.replace_all(input, "_").to_string();
        
        // Limitar tamanho
        if sanitized.len() > 255 {
            sanitized[..255].to_string()
        } else {
            sanitized
        }
    }

    /// Sanitização para texto livre (descrições, comentários)
    pub fn sanitize_text(input: &str, max_length: usize) -> String {
        // Remover caracteres de controle
        let control_chars_regex = Regex::new(r"[\x00-\x1F\x7F]").unwrap();
        let mut sanitized = control_chars_regex.replace_all(input, "").to_string();
        
        // Normalizar espaços em branco
        let whitespace_regex = Regex::new(r"\s+").unwrap();
        sanitized = whitespace_regex.replace_all(&sanitized, " ").to_string();
        
        // Remover espaços no início e fim
        sanitized = sanitized.trim().to_string();
        
        // Limitar tamanho
        if sanitized.len() > max_length {
            sanitized.truncate(max_length);
        }
        
        sanitized
    }
}

/// Verificar se é IP privado ou localhost
fn is_private_ip_or_localhost(host: &str) -> bool {
    if host == "localhost" || host == "127.0.0.1" || host == "::1" {
        return true;
    }
    
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                ipv4.is_loopback() || ipv4.is_private()
            }
            std::net::IpAddr::V6(ipv6) => {
                ipv6.is_loopback()
            }
        }
    } else {
        false
    }
}
```

### **11.3 Proteção contra XSS e SQL Injection**

Proteções específicas contra ataques comuns.

#### **11.3.1 Proteção Anti-XSS**

```rust
/// Proteção avançada contra XSS
pub struct XssProtection;

impl XssProtection {
    /// Detecta possíveis payloads XSS
    pub fn detect_xss(input: &str) -> bool {
        let xss_patterns = [
            r"(?i)<script[^>]*>",
            r"(?i)javascript:",
            r"(?i)vbscript:",
            r"(?i)onload\s*=",
            r"(?i)onerror\s*=",
            r"(?i)onclick\s*=",
            r"(?i)onmouseover\s*=",
            r"(?i)onfocus\s*=",
            r"(?i)onblur\s*=",
            r"(?i)onchange\s*=",
            r"(?i)onsubmit\s*=",
            r"(?i)onkeyup\s*=",
            r"(?i)onkeydown\s*=",
            r"(?i)onmousedown\s*=",
            r"(?i)onmouseup\s*=",
            r"(?i)<iframe[^>]*>",
            r"(?i)<object[^>]*>",
            r"(?i)<embed[^>]*>",
            r"(?i)<link[^>]*>",
            r"(?i)<meta[^>]*>",
            r"(?i)data:text/html",
            r"(?i)data:image/svg",
        ];

        for pattern in &xss_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(input) {
                    log::warn!("XSS pattern detected: {}", pattern);
                    return true;
                }
            }
        }

        false
    }

    /// Remove ou escapa conteúdo XSS
    pub fn sanitize_xss(input: &str) -> String {
        if Self::detect_xss(input) {
            log::warn!("XSS attempt detected, sanitizing input");
            
            // Escapar caracteres perigosos
            let mut sanitized = input
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&#x27;")
                .replace('&', "&amp;");
            
            // Remover javascript: e vbscript:
            let js_regex = Regex::new(r"(?i)javascript:").unwrap();
            sanitized = js_regex.replace_all(&sanitized, "").to_string();
            
            let vbs_regex = Regex::new(r"(?i)vbscript:").unwrap();
            sanitized = vbs_regex.replace_all(&sanitized, "").to_string();
            
            // Remover event handlers
            let event_regex = Regex::new(r"(?i)on\w+\s*=\s*[\"'][^\"']*[\"']").unwrap();
            sanitized = event_regex.replace_all(&sanitized, "").to_string();
            
            sanitized
        } else {
            input.to_string()
        }
    }

    /// Whitelist de tags HTML permitidas (para rich text)
    pub fn sanitize_html_whitelist(input: &str, allowed_tags: &[&str]) -> String {
        let mut result = input.to_string();
        
        // Primeiro, remover todas as tags
        let tag_regex = Regex::new(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)[^>]*>").unwrap();
        
        result = tag_regex.replace_all(&result, |caps: &regex::Captures| {
            let closing = &caps[1];
            let tag_name = &caps[2].to_lowercase();
            
            if allowed_tags.contains(&tag_name.as_str()) {
                // Tag permitida, manter mas limpar atributos perigosos
                format!("<{}{}>", closing, tag_name)
            } else {
                // Tag não permitida, remover
                "".to_string()
            }
        }).to_string();
        
        result
    }
}

/// Proteção contra SQL Injection
pub struct SqlInjectionProtection;

impl SqlInjectionProtection {
    /// Detecta possíveis tentativas de SQL injection
    pub fn detect_sql_injection(input: &str) -> bool {
        let sql_patterns = [
            r"(?i)\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b",
            r"(?i)\b(or|and)\s+\d+\s*=\s*\d+",
            r"(?i)'\s*(or|and)",
            r"(?i);\s*(drop|delete|insert|update)",
            r"(?i)/\*.*\*/",
            r"(?i)--[^\r\n]*",
            r"(?i)\bxp_cmdshell\b",
            r"(?i)\bsp_executesql\b",
            r"(?i)'\s*;\s*shutdown\s*--",
            r"(?i)'\s*;\s*drop\s+",
        ];

        for pattern in &sql_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(input) {
                    log::warn!("SQL injection pattern detected: {}", pattern);
                    return true;
                }
            }
        }

        false
    }

    /// Sanitiza input removendo caracteres SQL perigosos
    pub fn sanitize_sql_input(input: &str) -> String {
        if Self::detect_sql_injection(input) {
            log::warn!("SQL injection attempt detected, sanitizing input");
            
            // Remover caracteres perigosos para SQL
            input
                .replace('\'', "")
                .replace('"', "")
                .replace(';', "")
                .replace('--', "")
                .replace("/*", "")
                .replace("*/", "")
                .replace('\0', "")
        } else {
            input.to_string()
        }
    }
}
```

---

## 🎯 **Exercícios Práticos**

### **Exercício 1: Middleware de Auditoria**
Implemente um middleware que registra todas as requisições com:
- IP do cliente, user agent, timestamp
- Detecção de padrões suspeitos
- Alertas para tentativas de ataque

### **Exercício 2: Rate Limiting Adaptativo**
Crie um sistema de rate limiting que:
- Ajusta limites baseado no comportamento do usuário
- Diferentes limites para usuários autenticados vs anônimos
- Integração com Redis para aplicações distribuídas

### **Exercício 3: CSP Dinâmico**
Desenvolva um sistema de Content Security Policy que:
- Gera nonces únicos para scripts inline
- Adapta políticas baseado no conteúdo da página
- Reporta violações para análise

---

## 📋 **Resumo da Unidade**

**✅ Domínio Adquirido:**
- **Middlewares de Segurança**: Headers, sanitização e proteção completa
- **Autenticação Robusta**: JWT com validação rigorosa e claims customizados
- **CORS Configurável**: Adaptação automática por ambiente
- **Rate Limiting Avançado**: Proteção DDoS com bloqueio inteligente
- **Validação Automática**: Sanitização e proteção contra XSS/SQL Injection

**🚀 Próxima Unidade:**
Na **Unidade VIII**, abordaremos **Testes e Qualidade de Código**, incluindo testes unitários, de integração, mocks e cobertura completa.

**🔗 Recursos Críticos:**
- Middleware stack completo para produção
- Proteção multicamadas contra ataques
- Validação automática com feedback detalhado
- Rate limiting configurável por operação

Esta unidade estabelece **segurança de nível empresarial** para aplicações Rust com proteção abrangente contra ameaças modernas! 🛡️
