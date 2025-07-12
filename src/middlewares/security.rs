use actix_web::{
    dev::{ServiceRequest, ServiceResponse, Transform},
    error::ErrorBadRequest,
    http::header::{HeaderName, HeaderValue},
    Error,
};
use futures_util::future::{ok, Ready};
use std::future::{ready, Future};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Middleware de headers de segurança
pub struct SecurityHeaders;

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
        ok(SecurityHeadersMiddleware { service })
    }
}

pub struct SecurityHeadersMiddleware<S> {
    service: S,
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

        Box::pin(async move {
            let mut res = fut.await?;

            // Adicionar headers de segurança
            let headers = res.headers_mut();

            // Proteção XSS
            headers.insert(
                HeaderName::from_static("x-xss-protection"),
                HeaderValue::from_static("1; mode=block"),
            );

            // Prevenir MIME sniffing
            headers.insert(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );

            // Prevenir clickjacking
            headers.insert(
                HeaderName::from_static("x-frame-options"),
                HeaderValue::from_static("DENY"),
            );

            // Content Security Policy básico
            headers.insert(
                HeaderName::from_static("content-security-policy"),
                HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"),
            );

            // Strict Transport Security (HTTPS)
            headers.insert(
                HeaderName::from_static("strict-transport-security"),
                HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            );

            // Referrer Policy
            headers.insert(
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("strict-origin-when-cross-origin"),
            );

            // Permissions Policy
            headers.insert(
                HeaderName::from_static("permissions-policy"),
                HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
            );

            Ok(res)
        })
    }
}

/// Middleware de sanitização de input
pub struct InputSanitizer;

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
        ok(InputSanitizerMiddleware { service })
    }
}

pub struct InputSanitizerMiddleware<S> {
    service: S,
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
        // Verificar query parameters suspeitos
        let query_string = req.query_string();
        if contains_suspicious_patterns(query_string) {
            return Box::pin(ready(Err(ErrorBadRequest("Suspicious input detected"))));
        }

        let fut = self.service.call(req);
        Box::pin(async move { fut.await })
    }
}

/// Verifica padrões suspeitos de SQL Injection e XSS
fn contains_suspicious_patterns(input: &str) -> bool {
    let suspicious_patterns = [
        "script>", "javascript:", "onload=", "onerror=", "eval(",
        "union select", "drop table", "delete from", "insert into",
        "update set", "exec(", "execute(", "sp_", "xp_",
        "<iframe", "<object", "<embed", "<link",
    ];

    let input_lower = input.to_lowercase();
    suspicious_patterns.iter().any(|&pattern| input_lower.contains(pattern))
}

/// Utilitário para sanitizar strings
pub fn sanitize_string(input: &str) -> String {
    // Remove caracteres perigosos
    input
        .chars()
        .filter(|c| c.is_alphanumeric() || " @.-_".contains(*c))
        .collect()
}

/// Utilitário para validar email de forma mais rigorosa
pub fn is_valid_email(email: &str) -> bool {
    let email_regex = regex::Regex::new(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    ).unwrap();
    
    email_regex.is_match(email) && email.len() <= 254
}
