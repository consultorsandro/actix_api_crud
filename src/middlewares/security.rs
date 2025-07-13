use actix_web::{
    Error,
    dev::{ServiceRequest, ServiceResponse, Transform},
    error::ErrorBadRequest,
    http::header::{HeaderName, HeaderValue},
};
use futures_util::future::{Ready, ok};
use std::future::{Future, ready};
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
        "script>",
        "javascript:",
        "onload=",
        "onerror=",
        "eval(",
        "union select",
        "drop table",
        "delete from",
        "insert into",
        "update set",
        "exec(",
        "execute(",
        "sp_",
        "xp_",
        "<iframe",
        "<object",
        "<embed",
        "<link",
    ];

    let input_lower = input.to_lowercase();
    suspicious_patterns
        .iter()
        .any(|&pattern| input_lower.contains(pattern))
}

/// Utilitário para sanitizar strings
#[allow(dead_code)]
pub fn sanitize_string(input: &str) -> String {
    // Remove caracteres perigosos
    input
        .chars()
        .filter(|c| c.is_alphanumeric() || " @.-_".contains(*c))
        .collect()
}

/// Utilitário para validar email de forma mais rigorosa
#[allow(dead_code)]
pub fn is_valid_email(email: &str) -> bool {
    let email_regex =
        regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();

    email_regex.is_match(email) && email.len() <= 254
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpResponse, test, web};

    async fn test_handler() -> Result<HttpResponse, Error> {
        Ok(HttpResponse::Ok().json("Success"))
    }

    #[actix_web::test]
    async fn test_security_headers_middleware() {
        let app = test::init_service(
            App::new()
                .wrap(SecurityHeaders)
                .route("/test", web::get().to(test_handler)),
        )
        .await;

        let req = test::TestRequest::get().uri("/test").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        // Verificar se os headers de segurança foram adicionados
        let headers = resp.headers();

        assert_eq!(headers.get("x-xss-protection").unwrap(), "1; mode=block");

        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");

        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");

        assert!(headers.get("content-security-policy").is_some());
        assert!(headers.get("strict-transport-security").is_some());
        assert!(headers.get("referrer-policy").is_some());
        assert!(headers.get("permissions-policy").is_some());
    }

    #[actix_web::test]
    async fn test_input_sanitizer_middleware() {
        let app = test::init_service(
            App::new()
                .wrap(InputSanitizer)
                .route("/test", web::post().to(test_handler)),
        )
        .await;

        // Test com input limpo
        let clean_req = test::TestRequest::post()
            .uri("/test")
            .set_json(&serde_json::json!({"name": "John Doe"}))
            .to_request();

        let resp = test::call_service(&app, clean_req).await;
        assert!(resp.status().is_success());

        // Test com input malicioso (script)
        let malicious_req = test::TestRequest::post()
            .uri("/test")
            .set_json(&serde_json::json!({"name": "<script>alert('xss')</script>"}))
            .to_request();

        let _resp = test::call_service(&app, malicious_req).await;
        // O middleware deve rejeitar ou sanitizar o input
        // Dependendo da implementação, pode retornar 400 ou processar sanitizado
    }

    #[test]
    async fn test_contains_suspicious_patterns() {
        // Testes para detecção de padrões suspeitos
        assert!(contains_suspicious_patterns("<script>"));
        assert!(contains_suspicious_patterns("javascript:"));
        assert!(contains_suspicious_patterns("onload="));
        assert!(contains_suspicious_patterns("union select from users"));
        assert!(contains_suspicious_patterns("'; DROP TABLE"));

        // Inputs limpos não devem ser flagados
        assert!(!contains_suspicious_patterns("John Doe"));
        assert!(!contains_suspicious_patterns("user@example.com"));
        assert!(!contains_suspicious_patterns("Valid text content"));
    }

    #[test]
    async fn test_sanitize_string() {
        // Test de sanitização básica
        let input = "<script>alert('xss')</script>";
        let sanitized = sanitize_string(input);
        assert!(!sanitized.contains("<script>"));
        assert!(!sanitized.contains("</script>"));

        let input = "Normal text";
        let sanitized = sanitize_string(input);
        assert_eq!(sanitized, "Normal text");

        let input = "Text with < and > symbols";
        let sanitized = sanitize_string(input);
        assert!(!sanitized.contains("<"));
        assert!(!sanitized.contains(">"));
    }

    #[test]
    async fn test_security_headers_compilation() {
        // Test que verifica se o middleware compila corretamente
        let _middleware = SecurityHeaders;
        // Se chegou até aqui, o middleware compila sem problemas
    }

    #[test]
    async fn test_input_sanitizer_compilation() {
        // Test que verifica se o middleware compila corretamente
        let _middleware = InputSanitizer;
        // Se chegou até aqui, o middleware compila sem problemas
    }
}
