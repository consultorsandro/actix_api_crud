// Middlewares - Processamento intermediário de requisições
// Etapa 4: Middleware de validação implementado

pub mod auth_middleware;
pub mod cors_middleware;
pub mod validation;
pub mod auth;
pub mod security;
pub mod rate_limit;
pub mod cors;

// Re-exports for convenience
pub use validation::ValidatedJson;
pub use auth::{JwtAuthMiddleware, JwtClaims, jwt_validator};
pub use security::{SecurityHeaders, InputSanitizer, sanitize_string, is_valid_email};
pub use rate_limit::{RateLimitConfig, SimpleRateLimiter, extract_client_ip, rate_limit_response};
pub use cors::CorsConfig;
