// Middlewares - Processamento intermediário de requisições
// Etapa 4: Middleware de validação implementado

pub mod auth;
pub mod auth_middleware;
pub mod cors;
pub mod cors_middleware;
pub mod rate_limit;
pub mod security;
pub mod validation;

// Re-exports for convenience
pub use auth::{JwtAuthMiddleware, JwtClaims, jwt_validator};
pub use cors::CorsConfig;
pub use rate_limit::{RateLimitConfig, SimpleRateLimiter, extract_client_ip, rate_limit_response};
pub use security::{InputSanitizer, SecurityHeaders, is_valid_email, sanitize_string};
pub use validation::ValidatedJson;
