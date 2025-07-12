// Middlewares - Processamento intermediário de requisições
// Etapa 4: Middleware de validação adicionado

pub mod auth_middleware;
pub mod cors_middleware;
pub mod validation;

pub use validation::{ValidationMiddleware, ValidatedJson};
