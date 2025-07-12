// Errors - Tratamento estruturado de erros
// Aqui ficarão os tipos de erro customizados e suas implementações

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Internal server error")]
    InternalServer,
}

// Implementação para converter AppError em resposta HTTP
impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::Database(_) => HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": "Database error"
            })),
            AppError::Auth(msg) => HttpResponse::Unauthorized().json(serde_json::json!({
                "status": "error",
                "message": msg
            })),
            AppError::Validation(msg) => HttpResponse::BadRequest().json(serde_json::json!({
                "status": "error",
                "message": msg
            })),
            AppError::NotFound(msg) => HttpResponse::NotFound().json(serde_json::json!({
                "status": "error",
                "message": msg
            })),
            AppError::InternalServer => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "error",
                    "message": "Internal server error"
                }))
            }
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            AppError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Auth(_) => StatusCode::UNAUTHORIZED,
            AppError::Validation(_) => StatusCode::BAD_REQUEST,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::InternalServer => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
