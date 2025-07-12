// Errors - Tratamento estruturado de erros
// Aqui ficarão os tipos de erro customizados e suas implementações

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use thiserror::Error;
use chrono;

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

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal server error")]
    InternalServer,
}

// Implementação para converter AppError em resposta HTTP
impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::Database(msg) => {
                log::error!("Database error: {}", msg);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "error",
                    "message": "Database error occurred",
                    "code": "DATABASE_ERROR",
                    "timestamp": chrono::Utc::now().to_rfc3339()
                }))
            },
            AppError::Auth(msg) => HttpResponse::Unauthorized().json(serde_json::json!({
                "status": "error", 
                "message": msg,
                "code": "AUTHENTICATION_ERROR",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
            AppError::Validation(msg) => HttpResponse::BadRequest().json(serde_json::json!({
                "status": "error",
                "message": msg,
                "code": "VALIDATION_ERROR",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
            AppError::NotFound(msg) => HttpResponse::NotFound().json(serde_json::json!({
                "status": "error",
                "message": msg,
                "code": "NOT_FOUND",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
            AppError::Conflict(msg) => HttpResponse::Conflict().json(serde_json::json!({
                "status": "error",
                "message": msg,
                "code": "CONFLICT",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
            AppError::BadRequest(msg) => HttpResponse::BadRequest().json(serde_json::json!({
                "status": "error",
                "message": msg,
                "code": "BAD_REQUEST",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
            AppError::InternalServer => {
                log::error!("Internal server error occurred");
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "error",
                    "message": "Internal server error",
                    "code": "INTERNAL_ERROR",
                    "timestamp": chrono::Utc::now().to_rfc3339()
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
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::InternalServer => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
