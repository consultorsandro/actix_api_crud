// Errors - Tratamento estruturado de erros
// Aqui ficarão os tipos de erro customizados e suas implementações

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use chrono;
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

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal server error")]
    InternalServer,

    // Etapa 5: Novos erros para autenticação JWT
    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Authorization error: {0}")]
    Authorization(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Internal error: {0}")]
    Internal(String),
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
            }
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
            // Etapa 5: Novos casos para autenticação
            AppError::Authentication(msg) => HttpResponse::Unauthorized().json(serde_json::json!({
                "status": "error",
                "message": msg,
                "code": "AUTHENTICATION_ERROR",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
            AppError::Authorization(msg) => HttpResponse::Forbidden().json(serde_json::json!({
                "status": "error",
                "message": msg,
                "code": "AUTHORIZATION_ERROR",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
            AppError::Configuration(msg) => {
                log::error!("Configuration error: {}", msg);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "error",
                    "message": "Service configuration error",
                    "code": "CONFIGURATION_ERROR",
                    "timestamp": chrono::Utc::now().to_rfc3339()
                }))
            }
            AppError::Internal(msg) => {
                log::error!("Internal error: {}", msg);
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
            // Etapa 5: Novos status codes
            AppError::Authentication(_) => StatusCode::UNAUTHORIZED,
            AppError::Authorization(_) => StatusCode::FORBIDDEN,
            AppError::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;

    #[test]
    fn test_app_error_display() {
        let error = AppError::Database("Connection failed".to_string());
        assert_eq!(error.to_string(), "Database error: Connection failed");

        let error = AppError::Authentication("Invalid token".to_string());
        assert_eq!(error.to_string(), "Authentication error: Invalid token");

        let error = AppError::NotFound("User not found".to_string());
        assert_eq!(error.to_string(), "Not found: User not found");
    }

    #[test]
    fn test_app_error_status_codes() {
        assert_eq!(
            AppError::Database("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AppError::Auth("test".to_string()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppError::Validation("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AppError::NotFound("test".to_string()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppError::Conflict("test".to_string()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AppError::BadRequest("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AppError::InternalServer.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AppError::Authentication("test".to_string()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppError::Authorization("test".to_string()).status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AppError::Configuration("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AppError::Internal("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_app_error_response_structure() {
        let error = AppError::Validation("Invalid input".to_string());
        let response = error.error_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Test that response contains expected JSON structure
        // Note: In a real test, you might want to extract and parse the JSON body
    }

    #[test]
    fn test_error_variants_compilation() {
        // Test that all error variants can be created
        let _db_error = AppError::Database("test".to_string());
        let _auth_error = AppError::Auth("test".to_string());
        let _validation_error = AppError::Validation("test".to_string());
        let _not_found_error = AppError::NotFound("test".to_string());
        let _conflict_error = AppError::Conflict("test".to_string());
        let _bad_request_error = AppError::BadRequest("test".to_string());
        let _internal_server_error = AppError::InternalServer;
        let _authentication_error = AppError::Authentication("test".to_string());
        let _authorization_error = AppError::Authorization("test".to_string());
        let _configuration_error = AppError::Configuration("test".to_string());
        let _internal_error = AppError::Internal("test".to_string());
    }

    #[test]
    fn test_error_debug_formatting() {
        let error = AppError::Database("Connection timeout".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Database"));
        assert!(debug_str.contains("Connection timeout"));
    }
}
