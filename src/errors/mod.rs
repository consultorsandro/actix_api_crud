// Errors - Tratamento estruturado de erros
// Aqui ficarão os tipos de erro customizados e suas implementações

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
