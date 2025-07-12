// src/auth/models.rs
// Etapa 5: Modelos de dados para autenticação

use serde::{Deserialize, Serialize};
use validator::Validate;

/// DTO para login de usuário
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Email deve ter formato válido"))]
    pub email: String,
    
    #[validate(length(min = 6, message = "Senha deve ter pelo menos 6 caracteres"))]
    pub password: String,
}

/// DTO para registro de usuário
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 2, max = 100, message = "Nome deve ter entre 2 e 100 caracteres"))]
    pub name: String,
    
    #[validate(email(message = "Email deve ter formato válido"))]
    pub email: String,
    
    #[validate(length(min = 6, message = "Senha deve ter pelo menos 6 caracteres"))]
    pub password: String,
    
    #[validate(range(min = 1, max = 150, message = "Idade deve estar entre 1 e 150 anos"))]
    pub age: i32,
}

/// DTO para mudança de senha
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 6, message = "Senha atual deve ter pelo menos 6 caracteres"))]
    pub current_password: String,
    
    #[validate(length(min = 6, message = "Nova senha deve ter pelo menos 6 caracteres"))]
    pub new_password: String,
}

/// Resposta de autenticação com token
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: UserInfo,
}

/// Informações básicas do usuário para resposta
#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
    pub email: String,
    pub role: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Resposta de refresh token
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    pub token: String,
    pub expires_in: i64,
}

/// Request para refresh token
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct RefreshTokenRequest {
    #[validate(length(min = 1, message = "Refresh token é obrigatório"))]
    pub refresh_token: String,
}

impl AuthResponse {
    pub fn new(token: String, expires_in: i64, user: UserInfo) -> Self {
        Self {
            token,
            token_type: "Bearer".to_string(),
            expires_in,
            user,
        }
    }
}

impl UserInfo {
    pub fn from_user(user: &crate::models::user::User) -> Self {
        Self {
            id: user.id.to_string(),
            name: user.name.clone(),
            email: user.email.clone(),
            role: user.role.clone().unwrap_or_else(|| "user".to_string()),
            created_at: user.created_at,
        }
    }
}
