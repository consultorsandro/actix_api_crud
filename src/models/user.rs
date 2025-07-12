// User model
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

// Entidade User principal
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub age: i32,
    #[serde(skip_serializing)] // Nunca serializar a senha
    pub password_hash: String,
    pub role: Option<String>,  // Role do usuário (admin, user, etc.)
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// DTO para resposta de usuário (sem dados sensíveis)
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub age: i32,
    pub role: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: user.id,
            name: user.name,
            email: user.email,
            age: user.age,
            role: user.role,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

// DTO para criação de usuários com validações
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct CreateUserDto {
    #[validate(length(
        min = 2,
        max = 100,
        message = "Name must be between 2 and 100 characters"
    ))]
    pub name: String,

    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(range(min = 1, max = 150, message = "Age must be between 1 and 150"))]
    pub age: i32,

    #[validate(length(min = 6, message = "Password must be at least 6 characters"))]
    pub password: String,
}

// DTO para atualização de usuários com validações
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct UpdateUserDto {
    #[validate(length(
        min = 2,
        max = 100,
        message = "Name must be between 2 and 100 characters"
    ))]
    pub name: Option<String>,

    #[validate(email(message = "Invalid email format"))]
    pub email: Option<String>,
}

// DTO para login com validações
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct LoginDto {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}
