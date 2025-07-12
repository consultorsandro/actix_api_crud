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
    pub role: Option<String>, // Role do usuário (admin, user, etc.)
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

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    #[test]
    fn test_user_response_from_user() {
        let user = User {
            id: Uuid::new_v4(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            age: 25,
            password_hash: "hashed_password".to_string(),
            role: Some("user".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let response = UserResponse::from(user.clone());

        assert_eq!(response.id, user.id);
        assert_eq!(response.name, user.name);
        assert_eq!(response.email, user.email);
        assert_eq!(response.age, user.age);
        assert_eq!(response.role, user.role);
        // Note: password_hash should not be in UserResponse
    }

    #[test]
    fn test_create_user_dto_validation_valid() {
        let dto = CreateUserDto {
            name: "Valid Name".to_string(),
            email: "valid@example.com".to_string(),
            age: 25,
            password: "validpassword".to_string(),
        };

        assert!(dto.validate().is_ok());
    }

    #[test]
    fn test_create_user_dto_validation_invalid_email() {
        let dto = CreateUserDto {
            name: "Valid Name".to_string(),
            email: "invalid-email".to_string(),
            age: 25,
            password: "validpassword".to_string(),
        };

        let validation_result = dto.validate();
        assert!(validation_result.is_err());

        let errors = validation_result.unwrap_err();
        assert!(errors.field_errors().contains_key("email"));
    }

    #[test]
    fn test_create_user_dto_validation_short_name() {
        let dto = CreateUserDto {
            name: "A".to_string(), // Too short
            email: "valid@example.com".to_string(),
            age: 25,
            password: "validpassword".to_string(),
        };

        let validation_result = dto.validate();
        assert!(validation_result.is_err());

        let errors = validation_result.unwrap_err();
        assert!(errors.field_errors().contains_key("name"));
    }

    #[test]
    fn test_create_user_dto_validation_invalid_age() {
        let dto = CreateUserDto {
            name: "Valid Name".to_string(),
            email: "valid@example.com".to_string(),
            age: 200, // Too high
            password: "validpassword".to_string(),
        };

        let validation_result = dto.validate();
        assert!(validation_result.is_err());

        let errors = validation_result.unwrap_err();
        assert!(errors.field_errors().contains_key("age"));
    }

    #[test]
    fn test_create_user_dto_validation_short_password() {
        let dto = CreateUserDto {
            name: "Valid Name".to_string(),
            email: "valid@example.com".to_string(),
            age: 25,
            password: "123".to_string(), // Too short
        };

        let validation_result = dto.validate();
        assert!(validation_result.is_err());

        let errors = validation_result.unwrap_err();
        assert!(errors.field_errors().contains_key("password"));
    }

    #[test]
    fn test_update_user_dto_validation_valid() {
        let dto = UpdateUserDto {
            name: Some("Updated Name".to_string()),
            email: Some("updated@example.com".to_string()),
        };

        assert!(dto.validate().is_ok());
    }

    #[test]
    fn test_update_user_dto_validation_none_values() {
        let dto = UpdateUserDto {
            name: None,
            email: None,
        };

        assert!(dto.validate().is_ok());
    }

    #[test]
    fn test_login_dto_validation_valid() {
        let dto = LoginDto {
            email: "user@example.com".to_string(),
            password: "password123".to_string(),
        };

        assert!(dto.validate().is_ok());
    }

    #[test]
    fn test_login_dto_validation_invalid_email() {
        let dto = LoginDto {
            email: "invalid-email".to_string(),
            password: "password123".to_string(),
        };

        let validation_result = dto.validate();
        assert!(validation_result.is_err());

        let errors = validation_result.unwrap_err();
        assert!(errors.field_errors().contains_key("email"));
    }

    #[test]
    fn test_login_dto_validation_empty_password() {
        let dto = LoginDto {
            email: "user@example.com".to_string(),
            password: "".to_string(),
        };

        let validation_result = dto.validate();
        assert!(validation_result.is_err());

        let errors = validation_result.unwrap_err();
        assert!(errors.field_errors().contains_key("password"));
    }
}
