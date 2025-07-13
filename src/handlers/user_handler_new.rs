use actix_web::{HttpResponse, Result, web};
use log::{error, info};

use crate::errors::AppError;
use crate::middlewares::validation::ValidatedJson;
use crate::models::{
    pagination::{PaginatedResponse, PaginationParams, SortOrder},
    user::{CreateUserDto, UpdateUserDto, UserResponse},
};
use crate::services::UserServiceTrait;
use uuid::Uuid;

// Handler genérico para operações de usuário
#[derive(Clone)]
pub struct UserHandler<S: UserServiceTrait> {
    user_service: S,
}

impl<S: UserServiceTrait> UserHandler<S> {
    pub fn new(user_service: S) -> Self {
        Self { user_service }
    }

    // POST /users - Criar novo usuário com validação automática
    pub async fn create_user(
        &self,
        create_dto: ValidatedJson<CreateUserDto>,
    ) -> Result<HttpResponse, AppError> {
        info!("Creating new user with email: {}", create_dto.email);

        match self.user_service.create_user(create_dto.into_inner()).await {
            Ok(user) => {
                let response = UserResponse::from(user);

                info!("User created successfully with ID: {}", response.id);
                Ok(HttpResponse::Created().json(serde_json::json!({
                    "status": "success",
                    "message": "User created successfully",
                    "data": response
                })))
            }
            Err(e) => {
                error!("Failed to create user: {}", e);
                Err(e)
            }
        }
    }

    // GET /users/{id} - Buscar usuário por ID
    pub async fn get_user_by_id(&self, path: web::Path<Uuid>) -> Result<HttpResponse, AppError> {
        let user_id = path.into_inner();
        info!("Fetching user with ID: {}", user_id);

        match self.user_service.get_user_by_id(user_id).await {
            Ok(user) => {
                let response = UserResponse::from(user);
                info!("User found with ID: {}", user_id);
                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "status": "success",
                    "data": response
                })))
            }
            Err(e) => {
                error!("Failed to get user by ID {}: {}", user_id, e);
                Err(e)
            }
        }
    }

    // GET /users - Listar todos os usuários
    pub async fn get_all_users(&self) -> Result<HttpResponse, AppError> {
        info!("Fetching all users");

        match self.user_service.get_all_users().await {
            Ok(users) => {
                let responses: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();

                info!("Retrieved {} users", responses.len());
                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "status": "success",
                    "data": responses,
                    "count": responses.len()
                })))
            }
            Err(e) => {
                error!("Failed to get all users: {}", e);
                Err(e)
            }
        }
    }

    // GET /users/paginated - Listar usuários com paginação
    pub async fn get_users_paginated(
        &self,
        params: web::Query<PaginationParams>,
    ) -> Result<HttpResponse, AppError> {
        info!("Fetching users with pagination: {:?}", params);

        match self
            .user_service
            .get_users_paginated(params.into_inner())
            .await
        {
            Ok(paginated_response) => {
                info!(
                    "Retrieved paginated users: page={}, total={}",
                    paginated_response.pagination.current_page, paginated_response.pagination.total_items
                );

                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "status": "success",
                    "data": paginated_response
                })))
            }
            Err(e) => {
                error!("Failed to get paginated users: {}", e);
                Err(e)
            }
        }
    }

    // PUT /users/{id} - Atualizar usuário com validação automática
    pub async fn update_user(
        &self,
        path: web::Path<Uuid>,
        update_dto: ValidatedJson<UpdateUserDto>,
    ) -> Result<HttpResponse, AppError> {
        let user_id = path.into_inner();

        info!("Updating user with ID: {}", user_id);

        match self
            .user_service
            .update_user(user_id, update_dto.into_inner())
            .await
        {
            Ok(user) => {
                let response = UserResponse::from(user);

                info!("User updated successfully with ID: {}", user_id);
                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "status": "success",
                    "message": "User updated successfully",
                    "data": response
                })))
            }
            Err(e) => {
                error!("Failed to update user with ID {}: {}", user_id, e);
                Err(e)
            }
        }
    }

    // DELETE /users/{id} - Deletar usuário
    pub async fn delete_user(&self, path: web::Path<Uuid>) -> Result<HttpResponse, AppError> {
        let user_id = path.into_inner();
        info!("Deleting user with ID: {}", user_id);

        match self.user_service.delete_user(user_id).await {
            Ok(deleted) => {
                if deleted {
                    info!("User deleted successfully with ID: {}", user_id);
                    Ok(HttpResponse::Ok().json(serde_json::json!({
                        "status": "success",
                        "message": "User deleted successfully"
                    })))
                } else {
                    Ok(HttpResponse::NotFound().json(serde_json::json!({
                        "status": "error",
                        "message": "User not found"
                    })))
                }
            }
            Err(e) => {
                error!("Failed to delete user with ID {}: {}", user_id, e);
                Err(e)
            }
        }
    }
}

// Health check handler
pub async fn health_check() -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "Service is healthy"
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::user::{CreateUserDto, UpdateUserDto, User};
    use chrono::Utc;
    use uuid::Uuid;

    // Teste básico de handler
    #[tokio::test]
    async fn test_create_user_dto_validation() {
        let dto = CreateUserDto {
            name: "John Doe".to_string(),
            email: "john@example.com".to_string(),
            password: "password123".to_string(),
            age: 30,
        };

        // Verificar que o DTO foi criado corretamente
        assert_eq!(dto.name, "John Doe");
        assert_eq!(dto.email, "john@example.com");
        assert!(dto.age > 18);
        assert!(!dto.password.is_empty());
    }

    #[tokio::test]
    async fn test_update_user_dto_validation() {
        let dto = UpdateUserDto {
            name: Some("Updated Name".to_string()),
            email: Some("updated@example.com".to_string()),
        };

        assert!(dto.name.is_some());
        assert!(dto.email.is_some());
    }

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        assert!(response.is_ok());
    }

    fn create_test_user() -> User {
        User {
            id: Uuid::new_v4(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            age: 25,
            password_hash: "$2b$12$test_hash".to_string(),
            role: Some("user".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_user_creation() {
        let user = create_test_user();
        assert!(!user.id.to_string().is_empty());
        assert_eq!(user.name, "Test User");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.age, 25);
    }
}
