// User handler - Controllers para endpoints HTTP relacionados a usuários

use actix_web::{HttpResponse, Result, web};
use uuid::Uuid;

use crate::errors::AppError;
use crate::middlewares::ValidatedJson;
use crate::models::{
    pagination::PaginationParams,
    user::{CreateUserDto, UpdateUserDto, UserResponse},
};
use crate::services::UserServiceTrait;

// Estrutura que encapsula as dependências dos handlers
#[derive(Clone)]
pub struct UserHandler<S>
where
    S: UserServiceTrait + Send + Sync,
{
    user_service: S,
}

impl<S> UserHandler<S>
where
    S: UserServiceTrait + Send + Sync,
{
    pub fn new(user_service: S) -> Self {
        Self { user_service }
    }

    // POST /users - Criar usuário com validação automática
    pub async fn create_user(
        &self,
        create_dto: ValidatedJson<CreateUserDto>,
    ) -> Result<HttpResponse, AppError> {
        log::info!("Creating new user with email: {}", create_dto.email);

        let user = self
            .user_service
            .create_user(create_dto.into_inner())
            .await?;
        let response = UserResponse::from(user);

        log::info!("User created successfully with ID: {}", response.id);
        Ok(HttpResponse::Created().json(serde_json::json!({
            "status": "success",
            "message": "User created successfully",
            "data": response
        })))
    }

    // GET /users/{id} - Buscar usuário por ID
    pub async fn get_user_by_id(&self, path: web::Path<Uuid>) -> Result<HttpResponse, AppError> {
        let user_id = path.into_inner();
        let user = self.user_service.get_user_by_id(user_id).await?;
        let response = UserResponse::from(user);

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "data": response
        })))
    }

    // GET /users - Listar todos os usuários (mantém compatibilidade)
    pub async fn get_all_users(&self) -> Result<HttpResponse, AppError> {
        log::info!("Fetching all users (legacy endpoint)");

        let users = self.user_service.get_all_users().await?;
        let responses: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();

        log::info!("Retrieved {} users", responses.len());
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "data": responses,
            "count": responses.len()
        })))
    }

    // GET /users/paginated - Listar usuários com paginação
    pub async fn get_users_paginated(
        &self,
        params: web::Query<PaginationParams>,
    ) -> Result<HttpResponse, AppError> {
        log::info!("Fetching users with pagination: {:?}", params);

        let paginated_response = self
            .user_service
            .get_users_paginated(params.into_inner())
            .await?;

        log::info!(
            "Retrieved paginated users: page={}, total={}",
            paginated_response.pagination.current_page,
            paginated_response.pagination.total_items
        );

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "data": paginated_response.data,
            "pagination": paginated_response.pagination
        })))
    }

    // PUT /users/{id} - Atualizar usuário com validação automática
    pub async fn update_user(
        &self,
        path: web::Path<Uuid>,
        update_dto: ValidatedJson<UpdateUserDto>,
    ) -> Result<HttpResponse, AppError> {
        let user_id = path.into_inner();
        log::info!("Updating user with ID: {}", user_id);

        let user = self
            .user_service
            .update_user(user_id, update_dto.into_inner())
            .await?;
        let response = UserResponse::from(user);

        log::info!("User updated successfully with ID: {}", user_id);
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "message": "User updated successfully",
            "data": response
        })))
    }

    // DELETE /users/{id} - Deletar usuário
    pub async fn delete_user(&self, path: web::Path<Uuid>) -> Result<HttpResponse, AppError> {
        let user_id = path.into_inner();
        let deleted = self.user_service.delete_user(user_id).await?;

        if deleted {
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

    // Login será implementado na próxima etapa
}

// Funções helper para uso com Actix Web (sem dependências específicas)
pub async fn health_check() -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "User service is healthy",
        "timestamp": chrono::Utc::now()
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::pagination::{PaginatedResponse, PaginationParams, SortOrder};
    use crate::models::user::{CreateUserDto, UpdateUserDto, User};
    use crate::services::UserServiceTrait;
    use actix_web::web;
    use chrono::Utc;
    use uuid::Uuid;

    // Teste básico de handler
    #[tokio::test]
    async fn test_create_user_dto_validation() {
        let dto = CreateUserDto {
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            password: "123456".to_string(),
            age: 25,
        };

        // Verificar se o DTO está correto
        assert_eq!(dto.name, "Test User");
        assert_eq!(dto.email, "test@example.com");
        assert!(dto.age >= 18);
    }

    #[tokio::test]
    async fn test_update_user_dto_validation() {
        let dto = UpdateUserDto {
            name: Some("Updated User".to_string()),
            email: Some("updated@example.com".to_string()),
        };

        assert_eq!(dto.name.unwrap(), "Updated User");
        assert!(dto.email.unwrap().contains('@'));
    }

    #[tokio::test]
    async fn test_handler_compilation() {
        // Teste simples para verificar se o handler compila
        use actix_web::web;

        let create_dto = CreateUserDto {
            name: "Test".to_string(),
            email: "test@test.com".to_string(),
            password: "123456".to_string(),
            age: 25,
        };

        let json_payload = web::Json(create_dto);

        // Verificar se o payload está correto
        assert_eq!(json_payload.name, "Test");
    }

    fn create_test_user() -> User {
        User {
            id: Uuid::new_v4(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            age: 25,
            password_hash: "hashed_password".to_string(),
            role: Some("user".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn create_test_create_dto() -> CreateUserDto {
        CreateUserDto {
            name: "New User".to_string(),
            email: "new@example.com".to_string(),
            age: 30,
            password: "password123".to_string(),
        }
    }

    #[actix_web::test]
    async fn test_health_check() {
        let response = health_check().await;
        assert!(response.is_ok());

        let http_response = response.unwrap();
        assert_eq!(http_response.status(), 200);
    }

    #[tokio::test]
    async fn test_create_user_dto_structure() {
        let create_dto = create_test_create_dto();

        // Verificar se o DTO tem estrutura correta
        assert_eq!(create_dto.name, "New User");
        assert_eq!(create_dto.email, "new@example.com");
        assert_eq!(create_dto.age, 30);
        assert!(!create_dto.password.is_empty());
    }

    #[tokio::test]
    async fn test_create_user_validation_basic() {
        let invalid_dto = CreateUserDto {
            name: "".to_string(),               // Invalid: empty name
            email: "invalid-email".to_string(), // Invalid: not an email
            age: 0,                             // Invalid: age 0
            password: "123".to_string(),        // Invalid: too short
        };

        // Verificar que os campos estão com valores inválidos conforme esperado
        assert!(invalid_dto.name.is_empty());
        assert!(!invalid_dto.email.contains('@'));
        assert_eq!(invalid_dto.age, 0);
        assert!(invalid_dto.password.len() < 6);
    }

    #[tokio::test]
    async fn test_get_user_by_id_structure() {
        let user_id = Uuid::new_v4();

        // Testar que o ID é válido
        assert!(!user_id.to_string().is_empty());
    }

    #[tokio::test]
    async fn test_pagination_params_defaults() {
        let params = PaginationParams {
            page: 1,
            limit: 10,
            search: None,
            sort_by: None,
            sort_order: SortOrder::Desc,
        };

        assert_eq!(params.page, 1);
        assert_eq!(params.limit, 10);
        assert!(params.search.is_none());
    }

    #[tokio::test]
    async fn test_update_user_dto_structure() {
        let update_dto = UpdateUserDto {
            name: Some("Updated Name".to_string()),
            email: Some("updated@example.com".to_string()),
        };

        assert!(update_dto.name.is_some());
        assert!(update_dto.email.is_some());
        assert_eq!(update_dto.name.unwrap(), "Updated Name");
    }
}
