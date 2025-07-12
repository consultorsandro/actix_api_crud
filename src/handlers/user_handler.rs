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
    use actix_web::{App, HttpResponse, test, web};
    use chrono::Utc;
    use mockall::mock;
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
    async fn test_create_user_success() {
        let mut mock_service = MockUserService::new();
        let test_user = create_test_user();
        let create_dto = create_test_create_dto();

        mock_service
            .expect_create_user()
            .times(1)
            .returning(move |_| Ok(create_test_user()));

        let handler = UserHandler::new(mock_service);
        let validated_json = ValidatedJson::new(create_dto).unwrap();

        let result = handler.create_user(validated_json).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 201);
    }

    #[tokio::test]
    async fn test_create_user_validation_error() {
        let mock_service = MockUserService::new();

        let invalid_dto = CreateUserDto {
            name: "".to_string(),               // Invalid: empty name
            email: "invalid-email".to_string(), // Invalid: not an email
            age: 0,                             // Invalid: age 0
            password: "123".to_string(),        // Invalid: too short
        };

        let handler = UserHandler::new(mock_service);

        // This should fail during validation
        let validation_result = ValidatedJson::new(invalid_dto);
        assert!(validation_result.is_err());
    }

    #[tokio::test]
    async fn test_get_user_by_id_success() {
        let mut mock_service = MockUserService::new();
        let test_user = create_test_user();
        let user_id = test_user.id;

        mock_service
            .expect_get_user_by_id()
            .with(mockall::predicate::eq(user_id))
            .times(1)
            .returning(move |_| Ok(create_test_user()));

        let handler = UserHandler::new(mock_service);
        let path = web::Path::from(user_id);

        let result = handler.get_user_by_id(path).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_get_user_by_id_not_found() {
        let mut mock_service = MockUserService::new();
        let user_id = Uuid::new_v4();

        mock_service
            .expect_get_user_by_id()
            .with(mockall::predicate::eq(user_id))
            .times(1)
            .returning(|_| Err(AppError::NotFound("User not found".to_string())));

        let handler = UserHandler::new(mock_service);
        let path = web::Path::from(user_id);

        let result = handler.get_user_by_id(path).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::NotFound(_) => (),
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_get_users_paginated_success() {
        let mut mock_service = MockUserService::new();
        let test_users = vec![
            UserResponse::from(create_test_user()),
            UserResponse::from(create_test_user()),
        ];

        let paginated_response = PaginatedResponse::new(test_users, 1, 10, 2);

        mock_service
            .expect_get_users_paginated()
            .times(1)
            .returning(move |_| {
                let test_users = vec![
                    UserResponse::from(create_test_user()),
                    UserResponse::from(create_test_user()),
                ];
                Ok(PaginatedResponse::new(test_users, 1, 10, 2))
            });

        let handler = UserHandler::new(mock_service);
        let query = web::Query(PaginationParams {
            page: 1,
            limit: 10,
            search: None,
            sort_by: None,
            sort_order: SortOrder::Desc,
        });

        let result = handler.get_users_paginated(query).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_update_user_success() {
        let mut mock_service = MockUserService::new();
        let test_user = create_test_user();
        let user_id = test_user.id;
        let update_dto = UpdateUserDto {
            name: Some("Updated Name".to_string()),
            email: Some("updated@example.com".to_string()),
        };

        mock_service
            .expect_update_user()
            .with(
                mockall::predicate::eq(user_id),
                mockall::predicate::always(),
            )
            .times(1)
            .returning(move |_, _| Ok(create_test_user()));

        let handler = UserHandler::new(mock_service);
        let path = web::Path::from(user_id);
        let validated_json = ValidatedJson::new(update_dto).unwrap();

        let result = handler.update_user(path, validated_json).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_delete_user_success() {
        let mut mock_service = MockUserService::new();
        let user_id = Uuid::new_v4();

        mock_service
            .expect_delete_user()
            .with(mockall::predicate::eq(user_id))
            .times(1)
            .returning(|_| Ok(true));

        let handler = UserHandler::new(mock_service);
        let path = web::Path::from(user_id);

        let result = handler.delete_user(path).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_delete_user_not_found() {
        let mut mock_service = MockUserService::new();
        let user_id = Uuid::new_v4();

        mock_service
            .expect_delete_user()
            .with(mockall::predicate::eq(user_id))
            .times(1)
            .returning(|_| Ok(false));

        let handler = UserHandler::new(mock_service);
        let path = web::Path::from(user_id);

        let result = handler.delete_user(path).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 404);
    }
}
