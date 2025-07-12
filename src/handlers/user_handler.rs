// User handler - Controllers para endpoints HTTP relacionados a usuários

use actix_web::{HttpResponse, Result, web};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{
    pagination::PaginationParams,
    user::{CreateUserDto, UpdateUserDto, UserResponse},
};
use crate::services::UserServiceTrait;
use crate::middlewares::ValidatedJson;

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
