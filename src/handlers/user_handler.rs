// User handler - Controllers para endpoints HTTP relacionados a usuários

use actix_web::{web, HttpResponse, Result};
use uuid::Uuid;

use crate::models::user::{CreateUserDto, UpdateUserDto, UserResponse, LoginDto, AuthResponse};
use crate::services::UserServiceTrait;
use crate::errors::AppError;

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

    // POST /users - Criar usuário
    pub async fn create_user(&self, create_dto: web::Json<CreateUserDto>) -> Result<HttpResponse, AppError> {
        let user = self.user_service.create_user(create_dto.into_inner()).await?;
        let response = UserResponse::from(user);
        
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

    // GET /users - Listar todos os usuários
    pub async fn get_all_users(&self) -> Result<HttpResponse, AppError> {
        let users = self.user_service.get_all_users().await?;
        let responses: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();
        
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "data": responses,
            "count": responses.len()
        })))
    }

    // PUT /users/{id} - Atualizar usuário
    pub async fn update_user(
        &self, 
        path: web::Path<Uuid>, 
        update_dto: web::Json<UpdateUserDto>
    ) -> Result<HttpResponse, AppError> {
        let user_id = path.into_inner();
        let user = self.user_service.update_user(user_id, update_dto.into_inner()).await?;
        let response = UserResponse::from(user);
        
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

    // POST /auth/login - Autenticar usuário
    pub async fn login(&self, login_dto: web::Json<LoginDto>) -> Result<HttpResponse, AppError> {
        let login_data = login_dto.into_inner();
        let user = self.user_service.authenticate_user(&login_data.email, &login_data.password).await?;
        
        // TODO: Gerar JWT token (será implementado na próxima etapa)
        let token = "temporary_token".to_string(); // Placeholder
        
        let response = AuthResponse {
            token,
            user: UserResponse::from(user),
        };
        
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "message": "Login successful",
            "data": response
        })))
    }
}

// Funções helper para uso com Actix Web (sem dependências específicas)
pub async fn health_check() -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "User service is healthy",
        "timestamp": chrono::Utc::now()
    })))
}
