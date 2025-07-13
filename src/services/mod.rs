// Services - Lógica de negócio da aplicação
// Aqui ficará a lógica de negócio que não depende de detalhes de infraestrutura

use crate::errors::AppError;
use crate::models::{
    pagination::{PaginatedResponse, PaginationParams},
    user::{CreateUserDto, UpdateUserDto, User, UserResponse},
};
use async_trait::async_trait;
use uuid::Uuid;

pub mod user_service;

// Trait para User Service com paginação
#[async_trait]
pub trait UserServiceTrait {
    async fn create_user(&self, create_dto: CreateUserDto) -> Result<User, AppError>;
    async fn get_user_by_id(&self, id: Uuid) -> Result<User, AppError>;
    async fn get_all_users(&self) -> Result<Vec<User>, AppError>;
    async fn get_users_paginated(
        &self,
        params: PaginationParams,
    ) -> Result<PaginatedResponse<UserResponse>, AppError>;
    async fn update_user(&self, id: Uuid, update_dto: UpdateUserDto) -> Result<User, AppError>;
    async fn delete_user(&self, id: Uuid) -> Result<bool, AppError>;

    // Etapa 5: Métodos de autenticação
    async fn authenticate_user(&self, email: &str, password: &str) -> Result<User, AppError>;
    async fn find_by_email(&self, email: &str) -> Result<User, AppError>;
    async fn find_by_id(&self, id: Uuid) -> Result<User, AppError>;
    async fn create_with_password(
        &self,
        create_dto: CreateUserDto,
        password_hash: String,
        role: String,
    ) -> Result<User, AppError>;
    async fn update_password(&self, id: Uuid, new_password_hash: String) -> Result<(), AppError>;
}
