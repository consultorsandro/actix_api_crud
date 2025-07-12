// Services - Lógica de negócio da aplicação
// Aqui ficará a lógica de negócio que não depende de detalhes de infraestrutura

use async_trait::async_trait;
use uuid::Uuid;
use crate::errors::AppError;
use crate::models::{
    user::{User, CreateUserDto, UpdateUserDto}, 
    PaginationParams, PaginatedResponse, UserResponse
};

pub mod user_service;

// Trait para User Service com paginação
#[async_trait]
pub trait UserServiceTrait {
    async fn create_user(&self, create_dto: CreateUserDto) -> Result<User, AppError>;
    async fn get_user_by_id(&self, id: Uuid) -> Result<User, AppError>;
    async fn get_all_users(&self) -> Result<Vec<User>, AppError>;
    async fn get_users_paginated(&self, params: PaginationParams) -> Result<PaginatedResponse<UserResponse>, AppError>;
    async fn update_user(&self, id: Uuid, update_dto: UpdateUserDto) -> Result<User, AppError>;
    async fn delete_user(&self, id: Uuid) -> Result<bool, AppError>;
    async fn authenticate_user(&self, email: &str, password: &str) -> Result<User, AppError>;
}
