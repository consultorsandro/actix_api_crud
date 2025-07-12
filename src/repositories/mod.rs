// Repositories - Camada de acesso a dados
// Aqui ficarão as implementações de acesso ao banco de dados

use crate::errors::AppError;
use crate::models::{PaginationParams, UserFilters, user::User};
use async_trait::async_trait;
use uuid::Uuid;

pub mod user_repository;

// Trait genérico para operações básicas de repositório
#[async_trait]
pub trait Repository<T, ID> {
    async fn create(&self, entity: T) -> Result<T, AppError>;
    async fn find_by_id(&self, id: ID) -> Result<Option<T>, AppError>;
    async fn find_all(&self) -> Result<Vec<T>, AppError>;
    async fn find_all_paginated(
        &self,
        params: &PaginationParams,
    ) -> Result<(Vec<T>, u64), AppError>;
    async fn update(&self, id: ID, entity: T) -> Result<T, AppError>;
    async fn delete(&self, id: ID) -> Result<bool, AppError>;
}

// Trait específico para User Repository
#[async_trait]
pub trait UserRepositoryTrait: Repository<User, Uuid> {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AppError>;
    async fn exists_by_email(&self, email: &str) -> Result<bool, AppError>;
    async fn find_with_filters(
        &self,
        filters: &UserFilters,
        params: &PaginationParams,
    ) -> Result<(Vec<User>, u64), AppError>;
    async fn count_all(&self) -> Result<u64, AppError>;
}
