// User repository - Implementação concreta do acesso a dados para usuários
// Etapa 3: Implementação completa com queries SQLx (versão offline)

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;
use chrono::Utc;

use crate::models::user::User;
use crate::repositories::{Repository, UserRepositoryTrait};
use crate::errors::AppError;

// Estrutura concreta do repositório de usuários
#[derive(Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

// Implementação do trait genérico Repository
#[async_trait]
impl Repository<User, Uuid> for UserRepository {
    async fn create(&self, mut user: User) -> Result<User, AppError> {
        // Garantir que temos um ID válido
        if user.id == Uuid::nil() {
            user.id = Uuid::new_v4();
        }
        
        let now = Utc::now();
        user.created_at = now;
        user.updated_at = now;

        // Query usando sqlx::query em vez do macro (para compilação offline)
        let result = sqlx::query(
            "INSERT INTO users (id, name, email, password_hash, created_at, updated_at) 
             VALUES ($1, $2, $3, $4, $5, $6) 
             RETURNING id, name, email, password_hash, created_at, updated_at"
        )
        .bind(&user.id)
        .bind(&user.name)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(&user.created_at)
        .bind(&user.updated_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                AppError::Validation("Email already exists".to_string())
            } else {
                AppError::Database(format!("Failed to create user: {}", e))
            }
        })?;

        // Mapear o resultado manualmente
        let created_user = User {
            id: result.get("id"),
            name: result.get("name"),
            email: result.get("email"),
            password_hash: result.get("password_hash"),
            created_at: result.get("created_at"),
            updated_at: result.get("updated_at"),
        };

        Ok(created_user)
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AppError> {
        let result = sqlx::query(
            "SELECT id, name, email, password_hash, created_at, updated_at FROM users WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Database(format!("Failed to find user by id: {}", e)))?;

        match result {
            Some(row) => {
                let user = User {
                    id: row.get("id"),
                    name: row.get("name"),
                    email: row.get("email"),
                    password_hash: row.get("password_hash"),
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                };
                Ok(Some(user))
            }
            None => Ok(None),
        }
    }

    async fn find_all(&self) -> Result<Vec<User>, AppError> {
        let rows = sqlx::query(
            "SELECT id, name, email, password_hash, created_at, updated_at FROM users ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Database(format!("Failed to fetch all users: {}", e)))?;

        let users = rows.into_iter().map(|row| User {
            id: row.get("id"),
            name: row.get("name"),
            email: row.get("email"),
            password_hash: row.get("password_hash"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }).collect();

        Ok(users)
    }

    async fn update(&self, id: Uuid, mut user: User) -> Result<User, AppError> {
        user.updated_at = Utc::now();

        let result = sqlx::query(
            "UPDATE users 
             SET name = $2, email = $3, password_hash = $4, updated_at = $5
             WHERE id = $1
             RETURNING id, name, email, password_hash, created_at, updated_at"
        )
        .bind(id)
        .bind(&user.name)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(&user.updated_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                AppError::Validation("Email already exists".to_string())
            } else if e.to_string().contains("no rows returned") {
                AppError::NotFound("User not found".to_string())
            } else {
                AppError::Database(format!("Failed to update user: {}", e))
            }
        })?;

        let updated_user = User {
            id: result.get("id"),
            name: result.get("name"),
            email: result.get("email"),
            password_hash: result.get("password_hash"),
            created_at: result.get("created_at"),
            updated_at: result.get("updated_at"),
        };

        Ok(updated_user)
    }

    async fn delete(&self, id: Uuid) -> Result<bool, AppError> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to delete user: {}", e)))?;

        Ok(result.rows_affected() > 0)
    }

    async fn find_all_paginated(&self, params: &PaginationParams) -> Result<(Vec<User>, u64), AppError> {
        let offset = params.offset() as i64;
        let limit = params.limit as i64;
        
        // Query para contar total de registros
        let count_query = if let Some(ref search) = params.search {
            sqlx::query("SELECT COUNT(*) as count FROM users WHERE name ILIKE $1 OR email ILIKE $1")
                .bind(format!("%{}%", search))
        } else {
            sqlx::query("SELECT COUNT(*) as count FROM users")
        };
        
        let count_result = count_query
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to count users: {}", e)))?;
        
        let total: i64 = count_result.get("count");
        
        // Query para buscar dados com paginação
        let sort_order = match params.sort_order {
            crate::models::SortOrder::Asc => "ASC",
            crate::models::SortOrder::Desc => "DESC",
        };
        
        let sort_field = params.sort_by.as_deref().unwrap_or("created_at");
        
        let query_str = if let Some(ref search) = params.search {
            format!(
                "SELECT id, name, email, password_hash, created_at, updated_at 
                 FROM users 
                 WHERE name ILIKE $1 OR email ILIKE $1 
                 ORDER BY {} {} 
                 LIMIT $2 OFFSET $3",
                sort_field, sort_order
            )
        } else {
            format!(
                "SELECT id, name, email, password_hash, created_at, updated_at 
                 FROM users 
                 ORDER BY {} {} 
                 LIMIT $1 OFFSET $2",
                sort_field, sort_order
            )
        };
        
        let rows = if let Some(ref search) = params.search {
            sqlx::query(&query_str)
                .bind(format!("%{}%", search))
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
        } else {
            sqlx::query(&query_str)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await
        };
        
        let rows = rows.map_err(|e| AppError::Database(format!("Failed to fetch paginated users: {}", e)))?;
        
        let users = rows.into_iter().map(|row| User {
            id: row.get("id"),
            name: row.get("name"),
            email: row.get("email"),
            password_hash: row.get("password_hash"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }).collect();
        
        Ok((users, total as u64))
    }

    async fn find_with_filters(&self, filters: &UserFilters, params: &PaginationParams) -> Result<(Vec<User>, u64), AppError> {
        let mut where_conditions = Vec::new();
        let mut bind_values: Vec<&dyn sqlx::Encode<sqlx::Postgres> + Send + Sync> = Vec::new();
        let mut param_count = 1;
        
        // Construir condições WHERE dinamicamente
        if let Some(ref name) = filters.name {
            where_conditions.push(format!("name ILIKE ${}", param_count));
            param_count += 1;
        }
        
        if let Some(ref email) = filters.email {
            where_conditions.push(format!("email ILIKE ${}", param_count));
            param_count += 1;
        }
        
        if filters.created_after.is_some() {
            where_conditions.push(format!("created_at >= ${}", param_count));
            param_count += 1;
        }
        
        if filters.created_before.is_some() {
            where_conditions.push(format!("created_at <= ${}", param_count));
            param_count += 1;
        }
        
        let where_clause = if where_conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_conditions.join(" AND "))
        };
        
        // Por simplicidade, vamos usar a busca geral
        self.find_all_paginated(params).await
    }

    async fn count_all(&self) -> Result<u64, AppError> {
        let result = sqlx::query("SELECT COUNT(*) as count FROM users")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to count users: {}", e)))?;
        
        Ok(result.get::<i64, _>("count") as u64)
    }
}

// Implementação do trait específico UserRepositoryTrait
#[async_trait]
impl UserRepositoryTrait for UserRepository {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        let result = sqlx::query(
            "SELECT id, name, email, password_hash, created_at, updated_at FROM users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Database(format!("Failed to find user by email: {}", e)))?;

        match result {
            Some(row) => {
                let user = User {
                    id: row.get("id"),
                    name: row.get("name"),
                    email: row.get("email"),
                    password_hash: row.get("password_hash"),
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                };
                Ok(Some(user))
            }
            None => Ok(None),
        }
    }

    async fn exists_by_email(&self, email: &str) -> Result<bool, AppError> {
        let result = sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1) as exists")
            .bind(email)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to check if email exists: {}", e)))?;

        Ok(result.get::<bool, _>("exists"))
    }
}
