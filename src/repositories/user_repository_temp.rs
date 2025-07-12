// User repository - Implementação concreta do acesso a dados para usuários
// Etapa 3: Implementação completa com queries SQLx (versão offline)

use async_trait::async_trait;
use chrono::Utc;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{
    pagination::{PaginationParams, UserFilters},
    user::User,
};
use crate::repositories::{Repository, UserRepositoryTrait};

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
             RETURNING id, name, email, password_hash, created_at, updated_at",
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
            age: result.get("age"),
            password_hash: result.get("password_hash"),
            role: result.get("role"),
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

        let users = rows
            .into_iter()
            .map(|row| User {
                id: row.get("id"),
                name: row.get("name"),
                email: row.get("email"),
                password_hash: row.get("password_hash"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
            .collect();

        Ok(users)
    }

    async fn update(&self, id: Uuid, mut user: User) -> Result<User, AppError> {
        user.updated_at = Utc::now();

        let result = sqlx::query(
            "UPDATE users 
             SET name = $2, email = $3, password_hash = $4, updated_at = $5
             WHERE id = $1
             RETURNING id, name, email, password_hash, created_at, updated_at",
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

    async fn find_all_paginated(
        &self,
        params: &PaginationParams,
    ) -> Result<(Vec<User>, u64), AppError> {
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

        let query_str = if let Some(ref _search) = params.search {
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

        let rows = rows
            .map_err(|e| AppError::Database(format!("Failed to fetch paginated users: {}", e)))?;

        let users = rows
            .into_iter()
            .map(|row| User {
                id: row.get("id"),
                name: row.get("name"),
                email: row.get("email"),
                password_hash: row.get("password_hash"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
            .collect();

        Ok((users, total as u64))
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

    // Implementação simplificada dos métodos de paginação
    async fn find_with_filters(
        &self,
        _filters: &UserFilters,
        params: &PaginationParams,
    ) -> Result<(Vec<User>, u64), AppError> {
        // Por enquanto, ignoramos os filtros e fazemos uma consulta simples
        let offset = (params.page - 1) * params.limit;

        let users = sqlx::query_as::<_, User>(
            "SELECT id, name, email, password_hash, created_at, updated_at 
             FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(params.limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Database(format!("Failed to find users: {}", e)))?;

        let total = self.count_all().await?;
        Ok((users, total))
    }

    async fn count_all(&self) -> Result<u64, AppError> {
        let result = sqlx::query("SELECT COUNT(*) as count FROM users")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to count users: {}", e)))?;

        Ok(result.get::<i64, _>("count") as u64)
    }

    // Etapa 5: Métodos de autenticação
    async fn find_by_email_direct(&self, email: &str) -> Result<User, AppError> {
        match self.find_by_email(email).await? {
            Some(user) => Ok(user),
            None => Err(AppError::NotFound(format!("User with email {} not found", email))),
        }
    }

    async fn create_with_password(&self, create_dto: CreateUserDto, password_hash: String, role: String) -> Result<User, AppError> {
        let user_id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, name, email, age, password_hash, role, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
            user_id,
            create_dto.name,
            create_dto.email,
            create_dto.age,
            password_hash,
            role,
            now,
            now
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("unique constraint") {
                AppError::Conflict("Email already exists".to_string())
            } else {
                AppError::Database(format!("Failed to create user: {}", e))
            }
        })?;

        log::info!("User created successfully with ID: {}", user.id);
        Ok(user)
    }

    async fn update_password(&self, id: Uuid, new_password_hash: String) -> Result<(), AppError> {
        let updated_at = chrono::Utc::now();

        let result = sqlx::query!(
            r#"
            UPDATE users 
            SET password_hash = $1, updated_at = $2
            WHERE id = $3
            "#,
            new_password_hash,
            updated_at,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(format!("Failed to update password: {}", e)))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("User with ID {} not found", id)));
        }

        log::info!("Password updated successfully for user: {}", id);
        Ok(())
    }
}
