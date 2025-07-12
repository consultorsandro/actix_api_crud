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
