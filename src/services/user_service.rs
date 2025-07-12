// User service - Implementação da lógica de negócio para usuários

use async_trait::async_trait;
use uuid::Uuid;
use chrono::Utc;
use bcrypt::{hash, verify, DEFAULT_COST};

use crate::models::user::{User, CreateUserDto, UpdateUserDto};
use crate::services::UserServiceTrait;
use crate::repositories::UserRepositoryTrait;
use crate::errors::AppError;
use crate::pagination::{PaginationParams, PaginatedResponse}; // Importar tipos de paginação
use crate::models::user::UserResponse; // Importar UserResponse

// Estrutura concreta do serviço de usuários
#[derive(Clone)]
pub struct UserService<R>
where
    R: UserRepositoryTrait + Send + Sync,
{
    user_repository: R,
}

impl<R> UserService<R>
where
    R: UserRepositoryTrait + Send + Sync,
{
    pub fn new(user_repository: R) -> Self {
        Self { user_repository }
    }

    // Helper para hash de senha
    fn hash_password(&self, password: &str) -> Result<String, AppError> {
        hash(password, DEFAULT_COST)
            .map_err(|_e| AppError::InternalServer)
    }

    // Helper para verificar senha
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, AppError> {
        verify(password, hash)
            .map_err(|_e| AppError::Auth("Invalid password".to_string()))
    }
}

// Implementação do trait UserServiceTrait
#[async_trait]
impl<R> UserServiceTrait for UserService<R>
where
    R: UserRepositoryTrait + Send + Sync,
{
    async fn create_user(&self, create_dto: CreateUserDto) -> Result<User, AppError> {
        // Validar se email já existe
        if self.user_repository.exists_by_email(&create_dto.email).await? {
            return Err(AppError::Validation("Email already exists".to_string()));
        }

        // Validar dados básicos
        if create_dto.name.trim().is_empty() {
            return Err(AppError::Validation("Name cannot be empty".to_string()));
        }

        if create_dto.email.trim().is_empty() || !create_dto.email.contains('@') {
            return Err(AppError::Validation("Invalid email format".to_string()));
        }

        if create_dto.password.len() < 6 {
            return Err(AppError::Validation("Password must be at least 6 characters".to_string()));
        }

        // Hash da senha
        let password_hash = self.hash_password(&create_dto.password)?;

        // Criar usuário
        let user = User {
            id: Uuid::new_v4(),
            name: create_dto.name.trim().to_string(),
            email: create_dto.email.trim().to_lowercase(),
            password_hash,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        self.user_repository.create(user).await
    }

    async fn get_user_by_id(&self, id: Uuid) -> Result<User, AppError> {
        self.user_repository
            .find_by_id(id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))
    }

    async fn get_all_users(&self) -> Result<Vec<User>, AppError> {
        self.user_repository.find_all().await
    }

    async fn update_user(&self, id: Uuid, update_dto: UpdateUserDto) -> Result<User, AppError> {
        // Buscar usuário existente
        let mut user = self.get_user_by_id(id).await?;

        // Atualizar campos fornecidos
        if let Some(name) = update_dto.name {
            if name.trim().is_empty() {
                return Err(AppError::Validation("Name cannot be empty".to_string()));
            }
            user.name = name.trim().to_string();
        }

        if let Some(email) = update_dto.email {
            if email.trim().is_empty() || !email.contains('@') {
                return Err(AppError::Validation("Invalid email format".to_string()));
            }

            let email_lower = email.trim().to_lowercase();
            
            // Verificar se email já existe (exceto para o próprio usuário)
            if let Some(existing_user) = self.user_repository.find_by_email(&email_lower).await? {
                if existing_user.id != id {
                    return Err(AppError::Validation("Email already exists".to_string()));
                }
            }
            
            user.email = email_lower;
        }

        if let Some(password) = update_dto.password {
            if password.len() < 6 {
                return Err(AppError::Validation("Password must be at least 6 characters".to_string()));
            }
            user.password_hash = self.hash_password(&password)?;
        }

        user.updated_at = Utc::now();

        self.user_repository.update(id, user).await
    }

    async fn delete_user(&self, id: Uuid) -> Result<bool, AppError> {
        // Verificar se usuário existe
        self.get_user_by_id(id).await?;
        
        self.user_repository.delete(id).await
    }

    async fn authenticate_user(&self, email: &str, password: &str) -> Result<User, AppError> {
        let email_lower = email.trim().to_lowercase();
        
        let user = self.user_repository
            .find_by_email(&email_lower)
            .await?
            .ok_or_else(|| AppError::Auth("Invalid credentials".to_string()))?;

        if self.verify_password(password, &user.password_hash)? {
            Ok(user)
        } else {
            Err(AppError::Auth("Invalid credentials".to_string()))
        }
    }

    async fn get_users_paginated(&self, mut params: PaginationParams) -> Result<PaginatedResponse<UserResponse>, AppError> {
        // Validar parâmetros de paginação
        params.validate();
        
        log::info!("Fetching users with pagination: page={}, limit={}", params.page, params.limit);
        
        let (users, total_count) = self.user_repository.find_all_paginated(&params).await?;
        
        let user_responses: Vec<UserResponse> = users
            .into_iter()
            .map(UserResponse::from)
            .collect();
        
        let paginated_response = PaginatedResponse::new(
            user_responses,
            params.page,
            params.limit,
            total_count,
        );
        
        log::info!("Retrieved {} users (page {} of {})", 
            paginated_response.data.len(), 
            paginated_response.pagination.current_page,
            paginated_response.pagination.total_pages
        );
        
        Ok(paginated_response)
    }
}
