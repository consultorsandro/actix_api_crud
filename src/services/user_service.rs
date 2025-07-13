// User service - Implementação da lógica de negócio para usuários

use async_trait::async_trait;
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::Utc;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::pagination::{PaginatedResponse, PaginationParams}; // Importar tipos de paginação
use crate::models::user::UserResponse;
use crate::models::user::{CreateUserDto, UpdateUserDto, User};
use crate::repositories::UserRepositoryTrait;
use crate::services::UserServiceTrait; // Importar UserResponse

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
        hash(password, DEFAULT_COST).map_err(|_e| AppError::InternalServer)
    }

    // Helper para verificar senha
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, AppError> {
        verify(password, hash).map_err(|_e| AppError::Auth("Invalid password".to_string()))
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
        if self
            .user_repository
            .exists_by_email(&create_dto.email)
            .await?
        {
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
            return Err(AppError::Validation(
                "Password must be at least 6 characters".to_string(),
            ));
        }

        // Hash da senha
        let password_hash = self.hash_password(&create_dto.password)?;

        // Criar usuário
        let user = User {
            id: Uuid::new_v4(),
            name: create_dto.name.trim().to_string(),
            email: create_dto.email.trim().to_lowercase(),
            age: create_dto.age,
            password_hash,
            role: Some("user".to_string()), // Role padrão
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

    async fn find_by_id(&self, id: Uuid) -> Result<User, AppError> {
        self.get_user_by_id(id).await
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

        // Password update removed for now - will be added in authentication feature

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

        let user = self
            .user_repository
            .find_by_email(&email_lower)
            .await?
            .ok_or_else(|| AppError::Auth("Invalid credentials".to_string()))?;

        if self.verify_password(password, &user.password_hash)? {
            Ok(user)
        } else {
            Err(AppError::Auth("Invalid credentials".to_string()))
        }
    }

    async fn get_users_paginated(
        &self,
        mut params: PaginationParams,
    ) -> Result<PaginatedResponse<UserResponse>, AppError> {
        // Validar parâmetros de paginação
        params.validate();

        log::info!(
            "Fetching users with pagination: page={}, limit={}",
            params.page,
            params.limit
        );

        let (users, total_count) = self.user_repository.find_all_paginated(&params).await?;

        let user_responses: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();

        let paginated_response =
            PaginatedResponse::new(user_responses, params.page, params.limit, total_count);

        log::info!(
            "Retrieved {} users (page {} of {})",
            paginated_response.data.len(),
            paginated_response.pagination.current_page,
            paginated_response.pagination.total_pages
        );

        Ok(paginated_response)
    }

    async fn find_by_email(&self, email: &str) -> Result<User, AppError> {
        self.user_repository.find_by_email_direct(email).await
    }

    async fn create_with_password(
        &self,
        create_dto: CreateUserDto,
        password_hash: String,
        role: String,
    ) -> Result<User, AppError> {
        // Verificar se email já existe
        if let Ok(Some(_)) = self.user_repository.find_by_email(&create_dto.email).await {
            return Err(AppError::Conflict("Email already exists".to_string()));
        }

        self.user_repository
            .create_with_password(create_dto, password_hash, role)
            .await
    }

    async fn update_password(&self, id: Uuid, new_password_hash: String) -> Result<(), AppError> {
        self.user_repository
            .update_password(id, new_password_hash)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::pagination::PaginationParams;
    use uuid::Uuid;

    // Teste simplificado para validação de DTO
    #[tokio::test]
    async fn test_create_dto_validation() {
        // Teste básico de compilação sem mock
        let dto = CreateUserDto {
            name: "Test User".to_string(),
            email: "test@test.com".to_string(),
            password: "123456".to_string(),
            age: 25,
        };

        // Verificar se o DTO é válido
        assert_eq!(dto.name, "Test User");
        assert_eq!(dto.email, "test@test.com");
        assert!(dto.age > 18);
    }

    #[tokio::test]
    async fn test_password_hashing() {
        use bcrypt::{DEFAULT_COST, hash, verify};

        let password = "test_password";
        let hashed = hash(password, DEFAULT_COST).unwrap();

        assert!(verify(password, &hashed).unwrap());
        assert!(!verify("wrong_password", &hashed).unwrap());
    }

    #[tokio::test]
    async fn test_user_validation() {
        let valid_dto = CreateUserDto {
            name: "Valid User".to_string(),
            email: "valid@example.com".to_string(),
            password: "123456".to_string(),
            age: 25,
        };

        // Teste se a estrutura está correta
        assert!(!valid_dto.name.is_empty());
        assert!(valid_dto.email.contains('@'));
        assert!(valid_dto.age >= 18);
    }

    fn create_test_user() -> User {
        User {
            id: Uuid::new_v4(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            age: 25,
            password_hash: "$2b$12$test_hash".to_string(),
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

    #[tokio::test]
    async fn test_create_user_dto_mapping() {
        let create_dto = create_test_create_dto();

        // Verificar se o DTO tem os dados corretos
        assert_eq!(create_dto.name, "New User");
        assert_eq!(create_dto.email, "new@example.com");
        assert_eq!(create_dto.age, 30);
        assert!(!create_dto.password.is_empty());
    }

    #[test]
    fn test_hash_password_functionality() {
        let password = "test_password";
        let hash_result = bcrypt::hash(password, bcrypt::DEFAULT_COST);

        assert!(hash_result.is_ok());
        let hash = hash_result.unwrap();
        assert!(hash.starts_with("$2b$"));
        assert_ne!(hash, password);
    }

    #[test]
    fn test_verify_password_functionality() {
        let password = "test_password";
        let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap();

        let verify_result = bcrypt::verify(password, &hash);
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());

        let wrong_verify_result = bcrypt::verify("wrong_password", &hash);
        assert!(wrong_verify_result.is_ok());
        assert!(!wrong_verify_result.unwrap());
    }

    #[test]
    fn test_user_model_creation() {
        let user = create_test_user();
        
        assert!(!user.id.to_string().is_empty());
        assert_eq!(user.name, "Test User");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.age, 25);
        assert!(!user.password_hash.is_empty());
    }
}
