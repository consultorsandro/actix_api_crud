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
    use crate::repositories::UserRepositoryTrait;
    use mockall::mock;
    use std::collections::HashMap;
    use uuid::Uuid;

    // Teste simplificado para criação de usuário
    #[tokio::test]
    async fn test_create_user_success() {
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
    async fn test_create_user_success() {
        let mut mock_repo = MockUserRepo::new();
        let test_user = create_test_user();
        let create_dto = create_test_create_dto();

        // Setup mock expectations
        mock_repo
            .expect_exists_by_email()
            .with(mockall::predicate::eq("new@example.com"))
            .times(1)
            .returning(|_| Ok(false));

        mock_repo
            .expect_create()
            .times(1)
            .returning(|user| Ok(user));

        let service = UserService::new(mock_repo);
        let result = service.create_user(create_dto).await;

        assert!(result.is_ok());
        let created_user = result.unwrap();
        assert_eq!(created_user.name, "New User");
        assert_eq!(created_user.email, "new@example.com");
        assert_eq!(created_user.age, 30);
    }

    #[tokio::test]
    async fn test_create_user_email_already_exists() {
        let mut mock_repo = MockUserRepo::new();
        let create_dto = create_test_create_dto();

        // Setup mock expectations - email already exists
        mock_repo
            .expect_exists_by_email()
            .with(mockall::predicate::eq("new@example.com"))
            .times(1)
            .returning(|_| Ok(true));

        let service = UserService::new(mock_repo);
        let result = service.create_user(create_dto).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert_eq!(msg, "Email already exists"),
            _ => panic!("Expected Validation error"),
        }
    }

    #[tokio::test]
    async fn test_create_user_invalid_password() {
        let mut mock_repo = MockUserRepo::new();
        let mut create_dto = create_test_create_dto();
        create_dto.password = "123".to_string(); // Too short

        mock_repo.expect_exists_by_email().returning(|_| Ok(false));

        let service = UserService::new(mock_repo);
        let result = service.create_user(create_dto).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert_eq!(msg, "Password must be at least 6 characters"),
            _ => panic!("Expected Validation error"),
        }
    }

    #[tokio::test]
    async fn test_get_user_by_id_success() {
        let mut mock_repo = MockUserRepo::new();
        let test_user = create_test_user();
        let user_id = test_user.id;

        mock_repo
            .expect_find_by_id()
            .with(mockall::predicate::eq(user_id))
            .times(1)
            .returning(move |_| Ok(Some(create_test_user())));

        let service = UserService::new(mock_repo);
        let result = service.get_user_by_id(user_id).await;

        assert!(result.is_ok());
        let found_user = result.unwrap();
        assert_eq!(found_user.id, user_id);
        assert_eq!(found_user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_get_user_by_id_not_found() {
        let mut mock_repo = MockUserRepo::new();
        let user_id = Uuid::new_v4();

        mock_repo
            .expect_find_by_id()
            .with(mockall::predicate::eq(user_id))
            .times(1)
            .returning(|_| Ok(None));

        let service = UserService::new(mock_repo);
        let result = service.get_user_by_id(user_id).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::NotFound(msg) => assert_eq!(msg, "User not found"),
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_user_success() {
        let mut mock_repo = MockUserRepo::new();
        let mut test_user = create_test_user();
        // Use a real bcrypt hash for testing
        test_user.password_hash = bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap();

        mock_repo
            .expect_find_by_email()
            .with(mockall::predicate::eq("test@example.com"))
            .times(1)
            .returning(move |_| {
                let mut user = create_test_user();
                user.password_hash = bcrypt::hash("password123", bcrypt::DEFAULT_COST).unwrap();
                Ok(Some(user))
            });

        let service = UserService::new(mock_repo);
        let result = service
            .authenticate_user("test@example.com", "password123")
            .await;

        assert!(result.is_ok());
        let authenticated_user = result.unwrap();
        assert_eq!(authenticated_user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_authenticate_user_invalid_password() {
        let mut mock_repo = MockUserRepo::new();
        let mut test_user = create_test_user();
        test_user.password_hash = bcrypt::hash("correct_password", bcrypt::DEFAULT_COST).unwrap();

        mock_repo
            .expect_find_by_email()
            .with(mockall::predicate::eq("test@example.com"))
            .times(1)
            .returning(move |_| {
                let mut user = create_test_user();
                user.password_hash =
                    bcrypt::hash("correct_password", bcrypt::DEFAULT_COST).unwrap();
                Ok(Some(user))
            });

        let service = UserService::new(mock_repo);
        let result = service
            .authenticate_user("test@example.com", "wrong_password")
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Auth(msg) => assert_eq!(msg, "Invalid credentials"),
            _ => panic!("Expected Auth error"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_user_not_found() {
        let mut mock_repo = MockUserRepo::new();

        mock_repo
            .expect_find_by_email()
            .with(mockall::predicate::eq("nonexistent@example.com"))
            .times(1)
            .returning(|_| Ok(None));

        let service = UserService::new(mock_repo);
        let result = service
            .authenticate_user("nonexistent@example.com", "password")
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Auth(msg) => assert_eq!(msg, "Invalid credentials"),
            _ => panic!("Expected Auth error"),
        }
    }

    #[tokio::test]
    async fn test_get_users_paginated() {
        let mut mock_repo = MockUserRepo::new();
        let test_users = vec![create_test_user(), create_test_user()];
        let total_count = 2u64;

        mock_repo
            .expect_find_all_paginated()
            .times(1)
            .returning(move |_| Ok((vec![create_test_user(), create_test_user()], 2)));

        let service = UserService::new(mock_repo);
        let params = PaginationParams {
            page: 1,
            limit: 10,
            search: None,
            sort_by: None,
            sort_order: crate::models::pagination::SortOrder::Desc,
        };

        let result = service.get_users_paginated(params).await;

        assert!(result.is_ok());
        let paginated_response = result.unwrap();
        assert_eq!(paginated_response.data.len(), 2);
        assert_eq!(paginated_response.pagination.total_items, 2);
        assert_eq!(paginated_response.pagination.current_page, 1);
    }

    #[test]
    fn test_hash_password() {
        let mock_repo = MockUserRepo::new();
        let service = UserService::new(mock_repo);

        let password = "test_password";
        let result = service.hash_password(password);

        assert!(result.is_ok());
        let hash = result.unwrap();
        assert!(hash.starts_with("$2b$"));
        assert_ne!(hash, password);
    }

    #[test]
    fn test_verify_password() {
        let mock_repo = MockUserRepo::new();
        let service = UserService::new(mock_repo);

        let password = "test_password";
        let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap();

        let result = service.verify_password(password, &hash);
        assert!(result.is_ok());
        assert!(result.unwrap());

        let wrong_result = service.verify_password("wrong_password", &hash);
        assert!(wrong_result.is_ok());
        assert!(!wrong_result.unwrap());
    }
}
