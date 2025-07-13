# 🧪 **UNIDADE VIII: TESTES E QUALIDADE**
*"Garantindo robustez e confiabilidade através de testes abrangentes"*

## 📚 **Introdução**

**Testes** são a base de qualquer aplicação confiável e mantível. Nesta unidade, você aprenderá a implementar uma suíte completa de testes para aplicações Rust/Actix-Web, incluindo testes unitários, de integração, mocks, benchmarks e análise de qualidade de código. O projeto já possui **77+ testes** implementados que servem como base para esta unidade.

**Objetivos desta Unidade:**
- ✅ Implementar testes unitários e de integração robustos
- ✅ Criar mocks eficazes com `mockall`
- ✅ Desenvolver testes de performance e benchmarks
- ✅ Configurar análise de cobertura de código
- ✅ Aplicar ferramentas de qualidade e linting

---

## 📌 **CAPÍTULO 12: TESTES UNITÁRIOS E INTEGRAÇÃO**

### **12.1 Fundamentos de Testes em Rust**

Rust possui um sistema de testes nativo robusto que permite diferentes tipos de testes integrados ao ecossistema `cargo`.

#### **12.1.1 Estrutura de Testes do Projeto**

```rust
// Estrutura de testes do projeto actix_api_crud

// 1. Testes unitários (dentro dos módulos)
// src/models/user.rs
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_user_creation() { }
    
    #[test]
    fn test_user_validation() { }
}

// 2. Testes de integração (diretório tests/)
// tests/integration_tests.rs
#[actix_web::test]
async fn test_health_endpoint() { }

// tests/jwt_tests.rs  
#[tokio::test]
async fn test_jwt_generation() { }

// 3. Benchmarks (benches/ - opcional)
// benches/api_benchmarks.rs
#[bench]
fn bench_user_creation(b: &mut Bencher) { }
```

#### **12.1.2 Configuração de Dependências de Teste**

```toml
# Cargo.toml - Seção [dev-dependencies] já configurada
[dev-dependencies]
actix-rt = "2.9"          # Runtime para testes async
tokio = { version = "1", features = ["full"] }  # Async runtime completo
mockall = "0.12"          # Framework de mocking
serial_test = "3.0"       # Testes sequenciais para ambiente compartilhado
tempfile = "3.8"          # Arquivos temporários para testes
rstest = "0.18"           # Testes parametrizados avançados
once_cell = "1.19"        # Lazy static para configurações de teste

# Adicional para cobertura e análise
[dev-dependencies.criterion]
version = "0.5"
features = ["html_reports"]  # Para benchmarks com relatórios HTML
```

#### **12.1.3 Testes Unitários - Modelos e Validação**

```rust
// src/models/user.rs - Testes unitários de modelos
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_user_new_valid() {
        let user = User {
            id: Uuid::new_v4(),
            name: "João Silva".to_string(),
            email: "joao@exemplo.com".to_string(),
            age: 30,
            created_at: Utc::now(),
            role: Some("user".to_string()),
        };

        assert_eq!(user.name, "João Silva");
        assert_eq!(user.email, "joao@exemplo.com");
        assert_eq!(user.age, 30);
        assert!(user.is_adult());
    }

    #[test]
    fn test_user_age_validation() {
        // Teste idade mínima
        let minor = User {
            id: Uuid::new_v4(),
            name: "Menor Idade".to_string(),
            email: "menor@test.com".to_string(),
            age: 12,
            created_at: Utc::now(),
            role: Some("user".to_string()),
        };
        assert!(!minor.is_adult());

        // Teste idade válida
        let adult = User {
            id: Uuid::new_v4(),
            name: "Maior Idade".to_string(),
            email: "maior@test.com".to_string(),
            age: 25,
            created_at: Utc::now(),
            role: Some("user".to_string()),
        };
        assert!(adult.is_adult());
    }

    #[test]
    fn test_user_email_validation() {
        use validator::Validate;
        
        // Email válido
        let valid_user = CreateUserRequest {
            name: "Usuário Teste".to_string(),
            email: "usuario@exemplo.com".to_string(),
            age: 25,
        };
        assert!(valid_user.validate().is_ok());

        // Email inválido
        let invalid_user = CreateUserRequest {
            name: "Usuário Teste".to_string(),
            email: "email_invalido".to_string(),
            age: 25,
        };
        assert!(invalid_user.validate().is_err());
    }

    #[test]
    fn test_user_role_defaults() {
        let user_without_role = User {
            id: Uuid::new_v4(),
            name: "Sem Role".to_string(),
            email: "sem@role.com".to_string(),
            age: 30,
            created_at: Utc::now(),
            role: None,
        };

        assert_eq!(user_without_role.get_role(), "user");

        let user_with_role = User {
            id: Uuid::new_v4(),
            name: "Com Role".to_string(),
            email: "com@role.com".to_string(),
            age: 30,
            created_at: Utc::now(),
            role: Some("admin".to_string()),
        };

        assert_eq!(user_with_role.get_role(), "admin");
    }

    #[test]
    fn test_user_display_name() {
        let user = User {
            id: Uuid::new_v4(),
            name: "  João Silva  ".to_string(),  // Com espaços
            email: "joao@exemplo.com".to_string(),
            age: 30,
            created_at: Utc::now(),
            role: None,
        };

        assert_eq!(user.display_name(), "João Silva");  // Trimmed
    }
}
```

#### **12.1.4 Testes Unitários - Serviços e Lógica de Negócio**

```rust
// src/services/user_service.rs - Testes com mocks
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use sqlx::PgPool;
    use uuid::Uuid;

    // Mock do repositório para testes isolados
    mockall::mock! {
        UserRepo {
            async fn create_user(&self, user: CreateUserRequest) -> Result<User, AppError>;
            async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, AppError>;
            async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AppError>;
            async fn update_user(&self, id: Uuid, user: UpdateUserRequest) -> Result<User, AppError>;
            async fn delete_user(&self, id: Uuid) -> Result<(), AppError>;
            async fn list_users(&self, pagination: PaginationParams) -> Result<PagedResponse<User>, AppError>;
        }
    }

    #[tokio::test]
    async fn test_create_user_success() {
        let mut mock_repo = MockUserRepo::new();
        let user_id = Uuid::new_v4();
        
        let expected_user = User {
            id: user_id,
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            age: 25,
            created_at: chrono::Utc::now(),
            role: Some("user".to_string()),
        };

        // Configurar expectativa do mock
        mock_repo
            .expect_create_user()
            .with(eq(CreateUserRequest {
                name: "Test User".to_string(),
                email: "test@example.com".to_string(),
                age: 25,
            }))
            .times(1)
            .returning(move |_| Ok(expected_user.clone()));

        // Testar o serviço
        let service = UserService::new(Box::new(mock_repo));
        let create_request = CreateUserRequest {
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            age: 25,
        };

        let result = service.create_user(create_request).await;
        
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.name, "Test User");
        assert_eq!(user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_create_user_duplicate_email() {
        let mut mock_repo = MockUserRepo::new();

        // Simular usuário já existente
        mock_repo
            .expect_get_user_by_email()
            .with(eq("existing@example.com"))
            .times(1)
            .returning(|_| Ok(Some(User {
                id: Uuid::new_v4(),
                name: "Existing User".to_string(),
                email: "existing@example.com".to_string(),
                age: 30,
                created_at: chrono::Utc::now(),
                role: Some("user".to_string()),
            })));

        let service = UserService::new(Box::new(mock_repo));
        let create_request = CreateUserRequest {
            name: "New User".to_string(),
            email: "existing@example.com".to_string(),
            age: 25,
        };

        let result = service.create_user(create_request).await;
        
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Conflict(msg) => assert!(msg.contains("already exists")),
            _ => panic!("Expected Conflict error"),
        }
    }

    #[tokio::test]
    async fn test_get_user_by_id_found() {
        let mut mock_repo = MockUserRepo::new();
        let user_id = Uuid::new_v4();
        
        let expected_user = User {
            id: user_id,
            name: "Found User".to_string(),
            email: "found@example.com".to_string(),
            age: 28,
            created_at: chrono::Utc::now(),
            role: Some("user".to_string()),
        };

        mock_repo
            .expect_get_user_by_id()
            .with(eq(user_id))
            .times(1)
            .returning(move |_| Ok(Some(expected_user.clone())));

        let service = UserService::new(Box::new(mock_repo));
        let result = service.get_user_by_id(user_id).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.id, user_id);
        assert_eq!(user.name, "Found User");
    }

    #[tokio::test]
    async fn test_get_user_by_id_not_found() {
        let mut mock_repo = MockUserRepo::new();
        let user_id = Uuid::new_v4();

        mock_repo
            .expect_get_user_by_id()
            .with(eq(user_id))
            .times(1)
            .returning(|_| Ok(None));

        let service = UserService::new(Box::new(mock_repo));
        let result = service.get_user_by_id(user_id).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::NotFound(msg) => assert!(msg.contains("not found")),
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_update_user_success() {
        let mut mock_repo = MockUserRepo::new();
        let user_id = Uuid::new_v4();
        
        let updated_user = User {
            id: user_id,
            name: "Updated Name".to_string(),
            email: "updated@example.com".to_string(),
            age: 30,
            created_at: chrono::Utc::now(),
            role: Some("user".to_string()),
        };

        mock_repo
            .expect_update_user()
            .with(eq(user_id), eq(UpdateUserRequest {
                name: Some("Updated Name".to_string()),
                email: Some("updated@example.com".to_string()),
                age: Some(30),
            }))
            .times(1)
            .returning(move |_, _| Ok(updated_user.clone()));

        let service = UserService::new(Box::new(mock_repo));
        let update_request = UpdateUserRequest {
            name: Some("Updated Name".to_string()),
            email: Some("updated@example.com".to_string()),
            age: Some(30),
        };

        let result = service.update_user(user_id, update_request).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.name, "Updated Name");
        assert_eq!(user.email, "updated@example.com");
    }

    #[tokio::test]
    async fn test_delete_user_success() {
        let mut mock_repo = MockUserRepo::new();
        let user_id = Uuid::new_v4();

        mock_repo
            .expect_delete_user()
            .with(eq(user_id))
            .times(1)
            .returning(|_| Ok(()));

        let service = UserService::new(Box::new(mock_repo));
        let result = service.delete_user(user_id).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_users_with_pagination() {
        let mut mock_repo = MockUserRepo::new();
        
        let users = vec![
            User {
                id: Uuid::new_v4(),
                name: "User 1".to_string(),
                email: "user1@example.com".to_string(),
                age: 25,
                created_at: chrono::Utc::now(),
                role: Some("user".to_string()),
            },
            User {
                id: Uuid::new_v4(),
                name: "User 2".to_string(),
                email: "user2@example.com".to_string(),
                age: 30,
                created_at: chrono::Utc::now(),
                role: Some("user".to_string()),
            },
        ];

        let expected_response = PagedResponse {
            data: users.clone(),
            pagination: PaginationInfo {
                page: 1,
                per_page: 10,
                total: 2,
                total_pages: 1,
            },
        };

        mock_repo
            .expect_list_users()
            .with(eq(PaginationParams { page: 1, per_page: 10 }))
            .times(1)
            .returning(move |_| Ok(expected_response.clone()));

        let service = UserService::new(Box::new(mock_repo));
        let pagination = PaginationParams { page: 1, per_page: 10 };
        let result = service.list_users(pagination).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.data.len(), 2);
        assert_eq!(response.pagination.total, 2);
    }
}
```

### **12.2 Testes de Integração com Actix-Web**

Testes de integração verificam o comportamento completo da aplicação incluindo rotas, middlewares e integrações.

#### **12.2.1 Setup de Testes de Integração**

```rust
// tests/integration_tests.rs - Configuração base
use actix_web::{App, middleware, test, web, HttpResponse};
use serde_json::json;
use actix_api_crud::{
    handlers::user_handler::*,
    middlewares::{auth::jwt_validator, cors::CorsConfig, security::SecurityHeaders},
    config::database::DatabaseConfig,
    services::user_service::UserService,
};

/// Helper para criar app de teste com configuração completa
async fn create_test_app() -> impl actix_web::dev::Service<
    actix_web::dev::ServiceRequest,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
    test::init_service(
        App::new()
            // Middlewares de teste
            .wrap(middleware::Logger::default())
            .wrap(CorsConfig::testing())
            .wrap(SecurityHeaders::development())
            
            // Configuração de dados de teste
            .app_data(web::Data::new(create_test_user_service()))
            
            // Rotas
            .service(
                web::scope("/api/v1")
                    .service(
                        web::resource("/users")
                            .route(web::get().to(list_users))
                            .route(web::post().to(create_user))
                    )
                    .service(
                        web::resource("/users/{id}")
                            .route(web::get().to(get_user))
                            .route(web::put().to(update_user))
                            .route(web::delete().to(delete_user))
                    )
                    // Rotas protegidas por autenticação
                    .service(
                        web::resource("/protected")
                            .wrap(actix_web_httpauth::middleware::HttpAuthentication::bearer(jwt_validator))
                            .route(web::get().to(protected_endpoint))
                    )
            )
            // Rota de health check
            .route("/health", web::get().to(health_check))
    )
    .await
}

/// Criar serviço de usuário para testes (usando mock ou banco de teste)
fn create_test_user_service() -> UserService {
    // Em testes reais, você usaria um banco de dados de teste
    // Por agora, usamos um mock
    UserService::new_with_mock_repository()
}

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now(),
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn protected_endpoint() -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "message": "Access granted to protected resource",
        "timestamp": chrono::Utc::now()
    }))
}
```

#### **12.2.2 Testes de Endpoints CRUD**

```rust
#[actix_web::test]
async fn test_health_check_endpoint() {
    let app = create_test_app().await;

    let req = test::TestRequest::get()
        .uri("/health")
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "healthy");
    assert!(body["timestamp"].is_string());
}

#[actix_web::test]
async fn test_create_user_success() {
    let app = create_test_app().await;

    let new_user = json!({
        "name": "João Silva",
        "email": "joao@exemplo.com",
        "age": 30
    });

    let req = test::TestRequest::post()
        .uri("/api/v1/users")
        .set_json(&new_user)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::CREATED);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "João Silva");
    assert_eq!(body["email"], "joao@exemplo.com");
    assert_eq!(body["age"], 30);
    assert!(body["id"].is_string());
    assert!(body["created_at"].is_string());
}

#[actix_web::test]
async fn test_create_user_invalid_data() {
    let app = create_test_app().await;

    let invalid_user = json!({
        "name": "",  // Nome vazio
        "email": "email_invalido",  // Email inválido
        "age": 10   // Idade muito baixa
    });

    let req = test::TestRequest::post()
        .uri("/api/v1/users")
        .set_json(&invalid_user)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "validation_failed");
    assert!(body["details"].is_array());
}

#[actix_web::test]
async fn test_get_user_by_id_found() {
    let app = create_test_app().await;
    
    // Primeiro criar um usuário
    let new_user = json!({
        "name": "Maria Santos",
        "email": "maria@exemplo.com",
        "age": 28
    });

    let create_req = test::TestRequest::post()
        .uri("/api/v1/users")
        .set_json(&new_user)
        .to_request();

    let create_resp = test::call_service(&app, create_req).await;
    let created_user: serde_json::Value = test::read_body_json(create_resp).await;
    let user_id = created_user["id"].as_str().unwrap();

    // Agora buscar o usuário criado
    let get_req = test::TestRequest::get()
        .uri(&format!("/api/v1/users/{}", user_id))
        .to_request();

    let get_resp = test::call_service(&app, get_req).await;
    
    assert_eq!(get_resp.status(), StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(get_resp).await;
    assert_eq!(body["id"], user_id);
    assert_eq!(body["name"], "Maria Santos");
    assert_eq!(body["email"], "maria@exemplo.com");
}

#[actix_web::test]
async fn test_get_user_by_id_not_found() {
    let app = create_test_app().await;
    
    let fake_id = uuid::Uuid::new_v4();
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/users/{}", fake_id))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "not_found");
}

#[actix_web::test]
async fn test_update_user_success() {
    let app = create_test_app().await;
    
    // Criar usuário primeiro
    let new_user = json!({
        "name": "Pedro Silva",
        "email": "pedro@exemplo.com",
        "age": 25
    });

    let create_req = test::TestRequest::post()
        .uri("/api/v1/users")
        .set_json(&new_user)
        .to_request();

    let create_resp = test::call_service(&app, create_req).await;
    let created_user: serde_json::Value = test::read_body_json(create_resp).await;
    let user_id = created_user["id"].as_str().unwrap();

    // Atualizar usuário
    let update_data = json!({
        "name": "Pedro Santos",
        "age": 26
    });

    let update_req = test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user_id))
        .set_json(&update_data)
        .to_request();

    let update_resp = test::call_service(&app, update_req).await;
    
    assert_eq!(update_resp.status(), StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(update_resp).await;
    assert_eq!(body["name"], "Pedro Santos");
    assert_eq!(body["age"], 26);
    assert_eq!(body["email"], "pedro@exemplo.com"); // Email não mudou
}

#[actix_web::test]
async fn test_delete_user_success() {
    let app = create_test_app().await;
    
    // Criar usuário primeiro
    let new_user = json!({
        "name": "Ana Costa",
        "email": "ana@exemplo.com",
        "age": 32
    });

    let create_req = test::TestRequest::post()
        .uri("/api/v1/users")
        .set_json(&new_user)
        .to_request();

    let create_resp = test::call_service(&app, create_req).await;
    let created_user: serde_json::Value = test::read_body_json(create_resp).await;
    let user_id = created_user["id"].as_str().unwrap();

    // Deletar usuário
    let delete_req = test::TestRequest::delete()
        .uri(&format!("/api/v1/users/{}", user_id))
        .to_request();

    let delete_resp = test::call_service(&app, delete_req).await;
    assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);

    // Verificar que usuário foi deletado
    let get_req = test::TestRequest::get()
        .uri(&format!("/api/v1/users/{}", user_id))
        .to_request();

    let get_resp = test::call_service(&app, get_req).await;
    assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn test_list_users_with_pagination() {
    let app = create_test_app().await;
    
    // Criar vários usuários para teste de paginação
    for i in 1..=15 {
        let user = json!({
            "name": format!("User {}", i),
            "email": format!("user{}@exemplo.com", i),
            "age": 20 + i
        });

        let req = test::TestRequest::post()
            .uri("/api/v1/users")
            .set_json(&user)
            .to_request();

        test::call_service(&app, req).await;
    }

    // Testar primeira página
    let req = test::TestRequest::get()
        .uri("/api/v1/users?page=1&per_page=10")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["data"].as_array().unwrap().len(), 10);
    assert_eq!(body["pagination"]["page"], 1);
    assert_eq!(body["pagination"]["per_page"], 10);
    assert_eq!(body["pagination"]["total"], 15);
    assert_eq!(body["pagination"]["total_pages"], 2);

    // Testar segunda página
    let req2 = test::TestRequest::get()
        .uri("/api/v1/users?page=2&per_page=10")
        .to_request();

    let resp2 = test::call_service(&app, req2).await;
    assert_eq!(resp2.status(), StatusCode::OK);
    
    let body2: serde_json::Value = test::read_body_json(resp2).await;
    assert_eq!(body2["data"].as_array().unwrap().len(), 5);
    assert_eq!(body2["pagination"]["page"], 2);
}
```

### **12.3 Testes de Autenticação JWT**

Testes específicos para o sistema de autenticação JWT implementado.

#### **12.3.1 Testes de Geração e Validação de Tokens**

```rust
// tests/jwt_tests.rs - Testes abrangentes de JWT
use actix_api_crud::auth::jwt::{Claims, JwtConfig};
use actix_api_crud::middlewares::auth::JwtAuthMiddleware;
use actix_web::{App, HttpResponse, http::StatusCode, test, web};
use serde_json::json;
use serial_test::serial;
use std::env;
use uuid::Uuid;

#[tokio::test]
#[serial]
async fn test_jwt_config_from_env_valid() {
    // Configurar variáveis de ambiente para teste
    env::set_var("JWT_SECRET", "test_secret_key_with_32_characters_min");
    env::set_var("JWT_EXPIRATION", "24");

    let config = JwtConfig::from_env();
    assert!(config.is_ok());

    let jwt_config = config.unwrap();
    assert_eq!(jwt_config.secret, "test_secret_key_with_32_characters_min");
    assert_eq!(jwt_config.expiration_hours, 24);

    // Limpar variáveis
    env::remove_var("JWT_SECRET");
    env::remove_var("JWT_EXPIRATION");
}

#[tokio::test]
#[serial]
async fn test_jwt_config_invalid_secret_length() {
    env::set_var("JWT_SECRET", "short_secret");  // Menos de 32 caracteres
    env::set_var("JWT_EXPIRATION", "24");

    let config = JwtConfig::from_env();
    assert!(config.is_err());

    env::remove_var("JWT_SECRET");
    env::remove_var("JWT_EXPIRATION");
}

#[tokio::test]
#[serial]
async fn test_jwt_token_generation_and_validation() {
    env::set_var("JWT_SECRET", "test_secret_key_with_32_characters_min");
    env::set_var("JWT_EXPIRATION", "1");

    let config = JwtConfig::from_env().unwrap();
    let user_id = Uuid::new_v4();

    // Gerar token
    let token = config
        .generate_token(user_id, "test@example.com", "Test User", "user")
        .unwrap();

    // Validar token
    let claims = config.decode_token(&token).unwrap();

    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.email, "test@example.com");
    assert_eq!(claims.name, "Test User");
    assert_eq!(claims.role, "user");
    assert!(config.is_token_valid(&claims));

    env::remove_var("JWT_SECRET");
    env::remove_var("JWT_EXPIRATION");
}

#[tokio::test]
#[serial]
async fn test_jwt_token_with_permissions() {
    env::set_var("JWT_SECRET", "test_secret_key_with_32_characters_min");
    env::set_var("JWT_EXPIRATION", "1");

    let config = JwtConfig::from_env().unwrap();
    let user_id = Uuid::new_v4();

    let permissions = vec![
        "users:read".to_string(),
        "users:write".to_string(),
        "admin:access".to_string(),
    ];

    // Gerar token com permissões
    let token = config
        .generate_token_with_permissions(
            user_id,
            "admin@example.com",
            "Admin User",
            "admin",
            permissions.clone(),
            Some("org_123".to_string()),
        )
        .unwrap();

    // Validar token
    let claims = config.decode_token(&token).unwrap();

    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.role, "admin");
    assert_eq!(claims.permissions.unwrap(), permissions);
    assert_eq!(claims.organization_id.unwrap(), "org_123");

    env::remove_var("JWT_SECRET");
    env::remove_var("JWT_EXPIRATION");
}

#[tokio::test]
#[serial] 
async fn test_jwt_token_expiration() {
    env::set_var("JWT_SECRET", "test_secret_key_with_32_characters_min");
    env::set_var("JWT_EXPIRATION", "1");

    let config = JwtConfig::from_env().unwrap();

    // Criar claims expirados manualmente
    let expired_claims = Claims {
        sub: Uuid::new_v4().to_string(),
        email: "test@example.com".to_string(),
        name: "Test User".to_string(),
        exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp(),
        iat: (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp(),
        role: "user".to_string(),
        permissions: None,
        organization_id: None,
        department: None,
        last_login: None,
        session_id: None,
    };

    assert!(!config.is_token_valid(&expired_claims));

    env::remove_var("JWT_SECRET");
    env::remove_var("JWT_EXPIRATION");
}

#[tokio::test]
#[serial]
async fn test_jwt_refresh_token_logic() {
    env::set_var("JWT_SECRET", "test_secret_key_with_32_characters_min");
    env::set_var("JWT_EXPIRATION", "24"); // 24 horas

    let config = JwtConfig::from_env().unwrap();
    let user_id = Uuid::new_v4();

    // Gerar token
    let token = config
        .generate_token(user_id, "test@example.com", "Test User", "user")
        .unwrap();

    let claims = config.decode_token(&token).unwrap();

    // Token recém criado não deve precisar de refresh
    assert!(!config.should_refresh_token(&claims));

    // Simular token antigo (criado há 20 horas = 83% do tempo de vida)
    let old_claims = Claims {
        sub: user_id.to_string(),
        email: "test@example.com".to_string(),
        name: "Test User".to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(4)).timestamp(), // Expira em 4h
        iat: (chrono::Utc::now() - chrono::Duration::hours(20)).timestamp(), // Criado há 20h
        role: "user".to_string(),
        permissions: None,
        organization_id: None,
        department: None,
        last_login: None,
        session_id: None,
    };

    // Token antigo deve precisar de refresh (80% do tempo de vida)
    assert!(config.should_refresh_token(&old_claims));

    env::remove_var("JWT_SECRET");
    env::remove_var("JWT_EXPIRATION");
}

#[actix_web::test]
#[serial]
async fn test_jwt_middleware_valid_token() {
    env::set_var("JWT_SECRET", "test_secret_key_with_32_characters_min");

    let config = JwtConfig::from_env().unwrap();
    let user_id = Uuid::new_v4();

    let token = config
        .generate_token(user_id, "test@example.com", "Test User", "user")
        .unwrap();

    let app = test::init_service(
        App::new()
            .wrap(actix_web_httpauth::middleware::HttpAuthentication::bearer(
                actix_api_crud::middlewares::auth::jwt_validator
            ))
            .route("/protected", web::get().to(|| async {
                HttpResponse::Ok().json(json!({"message": "Protected resource"}))
            }))
    ).await;

    let req = test::TestRequest::get()
        .uri("/protected")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    env::remove_var("JWT_SECRET");
}

#[actix_web::test]
#[serial]
async fn test_jwt_middleware_invalid_token() {
    env::set_var("JWT_SECRET", "test_secret_key_with_32_characters_min");

    let app = test::init_service(
        App::new()
            .wrap(actix_web_httpauth::middleware::HttpAuthentication::bearer(
                actix_api_crud::middlewares::auth::jwt_validator
            ))
            .route("/protected", web::get().to(|| async {
                HttpResponse::Ok().json(json!({"message": "Protected resource"}))
            }))
    ).await;

    let req = test::TestRequest::get()
        .uri("/protected")
        .insert_header(("Authorization", "Bearer invalid_token"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    env::remove_var("JWT_SECRET");
}

#[actix_web::test]
#[serial]
async fn test_jwt_middleware_missing_token() {
    let app = test::init_service(
        App::new()
            .wrap(actix_web_httpauth::middleware::HttpAuthentication::bearer(
                actix_api_crud::middlewares::auth::jwt_validator
            ))
            .route("/protected", web::get().to(|| async {
                HttpResponse::Ok().json(json!({"message": "Protected resource"}))
            }))
    ).await;

    let req = test::TestRequest::get()
        .uri("/protected")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// Teste de claims extraction em handlers
#[test] 
fn test_claims_role_validation() {
    use actix_api_crud::middlewares::auth::JwtClaims;
    
    let claims = Claims {
        sub: Uuid::new_v4().to_string(),
        email: "admin@example.com".to_string(),
        name: "Admin User".to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
        iat: chrono::Utc::now().timestamp(),
        role: "admin".to_string(),
        permissions: Some(vec!["users:write".to_string()]),
        organization_id: Some("org_123".to_string()),
        department: None,
        last_login: None,
        session_id: None,
    };

    let jwt_claims = JwtClaims(claims);

    // Testar verificações de role
    assert!(jwt_claims.has_role("admin"));
    assert!(!jwt_claims.has_role("user"));
    assert!(jwt_claims.is_admin());

    // Testar verificações de permissão
    assert!(jwt_claims.has_permission("users:write"));
    assert!(!jwt_claims.has_permission("users:delete"));

    // Testar acesso a recursos do usuário
    let own_id = jwt_claims.0.sub.clone();
    let other_id = Uuid::new_v4().to_string();
    
    assert!(jwt_claims.can_access_user_resource(&own_id));
    assert!(jwt_claims.can_access_user_resource(&other_id)); // Admin pode acessar qualquer recurso
}
```

## 📌 **CAPÍTULO 13: TESTES DE INTEGRAÇÃO E QUALIDADE**

### **13.1 Testando Endpoints Completos (`tests/integration_tests.rs`)**

Testes de integração verificam o comportamento completo da aplicação incluindo todas as camadas e integrações.

#### **13.1.1 Estrutura Avançada de Testes de Integração**

```rust
// tests/integration_tests.rs - Testes completos de endpoints
use actix_web::{App, http::StatusCode, middleware, test, web};
use serde_json::json;
use uuid::Uuid;
use actix_api_crud::{
    handlers::user_handler::*,
    middlewares::{
        auth::jwt_validator,
        cors::CorsConfig,
        security::{SecurityHeaders, InputSanitizer},
        rate_limit::RateLimitMiddleware,
    },
    services::user_service::UserService,
    models::{user::*, pagination::*},
    errors::AppError,
};

/// Setup completo de aplicação para testes de integração
async fn create_integration_test_app() -> impl actix_web::dev::Service<
    actix_web::dev::ServiceRequest,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
    test::init_service(
        App::new()
            // Middleware stack completo
            .wrap(middleware::Logger::default())
            .wrap(SecurityHeaders::development())
            .wrap(InputSanitizer::default())
            .wrap(CorsConfig::testing())
            
            // Dados de aplicação
            .app_data(web::Data::new(create_test_user_service()))
            .app_data(web::Data::new(create_test_jwt_config()))
            
            // Rotas públicas
            .service(
                web::scope("/api/v1")
                    .service(
                        web::resource("/auth/login")
                            .route(web::post().to(login_user))
                    )
                    .service(
                        web::resource("/auth/register")
                            .route(web::post().to(register_user))
                    )
                    .service(
                        web::resource("/users")
                            .route(web::get().to(list_users))
                            .route(web::post().to(create_user))
                    )
                    .service(
                        web::resource("/users/{id}")
                            .route(web::get().to(get_user))
                            .route(web::put().to(update_user))
                            .route(web::delete().to(delete_user))
                    )
            )
            
            // Rotas protegidas
            .service(
                web::scope("/api/v1/protected")
                    .wrap(actix_web_httpauth::middleware::HttpAuthentication::bearer(jwt_validator))
                    .service(
                        web::resource("/profile")
                            .route(web::get().to(get_user_profile))
                            .route(web::put().to(update_user_profile))
                    )
                    .service(
                        web::resource("/admin/users")
                            .route(web::get().to(admin_list_users))
                    )
            )
            
            // Utilitários
            .route("/health", web::get().to(health_check))
            .route("/metrics", web::get().to(metrics_endpoint))
    )
    .await
}

/// Handlers de teste auxiliares
async fn health_check() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now(),
        "version": env!("CARGO_PKG_VERSION"),
        "uptime": "test_mode"
    }))
}

async fn metrics_endpoint() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().json(json!({
        "requests_total": 1000,
        "active_connections": 10,
        "response_time_avg": "45ms",
        "error_rate": "0.1%"
    }))
}

async fn get_user_profile() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().json(json!({
        "message": "User profile accessed",
        "protected": true
    }))
}

async fn update_user_profile() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().json(json!({
        "message": "Profile updated successfully"
    }))
}

async fn admin_list_users() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().json(json!({
        "message": "Admin access granted",
        "users": ["admin@example.com", "user@example.com"]
    }))
}
```

#### **13.1.2 Testes de Middleware Chain Completo**

```rust
#[actix_web::test]
async fn test_complete_middleware_chain() {
    let app = create_integration_test_app().await;

    // Teste com dados normais
    let req = test::TestRequest::post()
        .uri("/api/v1/users")
        .insert_header(("Origin", "http://localhost:3000"))
        .insert_header(("User-Agent", "Test-Client/1.0"))
        .set_json(&json!({
            "name": "Middleware Test",
            "email": "middleware@test.com",
            "age": 25
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    // Verificar status de sucesso
    assert_eq!(resp.status(), StatusCode::CREATED);
    
    // Verificar headers de segurança aplicados
    let headers = resp.headers();
    assert!(headers.contains_key("x-xss-protection"));
    assert!(headers.contains_key("x-content-type-options"));
    assert!(headers.contains_key("x-frame-options"));
    assert!(headers.contains_key("content-security-policy"));
    
    // Verificar CORS headers
    assert!(headers.contains_key("access-control-allow-origin"));
}

#[actix_web::test]
async fn test_input_sanitization_middleware() {
    let app = create_integration_test_app().await;

    // Teste com input suspeito
    let malicious_data = json!({
        "name": "<script>alert('xss')</script>",
        "email": "test@example.com",
        "age": 25
    });

    let req = test::TestRequest::post()
        .uri("/api/v1/users")
        .set_json(&malicious_data)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    // Input sanitization pode resultar em erro de validação ou sanitização
    assert!(resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::CREATED);
    
    if resp.status() == StatusCode::CREATED {
        let body: serde_json::Value = test::read_body_json(resp).await;
        // Verificar se script foi sanitizado
        assert!(!body["name"].as_str().unwrap().contains("<script>"));
    }
}

#[actix_web::test]
async fn test_error_handling_chain() {
    let app = create_integration_test_app().await;

    // 1. Teste Not Found
    let req = test::TestRequest::get()
        .uri("/api/v1/nonexistent")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 2. Teste Method Not Allowed
    let req = test::TestRequest::patch()  // PATCH não permitido
        .uri("/api/v1/users")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    // 3. Teste Validation Error
    let invalid_data = json!({
        "name": "",  // Nome vazio
        "email": "invalid-email",  // Email inválido
        "age": -5   // Idade inválida
    });

    let req = test::TestRequest::post()
        .uri("/api/v1/users")
        .set_json(&invalid_data)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let error_body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(error_body["error"], "validation_failed");
    assert!(error_body["details"].is_array());
}
```

#### **13.1.3 Testes de Autenticação e Autorização Completos**

```rust
#[actix_web::test]
async fn test_authentication_flow_complete() {
    let app = create_integration_test_app().await;

    // 1. Registrar usuário
    let register_data = json!({
        "name": "Auth Test User",
        "email": "auth@test.com",
        "age": 28,
        "password": "secure_password123"
    });

    let register_req = test::TestRequest::post()
        .uri("/api/v1/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert_eq!(register_resp.status(), StatusCode::CREATED);

    // 2. Fazer login
    let login_data = json!({
        "email": "auth@test.com",
        "password": "secure_password123"
    });

    let login_req = test::TestRequest::post()
        .uri("/api/v1/auth/login")
        .set_json(&login_data)
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert_eq!(login_resp.status(), StatusCode::OK);

    let login_body: serde_json::Value = test::read_body_json(login_resp).await;
    let token = login_body["token"].as_str().unwrap();

    // 3. Acessar rota protegida com token válido
    let protected_req = test::TestRequest::get()
        .uri("/api/v1/protected/profile")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let protected_resp = test::call_service(&app, protected_req).await;
    assert_eq!(protected_resp.status(), StatusCode::OK);

    // 4. Tentar acessar rota protegida sem token
    let unauth_req = test::TestRequest::get()
        .uri("/api/v1/protected/profile")
        .to_request();

    let unauth_resp = test::call_service(&app, unauth_req).await;
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    // 5. Tentar acessar com token inválido
    let invalid_req = test::TestRequest::get()
        .uri("/api/v1/protected/profile")
        .insert_header(("Authorization", "Bearer invalid_token"))
        .to_request();

    let invalid_resp = test::call_service(&app, invalid_req).await;
    assert_eq!(invalid_resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn test_authorization_levels() {
    let app = create_integration_test_app().await;

    // Simular diferentes tipos de usuários
    let user_token = generate_test_token("user", vec!["users:read"]);
    let admin_token = generate_test_token("admin", vec!["users:read", "users:write", "admin:access"]);

    // 1. Usuário comum tentando acessar área admin
    let user_admin_req = test::TestRequest::get()
        .uri("/api/v1/protected/admin/users")
        .insert_header(("Authorization", format!("Bearer {}", user_token)))
        .to_request();

    let user_admin_resp = test::call_service(&app, user_admin_req).await;
    assert_eq!(user_admin_resp.status(), StatusCode::FORBIDDEN);

    // 2. Admin acessando área admin
    let admin_req = test::TestRequest::get()
        .uri("/api/v1/protected/admin/users")
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .to_request();

    let admin_resp = test::call_service(&app, admin_req).await;
    assert_eq!(admin_resp.status(), StatusCode::OK);
}

/// Helper para gerar tokens de teste
fn generate_test_token(role: &str, permissions: Vec<&str>) -> String {
    use actix_api_crud::auth::jwt::JwtConfig;
    
    std::env::set_var("JWT_SECRET", "test_secret_key_with_32_characters_for_testing");
    let config = JwtConfig::from_env().unwrap();
    
    config.generate_token_with_permissions(
        uuid::Uuid::new_v4(),
        &format!("{}@test.com", role),
        &format!("{} User", role),
        role,
        permissions.into_iter().map(|s| s.to_string()).collect(),
        Some("test_org".to_string()),
    ).unwrap()
}
```

### **13.2 Testes de JWT (`tests/jwt_tests.rs`)**

Testes específicos e abrangentes para o sistema JWT implementado.

#### **13.2.1 Testes de Ciclo de Vida Completo do JWT**

```rust
// tests/jwt_tests.rs - Testes abrangentes de JWT
use actix_api_crud::auth::jwt::{Claims, JwtConfig};
use chrono::{Duration, Utc};
use serial_test::serial;
use std::env;
use uuid::Uuid;

#[tokio::test]
#[serial]
async fn test_jwt_complete_lifecycle() {
    // Setup
    env::set_var("JWT_SECRET", "test_secret_key_with_32_characters_for_complete_testing");
    env::set_var("JWT_EXPIRATION", "24");

    let config = JwtConfig::from_env().unwrap();
    let user_id = Uuid::new_v4();

    // 1. Geração de token
    let token = config
        .generate_token(user_id, "lifecycle@test.com", "Lifecycle User", "user")
        .unwrap();

    assert!(!token.is_empty());
    assert!(token.contains('.'));  // JWT deve ter 3 partes separadas por pontos

    // 2. Validação inicial
    let claims = config.decode_token(&token).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.email, "lifecycle@test.com");
    assert!(config.is_token_valid(&claims));

    // 3. Verificação de tempo
    let now = Utc::now().timestamp();
    assert!(claims.iat <= now);
    assert!(claims.exp > now);

    // 4. Verificação de refresh necessário (token novo não deve precisar)
    assert!(!config.should_refresh_token(&claims));

    // 5. Simulação de token antigo que precisa refresh
    let old_claims = Claims {
        sub: user_id.to_string(),
        email: "lifecycle@test.com".to_string(),
        name: "Lifecycle User".to_string(),
        exp: (Utc::now() + Duration::hours(2)).timestamp(),  // Expira em 2h
        iat: (Utc::now() - Duration::hours(20)).timestamp(), // Criado há 20h
        role: "user".to_string(),
        permissions: None,
        organization_id: None,
        department: None,
        last_login: None,
        session_id: None,
    };

    assert!(config.should_refresh_token(&old_claims));

    // Cleanup
    env::remove_var("JWT_SECRET");
    env::remove_var("JWT_EXPIRATION");
}

#[tokio::test]
#[serial]
async fn test_jwt_claims_validation_comprehensive() {
    env::set_var("JWT_SECRET", "test_secret_comprehensive_validation_key_32chars");
    env::set_var("JWT_EXPIRATION", "1");

    let config = JwtConfig::from_env().unwrap();
    let user_id = Uuid::new_v4();

    // 1. Claims básicos
    let basic_token = config
        .generate_token(user_id, "basic@test.com", "Basic User", "user")
        .unwrap();

    let basic_claims = config.decode_token(&basic_token).unwrap();
    assert_eq!(basic_claims.role, "user");
    assert!(basic_claims.permissions.is_none());

    // 2. Claims com permissões
    let permissions = vec![
        "users:read".to_string(),
        "users:write".to_string(),
        "profile:update".to_string(),
    ];

    let perm_token = config
        .generate_token_with_permissions(
            user_id,
            "perm@test.com",
            "Permission User",
            "moderator",
            permissions.clone(),
            Some("org_456".to_string()),
        )
        .unwrap();

    let perm_claims = config.decode_token(&perm_token).unwrap();
    assert_eq!(perm_claims.role, "moderator");
    assert_eq!(perm_claims.permissions.unwrap(), permissions);
    assert_eq!(perm_claims.organization_id.unwrap(), "org_456");

    // 3. Claims de admin
    let admin_permissions = vec![
        "users:read".to_string(),
        "users:write".to_string(),
        "users:delete".to_string(),
        "admin:access".to_string(),
        "system:manage".to_string(),
    ];

    let admin_token = config
        .generate_admin_token(
            user_id,
            "admin@test.com",
            "Admin User",
            9, // High admin level
            vec!["users".to_string(), "system".to_string(), "audit".to_string()],
        )
        .unwrap();

    let admin_claims = config.decode_token(&admin_token).unwrap();
    assert_eq!(admin_claims.role, "admin");

    env::remove_var("JWT_SECRET");
    env::remove_var("JWT_EXPIRATION");
}

#[tokio::test]
#[serial]
async fn test_jwt_error_scenarios() {
    env::set_var("JWT_SECRET", "test_secret_error_scenarios_key_32_characters");

    let config = JwtConfig::from_env().unwrap();

    // 1. Token malformado
    let malformed_tokens = vec![
        "invalid.token",
        "definitely.not.a.jwt.token",
        "",
        "header.payload", // Faltando signature
        "a.b.c.d.e", // Muitas partes
    ];

    for malformed_token in malformed_tokens {
        let result = config.decode_token(malformed_token);
        assert!(result.is_err(), "Token '{}' should be invalid", malformed_token);
    }

    // 2. Token com secret diferente
    env::set_var("JWT_SECRET", "different_secret_key_with_32_characters");
    let config2 = JwtConfig::from_env().unwrap();
    
    env::set_var("JWT_SECRET", "original_secret_key_with_32_characters");
    let config1 = JwtConfig::from_env().unwrap();

    let token = config1
        .generate_token(Uuid::new_v4(), "test@example.com", "Test", "user")
        .unwrap();

    // Token gerado com config1 não deve ser válido para config2
    let result = config2.decode_token(&token);
    assert!(result.is_err());

    // 3. Token expirado manualmente
    let expired_token = create_expired_token();
    let result = config1.decode_token(&expired_token);
    assert!(result.is_err());

    env::remove_var("JWT_SECRET");
}

/// Helper para criar token expirado para testes
fn create_expired_token() -> String {
    use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};

    let claims = Claims {
        sub: Uuid::new_v4().to_string(),
        email: "expired@test.com".to_string(),
        name: "Expired User".to_string(),
        exp: (Utc::now() - Duration::hours(1)).timestamp(), // Expirado há 1 hora
        iat: (Utc::now() - Duration::hours(2)).timestamp(),
        role: "user".to_string(),
        permissions: None,
        organization_id: None,
        department: None,
        last_login: None,
        session_id: None,
    };

    let secret = "original_secret_key_with_32_characters";
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    ).unwrap()
}

#[tokio::test]
#[serial]
async fn test_jwt_refresh_token_system() {
    env::set_var("JWT_SECRET", "test_refresh_token_system_key_32_characters");

    let config = JwtConfig::from_env().unwrap();
    let user_id = Uuid::new_v4();

    // 1. Gerar par de tokens (access + refresh)
    let (access_token, refresh_token) = config
        .generate_token_pair(
            user_id,
            "refresh@test.com",
            "Refresh User",
            "user",
            Some("device_123".to_string()),
        )
        .unwrap();

    // 2. Validar access token
    let access_claims = config.decode_token(&access_token).unwrap();
    assert_eq!(access_claims.sub, user_id.to_string());

    // 3. Validar refresh token
    let refresh_claims = config.decode_refresh_token(&refresh_token).unwrap();
    assert_eq!(refresh_claims.sub, user_id.to_string());
    assert_eq!(refresh_claims.token_type, "refresh");
    assert_eq!(refresh_claims.device_id.unwrap(), "device_123");

    // 4. Simular uso do refresh token
    // (Em implementação real, seria usado com UserService)
    let mock_user_service = create_mock_user_service();
    let refresh_response = config
        .refresh_access_token(&refresh_token, &mock_user_service)
        .unwrap();

    assert_eq!(refresh_response.token_type, "Bearer");
    assert!(refresh_response.expires_in > 0);
    assert!(!refresh_response.access_token.is_empty());
    assert!(!refresh_response.refresh_token.is_empty());

    // 5. Novo access token deve ser válido
    let new_claims = config.decode_token(&refresh_response.access_token).unwrap();
    assert_eq!(new_claims.sub, user_id.to_string());

    env::remove_var("JWT_SECRET");
}

#[tokio::test]
#[serial]
async fn test_jwt_special_characters_and_encoding() {
    env::set_var("JWT_SECRET", "test_encoding_special_chars_key_32_characters");

    let config = JwtConfig::from_env().unwrap();
    let user_id = Uuid::new_v4();

    // Dados com caracteres especiais
    let special_cases = vec![
        ("José María", "jose.maria+test@empresa.com.br", "administrador"),
        ("李小明", "xiaoming@中国.com", "用户"),
        ("Олег Петров", "oleg@пример.рф", "модератор"),
        ("", "empty@name.com", "user"), // Nome vazio
        ("A".repeat(100), "long@name.com", "user"), // Nome muito longo
    ];

    for (name, email, role) in special_cases {
        let token = config
            .generate_token(user_id, &email, &name, &role)
            .unwrap();

        let claims = config.decode_token(&token).unwrap();
        assert_eq!(claims.name, name);
        assert_eq!(claims.email, email);
        assert_eq!(claims.role, role);
        assert!(config.is_token_valid(&claims));
    }

    env::remove_var("JWT_SECRET");
}
```

### **13.3 Testes de Middleware**

Testes específicos para cada middleware implementado no sistema.

#### **13.3.1 Testes de Rate Limiting**

```rust
#[actix_web::test]
async fn test_rate_limiting_comprehensive() {
    use actix_api_crud::middlewares::rate_limit::{RateLimitConfig, AdvancedRateLimiter};
    use std::sync::Arc;

    // Configuração restritiva para teste
    let config = RateLimitConfig {
        requests_per_window: 3,
        window_duration: std::time::Duration::from_secs(60),
        burst_size: 2,
        punishment_duration: std::time::Duration::from_secs(300),
    };

    let limiter = Arc::new(AdvancedRateLimiter::new(config));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(limiter.clone()))
            .route("/limited", web::get().to(move |limiter: web::Data<Arc<AdvancedRateLimiter>>| {
                async move {
                    let client_ip = "192.168.1.100";
                    match limiter.check_rate_limit(client_ip) {
                        actix_api_crud::middlewares::rate_limit::RateLimitResult::Allowed { remaining, .. } => {
                            actix_web::HttpResponse::Ok().json(json!({
                                "status": "allowed",
                                "remaining": remaining
                            }))
                        }
                        result => {
                            actix_api_crud::middlewares::rate_limit::rate_limit_response(&result).unwrap()
                        }
                    }
                }
            }))
    ).await;

    // 1. Primeiras requisições dentro do limite
    for i in 1..=3 {
        let req = test::TestRequest::get().uri("/limited").to_request();
        let resp = test::call_service(&app, req).await;
        
        assert_eq!(resp.status(), StatusCode::OK);
        
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "allowed");
        assert_eq!(body["remaining"], 3 - i);
    }

    // 2. Requisição que excede o limite
    let req = test::TestRequest::get().uri("/limited").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    let error_body: serde_json::Value = test::read_body_json(resp).await;
    assert!(error_body["error"].as_str().unwrap().contains("blocked") || 
             error_body["error"].as_str().unwrap().contains("exceeded"));
}

#[actix_web::test]
async fn test_security_headers_comprehensive() {
    use actix_api_crud::middlewares::security::SecurityHeaders;

    let security_config = SecurityHeaders::production();

    let app = test::init_service(
        App::new()
            .wrap(security_config)
            .route("/secure", web::get().to(|| async {
                actix_web::HttpResponse::Ok().json(json!({
                    "message": "Secure endpoint"
                }))
            }))
    ).await;

    let req = test::TestRequest::get().uri("/secure").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);

    // Verificar todos os headers de segurança
    let headers = resp.headers();
    
    // XSS Protection
    assert_eq!(
        headers.get("x-xss-protection").unwrap().to_str().unwrap(),
        "1; mode=block"
    );

    // Content Type Options
    assert_eq!(
        headers.get("x-content-type-options").unwrap().to_str().unwrap(),
        "nosniff"
    );

    // Frame Options
    assert_eq!(
        headers.get("x-frame-options").unwrap().to_str().unwrap(),
        "DENY"
    );

    // CSP
    assert!(headers.contains_key("content-security-policy"));
    let csp = headers.get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.contains("default-src 'self'"));

    // HSTS
    assert!(headers.contains_key("strict-transport-security"));
    let hsts = headers.get("strict-transport-security").unwrap().to_str().unwrap();
    assert!(hsts.contains("max-age="));
    assert!(hsts.contains("includeSubDomains"));

    // Referrer Policy
    assert_eq!(
        headers.get("referrer-policy").unwrap().to_str().unwrap(),
        "strict-origin-when-cross-origin"
    );

    // Permissions Policy
    assert!(headers.contains_key("permissions-policy"));
}

#[actix_web::test]
async fn test_input_sanitization_scenarios() {
    use actix_api_crud::middlewares::security::InputSanitizer;

    let app = test::init_service(
        App::new()
            .wrap(InputSanitizer::default())
            .route("/sanitize", web::post().to(|data: web::Json<serde_json::Value>| async move {
                actix_web::HttpResponse::Ok().json(data.into_inner())
            }))
    ).await;

    // 1. Input normal (deve passar)
    let normal_data = json!({
        "name": "João Silva",
        "message": "Hello world!"
    });

    let req = test::TestRequest::post()
        .uri("/sanitize")
        .set_json(&normal_data)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Input com padrões suspeitos
    let suspicious_patterns = vec![
        "SELECT * FROM users",
        "<script>alert('xss')</script>",
        "'; DROP TABLE users; --",
        "javascript:alert('xss')",
        "../../../etc/passwd",
    ];

    for pattern in suspicious_patterns {
        let malicious_data = json!({
            "input": pattern
        });

        let req = test::TestRequest::post()
            .uri("/sanitize")
            .set_json(&malicious_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        
        // Middleware de sanitização deve bloquear ou sanitizar
        assert!(
            resp.status() == StatusCode::BAD_REQUEST ||
            resp.status() == StatusCode::OK // Se sanitizou
        );
    }
}
```

### **13.4 Cobertura de Código**

Implementação de análise de cobertura e métricas de qualidade.

#### **13.4.1 Configuração de Cobertura com Tarpaulin**

```toml
# Adicionar ao Cargo.toml para ferramentas de análise
[dev-dependencies]
# ...existing code...
criterion = { version = "0.5", features = ["html_reports"] }
tarpaulin = "0.27"

# Configuração para cobertura
[package.metadata.tarpaulin]
exclude = ["tests/*", "benches/*"]
out = ["Html", "Lcov"]
output-dir = "coverage/"
```

#### **13.4.2 Scripts de Análise de Qualidade**

```bash
#!/bin/bash
# scripts/quality_check.sh

echo "🧪 Executando análise completa de qualidade..."

# 1. Testes unitários
echo "📋 Executando testes unitários..."
cargo test --lib

# 2. Testes de integração
echo "🔗 Executando testes de integração..."
cargo test --test '*'

# 3. Cobertura de código
echo "📊 Analisando cobertura de código..."
cargo tarpaulin --verbose --all-features --workspace --timeout 120 --out Html --output-dir coverage/

# 4. Análise estática com Clippy
echo "🔍 Executando Clippy..."
cargo clippy --all-targets --all-features -- -D warnings

# 5. Formatação de código
echo "✨ Verificando formatação..."
cargo fmt --all -- --check

# 6. Auditoria de segurança
echo "🛡️ Executando auditoria de segurança..."
cargo audit

# 7. Verificação de dependências não utilizadas
echo "🧹 Verificando dependências não utilizadas..."
cargo machete

# 8. Benchmarks (opcional)
echo "⚡ Executando benchmarks..."
cargo bench --no-run

echo "✅ Análise de qualidade concluída!"
echo "📊 Relatórios de cobertura disponíveis em: coverage/"
```

#### **13.4.3 Métricas e Relatórios**

```rust
// tests/quality_metrics.rs - Testes de métricas de qualidade
use std::process::Command;

#[test]
fn test_code_coverage_minimum() {
    // Este teste verifica se a cobertura mínima está sendo mantida
    let output = Command::new("cargo")
        .args(["tarpaulin", "--print-summary"])
        .output()
        .expect("Failed to run tarpaulin");

    let coverage_output = String::from_utf8_lossy(&output.stdout);
    
    // Extrair percentual de cobertura (simplificado)
    if let Some(line) = coverage_output.lines().find(|l| l.contains("Coverage:")) {
        let coverage_str = line.split_whitespace()
            .find(|s| s.ends_with('%'))
            .unwrap_or("0%");
        
        let coverage: f32 = coverage_str.trim_end_matches('%')
            .parse()
            .unwrap_or(0.0);
        
        assert!(coverage >= 80.0, "Code coverage is below 80%: {}%", coverage);
    }
}

#[test]
fn test_no_clippy_warnings() {
    let output = Command::new("cargo")
        .args(["clippy", "--all-targets", "--", "-D", "warnings"])
        .output()
        .expect("Failed to run clippy");

    assert!(
        output.status.success(),
        "Clippy found warnings:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_formatting_compliance() {
    let output = Command::new("cargo")
        .args(["fmt", "--all", "--", "--check"])
        .output()
        .expect("Failed to run rustfmt");

    assert!(
        output.status.success(),
        "Code formatting issues found:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn test_dependency_audit() {
    let output = Command::new("cargo")
        .arg("audit")
        .output()
        .expect("Failed to run cargo audit");

    assert!(
        output.status.success(),
        "Security vulnerabilities found:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
```

#### **13.4.4 Configuração de CI/CD para Qualidade**

```yaml
# .github/workflows/quality.yml
name: Quality Assurance

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  quality:
    name: Code Quality
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        components: rustfmt, clippy
        override: true

    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: |
          ~/.cargo/registry
          ~/.cargo/git
          target/
        key: ${{ runner.os }}-cargo-quality-${{ hashFiles('**/Cargo.lock') }}

    - name: Install coverage tools
      run: |
        cargo install cargo-tarpaulin
        cargo install cargo-audit
        cargo install cargo-machete

    - name: Run tests
      run: cargo test --all-features --workspace

    - name: Generate coverage
      run: |
        cargo tarpaulin \
          --verbose \
          --all-features \
          --workspace \
          --timeout 120 \
          --out Xml \
          --output-dir coverage/

    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: coverage/cobertura.xml
        fail_ci_if_error: true

    - name: Run Clippy
      run: cargo clippy --all-targets --all-features -- -D warnings

    - name: Check formatting
      run: cargo fmt --all -- --check

    - name: Security audit
      run: cargo audit

    - name: Check unused dependencies
      run: cargo machete

  performance:
    name: Performance Tests
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        override: true

    - name: Install criterion
      run: cargo install cargo-criterion

    - name: Run benchmarks
      run: cargo criterion --message-format=json > benchmark-results.json

    - name: Archive benchmark results
      uses: actions/upload-artifact@v3
      with:
        name: benchmark-results
        path: benchmark-results.json
```

---

## 🎯 **Exercícios Práticos**

### **Exercício 1: Testes de Middleware Avançados**
Implemente testes completos para middlewares:
- Rate limiting com múltiplos IPs e janelas de tempo
- Security headers personalizados por rota
- CORS dinâmico baseado em subdomínios
- Input sanitization com patterns customizados

### **Exercício 2: Testes de Error Handling Completos**
Crie testes abrangentes para tratamento de erros:
- Cascade de erros através de múltiplas camadas
- Recovery automático de falhas temporárias
- Timeouts e circuit breakers
- Logging estruturado de erros

### **Exercício 3: Sistema de Benchmarks Abrangente**
Desenvolva benchmarks para:
- Endpoints CRUD sob diferentes cargas
- Performance de geração/validação JWT vs outras soluções
- Throughput de middlewares de segurança
- Comparação de estratégias de cache

### **Exercício 4: Pipeline de Qualidade Completo**
Configure pipeline de qualidade:
- Cobertura mínima de 85% com relatórios HTML
- Análise de complexidade ciclomática
- Detecção de code smells automática
- Métricas de performance contínuas

---

## 📋 **Resumo da Unidade VIII**

**✅ Domínio Completo Adquirido:**

### **Capítulo 12: Testes Unitários e Integração**
- **Testes Unitários**: Modelos, serviços e lógica isolada com mocks
- **Testes de Integração**: Endpoints completos com middleware stack
- **Setup Robusto**: Configuração de aplicação de teste completa
- **Mocking Eficaz**: Mockall para isolamento total de dependências

### **Capítulo 13: Testes de Integração e Qualidade**
- **Endpoints Completos**: Fluxo de autenticação e autorização end-to-end
- **JWT Abrangente**: Ciclo de vida completo com refresh tokens
- **Middleware Testing**: Rate limiting, security headers, sanitização
- **Cobertura e Qualidade**: Tarpaulin, Clippy, auditoria de segurança

**🚀 Próxima Unidade:**
Na **Unidade IX**, abordaremos **Deploy e Produção**, incluindo containerização, monitoring, logging e estratégias de deploy.

**🔗 Recursos Críticos Implementados:**
- **77+ Testes**: Suite completa baseada no projeto real
- **Cobertura Automática**: Análise com relatórios HTML e CI/CD
- **Quality Gates**: Clippy, fmt, audit integrados
- **Performance Monitoring**: Benchmarks com Criterion
- **Testes E2E**: Fluxos completos de usuário com autenticação

**📊 Métricas de Qualidade Estabelecidas:**
- Cobertura mínima: 80%
- Zero warnings do Clippy
- Formatação consistente automática
- Auditoria de segurança contínua
- Benchmarks de performance automatizados

**🛡️ Aspectos de Segurança Testados:**
- JWT com diferentes cenários de ataque
- Input sanitization contra XSS/SQL Injection
- Rate limiting com bypass attempts
- Headers de segurança em diferentes ambientes

Esta unidade estabelece **qualidade de nível empresarial** com testes abrangentes, cobertura automática e pipeline de qualidade completo para aplicações Rust/Actix-Web de produção! 🧪✨
