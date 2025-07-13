# 🟠 **UNIDADE IV: LÓGICA DE NEGÓCIO**
*"Implementando regras de negócio robustas"*

## 📚 **Introdução**

A **Camada de Serviços** é onde reside o coração da aplicação - a lógica de negócio. Nesta unidade, você aprenderá a implementar serviços robustos que encapsulam regras de negócio complexas, mantendo-se independentes de detalhes de infraestrutura como bancos de dados ou frameworks web.

**Objetivos desta Unidade:**
- ✅ Compreender a arquitetura de serviços em Rust
- ✅ Implementar injeção de dependência com traits
- ✅ Separar lógica de negócio da persistência
- ✅ Aplicar princípios SOLID em Rust
- ✅ Criar abstrações testáveis e flexíveis

---

## 📌 **CAPÍTULO 6: CAMADA DE SERVIÇOS**

### **6.1 Arquitetura de Serviços (`services/`)**

A camada de serviços atua como intermediária entre os **handlers** (controllers) e os **repositories** (acesso a dados), encapsulando toda a lógica de negócio da aplicação.

#### **6.1.1 Estrutura da Camada de Serviços**

```rust
// src/services/mod.rs
use crate::errors::AppError;
use crate::models::{
    pagination::{PaginatedResponse, PaginationParams},
    user::{CreateUserDto, UpdateUserDto, User, UserResponse},
};
use async_trait::async_trait;
use uuid::Uuid;

pub mod user_service;

// Trait que define o contrato do serviço de usuários
#[async_trait]
pub trait UserServiceTrait {
    // Operações CRUD básicas
    async fn create_user(&self, create_dto: CreateUserDto) -> Result<User, AppError>;
    async fn get_user_by_id(&self, id: Uuid) -> Result<User, AppError>;
    async fn get_all_users(&self) -> Result<Vec<User>, AppError>;
    async fn get_users_paginated(
        &self,
        params: PaginationParams,
    ) -> Result<PaginatedResponse<UserResponse>, AppError>;
    async fn update_user(&self, id: Uuid, update_dto: UpdateUserDto) -> Result<User, AppError>;
    async fn delete_user(&self, id: Uuid) -> Result<bool, AppError>;

    // Operações de negócio específicas
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
```

**🔍 Análise do Design:**
- **Contrato Claro**: Define todas as operações disponíveis
- **Async/Await**: Suporte a operações assíncronas
- **Error Handling**: Tipo de erro consistente (`AppError`)
- **Flexibilidade**: Permite múltiplas implementações

#### **6.1.2 Implementação Concreta do Serviço**

```rust
// src/services/user_service.rs
use async_trait::async_trait;
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::Utc;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::pagination::{PaginatedResponse, PaginationParams};
use crate::models::user::{CreateUserDto, UpdateUserDto, User, UserResponse};
use crate::repositories::UserRepositoryTrait;
use crate::services::UserServiceTrait;

// Serviço concreto com dependência genérica do repositório
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

    // Helper privado para hash de senha
    fn hash_password(&self, password: &str) -> Result<String, AppError> {
        hash(password, DEFAULT_COST)
            .map_err(|_e| AppError::InternalServer)
    }

    // Helper privado para verificar senha
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, AppError> {
        verify(password, hash)
            .map_err(|_e| AppError::Auth("Invalid password".to_string()))
    }
}
```

**🚀 Características Profissionais:**
- **Generics**: `UserService<R>` permite qualquer implementação de repositório
- **Constraints**: `R: UserRepositoryTrait + Send + Sync` garante thread-safety
- **Encapsulamento**: Métodos helper privados para operações internas
- **Separation of Concerns**: Lógica de hash separada da lógica de negócio

#### **6.1.3 Implementação da Lógica de Negócio**

```rust
#[async_trait]
impl<R> UserServiceTrait for UserService<R>
where
    R: UserRepositoryTrait + Send + Sync,
{
    async fn create_user(&self, create_dto: CreateUserDto) -> Result<User, AppError> {
        // 1. Validações de negócio
        if self.user_repository.exists_by_email(&create_dto.email).await? {
            return Err(AppError::Validation("Email already exists".to_string()));
        }

        // 2. Validação de dados básicos
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

        // 3. Processamento de dados
        let password_hash = self.hash_password(&create_dto.password)?;

        // 4. Criação da entidade
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

        // 5. Persistência
        self.user_repository.create(user).await
    }

    async fn update_user(&self, id: Uuid, update_dto: UpdateUserDto) -> Result<User, AppError> {
        // 1. Buscar usuário existente
        let mut user = self.get_user_by_id(id).await?;

        // 2. Aplicar atualizações com validações
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

        // 3. Atualizar timestamp
        user.updated_at = Utc::now();

        // 4. Persistir mudanças
        self.user_repository.update(id, user).await
    }

    async fn get_users_paginated(
        &self,
        mut params: PaginationParams,
    ) -> Result<PaginatedResponse<UserResponse>, AppError> {
        // 1. Validar parâmetros de paginação
        params.validate();

        log::info!(
            "Fetching users with pagination: page={}, limit={}",
            params.page,
            params.limit
        );

        // 2. Buscar dados do repositório
        let (users, total_count) = self.user_repository.find_all_paginated(&params).await?;

        // 3. Transformar em DTOs de resposta (sem dados sensíveis)
        let user_responses: Vec<UserResponse> = users
            .into_iter()
            .map(UserResponse::from)
            .collect();

        // 4. Criar resposta paginada
        let paginated_response = PaginatedResponse::new(
            user_responses,
            params.page,
            params.limit,
            total_count,
        );

        log::info!(
            "Retrieved {} users (page {} of {})",
            paginated_response.data.len(),
            paginated_response.pagination.current_page,
            paginated_response.pagination.total_pages
        );

        Ok(paginated_response)
    }

    async fn authenticate_user(&self, email: &str, password: &str) -> Result<User, AppError> {
        // 1. Normalizar email
        let email_lower = email.trim().to_lowercase();

        // 2. Buscar usuário por email
        let user = self
            .user_repository
            .find_by_email(&email_lower)
            .await?
            .ok_or_else(|| AppError::Auth("Invalid credentials".to_string()))?;

        // 3. Verificar senha
        if self.verify_password(password, &user.password_hash)? {
            Ok(user)
        } else {
            Err(AppError::Auth("Invalid credentials".to_string()))
        }
    }

    async fn delete_user(&self, id: Uuid) -> Result<bool, AppError> {
        // 1. Verificar se usuário existe
        self.get_user_by_id(id).await?;

        // 2. Realizar exclusão
        self.user_repository.delete(id).await
    }
}
```

**🎯 Padrões de Lógica de Negócio:**
- **Validação em Camadas**: Dados → Negócio → Persistência
- **Fail Fast**: Validações no início dos métodos
- **Transformação de Dados**: DTOs → Entities → DTOs
- **Logging Estratégico**: Operações importantes registradas
- **Security**: Senhas hasheadas, emails normalizados

---

### **6.2 Injeção de Dependência**

A injeção de dependência permite que os serviços dependam de abstrações ao invés de implementações concretas, facilitando testes e flexibilidade.

#### **6.2.1 Estrutura de Dependências**

```rust
// Hierarquia de dependências:
// Handler → Service → Repository

// Handler depende de trait, não implementação concreta
#[derive(Clone)]
pub struct UserHandler<S: UserServiceTrait> {
    user_service: S,
}

impl<S: UserServiceTrait> UserHandler<S> {
    pub fn new(user_service: S) -> Self {
        Self { user_service }
    }

    pub async fn create_user(
        &self,
        create_dto: ValidatedJson<CreateUserDto>,
    ) -> Result<HttpResponse, AppError> {
        info!("Creating new user with email: {}", create_dto.email);

        match self.user_service.create_user(create_dto.into_inner()).await {
            Ok(user) => {
                let response = UserResponse::from(user);
                info!("User created successfully with ID: {}", response.id);
                
                Ok(HttpResponse::Created().json(serde_json::json!({
                    "status": "success",
                    "message": "User created successfully",
                    "data": response
                })))
            }
            Err(e) => {
                error!("Failed to create user: {}", e);
                Err(e)
            }
        }
    }
}
```

#### **6.2.2 Composição no Main**

```rust
// src/main.rs - Composição das dependências
use actix_web::{web, App, HttpServer, middleware::Logger};

use crate::config::database::{create_connection_pool, DatabaseConfig};
use crate::handlers::UserHandler;
use crate::repositories::UserRepository;
use crate::services::UserService;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 1. Configuração do banco
    let db_config = DatabaseConfig::from_env();
    let pool = create_connection_pool(&db_config).await.unwrap();

    // 2. Criação da cadeia de dependências
    let user_repository = UserRepository::new(pool);
    let user_service = UserService::new(user_repository);
    let user_handler = UserHandler::new(user_service);

    // 3. Configuração do servidor
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(user_handler.clone()))
            .service(
                web::scope("/api/users")
                    .route("", web::post().to(create_user_wrapper))
                    .route("", web::get().to(get_all_users_wrapper))
                    .route("/paginated", web::get().to(get_users_paginated_wrapper))
                    .route("/{id}", web::get().to(get_user_by_id_wrapper))
                    .route("/{id}", web::put().to(update_user_wrapper))
                    .route("/{id}", web::delete().to(delete_user_wrapper)),
            )
            .wrap(Logger::default())
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

// Wrapper functions para compatibilidade com Actix Web
async fn create_user_wrapper(
    handler: web::Data<UserHandler<UserService<UserRepository>>>,
    dto: ValidatedJson<CreateUserDto>,
) -> impl Responder {
    handler.create_user(dto).await
}

// ... outros wrappers
```

**🔧 Benefícios da Injeção de Dependência:**
- **Testabilidade**: Fácil substituição por mocks
- **Flexibilidade**: Troca de implementações sem modificar código
- **Baixo Acoplamento**: Dependência de abstrações
- **Reutilização**: Componentes intercambiáveis

---

### **6.3 Traits e Abstrações**

Os traits em Rust permitem definir contratos claros e criar abstrações poderosas para a lógica de negócio.

#### **6.3.1 Design de Traits Eficazes**

```rust
// Trait bem estruturado com responsabilidades claras
#[async_trait]
pub trait UserServiceTrait {
    // Operações CRUD fundamentais
    async fn create_user(&self, create_dto: CreateUserDto) -> Result<User, AppError>;
    async fn get_user_by_id(&self, id: Uuid) -> Result<User, AppError>;
    async fn update_user(&self, id: Uuid, update_dto: UpdateUserDto) -> Result<User, AppError>;
    async fn delete_user(&self, id: Uuid) -> Result<bool, AppError>;

    // Operações de consulta avançadas
    async fn get_users_paginated(
        &self,
        params: PaginationParams,
    ) -> Result<PaginatedResponse<UserResponse>, AppError>;

    // Operações de negócio específicas
    async fn authenticate_user(&self, email: &str, password: &str) -> Result<User, AppError>;
    async fn find_by_email(&self, email: &str) -> Result<User, AppError>;
}

// Trait especializado para operações administrativas
#[async_trait]
pub trait AdminUserServiceTrait: UserServiceTrait {
    async fn promote_to_admin(&self, user_id: Uuid) -> Result<User, AppError>;
    async fn suspend_user(&self, user_id: Uuid, reason: String) -> Result<(), AppError>;
    async fn get_user_activity(&self, user_id: Uuid) -> Result<UserActivity, AppError>;
    async fn bulk_delete_users(&self, user_ids: Vec<Uuid>) -> Result<usize, AppError>;
}
```

#### **6.3.2 Implementação de Traits Compostos**

```rust
// Implementação para operações administrativas
#[async_trait]
impl<R> AdminUserServiceTrait for UserService<R>
where
    R: UserRepositoryTrait + Send + Sync,
{
    async fn promote_to_admin(&self, user_id: Uuid) -> Result<User, AppError> {
        // 1. Buscar usuário
        let mut user = self.get_user_by_id(user_id).await?;

        // 2. Verificar se já é admin
        if user.role.as_deref() == Some("admin") {
            return Err(AppError::Validation("User is already an admin".to_string()));
        }

        // 3. Aplicar mudança
        user.role = Some("admin".to_string());
        user.updated_at = Utc::now();

        // 4. Persistir
        self.user_repository.update(user_id, user).await
    }

    async fn suspend_user(&self, user_id: Uuid, reason: String) -> Result<(), AppError> {
        // 1. Validar razão
        if reason.trim().is_empty() {
            return Err(AppError::Validation("Suspension reason is required".to_string()));
        }

        // 2. Buscar usuário
        let mut user = self.get_user_by_id(user_id).await?;

        // 3. Aplicar suspensão
        user.role = Some("suspended".to_string());
        user.updated_at = Utc::now();

        // 4. Log da operação
        log::warn!("User {} suspended. Reason: {}", user_id, reason);

        // 5. Persistir
        self.user_repository.update(user_id, user).await?;
        Ok(())
    }

    async fn bulk_delete_users(&self, user_ids: Vec<Uuid>) -> Result<usize, AppError> {
        let mut deleted_count = 0;

        for user_id in user_ids {
            match self.delete_user(user_id).await {
                Ok(true) => deleted_count += 1,
                Ok(false) => log::warn!("User {} not found for deletion", user_id),
                Err(e) => log::error!("Failed to delete user {}: {}", user_id, e),
            }
        }

        log::info!("Bulk deletion completed: {} users deleted", deleted_count);
        Ok(deleted_count)
    }
}
```

#### **6.3.3 Traits para Cross-Cutting Concerns**

```rust
// Trait para auditoria
#[async_trait]
pub trait AuditableService {
    async fn log_action(&self, user_id: Uuid, action: &str, details: &str) -> Result<(), AppError>;
    async fn get_user_audit_log(&self, user_id: Uuid) -> Result<Vec<AuditEntry>, AppError>;
}

// Trait para cache
#[async_trait]
pub trait CacheableService {
    async fn invalidate_cache(&self, key: &str) -> Result<(), AppError>;
    async fn warm_cache(&self) -> Result<(), AppError>;
}

// Implementação composta
pub struct AuditableUserService<R, A>
where
    R: UserRepositoryTrait + Send + Sync,
    A: AuditRepository + Send + Sync,
{
    user_service: UserService<R>,
    audit_repository: A,
}

#[async_trait]
impl<R, A> UserServiceTrait for AuditableUserService<R, A>
where
    R: UserRepositoryTrait + Send + Sync,
    A: AuditRepository + Send + Sync,
{
    async fn create_user(&self, create_dto: CreateUserDto) -> Result<User, AppError> {
        // 1. Executar operação principal
        let user = self.user_service.create_user(create_dto).await?;

        // 2. Registrar auditoria
        self.log_action(
            user.id,
            "CREATE_USER",
            &format!("User created with email: {}", user.email),
        ).await?;

        Ok(user)
    }

    // ... implementar outros métodos com auditoria
}
```

---

### **6.4 Lógica de Negócio vs. Persistência**

A separação clara entre lógica de negócio e persistência é fundamental para uma arquitetura robusta.

#### **6.4.1 Responsabilidades da Camada de Serviço**

**✅ O que DEVE estar nos serviços:**
- Validações de regras de negócio
- Transformações de dados
- Coordenação entre repositórios
- Aplicação de políticas de segurança
- Cálculos e processamentos
- Logging de operações importantes

**❌ O que NÃO deve estar nos serviços:**
- Detalhes de SQL/queries
- Mapeamento de banco de dados
- Configurações de conexão
- Tratamento de transações HTTP
- Serialização/deserialização

#### **6.4.2 Exemplo de Separação Correta**

```rust
// ✅ CORRETO: Serviço focado em lógica de negócio
impl<R> UserServiceTrait for UserService<R>
where
    R: UserRepositoryTrait + Send + Sync,
{
    async fn create_user(&self, create_dto: CreateUserDto) -> Result<User, AppError> {
        // LÓGICA DE NEGÓCIO: Validações
        self.validate_user_creation(&create_dto)?;

        // LÓGICA DE NEGÓCIO: Verificar duplicatas
        if self.user_repository.exists_by_email(&create_dto.email).await? {
            return Err(AppError::Validation("Email already exists".to_string()));
        }

        // LÓGICA DE NEGÓCIO: Processamento de dados
        let password_hash = self.hash_password(&create_dto.password)?;
        let normalized_email = create_dto.email.trim().to_lowercase();

        // LÓGICA DE NEGÓCIO: Criação da entidade
        let user = User {
            id: Uuid::new_v4(),
            name: create_dto.name.trim().to_string(),
            email: normalized_email,
            age: create_dto.age,
            password_hash,
            role: Some(self.determine_default_role()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // DELEGAÇÃO: Persistência é responsabilidade do repositório
        self.user_repository.create(user).await
    }

    // LÓGICA DE NEGÓCIO: Método helper privado
    fn validate_user_creation(&self, dto: &CreateUserDto) -> Result<(), AppError> {
        if dto.name.trim().is_empty() {
            return Err(AppError::Validation("Name cannot be empty".to_string()));
        }

        if dto.age < 13 {
            return Err(AppError::Validation("User must be at least 13 years old".to_string()));
        }

        if dto.password.len() < 8 {
            return Err(AppError::Validation("Password must be at least 8 characters".to_string()));
        }

        if !dto.email.contains('@') || dto.email.len() < 5 {
            return Err(AppError::Validation("Invalid email format".to_string()));
        }

        Ok(())
    }

    // LÓGICA DE NEGÓCIO: Determinação de role padrão
    fn determine_default_role(&self) -> String {
        // Regra: primeiro usuário é admin, outros são users
        match self.user_repository.count_all().await {
            Ok(0) => "admin".to_string(),
            _ => "user".to_string(),
        }
    }
}
```

#### **6.4.3 Coordenação Entre Repositórios**

```rust
// Exemplo de operação complexa que coordena múltiplos repositórios
impl<R> UserServiceTrait for UserService<R>
where
    R: UserRepositoryTrait + Send + Sync,
{
    async fn delete_user_with_cleanup(&self, user_id: Uuid) -> Result<(), AppError> {
        // 1. Verificar se usuário existe
        let user = self.get_user_by_id(user_id).await?;

        // 2. LÓGICA DE NEGÓCIO: Verificar se pode ser deletado
        if user.role.as_deref() == Some("admin") {
            let admin_count = self.user_repository.count_by_role("admin").await?;
            if admin_count <= 1 {
                return Err(AppError::Validation(
                    "Cannot delete the last admin user".to_string()
                ));
            }
        }

        // 3. COORDENAÇÃO: Limpar dados relacionados
        // (Aqui você injetaria outros repositórios conforme necessário)
        
        // 3a. Remover posts do usuário
        // self.post_repository.delete_by_user_id(user_id).await?;
        
        // 3b. Remover comentários
        // self.comment_repository.delete_by_user_id(user_id).await?;
        
        // 3c. Invalidar sessões ativas
        // self.session_repository.invalidate_by_user_id(user_id).await?;

        // 4. DELEGAÇÃO: Deletar usuário principal
        let deleted = self.user_repository.delete(user_id).await?;

        if deleted {
            log::info!("User {} successfully deleted with cleanup", user_id);
            Ok(())
        } else {
            Err(AppError::NotFound("User not found".to_string()))
        }
    }
}
```

---

## 🎯 **Exercícios Práticos**

### **Exercício 1: Serviço de Produtos**
Implemente um `ProductService` com:
- Validações de negócio (preço > 0, categoria válida)
- Cálculo automático de desconto por categoria
- Controle de estoque integrado

### **Exercício 2: Auditoria Automática**
Crie um `AuditableUserService` que:
- Registra todas as operações em log de auditoria
- Mantém histórico de mudanças
- Permite rollback de operações

### **Exercício 3: Cache Inteligente**
Desenvolva um `CachedUserService` que:
- Cache consultas frequentes
- Invalida cache automaticamente em mudanças
- Implementa cache warming estratégico

---

## 📋 **Resumo da Unidade**

**✅ Domínio Adquirido:**
- **Arquitetura de Serviços**: Estrutura clara e responsabilidades bem definidas
- **Injeção de Dependência**: Flexibilidade e testabilidade através de traits
- **Abstrações Eficazes**: Traits bem projetados para contratos claros
- **Separação de Responsabilidades**: Lógica de negócio isolada da persistência

**🚀 Próxima Unidade:**
Na **Unidade V**, exploraremos **Camada Web e Actix-Web** (já desenvolvida), onde implementaremos handlers robustos, middleware avançado e integração HTTP completa.

**🔗 Recursos Importantes:**
- Traits genéricos para máxima flexibilidade
- Validações em múltiplas camadas
- Error handling consistente e informativo
- Logging estratégico para operações críticas

Esta unidade estabelece os **fundamentos sólidos** para lógica de negócio robusta e manutenível em aplicações Rust de produção!
