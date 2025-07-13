# 🟡 **UNIDADE III: CAMADA DE DADOS E PERSISTÊNCIA**
*"Dominando SQLx e PostgreSQL com Rust"*

## 📚 **Introdução**

A **Camada de Dados** é o coração de qualquer aplicação web robusta. Nesta unidade, você aprenderá a implementar padrões profissionais de acesso a dados usando **SQLx** - o toolkit de banco de dados assíncrono mais avançado do ecossistema Rust, combinado com **PostgreSQL** como sistema de gerenciamento de banco de dados.

**Objetivos desta Unidade:**
- ✅ Implementar o padrão Repository para abstração de dados
- ✅ Dominar queries type-safe com SQLx
- ✅ Gerenciar migrações e versionamento de schema
- ✅ Configurar e otimizar pools de conexão
- ✅ Aplicar técnicas avançadas de persistência

---

## 📌 **CAPÍTULO 5: REPOSITÓRIOS E BANCO DE DADOS**

### **5.1 Padrão Repository (`repositories/`)**

O **padrão Repository** fornece uma interface uniforme para acesso a dados, abstraindo os detalhes de implementação específicos do banco. Vamos examinar nossa implementação profissional:

#### **5.1.1 Definindo Traits Genéricos**

```rust
// src/repositories/mod.rs
use crate::errors::AppError;
use crate::models::{PaginationParams, UserFilters, user::User};
use async_trait::async_trait;
use uuid::Uuid;

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
    // Queries específicas de usuário
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AppError>;
    async fn exists_by_email(&self, email: &str) -> Result<bool, AppError>;
    
    // Paginação e filtros avançados
    async fn find_with_filters(
        &self,
        filters: &UserFilters,
        params: &PaginationParams,
    ) -> Result<(Vec<User>, u64), AppError>;
    
    async fn count_all(&self) -> Result<u64, AppError>;
    
    // Métodos de autenticação
    async fn find_by_email_direct(&self, email: &str) -> Result<User, AppError>;
    async fn create_with_password(
        &self,
        create_dto: crate::models::user::CreateUserDto,
        password_hash: String,
        role: String,
    ) -> Result<User, AppError>;
    async fn update_password(&self, id: Uuid, new_password_hash: String) -> Result<(), AppError>;
}
```

**🔍 Análise do Design:**
- **Separação de Responsabilidades**: `Repository<T, ID>` para operações genéricas
- **Especialização**: `UserRepositoryTrait` para operações específicas de usuário
- **Type Safety**: Uso de tipos genéricos e `async_trait`
- **Error Handling**: Retorno consistente com `AppError`

#### **5.1.2 Implementação Concreta com SQLx**

```rust
// src/repositories/user_repository.rs
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{
    pagination::{PaginationParams, UserFilters},
    user::{CreateUserDto, User},
};
use crate::repositories::{Repository, UserRepositoryTrait};

#[derive(Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

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

        // Query type-safe usando sqlx::query
        let result = sqlx::query(
            "INSERT INTO users (id, name, email, age, password_hash, role, created_at, updated_at) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
             RETURNING id, name, email, age, password_hash, role, created_at, updated_at",
        )
        .bind(&user.id)
        .bind(&user.name)
        .bind(&user.email)
        .bind(user.age)
        .bind(&user.password_hash)
        .bind(&user.role)
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

        // Mapear resultado para estrutura User
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
            "SELECT id, name, email, age, password_hash, role, created_at, updated_at 
             FROM users WHERE id = $1"
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
                    age: row.get("age"),
                    password_hash: row.get("password_hash"),
                    role: row.get("role"),
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                };
                Ok(Some(user))
            }
            None => Ok(None),
        }
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

        // Query dinâmica para buscar dados com paginação
        let sort_order = match params.sort_order {
            crate::models::SortOrder::Asc => "ASC",
            crate::models::SortOrder::Desc => "DESC",
        };

        let sort_field = params.sort_by.as_deref().unwrap_or("created_at");

        let query_str = if let Some(ref _search) = params.search {
            format!(
                "SELECT id, name, email, age, password_hash, role, created_at, updated_at 
                 FROM users 
                 WHERE name ILIKE $1 OR email ILIKE $1 
                 ORDER BY {} {} 
                 LIMIT $2 OFFSET $3",
                sort_field, sort_order
            )
        } else {
            format!(
                "SELECT id, name, email, age, password_hash, role, created_at, updated_at 
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
                age: row.get("age"),
                password_hash: row.get("password_hash"),
                role: row.get("role"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
            .collect();

        Ok((users, total as u64))
    }

    // ... outras implementações
}
```

**🚀 Características Profissionais:**
- **Error Handling Específico**: Tratamento diferenciado para duplicate key
- **Queries Dinâmicas**: Suporte a busca, ordenação e paginação
- **Type Safety**: Mapeamento manual garantindo tipos corretos
- **Performance**: Queries otimizadas com índices apropriados

#### **5.1.3 Implementações Especializadas**

```rust
#[async_trait]
impl UserRepositoryTrait for UserRepository {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        let result = sqlx::query(
            "SELECT id, name, email, age, password_hash, role, created_at, updated_at 
             FROM users WHERE email = $1"
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
                    age: row.get("age"),
                    password_hash: row.get("password_hash"),
                    role: row.get("role"),
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

    async fn create_with_password(
        &self,
        create_dto: CreateUserDto,
        password_hash: String,
        role: String,
    ) -> Result<User, AppError> {
        let result = sqlx::query(
            "INSERT INTO users (name, email, age, password_hash, role) 
             VALUES ($1, $2, $3, $4, $5) 
             RETURNING id, name, email, age, password_hash, role, created_at, updated_at"
        )
        .bind(&create_dto.name)
        .bind(&create_dto.email)
        .bind(create_dto.age)
        .bind(&password_hash)
        .bind(&role)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Database(format!("Failed to create user: {}", e)))?;

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
}
```

---

### **5.2 SQLx: Queries Type-Safe**

**SQLx** é o toolkit de banco de dados mais avançado do Rust, oferecendo compile-time verification de queries SQL.

#### **5.2.1 Configuração Avançada do SQLx**

```rust
// src/config/database.rs
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;
use crate::errors::AppError;

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
}

impl DatabaseConfig {
    pub fn from_env() -> Self {
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgresql://postgres:postgres@localhost:5432/actix_crud_db".to_string()
        });

        Self {
            url: database_url,
            max_connections: std::env::var("DB_MAX_CONNECTIONS")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or(10),
            min_connections: std::env::var("DB_MIN_CONNECTIONS")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or(1),
            connect_timeout: Duration::from_secs(
                std::env::var("DB_CONNECT_TIMEOUT")
                    .ok()
                    .and_then(|val| val.parse().ok())
                    .unwrap_or(30),
            ),
            idle_timeout: Duration::from_secs(
                std::env::var("DB_IDLE_TIMEOUT")
                    .ok()
                    .and_then(|val| val.parse().ok())
                    .unwrap_or(600),
            ),
        }
    }
}
```

#### **5.2.2 Técnicas Avançadas de Query**

**1. Queries Preparadas para Performance:**
```rust
// Cache de queries preparadas
impl UserRepository {
    async fn find_users_by_role_prepared(&self, role: &str) -> Result<Vec<User>, AppError> {
        // Query é compilada uma vez e reutilizada
        let rows = sqlx::query_as!(
            User,
            "SELECT id, name, email, age, password_hash, role, created_at, updated_at 
             FROM users WHERE role = $1",
            role
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Database(format!("Failed to find users by role: {}", e)))?;

        Ok(rows)
    }
}
```

**2. Transações para Operações Complexas:**
```rust
impl UserRepository {
    async fn create_user_with_profile(
        &self, 
        create_dto: CreateUserDto,
        profile_data: ProfileData
    ) -> Result<(User, Profile), AppError> {
        let mut tx = self.pool.begin().await
            .map_err(|e| AppError::Database(format!("Failed to start transaction: {}", e)))?;

        // Criar usuário
        let user = sqlx::query_as!(
            User,
            "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING *",
            create_dto.name,
            create_dto.email,
            create_dto.password_hash
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(format!("Failed to create user: {}", e)))?;

        // Criar perfil associado
        let profile = sqlx::query_as!(
            Profile,
            "INSERT INTO profiles (user_id, bio, avatar_url) VALUES ($1, $2, $3) RETURNING *",
            user.id,
            profile_data.bio,
            profile_data.avatar_url
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(format!("Failed to create profile: {}", e)))?;

        // Confirmar transação
        tx.commit().await
            .map_err(|e| AppError::Database(format!("Failed to commit transaction: {}", e)))?;

        Ok((user, profile))
    }
}
```

**3. Queries Dinâmicas com Query Builder:**
```rust
use sqlx::QueryBuilder;

impl UserRepository {
    async fn search_users_advanced(
        &self,
        filters: &UserFilters,
        params: &PaginationParams,
    ) -> Result<(Vec<User>, u64), AppError> {
        let mut query_builder = QueryBuilder::new(
            "SELECT id, name, email, age, password_hash, role, created_at, updated_at FROM users WHERE 1=1"
        );

        // Adicionar filtros dinamicamente
        if let Some(ref name) = filters.name {
            query_builder.push(" AND name ILIKE ");
            query_builder.push_bind(format!("%{}%", name));
        }

        if let Some(ref email_domain) = filters.email_domain {
            query_builder.push(" AND email LIKE ");
            query_builder.push_bind(format!("%@{}", email_domain));
        }

        if let Some(min_age) = filters.min_age {
            query_builder.push(" AND age >= ");
            query_builder.push_bind(min_age);
        }

        // Adicionar ordenação
        query_builder.push(" ORDER BY ");
        query_builder.push(params.sort_by.as_deref().unwrap_or("created_at"));
        match params.sort_order {
            crate::models::SortOrder::Asc => query_builder.push(" ASC"),
            crate::models::SortOrder::Desc => query_builder.push(" DESC"),
        };

        // Adicionar paginação
        query_builder.push(" LIMIT ");
        query_builder.push_bind(params.limit as i64);
        query_builder.push(" OFFSET ");
        query_builder.push_bind(params.offset() as i64);

        let users = query_builder
            .build_query_as::<User>()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to search users: {}", e)))?;

        // Query separada para contar total
        let total = self.count_with_filters(filters).await?;

        Ok((users, total))
    }
}
```

---

### **5.3 Migrações e Versionamento**

O sistema de migrações garante evolução controlada do schema do banco de dados.

#### **5.3.1 Estrutura de Migrações**

```sql
-- migrations/001_initial_users.up.sql
-- Migration: Initial user table
-- Created at: 2025-01-12

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(320) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

-- Create trigger to automatically update updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();
```

```sql
-- migrations/001_initial_users.down.sql
-- Rollback: Remove user table and related objects

DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP FUNCTION IF EXISTS update_updated_at_column();
DROP INDEX IF EXISTS idx_users_created_at;
DROP INDEX IF EXISTS idx_users_email;
DROP TABLE IF EXISTS users;
```

#### **5.3.2 Execução Automática de Migrações**

```rust
// src/config/database.rs
pub async fn run_migrations(pool: &PgPool) -> Result<(), AppError> {
    log::info!("Running database migrations...");

    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| {
            log::error!("Failed to run migrations: {}", e);
            AppError::Database(format!("Failed to run migrations: {}", e))
        })?;

    log::info!("Database migrations completed successfully");
    Ok(())
}

pub async fn test_connection(pool: &PgPool) -> Result<(), AppError> {
    log::info!("Testing database connection...");

    sqlx::query("SELECT 1 as test")
        .fetch_one(pool)
        .await
        .map_err(|e| {
            log::error!("Database connection test failed: {}", e);
            AppError::Database(format!("Database connection test failed: {}", e))
        })?;

    log::info!("Database connection test successful");
    Ok(())
}
```

#### **5.3.3 Migrações Avançadas com Dados**

```sql
-- migrations/002_add_user_roles.up.sql
-- Add role system to users

-- Adicionar coluna role
ALTER TABLE users ADD COLUMN role VARCHAR(50) DEFAULT 'user';

-- Criar tabela de roles
CREATE TABLE user_roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    permissions JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Inserir roles padrão
INSERT INTO user_roles (name, description, permissions) VALUES
('admin', 'System Administrator', '["read", "write", "delete", "admin"]'),
('moderator', 'Content Moderator', '["read", "write", "moderate"]'),
('user', 'Regular User', '["read"]');

-- Atualizar usuários existentes
UPDATE users SET role = 'user' WHERE role IS NULL;

-- Adicionar constraint
ALTER TABLE users ADD CONSTRAINT fk_users_role 
    FOREIGN KEY (role) REFERENCES user_roles(name);

-- Criar índice na role
CREATE INDEX idx_users_role ON users(role);
```

---

### **5.4 Pool de Conexões**

O gerenciamento eficiente de conexões é crucial para performance e escalabilidade.

#### **5.4.1 Configuração Avançada do Pool**

```rust
// src/config/database.rs
pub async fn create_connection_pool(config: &DatabaseConfig) -> Result<PgPool, AppError> {
    log::info!("Creating database connection pool...");
    log::info!("Database URL: {}", config.url);
    log::info!("Max connections: {}", config.max_connections);
    log::info!("Min connections: {}", config.min_connections);

    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.connect_timeout)
        .idle_timeout(config.idle_timeout)
        .max_lifetime(Duration::from_secs(1800)) // 30 minutos
        .test_before_acquire(true) // Testar conexão antes de usar
        .connect(&config.url)
        .await
        .map_err(|e| {
            log::error!("Failed to create connection pool: {}", e);
            AppError::Database(format!("Failed to create connection pool: {}", e))
        })?;

    log::info!("Database connection pool created successfully");

    // Teste a conexão
    test_connection(&pool).await?;

    Ok(pool)
}
```

#### **5.4.2 Monitoramento do Pool**

```rust
use sqlx::pool::PoolConnection;
use sqlx::Postgres;

impl DatabaseConfig {
    pub async fn monitor_pool_health(pool: &PgPool) -> Result<PoolHealth, AppError> {
        let pool_options = pool.options();
        
        Ok(PoolHealth {
            max_connections: pool_options.get_max_connections(),
            active_connections: pool.size(),
            idle_connections: pool.num_idle(),
            total_connections: pool.size(),
            is_healthy: pool.size() > 0,
        })
    }
}

#[derive(Debug, serde::Serialize)]
pub struct PoolHealth {
    pub max_connections: u32,
    pub active_connections: u32,
    pub idle_connections: usize,
    pub total_connections: u32,
    pub is_healthy: bool,
}

// Endpoint para health check
pub async fn database_health_handler(
    pool: web::Data<PgPool>
) -> Result<impl Responder, AppError> {
    let health = DatabaseConfig::monitor_pool_health(&pool).await?;
    Ok(HttpResponse::Ok().json(health))
}
```

#### **5.4.3 Recuperação Automática de Conexões**

```rust
pub async fn check_database_availability(database_url: &str) -> Result<(), AppError> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .map_err(|e| AppError::Database(format!("Database not available: {}", e)))?;

    sqlx::query("SELECT 1")
        .fetch_one(&pool)
        .await
        .map_err(|e| AppError::Database(format!("Database query failed: {}", e)))?;

    pool.close().await;
    Ok(())
}

// Retry logic com exponential backoff
pub async fn create_resilient_pool(config: &DatabaseConfig) -> Result<PgPool, AppError> {
    let mut attempts = 0;
    let max_attempts = 5;
    
    loop {
        match create_connection_pool(config).await {
            Ok(pool) => return Ok(pool),
            Err(e) if attempts < max_attempts => {
                attempts += 1;
                let delay = Duration::from_secs(2_u64.pow(attempts));
                log::warn!("Database connection failed (attempt {}), retrying in {:?}...", attempts, delay);
                tokio::time::sleep(delay).await;
            }
            Err(e) => return Err(e),
        }
    }
}
```

---

## 🎯 **Exercícios Práticos**

### **Exercício 1: Repository Avançado**
Implemente um `ProductRepository` com:
- Busca por categoria e faixa de preço
- Ordenação por popularidade/preço
- Cache de queries frequentes

### **Exercício 2: Migrações Complexas**
Crie migrações para:
- Sistema de auditoria (log de alterações)
- Soft delete (exclusão lógica)
- Particionamento por data

### **Exercício 3: Performance Optimization**
Otimize queries para:
- Busca full-text em descrições
- Agregações complexas (vendas por período)
- Índices compostos otimizados

---

## 📋 **Resumo da Unidade**

**✅ Domínio Adquirido:**
- **Padrão Repository**: Abstração profissional de acesso a dados
- **SQLx Avançado**: Queries type-safe, transações e performance
- **Migrações**: Versionamento e evolução controlada do schema
- **Pool Management**: Configuração, monitoramento e recuperação

**🚀 Próxima Unidade:**
Na **Unidade IV**, exploraremos **Camada de Serviços e Lógica de Negócio**, onde implementaremos padrões avançados de arquitetura e validação de regras de negócio.

**🔗 Recursos Importantes:**
- Pool de conexões otimizado para alta concorrência
- Sistema de migrações robusto com rollback
- Queries type-safe com compile-time verification
- Tratamento de erros específicos do banco de dados

Esta unidade estabelece a **base sólida** para operações de dados eficientes e confiáveis em aplicações Rust de produção!
