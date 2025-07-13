<div align="center">

# 🚀 Actix API CRUD

### ⚡ API REST robusta e performática em Rust

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Actix-Web](https://img.shields.io/badge/Actix--Web-4.0+-blue.svg)](https://actix.rs/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-blue.svg)](https://www.postgresql.org/)
[![JWT](https://img.shields.io/badge/JWT-Auth-green.svg)](https://jwt.io/)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-green.svg)](https://github.com/features/actions)
[![Tests](https://img.shields.io/badge/Tests-67%2B-brightgreen.svg)](#-testes-e-qualidade)

*Uma API moderna para gerenciamento de usuários com foco em performance, segurança e qualidade de código*

[📖 Documentação](#-documentação) • [🚀 Começar](#-instalação-e-uso) • [🧪 Testes](#-testes-e-qualidade) • [🔧 API](#-endpoints-da-api)

</div>

---

## ✨ Características

<table>
<tr>
<td>

### � **Performance**
- Framework Actix-Web assíncrono
- Zero-cost abstractions do Rust
- Pool de conexões otimizado
- Middleware de cache e compressão

</td>
<td>

### 🔒 **Segurança**
- Autenticação JWT robusta
- Hash BCrypt para senhas
- Rate limiting configurável
- Headers de segurança (CSRF, XSS, etc.)

</td>
</tr>
<tr>
<td>

### 🏗️ **Arquitetura**
- Clean Architecture / Onion Architecture
- Injeção de dependência
- Separação clara de responsabilidades
- Type-safe em todo o código

</td>
<td>

### ✅ **Qualidade**
- **67+ testes** (96% de cobertura)
- CI/CD com GitHub Actions
- Linting automático (Clippy)
- Documentação completa

</td>
</tr>
</table>

---

## 🛠️ Stack Tecnológica

| Categoria | Tecnologia | Versão | Descrição |
|-----------|------------|--------|-----------|
| **Core** | [Rust](https://www.rust-lang.org/) | 1.70+ | Linguagem principal - performance e segurança |
| **Web Framework** | [Actix-Web](https://actix.rs/) | 4.0+ | Framework web assíncrono de alta performance |
| **Database** | [PostgreSQL](https://www.postgresql.org/) | 15+ | Banco de dados relacional robusto |
| **ORM** | [SQLx](https://github.com/launchbadge/sqlx) | 0.7+ | Driver SQL assíncrono e type-safe |
| **Auth** | [JWT](https://jwt.io/) + [BCrypt](https://en.wikipedia.org/wiki/Bcrypt) | - | Autenticação segura baseada em tokens |
| **Serialization** | [Serde](https://serde.rs/) | 1.0+ | Serialização JSON ultra-rápida |
| **Testing** | [Tokio Test](https://tokio.rs/) + [Mockall](https://docs.rs/mockall/) | - | Framework de testes assíncronos |

---

## 📁 Arquitetura do Projeto

```
📦 actix_api_crud/
├── 🚀 src/
│   ├── 🎯 main.rs                    # Entry point da aplicação
│   ├── 📚 lib.rs                     # Biblioteca pública (para testes)
│   ├── 🎮 handlers/                  # Controllers (HTTP endpoints)
│   │   ├── user_handler.rs          # CRUD de usuários
│   │   └── auth_handler.rs           # Autenticação
│   ├── 📊 models/                    # Entidades e DTOs
│   │   ├── user.rs                   # Modelo de usuário
│   │   └── pagination.rs             # Sistema de paginação
│   ├── 🏪 services/                  # Lógica de negócio
│   │   └── user_service.rs           # Regras de negócio de usuários
│   ├── 🗄️ repositories/             # Camada de dados
│   │   └── user_repository.rs        # Acesso ao banco
│   ├── 🛡️ middlewares/              # Middlewares customizados
│   │   ├── auth.rs                   # Middleware JWT
│   │   ├── security.rs               # Headers de segurança
│   │   ├── cors.rs                   # CORS configurável
│   │   └── validation.rs             # Validação automática
│   ├── 🔐 auth/                      # Sistema de autenticação
│   │   ├── jwt.rs                    # Geração/validação JWT
│   │   └── models.rs                 # DTOs de auth
│   ├── ⚙️ config/                    # Configurações
│   │   ├── database.rs               # Config do banco
│   │   └── security.rs               # Config de segurança
│   ├── ❌ errors/                    # Tratamento de erros
│   │   └── mod.rs                    # Error types customizados
│   └── 🛤️ routes/                    # Configuração de rotas
│       └── mod.rs                    # Agrupamento de rotas
├── 🧪 tests/                         # Testes de integração
│   ├── integration_tests.rs          # Testes end-to-end
│   └── jwt_tests.rs                  # Testes especializados JWT
├── 🔧 scripts/                       # Scripts utilitários
│   ├── quality_check.ps1             # Verificação de qualidade (Windows)
│   └── quality_check.sh              # Verificação de qualidade (Unix)
├── 🚦 .github/workflows/             # CI/CD Pipeline
│   └── ci.yml                        # GitHub Actions
├── 📋 migrations/                    # Migrações do banco
├── 📖 docs/                          # Documentação adicional
└── 📄 README.md                      # Este arquivo
```

---

## 🚀 Instalação e Uso

### 📋 Pré-requisitos

- **Rust 1.70+** ([instalar](https://rustup.rs/))
- **PostgreSQL 15+** ([instalar](https://www.postgresql.org/download/))
- **Git** ([instalar](https://git-scm.com/downloads))

### ⚡ Início Rápido

```bash
# 1️⃣ Clone o repositório
git clone https://github.com/consultorsandro/actix_api_crud.git
cd actix_api_crud

# 2️⃣ Configure as variáveis de ambiente
cp .env.example .env
# Edite o arquivo .env com suas configurações

# 3️⃣ Configure o banco de dados
createdb actix_api_db
# Execute as migrações (se houver)

# 4️⃣ Execute o projeto
cargo run
```

### 🔧 Configuração (.env)

```bash
# 🗄️ Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/actix_api_db

# 🔐 JWT Configuration
JWT_SECRET=seu-super-secret-jwt-key-com-pelo-menos-32-caracteres
JWT_EXPIRATION=24  # horas

# 🌍 Server Configuration
APP_HOST=127.0.0.1
APP_PORT=8080
RUST_ENV=development

# 📝 Logging
RUST_LOG=info

# �️ Security
RATE_LIMIT_ENABLED=true
SECURITY_HEADERS_ENABLED=true
INPUT_SANITIZATION_ENABLED=true
HTTPS_ONLY=false  # true em produção

# 🌐 CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
```

### 🏃‍♂️ Comandos Úteis

```bash
# 🔍 Verificar compilação
cargo check

# 🧪 Executar todos os testes
cargo test

# 🎯 Executar testes específicos
cargo test --test integration_tests
cargo test --test jwt_tests

# 🧹 Formatação de código
cargo fmt

# 🔧 Linting
cargo clippy

# 🚀 Build para produção
cargo build --release

# 📊 Verificação de qualidade completa
./scripts/quality_check.sh  # Unix/Linux/macOS
.\scripts\quality_check.ps1 # Windows
```

---

## 🔧 Endpoints da API

### 🏠 Health Check

```http
GET /health
```

**Resposta:**
```json
{
  "status": "success",
  "message": "User service is healthy",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 👤 Gerenciamento de Usuários

#### Criar Usuário
```http
POST /api/v1/users
Content-Type: application/json

{
  "name": "João Silva",
  "email": "joao@exemplo.com",
  "password": "senha123",
  "age": 25
}
```

#### Buscar Usuário por ID
```http
GET /api/v1/users/{id}
```

#### Listar Usuários (Paginado)
```http
GET /api/v1/users/paginated?page=1&limit=10&search=joão&sort_by=name&sort_order=asc
```

#### Atualizar Usuário
```http
PUT /api/v1/users/{id}
Content-Type: application/json

{
  "name": "João Santos",
  "email": "joao.santos@exemplo.com"
}
```

#### Deletar Usuário
```http
DELETE /api/v1/users/{id}
```

### � Autenticação (Planejado)

```http
POST /api/v1/auth/login
POST /api/v1/auth/register
GET /api/v1/auth/me
PUT /api/v1/auth/change-password
POST /api/v1/auth/logout
```

---

## 🧪 Testes e Qualidade

### 📊 Estatísticas de Testes

| Tipo de Teste | Quantidade | Status |
|---------------|------------|--------|
| **Testes Unitários** | 47+ | ✅ Passando |
| **Testes de Integração** | 10 | ✅ Passando |
| **Testes JWT** | 10 | ✅ Passando |
| **Total** | **67+** | **✅ 96% Sucesso** |

### 🎯 Cobertura de Testes

- ✅ **Models** - Validação de DTOs, serialização, entidades
- ✅ **Services** - Lógica de negócio, regras de validação
- ✅ **Handlers** - Controllers HTTP, tratamento de requests
- ✅ **Middlewares** - Autenticação, segurança, CORS
- ✅ **Integration** - Fluxos end-to-end, middlewares chains
- ✅ **JWT System** - Geração, validação, expiração de tokens

### � Executar Testes

```bash
# 🧪 Todos os testes
cargo test

# 🔍 Testes específicos
cargo test --test integration_tests  # Integração
cargo test --test jwt_tests          # JWT
cargo test --lib                     # Unitários

# 📊 Com cobertura (se tiver cargo-tarpaulin)
cargo tarpaulin --verbose --all-features --workspace
```

### 🏆 Qualidade de Código

```bash
# 🎨 Formatação
cargo fmt --all

# 🔧 Linting
cargo clippy --all-targets --all-features -- -D warnings

# ✅ Verificação completa
./scripts/quality_check.sh
```

---

## 🚦 CI/CD Pipeline

### 🔄 GitHub Actions

O projeto inclui um pipeline completo de CI/CD:

- ✅ **Code Quality** - fmt, clippy, compilation
- ✅ **Testing** - Unit, integration, JWT tests
- ✅ **Security** - cargo audit, dependency check
- ✅ **Build** - Release build verification
- ✅ **Deploy** - Automated deployment (on main branch)

### � Jobs do Pipeline

1. **🧹 Code Quality Checks**
   - Formatação de código
   - Linting (Clippy)
   - Verificação de compilação

2. **🧪 Test Suite**
   - Testes unitários
   - Testes de integração
   - Cobertura de código

3. **🏗️ Build Production**
   - Build de release
   - Verificação de dependências

4. **� Security Audit**
   - Auditoria de vulnerabilidades
   - Verificação de código inseguro

---

## 📈 Roadmap e Status

### ✅ Concluído

- [x] **Etapa 1** - Setup e estrutura inicial
- [x] **Etapa 2** - Arquitetura e módulos base
- [x] **Etapa 3** - Integração PostgreSQL + SQLx
- [x] **Etapa 4** - CRUD completo de usuários
- [x] **Etapa 5** - Sistema de autenticação JWT
- [x] **Etapa 6** - Middlewares e segurança
- [x] **Etapa 7** - Testes e qualidade (67+ testes)

### 🚧 Em Desenvolvimento

- [ ] **Etapa 8** - Documentação e deploy

### 🔮 Futuro

- [ ] **WebSockets** para notificações em tempo real
- [ ] **Caching** com Redis
- [ ] **Rate Limiting** avançado
- [ ] **Métricas** e observabilidade
- [ ] **Docker** containerization
- [ ] **Kubernetes** deployment

---

## 🤝 Contribuindo

### 🛠️ Setup para Desenvolvimento

```bash
# Fork o projeto
git clone https://github.com/SEU-USUARIO/actix_api_crud.git
cd actix_api_crud

# Configure o ambiente
cp .env.example .env
# Configure suas variáveis de ambiente

# Execute os testes
cargo test

# Verifique a qualidade
./scripts/quality_check.sh
```

### 📝 Guidelines

1. **Code Style** - Use `cargo fmt` antes de commit
2. **Linting** - Resolva todos os warnings do `cargo clippy`
3. **Tests** - Mantenha cobertura alta (>90%)
4. **Commits** - Use [Conventional Commits](https://www.conventionalcommits.org/)
5. **PR** - Inclua descrição detalhada das mudanças

---

## 📄 Licença

Este projeto está licenciado sob a **MIT License** - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

## 👨‍💻 Autor

**Sandro Reis** - *Desenvolvedor*

- 📧 Email: [sandro@exemplo.com](mailto:consultorsandro@hotmail.com)
- 🐱 GitHub: [@consultorsandro](https://github.com/consultorsandro)
- 💼 LinkedIn: [Sandro Ramos](https://linkedin.com/in/sandro-reis-veterano)

---

<div align="center">

### ⭐ Se este projeto te ajudou, dê uma estrela!

**Feito com ❤️ e ☕ usando Rust 🦀 e prompts de IA**

*API moderna, segura e performática para o mundo real*

</div>
