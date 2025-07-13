# 🏛️ Arquitetura do Sistema

## 🎯 Visão Geral

O projeto segue os princípios da **Clean Architecture** (Arquitetura Limpa) e **Onion Architecture**, garantindo:

- ✅ **Separação de responsabilidades**
- ✅ **Baixo acoplamento**
- ✅ **Alta coesão**
- ✅ **Testabilidade**
- ✅ **Manutenibilidade**

---

## 🧅 Camadas da Arquitetura

```
┌─────────────────────────────────────────────┐
│                  🌐 HTTP Layer               │
│           (Actix-Web Framework)             │
├─────────────────────────────────────────────┤
│              🎮 Handlers Layer               │
│         (Controllers/HTTP Endpoints)        │
├─────────────────────────────────────────────┤
│             🛡️ Middleware Layer              │
│      (Auth, CORS, Security, Validation)     │
├─────────────────────────────────────────────┤
│              🏪 Services Layer               │
│            (Business Logic)                 │
├─────────────────────────────────────────────┤
│            🗄️ Repository Layer              │
│            (Data Access Logic)              │
├─────────────────────────────────────────────┤
│              💾 Database Layer               │
│              (PostgreSQL)                   │
└─────────────────────────────────────────────┘
```

---

## 📊 Diagrama de Componentes

```
   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
   │  📱 Client   │    │  🌐 Browser │    │  📡 Mobile  │
   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
          │                  │                  │
          └──────────────────┼──────────────────┘
                             │
   ┌─────────────────────────▼─────────────────────────┐
   │                🚀 Actix-Web Server               │
   └─────────────────────────┬─────────────────────────┘
                             │
   ┌─────────────────────────▼─────────────────────────┐
   │              🛡️ Middleware Pipeline               │
   │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ │
   │  │  CORS   │ │   JWT   │ │Security │ │Validate │ │
   │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ │
   └─────────────────────────┬─────────────────────────┘
                             │
   ┌─────────────────────────▼─────────────────────────┐
   │               🎮 Handlers (Controllers)           │
   │  ┌─────────────┐           ┌─────────────┐       │
   │  │UserHandler  │           │AuthHandler  │       │
   │  └─────────────┘           └─────────────┘       │
   └─────────────────────────┬─────────────────────────┘
                             │
   ┌─────────────────────────▼─────────────────────────┐
   │                🏪 Services Layer                  │
   │  ┌─────────────┐           ┌─────────────┐       │
   │  │UserService  │           │AuthService  │       │
   │  └─────────────┘           └─────────────┘       │
   └─────────────────────────┬─────────────────────────┘
                             │
   ┌─────────────────────────▼─────────────────────────┐
   │              🗄️ Repository Layer                  │
   │  ┌─────────────────┐     ┌─────────────────┐     │
   │  │ UserRepository  │     │ AuthRepository  │     │
   │  └─────────────────┘     └─────────────────┘     │
   └─────────────────────────┬─────────────────────────┘
                             │
   ┌─────────────────────────▼─────────────────────────┐
   │                💾 PostgreSQL                     │
   │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ │
   │  │  users  │ │sessions │ │  roles  │ │  logs   │ │
   │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ │
   └───────────────────────────────────────────────────┘
```

---

## 🔄 Fluxo de Dados

### 1️⃣ Request Flow (Entrada)

```
🌐 HTTP Request
    ↓
🛡️ Middleware Pipeline
    ├── CORS Check
    ├── Rate Limiting
    ├── Security Headers
    ├── Input Sanitization
    └── JWT Validation (se necessário)
    ↓
🎮 Handler (Controller)
    ├── Extrair parâmetros
    ├── Validar dados
    └── Chamar Service
    ↓
🏪 Service (Business Logic)
    ├── Aplicar regras de negócio
    ├── Validações complexas
    └── Chamar Repository
    ↓
🗄️ Repository (Data Access)
    ├── Montar queries SQL
    ├── Executar transações
    └── Mapear resultados
    ↓
💾 PostgreSQL Database
```

### 2️⃣ Response Flow (Saída)

```
💾 Database Result
    ↓
🗄️ Repository
    ├── Mapear para entidades
    └── Tratar erros de DB
    ↓
🏪 Service
    ├── Aplicar transformações
    ├── Converter para DTOs
    └── Tratar erros de negócio
    ↓
🎮 Handler
    ├── Formatar resposta JSON
    ├── Definir status HTTP
    └── Adicionar headers
    ↓
🛡️ Middleware Pipeline
    ├── Adicionar headers de segurança
    ├── Comprimir resposta
    └── Log da requisição
    ↓
🌐 HTTP Response
```

---

## 🎯 Princípios SOLID Aplicados

### **S** - Single Responsibility Principle
- **Handlers**: Apenas processamento HTTP
- **Services**: Apenas lógica de negócio
- **Repositories**: Apenas acesso a dados
- **Models**: Apenas estrutura de dados

### **O** - Open/Closed Principle
- Traits permitem extensão sem modificação
- Middleware pipeline extensível
- Sistema de erros customizáveis

### **L** - Liskov Substitution Principle
- Implementações de traits são intercambiáveis
- Mocks substituem implementações reais em testes

### **I** - Interface Segregation Principle
- Traits específicas e focadas (UserServiceTrait, UserRepositoryTrait)
- Interfaces mínimas e bem definidas

### **D** - Dependency Inversion Principle
- Dependências injetadas via traits
- Camadas superiores não dependem de implementações concretas

---

## 🔧 Dependency Injection

### Estrutura de Injeção

```rust
// Handler depende de trait, não implementação concreta
pub struct UserHandler<S> 
where 
    S: UserServiceTrait + Send + Sync 
{
    user_service: S,
}

// Service depende de trait do Repository
pub struct UserService<R> 
where 
    R: UserRepositoryTrait + Send + Sync 
{
    user_repository: R,
}

// Composição no main.rs
let repository = UserRepository::new(db_pool);
let service = UserService::new(repository);
let handler = UserHandler::new(service);
```

### Benefícios

- ✅ **Testabilidade**: Fácil substituição por mocks
- ✅ **Flexibilidade**: Troca de implementações
- ✅ **Baixo Acoplamento**: Dependência de abstrações
- ✅ **Reutilização**: Componentes intercambiáveis

---

## 🧪 Arquitetura de Testes

```
┌─────────────────────────────────────────────┐
│              🧪 Test Strategy                │
├─────────────────────────────────────────────┤
│  📊 Unit Tests (Models, Services, Utils)    │
│  ├── Validação de DTOs                     │
│  ├── Lógica de negócio                     │
│  └── Funções utilitárias                   │
├─────────────────────────────────────────────┤
│  🔧 Integration Tests (Handlers, Middleware)│
│  ├── Endpoints HTTP                        │
│  ├── Middleware chains                     │
│  └── Database integration                  │
├─────────────────────────────────────────────┤
│  🎭 Mock Tests (Service Layer)              │
│  ├── Repository mocks                      │
│  ├── External service mocks                │
│  └── Error scenario testing               │
├─────────────────────────────────────────────┤
│  🔐 Specialized Tests (JWT, Security)       │
│  ├── Token generation/validation           │
│  ├── Security headers                      │
│  └── Authentication flows                  │
└─────────────────────────────────────────────┘
```

---

## 📈 Padrões de Design Utilizados

### 🏭 Repository Pattern
- Abstração da camada de dados
- Facilita troca de banco de dados
- Melhora testabilidade

### 🏗️ Service Layer Pattern
- Encapsula lógica de negócio
- Coordena operações entre repositories
- Mantém handlers simples

### 🎭 Dependency Injection
- Inversão de controle
- Baixo acoplamento
- Alta testabilidade

### 🔧 Factory Pattern
- Criação de objetos complexos
- Configuração centralizada
- Facilita manutenção

### 🎯 DTO Pattern
- Transferência de dados entre camadas
- Validação automática
- Serialização type-safe

---

## 🚀 Performance e Escalabilidade

### ⚡ Otimizações Implementadas

1. **Pool de Conexões**
   - Reutilização de conexões DB
   - Configuração otimizada
   - Timeout apropriado

2. **Async/Await**
   - I/O não-bloqueante
   - Alta concorrência
   - Baixo uso de recursos

3. **Zero-Copy Serialization**
   - Serde otimizado
   - Mínima alocação de memória
   - Serialização ultra-rápida

4. **Middleware Eficiente**
   - Pipeline otimizado
   - Cache de configurações
   - Validação rápida

### 📊 Métricas de Escalabilidade

- **Vertical**: CPU e memória linear com carga
- **Horizontal**: Stateless, fácil load balancing
- **Database**: Pool de conexões configurável
- **Caching**: Preparado para Redis integration

---

## 🛡️ Segurança por Design

### Camadas de Segurança

1. **Input Layer**
   - Validação de dados
   - Sanitização automática
   - Rate limiting

2. **Authentication Layer**
   - JWT tokens seguros
   - BCrypt password hashing
   - Session management

3. **Authorization Layer**
   - Role-based access control
   - Resource-level permissions
   - Audit trails

4. **Transport Layer**
   - HTTPS enforcement
   - Security headers
   - CORS protection

---

*Arquitetura projetada para crescer e evoluir com o projeto*
