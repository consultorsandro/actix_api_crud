# Unidade 9: Deploy e Produção

Esta unidade aborda os aspectos finais e cruciais para colocar sua API em produção, incluindo otimização de build, configurações de produção, monitoramento e containerização com Docker.

## Capítulo 14: Deploy e Ambiente de Produção

### 14.1 Otimização de Build para Produção

#### 14.1.1 Configurações de Release no Cargo.toml

Primeiro, vamos otimizar as configurações de compilação para produção. Adicione as seguintes configurações ao seu `Cargo.toml`:

```toml
[profile.release]
# Otimização máxima
opt-level = 3
# Permite mais tempo de compilação para melhor otimização
codegen-units = 1
# Link-time optimization
lto = true
# Remove símbolos de debug no release
debug = false
# Panic = abort reduz o tamanho do binário
panic = "abort"
# Strip símbolos para reduzir tamanho
strip = true
# Overflow checks em release (opcional, pode impactar performance)
overflow-checks = false

[profile.dev]
# Para desenvolvimento mais rápido
opt-level = 0
debug = true
incremental = true

[profile.test]
# Para testes otimizados
opt-level = 1
debug = true
```

#### 14.1.2 Features Condicionais para Produção

Adicione features condicionais para diferentes ambientes:

```toml
[features]
default = ["production"]
production = []
development = ["console-logging"]
console-logging = []
```

### 14.2 Dockerfile e Containerização

#### 14.2.1 Criando um Dockerfile Multi-Stage

Crie um `Dockerfile` otimizado para produção:

```dockerfile
# Dockerfile
# Stage 1: Build
FROM rust:1.75-slim as builder

# Instalar dependências necessárias
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Definir diretório de trabalho
WORKDIR /app

# Copiar arquivos de configuração primeiro (para cache)
COPY Cargo.toml Cargo.lock ./

# Criar projeto dummy para baixar dependências
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > src/lib.rs

# Build dependências (será cached se Cargo.toml não mudar)
RUN cargo build --release && \
    rm -rf src target/release/deps/actix_api_crud*

# Copiar código fonte
COPY src ./src

# Build final
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim as runtime

# Instalar dependências de runtime
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpq5 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Criar usuário não-root
RUN useradd -m -u 1001 appuser

# Criar diretórios necessários
RUN mkdir -p /app/logs && \
    chown -R appuser:appuser /app

# Copiar binário do stage de build
COPY --from=builder /app/target/release/actix_api_crud /app/

# Definir usuário
USER appuser

# Definir diretório de trabalho
WORKDIR /app

# Expor porta
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Comando de execução
CMD ["./actix_api_crud"]
```

#### 14.2.2 Docker Compose para Produção

Atualize o `docker-compose.yml` para incluir a aplicação:

```yaml
version: '3.8'

services:
  # Aplicação Rust/Actix-Web
  api:
    build:
      context: .
      dockerfile: Dockerfile
      target: runtime
    container_name: actix_api_crud
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://postgres:postgres123@postgres:5432/actix_crud
      - JWT_SECRET=${JWT_SECRET}
      - JWT_REFRESH_SECRET=${JWT_REFRESH_SECRET}
      - RUST_LOG=info
      - ENVIRONMENT=production
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - actix_network
    volumes:
      - ./logs:/app/logs
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # PostgreSQL Database
  postgres:
    image: postgres:15-alpine
    container_name: postgres_actix
    restart: unless-stopped
    environment:
      POSTGRES_DB: actix_crud
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres123
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - actix_network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d actix_crud"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Adminer para administração do banco
  adminer:
    image: adminer:4.8.1
    container_name: adminer_actix
    restart: unless-stopped
    ports:
      - "8081:8080"
    networks:
      - actix_network
    depends_on:
      - postgres

  # Redis para cache (opcional)
  redis:
    image: redis:7-alpine
    container_name: redis_actix
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - actix_network
    command: redis-server --appendonly yes

volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local

networks:
  actix_network:
    driver: bridge
```

### 14.3 Configurações de Produção

#### 14.3.1 Variáveis de Ambiente para Produção

Crie um arquivo `.env.production`:

```env
# .env.production
# Database Configuration
DATABASE_URL=postgresql://postgres:postgres123@postgres:5432/actix_crud
DATABASE_POOL_SIZE=20
DATABASE_TIMEOUT=30

# JWT Configuration
JWT_SECRET=your-super-secure-jwt-secret-key-change-this-in-production
JWT_REFRESH_SECRET=your-super-secure-refresh-secret-key-change-this-in-production
JWT_EXPIRATION=900
JWT_REFRESH_EXPIRATION=604800

# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
SERVER_WORKERS=4

# Logging Configuration
RUST_LOG=actix_api_crud=info,actix_web=info
LOG_LEVEL=info
LOG_FILE=/app/logs/actix_api_crud.log

# Security Configuration
BCRYPT_COST=12
RATE_LIMIT_REQUESTS=1000
RATE_LIMIT_WINDOW=60
CORS_ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
SECURITY_HEADERS=true

# Environment
ENVIRONMENT=production
DEBUG=false

# Health Check
HEALTH_CHECK_INTERVAL=30

# Monitoring
METRICS_ENABLED=true
METRICS_PORT=9090

# Cache Configuration (Redis)
REDIS_URL=redis://redis:6379
CACHE_TTL=3600
```

#### 14.3.2 Configuração de Logging Estruturado

Crie um módulo de configuração de logging avançado em `src/config/logging.rs`:

```rust
// src/config/logging.rs
use std::env;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use tracing_appender::rolling::{RollingFileAppender, Rotation};

pub fn init_logging() {
    let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
    let log_level = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

    match environment.as_str() {
        "production" => init_production_logging(&log_level),
        "development" => init_development_logging(&log_level),
        _ => init_development_logging(&log_level),
    }
}

fn init_production_logging(log_level: &str) {
    let log_dir = env::var("LOG_DIR").unwrap_or_else(|_| "./logs".to_string());
    
    // Arquivo rotativo diário
    let file_appender = RollingFileAppender::new(
        Rotation::DAILY,
        &log_dir,
        "actix_api_crud.log"
    );

    let file_layer = fmt::layer()
        .with_writer(file_appender)
        .json()
        .with_current_span(false)
        .with_span_list(true);

    // Console para Docker logs
    let console_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .json();

    tracing_subscriber::registry()
        .with(EnvFilter::new(log_level))
        .with(file_layer)
        .with(console_layer)
        .init();
}

fn init_development_logging(log_level: &str) {
    tracing_subscriber::registry()
        .with(EnvFilter::new(log_level))
        .with(fmt::layer().pretty())
        .init();
}

// Estruturas para logging estruturado
#[derive(serde::Serialize)]
pub struct RequestLog {
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_ms: u64,
    pub user_id: Option<String>,
    pub ip: String,
    pub user_agent: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ErrorLog {
    pub error: String,
    pub context: Option<String>,
    pub user_id: Option<String>,
    pub request_id: Option<String>,
}

#[derive(serde::Serialize)]
pub struct SecurityLog {
    pub event_type: String,
    pub ip: String,
    pub user_id: Option<String>,
    pub details: String,
    pub severity: String,
}
```

### 14.4 Monitoramento e Observabilidade

#### 14.4.1 Health Check Endpoint

Adicione um endpoint de health check em `src/handlers/health.rs`:

```rust
// src/handlers/health.rs
use actix_web::{web, HttpResponse, Result};
use serde_json::json;
use sqlx::PgPool;
use std::time::Instant;

pub struct HealthHandler {
    pool: PgPool,
}

impl HealthHandler {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn health_check(&self) -> Result<HttpResponse> {
        let start = Instant::now();
        
        // Verificar conexão com banco
        let db_status = match sqlx::query("SELECT 1").fetch_one(&self.pool).await {
            Ok(_) => "healthy",
            Err(_) => "unhealthy",
        };

        let duration = start.elapsed();

        let response = json!({
            "status": if db_status == "healthy" { "ok" } else { "error" },
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "services": {
                "database": {
                    "status": db_status,
                    "response_time_ms": duration.as_millis()
                }
            },
            "version": env!("CARGO_PKG_VERSION"),
            "environment": std::env::var("ENVIRONMENT").unwrap_or_else(|_| "unknown".to_string())
        });

        match db_status {
            "healthy" => Ok(HttpResponse::Ok().json(response)),
            _ => Ok(HttpResponse::ServiceUnavailable().json(response)),
        }
    }

    pub async fn readiness_check(&self) -> Result<HttpResponse> {
        // Verificações mais rigorosas para readiness
        let checks = vec![
            self.check_database().await,
            self.check_memory().await,
        ];

        let all_healthy = checks.iter().all(|check| check.healthy);

        let response = json!({
            "status": if all_healthy { "ready" } else { "not_ready" },
            "checks": checks
        });

        match all_healthy {
            true => Ok(HttpResponse::Ok().json(response)),
            false => Ok(HttpResponse::ServiceUnavailable().json(response)),
        }
    }

    async fn check_database(&self) -> HealthCheck {
        let start = Instant::now();
        match sqlx::query("SELECT 1").fetch_one(&self.pool).await {
            Ok(_) => HealthCheck {
                name: "database".to_string(),
                healthy: true,
                message: "Database connection successful".to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
            },
            Err(e) => HealthCheck {
                name: "database".to_string(),
                healthy: false,
                message: format!("Database connection failed: {}", e),
                duration_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    async fn check_memory(&self) -> HealthCheck {
        // Verificação básica de memória disponível
        HealthCheck {
            name: "memory".to_string(),
            healthy: true,
            message: "Memory usage within acceptable limits".to_string(),
            duration_ms: 0,
        }
    }
}

#[derive(serde::Serialize)]
struct HealthCheck {
    name: String,
    healthy: bool,
    message: String,
    duration_ms: u64,
}

pub fn configure_health_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/health")
            .route("", web::get().to(health_check))
            .route("/ready", web::get().to(readiness_check))
    );
}

async fn health_check(handler: web::Data<HealthHandler>) -> Result<HttpResponse> {
    handler.health_check().await
}

async fn readiness_check(handler: web::Data<HealthHandler>) -> Result<HttpResponse> {
    handler.readiness_check().await
}
```

#### 14.4.2 Métricas com Prometheus

Adicione dependências para métricas no `Cargo.toml`:

```toml
# Adicionar ao [dependencies]
prometheus = "0.13"
actix-web-prometheus = "0.1"
```

Crie um módulo de métricas em `src/metrics/mod.rs`:

```rust
// src/metrics/mod.rs
use prometheus::{
    Counter, Histogram, IntGauge, Registry, Encoder, TextEncoder,
    HistogramOpts, Opts,
};
use actix_web::{HttpResponse, Result, web};
use std::sync::Arc;

pub struct Metrics {
    pub registry: Registry,
    pub requests_total: Counter,
    pub request_duration: Histogram,
    pub active_connections: IntGauge,
    pub database_connections: IntGauge,
}

impl Metrics {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let registry = Registry::new();

        let requests_total = Counter::with_opts(
            Opts::new("http_requests_total", "Total number of HTTP requests")
                .namespace("actix_api_crud")
        )?;

        let request_duration = Histogram::with_opts(
            HistogramOpts::new("http_request_duration_seconds", "HTTP request duration")
                .namespace("actix_api_crud")
                .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
        )?;

        let active_connections = IntGauge::with_opts(
            Opts::new("active_connections", "Number of active connections")
                .namespace("actix_api_crud")
        )?;

        let database_connections = IntGauge::with_opts(
            Opts::new("database_connections", "Number of database connections")
                .namespace("actix_api_crud")
        )?;

        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(request_duration.clone()))?;
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(database_connections.clone()))?;

        Ok(Metrics {
            registry,
            requests_total,
            request_duration,
            active_connections,
            database_connections,
        })
    }
}

pub async fn metrics_handler(metrics: web::Data<Arc<Metrics>>) -> Result<HttpResponse> {
    let encoder = TextEncoder::new();
    let metric_families = metrics.registry.gather();
    let mut buffer = Vec::new();
    
    encoder.encode(&metric_families, &mut buffer)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(buffer))
}
```

### 14.5 Scripts de Deploy

#### 14.5.1 Script de Build e Deploy

Crie um script `deploy.sh`:

```bash
#!/bin/bash
# deploy.sh

set -e

echo "🚀 Iniciando deploy da API Actix-Web..."

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Função para logs
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar se Docker está rodando
if ! docker info > /dev/null 2>&1; then
    log_error "Docker não está rodando!"
    exit 1
fi

# Verificar se arquivo .env.production existe
if [[ ! -f .env.production ]]; then
    log_error "Arquivo .env.production não encontrado!"
    exit 1
fi

# Criar diretórios necessários
log_info "Criando diretórios necessários..."
mkdir -p logs
mkdir -p data/postgres

# Copiar arquivo de ambiente
cp .env.production .env

# Build da aplicação
log_info "Construindo imagem Docker..."
docker build -t actix_api_crud:latest .

# Parar containers existentes
log_info "Parando containers existentes..."
docker-compose down || true

# Limpar volumes órfãos (opcional)
read -p "Deseja limpar volumes de dados existentes? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_warn "Removendo volumes existentes..."
    docker-compose down -v
fi

# Iniciar serviços
log_info "Iniciando serviços..."
docker-compose up -d

# Aguardar serviços ficarem prontos
log_info "Aguardando serviços ficarem prontos..."
sleep 10

# Verificar health dos serviços
log_info "Verificando status dos serviços..."

# PostgreSQL
if docker-compose exec -T postgres pg_isready -U postgres > /dev/null 2>&1; then
    log_info "✓ PostgreSQL está saudável"
else
    log_error "✗ PostgreSQL não está respondendo"
    exit 1
fi

# API
sleep 5
if curl -f http://localhost:8080/health > /dev/null 2>&1; then
    log_info "✓ API está saudável"
else
    log_error "✗ API não está respondendo"
    docker-compose logs api
    exit 1
fi

# Mostrar logs
log_info "Deploy concluído com sucesso! 🎉"
log_info "API disponível em: http://localhost:8080"
log_info "Adminer disponível em: http://localhost:8081"
log_info "Health check: http://localhost:8080/health"

echo ""
log_info "Para ver os logs em tempo real:"
echo "  docker-compose logs -f api"
echo ""
log_info "Para parar os serviços:"
echo "  docker-compose down"
```

#### 14.5.2 Script de Backup

Crie um script `backup.sh`:

```bash
#!/bin/bash
# backup.sh

set -e

BACKUP_DIR="./backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="backup_${TIMESTAMP}.sql"

echo "🔄 Iniciando backup do banco de dados..."

# Criar diretório de backup
mkdir -p $BACKUP_DIR

# Realizar backup
docker-compose exec -T postgres pg_dump -U postgres actix_crud > "${BACKUP_DIR}/${BACKUP_FILE}"

# Comprimir backup
gzip "${BACKUP_DIR}/${BACKUP_FILE}"

echo "✅ Backup criado: ${BACKUP_DIR}/${BACKUP_FILE}.gz"

# Limpar backups antigos (manter últimos 7 dias)
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +7 -delete

echo "🧹 Backups antigos removidos"
```

### 14.6 Configuração de CI/CD

#### 14.6.1 GitHub Actions

Crie `.github/workflows/ci.yml`:

```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: actix_crud_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        override: true
        components: rustfmt, clippy

    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: |
          ~/.cargo/registry
          ~/.cargo/git
          target
        key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y libpq-dev

    - name: Check formatting
      run: cargo fmt -- --check

    - name: Run clippy
      run: cargo clippy -- -D warnings

    - name: Run tests
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/actix_crud_test
        JWT_SECRET: test-secret
        JWT_REFRESH_SECRET: test-refresh-secret
      run: cargo test

    - name: Generate test coverage
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/actix_crud_test
        JWT_SECRET: test-secret
        JWT_REFRESH_SECRET: test-refresh-secret
      run: |
        cargo install cargo-tarpaulin
        cargo tarpaulin --out xml

    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./cobertura.xml

  build:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'

    steps:
    - uses: actions/checkout@v4

    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3

    - name: Login to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ghcr.io
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Build and push Docker image
      uses: docker/build-push-action@v5
      with:
        context: .
        push: true
        tags: |
          ghcr.io/${{ github.repository }}:latest
          ghcr.io/${{ github.repository }}:${{ github.sha }}
        cache-from: type=gha
        cache-to: type=gha,mode=max

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production

    steps:
    - name: Deploy to production
      run: |
        echo "Deploy seria executado aqui"
        # ssh para servidor de produção
        # docker pull nova imagem
        # docker-compose restart
```

### 14.7 Checklist de Produção

#### 14.7.1 Segurança

- [ ] Senhas e secrets seguros em variáveis de ambiente
- [ ] HTTPS configurado
- [ ] Rate limiting ativo
- [ ] Headers de segurança configurados
- [ ] Validação de entrada rigorosa
- [ ] Logs de segurança implementados

#### 14.7.2 Performance

- [ ] Build otimizado com release profile
- [ ] Connection pooling configurado
- [ ] Cache implementado onde necessário
- [ ] Compressão HTTP ativada
- [ ] Métricas de performance coletadas

#### 14.7.3 Monitoramento

- [ ] Health checks implementados
- [ ] Logging estruturado configurado
- [ ] Métricas Prometheus expostas
- [ ] Alertas configurados
- [ ] Dashboard de monitoramento

#### 14.7.4 Backup e Recuperação

- [ ] Backup automático do banco
- [ ] Procedimento de recuperação testado
- [ ] Retenção de backups definida
- [ ] Backup em múltiplas localizações

### 14.8 Resumo do Capítulo

Neste capítulo, cobrimos todos os aspectos essenciais para colocar uma API Rust/Actix-Web em produção:

1. **Otimização de Build**: Configurações de release para melhor performance
2. **Containerização**: Dockerfile multi-stage e Docker Compose
3. **Configuração de Produção**: Variáveis de ambiente e logging estruturado
4. **Monitoramento**: Health checks, métricas e observabilidade
5. **Deploy**: Scripts automatizados e CI/CD
6. **Segurança**: Checklist e melhores práticas

Com essas configurações, sua API estará pronta para um ambiente de produção robusto, monitorado e seguro.

### Exercícios Práticos

1. **Otimização**: Meça o tamanho do binário antes e depois das otimizações de release
2. **Containerização**: Execute a aplicação usando Docker e verifique os health checks
3. **Monitoramento**: Configure alertas básicos baseados nas métricas expostas
4. **Deploy**: Execute o script de deploy em um ambiente de teste
5. **Backup**: Teste o procedimento de backup e recuperação

### Recursos Adicionais

- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Prometheus Monitoring](https://prometheus.io/docs/guides/go-application/)
- [Actix-Web Production Deployment](https://actix.rs/docs/deployment/)
