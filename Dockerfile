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
    curl \
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
