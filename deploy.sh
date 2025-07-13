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
