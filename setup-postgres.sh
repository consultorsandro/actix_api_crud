#!/bin/bash

# Script para configurar PostgreSQL com Docker - Etapa 3
# Execução: chmod +x setup-postgres.sh && ./setup-postgres.sh

echo "🐘 Setting up PostgreSQL with Docker for Actix API CRUD"

# Verificar se Docker está instalado
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Parar container existente se estiver rodando
echo "🛑 Stopping existing PostgreSQL container if running..."
docker stop postgres-actix 2>/dev/null || echo "No existing container found"
docker rm postgres-actix 2>/dev/null || echo "No existing container to remove"

# Criar e executar container PostgreSQL
echo "🚀 Starting PostgreSQL container..."
docker run -d \
  --name postgres-actix \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=actix_crud_db \
  -p 5432:5432 \
  postgres:15

# Aguardar PostgreSQL inicializar
echo "⏳ Waiting for PostgreSQL to start..."
sleep 10

# Verificar se container está rodando
if docker ps | grep -q postgres-actix; then
    echo "✅ PostgreSQL is running successfully!"
    echo "📊 Database Details:"
    echo "   Host: localhost"
    echo "   Port: 5432"
    echo "   Database: actix_crud_db"
    echo "   Username: postgres"
    echo "   Password: postgres"
    echo ""
    echo "🔗 Connection URL: postgresql://postgres:postgres@localhost:5432/actix_crud_db"
    echo ""
    echo "🧪 You can test the connection with:"
    echo "   psql -h localhost -U postgres -d actix_crud_db"
    echo ""
    echo "📝 To stop the database:"
    echo "   docker stop postgres-actix"
    echo ""
    echo "🗑️  To remove the database completely:"
    echo "   docker stop postgres-actix && docker rm postgres-actix"
else
    echo "❌ Failed to start PostgreSQL container"
    echo "🔍 Check Docker logs with: docker logs postgres-actix"
    exit 1
fi
