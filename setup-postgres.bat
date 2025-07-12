@echo off
REM Script para configurar PostgreSQL com Docker no Windows - Etapa 3
REM Execução: setup-postgres.bat

echo 🐘 Setting up PostgreSQL with Docker for Actix API CRUD

REM Verificar se Docker está instalado
docker --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not installed. Please install Docker Desktop first.
    echo 📥 Download from: https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

REM Parar container existente se estiver rodando
echo 🛑 Stopping existing PostgreSQL container if running...
docker stop postgres-actix >nul 2>&1
docker rm postgres-actix >nul 2>&1

REM Criar e executar container PostgreSQL
echo 🚀 Starting PostgreSQL container...
docker run -d ^
  --name postgres-actix ^
  -e POSTGRES_USER=postgres ^
  -e POSTGRES_PASSWORD=postgres ^
  -e POSTGRES_DB=actix_crud_db ^
  -p 5432:5432 ^
  postgres:15

REM Aguardar PostgreSQL inicializar
echo ⏳ Waiting for PostgreSQL to start...
timeout /t 10 /nobreak >nul

REM Verificar se container está rodando
docker ps | findstr postgres-actix >nul
if errorlevel 1 (
    echo ❌ Failed to start PostgreSQL container
    echo 🔍 Check Docker logs with: docker logs postgres-actix
    pause
    exit /b 1
) else (
    echo ✅ PostgreSQL is running successfully!
    echo.
    echo 📊 Database Details:
    echo    Host: localhost
    echo    Port: 5432
    echo    Database: actix_crud_db
    echo    Username: postgres
    echo    Password: postgres
    echo.
    echo 🔗 Connection URL: postgresql://postgres:postgres@localhost:5432/actix_crud_db
    echo.
    echo 🧪 You can test the connection with:
    echo    docker exec -it postgres-actix psql -U postgres -d actix_crud_db
    echo.
    echo 📝 To stop the database:
    echo    docker stop postgres-actix
    echo.
    echo 🗑️  To remove the database completely:
    echo    docker stop postgres-actix && docker rm postgres-actix
    echo.
)

pause
