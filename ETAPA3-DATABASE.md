# Etapa 3: Integração com Banco de Dados PostgreSQL

## 🚀 Executar o Setup do PostgreSQL

### Opção 1: Docker (Recomendado)

**Windows:**
```bash
setup-postgres.bat
```

**Linux/macOS:**
```bash
chmod +x setup-postgres.sh
./setup-postgres.sh
```

**Manual Docker:**
```bash
docker run -d \
  --name postgres-actix \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=actix_crud_db \
  -p 5432:5432 \
  postgres:15
```

### Opção 2: PostgreSQL Local

Se você tem PostgreSQL instalado localmente:

1. Criar banco de dados:
```sql
CREATE DATABASE actix_crud_db;
```

2. Atualizar `DATABASE_URL` no arquivo `.env` se necessário

## 🧪 Testar a Aplicação

1. **Verificar que PostgreSQL está rodando:**
```bash
docker ps | grep postgres-actix
```

2. **Compilar e executar:**
```bash
cargo run
```

3. **Testar endpoints:**

**Health Check:**
```bash
curl http://localhost:8080/
```

**Criar usuário:**
```bash
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "name": "João Silva",
    "email": "joao@example.com",
    "password": "123456"
  }'
```

**Listar usuários:**
```bash
curl http://localhost:8080/api/users
```

**Buscar usuário por ID:**
```bash
curl http://localhost:8080/api/users/{uuid}
```

## 📊 Verificar Banco de Dados

**Conectar ao PostgreSQL:**
```bash
docker exec -it postgres-actix psql -U postgres -d actix_crud_db
```

**Listar tabelas:**
```sql
\dt
```

**Ver usuários cadastrados:**
```sql
SELECT id, name, email, created_at FROM users;
```

## 🔧 Solução de Problemas

### Erro: "Database is not available"

1. Verificar se Docker está rodando:
```bash
docker ps
```

2. Verificar logs do container:
```bash
docker logs postgres-actix
```

3. Reiniciar container:
```bash
docker restart postgres-actix
```

### Erro: "Failed to run migrations"

1. Verificar se arquivo de migration existe:
```bash
ls migrations/
```

2. Executar migration manualmente:
```bash
cargo install sqlx-cli
sqlx migrate run
```

## 📁 Estrutura Implementada

```
src/
├── config/
│   └── database.rs      # ✅ Configuração completa do banco
├── models/
│   └── user.rs          # ✅ Modelo de dados
├── repositories/
│   ├── mod.rs           # ✅ Traits genéricos
│   └── user_repository.rs # ✅ Implementação com SQLx
├── services/
│   ├── mod.rs           # ✅ Traits de serviços
│   └── user_service.rs  # ✅ Lógica de negócio
├── handlers/
│   └── user_handler.rs  # ✅ Controllers HTTP
└── main.rs              # ✅ Integração completa

migrations/
├── 001_initial_users.up.sql    # ✅ Schema do banco
└── 001_initial_users.down.sql  # ✅ Rollback
```

## 🎯 Próximos Passos

- **Etapa 4:** Implementação completa do CRUD
- **Etapa 5:** Autenticação JWT
- **Etapa 6:** Middleware de autorização
- **Etapa 7:** Testes automatizados
- **Etapa 8:** Documentação e deploy

## 🔗 URLs Úteis

- **API Base:** http://localhost:8080
- **Health Check:** http://localhost:8080/
- **Users API:** http://localhost:8080/api/users
- **Database:** postgresql://postgres:postgres@localhost:5432/actix_crud_db
