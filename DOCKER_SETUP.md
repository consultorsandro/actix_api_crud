# Etapa 4 Aperfeiçoamento - Guia de Setup Docker

## 🐳 Configuração do Ambiente Docker

### 1. Pré-requisitos
- Docker Desktop instalado e funcionando
- Git (para clonar e versionar o projeto)

### 2. Iniciar o Ambiente
```bash
# Subir os serviços (PostgreSQL + Adminer)
docker-compose up -d

# Verificar se os serviços estão rodando
docker-compose ps

# Ver logs dos serviços
docker-compose logs -f
```

### 3. Acessos
- **PostgreSQL**: `localhost:5432`
  - Database: `actix_crud_db`
  - Username: `postgres`
  - Password: `postgres`

- **Adminer** (Interface Web): http://localhost:8081
  - Sistema: PostgreSQL
  - Servidor: postgres
  - Usuário: postgres
  - Senha: postgres
  - Base de dados: actix_crud_db

### 4. Comandos Úteis

```bash
# Parar todos os serviços
docker-compose down

# Parar e remover volumes (CUIDADO: apaga dados!)
docker-compose down -v

# Reconstruir containers
docker-compose up --build -d

# Executar comando no PostgreSQL
docker-compose exec postgres psql -U postgres -d actix_crud_db

# Backup do banco
docker-compose exec postgres pg_dump -U postgres actix_crud_db > backup.sql

# Restore do banco
docker-compose exec -T postgres psql -U postgres actix_crud_db < backup.sql
```

### 5. Desenvolvimento Local

Para conectar sua aplicação Rust ao PostgreSQL:

```rust
// No seu .env ou variável de ambiente
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/actix_crud_db
```

### 6. Próximos Passos
1. ✅ Docker configurado
2. 🔄 Testar conexão da aplicação Rust
3. 🔄 Implementar migrações com SQLx
4. 🔄 Adicionar testes de integração
5. 🔄 Configurar CI/CD

## 🚀 Vantagens desta Configuração

- **Isolamento**: Banco separado do sistema
- **Consistency**: Mesma versão para toda equipe
- **Backup**: Volumes persistentes
- **Interface**: Adminer para visualização
- **Performance**: PostgreSQL otimizado
- **Escalabilidade**: Fácil adicionar Redis, etc.
