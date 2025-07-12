# Actix API CRUD

Uma API REST robusta para gerenciar Usuários construída com Rust e Actix-Web.

## 🚀 Tecnologias

- **Rust** - Linguagem de programação de sistemas
- **Actix-Web** - Framework web de alta performance
- **SQLx** - Driver SQL assíncrono e type-safe
- **PostgreSQL** - Banco de dados relacional
- **JWT** - Autenticação baseada em tokens
- **Serde** - Serialização/deserialização JSON
- **BCrypt** - Hash de senhas seguro

## 📁 Estrutura do Projeto

```
src/
├── main.rs              # Ponto de entrada da aplicação
├── handlers/            # Controllers (endpoints HTTP)
├── models/              # Modelos de dados e entidades
├── services/            # Lógica de negócio
├── repositories/        # Camada de acesso a dados
├── middlewares/         # Middlewares customizados
├── auth/                # Sistema de autenticação
├── config/              # Configurações da aplicação
├── errors/              # Tratamento de erros estruturado
└── routes/              # Configuração de rotas
migrations/              # Scripts de migração do banco
```

## ⚙️ Configuração

### Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto:

```env
DATABASE_URL=postgres://user:password@localhost:5432/actix_api_db
JWT_SECRET=my-super-secret-key
APP_PORT=8080
RUST_ENV=development
RUST_LOG=info
```

## 🔄 Status do Projeto

### ✅ Etapa 1 - Setup do Projeto (Concluída)
- [x] Estrutura de diretórios criada
- [x] Dependências configuradas no Cargo.toml
- [x] Variáveis de ambiente configuradas
- [x] Sistema de logs implementado
- [x] Servidor básico funcionando
- [x] Tratamento de erros estruturado

### 🔄 Próximas Etapas
- [ ] Etapa 2 - Arquitetura e módulos
- [ ] Etapa 3 - Integração com PostgreSQL
- [ ] Etapa 4 - CRUD de usuários
- [ ] Etapa 5 - Autenticação JWT
- [ ] Etapa 6 - Middleware e segurança
- [ ] Etapa 7 - Testes
- [ ] Etapa 8 - Documentação final

## 🚀 Como Executar

### Pré-requisitos
- Rust 1.70+ instalado
- PostgreSQL rodando localmente

### Comandos

```bash
# Verificar se compila
cargo check

# Executar em modo desenvolvimento
cargo run

# Build para produção
cargo build --release
```

## 📝 Logs

O servidor mostra informações úteis na inicialização:
- 🚀 Status do servidor
- 📍 Endereço de execução
- 🔧 Ambiente (development/production)
- 💾 Status da configuração do banco
- 🔐 Status da configuração JWT

## 🎯 Objetivos

Este projeto implementa os princípios SOLID e boas práticas de desenvolvimento em Rust, focando em:

- **Performance** - Servidor assíncrono de alta performance
- **Segurança** - Autenticação JWT e hash seguro de senhas
- **Manutenibilidade** - Arquitetura modular e bem estruturada
- **Type Safety** - Aproveitando o sistema de tipos do Rust
- **Testing** - Cobertura de testes unitários e de integração

---

*Projeto em desenvolvimento - Etapa 1 concluída* ✅
