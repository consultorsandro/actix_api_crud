// Routes - Configuração de rotas da aplicação
// Aqui ficarão as configurações de roteamento da API

use actix_web::web;
use crate::handlers::user_handler;

// Configuração das rotas de usuários
pub fn configure_user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("/health", web::get().to(user_handler::health_check))
            // As rotas específicas de CRUD serão configuradas quando 
            // implementarmos a injeção de dependência
    );
}

// Configuração das rotas de autenticação
pub fn configure_auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            // As rotas de auth serão implementadas quando tivermos JWT
    );
}

// Configuração principal de todas as rotas
pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .configure(configure_user_routes)
            .configure(configure_auth_routes)
    );
}
