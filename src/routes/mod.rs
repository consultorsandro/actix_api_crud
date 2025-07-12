// Routes - Configuração de rotas da aplicação
// Etapa 4: Rotas simplificadas para compilação

use actix_web::web;

// Configuração básica das rotas
pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .service(
                web::scope("/users")
                    .route("/health", web::get().to(crate::handlers::user_handler::health_check))
                    // As rotas específicas serão configuradas dinamicamente no main.rs
            )
            .service(
                web::scope("/auth")
                    // As rotas de autenticação serão configuradas dinamicamente
            )
    );
}
