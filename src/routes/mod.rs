// Routes - Configuração de rotas da aplicação
// Aqui ficarão as configurações de roteamento da API

use actix_web::web;

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            // As rotas específicas serão adicionadas nas próximas etapas
    );
}
