use actix_web::{App, HttpServer, Responder, HttpResponse, get, middleware::Logger};
use dotenvy::dotenv;
use std::env;
use log::info;

// Declaração dos módulos
mod handlers;
mod models;
mod services;
mod repositories;
mod middlewares;
mod auth;
mod config;
mod errors;
mod routes;

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Actix API CRUD is running! 🚀",
        "version": "0.1.0",
        "status": "healthy"
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Carrega variáveis de ambiente do arquivo .env
    dotenv().ok();
    
    // Configura o sistema de logs
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    // Lê configurações do ambiente
    let port = env::var("APP_PORT").unwrap_or_else(|_| "8080".to_string());
    let host = "0.0.0.0";
    let addr = format!("{}:{}", host, port);
    
    info!("🚀 Starting Actix API CRUD Server");
    info!("📍 Server running at: http://{}", addr);
    info!("🔧 Environment: {}", env::var("RUST_ENV").unwrap_or_else(|_| "development".to_string()));
    info!("💾 Database URL configured: {}", if env::var("DATABASE_URL").is_ok() { "✅" } else { "❌" });
    info!("🔐 JWT Secret configured: {}", if env::var("JWT_SECRET").is_ok() { "✅" } else { "❌" });

    HttpServer::new(|| {
        App::new()
            // Middleware de logging
            .wrap(Logger::default())
            // Rota de health check na raiz
            .service(index)
            // Configura as rotas da API
            .configure(routes::init_routes)
    })
    .bind(&addr)?
    .run()
    .await
}
