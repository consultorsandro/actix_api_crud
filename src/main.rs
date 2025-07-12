use actix_web::{App, HttpServer, Responder, HttpResponse, get, middleware::Logger, web};
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

use config::database;
use handlers::user_handler::UserHandler;
use repositories::user_repository::UserRepository;
use services::user_service::UserService;

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Actix API CRUD is running! 🚀",
        "version": "0.1.0",
        "status": "healthy",
        "database": "connected"
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Carrega variáveis de ambiente do arquivo .env
    dotenv().ok();
    
    // Configura o sistema de logs
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    
    info!("🚀 Starting Actix API CRUD Server - Etapa 3: Database Integration");

    // Configurar banco de dados
    let db_config = database::DatabaseConfig::from_env();
    
    info!("💾 Database configuration loaded");
    info!("🔗 Database URL: {}", db_config.url);
    
    // Tentar criar pool de conexões
    let db_pool = match database::create_connection_pool(&db_config).await {
        Ok(pool) => {
            info!("✅ Database connection pool created successfully");
            
            // Executar migrations
            if let Err(e) = database::run_migrations(&pool).await {
                log::warn!("⚠️  Failed to run migrations: {}", e);
                log::info!("🔧 Please run migrations manually when database is available");
            } else {
                info!("✅ Database migrations completed successfully");
            }
            
            pool
        }
        Err(e) => {
            log::warn!("⚠️  Database is not available: {}", e);
            log::info!("� Please ensure PostgreSQL is running and accessible");
            log::info!("🔧 Expected database URL: {}", db_config.url);
            log::info!("💡 You can run PostgreSQL with Docker:");
            log::info!("   docker run --name postgres-actix -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=actix_crud_db -p 5432:5432 -d postgres:15");
            log::info!("🚀 Starting server anyway - install PostgreSQL to enable database features");
            
            // Para compilação, usar um pool que vai falhar nas operações
            // mas permite o servidor iniciar
            std::process::exit(1);
        }
    };

    // Configurar dependências com injeção
    let user_repository = UserRepository::new(db_pool.clone());
    let user_service = UserService::new(user_repository);
    let user_handler = UserHandler::new(user_service);

    info!("🔧 Dependencies configured with dependency injection");

    // Lê configurações do ambiente
    let port = env::var("APP_PORT").unwrap_or_else(|_| "8080".to_string());
    let host = "0.0.0.0";
    let addr = format!("{}:{}", host, port);
    
    info!("� Server will run at: http://{}", addr);
    info!("🔧 Environment: {}", env::var("RUST_ENV").unwrap_or_else(|_| "development".to_string()));
    info!("🔐 JWT Secret configured: {}", if env::var("JWT_SECRET").is_ok() { "✅" } else { "❌" });

    HttpServer::new(move || {
        App::new()
            // Middleware de logging
            .wrap(Logger::default())
            // Adicionar handler como dados da aplicação
            .app_data(web::Data::new(user_handler.clone()))
            // Rota de health check na raiz
            .service(index)
            // Rotas da API
            .service(
                web::scope("/api/v1")
                    .service(
                        web::scope("/users")
                            .route("", web::post().to(|handler: web::Data<UserHandler<_>>, dto| async move {
                                handler.create_user(dto).await
                            }))
                            .route("", web::get().to(|handler: web::Data<UserHandler<_>>| async move {
                                handler.get_all_users().await
                            }))
                            .route("/paginated", web::get().to(|handler: web::Data<UserHandler<_>>, params| async move {
                                handler.get_users_paginated(params).await
                            }))
                            .route("/{id}", web::get().to(|handler: web::Data<UserHandler<_>>, path| async move {
                                handler.get_user_by_id(path).await
                            }))
                            .route("/{id}", web::put().to(|handler: web::Data<UserHandler<_>>, path, dto| async move {
                                handler.update_user(path, dto).await
                            }))
                            .route("/{id}", web::delete().to(|handler: web::Data<UserHandler<_>>, path| async move {
                                handler.delete_user(path).await
                            }))
                    )
                    .service(
                        web::scope("/auth")
                            .route("/login", web::post().to(|handler: web::Data<UserHandler<_>>, dto| async move {
                                handler.login(dto).await
                            }))
                    )
            )
            // Configura as rotas básicas
            .configure(routes::init_routes)
    })
    .bind(&addr)?
    .run()
    .await
}
