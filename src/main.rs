use actix_web::{App, HttpResponse, HttpServer, Responder, get, middleware::Logger, web};
use dotenvy::dotenv;
use log::info;
use std::env;

// Declaração dos módulos
mod auth;
mod config;
mod errors;
mod handlers;
mod middlewares;
mod models;
mod repositories;
mod routes;
mod services;

use config::database;
use handlers::UserHandler;
// use handlers::AuthHandler; // Comentado temporariamente
use repositories::user_repository::UserRepository;
use services::user_service::UserService;
use models::user::{CreateUserDto, UpdateUserDto};
use models::pagination::PaginationParams;
// use auth::models::{LoginRequest, RegisterRequest, ChangePasswordRequest}; // Comentado temporariamente
use middlewares::ValidatedJson;

// Handler wrapper functions para evitar problemas de tipo
async fn create_user_wrapper(
    handler: web::Data<UserHandler<UserService<UserRepository>>>,
    dto: ValidatedJson<CreateUserDto>,
) -> impl Responder {
    handler.create_user(dto).await
}

async fn get_all_users_wrapper(
    handler: web::Data<UserHandler<UserService<UserRepository>>>,
) -> impl Responder {
    handler.get_all_users().await
}

async fn get_users_paginated_wrapper(
    handler: web::Data<UserHandler<UserService<UserRepository>>>,
    params: web::Query<PaginationParams>,
) -> impl Responder {
    handler.get_users_paginated(params).await
}

async fn get_user_by_id_wrapper(
    handler: web::Data<UserHandler<UserService<UserRepository>>>,
    path: web::Path<uuid::Uuid>,
) -> impl Responder {
    handler.get_user_by_id(path).await
}

async fn update_user_wrapper(
    handler: web::Data<UserHandler<UserService<UserRepository>>>,
    path: web::Path<uuid::Uuid>,
    dto: ValidatedJson<UpdateUserDto>,
) -> impl Responder {
    handler.update_user(path, dto).await
}

async fn delete_user_wrapper(
    handler: web::Data<UserHandler<UserService<UserRepository>>>,
    path: web::Path<uuid::Uuid>,
) -> impl Responder {
    handler.delete_user(path).await
}

/* Auth handler wrapper functions - Ready for integration after trait resolution
async fn login_wrapper(
    handler: web::Data<AuthHandler<UserService<UserRepository>>>,
    dto: web::Json<LoginRequest>,
) -> impl Responder {
    handler.login(dto).await
}

async fn register_wrapper(
    handler: web::Data<AuthHandler<UserService<UserRepository>>>,
    dto: web::Json<RegisterRequest>,
) -> impl Responder {
    handler.register(dto).await
}

async fn me_wrapper(
    handler: web::Data<AuthHandler<UserService<UserRepository>>>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    handler.me(req).await
}

async fn change_password_wrapper(
    handler: web::Data<AuthHandler<UserService<UserRepository>>>,
    req: actix_web::HttpRequest,
    dto: web::Json<ChangePasswordRequest>,
) -> impl Responder {
    handler.change_password(req, dto).await
}

async fn logout_wrapper(
    handler: web::Data<AuthHandler<UserService<UserRepository>>>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    handler.logout(req).await
}
*/

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
            log::info!(
                "   docker run --name postgres-actix -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=actix_crud_db -p 5432:5432 -d postgres:15"
            );
            log::info!(
                "🚀 Starting server anyway - install PostgreSQL to enable database features"
            );

            // Para compilação, usar um pool que vai falhar nas operações
            // mas permite o servidor iniciar
            std::process::exit(1);
        }
    };

    // Configurar dependências com injeção
    let user_repository = UserRepository::new(db_pool.clone());
    let user_service = UserService::new(user_repository.clone());
    let user_handler = UserHandler::new(user_service.clone());
    // let auth_handler = AuthHandler::new(user_service.clone()); // Comentado temporariamente

    info!("🔧 Dependencies configured with dependency injection");
    info!("🔐 Auth system ready for integration (temporarily commented)");

    // Lê configurações do ambiente
    let port = env::var("APP_PORT").unwrap_or_else(|_| "8080".to_string());
    let host = "0.0.0.0";
    let addr = format!("{}:{}", host, port);

    info!("� Server will run at: http://{}", addr);
    info!(
        "🔧 Environment: {}",
        env::var("RUST_ENV").unwrap_or_else(|_| "development".to_string())
    );
    info!(
        "🔐 JWT Secret configured: {}",
        if env::var("JWT_SECRET").is_ok() {
            "✅"
        } else {
            "❌"
        }
    );

    HttpServer::new(move || {
        App::new()
            // Middleware de logging
            .wrap(Logger::default())
            // Adicionar handlers como dados da aplicação
            .app_data(web::Data::new(user_handler.clone()))
            // .app_data(web::Data::new(auth_handler.clone())) // Comentado temporariamente
            // Rota de health check na raiz
            .service(index)
            // Rotas da API
            .service(
                web::scope("/api/v1")
                    .service(
                        web::scope("/users")
                            .route("", web::post().to(create_user_wrapper))
                            .route("", web::get().to(get_all_users_wrapper))
                            .route("/paginated", web::get().to(get_users_paginated_wrapper))
                            .route("/{id}", web::get().to(get_user_by_id_wrapper))
                            .route("/{id}", web::put().to(update_user_wrapper))
                            .route("/{id}", web::delete().to(delete_user_wrapper)),
                    )
                    // Auth routes commented temporarily - ready for integration
                    // .service(
                    //     web::scope("/auth")
                    //         .route("/login", web::post().to(login_wrapper))
                    //         .route("/register", web::post().to(register_wrapper))
                    //         .route("/me", web::get().to(me_wrapper))
                    //         .route("/change-password", web::put().to(change_password_wrapper))
                    //         .route("/logout", web::post().to(logout_wrapper))
                    // )
            )
            // Configura as rotas básicas
            .configure(routes::init_routes)
    })
    .bind(&addr)?
    .run()
    .await
}
