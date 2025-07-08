use actix_web::{App, HttpServer, Responder, HttpResponse, get};
use dotenvy::dotenv;
use std::env;
use env_logger::Env;
use log::info;

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("API is running 🚀")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok(); // Load .env file
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let port = env::var("APP_PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);

    info!("🚀 Starting server at: http://{}", addr);

    HttpServer::new(|| {
        App::new()
            .service(index)
    })
    .bind(&addr)?
    .run()
    .await
}
