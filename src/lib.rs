// lib.rs - Biblioteca Actix API CRUD
// Etapa 7: Testes e Qualidade - Exposição dos módulos para testes

// Módulos públicos para testes
pub mod auth;
pub mod config;
pub mod errors;
pub mod handlers;
pub mod middlewares;
pub mod models;
pub mod repositories;
pub mod routes;
pub mod services;

// Re-exports úteis para testes
pub use errors::AppError;
pub use models::pagination::{PaginatedResponse, PaginationParams, SortOrder};
pub use models::user::{CreateUserDto, LoginDto, UpdateUserDto, User, UserResponse};
