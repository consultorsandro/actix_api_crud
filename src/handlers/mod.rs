// Handlers (Controllers) - Responsáveis por processar requisições HTTP
// Etapa 5: Adicionado AuthHandler para autenticação JWT

pub mod auth_handler;
pub mod user_handler;

// Re-exportar structs principais
pub use user_handler::UserHandler;
// pub use auth_handler::AuthHandler; // Comentado temporariamente até resolver import issues
