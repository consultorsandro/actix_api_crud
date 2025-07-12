// Config - Configurações da aplicação
// Aqui ficarão as configurações de banco, servidor, variáveis de ambiente

pub mod app_config;
pub mod database;
pub mod security;

pub use security::SecurityConfig;
