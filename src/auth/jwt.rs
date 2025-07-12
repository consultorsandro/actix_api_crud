// src/auth/jwt.rs
// Etapa 5: Sistema JWT para autenticação e autorização

use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use actix_web_httpauth::extractors::bearer::{BearerAuth, Config};
use actix_web_httpauth::extractors::AuthenticationError;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;

use crate::errors::AppError;

/// Claims do JWT token
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,        // Subject (user ID)
    pub email: String,      // Email do usuário
    pub name: String,       // Nome do usuário
    pub exp: i64,          // Expiration time
    pub iat: i64,          // Issued at
    pub role: String,      // Role do usuário (admin, user, etc.)
}

/// Configuração JWT
#[allow(dead_code)] // Temporarily unused while auth is commented
pub struct JwtConfig {
    pub secret: String,
    pub expiration_hours: i64,
    pub algorithm: Algorithm,
}

impl JwtConfig {
    /// Cria configuração JWT a partir de variáveis de ambiente
    pub fn from_env() -> Result<Self, AppError> {
        let secret = env::var("JWT_SECRET")
            .map_err(|_| AppError::Configuration("JWT_SECRET not found".to_string()))?;
        
        let expiration_hours = env::var("JWT_EXPIRATION")
            .unwrap_or("24".to_string())
            .parse::<i64>()
            .map_err(|_| AppError::Configuration("Invalid JWT_EXPIRATION".to_string()))?;

        Ok(Self {
            secret,
            expiration_hours,
            algorithm: Algorithm::HS256,
        })
    }

    /// Gera um token JWT
    pub fn generate_token(&self, user_id: Uuid, email: &str, name: &str, role: &str) -> Result<String, AppError> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.expiration_hours);

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            name: name.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            role: role.to_string(),
        };

        let header = Header::new(self.algorithm);
        let encoding_key = EncodingKey::from_secret(self.secret.as_ref());

        encode(&header, &claims, &encoding_key)
            .map_err(|e| AppError::Authentication(format!("Failed to generate token: {}", e)))
    }

    /// Valida e decodifica um token JWT
    pub fn decode_token(&self, token: &str) -> Result<Claims, AppError> {
        let decoding_key = DecodingKey::from_secret(self.secret.as_ref());
        let validation = Validation::new(self.algorithm);

        decode::<Claims>(token, &decoding_key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|e| AppError::Authentication(format!("Invalid token: {}", e)))
    }

    /// Verifica se o token não expirou
    pub fn is_token_valid(&self, claims: &Claims) -> bool {
        let now = Utc::now().timestamp();
        claims.exp > now
    }
}

/// Middleware de validação JWT para Actix-Web
#[allow(dead_code)] // Temporarily unused while auth is commented
pub async fn jwt_middleware(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let config = match JwtConfig::from_env() {
        Ok(config) => config,
        Err(e) => {
            log::error!("Failed to load JWT config: {}", e);
            let config = Config::default()
                .realm("Restricted area")
                .scope("read write");
            return Err((AuthenticationError::from(config).into(), req));
        }
    };

    let token = credentials.token();
    
    match config.decode_token(token) {
        Ok(claims) => {
            if config.is_token_valid(&claims) {
                // Adicionar claims às extensões da request
                req.extensions_mut().insert(claims);
                Ok(req)
            } else {
                log::warn!("Token expired for user: {}", claims.email);
                let config = Config::default()
                    .realm("Restricted area")
                    .scope("read write");
                Err((AuthenticationError::from(config).into(), req))
            }
        }
        Err(e) => {
            log::warn!("Invalid token: {}", e);
            let config = Config::default()
                .realm("Restricted area")
                .scope("read write");
            Err((AuthenticationError::from(config).into(), req))
        }
    }
}

/// Extrator de claims do JWT para uso nos handlers
#[allow(dead_code)] // Temporarily unused while auth is commented
pub struct JwtUser(pub Claims);

impl From<Claims> for JwtUser {
    fn from(claims: Claims) -> Self {
        JwtUser(claims)
    }
}

/// Helper para extrair usuário autenticado da request
#[allow(dead_code)] // Temporarily unused while auth is commented
pub fn get_current_user(req: &actix_web::HttpRequest) -> Result<Claims, AppError> {
    req.extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| AppError::Authentication("User not authenticated".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_jwt_generation_and_validation() {
        unsafe {
            env::set_var("JWT_SECRET", "test-secret-key");
            env::set_var("JWT_EXPIRATION", "1");
        }

        let config = JwtConfig::from_env().unwrap();
        let user_id = Uuid::new_v4();
        
        let token = config.generate_token(
            user_id,
            "test@example.com",
            "Test User",
            "user"
        ).unwrap();

        let claims = config.decode_token(&token).unwrap();
        
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.name, "Test User");
        assert_eq!(claims.role, "user");
        assert!(config.is_token_valid(&claims));
    }
}
