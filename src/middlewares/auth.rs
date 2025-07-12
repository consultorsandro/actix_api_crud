use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    error::ErrorUnauthorized,
    http::header::AUTHORIZATION,
    Error, HttpMessage,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use futures_util::future::LocalBoxFuture;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::env;

/// Claims JWT para autenticação
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,    // Subject (user id)
    pub email: String,  // User email
    pub role: Option<String>, // User role
    pub exp: usize,     // Expiration time
}

/// Middleware de autenticação JWT
pub struct JwtAuthMiddleware;

impl JwtAuthMiddleware {
    /// Valida token JWT e extrai claims
    pub fn validate_token(token: &str) -> Result<Claims, Error> {
        let secret = env::var("JWT_SECRET")
            .map_err(|_| ErrorUnauthorized("JWT secret not configured"))?;
        
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_ref()),
            &validation,
        )
        .map_err(|_| ErrorUnauthorized("Invalid JWT token"))?;
        
        Ok(token_data.claims)
    }
    
    /// Extrai e valida token do header Authorization
    pub fn extract_and_validate_token(req: &ServiceRequest) -> Result<Claims, Error> {
        // Tentar extrair token do header Authorization
        let auth_header = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|header| header.to_str().ok())
            .ok_or_else(|| ErrorUnauthorized("Missing Authorization header"))?;
        
        // Verificar se é Bearer token
        if !auth_header.starts_with("Bearer ") {
            return Err(ErrorUnauthorized("Invalid Authorization header format"));
        }
        
        let token = auth_header.trim_start_matches("Bearer ");
        Self::validate_token(token)
    }
}

/// Validator function para actix-web-httpauth
pub async fn jwt_validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    match JwtAuthMiddleware::validate_token(credentials.token()) {
        Ok(claims) => {
            // Adicionar claims às extensões da request
            req.extensions_mut().insert(claims);
            Ok(req)
        }
        Err(e) => Err((e, req)),
    }
}

/// Extractor para claims JWT em handlers
pub struct JwtClaims(pub Claims);

impl actix_web::FromRequest for JwtClaims {
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            req.extensions()
                .get::<Claims>()
                .cloned()
                .map(JwtClaims)
                .ok_or_else(|| ErrorUnauthorized("No JWT claims found"))
        })
    }
}
