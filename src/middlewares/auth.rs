use actix_web::{
    Error, HttpMessage,
    dev::{ServiceRequest, ServiceResponse},
    error::ErrorUnauthorized,
    http::header::AUTHORIZATION,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use futures_util::future::LocalBoxFuture;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::env;

/// Claims JWT para autenticação
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,          // Subject (user id)
    pub email: String,        // User email
    pub role: Option<String>, // User role
    pub exp: usize,           // Expiration time
}

/// Middleware de autenticação JWT
pub struct JwtAuthMiddleware;

impl JwtAuthMiddleware {
    /// Valida token JWT e extrai claims
    pub fn validate_token(token: &str) -> Result<Claims, Error> {
        let secret =
            env::var("JWT_SECRET").map_err(|_| ErrorUnauthorized("JWT secret not configured"))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpResponse, test, web};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serial_test::serial;
    use std::env;

    async fn test_handler() -> Result<HttpResponse, Error> {
        Ok(HttpResponse::Ok().json("Success"))
    }

    #[tokio::test]
    #[serial]
    async fn test_jwt_token_validation_valid() {
        unsafe {
            env::set_var("JWT_SECRET", "test_secret_key_with_32_characters");
        }

        let claims = Claims {
            sub: "user123".to_string(),
            email: "test@example.com".to_string(),
            role: Some("user".to_string()),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("test_secret_key_with_32_characters".as_ref()),
        )
        .unwrap();

        let result = JwtAuthMiddleware::validate_token(&token);
        assert!(result.is_ok());

        let decoded_claims = result.unwrap();
        assert_eq!(decoded_claims.sub, "user123");
        assert_eq!(decoded_claims.email, "test@example.com");

        unsafe {
            env::remove_var("JWT_SECRET");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_jwt_token_validation_invalid() {
        unsafe {
            env::set_var("JWT_SECRET", "test_secret_key_with_32_characters");
        }

        let invalid_token = "invalid.token.here";
        let result = JwtAuthMiddleware::validate_token(invalid_token);
        assert!(result.is_err());

        unsafe {
            env::remove_var("JWT_SECRET");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_jwt_token_validation_expired() {
        unsafe {
            env::set_var("JWT_SECRET", "test_secret_key_with_32_characters");
        }

        let claims = Claims {
            sub: "user123".to_string(),
            email: "test@example.com".to_string(),
            role: Some("user".to_string()),
            exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp() as usize, // Expired
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("test_secret_key_with_32_characters".as_ref()),
        )
        .unwrap();

        let result = JwtAuthMiddleware::validate_token(&token);
        assert!(result.is_err());

        unsafe {
            env::remove_var("JWT_SECRET");
        }
    }

    #[tokio::test]
    async fn test_jwt_token_validation_no_secret() {
        unsafe {
            env::remove_var("JWT_SECRET");
        }

        let token = "any.token.here";
        let result = JwtAuthMiddleware::validate_token(token);
        assert!(result.is_err());
    }

    #[actix_web::test]
    #[serial]
    async fn test_extract_token_from_header_valid() {
        unsafe {
            env::set_var("JWT_SECRET", "test_secret_key_with_32_characters");
        }

        let claims = Claims {
            sub: "user123".to_string(),
            email: "test@example.com".to_string(),
            role: Some("user".to_string()),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("test_secret_key_with_32_characters".as_ref()),
        )
        .unwrap();

        let app = test::init_service(App::new().route("/test", web::get().to(test_handler))).await;

        let req = test::TestRequest::get()
            .uri("/test")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let service_req = test::call_service(&app, req).await;
        // Note: This test mainly verifies the setup works
        // Full middleware testing would require more complex setup

        unsafe {
            env::remove_var("JWT_SECRET");
        }
    }

    #[test]
    async fn test_claims_serialization() {
        let claims = Claims {
            sub: "user123".to_string(),
            email: "test@example.com".to_string(),
            role: Some("admin".to_string()),
            exp: 1234567890,
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("user123"));
        assert!(json.contains("test@example.com"));
        assert!(json.contains("admin"));

        let deserialized: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.sub, claims.sub);
        assert_eq!(deserialized.email, claims.email);
        assert_eq!(deserialized.role, claims.role);
        assert_eq!(deserialized.exp, claims.exp);
    }
}
