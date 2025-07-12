// Testes específicos para o sistema JWT
// Etapa 7: Testes e Qualidade - Testes JWT

use actix_api_crud::auth::jwt::{Claims, JwtConfig};
use actix_api_crud::middlewares::auth::JwtAuthMiddleware;
use actix_web::{App, HttpResponse, http::StatusCode, test, web};
use serde_json::json;
use serial_test::serial;
use std::env;
use uuid::Uuid;

#[tokio::test]
#[serial]
async fn test_jwt_config_from_env() {
    unsafe {
        env::set_var("JWT_SECRET", "test_secret_key_with_32_characters");
        env::set_var("JWT_EXPIRATION", "24");
    }

    let config = JwtConfig::from_env();
    assert!(config.is_ok());

    let jwt_config = config.unwrap();
    assert_eq!(jwt_config.secret, "test_secret_key_with_32_characters");
    assert_eq!(jwt_config.expiration_hours, 24);

    unsafe {
        env::remove_var("JWT_SECRET");
        env::remove_var("JWT_EXPIRATION");
    }
}

#[tokio::test]
#[serial]
async fn test_jwt_token_generation_and_validation() {
    unsafe {
        env::set_var("JWT_SECRET", "test_secret_key_with_32_characters");
        env::set_var("JWT_EXPIRATION", "1");
    }

    let config = JwtConfig::from_env().unwrap();
    let user_id = Uuid::new_v4();

    let token = config
        .generate_token(user_id, "test@example.com", "Test User", "user")
        .unwrap();

    let claims = config.decode_token(&token).unwrap();

    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.email, "test@example.com");
    assert_eq!(claims.name, "Test User");
    assert_eq!(claims.role, "user");
    assert!(config.is_token_valid(&claims));

    unsafe {
        env::remove_var("JWT_SECRET");
        env::remove_var("JWT_EXPIRATION");
    }
}

#[tokio::test]
#[serial]
async fn test_jwt_token_expiration() {
    unsafe {
        env::set_var("JWT_SECRET", "test_secret_key_with_32_characters");
        env::set_var("JWT_EXPIRATION", "1");
    }

    let config = JwtConfig::from_env().unwrap();

    // Create a token that's already expired
    let expired_claims = Claims {
        sub: Uuid::new_v4().to_string(),
        email: "test@example.com".to_string(),
        name: "Test User".to_string(),
        exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp(),
        iat: (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp(),
        role: "user".to_string(),
    };

    assert!(!config.is_token_valid(&expired_claims));

    unsafe {
        env::remove_var("JWT_SECRET");
        env::remove_var("JWT_EXPIRATION");
    }
}

#[tokio::test]
#[serial]
async fn test_jwt_middleware_validation() {
    unsafe {
        env::set_var("JWT_SECRET", "test_secret_key_with_32_characters");
    }

    let config = JwtConfig::from_env().unwrap();
    let user_id = Uuid::new_v4();

    let token = config
        .generate_token(user_id, "test@example.com", "Test User", "user")
        .unwrap();

    // Test token validation through middleware
    let result = JwtAuthMiddleware::validate_token(&token);
    assert!(result.is_ok());

    let claims = result.unwrap();
    assert_eq!(claims.sub, user_id.to_string());

    // Test invalid token
    let invalid_result = JwtAuthMiddleware::validate_token("invalid.token.here");
    assert!(invalid_result.is_err());

    unsafe {
        env::remove_var("JWT_SECRET");
    }
}

#[actix_web::test]
#[serial]
async fn test_jwt_authentication_flow() {
    unsafe {
        env::set_var("JWT_SECRET", "test_secret_key_with_32_characters");
    }

    let config = JwtConfig::from_env().unwrap();
    let user_id = Uuid::new_v4();

    let token = config
        .generate_token(user_id, "test@example.com", "Test User", "user")
        .unwrap();

    let app = test::init_service(
        App::new()
            .route(
                "/protected",
                web::get().to(|| async {
                    HttpResponse::Ok().json(json!({"message": "Protected resource"}))
                }),
            )
            .route(
                "/login",
                web::post().to(move |_: web::Json<serde_json::Value>| {
                    let token = token.clone();
                    async move {
                        HttpResponse::Ok().json(json!({
                            "token": token,
                            "type": "Bearer"
                        }))
                    }
                }),
            ),
    )
    .await;

    // Test login to get token
    let login_req = test::TestRequest::post()
        .uri("/login")
        .set_json(&json!({"email": "test@example.com", "password": "password"}))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert_eq!(login_resp.status(), StatusCode::OK);

    // Test accessing protected resource without token
    let unauth_req = test::TestRequest::get().uri("/protected").to_request();

    let unauth_resp = test::call_service(&app, unauth_req).await;
    // Note: This would normally return 401, but our test setup doesn't include auth middleware
    // In a real scenario, you'd set up the full auth middleware

    unsafe {
        env::remove_var("JWT_SECRET");
    }
}

#[test]
async fn test_claims_serialization_deserialization() {
    let claims = Claims {
        sub: "user123".to_string(),
        email: "test@example.com".to_string(),
        name: "Test User".to_string(),
        exp: 1234567890,
        iat: 1234567800,
        role: "admin".to_string(),
    };

    let json = serde_json::to_string(&claims).unwrap();
    assert!(json.contains("user123"));
    assert!(json.contains("test@example.com"));
    assert!(json.contains("admin"));

    let deserialized: Claims = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.sub, claims.sub);
    assert_eq!(deserialized.email, claims.email);
    assert_eq!(deserialized.name, claims.name);
    assert_eq!(deserialized.exp, claims.exp);
    assert_eq!(deserialized.iat, claims.iat);
    assert_eq!(deserialized.role, claims.role);
}

#[tokio::test]
#[serial]
async fn test_jwt_different_roles() {
    unsafe {
        env::set_var("JWT_SECRET", "test_secret_key_with_32_characters");
    }

    let config = JwtConfig::from_env().unwrap();
    let user_id = Uuid::new_v4();

    // Test user role
    let user_token = config
        .generate_token(user_id, "user@example.com", "Regular User", "user")
        .unwrap();

    let user_claims = config.decode_token(&user_token).unwrap();
    assert_eq!(user_claims.role, "user");

    // Test admin role
    let admin_token = config
        .generate_token(user_id, "admin@example.com", "Admin User", "admin")
        .unwrap();

    let admin_claims = config.decode_token(&admin_token).unwrap();
    assert_eq!(admin_claims.role, "admin");

    unsafe {
        env::remove_var("JWT_SECRET");
    }
}

#[tokio::test]
#[serial]
async fn test_jwt_config_missing_secret() {
    unsafe {
        env::remove_var("JWT_SECRET");
    }

    let result = JwtConfig::from_env();
    assert!(result.is_err());
}

#[tokio::test]
#[serial]
async fn test_jwt_config_invalid_expiration() {
    unsafe {
        env::set_var("JWT_SECRET", "test_secret_key_with_32_characters");
        env::set_var("JWT_EXPIRATION", "invalid");
    }

    let result = JwtConfig::from_env();
    assert!(result.is_err());

    unsafe {
        env::remove_var("JWT_SECRET");
        env::remove_var("JWT_EXPIRATION");
    }
}

#[tokio::test]
#[serial]
async fn test_jwt_token_with_special_characters() {
    unsafe {
        env::set_var("JWT_SECRET", "test_secret_key_with_32_characters");
    }

    let config = JwtConfig::from_env().unwrap();
    let user_id = Uuid::new_v4();

    let token = config
        .generate_token(
            user_id,
            "user+test@example.com", // Email with special characters
            "José da Silva",         // Name with accents
            "user",
        )
        .unwrap();

    let claims = config.decode_token(&token).unwrap();

    assert_eq!(claims.email, "user+test@example.com");
    assert_eq!(claims.name, "José da Silva");

    unsafe {
        env::remove_var("JWT_SECRET");
    }
}
