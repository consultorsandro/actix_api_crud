// Testes de integração para endpoints da API
// Etapa 7: Testes e Qualidade - Testes de Integração

use actix_web::{App, http::StatusCode, middleware, test, web};
use serde_json::json;
use uuid::Uuid;

// Note: Estes são testes de integração básicos
// Em uma aplicação real, você usaria um banco de dados de teste

#[actix_web::test]
async fn test_health_check_endpoint() {
    let app = test::init_service(App::new().route(
        "/health",
        web::get().to(|| async {
            actix_web::HttpResponse::Ok().json(json!({
                "status": "healthy",
                "timestamp": chrono::Utc::now()
            }))
        }),
    ))
    .await;

    let req = test::TestRequest::get().uri("/health").to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_cors_headers() {
    let app = test::init_service(
        App::new()
            .wrap(actix_cors::Cors::permissive()) // Para teste apenas
            .route(
                "/test",
                web::get().to(|| async {
                    actix_web::HttpResponse::Ok().json(json!({"message": "test"}))
                }),
            ),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/test")
        .insert_header(("Origin", "http://localhost:3000"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Verificar se headers CORS estão presentes
    let headers = resp.headers();
    assert!(headers.contains_key("access-control-allow-origin"));
}

#[actix_web::test]
async fn test_security_headers() {
    use actix_api_crud::middlewares::security::SecurityHeaders;

    let app = test::init_service(
        App::new().wrap(SecurityHeaders).route(
            "/test",
            web::get()
                .to(|| async { actix_web::HttpResponse::Ok().json(json!({"message": "secure"})) }),
        ),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Verificar headers de segurança
    let headers = resp.headers();
    assert!(headers.contains_key("x-xss-protection"));
    assert!(headers.contains_key("x-content-type-options"));
    assert!(headers.contains_key("x-frame-options"));
    assert!(headers.contains_key("content-security-policy"));
}

#[actix_web::test]
async fn test_json_validation() {
    let app = test::init_service(App::new().route(
        "/validate",
        web::post().to(|data: web::Json<serde_json::Value>| async move {
            actix_web::HttpResponse::Ok().json(json!({
                "received": data.into_inner()
            }))
        }),
    ))
    .await;

    // Test com JSON válido
    let valid_req = test::TestRequest::post()
        .uri("/validate")
        .set_json(&json!({"name": "Test", "email": "test@example.com"}))
        .to_request();

    let resp = test::call_service(&app, valid_req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Test com JSON inválido
    let invalid_req = test::TestRequest::post()
        .uri("/validate")
        .set_payload("invalid json")
        .insert_header(("content-type", "application/json"))
        .to_request();

    let resp = test::call_service(&app, invalid_req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn test_error_handling() {
    use actix_api_crud::errors::AppError;

    let app = test::init_service(
        App::new()
            .route(
                "/error/notfound",
                web::get().to(|| async {
                    Err::<actix_web::HttpResponse, AppError>(AppError::NotFound(
                        "Resource not found".to_string(),
                    ))
                }),
            )
            .route(
                "/error/validation",
                web::get().to(|| async {
                    Err::<actix_web::HttpResponse, AppError>(AppError::Validation(
                        "Invalid input".to_string(),
                    ))
                }),
            )
            .route(
                "/error/auth",
                web::get().to(|| async {
                    Err::<actix_web::HttpResponse, AppError>(AppError::Authentication(
                        "Unauthorized".to_string(),
                    ))
                }),
            ),
    )
    .await;

    // Test NotFound error
    let req = test::TestRequest::get().uri("/error/notfound").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Test Validation error
    let req = test::TestRequest::get()
        .uri("/error/validation")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Test Authentication error
    let req = test::TestRequest::get().uri("/error/auth").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn test_middleware_chain() {
    use actix_api_crud::middlewares::security::{InputSanitizer, SecurityHeaders};

    let app = test::init_service(
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(SecurityHeaders)
            .wrap(InputSanitizer)
            .route(
                "/chain",
                web::post().to(|data: web::Json<serde_json::Value>| async move {
                    actix_web::HttpResponse::Ok().json(json!({
                        "processed": data.into_inner()
                    }))
                }),
            ),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/chain")
        .set_json(&json!({"message": "Hello World"}))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Verificar que todos os middlewares foram aplicados
    let headers = resp.headers();
    assert!(headers.contains_key("x-xss-protection"));
}

#[actix_web::test]
async fn test_pagination_query_params() {
    let app = test::init_service(App::new().route(
        "/paginated",
        web::get().to(
            |query: web::Query<actix_api_crud::models::pagination::PaginationParams>| async move {
                actix_web::HttpResponse::Ok().json(json!({
                    "page": query.page,
                    "limit": query.limit,
                    "search": query.search,
                    "sort_by": query.sort_by,
                    "sort_order": query.sort_order
                }))
            },
        ),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/paginated?page=2&limit=20&search=test&sort_by=name&sort_order=asc")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_uuid_path_params() {
    let app = test::init_service(App::new().route(
        "/user/{id}",
        web::get().to(|path: web::Path<Uuid>| async move {
            let user_id = path.into_inner();
            actix_web::HttpResponse::Ok().json(json!({
                "user_id": user_id.to_string()
            }))
        }),
    ))
    .await;

    let valid_uuid = Uuid::new_v4();
    let req = test::TestRequest::get()
        .uri(&format!("/user/{}", valid_uuid))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Test com UUID inválido
    let req = test::TestRequest::get()
        .uri("/user/invalid-uuid")
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    // UUID inválido pode retornar 400 ou 404 dependendo do roteamento
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
        "Expected 400 or 404, got {}",
        status.as_u16()
    );
}

#[actix_web::test]
async fn test_content_type_handling() {
    let app = test::init_service(App::new().route(
        "/upload",
        web::post().to(|_payload: web::Payload| async move {
            actix_web::HttpResponse::Ok().json(json!({"status": "received"}))
        }),
    ))
    .await;

    // Test JSON content
    let req = test::TestRequest::post()
        .uri("/upload")
        .set_json(&json!({"data": "test"}))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Test form data
    let req = test::TestRequest::post()
        .uri("/upload")
        .set_form(&[("field", "value")])
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn test_rate_limiting_simulation() {
    // Simulação básica de rate limiting
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    let counter = Arc::new(Mutex::new(HashMap::<String, u32>::new()));

    let app = test::init_service(App::new().app_data(web::Data::new(counter.clone())).route(
        "/limited",
        web::get().to(
            move |data: web::Data<Arc<Mutex<HashMap<String, u32>>>>| async move {
                let mut counter = data.lock().unwrap();
                let ip = "test_ip".to_string();
                let count = counter.entry(ip).or_insert(0);
                *count += 1;

                if *count > 5 {
                    actix_web::HttpResponse::TooManyRequests().json(json!({
                        "error": "Rate limit exceeded"
                    }))
                } else {
                    actix_web::HttpResponse::Ok().json(json!({
                        "request_count": *count
                    }))
                }
            },
        ),
    ))
    .await;

    // Fazer várias requisições para testar rate limiting
    for i in 1..=7 {
        let req = test::TestRequest::get().uri("/limited").to_request();
        let resp = test::call_service(&app, req).await;

        if i <= 5 {
            assert_eq!(resp.status(), StatusCode::OK);
        } else {
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }
}
