// Middleware de validação para DTOs usando validator
// Etapa 4: Validações automáticas para todos os endpoints

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse, Result,
    web::Json,
};
use futures_util::future::LocalBoxFuture;
use std::{
    future::{ready, Ready},
    rc::Rc,
};
use validator::Validate;
use serde::de::DeserializeOwned;

use crate::errors::AppError;

// Trait para objetos que podem ser validados
pub trait Validatable: Validate + DeserializeOwned {}

// Implementação automática para qualquer tipo que implemente Validate + DeserializeOwned
impl<T> Validatable for T where T: Validate + DeserializeOwned {}

// Estrutura do middleware de validação
pub struct ValidationMiddleware;

impl<S, B> Transform<S, ServiceRequest> for ValidationMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = ValidationMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ValidationMiddlewareService {
            service: Rc::new(service),
        }))
    }
}

pub struct ValidationMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for ValidationMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        Box::pin(async move {
            // Por enquanto, apenas passamos a requisição adiante
            // A validação será feita nos handlers usando o extractor ValidatedJson
            service.call(req).await
        })
    }
}

// Extractor personalizado para JSON validado
pub struct ValidatedJson<T>(pub T);

impl<T> std::ops::Deref for ValidatedJson<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for ValidatedJson<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> From<ValidatedJson<T>> for T {
    fn from(validated: ValidatedJson<T>) -> Self {
        validated.0
    }
}

// Implementação do FromRequest para ValidatedJson
use actix_web::{FromRequest, HttpRequest};
use std::pin::Pin;

impl<T> FromRequest for ValidatedJson<T>
where
    T: Validate + DeserializeOwned + 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut actix_web::dev::Payload) -> Self::Future {
        let json_future = Json::<T>::from_request(req, payload);

        Box::pin(async move {
            match json_future.await {
                Ok(json) => {
                    // Validar os dados
                    if let Err(validation_errors) = json.validate() {
                        let error_messages: Vec<String> = validation_errors
                            .field_errors()
                            .iter()
                            .flat_map(|(field, errors)| {
                                errors.iter().map(move |error| {
                                    match &error.message {
                                        Some(msg) => format!("{}: {}", field, msg),
                                        None => format!("{}: Validation failed", field),
                                    }
                                })
                            })
                            .collect();

                        let error_msg = error_messages.join(", ");
                        return Err(AppError::Validation(error_msg).into());
                    }

                    Ok(ValidatedJson(json.into_inner()))
                }
                Err(e) => {
                    log::warn!("JSON deserialization failed: {}", e);
                    Err(AppError::Validation("Invalid JSON format".to_string()).into())
                }
            }
        })
    }
}
