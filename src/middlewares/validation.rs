// src/middlewares/validation.rs
// Etapa 4 Aperfeiçoamento: ValidatedJson middleware para validação automática

use actix_web::{
    dev::Payload, web, Error, FromRequest, HttpRequest,
};
use futures::future::{LocalBoxFuture, ready};
use serde::de::DeserializeOwned;
use std::ops::{Deref, DerefMut};
use validator::Validate;
use crate::errors::AppError;

/// Wrapper para JSON validado automaticamente
/// Extrai, deserializa e valida JSON em uma única operação
#[derive(Debug)]
pub struct ValidatedJson<T>(pub T);

impl<T> ValidatedJson<T> {
    /// Extrai o valor interno
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for ValidatedJson<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for ValidatedJson<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> FromRequest for ValidatedJson<T>
where
    T: DeserializeOwned + Validate + 'static,
{
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let json_future = web::Json::<T>::from_request(req, payload);
        
        Box::pin(async move {
            match json_future.await {
                Ok(json) => {
                    // Validar os dados extraídos
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
                        log::warn!("Validation failed: {}", error_msg);
                        return Err(AppError::Validation(error_msg).into());
                    }

                    log::debug!("Validation successful for type: {}", std::any::type_name::<T>());
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
