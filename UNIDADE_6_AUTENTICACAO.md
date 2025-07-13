# 🟣 **UNIDADE VI: AUTENTICAÇÃO E AUTORIZAÇÃO**
*"Implementando segurança robusta com JWT"*

## 📚 **Introdução**

A **Autenticação e Autorização** são componentes críticos para qualquer aplicação web moderna. Nesta unidade, você aprenderá a implementar um sistema de segurança robusto usando **JSON Web Tokens (JWT)** com Rust e Actix-Web, incluindo geração de tokens, validação, middleware de autenticação e controle de acesso baseado em roles.

**Objetivos desta Unidade:**
- ✅ Implementar sistema JWT completo e seguro
- ✅ Criar middleware de autenticação e autorização
- ✅ Gerenciar claims customizados e roles
- ✅ Implementar refresh tokens para sessões longas
- ✅ Aplicar melhores práticas de segurança

---

## 📌 **CAPÍTULO 9: SISTEMA JWT**

### **9.1 Autenticação JWT (`auth/`)**

O JSON Web Token (JWT) é um padrão aberto (RFC 7519) que define uma forma compacta e segura de transmitir informações entre partes como um objeto JSON.

#### **9.1.1 Estrutura do Sistema de Autenticação**

```rust
// src/auth/mod.rs
// Sistema de autenticação e autorização modular

pub mod jwt;
pub mod models;

// Re-exports para facilitar uso
pub use jwt::{Claims, JwtConfig};
pub use models::{
    AuthResponse, LoginRequest, RegisterRequest, 
    ChangePasswordRequest, UserInfo, RefreshTokenRequest
};
```

#### **9.1.2 Configuração JWT Robusta**

```rust
// src/auth/jwt.rs
use actix_web::{Error, HttpMessage, dev::ServiceRequest};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;

use crate::errors::AppError;

/// Claims do JWT token com informações essenciais
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,   // Subject (user ID)
    pub email: String, // Email do usuário
    pub name: String,  // Nome do usuário
    pub exp: i64,      // Expiration time (timestamp)
    pub iat: i64,      // Issued at (timestamp)
    pub role: String,  // Role do usuário (admin, user, moderator, etc.)
}

/// Configuração JWT com parâmetros de segurança
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

        // Validar comprimento do secret
        if secret.len() < 32 {
            return Err(AppError::Configuration(
                "JWT_SECRET must be at least 32 characters long".to_string()
            ));
        }

        let expiration_hours = env::var("JWT_EXPIRATION")
            .unwrap_or("24".to_string())
            .parse::<i64>()
            .map_err(|_| AppError::Configuration("Invalid JWT_EXPIRATION".to_string()))?;

        // Validar tempo de expiração (entre 1 hora e 7 dias)
        if expiration_hours < 1 || expiration_hours > 168 {
            return Err(AppError::Configuration(
                "JWT_EXPIRATION must be between 1 and 168 hours".to_string()
            ));
        }

        Ok(Self {
            secret,
            expiration_hours,
            algorithm: Algorithm::HS256,
        })
    }
}
```

**🔒 Aspectos de Segurança:**
- **Secret Validation**: Mínimo 32 caracteres para força criptográfica
- **Expiration Control**: Limite máximo de 7 dias para reduzir exposure
- **Algorithm Safety**: HS256 como padrão seguro e amplamente suportado
- **Environment Configuration**: Secrets nunca hardcoded no código

#### **9.1.3 Modelos de Dados de Autenticação**

```rust
// src/auth/models.rs
use serde::{Deserialize, Serialize};
use validator::Validate;

/// DTO para login de usuário com validações
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Email deve ter formato válido"))]
    pub email: String,

    #[validate(length(min = 6, message = "Senha deve ter pelo menos 6 caracteres"))]
    pub password: String,
}

/// DTO para registro de usuário com validações robustas
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 2, max = 100, message = "Nome deve ter entre 2 e 100 caracteres"))]
    pub name: String,

    #[validate(email(message = "Email deve ter formato válido"))]
    pub email: String,

    #[validate(length(min = 8, message = "Senha deve ter pelo menos 8 caracteres"))]
    pub password: String,

    #[validate(range(min = 13, max = 150, message = "Idade deve estar entre 13 e 150 anos"))]
    pub age: i32,
}

/// DTO para mudança de senha
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 6, message = "Senha atual deve ter pelo menos 6 caracteres"))]
    pub current_password: String,

    #[validate(length(min = 8, message = "Nova senha deve ter pelo menos 8 caracteres"))]
    pub new_password: String,
}

/// Resposta de autenticação padronizada
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: UserInfo,
}

/// Informações básicas do usuário (sem dados sensíveis)
#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
    pub email: String,
    pub role: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl AuthResponse {
    pub fn new(token: String, expires_in: i64, user: UserInfo) -> Self {
        Self {
            token,
            token_type: "Bearer".to_string(),
            expires_in,
            user,
        }
    }
}

impl UserInfo {
    pub fn from_user(user: &crate::models::user::User) -> Self {
        Self {
            id: user.id.to_string(),
            name: user.name.clone(),
            email: user.email.clone(),
            role: user.role.clone().unwrap_or_else(|| "user".to_string()),
            created_at: user.created_at,
        }
    }
}
```

**📋 Características dos DTOs:**
- **Validação Automática**: Usando `validator` crate para rules de negócio
- **Segurança**: Senhas com mínimo 8 caracteres, idades válidas
- **Serialização Segura**: Exclusão de dados sensíveis nas respostas
- **Padronização**: Formato consistente para todas as operações

---

### **9.2 Geração e Validação de Tokens**

A geração e validação de tokens são operações críticas que devem ser implementadas com máxima segurança.

#### **9.2.1 Geração de Tokens Segura**

```rust
impl JwtConfig {
    /// Gera um token JWT com claims completos
    pub fn generate_token(
        &self,
        user_id: Uuid,
        email: &str,
        name: &str,
        role: &str,
    ) -> Result<String, AppError> {
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

    /// Gera token com claims customizados adiccionais
    pub fn generate_token_with_claims(
        &self,
        user_id: Uuid,
        email: &str,
        name: &str,
        role: &str,
        additional_claims: &serde_json::Value,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.expiration_hours);

        let mut claims = serde_json::json!({
            "sub": user_id.to_string(),
            "email": email,
            "name": name,
            "exp": exp.timestamp(),
            "iat": now.timestamp(),
            "role": role,
        });

        // Merge additional claims
        if let serde_json::Value::Object(ref map) = additional_claims {
            if let serde_json::Value::Object(ref mut claims_map) = claims {
                for (key, value) in map {
                    claims_map.insert(key.clone(), value.clone());
                }
            }
        }

        let header = Header::new(self.algorithm);
        let encoding_key = EncodingKey::from_secret(self.secret.as_ref());

        encode(&header, &claims, &encoding_key)
            .map_err(|e| AppError::Authentication(format!("Failed to generate token: {}", e)))
    }
}
```

#### **9.2.2 Validação de Tokens Rigorosa**

```rust
impl JwtConfig {
    /// Valida e decodifica um token JWT
    pub fn decode_token(&self, token: &str) -> Result<Claims, AppError> {
        let decoding_key = DecodingKey::from_secret(self.secret.as_ref());
        
        let mut validation = Validation::new(self.algorithm);
        validation.validate_exp = true;  // Validar expiração
        validation.validate_nbf = true;  // Validar "not before"
        validation.validate_aud = false; // Audience não usado neste exemplo
        validation.leeway = 60;          // Tolerância de 60 segundos para clock skew

        decode::<Claims>(token, &decoding_key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|e| {
                log::warn!("Token validation failed: {}", e);
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        AppError::Authentication("Token expired".to_string())
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                        AppError::Authentication("Invalid token signature".to_string())
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidToken => {
                        AppError::Authentication("Malformed token".to_string())
                    }
                    _ => AppError::Authentication(format!("Invalid token: {}", e))
                }
            })
    }

    /// Verifica se o token não expirou (dupla verificação)
    pub fn is_token_valid(&self, claims: &Claims) -> bool {
        let now = Utc::now().timestamp();
        claims.exp > now
    }

    /// Verifica se o token precisa ser renovado (80% do tempo de vida)
    pub fn should_refresh_token(&self, claims: &Claims) -> bool {
        let now = Utc::now().timestamp();
        let token_age = now - claims.iat;
        let token_lifetime = self.expiration_hours * 3600; // Convert to seconds
        
        token_age > (token_lifetime as i64 * 80 / 100) // 80% do tempo de vida
    }
}
```

**🔍 Validações Implementadas:**
- **Expiration Check**: Verificação automática de expiração
- **Clock Skew Tolerance**: 60 segundos de tolerância para diferenças de relógio
- **Signature Validation**: Verificação criptográfica da assinatura
- **Error Categorization**: Diferentes tipos de erro para debugging
- **Refresh Suggestion**: Lógica para renovação proativa de tokens

#### **9.2.3 Exemplo de Uso Completo**

```rust
// Exemplo de geração e validação em um handler
pub async fn login_user(
    login_request: LoginRequest,
    user_service: &impl UserServiceTrait,
    jwt_config: &JwtConfig,
) -> Result<AuthResponse, AppError> {
    // 1. Autenticar usuário
    let user = user_service
        .authenticate_user(&login_request.email, &login_request.password)
        .await?;

    // 2. Gerar token JWT
    let token = jwt_config.generate_token(
        user.id,
        &user.email,
        &user.name,
        &user.role.unwrap_or_else(|| "user".to_string()),
    )?;

    // 3. Calcular tempo de expiração
    let expires_in = jwt_config.expiration_hours * 3600; // Em segundos

    // 4. Criar resposta
    let user_info = UserInfo::from_user(&user);
    let auth_response = AuthResponse::new(token, expires_in, user_info);

    log::info!("User {} logged in successfully", user.email);
    Ok(auth_response)
}
```

---

### **9.3 Claims Customizados**

Claims customizados permitem incluir informações específicas da aplicação no token JWT.

#### **9.3.1 Estrutura de Claims Extensível**

```rust
/// Claims base para autenticação
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    // Claims padrão JWT
    pub sub: String,   // Subject (user ID)
    pub exp: i64,      // Expiration time
    pub iat: i64,      // Issued at
    pub nbf: Option<i64>, // Not before (opcional)
    
    // Claims customizados da aplicação
    pub email: String,
    pub name: String,
    pub role: String,
    
    // Claims adicionais opcionais
    pub permissions: Option<Vec<String>>,
    pub organization_id: Option<String>,
    pub department: Option<String>,
    pub last_login: Option<i64>,
    pub session_id: Option<String>,
}

/// Claims estendidos para administradores
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdminClaims {
    #[serde(flatten)]
    pub base: Claims,
    
    // Claims específicos de admin
    pub admin_level: u8,           // Nível de administração (1-10)
    pub allowed_modules: Vec<String>, // Módulos permitidos
    pub audit_required: bool,      // Se ações requerem auditoria
    pub delegation_count: u8,      // Número de delegações ativas
}

/// Claims para APIs/serviços
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceClaims {
    pub sub: String,   // Service ID
    pub exp: i64,
    pub iat: i64,
    
    // Claims específicos de serviço
    pub service_name: String,
    pub api_version: String,
    pub rate_limit: u32,
    pub allowed_endpoints: Vec<String>,
    pub environment: String, // dev, staging, prod
}
```

#### **9.3.2 Geração de Claims Customizados**

```rust
impl JwtConfig {
    /// Gera token com permissões específicas
    pub fn generate_token_with_permissions(
        &self,
        user_id: Uuid,
        email: &str,
        name: &str,
        role: &str,
        permissions: Vec<String>,
        organization_id: Option<String>,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.expiration_hours);

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            name: name.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: Some(now.timestamp()), // Token válido imediatamente
            role: role.to_string(),
            permissions: Some(permissions),
            organization_id,
            department: None,
            last_login: Some(now.timestamp()),
            session_id: Some(Uuid::new_v4().to_string()),
        };

        let header = Header::new(self.algorithm);
        let encoding_key = EncodingKey::from_secret(self.secret.as_ref());

        encode(&header, &claims, &encoding_key)
            .map_err(|e| AppError::Authentication(format!("Failed to generate token: {}", e)))
    }

    /// Gera token para administrador com claims estendidos
    pub fn generate_admin_token(
        &self,
        user_id: Uuid,
        email: &str,
        name: &str,
        admin_level: u8,
        allowed_modules: Vec<String>,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.expiration_hours);

        let base_claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            name: name.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: Some(now.timestamp()),
            role: "admin".to_string(),
            permissions: Some(vec![
                "users:read".to_string(),
                "users:write".to_string(),
                "users:delete".to_string(),
                "admin:access".to_string(),
            ]),
            organization_id: None,
            department: Some("IT".to_string()),
            last_login: Some(now.timestamp()),
            session_id: Some(Uuid::new_v4().to_string()),
        };

        let admin_claims = AdminClaims {
            base: base_claims,
            admin_level,
            allowed_modules,
            audit_required: admin_level >= 8, // Níveis altos requerem auditoria
            delegation_count: 0,
        };

        let header = Header::new(self.algorithm);
        let encoding_key = EncodingKey::from_secret(self.secret.as_ref());

        encode(&header, &admin_claims, &encoding_key)
            .map_err(|e| AppError::Authentication(format!("Failed to generate admin token: {}", e)))
    }
}
```

#### **9.3.3 Validação de Claims Customizados**

```rust
/// Trait para validação de claims customizados
pub trait ClaimsValidator {
    fn validate_permissions(&self, required_permission: &str) -> bool;
    fn validate_role(&self, required_roles: &[&str]) -> bool;
    fn validate_organization(&self, organization_id: &str) -> bool;
}

impl ClaimsValidator for Claims {
    fn validate_permissions(&self, required_permission: &str) -> bool {
        if let Some(ref permissions) = self.permissions {
            permissions.contains(&required_permission.to_string())
        } else {
            false
        }
    }

    fn validate_role(&self, required_roles: &[&str]) -> bool {
        required_roles.contains(&self.role.as_str())
    }

    fn validate_organization(&self, organization_id: &str) -> bool {
        if let Some(ref org_id) = self.organization_id {
            org_id == organization_id
        } else {
            false
        }
    }
}

/// Macro para verificação fácil de permissões
macro_rules! require_permission {
    ($claims:expr, $permission:expr) => {
        if !$claims.validate_permissions($permission) {
            return Err(AppError::Authorization(format!(
                "Permission '{}' required", 
                $permission
            )));
        }
    };
}

/// Exemplo de uso em handler
pub async fn delete_user_endpoint(
    claims: JwtClaims,
    user_id: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let claims = claims.0;
    
    // Verificar permissão específica
    require_permission!(claims, "users:delete");
    
    // Verificar role
    if !claims.validate_role(&["admin", "moderator"]) {
        return Err(AppError::Authorization(
            "Admin or moderator role required".to_string()
        ));
    }
    
    // Lógica do endpoint...
    Ok(HttpResponse::Ok().json("User deleted"))
}
```

---

### **9.4 Refresh Tokens**

Refresh tokens permitem renovar tokens de acesso sem reautenticação, melhorando a experiência do usuário mantendo a segurança.

#### **9.4.1 Estrutura de Refresh Tokens**

```rust
/// DTO para refresh token
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct RefreshTokenRequest {
    #[validate(length(min = 1, message = "Refresh token é obrigatório"))]
    pub refresh_token: String,
}

/// Resposta de refresh token
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub token_type: String,
}

/// Claims para refresh token (mais restritivos)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RefreshClaims {
    pub sub: String,        // User ID
    pub exp: i64,          // Expiration (muito mais longo)
    pub iat: i64,          // Issued at
    pub token_type: String, // "refresh"
    pub session_id: String, // ID da sessão
    pub device_id: Option<String>, // ID do dispositivo
}
```

#### **9.4.2 Implementação de Refresh Tokens**

```rust
impl JwtConfig {
    /// Gera par de tokens (access + refresh)
    pub fn generate_token_pair(
        &self,
        user_id: Uuid,
        email: &str,
        name: &str,
        role: &str,
        device_id: Option<String>,
    ) -> Result<(String, String), AppError> {
        let session_id = Uuid::new_v4().to_string();
        
        // 1. Gerar access token (curta duração)
        let access_token = self.generate_token(user_id, email, name, role)?;
        
        // 2. Gerar refresh token (longa duração)
        let refresh_token = self.generate_refresh_token(
            user_id, 
            session_id, 
            device_id
        )?;
        
        Ok((access_token, refresh_token))
    }

    /// Gera refresh token com validade de 30 dias
    pub fn generate_refresh_token(
        &self,
        user_id: Uuid,
        session_id: String,
        device_id: Option<String>,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let exp = now + Duration::days(30); // 30 dias para refresh

        let claims = RefreshClaims {
            sub: user_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            token_type: "refresh".to_string(),
            session_id,
            device_id,
        };

        let header = Header::new(self.algorithm);
        let encoding_key = EncodingKey::from_secret(self.secret.as_ref());

        encode(&header, &claims, &encoding_key)
            .map_err(|e| AppError::Authentication(format!("Failed to generate refresh token: {}", e)))
    }

    /// Valida refresh token e gera novo access token
    pub fn refresh_access_token(
        &self,
        refresh_token: &str,
        user_service: &impl UserServiceTrait,
    ) -> Result<RefreshTokenResponse, AppError> {
        // 1. Validar refresh token
        let refresh_claims = self.decode_refresh_token(refresh_token)?;
        
        // 2. Verificar se é realmente um refresh token
        if refresh_claims.token_type != "refresh" {
            return Err(AppError::Authentication(
                "Invalid token type".to_string()
            ));
        }

        // 3. Buscar usuário atual (verificar se ainda existe/ativo)
        let user_id = Uuid::parse_str(&refresh_claims.sub)
            .map_err(|_| AppError::Authentication("Invalid user ID in token".to_string()))?;
        
        let user = user_service.get_user_by_id(user_id).await?;

        // 4. Gerar novo access token
        let new_access_token = self.generate_token(
            user.id,
            &user.email,
            &user.name,
            &user.role.unwrap_or_else(|| "user".to_string()),
        )?;

        // 5. Gerar novo refresh token (rotação de tokens)
        let new_refresh_token = self.generate_refresh_token(
            user.id,
            refresh_claims.session_id,
            refresh_claims.device_id,
        )?;

        Ok(RefreshTokenResponse {
            access_token: new_access_token,
            refresh_token: new_refresh_token,
            expires_in: self.expiration_hours * 3600,
            token_type: "Bearer".to_string(),
        })
    }

    /// Decodifica refresh token
    fn decode_refresh_token(&self, token: &str) -> Result<RefreshClaims, AppError> {
        let decoding_key = DecodingKey::from_secret(self.secret.as_ref());
        let validation = Validation::new(self.algorithm);

        decode::<RefreshClaims>(token, &decoding_key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|e| AppError::Authentication(format!("Invalid refresh token: {}", e)))
    }
}
```

#### **9.4.3 Handler de Refresh Token**

```rust
/// Handler para renovação de tokens
pub async fn refresh_token_handler(
    request: web::Json<RefreshTokenRequest>,
    jwt_config: web::Data<JwtConfig>,
    user_service: web::Data<UserService>,
) -> Result<HttpResponse, AppError> {
    log::info!("Processing token refresh request");

    // Validar input
    request.validate()
        .map_err(|e| AppError::Validation(format!("Invalid request: {}", e)))?;

    // Processar refresh
    match jwt_config.refresh_access_token(&request.refresh_token, &**user_service).await {
        Ok(response) => {
            log::info!("Token refreshed successfully");
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::warn!("Token refresh failed: {}", e);
            Err(e)
        }
    }
}

/// Middleware para verificar se token precisa refresh
pub fn check_token_refresh_middleware() -> impl Fn(ServiceRequest, &Next<BoxBody>) -> LocalBoxFuture<'static, Result<ServiceResponse<BoxBody>, Error>> {
    move |req, next| {
        Box::pin(async move {
            // Verificar se há token nos headers
            if let Some(auth_header) = req.headers().get("Authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if auth_str.starts_with("Bearer ") {
                        let token = &auth_str[7..];
                        
                        // Decodificar e verificar se precisa refresh
                        if let Ok(jwt_config) = JwtConfig::from_env() {
                            if let Ok(claims) = jwt_config.decode_token(token) {
                                if jwt_config.should_refresh_token(&claims) {
                                    // Adicionar header indicando que token deveria ser renovado
                                    let mut res = next.call(req).await?;
                                    res.headers_mut().insert(
                                        "X-Token-Refresh-Suggested",
                                        "true".parse().unwrap(),
                                    );
                                    return Ok(res);
                                }
                            }
                        }
                    }
                }
            }
            
            next.call(req).await
        })
    }
}
```

#### **9.4.4 Estratégias de Revogação de Tokens**

```rust
/// Sistema de blacklist para tokens revogados
pub struct TokenBlacklist {
    // Em produção, usar Redis ou banco de dados
    blacklisted_tokens: std::sync::RwLock<std::collections::HashSet<String>>,
}

impl TokenBlacklist {
    pub fn new() -> Self {
        Self {
            blacklisted_tokens: std::sync::RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Adiciona token à blacklist
    pub fn revoke_token(&self, token_jti: &str) -> Result<(), AppError> {
        let mut blacklist = self.blacklisted_tokens.write()
            .map_err(|_| AppError::InternalServer)?;
        
        blacklist.insert(token_jti.to_string());
        log::info!("Token {} added to blacklist", token_jti);
        Ok(())
    }

    /// Verifica se token está revogado
    pub fn is_token_revoked(&self, token_jti: &str) -> bool {
        if let Ok(blacklist) = self.blacklisted_tokens.read() {
            blacklist.contains(token_jti)
        } else {
            false
        }
    }

    /// Limpa tokens expirados da blacklist
    pub fn cleanup_expired_tokens(&self, max_age_seconds: i64) {
        // Implementação de limpeza baseada em timestamp
        // Em produção, implementar com TTL no Redis
    }
}

/// Claims com JTI (JWT ID) para revogação
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClaimsWithJti {
    #[serde(flatten)]
    pub base: Claims,
    pub jti: String, // JWT ID único para revogação
}
```

---

## 🎯 **Exercícios Práticos**

### **Exercício 1: Sistema de Roles Avançado**
Implemente um sistema hierárquico de roles:
- Super Admin > Admin > Moderator > User > Guest
- Permissions granulares por módulo
- Herança de permissões

### **Exercício 2: Multi-Tenant JWT**
Crie sistema JWT para multi-tenant:
- Claims com tenant_id
- Isolamento de dados por tenant
- Rate limiting por tenant

### **Exercício 3: Token Analytics**
Desenvolva sistema de analytics para tokens:
- Tracking de login/logout
- Detecção de tokens suspeitos
- Métricas de uso por usuário

---

## 📋 **Resumo da Unidade**

**✅ Domínio Adquirido:**
- **Sistema JWT Completo**: Geração, validação e refresh tokens
- **Claims Customizados**: Informações específicas da aplicação
- **Middleware de Autenticação**: Proteção automática de rotas
- **Refresh Tokens**: Sessões longas com segurança mantida

**🚀 Próxima Unidade:**
Na **Unidade VII**, exploraremos **Middleware e Segurança Avançada**, incluindo CORS, rate limiting, sanitização de input e headers de segurança.

**🔗 Recursos Importantes:**
- Tokens seguros com validação rigorosa
- Claims extensíveis para casos complexos
- Refresh tokens com rotação automática
- Sistema de revogação para casos de emergência

Esta unidade estabelece **segurança robusta** para aplicações Rust de produção com padrões industriais de autenticação e autorização!
