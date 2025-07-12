// Sistema de paginação para listagens
// Etapa 4: Paginação para melhor performance em grandes datasets

use serde::{Deserialize, Serialize};
use validator::Validate;

// Parâmetros de paginação com validação
#[derive(Debug, Deserialize, Validate)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    #[validate(range(min = 1, max = 1000, message = "Page must be between 1 and 1000"))]
    pub page: u32,

    #[serde(default = "default_limit")]
    #[validate(range(min = 1, max = 100, message = "Limit must be between 1 and 100"))]
    pub limit: u32,

    #[serde(default)]
    #[validate(length(max = 100, message = "Search term too long"))]
    pub search: Option<String>,

    #[serde(default)]
    #[validate(length(max = 50, message = "Sort field name too long"))]
    pub sort_by: Option<String>,

    #[serde(default = "default_sort_order")]
    pub sort_order: SortOrder,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    Asc,
    Desc,
}

impl Default for SortOrder {
    fn default() -> Self {
        SortOrder::Desc
    }
}

// Resposta paginada
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub pagination: PaginationInfo,
}

#[derive(Debug, Serialize)]
pub struct PaginationInfo {
    pub current_page: u32,
    pub total_pages: u32,
    pub page_size: u32,
    pub total_items: u64,
    pub has_next: bool,
    pub has_previous: bool,
}

impl PaginationParams {
    pub fn validate(&mut self) {
        // Limitar página mínima
        if self.page == 0 {
            self.page = 1;
        }

        // Limitar tamanho da página
        if self.limit == 0 {
            self.limit = default_limit();
        } else if self.limit > 100 {
            self.limit = 100; // Máximo de 100 itens por página
        }
    }

    pub fn offset(&self) -> u32 {
        (self.page - 1) * self.limit
    }
}

impl<T> PaginatedResponse<T> {
    pub fn new(data: Vec<T>, page: u32, limit: u32, total_items: u64) -> Self {
        let total_pages = if total_items == 0 {
            1
        } else {
            ((total_items as f64) / (limit as f64)).ceil() as u32
        };

        let pagination = PaginationInfo {
            current_page: page,
            total_pages,
            page_size: limit,
            total_items,
            has_next: page < total_pages,
            has_previous: page > 1,
        };

        Self { data, pagination }
    }
}

fn default_page() -> u32 {
    1
}

fn default_limit() -> u32 {
    20
}

fn default_sort_order() -> SortOrder {
    SortOrder::Desc
}

// Filtros de busca para usuários
#[derive(Debug, Deserialize)]
pub struct UserFilters {
    pub name: Option<String>,
    pub email: Option<String>,
    pub created_after: Option<chrono::DateTime<chrono::Utc>>,
    pub created_before: Option<chrono::DateTime<chrono::Utc>>,
}

impl UserFilters {
    pub fn has_filters(&self) -> bool {
        self.name.is_some()
            || self.email.is_some()
            || self.created_after.is_some()
            || self.created_before.is_some()
    }
}
