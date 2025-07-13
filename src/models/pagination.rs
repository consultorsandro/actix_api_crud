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

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    #[test]
    fn test_pagination_params_defaults() {
        let params = PaginationParams {
            page: default_page(),
            limit: default_limit(),
            search: None,
            sort_by: None,
            sort_order: default_sort_order(),
        };

        assert_eq!(params.page, 1);
        assert_eq!(params.limit, 20);
        assert!(matches!(params.sort_order, SortOrder::Desc));
    }

    #[test]
    fn test_pagination_params_validation_valid() {
        let params = PaginationParams {
            page: 1,
            limit: 10,
            search: Some("test".to_string()),
            sort_by: Some("name".to_string()),
            sort_order: SortOrder::Asc,
        };

        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_pagination_params_validation_invalid_page() {
        let params = PaginationParams {
            page: 0, // Invalid
            limit: 10,
            search: None,
            sort_by: None,
            sort_order: SortOrder::Asc,
        };

        let validation_result = params.validate();
        assert!(validation_result.is_err());

        let errors = validation_result.unwrap_err();
        assert!(errors.field_errors().contains_key("page"));
    }

    #[test]
    fn test_pagination_params_validation_invalid_limit() {
        let params = PaginationParams {
            page: 1,
            limit: 101, // Too high
            search: None,
            sort_by: None,
            sort_order: SortOrder::Asc,
        };

        let validation_result = params.validate();
        assert!(validation_result.is_err());

        let errors = validation_result.unwrap_err();
        assert!(errors.field_errors().contains_key("limit"));
    }

    #[test]
    fn test_pagination_params_offset_calculation() {
        let params = PaginationParams {
            page: 3,
            limit: 10,
            search: None,
            sort_by: None,
            sort_order: SortOrder::Asc,
        };

        assert_eq!(params.offset(), 20); // (3-1) * 10 = 20
    }

    #[test]
    fn test_pagination_params_validate_method() {
        let mut params = PaginationParams {
            page: 0,  // Will be corrected to 1
            limit: 0, // Will be corrected to default
            search: None,
            sort_by: None,
            sort_order: SortOrder::Asc,
        };

        // Use o método personalizado de validação que modifica os valores
        PaginationParams::validate(&mut params);

        assert_eq!(params.page, 1);
        assert_eq!(params.limit, default_limit());
    }

    #[test]
    fn test_pagination_params_validate_limit_too_high() {
        let mut params = PaginationParams {
            page: 1,
            limit: 150, // Will be corrected to 100
            search: None,
            sort_by: None,
            sort_order: SortOrder::Asc,
        };

        // Use o método personalizado de validação que modifica os valores
        PaginationParams::validate(&mut params);

        assert_eq!(params.limit, 100);
    }

    #[test]
    fn test_paginated_response_creation() {
        let data = vec!["item1", "item2", "item3"];
        let response = PaginatedResponse::new(data.clone(), 1, 10, 25);

        assert_eq!(response.data, data);
        assert_eq!(response.pagination.current_page, 1);
        assert_eq!(response.pagination.page_size, 10);
        assert_eq!(response.pagination.total_items, 25);
        assert_eq!(response.pagination.total_pages, 3); // ceil(25/10) = 3
        assert!(!response.pagination.has_previous);
        assert!(response.pagination.has_next);
    }

    #[test]
    fn test_paginated_response_last_page() {
        let data = vec!["item1"];
        let response = PaginatedResponse::new(data, 3, 10, 25);

        assert_eq!(response.pagination.current_page, 3);
        assert_eq!(response.pagination.total_pages, 3);
        assert!(response.pagination.has_previous);
        assert!(!response.pagination.has_next);
    }

    #[test]
    fn test_paginated_response_empty_data() {
        let data: Vec<String> = vec![];
        let response = PaginatedResponse::new(data, 1, 10, 0);

        assert_eq!(response.pagination.current_page, 1);
        assert_eq!(response.pagination.total_pages, 1);
        assert_eq!(response.pagination.total_items, 0);
        assert!(!response.pagination.has_previous);
        assert!(!response.pagination.has_next);
    }

    #[test]
    fn test_sort_order_default() {
        let default_order = SortOrder::default();
        assert!(matches!(default_order, SortOrder::Desc));
    }

    #[test]
    fn test_user_filters_has_filters_true() {
        let filters = UserFilters {
            name: Some("John".to_string()),
            email: None,
            created_after: None,
            created_before: None,
        };

        assert!(filters.has_filters());
    }

    #[test]
    fn test_user_filters_has_filters_false() {
        let filters = UserFilters {
            name: None,
            email: None,
            created_after: None,
            created_before: None,
        };

        assert!(!filters.has_filters());
    }
}
