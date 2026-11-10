//! HTTP error type shared by every API handler.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use quark_core::domain::{ProviderError, ProviderErrorCategory};
use serde_json::json;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": {
                    "code": self.code,
                    "message": self.message,
                }
            })),
        )
            .into_response()
    }
}

impl From<ProviderError> for ApiError {
    fn from(error: ProviderError) -> Self {
        let status = match error.category {
            ProviderErrorCategory::Authentication => StatusCode::UNAUTHORIZED,
            ProviderErrorCategory::Permission => StatusCode::FORBIDDEN,
            ProviderErrorCategory::RateLimit => StatusCode::TOO_MANY_REQUESTS,
            ProviderErrorCategory::NotFound => StatusCode::NOT_FOUND,
            ProviderErrorCategory::Conflict => StatusCode::CONFLICT,
            ProviderErrorCategory::Unsupported => StatusCode::NOT_IMPLEMENTED,
            ProviderErrorCategory::InvalidRequest => StatusCode::BAD_REQUEST,
            ProviderErrorCategory::Network
            | ProviderErrorCategory::RemoteUnavailable
            | ProviderErrorCategory::InvalidResponse => StatusCode::BAD_GATEWAY,
            ProviderErrorCategory::Cancelled => StatusCode::CONFLICT,
        };
        Self::new(status, error.category.as_str(), error.message)
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        Self::internal(format!("{error:#}"))
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(error: rusqlite::Error) -> Self {
        Self::internal(format!("database error: {error}"))
    }
}

impl From<std::io::Error> for ApiError {
    fn from(error: std::io::Error) -> Self {
        Self::internal(format!("filesystem error: {error}"))
    }
}
