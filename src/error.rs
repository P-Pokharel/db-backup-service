use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

pub type AppResult<T> = Result<T, AppError>;

/// Every error a handler can return. Each variant maps to an HTTP status and
/// a JSON body: `{"error": "<code>", "message": "<text>"}`.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("authentication required")]
    Unauthorized,

    #[error("invalid email or password")]
    InvalidCredentials,

    #[error("you must change your password before doing anything else")]
    PasswordChangeRequired,

    #[error("admin access required")]
    Forbidden,

    #[error("{0}")]
    BadRequest(String),

    #[error("not found")]
    NotFound,

    #[error("{0}")]
    Conflict(String),

    #[error(transparent)]
    Database(#[from] sqlx::Error),

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            AppError::PasswordChangeRequired => (StatusCode::FORBIDDEN, "password_change_required"),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            AppError::Database(_) | AppError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        };

        // Log the real cause of server errors, but never send it to the client.
        let message = match &self {
            AppError::Database(e) => {
                tracing::error!(error = %e, "database error");
                "internal server error".to_string()
            }
            AppError::Internal(e) => {
                tracing::error!(error = ?e, "internal error");
                "internal server error".to_string()
            }
            other => other.to_string(),
        };

        let mut response = (status, Json(json!({ "error": code, "message": message }))).into_response();
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
        }
        response
    }
}
