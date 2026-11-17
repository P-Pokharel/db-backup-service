//! Axum extractors that enforce authentication and roles.
//!
//! Put one in a handler's arguments and the handler only runs if the check
//! passes; otherwise the request gets a 401 or 403 automatically.
//!
//! | Extractor     | Requires                                                 |
//! |---------------|----------------------------------------------------------|
//! | `SessionUser` | a valid, unexpired session for an enabled user           |
//! | `AuthUser`    | the above, and no pending forced password change         |
//! | `AdminUser`   | the above, and the user is an admin                      |
//!
//! Use `AuthUser` for "viewer can see this" routes, `AdminUser` for anything
//! that changes data. `SessionUser` is only for the few routes a user with a
//! temporary password still needs (me, change password, logout).

use super::token;
use crate::{error::AppError, state::AppState, time, users::User};
use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
};
use chrono::{Duration, Utc};

pub struct SessionUser {
    pub user: User,
    /// Hash of the token used for this request, so logout and password
    /// changes know which session is the current one.
    pub token_hash: Vec<u8>,
}

pub struct AuthUser(pub User);

pub struct AdminUser(pub User);

impl FromRequestParts<AppState> for SessionUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .ok_or(AppError::Unauthorized)?;

        let token_hash = token::hash(token);
        let now = time::now();

        let user: User = sqlx::query_as(
            "SELECT u.* FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = ? AND s.expires_at > ? AND u.is_disabled = 0",
        )
        .bind(&token_hash)
        .bind(&now)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::Unauthorized)?;

        // Record activity, but write at most once a minute per session
        // rather than on every request.
        let a_minute_ago = time::format(Utc::now() - Duration::minutes(1));
        sqlx::query(
            "UPDATE sessions SET last_seen_at = ?
             WHERE token_hash = ? AND (last_seen_at IS NULL OR last_seen_at < ?)",
        )
        .bind(&now)
        .bind(&token_hash)
        .bind(&a_minute_ago)
        .execute(&state.db)
        .await?;

        Ok(SessionUser { user, token_hash })
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let SessionUser { user, .. } = SessionUser::from_request_parts(parts, state).await?;
        if user.must_change_password {
            return Err(AppError::PasswordChangeRequired);
        }
        Ok(AuthUser(user))
    }
}

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let AuthUser(user) = AuthUser::from_request_parts(parts, state).await?;
        if !user.is_admin {
            return Err(AppError::Forbidden);
        }
        Ok(AdminUser(user))
    }
}
