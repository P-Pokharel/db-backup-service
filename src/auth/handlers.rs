use super::{SessionUser, password, token};
use crate::{
    audit,
    error::{AppError, AppResult},
    state::AppState,
    time,
    users::{User, UserResponse},
};
use axum::{Json, extract::State, http::StatusCode};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// After this many wrong passwords in a row, the account is locked...
const MAX_FAILED_LOGINS: i64 = 5;
/// ...for this long.
const LOCKOUT_MINUTES: i64 = 15;

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    token: String,
    expires_at: String,
    user: UserResponse,
}

/// `POST /api/auth/login`
///
/// Every failure (unknown email, wrong password, disabled or locked account)
/// returns the same 401, so the response doesn't reveal whether an email has
/// an account or what state it's in.
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    let email = req.email.trim().to_lowercase();
    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE email = ?")
        .bind(&email)
        .fetch_optional(&state.db)
        .await?;

    // Always run Argon2, even for an unknown email, so timing is the same.
    let password_ok = password::verify(req.password, user.as_ref().map(|u| u.password_hash.clone())).await?;

    let Some(user) = user else {
        return Err(AppError::InvalidCredentials);
    };
    let now = time::now();

    if user.is_disabled {
        return Err(AppError::InvalidCredentials);
    }
    if user.locked_until.as_deref().is_some_and(|until| until > now.as_str()) {
        // Don't count attempts during a lockout, or it would never end.
        return Err(AppError::InvalidCredentials);
    }

    if !password_ok {
        record_failed_login(&state, &user).await?;
        return Err(AppError::InvalidCredentials);
    }

    let (token, token_hash) = token::generate()?;
    let expires_at = time::format(Utc::now() + Duration::hours(state.config.session_ttl_hours));

    let mut tx = state.db.begin().await?;
    let user: User = sqlx::query_as(
        "UPDATE users
         SET failed_login_count = 0, locked_until = NULL, last_login_at = ?
         WHERE id = ?
         RETURNING *",
    )
    .bind(&now)
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(&token_hash)
        .bind(user.id)
        .bind(&expires_at)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    tracing::info!(user_id = user.id, "user logged in");
    Ok(Json(LoginResponse {
        token,
        expires_at,
        user: user.into(),
    }))
}

async fn record_failed_login(state: &AppState, user: &User) -> AppResult<()> {
    let lock_until = time::format(Utc::now() + Duration::minutes(LOCKOUT_MINUTES));

    // In an UPDATE, every expression on the right reads the row's *old*
    // values, so `failed_login_count + 1` is the new count in each CASE.
    let mut tx = state.db.begin().await?;
    let locked: bool = sqlx::query_scalar(
        "UPDATE users SET
           locked_until = CASE WHEN failed_login_count + 1 >= ?1 THEN ?2 ELSE locked_until END,
           failed_login_count = CASE WHEN failed_login_count + 1 >= ?1 THEN 0 ELSE failed_login_count + 1 END
         WHERE id = ?3
         RETURNING locked_until = ?2",
    )
    .bind(MAX_FAILED_LOGINS)
    .bind(&lock_until)
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await?;

    if locked {
        audit::record(
            &mut tx,
            None,
            "user.lockout",
            Some(("user", user.id)),
            Some(json!({ "locked_until": lock_until })),
        )
        .await?;
        tracing::warn!(user_id = user.id, %lock_until, "account locked after repeated failed logins");
    }
    tx.commit().await?;
    Ok(())
}

/// `POST /api/auth/logout`: ends the current session only.
pub async fn logout(State(state): State<AppState>, session: SessionUser) -> AppResult<StatusCode> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
        .bind(&session.token_hash)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/auth/me`: the logged-in user. Works even while a password
/// change is pending, so a client can see `must_change_password`.
pub async fn me(session: SessionUser) -> Json<UserResponse> {
    Json(session.user.into())
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

/// `POST /api/auth/password`: any user changes their own password.
///
/// Clears `must_change_password` and logs out every *other* session of this
/// user (e.g. a stolen token), keeping the one making this request.
pub async fn change_password(
    State(state): State<AppState>,
    session: SessionUser,
    Json(req): Json<ChangePasswordRequest>,
) -> AppResult<StatusCode> {
    password::validate(&req.new_password)?;
    if req.new_password == req.current_password {
        return Err(AppError::BadRequest(
            "new password must be different from the current one".into(),
        ));
    }
    if !password::verify(req.current_password, Some(session.user.password_hash.clone())).await? {
        return Err(AppError::BadRequest("current password is incorrect".into()));
    }

    let new_hash = password::hash(req.new_password).await?;
    let now = time::now();
    let user_id = session.user.id;

    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE users
         SET password_hash = ?, must_change_password = 0, password_changed_at = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(&new_hash)
    .bind(&now)
    .bind(&now)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?")
        .bind(user_id)
        .bind(&session.token_hash)
        .execute(&mut *tx)
        .await?;
    audit::record(&mut tx, Some(user_id), "user.password_change", Some(("user", user_id)), None).await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}
