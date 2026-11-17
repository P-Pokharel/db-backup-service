//! Admin-only user management. Every handler takes `AdminUser`, so viewers
//! get 403 and anonymous callers get 401 before any of this code runs.

use super::{Role, User, UserResponse, normalize_email, normalize_name};
use crate::{
    audit,
    auth::{AdminUser, password},
    error::{AppError, AppResult},
    state::AppState,
    time,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sqlx::SqliteConnection;

/// `GET /api/users`
pub async fn list(
    State(state): State<AppState>,
    _admin: AdminUser
) -> AppResult<Json<Vec<UserResponse>>> {
    let users: Vec<User> = sqlx::query_as("SELECT * FROM users ORDER BY id")
        .fetch_all(&state.db)
        .await?;
    Ok(Json(users.into_iter().map(UserResponse::from).collect()))
}

/// `GET /api/users/{id}`
pub async fn get_one(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<i64>,
) -> AppResult<Json<UserResponse>> {
    let user: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(user.into()))
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    name: String,
    email: String,
    password: String,
    role: Role,
}

/// `POST /api/users`: create an admin or a viewer.
///
/// The new user must change the admin-chosen password on first login.
pub async fn create(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(req): Json<CreateUserRequest>,
) -> AppResult<(StatusCode, Json<UserResponse>)> {
    let name = normalize_name(&req.name)?;
    let email = normalize_email(&req.email)?;
    password::validate(&req.password)?;
    let password_hash = password::hash(req.password).await?;

    let mut tx = state.db.begin().await?;
    let user: User = sqlx::query_as(
        "INSERT INTO users (name, email, password_hash, is_admin, must_change_password, created_by)
         VALUES (?, ?, ?, ?, 1, ?)
         RETURNING *",
    )
    .bind(&name)
    .bind(&email)
    .bind(&password_hash)
    .bind(req.role.is_admin())
    .bind(admin.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e.as_database_error() {
        Some(db) if db.is_unique_violation() => {
            AppError::Conflict("a user with this email already exists".into())
        }
        _ => e.into(),
    })?;
    audit::record(
        &mut tx,
        Some(admin.id),
        "user.create",
        Some(("user", user.id)),
        Some(json!({ "email": email, "role": req.role })),
    )
    .await?;
    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(user.into())))
}

/// Every field is optional; only the ones present are changed.
#[derive(Deserialize)]
pub struct UpdateUserRequest {
    name: Option<String>,
    role: Option<Role>,
    is_disabled: Option<bool>,
}

/// `PATCH /api/users/{id}`: rename, change role, or disable/enable a user.
pub async fn update(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<i64>,
    Json(req): Json<UpdateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    let name = req.name.as_deref().map(normalize_name).transpose()?;
    if name.is_none() && req.role.is_none() && req.is_disabled.is_none() {
        return Err(AppError::BadRequest(
            "provide at least one of: name, role, is_disabled".into(),
        ));
    }

    // IMMEDIATE takes the write lock up front, so two admins can't both pass
    // the "last admin" check below at the same moment.
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let current: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::NotFound)?;

    let new_is_admin = req.role.map_or(current.is_admin, Role::is_admin);
    let new_is_disabled = req.is_disabled.unwrap_or(current.is_disabled);
    let was_active_admin = current.is_admin && !current.is_disabled;
    let is_active_admin = new_is_admin && !new_is_disabled;
    if was_active_admin && !is_active_admin && !another_active_admin_exists(&mut tx, id).await? {
        return Err(AppError::Conflict(
            "cannot demote or disable the last active admin".into(),
        ));
    }

    let updated: User = sqlx::query_as(
        "UPDATE users SET name = ?, is_admin = ?, is_disabled = ?, updated_at = ?
         WHERE id = ?
         RETURNING *",
    )
    .bind(name.as_deref().unwrap_or(&current.name))
    .bind(new_is_admin)
    .bind(new_is_disabled)
    .bind(time::now())
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;

    // A disabled user is logged out everywhere immediately.
    if new_is_disabled && !current.is_disabled {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }

    let mut changes = Map::new();
    if let Some(n) = &name {
        changes.insert("name".into(), json!(n));
    }
    if let Some(r) = req.role {
        changes.insert("role".into(), json!(r));
    }
    if let Some(d) = req.is_disabled {
        changes.insert("is_disabled".into(), json!(d));
    }
    audit::record(&mut tx, Some(admin.id), "user.update", Some(("user", id)), Some(Value::Object(changes))).await?;
    tx.commit().await?;

    Ok(Json(updated.into()))
}

async fn another_active_admin_exists(conn: &mut SqliteConnection, excluding_id: i64) -> AppResult<bool> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users WHERE is_admin = 1 AND is_disabled = 0 AND id <> ?)",
    )
    .bind(excluding_id)
    .fetch_one(conn)
    .await?;
    Ok(exists)
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    new_password: String,
}

/// `PUT /api/users/{id}/password`: an admin sets a new temporary password
/// for someone else (e.g. they forgot theirs). It also unlocks the account,
/// logs them out everywhere, and forces a change at next login.
pub async fn reset_password(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<i64>,
    Json(req): Json<ResetPasswordRequest>,
) -> AppResult<StatusCode> {
    if id == admin.id {
        return Err(AppError::BadRequest(
            "use POST /api/auth/password to change your own password".into(),
        ));
    }
    password::validate(&req.new_password)?;
    let password_hash = password::hash(req.new_password).await?;
    let now = time::now();

    let mut tx = state.db.begin().await?;
    let result = sqlx::query(
        "UPDATE users
         SET password_hash = ?, must_change_password = 1, failed_login_count = 0,
             locked_until = NULL, password_changed_at = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(&password_hash)
    .bind(&now)
    .bind(&now)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit::record(&mut tx, Some(admin.id), "user.password_reset", Some(("user", id)), None).await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}
