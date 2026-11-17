mod handlers;

use crate::state::AppState;
use axum::{
    Router,
    routing::{get, put},
};
use serde::{Deserialize, Serialize};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users", get(handlers::list).post(handlers::create))
        .route("/users/{id}", get(handlers::get_one).patch(handlers::update))
        .route("/users/{id}/password", put(handlers::reset_password))
}

/// A full row from the `users` table.
///
/// Deliberately not `Serialize` or `Debug`: it holds `password_hash`, so it
/// must never be sent to a client or written to a log. Use [`UserResponse`].
#[derive(Clone, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub password_hash: String,
    pub is_admin: bool,
    pub must_change_password: bool,
    pub is_disabled: bool,
    pub locked_until: Option<String>,
    pub last_login_at: Option<String>,
    pub password_changed_at: Option<String>,
    pub created_by: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

/// The API's two roles. Stored as `users.is_admin` (1 = admin, 0 = viewer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Viewer,
}

impl Role {
    pub fn from_is_admin(is_admin: bool) -> Self {
        if is_admin { Role::Admin } else { Role::Viewer }
    }

    pub fn is_admin(self) -> bool {
        self == Role::Admin
    }
}

/// What the API returns for a user. Never includes the password hash.
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub role: Role,
    pub must_change_password: bool,
    pub is_disabled: bool,
    pub is_locked: bool,
    pub last_login_at: Option<String>,
    pub password_changed_at: Option<String>,
    pub created_by: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        let now = crate::time::now();
        Self {
            id: u.id,
            name: u.name,
            email: u.email,
            role: Role::from_is_admin(u.is_admin),
            must_change_password: u.must_change_password,
            is_disabled: u.is_disabled,
            is_locked: u.locked_until.is_some_and(|until| until > now),
            last_login_at: u.last_login_at,
            password_changed_at: u.password_changed_at,
            created_by: u.created_by,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

/// Trims and lowercases an email, with a basic sanity check. Real
/// verification would mean sending a mail, which is out of scope here.
pub fn normalize_email(email: &str) -> Result<String, crate::error::AppError> {
    let email = email.trim().to_lowercase();
    let valid = email.len() <= 254
        && !email.contains(char::is_whitespace)
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'));
    if valid {
        Ok(email)
    } else {
        Err(crate::error::AppError::BadRequest("invalid email address".into()))
    }
}

pub fn normalize_name(name: &str) -> Result<String, crate::error::AppError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(crate::error::AppError::BadRequest(
            "name must be 1 to 100 characters".into(),
        ));
    }
    Ok(name.to_string())
}
