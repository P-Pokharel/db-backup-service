mod extract;
mod handlers;
pub mod password;
pub mod token;

#[allow(unused_imports)]
pub use extract::{AdminUser, AuthUser, SessionUser};

use crate::state::AppState;
use axum::{
    Router,
    routing::{get, post},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(handlers::login))
        .route("/auth/logout", post(handlers::logout))
        .route("/auth/me", get(handlers::me))
        .route("/auth/password", post(handlers::change_password))
}
