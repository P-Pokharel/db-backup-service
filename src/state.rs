use crate::config::Config;
use sqlx::SqlitePool;
use std::sync::Arc;

/// Shared by every request handler. Cheap to clone: the pool and the Arc are
/// both reference-counted handles.
#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub config: Arc<Config>,
}
