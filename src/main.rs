mod audit;
mod auth;
mod bootstrap;
mod config;
mod error;
mod state;
mod time;
mod users;

use axum::{Router, routing::get};
use config::Config;
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use state::AppState;
use std::{str::FromStr, sync::Arc, time::Duration};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let config = Config::from_env()?;

    let opts = SqliteConnectOptions::from_str(&config.database_url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);
    let db = SqlitePoolOptions::new().connect_with(opts).await?;

    sqlx::migrate!("./migrations").run(&db).await?;
    bootstrap::ensure_first_admin(&db).await?;
    spawn_expired_session_cleanup(db.clone());

    let state = AppState {
        db,
        config: Arc::new(config),
    };

    let api = Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(auth::router())
        .merge(users::router());
    let app = Router::new().nest("/api", api).with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(state.config.bind_addr).await?;
    tracing::info!("listening on http://{}", state.config.bind_addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Expired sessions are already rejected by the auth extractors; this just
/// stops the table from growing forever.
fn spawn_expired_session_cleanup(db: SqlitePool) {
    tokio::spawn(async move {
        let mut every_hour = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            every_hour.tick().await;
            match sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
                .bind(time::now())
                .execute(&db)
                .await
            {
                Ok(r) if r.rows_affected() > 0 => {
                    tracing::info!(removed = r.rows_affected(), "deleted expired sessions")
                }
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "failed to delete expired sessions"),
            }
        }
    });
}

/// Resolves on Ctrl+C or SIGTERM (what `docker stop` sends), letting
/// in-flight requests finish before the process exits.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to listen for Ctrl+C");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to listen for SIGTERM")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutting down");
}
