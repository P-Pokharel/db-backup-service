//! Creates the first admin. Since only admins can create users, someone has
//! to exist before the API is usable.

use crate::{audit, auth::password, users};
use sqlx::SqlitePool;
use std::env;

/// If the `users` table is empty and `BOOTSTRAP_ADMIN_EMAIL` and
/// `BOOTSTRAP_ADMIN_PASSWORD` are set, creates an admin from them.
///
/// The admin must change that password on first login, so the value in the
/// environment stops being useful right away. Once any user exists this does
/// nothing, and the variables can be removed.
pub async fn ensure_first_admin(db: &SqlitePool) -> anyhow::Result<()> {
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(db)
        .await?;
    if user_count > 0 {
        return Ok(());
    }

    let (Ok(email), Ok(password)) = (
        env::var("BOOTSTRAP_ADMIN_EMAIL"),
        env::var("BOOTSTRAP_ADMIN_PASSWORD"),
    ) else {
        tracing::warn!(
            "no users exist yet; set BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD \
             and restart to create the first admin"
        );
        return Ok(());
    };
    let name = env::var("BOOTSTRAP_ADMIN_NAME").unwrap_or_else(|_| "Admin".into());

    let name = users::normalize_name(&name)?;
    let email = users::normalize_email(&email)?;
    password::validate(&password)?;
    let password_hash = password::hash(password).await?;

    let mut tx = db.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO users (name, email, password_hash, is_admin, must_change_password)
         VALUES (?, ?, ?, 1, 1)
         RETURNING id",
    )
    .bind(&name)
    .bind(&email)
    .bind(&password_hash)
    .fetch_one(&mut *tx)
    .await?;
    audit::record(&mut tx, None, "user.bootstrap_admin", Some(("user", id)), None).await?;
    tx.commit().await?;

    tracing::info!(%email, "created the first admin; log in and change its password");
    Ok(())
}
