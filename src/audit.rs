use sqlx::SqliteConnection;

/// Appends a row to `audit_log`. Takes a connection (usually `&mut *tx`) so
/// the audit entry commits or rolls back together with the change it records.
///
/// `details` must never contain secrets such as passwords or tokens.
pub async fn record(
    conn: &mut SqliteConnection,
    actor_id: Option<i64>,
    action: &str,
    target: Option<(&str, i64)>,
    details: Option<serde_json::Value>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (user_id, action, target_type, target_id, details)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(actor_id)
    .bind(action)
    .bind(target.map(|(kind, _)| kind))
    .bind(target.map(|(_, id)| id))
    .bind(details.map(|d| d.to_string()))
    .execute(conn)
    .await?;
    Ok(())
}
