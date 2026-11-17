use crate::error::{AppError, AppResult};
use anyhow::{Context, anyhow};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use std::sync::LazyLock;

pub const MIN_LEN: usize = 12;
/// Argon2 accepts very long input, but an upper bound stops someone from
/// making the server hash megabytes of data per request.
pub const MAX_LEN: usize = 128;

pub fn validate(password: &str) -> AppResult<()> {
    let len = password.chars().count();
    if len < MIN_LEN {
        return Err(AppError::BadRequest(format!(
            "password must be at least {MIN_LEN} characters"
        )));
    }
    if len > MAX_LEN {
        return Err(AppError::BadRequest(format!(
            "password must be at most {MAX_LEN} characters"
        )));
    }
    Ok(())
}

/// Hashes a password with Argon2id and returns a PHC string
/// (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`) ready to store.
///
/// Argon2 is deliberately slow (tens of milliseconds), so it runs on a
/// blocking thread instead of stalling the async runtime.
pub async fn hash(password: String) -> AppResult<String> {
    tokio::task::spawn_blocking(move || hash_blocking(&password))
        .await
        .context("password hashing task failed")?
}

fn hash_blocking(password: &str) -> AppResult<String> {
    let hash: PasswordHash = Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow!("password hashing failed: {e}"))?;
    Ok(hash.to_string())
}

/// A real Argon2 hash of a random password. Used when a login names an
/// email that doesn't exist, so that request takes as long as a real one
/// and response timing doesn't reveal which emails have accounts.
static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).expect("OS random number generator unavailable");
    let password: String = random.iter().map(|b| format!("{b:02x}")).collect();
    hash_blocking(&password).expect("hashing the dummy password failed")
});

/// Checks `password` against a stored PHC hash. With `None` it checks
/// against the dummy hash and always returns `false`.
pub async fn verify(password: String, stored_hash: Option<String>) -> AppResult<bool> {
    tokio::task::spawn_blocking(move || {
        let is_real = stored_hash.is_some();
        let stored = stored_hash.unwrap_or_else(|| DUMMY_HASH.clone());
        let parsed = PasswordHash::new(&stored)
            .map_err(|e| anyhow!("stored password hash is malformed: {e}"))?;
        let matches = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        Ok(is_real && matches)
    })
    .await
    .context("password verification task failed")?
}
