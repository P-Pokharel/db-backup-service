use anyhow::anyhow;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Creates a new session token. Returns `(token, sha256_of_token)`: the token
/// goes to the client once, and only the hash is stored in `sessions`. A leaked
/// database copy therefore contains no usable tokens.
pub fn generate() -> anyhow::Result<(String, Vec<u8>)> {
    let mut bytes = [0u8; 32]; // 256 bits of randomness
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("OS random number generator failed: {e}"))?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash(&token);
    Ok((token, hash))
}

/// The value stored in `sessions.token_hash`. Plain SHA-256 is enough here
/// (unlike passwords) because the token is already 256 random bits.
pub fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}
