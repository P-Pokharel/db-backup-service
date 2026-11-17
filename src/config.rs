use anyhow::Context;
use std::{env, net::SocketAddr};

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: SocketAddr,
    pub session_ttl_hours: i64,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            database_url: env::var("DATABASE_URL").context("DATABASE_URL must be set")?,
            bind_addr: env::var("BIND_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8080".into())
                .parse()
                .context("BIND_ADDR must look like 0.0.0.0:8080")?,
            session_ttl_hours: env::var("SESSION_TTL_HOURS")
                .unwrap_or_else(|_| "12".into())
                .parse()
                .context("SESSION_TTL_HOURS must be a whole number")?,
        })
    }
}
