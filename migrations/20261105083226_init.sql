-- Add migration script here
-- 0001_init.sql — initial schema for the DB backup service.
--
-- Conventions
--   * STRICT tables: SQLite enforces column types (needs SQLite >= 3.37).
--   * Booleans are INTEGER 0/1 (SQLite has no BOOLEAN type).
--   * Timestamps are UTC TEXT in ISO 8601, e.g. '2026-11-05T06:30:00Z'.
--     sqlx maps these to chrono::DateTime<Utc>.
--   * The app must run `PRAGMA foreign_keys = ON;` on every connection
--     (sqlx: SqliteConnectOptions::foreign_keys(true), on by default).
--   * updated_at is set by the app on every UPDATE.

------------------------------------------------------------------------------
-- Users and sessions
------------------------------------------------------------------------------

CREATE TABLE users (
    id                    INTEGER PRIMARY KEY,
    name                  TEXT    NOT NULL,
    email                 TEXT    NOT NULL COLLATE NOCASE UNIQUE,  -- login id
    password_hash         TEXT    NOT NULL,                        -- Argon2id PHC string
    is_admin              INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    must_change_password  INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0, 1)),
    is_disabled           INTEGER NOT NULL DEFAULT 0 CHECK (is_disabled IN (0, 1)),
    failed_login_count    INTEGER NOT NULL DEFAULT 0,
    locked_until          TEXT,                                    -- brute-force lockout
    last_login_at         TEXT,
    password_changed_at   TEXT,
    created_by            INTEGER REFERENCES users(id),            -- NULL for the bootstrap admin
    created_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
) STRICT;

-- Opaque random login tokens; only their SHA-256 is stored.
CREATE TABLE sessions (
    token_hash    BLOB    PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at    TEXT    NOT NULL,
    last_seen_at  TEXT
) STRICT, WITHOUT ROWID;

CREATE INDEX sessions_user_id    ON sessions(user_id);
CREATE INDEX sessions_expires_at ON sessions(expires_at);

------------------------------------------------------------------------------
-- Database servers to back up
------------------------------------------------------------------------------

-- One row per database *server*. Which database on it gets backed up is
-- chosen per job, so one server can have many jobs.
CREATE TABLE db_connections (
    id            INTEGER PRIMARY KEY,
    name          TEXT    NOT NULL COLLATE NOCASE UNIQUE,          -- e.g. "azure-prod-pg"
    engine        TEXT    NOT NULL CHECK (engine IN ('postgres', 'mysql', 'mongodb')),
    host          TEXT,
    port          INTEGER CHECK (port BETWEEN 1 AND 65535),
    username      TEXT,
    password_enc  BLOB,                                            -- nonce || ciphertext, master-key encrypted
    uri_enc       BLOB,                                            -- optional full URI (e.g. mongodb+srv://...), encrypted
    ssl_mode      TEXT    NOT NULL DEFAULT 'require'
                  CHECK (ssl_mode IN ('disable', 'prefer', 'require', 'verify-ca', 'verify-full')),
    is_disabled   INTEGER NOT NULL DEFAULT 0 CHECK (is_disabled IN (0, 1)),
    created_by    INTEGER NOT NULL REFERENCES users(id),
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    -- Either a full URI, or host + port + username.
    CHECK (uri_enc IS NOT NULL OR (host IS NOT NULL AND port IS NOT NULL AND username IS NOT NULL))
) STRICT;

------------------------------------------------------------------------------
-- Backup jobs and their run history
------------------------------------------------------------------------------

CREATE TABLE backup_jobs (
    id              INTEGER PRIMARY KEY,
    name            TEXT    NOT NULL COLLATE NOCASE UNIQUE,
    connection_id   INTEGER NOT NULL REFERENCES db_connections(id) ON DELETE RESTRICT,
    database_name   TEXT    NOT NULL,
    run_at          TEXT    NOT NULL                               -- daily local time, 'HH:MM'
                    CHECK (run_at GLOB '[0-2][0-9]:[0-5][0-9]' AND run_at < '24:00'),
    timezone        TEXT    NOT NULL,                              -- IANA name, e.g. 'Asia/Kathmandu'
    is_enabled      INTEGER NOT NULL DEFAULT 1 CHECK (is_enabled IN (0, 1)),
    paused_until    TEXT,                                          -- postpone: skip runs before this
    next_run_at     TEXT,                                          -- maintained by the scheduler (UTC)
    retention_days  INTEGER NOT NULL DEFAULT 14 CHECK (retention_days > 0),
    created_by      INTEGER NOT NULL REFERENCES users(id),
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE (connection_id, database_name)
) STRICT;

-- The scheduler's main query: "which enabled jobs are due?"
CREATE INDEX backup_jobs_due ON backup_jobs(next_run_at) WHERE is_enabled = 1;

CREATE TABLE job_history (
    id             INTEGER PRIMARY KEY,
    job_id         INTEGER NOT NULL REFERENCES backup_jobs(id) ON DELETE RESTRICT,
    trigger        TEXT    NOT NULL CHECK (trigger IN ('scheduled', 'manual')),
    triggered_by   INTEGER REFERENCES users(id),                   -- set only for manual runs
    scheduled_for  TEXT,                                           -- the slot a scheduled run was for
    status         TEXT    NOT NULL DEFAULT 'running'
                   CHECK (status IN ('running', 'succeeded', 'failed', 'skipped')),
    started_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    finished_at    TEXT,
    duration_ms    INTEGER CHECK (duration_ms >= 0),
    file_path      TEXT,                                           -- local encrypted file
    size_bytes     INTEGER CHECK (size_bytes >= 0),
    sha256         TEXT,
    error          TEXT,                                           -- short summary, goes in the email
    stderr_tail    TEXT,                                           -- last lines of dump tool stderr
    notified_at    TEXT,                                           -- when the failure email was sent

    CHECK ((trigger = 'manual')    = (triggered_by  IS NOT NULL)),
    CHECK ((trigger = 'scheduled') = (scheduled_for IS NOT NULL)),
    CHECK ((status  = 'running')   = (finished_at   IS NULL)),
    CHECK (status <> 'failed' OR error IS NOT NULL)
) STRICT;

CREATE INDEX job_history_job_started ON job_history(job_id, started_at DESC);
CREATE INDEX job_history_started     ON job_history(started_at DESC);

-- At most one running backup per job (manual and scheduled can't overlap).
CREATE UNIQUE INDEX job_history_one_running
    ON job_history(job_id) WHERE status = 'running';

-- A scheduled slot fires at most once, even if the service restarts mid-run.
CREATE UNIQUE INDEX job_history_one_per_slot
    ON job_history(job_id, scheduled_for) WHERE scheduled_for IS NOT NULL;

------------------------------------------------------------------------------
-- Audit log: who changed what
------------------------------------------------------------------------------

CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER REFERENCES users(id),                     -- NULL = system
    action       TEXT    NOT NULL,                                 -- e.g. 'job.run', 'job.pause', 'user.create'
    target_type  TEXT,                                             -- 'user', 'connection', 'job'
    target_id    INTEGER,
    details      TEXT,                                             -- JSON, never secrets
    at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
) STRICT;

CREATE INDEX audit_log_at ON audit_log(at DESC);