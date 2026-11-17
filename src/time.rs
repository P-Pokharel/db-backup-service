use chrono::{DateTime, Utc};

/// The timestamp format used in every TEXT time column, matching the
/// schema's `strftime('%Y-%m-%dT%H:%M:%SZ', 'now')` defaults.
///
/// Because it is fixed-width UTC, comparing two of these strings
/// (in SQL or in Rust) gives the same answer as comparing the times.
const FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

pub fn format(t: DateTime<Utc>) -> String {
    t.format(FORMAT).to_string()
}

pub fn now() -> String {
    format(Utc::now())
}
