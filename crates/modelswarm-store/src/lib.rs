//! Node-local persistence: SQLite via rusqlite, embedded migrations, and
//! typed access for installation state, license acceptances, EWMA
//! observations, and job accounting.
//!
//! Privacy is a structural property of the schema, not a convention: no
//! table has a column for prompts, completions, conversations, tokens, or
//! secrets (AGENTS.md hard constraint 5, `docs/privacy.md`). The
//! integration test in `tests/store.rs` enumerates every table/column via
//! `sqlite_master`/`PRAGMA table_info` and fails on any forbidden name, so a
//! future migration cannot reintroduce one silently.
//!
//! Job rows keep only timings, outcome, and the usage digest of a job
//! receipt (msp-v1 §7) — never request content.

use std::fmt;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Store errors. Database failures surface as [`StoreError::Sqlite`].
#[derive(Debug)]
pub enum StoreError {
    /// A SQLite operation failed.
    Sqlite(rusqlite::Error),
    /// A caller tried to persist a metric key outside the closed
    /// observation vocabulary (empty, longer than 64 bytes, or containing
    /// characters other than `a-z`, `0-9`, `_`). The key itself is
    /// deliberately NOT carried in the error — an unknown key is suspect
    /// content by definition and must never be echoed into logs.
    InvalidMetricKey { metric_len: usize },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Sqlite(e) => write!(f, "sqlite error: {e}"),
            StoreError::InvalidMetricKey { metric_len } => write!(
                f,
                "invalid metric key (length {metric_len}): empty, >64 bytes, or characters \
                 outside [a-z0-9_] — the observation-key vocabulary is closed"
            ),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sqlite(e)
    }
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, StoreError>;

/// Embedded migrations, applied in order by schema version
/// (`PRAGMA user_version`). Append-only: never edit an applied entry, only
/// add `(next_version, sql)` at the end.
const MIGRATIONS: &[(i64, &str)] = &[
    (
        1,
        r#"
CREATE TABLE IF NOT EXISTS installations (
    id         TEXT PRIMARY KEY,
    pub_key    BLOB NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS license_acceptances (
    installation_id TEXT NOT NULL,
    profile_id      TEXT NOT NULL,
    accepted_at     TEXT NOT NULL,
    PRIMARY KEY (installation_id, profile_id)
);

CREATE TABLE IF NOT EXISTS ewma_observations (
    peer_id    TEXT NOT NULL,
    metric     TEXT NOT NULL,
    value      REAL NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (peer_id, metric)
);

CREATE TABLE IF NOT EXISTS job_accounting (
    request_id   TEXT PRIMARY KEY,
    peer_id      TEXT NOT NULL,
    profile_id   TEXT NOT NULL,
    outcome      TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    ended_at     TEXT NOT NULL,
    usage_digest TEXT NOT NULL
);
"#,
    ),
    (
        2,
        r#"
CREATE TABLE IF NOT EXISTS artifacts (
    profile_id  TEXT PRIMARY KEY,
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    bytes       INTEGER NOT NULL,
    state       TEXT NOT NULL,
    verified_at TEXT NOT NULL
);
"#,
    ),
    // F15 (measurement plumbing): per-(peer, profile) EWMA observations —
    // completion distributions keyed by the exact profile the measurements
    // were taken against. ADDITIVE and backward-compatible: peer-scoped
    // metrics keep riding `ewma_observations` untouched; existing rows and
    // callers are unaffected. Values are timings/rates/counts only — the
    // structural privacy audit in tests/store.rs covers this table too.
    (
        3,
        r#"
CREATE TABLE IF NOT EXISTS peer_metric_observations (
    peer_id    TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    metric     TEXT NOT NULL,
    value      REAL NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (peer_id, profile_id, metric)
);
"#,
    ),
    // 9.6 pass-1 harness (Scheduler Scientist): per-(peer, profile)
    // speculative-acceptance EWMAs. ADDITIVE, same pattern as migration 3
    // (coordinator-sanctioned store touch; see
    // docs/reviews/handoff-scheduler-scientist-2026-10-09.md). Counter
    // columns (rounds / accepted / proposed) persist alongside the EWMA so
    // a restarted process resumes the aggregate, not just the smoothed
    // value. Counts of drafted tokens only — no token text, no prompts
    // (structural privacy audit in tests/store.rs enumerates this table
    // too).
    (
        4,
        r#"
CREATE TABLE IF NOT EXISTS speculative_acceptance_observations (
    peer_id        TEXT NOT NULL,
    profile_id     TEXT NOT NULL,
    acceptance_ewma REAL NOT NULL,
    rounds         INTEGER NOT NULL,
    accepted_count INTEGER NOT NULL,
    proposed_count INTEGER NOT NULL,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (peer_id, profile_id)
);
"#,
    ),
];

/// One persisted acceptance row (migration 4): `(acceptance_ewma,
/// rounds, accepted_count, proposed_count)`.
pub type AcceptanceRow = (f64, u64, u64, u64);

/// Upper bound for a persisted metric key. Every key in the closed F15
/// observation vocabulary (see `modelswarm-node::measure`) is far shorter;
/// the bound exists so a future caller cannot smuggle arbitrary-length
/// free-form text (worst case: prompt content) into the schema as a
/// "metric name".
const METRIC_KEY_MAX_LEN: usize = 64;

/// The structural shape every persisted metric key must have: non-empty,
/// at most [`METRIC_KEY_MAX_LEN`] bytes, lowercase snake_case. The node
/// layer additionally enforces exact membership in its closed const
/// enumeration; this store-side check is defense in depth so no caller
/// can write free-form names even if that enumeration is bypassed.
fn valid_metric_key(metric: &str) -> bool {
    !metric.is_empty()
        && metric.len() <= METRIC_KEY_MAX_LEN
        && metric
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The SQLite-backed node-local store.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Opens (creating if needed) the database at `path` and applies all
    /// pending migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::migrate(&conn)?;
        Ok(Self { conn })
    }

    fn migrate(conn: &Connection) -> Result<()> {
        let current: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        for (version, sql) in MIGRATIONS {
            if *version > current {
                conn.execute_batch(sql)?;
                conn.pragma_update(None, "user_version", *version)?;
            }
        }
        Ok(())
    }

    /// Inserts or refreshes this installation's identity row. `created_at`
    /// is preserved on update.
    pub fn upsert_installation(&self, id: &str, pub_key: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO installations (id, pub_key, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET pub_key = excluded.pub_key",
            rusqlite::params![id, pub_key, now_rfc3339()],
        )?;
        Ok(())
    }

    /// Records the installation's acceptance of a profile's license
    /// (idempotent per installation + profile).
    pub fn record_license(&self, installation_id: &str, profile_id: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO license_acceptances
                 (installation_id, profile_id, accepted_at)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![installation_id, profile_id, now_rfc3339()],
        )?;
        Ok(())
    }

    /// Inserts or refreshes the EWMA observation for one peer + metric.
    pub fn upsert_ewma(&self, peer_id: &str, metric: &str, value: f64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO ewma_observations
                 (peer_id, metric, value, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![peer_id, metric, value, now_rfc3339()],
        )?;
        Ok(())
    }

    /// The last stored EWMA value for a peer + metric, if any.
    pub fn get_ewma(&self, peer_id: &str, metric: &str) -> Result<Option<f64>> {
        let value = self
            .conn
            .query_row(
                "SELECT value FROM ewma_observations WHERE peer_id = ?1 AND metric = ?2",
                rusqlite::params![peer_id, metric],
                |row| row.get::<_, f64>(0),
            )
            .optional()?;
        Ok(value)
    }

    /// F15: inserts or refreshes the EWMA observation for one
    /// (peer, profile, metric) triple (migration 3 table). The metric key
    /// must match the closed vocabulary's shape
    /// (see [`valid_metric_key`]); anything else is rejected before the
    /// SQL runs so a future caller cannot smuggle free-form names into
    /// the schema.
    pub fn upsert_peer_metric(
        &self,
        peer_id: &str,
        profile_id: &str,
        metric: &str,
        value: f64,
    ) -> Result<()> {
        if !valid_metric_key(metric) {
            return Err(StoreError::InvalidMetricKey {
                metric_len: metric.len(),
            });
        }
        self.conn.execute(
            "INSERT INTO peer_metric_observations
                 (peer_id, profile_id, metric, value, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(peer_id, profile_id, metric) DO UPDATE SET
                 value = excluded.value, updated_at = excluded.updated_at",
            rusqlite::params![peer_id, profile_id, metric, value, now_rfc3339()],
        )?;
        Ok(())
    }

    /// F15: the stored (peer, profile, metric) value, if any.
    pub fn get_peer_metric(
        &self,
        peer_id: &str,
        profile_id: &str,
        metric: &str,
    ) -> Result<Option<f64>> {
        let value = self
            .conn
            .query_row(
                "SELECT value FROM peer_metric_observations
                 WHERE peer_id = ?1 AND profile_id = ?2 AND metric = ?3",
                rusqlite::params![peer_id, profile_id, metric],
                |row| row.get::<_, f64>(0),
            )
            .optional()?;
        Ok(value)
    }

    /// F15: every stored `(profile_id, metric, value)` row for one peer —
    /// the read side used to hydrate per-peer observations after a restart.
    pub fn peer_metrics_for(&self, peer_id: &str) -> Result<Vec<(String, String, f64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT profile_id, metric, value FROM peer_metric_observations
             WHERE peer_id = ?1 ORDER BY profile_id, metric",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![peer_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, f64>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// F15: every peer id that has ANY persisted observation row (union of
    /// the peer-scoped `ewma_observations` and per-profile
    /// `peer_metric_observations` tables), sorted. The read side for
    /// whole-store hydration at recorder-open time, so the requester-side
    /// measurement snapshot never needs a blocking SQLite read on a
    /// request path afterwards.
    pub fn persisted_peer_ids(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT peer_id FROM ewma_observations
             UNION SELECT peer_id FROM peer_metric_observations
             ORDER BY peer_id",
        )?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// 9.6 pass-1 harness: inserts or refreshes the speculative-acceptance
    /// observation for one (peer, profile) pair (migration 4 table). The
    /// caller owns the EWMA math; the store persists the smoothed value and
    /// the aggregate counters so a restart resumes correctly.
    pub fn upsert_acceptance(
        &self,
        peer_id: &str,
        profile_id: &str,
        acceptance_ewma: f64,
        rounds: u64,
        accepted_count: u64,
        proposed_count: u64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO speculative_acceptance_observations
                 (peer_id, profile_id, acceptance_ewma, rounds,
                  accepted_count, proposed_count, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(peer_id, profile_id) DO UPDATE SET
                 acceptance_ewma = excluded.acceptance_ewma,
                 rounds = excluded.rounds,
                 accepted_count = excluded.accepted_count,
                 proposed_count = excluded.proposed_count,
                 updated_at = excluded.updated_at",
            rusqlite::params![
                peer_id,
                profile_id,
                acceptance_ewma,
                rounds,
                accepted_count,
                proposed_count,
                now_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// 9.6 pass-1 harness: the stored acceptance observation for one
    /// (peer, profile), if any, as `(acceptance_ewma, rounds, accepted,
    /// proposed)`.
    pub fn acceptance_for(
        &self,
        peer_id: &str,
        profile_id: &str,
    ) -> Result<Option<(f64, u64, u64, u64)>> {
        let row = self
            .conn
            .query_row(
                "SELECT acceptance_ewma, rounds, accepted_count, proposed_count
                 FROM speculative_acceptance_observations
                 WHERE peer_id = ?1 AND profile_id = ?2",
                rusqlite::params![peer_id, profile_id],
                |row| {
                    Ok((
                        row.get::<_, f64>(0)?,
                        row.get::<_, i64>(1)? as u64,
                        row.get::<_, i64>(2)? as u64,
                        row.get::<_, i64>(3)? as u64,
                    ))
                },
            )
            .optional()?;
        Ok(row)
    }

    /// 9.6 pass-1 harness: every stored acceptance row keyed by
    /// `(peer_id, profile_id)`, ordered by (peer, profile) — the
    /// hydration read.
    pub fn all_acceptance_rows(&self) -> Vec<((String, String), AcceptanceRow)> {
        let Ok(mut stmt) = self.conn.prepare(
            "SELECT peer_id, profile_id, acceptance_ewma, rounds,
                    accepted_count, proposed_count
             FROM speculative_acceptance_observations
             ORDER BY peer_id, profile_id",
        ) else {
            return Vec::new();
        };
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    (row.get::<_, String>(0)?, row.get::<_, String>(1)?),
                    (
                        row.get::<_, f64>(2)?,
                        row.get::<_, i64>(3)? as u64,
                        row.get::<_, i64>(4)? as u64,
                        row.get::<_, i64>(5)? as u64,
                    ),
                ))
            })
            .map(|mapped| {
                mapped
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        rows
    }

    /// Records one finished job (timings, outcome, usage digest only).
    ///
    /// The argument list mirrors the `job_accounting` columns one-for-one
    /// (msp-v1 §7 receipt fields); a wrapper struct would only re-name them.
    #[allow(clippy::too_many_arguments)]
    pub fn record_job(
        &self,
        request_id: &str,
        peer_id: &str,
        profile_id: &str,
        outcome: &str,
        started_at: &str,
        ended_at: &str,
        usage_digest: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO job_accounting
                 (request_id, peer_id, profile_id, outcome,
                  started_at, ended_at, usage_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                request_id,
                peer_id,
                profile_id,
                outcome,
                started_at,
                ended_at,
                usage_digest
            ],
        )?;
        Ok(())
    }

    /// Total recorded jobs.
    pub fn count_jobs(&self) -> Result<i64> {
        let count = self
            .conn
            .query_row("SELECT COUNT(*) FROM job_accounting", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Records a verified model artifact (idempotent per profile; the latest
    /// verification wins). Columns mirror the Phase H artifact subsystem.
    pub fn record_artifact(
        &self,
        profile_id: &str,
        path: &str,
        sha256: &str,
        bytes: i64,
        state: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO artifacts
                 (profile_id, path, sha256, bytes, state, verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![profile_id, path, sha256, bytes, state, now_rfc3339()],
        )?;
        Ok(())
    }

    /// Whether this installation accepted the given profile's license.
    /// Removes one acknowledgement row (the hosting-preference kv user,
    /// 2026-10-17 hardening). Missing row = no-op.
    pub fn remove_license(&self, installation_id: &str, profile_id: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM license_acceptances WHERE installation_id = ?1 AND profile_id = ?2",
            rusqlite::params![installation_id, profile_id],
        )?;
        Ok(())
    }

    pub fn has_license(&self, installation_id: &str, profile_id: &str) -> Result<bool> {
        let found = self
            .conn
            .query_row(
                "SELECT 1 FROM license_acceptances WHERE installation_id = ?1 AND profile_id = ?2",
                rusqlite::params![installation_id, profile_id],
                |_| Ok(()),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// The recorded artifact row for a profile, if any, as
    /// `(path, sha256, bytes, state)`.
    pub fn get_artifact(&self, profile_id: &str) -> Result<Option<(String, String, i64, String)>> {
        let row = self
            .conn
            .query_row(
                "SELECT path, sha256, bytes, state FROM artifacts WHERE profile_id = ?1",
                rusqlite::params![profile_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        Ok(row)
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("formatting the current UTC time as RFC 3339 cannot fail")
}
