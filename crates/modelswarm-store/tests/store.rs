//! Integration tests for the node-local store: round-trips on a tempfile
//! database and the structural privacy assertion (no column anywhere may
//! carry prompt-like or secret-like names).

use modelswarm_store::Store;
use rusqlite::Connection;

/// Column-name fragments that must never appear in any table: prompts and
/// completions (AGENTS.md hard constraint 5) and credentials.
const FORBIDDEN_COLUMN_SUBSTRINGS: &[&str] = &[
    "prompt",
    "completion",
    "messages",
    "conversation",
    "content",
    "history",
    "hf_token",
    "access_token",
    "api_key",
    "secret",
];

#[test]
fn open_creates_schema_and_migrations_are_idempotent() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = Store::open(file.path()).unwrap();
    store.upsert_installation("install-1", &[1, 2, 3]).unwrap();
    // Reopening runs migrations again harmlessly (IF NOT EXISTS + versioned).
    let store = Store::open(file.path()).unwrap();
    store.upsert_ewma("peer-1", "ttft_ms", 12.5).unwrap();
    let conn = Connection::open(file.path()).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert!(
        version >= 1,
        "migrations must bump user_version, got {version}"
    );
}

#[test]
fn installation_upsert_round_trips_and_preserves_created_at() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = Store::open(file.path()).unwrap();
    store.upsert_installation("install-1", &[9, 9]).unwrap();
    store.upsert_installation("install-1", &[7, 7]).unwrap();

    let conn = Connection::open(file.path()).unwrap();
    let (pub_key, count): (Vec<u8>, i64) = conn
        .query_row(
            "SELECT pub_key, (SELECT COUNT(*) FROM installations) FROM installations WHERE id = 'install-1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(pub_key, vec![7, 7], "conflicting update refreshes the key");
    assert_eq!(count, 1, "upsert must not duplicate rows");
}

#[test]
fn license_records_are_idempotent_per_pair() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = Store::open(file.path()).unwrap();
    store.record_license("install-1", "msp1:aa").unwrap();
    store.record_license("install-1", "msp1:aa").unwrap();
    store.record_license("install-1", "msp1:bb").unwrap();

    let conn = Connection::open(file.path()).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM license_acceptances WHERE installation_id = 'install-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn ewma_round_trips_and_updates() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = Store::open(file.path()).unwrap();
    assert_eq!(store.get_ewma("peer-1", "ttft_ms").unwrap(), None);
    store.upsert_ewma("peer-1", "ttft_ms", 120.5).unwrap();
    assert_eq!(store.get_ewma("peer-1", "ttft_ms").unwrap(), Some(120.5));
    store.upsert_ewma("peer-1", "ttft_ms", 90.25).unwrap();
    assert_eq!(store.get_ewma("peer-1", "ttft_ms").unwrap(), Some(90.25));
    // Different metric, same peer: separate row.
    store.upsert_ewma("peer-1", "itl_ms", 33.0).unwrap();
    assert_eq!(store.get_ewma("peer-1", "itl_ms").unwrap(), Some(33.0));
    assert_eq!(store.get_ewma("peer-1", "ttft_ms").unwrap(), Some(90.25));
    assert_eq!(store.get_ewma("peer-2", "ttft_ms").unwrap(), None);
}

/// F15: per-(peer, profile) metric rows round-trip, stay scoped to the
/// exact profile they were measured against, and the migration is additive
/// (an existing v2 database gains the table; user_version >= 3).
#[test]
fn peer_metric_rows_round_trip_per_profile() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = Store::open(file.path()).unwrap();
    assert_eq!(
        store
            .get_peer_metric("peer-1", "msp1:aa", "ttft_ms")
            .unwrap(),
        None
    );
    store
        .upsert_peer_metric("peer-1", "msp1:aa", "ttft_ms", 42.0)
        .unwrap();
    store
        .upsert_peer_metric("peer-1", "msp1:aa", "ttft_ms", 38.5)
        .unwrap();
    store
        .upsert_peer_metric("peer-1", "msp1:bb", "ttft_ms", 90.0)
        .unwrap();
    store
        .upsert_peer_metric("peer-2", "msp1:aa", "itl_mean_ms", 12.0)
        .unwrap();
    assert_eq!(
        store
            .get_peer_metric("peer-1", "msp1:aa", "ttft_ms")
            .unwrap(),
        Some(38.5),
        "same triple updates in place"
    );
    assert_eq!(
        store
            .get_peer_metric("peer-1", "msp1:bb", "ttft_ms")
            .unwrap(),
        Some(90.0),
        "same peer + metric under another profile is a separate row"
    );
    let mut rows = store.peer_metrics_for("peer-1").unwrap();
    rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    assert_eq!(
        rows,
        vec![
            ("msp1:aa".to_string(), "ttft_ms".to_string(), 38.5),
            ("msp1:bb".to_string(), "ttft_ms".to_string(), 90.0),
        ]
    );
    assert!(store.peer_metrics_for("peer-3").unwrap().is_empty());

    let conn = Connection::open(file.path()).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert!(
        version >= 3,
        "migration 3 applied, got user_version {version}"
    );
}

/// F15 security condition: `upsert_peer_metric` accepts only keys shaped
/// like the closed observation vocabulary (non-empty, <=64 bytes,
/// `[a-z0-9_]`). Free-form names — the smuggling vector for arbitrary
/// text, worst case prompt content, into the schema — are rejected BEFORE
/// any SQL runs, and every key the node's const enumeration actually uses
/// still round-trips (backward compatible).
#[test]
fn upsert_peer_metric_rejects_keys_outside_the_closed_shape() {
    use modelswarm_store::StoreError;
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = Store::open(file.path()).unwrap();

    // The shape check, not enumeration membership: structurally valid
    // unknown names still pass at the store layer (the node's closed const
    // set is enforced one layer up); everything malformed is refused.
    for junk in [
        "",
        "has spaces",
        "UPPER_MS",
        "ttft-ms",
        "prompt: hello there",
        "a".repeat(65).as_str(),
        " café",
    ] {
        let err = store
            .upsert_peer_metric("peer-1", "msp1:aa", junk, 1.0)
            .expect_err("malformed metric key must be rejected");
        assert!(
            matches!(err, StoreError::InvalidMetricKey { .. }),
            "expected InvalidMetricKey for {junk:?}, got {err:?}"
        );
        // And nothing was written.
        assert!(
            store.peer_metrics_for("peer-1").unwrap().is_empty(),
            "rejected key {junk:?} must not create a row"
        );
    }

    // Every key the F15 const enumeration persists today still works.
    for legacy in [
        "ttft_ms",
        "itl_mean_ms",
        "total_ms",
        "prefill_tokens_per_ms",
        "decode_tokens_per_ms",
        "advertised_queue_ms",
        "completion_count",
        "failure_count",
    ] {
        store
            .upsert_peer_metric("peer-1", "msp1:aa", legacy, 1.0)
            .unwrap_or_else(|e| panic!("legacy key {legacy} must keep working: {e}"));
    }
    assert_eq!(store.peer_metrics_for("peer-1").unwrap().len(), 8);
}

/// F15 hydration support: `persisted_peer_ids` returns the union of peers
/// with any observation row across both metric tables, so the recorder
/// can hydrate the whole store once at open time.
#[test]
fn persisted_peer_ids_unions_both_observation_tables() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = Store::open(file.path()).unwrap();
    assert!(store.persisted_peer_ids().unwrap().is_empty());

    store.upsert_ewma("peer-b", "rtt_p50_ms", 10.0).unwrap();
    store
        .upsert_peer_metric("peer-a", "msp1:aa", "ttft_ms", 42.0)
        .unwrap();
    store
        .upsert_peer_metric("peer-b", "msp1:aa", "ttft_ms", 7.0)
        .unwrap();
    // A peer that appears in both tables is listed once.
    assert_eq!(
        store.persisted_peer_ids().unwrap(),
        vec!["peer-a".to_string(), "peer-b".to_string()]
    );
}

#[test]
fn job_accounting_counts_and_is_idempotent_per_request() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = Store::open(file.path()).unwrap();
    assert_eq!(store.count_jobs().unwrap(), 0);
    for (i, outcome) in ["stop", "error", "cancelled"].iter().enumerate() {
        store
            .record_job(
                &format!("req-{i}"),
                "peer-1",
                "msp1:aa",
                outcome,
                "2026-10-04T12:00:00Z",
                "2026-10-04T12:00:05Z",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .unwrap();
    }
    assert_eq!(store.count_jobs().unwrap(), 3);
    // Re-recording the same request id replaces, not appends.
    store
        .record_job(
            "req-0",
            "peer-1",
            "msp1:aa",
            "stop",
            "2026-10-04T12:00:00Z",
            "2026-10-04T12:00:05Z",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
    assert_eq!(store.count_jobs().unwrap(), 3);
}

/// Structural privacy gate: enumerate EVERY user table and EVERY column via
/// sqlite_master + PRAGMA table_info and assert no column name contains a
/// forbidden substring. A future migration that adds e.g. a `prompt_text`
/// column fails this test.
#[test]
fn no_table_column_holds_prompt_like_or_secret_like_names() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let _store = Store::open(file.path()).unwrap();

    let conn = Connection::open(file.path()).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )
        .unwrap();
    let tables: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    drop(stmt);

    assert!(
        tables.contains(&"installations".to_string())
            && tables.contains(&"license_acceptances".to_string())
            && tables.contains(&"ewma_observations".to_string())
            && tables.contains(&"job_accounting".to_string()),
        "expected the four schema tables, found {tables:?}"
    );

    let mut checked = 0;
    for table in &tables {
        let mut stmt = conn
            .prepare(&format!(
                "PRAGMA table_info(\"{}\")",
                table.replace('"', "\"\"")
            ))
            .unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        drop(stmt);
        assert!(!columns.is_empty(), "table {table} has no columns?");
        for column in columns {
            let lower = column.to_lowercase();
            for forbidden in FORBIDDEN_COLUMN_SUBSTRINGS {
                assert!(
                    !lower.contains(forbidden),
                    "privacy violation: {table}.{column} contains forbidden substring {forbidden:?}"
                );
            }
            checked += 1;
        }
    }
    assert!(
        checked >= 15,
        "expected the full column set, checked {checked}"
    );
}
