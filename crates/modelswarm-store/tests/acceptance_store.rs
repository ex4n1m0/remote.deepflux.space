//! 9.6 pass-1 harness: round-trip test for the additive migration 4
//! (`speculative_acceptance_observations`) — the per-(peer, profile)
//! speculative-acceptance EWMA persistence the Scheduler Scientist's
//! harness reads back after a restart. New test file (the existing
//! `tests/store.rs` privacy audit enumerates tables dynamically, so the
//! new table is already covered there).

use modelswarm_store::Store;

#[test]
fn acceptance_rows_round_trip_per_peer_profile() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = Store::open(file.path()).unwrap();

    assert_eq!(store.acceptance_for("peer-a", "msp1:aa").unwrap(), None);

    store
        .upsert_acceptance("peer-a", "msp1:aa", 0.75, 10, 60, 80)
        .unwrap();
    store
        .upsert_acceptance("peer-a", "msp1:bb", 0.10, 4, 3, 40)
        .unwrap();
    store
        .upsert_acceptance("peer-b", "msp1:aa", 0.90, 7, 50, 56)
        .unwrap();

    assert_eq!(
        store.acceptance_for("peer-a", "msp1:aa").unwrap(),
        Some((0.75, 10, 60, 80)),
        "exact triple round-trip"
    );
    assert_eq!(
        store.acceptance_for("peer-a", "msp1:bb").unwrap(),
        Some((0.10, 4, 3, 40)),
        "per-profile keying"
    );
    assert_eq!(
        store.acceptance_for("peer-b", "msp1:aa").unwrap(),
        Some((0.90, 7, 50, 56)),
        "per-peer keying"
    );

    // Upsert replaces (the EWMA + counters advance together).
    store
        .upsert_acceptance("peer-a", "msp1:aa", 0.80, 11, 67, 88)
        .unwrap();
    assert_eq!(
        store.acceptance_for("peer-a", "msp1:aa").unwrap(),
        Some((0.80, 11, 67, 88))
    );
}

#[test]
fn acceptance_rows_survive_reopen_and_migrations_are_idempotent() {
    let file = tempfile::NamedTempFile::new().unwrap();
    {
        let store = Store::open(file.path()).unwrap();
        store
            .upsert_acceptance("peer-a", "msp1:aa", 0.5, 2, 8, 16)
            .unwrap();
    }
    // Reopen: migrations re-run harmlessly, rows persist.
    let store = Store::open(file.path()).unwrap();
    let store_again = Store::open(file.path()).unwrap();
    assert_eq!(
        store.acceptance_for("peer-a", "msp1:aa").unwrap(),
        Some((0.5, 2, 8, 16)),
        "persisted across reopen"
    );
    assert_eq!(
        store_again.acceptance_for("peer-a", "msp1:aa").unwrap(),
        Some((0.5, 2, 8, 16))
    );
}
