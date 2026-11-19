//! Account directory (ADR-013 P2): the website account's machine list,
//! polled from the tracker (`GET /api/v1/account/directory`, machine-
//! signed like the heartbeat) by the swarm heartbeat thread. Replaces the
//! ADR-010 circle directory as the rail's discovery source: the rows are
//! connectable WITHOUT a pairing-code exchange because the controller
//! stamps an Ed25519 account proof on `connect_request` and the host
//! checks the installation against THIS cache before trusting it.
//!
//! Latest-wins cache, never queue-shaped (the circle directory's
//! discipline): one snapshot under a lock, refreshed every poll tick, read
//! by the rail command and the consent verification path. No secrets —
//! the session bearer stays in the credstore/heartbeat thread.

use std::sync::Mutex;

/// One machine of the account, as the tracker reports it. Field names
/// avoid the IPC surface's forbidden substrings (walked by the
/// ipc_surface test).
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct AccountMachineDto {
    pub installation_id: String,
    /// The owner-set (or heartbeat auto-filled) label; null while unnamed.
    pub label: Option<String>,
    pub last_seen_at_ms: Option<u64>,
    /// The machine's signaling mailbox id (16 hex) when it shares one —
    /// the rail's connect key. Null = online-but-not-controllable.
    pub signaling_device_id: Option<String>,
    /// True for this machine's own row.
    pub is_self: bool,
}

/// Latest-wins snapshot of the account's machines.
#[derive(Default)]
pub struct AccountDirectory {
    machines: Mutex<Vec<AccountMachineDto>>,
}

impl AccountDirectory {
    /// Replace the snapshot (poller only). `own_installation_id` marks the
    /// self row for the rail.
    pub fn update(&self, own_installation_id: &str, rows: Vec<AccountMachineDto>) {
        let mut rows = rows;
        for row in &mut rows {
            row.is_self = row.installation_id == own_installation_id;
        }
        *self.machines.lock().expect("account directory") = rows;
    }

    /// Current rows (the rail command).
    pub fn machines(&self) -> Vec<AccountMachineDto> {
        self.machines.lock().expect("account directory").clone()
    }

    /// Empty the snapshot (security review finding 2: the cache must FAIL
    /// CLOSED — auth death, membership loss, leave, and re-key all drop
    /// every row, so a revoked installation's proof stops matching a
    /// stale "same account" view immediately).
    pub fn clear(&self) {
        *self.machines.lock().expect("account directory") = Vec::new();
    }

    /// The host-side consent check: is this installation in OUR account?
    /// Returns its label for the prompt when it is.
    pub fn lookup(&self, installation_id: &str) -> Option<Option<String>> {
        let guard = self.machines.lock().expect("account directory");
        guard
            .iter()
            .find(|m| m.installation_id == installation_id)
            .map(|m| m.label.clone())
    }
}
