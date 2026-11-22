//! ADR-038 §3.7/§6.4 row 8 — the node's relay admission ticket cache.
//!
//! The tracker mints one ticket per successful heartbeat (§3.3) and the
//! node hands the FRESHEST one to every relay leg it opens: the serving
//! side's reservation supervisor and the requester's relayed dials both
//! present through the transport seam
//! ([`Libp2pTransport::set_relay_ticket_source`], the Network seat's
//! client half). This module is the cache that seam reads — nothing more:
//!
//! - **Fresh supply only.** The cache stores, replaces, and supplies. It
//!   deliberately applies NO freshness policy of its own: a cached ticket
//!   past its `expires_at` is still supplied verbatim, because the
//!   freshness rules live elsewhere and are already pinned there — the
//!   transport's renewal window (re-present iff expired/within 120 s,
//!   `relay_client::should_re_present`) and the relay's check-6 expiry
//!   refusal. A second policy here could only drift from those.
//! - **One slot, replace never accumulate.** Each heartbeat response
//!   replaces the cached ticket; there is no history to leak or evict.
//! - **Syntax-level honesty, not signature policy.** A stored string must
//!   parse under the frozen [`RelayAdmissionTicket::from_wire`] (length
//!   bound, segment shape, canonical strict JSON, exact field set,
//!   timestamps, nonce, the 600 s delta — the ADR's §3.4 checks 3-4).
//!   The SIGNATURE is not verified here: the relay owns check 5 against
//!   the pinned tracker key, the node treats the string as opaque
//!   beyond syntax (the transport seam's documented contract), and the
//!   golden vectors' tokens are signed by the FIXTURE key — a node-side
//!   signature check would reject them by construction.
//! - **Deploy skew tolerated.** The heartbeat field is additive
//!   (`#[serde(default)]`, empty = "no ticket issued"): an OLD tracker
//!   deploy leaves the PREVIOUS value in place rather than clearing it
//!   (§6.2(7): the client tolerates the tracker-first deploy order).
//!   A malformed or oversized string is dropped the same way — the last
//!   GOOD value stays and the outcome is reported as
//!   [`TicketStore::Dropped`] for the caller to observe.
//! - **No telemetry event is emitted here.** No name in the desktop's or
//!   node's frozen vocabulary fits a counts-only "ticket dropped" line
//!   (`roster.error`/`listener.error` carry free-text errors about other
//!   phases), and ADR-038 §6.2(6) forbids ticket bytes in logs — so the
//!   cache reports its outcome through the return value only and the
//!   caller logs nothing (recorded in the 2026-10-15 ticket-cache
//!   handoff; a frozen event name would come from an ADR, not here).
//!
//! Privacy: the cached string never reaches the webview, the UI, or any
//! user-facing status surface — the ticket rides the heartbeat invisibly
//! (the owner's everything-on-by-design directive; there is no switch).

use std::sync::{Arc, Mutex as StdMutex};

use modelswarm_eligibility::relay_ticket::RelayAdmissionTicket;
use modelswarm_tracker_api::HeartbeatResponse;
use modelswarm_transport::libp2p_backend::Libp2pTransport;
use modelswarm_transport::relay_client::TicketSource;

/// The outcome of one heartbeat-driven store — observability data only
/// (the cache itself is silent; see the module docs on telemetry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketStore {
    /// A well-formed ticket replaced the cache (the normal heartbeat
    /// path — one mint per successful heartbeat, ADR-038 §3.3).
    Stored,
    /// The response carried no ticket (empty `relayTicket` — an OLD
    /// tracker deploy, the §6.2(7) deploy-skew case): the previous
    /// value stays.
    Absent,
    /// The response's ticket string failed the frozen syntax parse
    /// (malformed or over the 1024-byte bound): dropped honestly, the
    /// last GOOD value stays.
    Dropped,
}

/// The node's single-slot relay admission ticket cache (ADR-038 §6.4
/// row 8). Cheap to share: one [`StdMutex`] around one [`Option`].
///
/// Construct one per hosting session, feed it every successful
/// [`HeartbeatResponse`] ([`RelayTicketCache::store_heartbeat`]), and
/// hand [`RelayTicketCache::ticket_source`] (or the
/// [`RelayTicketCache::attach_to`] convenience) to every
/// [`Libp2pTransport`] used for a relay leg — the serving-side
/// reservation supervisor's per-attempt transport and the requester
/// [`crate::remote::RemoteExecutor`]'s dial transport.
pub struct RelayTicketCache {
    ticket: StdMutex<Option<String>>,
}

impl Default for RelayTicketCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayTicketCache {
    /// An empty cache — the documented pre-wiring behavior: the source
    /// closure returns `None`, the transport skips the pre-flight OFFER,
    /// third-party relays dial as before, and an MSP relay's gate
    /// refuses the hop exchange with the upstream verbatim label.
    pub fn new() -> Self {
        Self {
            ticket: StdMutex::new(None),
        }
    }

    /// Consumes one successful heartbeat response (ADR-038 §3.3): a
    /// present, well-formed `relayTicket` REPLACES the cache; an absent
    /// one (old tracker deploy) keeps the previous value; a malformed or
    /// oversized string is dropped with the last good value kept.
    pub fn store_heartbeat(&self, response: &HeartbeatResponse) -> TicketStore {
        self.store(&response.relay_ticket)
    }

    /// The store primitive under [`Self::store_heartbeat`]. An empty
    /// string means "no ticket issued" (the serde-default deploy-skew
    /// encoding of an absent field).
    pub fn store(&self, relay_ticket: &str) -> TicketStore {
        if relay_ticket.is_empty() {
            return TicketStore::Absent;
        }
        // The frozen syntax parse (ADR-038 §3.4 checks 3-4) — the same
        // `from_wire` the transport runs on the cached ticket for its
        // renewal window, so "malformed" means exactly one thing across
        // the node and the transport. Signature checks are NOT here
        // (see the module docs).
        if RelayAdmissionTicket::from_wire(relay_ticket).is_err() {
            return TicketStore::Dropped;
        }
        *self.ticket.lock().expect("relay ticket cache lock") = Some(relay_ticket.to_string());
        TicketStore::Stored
    }

    /// The cached serialized ticket, if any. Deliberately returns STALE
    /// tickets too — fresh-supply-only; the transport and the relay own
    /// the freshness rules (see the module docs).
    pub fn current(&self) -> Option<String> {
        self.ticket.lock().expect("relay ticket cache lock").clone()
    }

    /// The closure handed to [`Libp2pTransport::set_relay_ticket_source`]:
    /// the cached ticket, or `None` while the cache is empty (the
    /// documented pre-wiring behavior — the transport then skips the
    /// pre-flight offer entirely).
    pub fn ticket_source(self: &Arc<Self>) -> TicketSource {
        let cache = Arc::clone(self);
        Arc::new(move || cache.current())
    }

    /// Attaches this cache to a transport in one call — the composition
    /// every relay-leg construction site uses:
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use modelswarm_identity::InstallationIdentity;
    /// # use modelswarm_node::relay_ticket_cache::RelayTicketCache;
    /// # use modelswarm_transport::libp2p_backend::Libp2pTransport;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let cache = Arc::new(RelayTicketCache::new());
    /// let transport = Libp2pTransport::new(&InstallationIdentity::from_bytes(&[7u8; 32]))?;
    /// cache.attach_to(&transport);
    /// # Ok(())
    /// # }
    /// ```
    pub fn attach_to(self: &Arc<Self>, transport: &Libp2pTransport) {
        transport.set_relay_ticket_source(self.ticket_source());
    }
}

// ---------------------------------------------------------------------------
// Tests — ADR-038 §6.2(5), the node half: "ticket cache refresh from
// heartbeat responses". The golden vector discipline (the lease-hubkey
// pattern): tickets come from `protocol/vectors/relay-ticket-1.json`,
// read from the file, never inlined.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn vector(name: &str) -> serde_json::Value {
        let path = format!(
            "{}/../../protocol/vectors/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(
            &std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}")),
        )
        .expect("vector JSON")
    }

    fn accept_token() -> String {
        vector("relay-ticket-1.json")["token"]
            .as_str()
            .expect("token")
            .to_string()
    }

    fn heartbeat_json(relay_ticket: Option<&str>) -> String {
        // The exact §3.3 response shape: `relayTicket` present vs absent
        // (the serde-default deploy-skew pair the tracker-api crate pins
        // on the wire; these tests pin what the NODE does with each).
        match relay_ticket {
            Some(ticket) => format!(
                r#"{{"leaseExpiresAt":"2026-10-15T12:10:00.000Z","relayTicket":{}}}"#,
                serde_json::json!(ticket)
            ),
            None => r#"{"leaseExpiresAt":"2026-10-15T12:10:00.000Z"}"#.to_string(),
        }
    }

    fn heartbeat(relay_ticket: Option<&str>) -> HeartbeatResponse {
        serde_json::from_str(&heartbeat_json(relay_ticket)).expect("heartbeat response parses")
    }

    /// §6.2(5) row 1: a heartbeat response WITH a ticket populates the
    /// cache (the golden accept vector's exact token), and the source
    /// closure hands the transport that same string.
    #[test]
    fn heartbeat_with_ticket_populates_cache_and_source() {
        let cache = RelayTicketCache::new();
        assert_eq!(cache.current(), None, "fresh cache is empty");
        let token = accept_token();
        assert_eq!(
            cache.store_heartbeat(&heartbeat(Some(&token))),
            TicketStore::Stored
        );
        assert_eq!(cache.current(), Some(token.clone()));
        let source = Arc::new(cache).ticket_source();
        assert_eq!(source(), Some(token));
    }

    /// §6.2(5) row 2 (deploy skew): a heartbeat response WITHOUT the
    /// field (old tracker deploy, tracker-first deploy order §6.2(7))
    /// leaves the PREVIOUS value in place — never clears, never errors.
    #[test]
    fn heartbeat_without_ticket_keeps_previous_value() {
        let cache = RelayTicketCache::new();
        let token = accept_token();
        cache.store_heartbeat(&heartbeat(Some(&token)));
        assert_eq!(cache.store_heartbeat(&heartbeat(None)), TicketStore::Absent);
        assert_eq!(
            cache.current(),
            Some(token.clone()),
            "deploy skew keeps the old value"
        );
        // The empty-string encoding of an absent field behaves the same.
        assert_eq!(cache.store(""), TicketStore::Absent);
        assert_eq!(cache.current(), Some(token));
        // And a fresh cache with no ticket yet stays empty.
        let fresh = RelayTicketCache::new();
        assert_eq!(fresh.store_heartbeat(&heartbeat(None)), TicketStore::Absent);
        assert_eq!(fresh.current(), None);
    }

    /// §6.2(5) row 3: a malformed or oversized ticket string is dropped
    /// honestly — the cache keeps the LAST GOOD one (a tracker bug or a
    /// corrupted response never degrades relay reachability below what
    /// the previous good ticket provides).
    #[test]
    fn malformed_and_oversized_tickets_are_dropped_honestly() {
        let cache = RelayTicketCache::new();
        let token = accept_token();
        cache.store_heartbeat(&heartbeat(Some(&token)));

        // Malformed: not the two-segment base64url wire form.
        assert_eq!(cache.store("not-a-ticket"), TicketStore::Dropped);
        // Malformed: two segments but the payload is not canonical
        // ticket JSON.
        assert_eq!(
            cache.store("YXNkZg.aGVsbG8"), // "asdf" . "hello" base64url
            TicketStore::Dropped
        );
        // Oversized: past the frozen 1024-byte serialized bound.
        let oversized = format!("{}.{}", "A".repeat(600), "B".repeat(600));
        assert_eq!(cache.store(&oversized), TicketStore::Dropped);
        // The last good value survived all three.
        assert_eq!(cache.current(), Some(token));

        // A dropped ticket on an EMPTY cache keeps it empty.
        let fresh = RelayTicketCache::new();
        assert_eq!(fresh.store("garbage"), TicketStore::Dropped);
        assert_eq!(fresh.current(), None);
    }

    /// The cache REPLACES, never accumulates: a second well-formed
    /// ticket (fresh nonce, the fixture-key mint the transport tests
    /// use) supersedes the first — one slot, freshest wins.
    #[test]
    fn fresh_ticket_replaces_never_accumulates() {
        let cache = RelayTicketCache::new();
        let first = accept_token();
        cache.store(&first);

        // Mint a second syntactically valid ticket from the vector's
        // own fixture key (the vector records the seed; the cache does
        // not verify signatures, so this is exactly the issuance shape).
        let doc = vector("relay-ticket-1.json");
        let seed_hex = doc["signing_seed_hex"].as_str().expect("seed");
        let mut seed = [0u8; 32];
        for (i, byte) in seed_hex.as_bytes().chunks(2).enumerate() {
            seed[i] = u8::from_str_radix(std::str::from_utf8(byte).expect("hex"), 16).expect("hex");
        }
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let (mut fields, _) = RelayAdmissionTicket::from_wire(&first).expect("vector parses");
        fields.nonce = "ffffffffffffffffffffffffffffffff".to_string();
        let second = modelswarm_eligibility::relay_ticket::sign_ticket(&fields, &key);

        assert_eq!(cache.store(&second), TicketStore::Stored);
        assert_eq!(cache.current(), Some(second));
        assert_ne!(cache.current(), Some(first));
    }

    /// Fresh supply only: a cached ticket LONG past its `expires_at`
    /// (the accept vector's deadline is 2026-10-15T12:12:00Z) is still
    /// supplied verbatim — the node applies no expiry policy of its
    /// own. The transport's renewal rule
    /// (`renewal_re_presentation_rule_matches_the_frozen_window`,
    /// pinned in `modelswarm-transport`) and the relay's check-6
    /// refusal own freshness; a stale cache therefore degrades exactly
    /// as the Network seat documented (honest 202 `expired` at the
    /// pre-flight, reservation not retried), never silently.
    #[test]
    fn stale_ticket_is_supplied_verbatim_the_transport_governs_freshness() {
        let cache = RelayTicketCache::new();
        let token = accept_token();
        cache.store(&token);
        // The vector's expires_at is fixed in the past relative to any
        // later wall clock; the point is the cache does not consult ANY
        // clock — assert by supplying right back what was stored.
        let supplied = Arc::new(cache).ticket_source()();
        assert_eq!(supplied, Some(token));
    }

    /// The composition call: `attach_to` wires the cache's source into a
    /// real transport (the same public seam the desktop's reservation
    /// supervisor and the RemoteExecutor use). Behavioral smoke — the
    /// pre-flight itself is byte-pinned transport-side
    /// (`pre_flight_ok_then_hop_proceeds` and siblings).
    #[test]
    fn attach_to_wires_a_real_transport_without_side_effects() {
        use modelswarm_identity::InstallationIdentity;
        let cache = Arc::new(RelayTicketCache::new());
        let transport = Libp2pTransport::new(&InstallationIdentity::from_bytes(&[0x5E_u8; 32]))
            .expect("transport");
        cache.attach_to(&transport);
        assert_eq!(cache.current(), None, "attaching stores nothing");
    }
}
