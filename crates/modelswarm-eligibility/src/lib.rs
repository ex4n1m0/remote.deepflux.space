//! Eligibility: the host-to-consume rule's artifacts (ADR-012).
//!
//! - [`EligibilityLease`]: the hub-signed lease (lease-capped TTL,
//!   peer/profile binding, multi-use with single-use request ids). Renames
//!   the artifact msp-v1 §5 called "capability token".
//! - [`CapacityClass`]: measured, never self-reported, serving capacity.
//! - `audit_epoch`: cheap revocation propagation (leases referencing a stale
//!   epoch are rejected without per-token lookups).
//! - [`suspension`]: the deterministic suspension policy table (slots to
//!   zero, 5 min / 30 min / 24 h escalating backoff, decay after 100 clean
//!   serves).
//!
//! Bootstrap allowance is OFF by default and exists only as an
//! experiments-scoped flag until Phase F evidence (ADR-012).

pub mod canonical;
pub mod lease;
pub mod policy;
pub mod receipt_v2;
pub mod relay_ticket;

pub use lease::{
    CapacityClass, EligibilityLease, LeaseError, EXPIRY_CLOCK_SKEW_SECS, LEASE_CAP_GRACE_SECS,
};
pub use policy::{
    backoff_for_streak, suspension, PolicyEvent, SuspensionDecision, CLEAN_EVENTS_FOR_DECAY,
    SUSPENDED_SLOTS, SUSPENSION_BACKOFF_WINDOWS_SECS,
};
pub use relay_ticket::{
    canonical_payload, sign_ticket, verify_wire, RelayAdmissionTicket, TicketError,
    RELAY_TICKET_MAX_SERIALIZED_LEN, RELAY_TICKET_SKEW_GRACE_SECS, RELAY_TICKET_TTL_SECS,
};
