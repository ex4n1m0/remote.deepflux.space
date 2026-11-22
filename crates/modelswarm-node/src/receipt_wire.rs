//! Receipts v2 on the production serving/chat wire (ADR-030 Phase B2).
//!
//! The serving side CONSTRUCTS + phase-1-signs a [`ReceiptV2`] at each
//! cleanly-completed swarm request and attaches it to the `Completed`
//! frame; the requester (desktop) counter-signs, best-effort-acks, and
//! POSTs it to the tracker — where the B1 intake validates against
//! enrolled keys and grants accounting. The first REAL accounting
//! entries.

use modelswarm_eligibility::receipt_v2::{ReceiptPeer, ReceiptV2};
use modelswarm_identity::InstallationIdentity;
use modelswarm_transport::message::{JobReceipt, JobReceiptPeer};

/// Converts the wire mirror into the semantic object (field-for-field the
/// same JSON — a serde round-trip is the conversion).
pub fn wire_to_receipt(wire: &JobReceipt) -> Result<ReceiptV2, String> {
    let value = serde_json::to_value(wire).map_err(|e| e.to_string())?;
    serde_json::from_value(value).map_err(|e| e.to_string())
}

/// Converts the semantic object into the wire mirror.
pub fn receipt_to_wire(receipt: &ReceiptV2) -> Result<JobReceipt, String> {
    let value = serde_json::to_value(receipt).map_err(|e| e.to_string())?;
    serde_json::from_value(value).map_err(|e| e.to_string())
}

/// `usage_digest` (frozen here, deterministic + content-blind): sha256
/// over the canonical JSON of the usage counters object.
pub fn usage_digest_of(
    prompt_tokens: u32,
    completion_tokens: u32,
    prefill_ms: u32,
    decode_ms: u32,
) -> String {
    let canonical = serde_json::json!({
        "completion_tokens": completion_tokens,
        "decode_ms": decode_ms,
        "prefill_ms": prefill_ms,
        "prompt_tokens": prompt_tokens,
    });
    let text = modelswarm_types::canonical_json(&canonical).expect("usage counters canonicalize");
    let hex: String = sha256_digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256:{hex}")
}

fn sha256_digest(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Everything the serving loop knows at `Completed` time.
pub struct ReceiptContext<'a> {
    pub request_id: &'a str,
    pub profile_id: &'a str,
    /// The REQUESTER (from the QUIC-authenticated peer id + the validated
    /// lease's bound installation).
    pub requester: ReceiptPeer,
    /// This serving installation's identity (peer id + installation id +
    /// the signing key).
    pub server_identity: &'a InstallationIdentity,
    pub started_at: time::OffsetDateTime,
    pub ended_at: time::OffsetDateTime,
    pub finish_reason: &'a str,
    pub accepted_tokens: u32,
    pub verified_tokens: u32,
    pub prompt_tokens: u32,
    pub prefill_ms: u32,
    pub decode_ms: u32,
    /// The clamped budget actually applied (msp-v1 §6.4).
    pub deadline_ms: u32,
    pub max_tokens: u32,
}

/// Builds + PHASE-1-SIGNS the receipt (server side). Honest field values
/// for the v0.x single-mode path: `mode_id = "single"`, `preset =
/// "unspecified"` (ADR-029 tier negotiation rides a future wire; the
/// field exists, the negotiation doesn't — never invented).
pub fn build_server_receipt(ctx: &ReceiptContext<'_>) -> Result<JobReceipt, String> {
    let server = ReceiptPeer {
        peer_id: ctx.server_identity.peer_id(),
        installation_id: ctx.server_identity.installation_id(),
        role: "server".into(),
    };
    let peers = vec![
        ReceiptPeer {
            peer_id: ctx.requester.peer_id.clone(),
            installation_id: ctx.requester.installation_id.clone(),
            role: "requester".into(),
        },
        server,
    ];
    let mut receipt = ReceiptV2 {
        request_id: ctx.request_id.to_string(),
        profile_id: ctx.profile_id.to_string(),
        preset: "unspecified".into(),
        mode_id: "single".into(),
        cohort_digest: ReceiptV2::cohort_digest_of(&peers).map_err(|e| e.to_string())?,
        peers,
        started_at: format_rfc3339(ctx.started_at),
        ended_at: format_rfc3339(ctx.ended_at),
        outcome: ctx.finish_reason.to_string(),
        accepted_tokens: ctx.accepted_tokens as u64,
        verified_tokens: ctx.verified_tokens as u64,
        endpoint_seconds: (ctx.ended_at - ctx.started_at).whole_seconds().max(0) as u64,
        usage_digest: usage_digest_of(
            ctx.prompt_tokens,
            ctx.verified_tokens,
            ctx.prefill_ms,
            ctx.decode_ms,
        ),
        budgets: serde_json::json!({
            "deadline_ms": ctx.deadline_ms,
            "max_tokens": ctx.max_tokens,
        }),
        server_signature: String::new(),
        requester_signature: String::new(),
    };
    let signing = ed25519_dalek::SigningKey::from_bytes(&ctx.server_identity.to_bytes());
    receipt.sign_server(&signing).map_err(|e| e.to_string())?;
    receipt_to_wire(&receipt)
}

/// The REQUESTER side (desktop): counter-signs a server-signed receipt
/// with the local installation identity (phase 2). Cryptographic
/// server-signature verification happens at the TRACKER's intake against
/// enrolled keys (the trust anchor); the requester's local check is the
/// peer binding below plus the ADR-045 INV-4 preset gate.
///
/// `negotiated_preset` is the session's negotiated tier — `Some(p)` when
/// a SessionOffer delivered `p` on this session's path, `None` when no
/// negotiation rode it (the msp-v1 §6 pull). INV-4: the receipt's
/// `preset` must equal the negotiated value, or be `unspecified` when
/// none was negotiated — a serving peer cannot monetize a tier claim
/// this requester never negotiated.
pub fn countersign(
    wire: &JobReceipt,
    requester_identity: &InstallationIdentity,
    remote_peer_id: &str,
    negotiated_preset: Option<&str>,
) -> Result<JobReceipt, String> {
    let mut receipt = wire_to_receipt(wire)?;
    // ADR-045 INV-4, first: the preset on the signed object must be
    // inside the frozen vocabulary AND consistent with what rode the
    // session — refused otherwise (the receipt dies, no accounting).
    if !modelswarm_eligibility::receipt_v2::is_valid_receipt_preset(&receipt.preset) {
        return Err(format!(
            "receipt preset {:?} is outside the frozen vocabulary",
            receipt.preset
        ));
    }
    match negotiated_preset {
        Some(p) if receipt.preset != p => {
            return Err(format!(
                "receipt preset {} != negotiated {p}",
                receipt.preset
            ));
        }
        None if receipt.preset != "unspecified" => {
            return Err(format!(
                "receipt claims preset {} but no SessionOffer rode this session",
                receipt.preset
            ));
        }
        _ => {}
    }
    // Local honesty check: the receipt names THIS conversation's peer.
    let server = receipt
        .peers
        .iter()
        .find(|p| p.role == "server")
        .ok_or_else(|| "receipt has no server peer".to_string())?;
    if server.peer_id != remote_peer_id {
        return Err(format!(
            "receipt server {} != session peer {remote_peer_id}",
            server.peer_id
        ));
    }
    // And THIS installation as the requester.
    if receipt
        .peers
        .iter()
        .any(|p| p.role == "requester" && p.installation_id != requester_identity.installation_id())
    {
        return Err("receipt requester is another installation".into());
    }
    let signing = ed25519_dalek::SigningKey::from_bytes(&requester_identity.to_bytes());
    receipt
        .sign_requester(&signing)
        .map_err(|e| e.to_string())?;
    receipt_to_wire(&receipt)
}

/// The final digest for the tracker POST (`sha256:`-prefixed hex of 64).
pub fn final_digest(wire: &JobReceipt) -> Result<String, String> {
    wire_to_receipt(wire)?
        .receipt_digest()
        .map_err(|e| e.to_string())
}

fn format_rfc3339(t: time::OffsetDateTime) -> String {
    use time::format_description::well_known::Rfc3339;
    t.format(&Rfc3339).expect("RFC-3339 formats")
}

#[allow(dead_code)]
fn _wire_peer_shape_check(p: &JobReceiptPeer) -> bool {
    !p.peer_id.is_empty() && !p.installation_id.is_empty() && !p.role.is_empty()
}
