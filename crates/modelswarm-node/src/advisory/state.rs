//! The advisory plane's SHARED vocabulary types (ADR-033 as amended by
//! the 2026-10-15 owner directive): the frozen gap vocabulary, the
//! suggestion schema types the assistant reply's `hints` array parses
//! into, the transport seam's request/failure shapes.
//!
//! The 2026-10-15 revision (owner directive verbatim: "how about we
//! remove this deepseek key completely, and make the helper use the
//! hosted model when hosted") DELETED the timer-driven digest-cycle
//! state machine that used to live here: its only purpose was the
//! content-egress-to-provider surface, and that surface is gone. The
//! assistant-plane machine (the pure `step` over an injected clock and
//! transport) lives in [`crate::advisory::assistant`]; this module
//! keeps the types both the machine and its callers share.

use super::egress::{self, HintAdmission};

/// The frozen 12-value gap vocabulary (ADR-033 §6 as amended by the
/// ADR-037 revision note of 2026-10-15: `no_key`, `interval`, and
/// `quota` died with the provider surface — nothing can emit them —
/// and `not_hosting` was added as the honest static-floor reason: the
/// assistant's model backing is THIS machine's hosted model, and
/// without hosting there is no backing). A further value needs an
/// ADR-037 amendment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gap {
    Disabled,
    /// The plane's model backing (the hosted model behind the local
    /// gateway) is absent: static-help mode. Never an error — it is
    /// the shipped default of every install that is not hosting.
    NotHosting,
    /// `advisory.json` is present but unparseable (fail closed to the
    /// static floor; the file's contents are never guessed).
    NoConfig,
    CapReached,
    EmptyAfterRedaction,
    Timeout,
    HttpError,
    ResponseOversized,
    Schema,
    /// Diagnostic-only (TR-RC-4/R-6): fires exactly at the discard of a
    /// response arriving after its turn closed — permitted ONLY
    /// following a `Timeout` gap for the same turn.
    Late,
    /// The assistant hourly burst bound (60/hour default).
    RateLimited,
    /// The assistant body over `max_request_bytes` even at zero
    /// history — nothing is sent.
    RequestOversized,
}

impl Gap {
    /// The frozen wire label (matches the artifact row byte-for-byte).
    pub fn as_str(self) -> &'static str {
        match self {
            Gap::Disabled => "disabled",
            Gap::NotHosting => "not_hosting",
            Gap::NoConfig => "no_config",
            Gap::CapReached => "cap_reached",
            Gap::EmptyAfterRedaction => "empty_after_redaction",
            Gap::Timeout => "timeout",
            Gap::HttpError => "http_error",
            Gap::ResponseOversized => "response_oversized",
            Gap::Schema => "schema",
            Gap::Late => "late",
            Gap::RateLimited => "rate_limited",
            Gap::RequestOversized => "request_oversized",
        }
    }

    /// All values, in the artifact's frozen order (the golden enum tie:
    /// this list, the artifact row, and the ADR §6 vocabulary are one).
    pub const ALL: [Gap; 12] = [
        Gap::Disabled,
        Gap::NotHosting,
        Gap::NoConfig,
        Gap::CapReached,
        Gap::EmptyAfterRedaction,
        Gap::Timeout,
        Gap::HttpError,
        Gap::ResponseOversized,
        Gap::Schema,
        Gap::Late,
        Gap::RateLimited,
        Gap::RequestOversized,
    ];
}

/// Frozen suggestion types (the four ADR-033 §2 classes — the
/// assistant reply's `hints` array may carry the display-only classes;
/// `tuning_hint` is digest-plane-only and is discarded whole in an
/// assistant reply per ADR-037 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuggestionType {
    TriageSummary,
    TuningHint,
    CatalogNote,
    Digest,
}

impl SuggestionType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "triage_summary" => Some(Self::TriageSummary),
            "tuning_hint" => Some(Self::TuningHint),
            "catalog_note" => Some(Self::CatalogNote),
            "digest" => Some(Self::Digest),
            _ => None,
        }
    }
}

/// Frozen confidence levels (ADR-033 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }
}

/// A suggestion's target: a 16-hex profile prefix or the literal
/// `fleet` (ADR-033 §4 schema).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuggestionTarget {
    Fleet,
    Profile16Hex(String),
}

/// One RECORDED suggestion — the display-record type of ADR-033 §5
/// ("No automatic promotion path may exist in code"): its hint values
/// are the ALREADY-CLAMPED, ALREADY-TYPED numbers; the raw model reply
/// `hint` map is not exposed. `Display` renders the summary under the
/// RC-5 contract (untrusted-provenance label, plain text).
#[derive(Debug, Clone, PartialEq)]
pub struct RecordedSuggestion {
    pub kind: SuggestionType,
    pub target: SuggestionTarget,
    pub confidence: Confidence,
    /// `(parameter, clamped_value, clamped, requires_adr)` — values
    /// inside the frozen clamp table's bounds or `requires_adr`-flagged.
    pub hints: Vec<(String, f64, bool, bool)>,
    /// Display-only free text; NEVER parsed. Rendered plain-text,
    /// capped, with the untrusted-provenance label adjacent (RC-5).
    pub rationale: String,
}

impl RecordedSuggestion {
    /// The frozen wire label of the suggestion type (telemetry label).
    pub fn kind_str(&self) -> &'static str {
        match self.kind {
            SuggestionType::TriageSummary => "triage_summary",
            SuggestionType::TuningHint => "tuning_hint",
            SuggestionType::CatalogNote => "catalog_note",
            SuggestionType::Digest => "digest",
        }
    }

    /// The frozen confidence label (telemetry label).
    pub fn confidence_str(&self) -> &'static str {
        match self.confidence {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

impl std::fmt::Display for RecordedSuggestion {
    /// The RC-5 rendering: the untrusted-provenance label travels WITH
    /// the summary — every consumer of the Display form re-states it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[assistant — untrusted, model-derived] {:?} target={} confidence={:?}",
            self.kind,
            match &self.target {
                SuggestionTarget::Fleet => "fleet".to_string(),
                SuggestionTarget::Profile16Hex(h) => h.clone(),
            },
            self.confidence
        )?;
        for (param, value, clamped, requires_adr) in &self.hints {
            write!(
                f,
                " {param}={value}{}{}",
                if *clamped { " (clamped)" } else { "" },
                if *requires_adr { " (requires_adr)" } else { "" }
            )?;
        }
        write!(f, " — {}", truncate_chars(&self.rationale, 2000))
    }
}

fn truncate_chars(text: &str, cap: usize) -> String {
    if text.chars().count() <= cap {
        return text.to_string();
    }
    let head: String = text.chars().take(cap).collect();
    format!("{head}…[TRUNCATED]")
}

/// Transport failure classes (the malformed-table injected conditions;
/// produced by the transport double in tests, by the pinned
/// local-gateway adapter in production).
#[derive(Debug, Clone, PartialEq)]
pub enum TransportFailure {
    /// Deadline exceeded → gap `timeout` (a late response afterwards is
    /// the no-op discard + diagnostic `late`).
    Deadline,
    /// HTTP status. 3xx arrives here too — redirects are NEVER followed
    /// (the loopback-only adapter pins this); every non-2xx maps to gap
    /// `http_error`.
    HttpStatus(u16),
    /// The response body exceeded `max_response_bytes` (detected at the
    /// adapter while buffering, or re-checked on returned bytes) → gap
    /// `response_oversized`.
    ResponseOversized,
    /// Network-level failure → gap `http_error`.
    Network(String),
}

/// One assistant-plane call — the ONLY egress payload. The gateway
/// address and the hosted profile id are deliberately ABSENT: they live
/// in the loopback-pinned transport (constructed from the running
/// node's bound gateway address and refused for any non-loopback
/// address), so no value inside the pure machine — corrupted or
/// otherwise — can redirect a call to another host. There is no key:
/// the 2026-10-15 owner directive removed the provider surface whole.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderRequest {
    /// The serialized, choke-point-verified request body.
    pub body: String,
    /// Per-call deadline, ms.
    pub timeout_ms: u64,
    /// The model-side output bound (`max_tokens` on the gateway call).
    pub max_completion_tokens: u32,
    /// Response body cap (the adapter refuses to buffer beyond it; the
    /// state machine re-checks on the returned bytes).
    pub max_response_bytes: usize,
    /// The fixed system prompt for this call (the assistant plane pins
    /// [`ASSISTANT_SYSTEM_PROMPT`
    /// (crate::advisory::assistant::ASSISTANT_SYSTEM_PROMPT)]).
    /// Repo-versioned constants only — never caller text.
    pub system_prompt: Option<&'static str>,
}

/// Parses ONE suggestion (the ADR-033 §4 shape; the assistant reply's
/// `hints` array parses through this — the assistant plane additionally
/// discards the `tuning_hint` class whole per ADR-037 §3.3/§3.7).
/// Public for the redaction suite's TR-AD-1 numeric-seam canaries.
/// The unit error is the malformed-table semantics: a failure discards
/// the suggestion WHOLE (counted), never a partial parse.
#[allow(clippy::result_unit_err)]
pub fn parse_one_suggestion(raw: &serde_json::Value) -> Result<RecordedSuggestion, ()> {
    let obj = raw.as_object().ok_or(())?;
    let kind =
        SuggestionType::parse(obj.get("type").and_then(|t| t.as_str()).ok_or(())?).ok_or(())?;
    let confidence =
        Confidence::parse(obj.get("confidence").and_then(|c| c.as_str()).ok_or(())?).ok_or(())?;
    let target = match obj.get("target").and_then(|t| t.as_str()) {
        Some("fleet") => SuggestionTarget::Fleet,
        Some(hex16) => {
            if !egress::is_profile_ref16(hex16) {
                return Err(());
            }
            SuggestionTarget::Profile16Hex(hex16.to_string())
        }
        None => return Err(()),
    };
    let rationale = obj
        .get("rationale")
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .to_string();

    // Hints: numeric values clamped per the frozen table; non-finite
    // (NaN/Inf, however encoded) discards the SUGGESTION, siblings
    // parse (TR-AD-1); an absent target is requires_adr=true — never an
    // improvised bound.
    let mut hints = Vec::new();
    if let Some(map) = obj.get("hint").and_then(|h| h.as_object()) {
        for (param, value) in map {
            let num = value.as_f64().ok_or(())?;
            if !num.is_finite() {
                return Err(());
            }
            match egress::clamp_hint(param, num) {
                HintAdmission::InRange(v) => hints.push((param.clone(), v, false, false)),
                HintAdmission::Clamped(v) => hints.push((param.clone(), v, true, false)),
                HintAdmission::RequiresAdr => hints.push((param.clone(), num, false, true)),
            }
        }
    }
    Ok(RecordedSuggestion {
        kind,
        target,
        confidence,
        hints,
        rationale,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The golden enum tie: the Gap vocabulary is 12 values, in the
    /// artifact's frozen order, and the labels round-trip — a value
    /// change without an ADR-037 amendment is a red build (the
    /// artifact row and the desktop corpus coverage ride the same
    /// list).
    #[test]
    fn golden_gap_vocabulary_is_the_frozen_twelve() {
        assert_eq!(
            Gap::ALL.iter().map(|g| g.as_str()).collect::<Vec<_>>(),
            vec![
                "disabled",
                "not_hosting",
                "no_config",
                "cap_reached",
                "empty_after_redaction",
                "timeout",
                "http_error",
                "response_oversized",
                "schema",
                "late",
                "rate_limited",
                "request_oversized",
            ]
        );
        // The provider-era labels are GONE — nothing can emit them
        // (the 2026-10-15 owner directive removed the surfaces they
        // described).
        for dead in ["no_key", "interval", "quota"] {
            assert!(
                !Gap::ALL.iter().map(|g| g.as_str()).any(|l| l == dead),
                "{dead} died with the provider surface"
            );
        }
        // The artifact row is byte-identical to the enum.
        let artifact = &egress::vocabulary().vocabularies["advisory_gap"].values;
        assert_eq!(
            artifact,
            &Gap::ALL
                .iter()
                .map(|g| g.as_str().to_string())
                .collect::<Vec<_>>()
        );
    }

    fn hint(type_: &str, target: &str, hint_map: serde_json::Value) -> RecordedSuggestion {
        parse_one_suggestion(&serde_json::json!({
            "type": type_, "target": target, "confidence": "low",
            "hint": hint_map, "rationale": "r"
        }))
        .unwrap()
    }

    #[test]
    fn suggestions_parse_targets_confidence_and_clamps() {
        // Fleet + profile targets.
        assert!(matches!(
            hint("digest", "fleet", serde_json::json!({})).target,
            SuggestionTarget::Fleet
        ));
        assert!(matches!(
            hint("digest", "0123456789abcdef", serde_json::json!({})).target,
            SuggestionTarget::Profile16Hex(_)
        ));
        // Malformed targets / unknown kinds / bad confidence drop.
        for bad in [
            serde_json::json!({"type":"digest","target":"not-hex!","confidence":"low"}),
            serde_json::json!({"type":"nope","target":"fleet","confidence":"low"}),
            serde_json::json!({"type":"digest","target":"fleet","confidence":"ultra"}),
            serde_json::json!({"target":"fleet","confidence":"low"}),
        ] {
            assert!(parse_one_suggestion(&bad).is_err(), "{bad}");
        }
        // Clamp discipline over the frozen table (§9.2(4) shape).
        let s = hint(
            "catalog_note",
            "fleet",
            serde_json::json!({"MSP_SHADOW_QUEUE_CAP_MS": 999999.0, "MSP_NEW_THING": 3.0}),
        );
        let cap = s
            .hints
            .iter()
            .find(|(p, _, _, _)| p == "MSP_SHADOW_QUEUE_CAP_MS")
            .unwrap();
        assert_eq!(cap.1, 120_000.0);
        assert!(cap.2, "out-of-range clamped");
        let adr = s
            .hints
            .iter()
            .find(|(p, _, _, _)| p == "MSP_NEW_THING")
            .unwrap();
        assert!(adr.3, "absent target requires_adr");
        // Non-finite discards the suggestion (TR-AD-1).
        let bad = serde_json::json!({
            "type":"digest","target":"fleet","confidence":"low",
            "hint": {"MSP_SHADOW_QUEUE_CAP_MS": serde_json::Value::String("NaN".into())}
        });
        assert!(parse_one_suggestion(&bad).is_err());
    }

    #[test]
    fn display_renders_the_untrusted_label_and_caps_rationale() {
        let s = RecordedSuggestion {
            kind: SuggestionType::Digest,
            target: SuggestionTarget::Fleet,
            confidence: Confidence::Low,
            hints: vec![("MSP_SHADOW_QUEUE_CAP_MS".into(), 1.0, true, false)],
            rationale: "x".repeat(3_000),
        };
        let text = s.to_string();
        assert!(text.starts_with("[assistant — untrusted, model-derived]"));
        assert!(text.contains("(clamped)"));
        assert!(text.contains("…[TRUNCATED]"));
        assert!(text.chars().count() < 2_400);
    }
}
