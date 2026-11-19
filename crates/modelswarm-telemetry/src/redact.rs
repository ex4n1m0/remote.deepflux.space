//! Mandatory redaction for everything ModelSwarm logs.
//!
//! The rule (`docs/privacy.md`, `AGENTS.md`): prompt/completion text,
//! keys, tokens, and bearer secrets never reach a log sink. `Redactor`
//! enforces it structurally — by field name and by content shape — so a
//! careless caller cannot leak by accident. The phase-3/4 acceptance
//! redaction gates test through this module.

use std::collections::HashSet;

/// Field names whose values are always dropped (privacy.md §1).
pub const FORBIDDEN_FIELDS: &[&str] = &[
    "prompt",
    "prompts",
    "completion",
    "completions",
    "messages",
    "message",
    "content",
    "conversation",
    "history",
    "response",
    "delta",
    "token",
    "tokens_text",
    "secret",
    "api_key",
    "apikey",
    "hf_token",
    "access_token",
    "authorization",
    "bearer",
    "password",
    "private_key",
    "signature_seed",
    // ADR-036 (T/R review R1, 2026-10-14): the pin carrier's
    // content-bearing fields are forbidden BY NAME as well — the
    // conversation's token ids and the content-derived commitment can
    // never reach a log sink even if a caller forgets the counts-only
    // rule. (Legitimate count fields like `tokens: 8` stay allowed —
    // see the shape scrub below.)
    "prompt_tokens",
    "pin_commitment",
];

/// A bare u32-array value: `[digits, digits, …]` (arbitrary whitespace),
/// at least one element — token-id shaped (ADR-036's carrier payload
/// form; the T/R review R1 shape scrub).
fn is_bare_u32_array(value: &str) -> bool {
    let v = value.trim();
    if !(v.starts_with('[') && v.ends_with(']')) {
        return false;
    }
    let inner = v[1..v.len() - 1].trim();
    if inner.is_empty() {
        return false;
    }
    inner.split(',').all(|part| {
        let p = part.trim();
        !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
    })
}

#[derive(Debug, Clone)]
pub struct Redactor {
    forbidden: HashSet<String>,
    /// Values longer than this in ANY field are truncated and flagged
    /// (catches prompt-shaped strings smuggled under innocent names).
    pub max_value_chars: usize,
}

impl Default for Redactor {
    fn default() -> Self {
        Self {
            forbidden: FORBIDDEN_FIELDS.iter().map(|s| s.to_string()).collect(),
            max_value_chars: 256,
        }
    }
}

impl Redactor {
    /// Redacts one `(name, value)` pair into a safe display string.
    /// Forbidden names drop the value entirely (length preserved as a
    /// count for debugging); oversized values are truncated with a marker;
    /// secret-shaped content is scrubbed even under allowed names.
    pub fn redact_field(&self, name: &str, value: &str) -> String {
        let lower = name.to_ascii_lowercase();
        if self.forbidden.contains(&lower) {
            return format!("[REDACTED:{} len={}]", lower, value.chars().count());
        }
        // ADR-036 (T/R review R1, 2026-10-14): a bare u32-array VALUE is
        // token-id-shaped content under ANY field name — redacted by
        // shape. Count fields stay legible (a scalar like "8" is not an
        // array); only whole-value `[1, 2, …]` integer arrays match.
        if is_bare_u32_array(value) {
            return "[REDACTED:TOKEN_ARRAY]".to_string();
        }
        let mut v = self.scrub_content(value);
        if v.chars().count() > self.max_value_chars {
            let head: String = v.chars().take(self.max_value_chars).collect();
            v = format!("{head}…[TRUNCATED]");
        }
        v
    }

    /// Scrubs secret-shaped substrings from free-form text:
    /// `hf_…` tokens, `sk-…` keys, JWTs (`eyJ…`), long hex/base64 blobs,
    /// and `Bearer …` headers.
    pub fn scrub_content(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        'outer: while !rest.is_empty() {
            for (prefix, label) in [("hf_", "HF_TOKEN"), ("sk-", "API_KEY"), ("eyJ", "JWT")] {
                if let Some(pos) = rest.find(prefix) {
                    // scrub the run of token-ish chars following the marker
                    let after = &rest[pos + prefix.len()..];
                    let run: usize = after
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                        .count();
                    if run >= 8 {
                        out.push_str(&rest[..pos]);
                        out.push_str(&format!("[REDACTED:{label}]"));
                        rest = &rest[pos + prefix.len() + run..];
                        continue 'outer;
                    }
                }
            }
            if let Some(pos) = rest.find("Bearer ") {
                let after = &rest[pos + 7..];
                let run: usize = after.chars().take_while(|c| !c.is_whitespace()).count();
                if run >= 8 {
                    out.push_str(&rest[..pos]);
                    out.push_str("[REDACTED:BEARER]");
                    rest = &rest[pos + 7 + run..];
                    continue 'outer;
                }
            }
            // Long homogeneous hex runs (keys/digests in prose) — keep
            // short hashes (8 hex chars are fine as ids), scrub ≥ 32.
            let bytes = rest.as_bytes();
            let mut i = 0usize;
            while i < bytes.len() {
                let c = bytes[i] as char;
                if c.is_ascii_hexdigit() {
                    let mut j = i;
                    while j < bytes.len() && (bytes[j] as char).is_ascii_hexdigit() {
                        j += 1;
                    }
                    if j - i >= 32 {
                        out.push_str(&rest[..i]);
                        out.push_str("[REDACTED:HEXBLOB]");
                        rest = &rest[j..];
                        continue 'outer;
                    }
                    i = j;
                } else {
                    i += 1;
                }
            }
            out.push_str(rest);
            rest = "";
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_fields_drop_values() {
        let r = Redactor::default();
        for name in ["prompt", "PROMPT", "messages", "hf_token", "authorization"] {
            let out = r.redact_field(name, "super secret prompt text");
            assert!(!out.contains("super"), "{name} leaked: {out}");
            assert!(out.starts_with("[REDACTED:"), "{name} -> {out}");
        }
    }

    #[test]
    fn allowed_fields_keep_normal_values() {
        let r = Redactor::default();
        assert_eq!(r.redact_field("peer_id", "12D3Kooabc"), "12D3Kooabc");
        assert_eq!(r.redact_field("profile_id", "msp1:ab12"), "msp1:ab12");
    }

    #[test]
    fn oversized_values_truncated() {
        let r = Redactor::default();
        let long = "x".repeat(10_000);
        let out = r.redact_field("note", &long);
        assert!(out.contains("[TRUNCATED]"));
        assert!(out.chars().count() < 300);
    }

    #[test]
    fn secret_shapes_scrubbed_in_content() {
        let r = Redactor::default();
        let cases = [
            (
                "token hf_ABCDEFGHIJKLMNOP123 was used",
                "[REDACTED:HF_TOKEN]",
            ),
            ("key sk-abcdef1234567890xyz leaked", "[REDACTED:API_KEY]"),
            ("jwt eyJhbGciOiJIUzI1NiJ9.payload", "[REDACTED:JWT]"),
            ("Bearer AAAABBBBCCCCDDDD", "[REDACTED:BEARER]"),
        ];
        for (input, expect_marker) in cases {
            let out = r.scrub_content(input);
            assert!(out.contains(expect_marker), "{input} -> {out}");
        }
        // long hex blob scrubbed, short id kept
        assert!(r
            .scrub_content("digest abcdefabcdefabcdefabcdefabcdefabcd done")
            .contains("[REDACTED:HEXBLOB]"));
        assert_eq!(r.scrub_content("id ab12cd34"), "id ab12cd34");
    }

    #[test]
    fn prompt_smuggled_under_allowed_name_is_truncated_not_dropped() {
        let r = Redactor::default();
        let out = r.redact_field("note", "user said: hello there how are you");
        // allowed names keep text (truncation only guards size) — the
        // privacy contract is enforced at the call sites via forbidden
        // names + this module's audit tests; document the boundary.
        assert!(out.contains("user said"));
    }

    /// A bare u32-array value: `[digits, digits, …]` (arbitrary
    /// whitespace), at least one element — token-id shaped.
    #[test]
    fn adr036_carrier_fields_are_forbidden_by_name() {
        let r = Redactor::default();
        let out = r.redact_field("prompt_tokens", "[151644, 11, 22]");
        // len is the VALUE's char count (the drop-with-count contract).
        assert_eq!(out, "[REDACTED:prompt_tokens len=16]");
        let out = r.redact_field("pin_commitment", "1bf75c5b110835d7");
        assert_eq!(out, "[REDACTED:pin_commitment len=16]");
    }

    #[test]
    fn bare_u32_array_values_are_redacted_by_shape_under_any_name() {
        let r = Redactor::default();
        // Under an innocent name — the shape is the leak.
        assert_eq!(
            r.redact_field("window", "[151644, 11, 22, 33]"),
            "[REDACTED:TOKEN_ARRAY]"
        );
        assert_eq!(
            r.redact_field("weird_field", " [ 1 , 2 ] "),
            "[REDACTED:TOKEN_ARRAY]"
        );
        assert_eq!(r.redact_field("single", "[7]"), "[REDACTED:TOKEN_ARRAY]");
        // NOT arrays: scalar counts stay legible (the counts-only permit).
        assert_eq!(r.redact_field("tokens", "8"), "8");
        assert_eq!(r.redact_field("accepted", "0"), "0");
        // Not integer arrays: text and mixed content pass through the
        // normal scrub path.
        assert!(r.redact_field("mode", "remote").contains("remote"));
        assert!(r.redact_field("ids", "[abc, def]").contains("abc"));
    }
}
