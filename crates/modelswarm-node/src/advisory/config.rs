//! `advisory.json` — the advisory plane's dedicated local config file
//! (ADR-033 §4, TR-RC-8), collapsed to what remains real by the
//! 2026-10-15 owner directive ("how about we remove this deepseek key
//! completely, and make the helper use the hosted model when hosted"):
//!
//! - The provider surface is GONE: no `endpoint_url`, no `model`, no
//!   `key_file`, no `MSP_ADVISORY_KEY_FILE`, no platform-default key
//!   path, no key reading anywhere. The assistant's backing is the
//!   machine's OWN hosted model behind the local loopback gateway —
//!   there is nothing to key and nowhere to point.
//! - What remains REAL is the ADR-037 §3.4 `assistant.*` cap rows plus
//!   the enable posture (`assistant.enabled`). Old advisory.json keys
//!   (the digest-plane rows, the provider rows) are IGNORED and
//!   PRESERVED on disk — never fatal, never rewritten. This module
//!   READS `advisory.json` and never writes it.
//!
//! TR-RC-8's ruling still holds structurally: the file is
//! `<data_dir>/advisory.json`, NOT `config.json` — the desktop's
//! `config.json` writer rewrites that file wholesale and unknown keys
//! must not live where a two-field writer can delete them.

use std::path::Path;

/// Advisory config file name under the data dir (ADR-033 §4, TR-RC-8).
pub const ADVISORY_CONFIG_FILE: &str = "advisory.json";

/// Advisory-plane configuration: the nine ADR-037 §3.4 `assistant.*`
/// rows (frozen defaults, tunable without an ADR). The digest-plane
/// and provider rows the ADR-033 §4 table used to carry are RETIRED by
/// the 2026-10-15 owner directive — present-but-unread on old installs.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AdvisoryConfig {
    pub assistant: AssistantCaps,
}

/// The nine ADR-037 §3.4 `assistant.*` rows.
#[derive(Debug, Clone, PartialEq)]
pub struct AssistantCaps {
    pub enabled: bool,
    pub max_calls_per_day: u32,
    pub max_calls_per_hour: u32,
    pub max_turns_per_conversation: u32,
    pub idle_reset_ms: u64,
    pub history_turns_sent: u32,
    pub max_request_bytes: usize,
    pub max_completion_tokens: u32,
    pub request_timeout_ms: u64,
}

impl Default for AssistantCaps {
    fn default() -> Self {
        Self {
            // ON by default since the 2026-10-15 collapse: the switch's
            // original default-off existed because cloud mode spent the
            // owner's money per call — the hosted-model backing costs
            // nothing external and egresses nothing off-machine, so the
            // helper rides whenever the machine hosts (the static floor
            // still serves whenever it does not).
            enabled: true,
            max_calls_per_day: 300,
            max_calls_per_hour: 60,
            max_turns_per_conversation: 40,
            idle_reset_ms: 900_000,
            history_turns_sent: 12,
            max_request_bytes: 49_152,
            max_completion_tokens: 1024,
            request_timeout_ms: 45_000,
        }
    }
}

/// Failures of reading `advisory.json`. A missing file is NOT an error —
/// it is the shipped default (static floor; the assistant answers with
/// the hosted model only while hosting).
#[derive(Debug, thiserror::Error)]
#[error("advisory config: {0}")]
pub struct ConfigError(String);

impl AdvisoryConfig {
    /// Reads `<data_dir>/advisory.json`. Missing file = defaults. A
    /// present-but-malformed file is an error the caller surfaces as
    /// the static floor with gap `no_config` — never a guess (fail
    /// closed). OLD keys (provider/digest rows) are ignored, never
    /// fatal: the directive removes the surface, not the operator's
    /// right to a stale file on disk.
    pub fn load(data_dir: &Path) -> Result<Self, ConfigError> {
        let path = data_dir.join(ADVISORY_CONFIG_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                Self::parse(&text).map_err(|e| ConfigError(format!("{}: {e}", path.display())))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(ConfigError(format!("{}: {e}", path.display()))),
        }
    }

    /// Parses the flat-object JSON form (unit-testable core; named
    /// `parse`, not `from_str`, to keep the lint surface honest about
    /// not being the `FromStr` trait).
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let root: serde_json::Value =
            serde_json::from_str(text).map_err(|e| ConfigError(format!("invalid JSON: {e}")))?;
        Self::from_json(&root)
    }

    /// Applies the KNOWN keys over the defaults; every other key —
    /// including every retired provider/digest row — is tolerated and
    /// ignored (preserved on disk by never writing this file).
    pub fn from_json(root: &serde_json::Value) -> Result<Self, ConfigError> {
        let obj = root
            .as_object()
            .ok_or_else(|| ConfigError("top level must be a flat JSON object".to_string()))?;
        let mut cfg = Self::default();
        let get_bool = |key: &str| -> Result<Option<bool>, ConfigError> {
            match obj.get(key) {
                None => Ok(None),
                Some(v) => v
                    .as_bool()
                    .map(Some)
                    .ok_or_else(|| ConfigError(format!("{key} must be a boolean"))),
            }
        };
        let get_u64 = |key: &str| -> Result<Option<u64>, ConfigError> {
            match obj.get(key) {
                None => Ok(None),
                Some(v) => v
                    .as_u64()
                    .map(Some)
                    .ok_or_else(|| ConfigError(format!("{key} must be an unsigned integer"))),
            }
        };
        let a = &mut cfg.assistant;
        if let Some(v) = get_bool("assistant.enabled")? {
            a.enabled = v;
        }
        if let Some(v) = get_u64("assistant.max_calls_per_day")? {
            a.max_calls_per_day = u32::try_from(v)
                .map_err(|_| ConfigError("assistant.max_calls_per_day overflows u32".into()))?;
        }
        if let Some(v) = get_u64("assistant.max_calls_per_hour")? {
            a.max_calls_per_hour = u32::try_from(v)
                .map_err(|_| ConfigError("assistant.max_calls_per_hour overflows u32".into()))?;
        }
        if let Some(v) = get_u64("assistant.max_turns_per_conversation")? {
            a.max_turns_per_conversation = u32::try_from(v).map_err(|_| {
                ConfigError("assistant.max_turns_per_conversation overflows u32".into())
            })?;
        }
        if let Some(v) = get_u64("assistant.idle_reset_ms")? {
            a.idle_reset_ms = v;
        }
        if let Some(v) = get_u64("assistant.history_turns_sent")? {
            a.history_turns_sent = u32::try_from(v)
                .map_err(|_| ConfigError("assistant.history_turns_sent overflows u32".into()))?;
        }
        if let Some(v) = get_u64("assistant.max_request_bytes")? {
            a.max_request_bytes = usize::try_from(v)
                .map_err(|_| ConfigError("assistant.max_request_bytes overflows usize".into()))?;
        }
        if let Some(v) = get_u64("assistant.max_completion_tokens")? {
            a.max_completion_tokens = u32::try_from(v)
                .map_err(|_| ConfigError("assistant.max_completion_tokens overflows u32".into()))?;
        }
        if let Some(v) = get_u64("assistant.request_timeout_ms")? {
            a.request_timeout_ms = v;
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_defaults_pin_the_adr037_assistant_rows() {
        // §9.2(8) as extended by ADR-037 §4.4 and collapsed by the
        // 2026-10-15 owner directive: the nine §3.4 defaults are the
        // WHOLE config — any value change without an amendment is a red
        // build.
        let cfg = AdvisoryConfig::default();
        let a = &cfg.assistant;
        assert!(a.enabled, "on by default since the 2026-10-15 collapse");
        assert_eq!(a.max_calls_per_day, 300);
        assert_eq!(a.max_calls_per_hour, 60);
        assert_eq!(a.max_turns_per_conversation, 40);
        assert_eq!(a.idle_reset_ms, 900_000);
        assert_eq!(a.history_turns_sent, 12);
        assert_eq!(a.max_request_bytes, 49_152);
        assert_eq!(a.max_completion_tokens, 1024);
        assert_eq!(a.request_timeout_ms, 45_000);
    }

    #[test]
    fn missing_file_is_default_static_floor_config() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = AdvisoryConfig::load(dir.path()).unwrap();
        assert_eq!(cfg, AdvisoryConfig::default());
    }

    #[test]
    fn assistant_rows_parse_and_old_provider_rows_are_ignored() {
        // A REAL old-era advisory.json (provider key file, endpoint,
        // digest caps) parses FINE today: every retired row is ignored,
        // the assistant rows still apply — never fatal, nothing read.
        let cfg = AdvisoryConfig::parse(
            r#"{"enabled":true,"endpoint_url":"https://api.deepseek.example/v1/chat/completions",
                "model":"DeepSeek-V4.1-Flash","key_file":"C:/keys/old.txt",
                "max_calls_per_day":12,"min_interval_ms":60000,"events_threshold":5,
                "assistant.enabled":true,"assistant.max_calls_per_hour":30,
                "future_key":"whatever"}"#,
        )
        .unwrap();
        assert!(cfg.assistant.enabled);
        assert_eq!(cfg.assistant.max_calls_per_hour, 30);
        assert_eq!(cfg.assistant.max_calls_per_day, 300, "unwritten = default");
    }

    #[test]
    fn malformed_config_fails_closed() {
        assert!(AdvisoryConfig::parse("{nope").is_err());
        assert!(AdvisoryConfig::parse("[1,2]").is_err());
        assert!(AdvisoryConfig::parse(r#"{"assistant.enabled":"yes"}"#).is_err());
        assert!(AdvisoryConfig::parse(r#"{"assistant.max_calls_per_day":-1}""#).is_err());
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(ADVISORY_CONFIG_FILE), "{bad").unwrap();
        assert!(AdvisoryConfig::load(dir.path()).is_err());
    }
}
