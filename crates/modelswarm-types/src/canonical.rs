//! Canonical JSON (msp-v1 §2.2 / ADR-011): the only serialization form that is
//! ever hashed or signed.
//!
//! Rules, matching the Node reference validator
//! (`apps/tracker/scripts/validate-vectors.mjs`) byte for byte:
//!
//! 1. UTF-8, no insignificant whitespace.
//! 2. Object keys sorted lexicographically, recursively.
//! 3. Integers in decimal; **floating-point numbers are rejected** — every
//!    hashed ModelSwarm payload (manifests, envelopes, leases) is defined to
//!    contain only strings, integers, booleans, arrays and objects, so a float
//!    reaching this function is a schema violation and fails closed.
//! 4. Strings use JSON minimum escaping (identical to `serde_json` and to
//!    JavaScript `JSON.stringify` for the same input).
//! 5. No trailing newline.
//!
//! Sorting is applied by this module itself (`Value::Object` may or may not
//! preserve insertion order depending on workspace feature unification), so
//! canonical output does not depend on how the value was built.

use std::fmt;

use serde_json::Value;

/// Failure modes of [`canonical_json`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// A floating-point number was encountered. Hashed ModelSwarm payloads
    /// never contain floats (see the module documentation); this is a
    /// fail-closed rejection, not a formatting choice.
    FloatRejected,
    /// The serialized value could not be produced.
    Serde(String),
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonicalError::FloatRejected => {
                write!(f, "canonical JSON rejected a floating-point number")
            }
            CanonicalError::Serde(e) => write!(f, "canonical JSON serialization failed: {e}"),
        }
    }
}

impl std::error::Error for CanonicalError {}

/// Renders `value` as canonical JSON (sorted keys, compact, integers only).
pub fn canonical_json(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // Integers only: `u64`/`i64` cover every numeric field defined by
            // the frozen schemas; anything else (floats, exotic numbers) is
            // rejected so no payload can hash differently across platforms.
            if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else {
                return Err(CanonicalError::FloatRejected);
            }
        }
        Value::String(s) => {
            // serde_json string encoding is exactly the JSON minimum escaping
            // required by msp-v1 §2.2 (quote, backslash, control characters).
            out.push_str(
                &serde_json::to_string(s).map_err(|e| CanonicalError::Serde(e.to_string()))?,
            );
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(
                    &serde_json::to_string(key.as_str())
                        .map_err(|e| CanonicalError::Serde(e.to_string()))?,
                );
                out.push(':');
                write_canonical(&map[key.as_str()], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_recursively_and_stays_compact() {
        let v = json!({
            "z": {"b": 2, "a": 1},
            "a": [true, false, null, "x"],
            "m": "plain"
        });
        assert_eq!(
            canonical_json(&v).unwrap(),
            r#"{"a":[true,false,null,"x"],"m":"plain","z":{"a":1,"b":2}}"#
        );
    }

    #[test]
    fn rejects_floats() {
        assert_eq!(
            canonical_json(&json!({"a": 1.5})),
            Err(CanonicalError::FloatRejected)
        );
        assert_eq!(
            canonical_json(&json!({"a": 1e2})),
            Err(CanonicalError::FloatRejected)
        );
    }

    #[test]
    fn accepts_integer_bounds() {
        assert_eq!(canonical_json(&json!({"a": 0})).unwrap(), r#"{"a":0}"#);
        assert_eq!(
            canonical_json(&json!(u64::MAX)).unwrap(),
            u64::MAX.to_string()
        );
        assert_eq!(
            canonical_json(&json!(i64::MIN)).unwrap(),
            i64::MIN.to_string()
        );
    }

    #[test]
    fn escapes_like_json_minimum() {
        let v = json!("quote\" back\\ nl\n tab\t\u{0001}");
        assert_eq!(
            canonical_json(&v).unwrap(),
            "\"quote\\\" back\\\\ nl\\n tab\\t\\u0001\""
        );
    }

    #[test]
    fn canonical_form_is_idempotent() {
        let v = json!({"b": [{"y": 1, "x": [2, 1]}], "a": "s"});
        let once = canonical_json(&v).unwrap();
        let reparsed: Value = serde_json::from_str(&once).unwrap();
        let twice = canonical_json(&reparsed).unwrap();
        assert_eq!(once, twice);
    }
}
