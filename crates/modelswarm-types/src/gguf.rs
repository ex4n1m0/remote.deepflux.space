//! GGUF metadata reading and ADR-022 identity-hash derivation.
//!
//! The resolver (`scripts/resolve-candidate.mjs`) derives a manifest's
//! `tokenizer_hash`, `chat_template_hash`, and `architecture_hash` from the
//! GGUF artifact itself; this module re-derives the same three hashes from
//! the same bytes so a node can verify possession (ADR-011 §possession,
//! ADR-022). The canonicalization rules are pinned by ADR-022:
//!
//! - GGUF v3 only; `[u64 key_len | key | u32 value_type | value]` layout.
//! - Strings decode as lossy UTF-8 (U+FFFD per invalid sequence).
//! - f32 metadata is hashed as the decimal u32 of its IEEE-754 bit pattern
//!   (`_bits` members) — canonical JSON forbids floats.
//! - Exactly the members ADR-022 enumerates; anything missing fails closed.

use crate::canonical::canonical_json;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufReader, Read};
use std::path::Path;

/// Errors from reading or hashing a GGUF artifact.
#[derive(Debug)]
pub enum GgufError {
    /// Underlying I/O failure (message included).
    Io(String),
    /// Not a GGUF file (bad magic).
    NotGguf,
    /// Unsupported GGUF version (only v3).
    UnsupportedVersion(u32),
    /// Malformed metadata (truncated buffer, bad length, bad type tag).
    Malformed(String),
    /// A required identity key is missing — fail closed (ADR-011/022).
    MissingKey(String),
    /// A required key exists but with the wrong value type.
    BadValue(String),
}

impl fmt::Display for GgufError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GgufError::Io(e) => write!(f, "gguf io: {e}"),
            GgufError::NotGguf => write!(f, "not a GGUF file (bad magic)"),
            GgufError::UnsupportedVersion(v) => write!(f, "unsupported GGUF version {v} (only v3)"),
            GgufError::Malformed(e) => write!(f, "malformed GGUF metadata: {e}"),
            GgufError::MissingKey(k) => {
                write!(f, "GGUF metadata missing required key {k:?} (fail-closed)")
            }
            GgufError::BadValue(k) => write!(f, "GGUF key {k:?} has an unusable value type"),
        }
    }
}

impl std::error::Error for GgufError {}

/// The GGUF metadata values this module cares about. Unknown shapes are
/// consumed (the reader still advances exactly over them) and surfaced as
/// [`GgufValue::Other`].
#[derive(Debug, Clone, PartialEq)]
pub enum GgufValue {
    U32(u32),
    I32(i32),
    /// f32, kept as its IEEE-754 bit pattern (ADR-022 float rule).
    F32Bits(u32),
    Bool(bool),
    Str(String),
    /// String array: lossy UTF-8 text (hash inputs, ADR-022) plus the raw
    /// bytes (exact-vocab lookups; byte-fallback tokens are invalid UTF-8).
    StrArray(Vec<String>, Vec<Vec<u8>>),
    I32Array(Vec<i32>),
    Other,
}

/// Exact bytes→id vocabulary plus EOS, for lossless token-id recovery in
/// runtimes (Phase H3). Built from `tokenizer.ggml.tokens` raw bytes.
#[derive(Debug, Clone)]
pub struct TokenVocab {
    pub bytes_to_id: std::collections::HashMap<Vec<u8>, u32>,
    pub eos_id: Option<u32>,
}

/// Builds a [`TokenVocab`] from GGUF metadata (`tokenizer.ggml.tokens` +
/// `tokenizer.ggml.eos_token_id`). `None` when the token array is missing.
///
/// For `tokenizer.ggml.model == "gpt2"` (byte-level BPE: Qwen, GPT-2,
/// Llama 3, …) GGUF stores tokens in the GPT-2 byte-to-unicode alphabet
/// (`" I"` as `"ĠI"`), while inference servers report generated tokens as
/// real UTF-8 bytes — so each token string is decoded back through the
/// GPT-2 byte decoder before indexing. Tokens containing characters outside
/// the mapping are skipped (they are not part of the byte alphabet).
pub fn token_vocab(metadata: &BTreeMap<String, GgufValue>) -> Option<TokenVocab> {
    let gpt2 = matches!(
        metadata.get("tokenizer.ggml.model"),
        Some(GgufValue::Str(model)) if model == "gpt2"
    );
    let decoder = gpt2.then(gpt2_byte_decoder);
    let raw = match metadata.get("tokenizer.ggml.tokens")? {
        GgufValue::StrArray(_, raw) => raw.clone(),
        _ => return None,
    };
    let mut bytes_to_id = std::collections::HashMap::with_capacity(raw.len());
    for (id, token) in raw.into_iter().enumerate() {
        let Some(id) = u32::try_from(id).ok() else {
            continue;
        };
        let bytes = match &decoder {
            Some(decoder) => {
                let mut decoded = Vec::with_capacity(token.len());
                let mut ok = true;
                for ch in String::from_utf8_lossy(&token).chars() {
                    match decoder.get(&ch) {
                        Some(byte) => decoded.push(*byte),
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok {
                    continue;
                }
                decoded
            }
            None => token,
        };
        // On byte collisions keep the lowest id (stable, deterministic).
        bytes_to_id.entry(bytes).or_insert(id);
    }
    let eos_id = match metadata.get("tokenizer.ggml.eos_token_id") {
        Some(GgufValue::U32(v)) => Some(*v),
        _ => None,
    };
    Some(TokenVocab {
        bytes_to_id,
        eos_id,
    })
}

/// The GPT-2 byte-to-unicode table, inverted: printable/latin self-mapped
/// bytes identity, every other byte assigned a distinct char ≥ U+0100
/// (the reversible mapping from the GPT-2 encoder; `Ġ` = space).
fn gpt2_byte_decoder() -> std::collections::HashMap<char, u8> {
    let mut decoder = std::collections::HashMap::with_capacity(256);
    let mut next = 0u32;
    for byte in 0u16..=255 {
        let keep = (33..=126).contains(&byte)
            || (161..=172).contains(&byte)
            || (174..=255).contains(&byte);
        let code = if keep {
            u32::from(byte)
        } else {
            let code = 256 + next;
            next += 1;
            code
        };
        if let Some(ch) = char::from_u32(code) {
            decoder.insert(ch, byte as u8);
        }
    }
    decoder
}

/// The three ADR-022 identity hashes (lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GgufIdentityHashes {
    pub tokenizer_hash: String,
    pub chat_template_hash: String,
    pub architecture_hash: String,
}

/// Reads the metadata KV section of a GGUF v3 file.
pub fn read_metadata(path: impl AsRef<Path>) -> Result<BTreeMap<String, GgufValue>, GgufError> {
    let file = std::fs::File::open(path.as_ref()).map_err(|e| GgufError::Io(e.to_string()))?;
    read_metadata_from(BufReader::new(file))
}

/// Reads the metadata KV section from in-memory GGUF bytes.
pub fn read_metadata_bytes(bytes: &[u8]) -> Result<BTreeMap<String, GgufValue>, GgufError> {
    read_metadata_from(bytes)
}

fn read_metadata_from<R: Read>(mut r: R) -> Result<BTreeMap<String, GgufValue>, GgufError> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic).map_err(io("magic"))?;
    if magic != *b"GGUF" {
        return Err(GgufError::NotGguf);
    }
    let version = read_u32(&mut r)?;
    if version != 3 {
        return Err(GgufError::UnsupportedVersion(version));
    }
    let _tensor_count = read_u64(&mut r)?;
    let kv_count = read_u64(&mut r)?;

    let mut map = BTreeMap::new();
    for _ in 0..kv_count {
        let key = read_string(&mut r)?;
        let value_type = read_u32(&mut r)?;
        let value = read_value(&mut r, value_type)?;
        map.insert(key, value);
    }
    Ok(map)
}

fn io(step: &'static str) -> impl Fn(std::io::Error) -> GgufError {
    move |e| GgufError::Io(format!("{step}: {e}"))
}

fn read_exact_n<R: Read>(r: &mut R, n: usize, what: &str) -> Result<Vec<u8>, GgufError> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)
        .map_err(|e| GgufError::Malformed(format!("{what}: {e}")))?;
    Ok(buf)
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32, GgufError> {
    let b = read_exact_n(r, 4, "u32")?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64, GgufError> {
    let b = read_exact_n(r, 8, "u64")?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn read_string_bytes<R: Read>(r: &mut R) -> Result<Vec<u8>, GgufError> {
    let n = read_u64(r)? as usize;
    read_exact_n(r, n, "string")
}

fn read_string<R: Read>(r: &mut R) -> Result<String, GgufError> {
    let bytes = read_string_bytes(r)?;
    // Lossy UTF-8 (U+FFFD) — matches the Node reader (ADR-022 §1).
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn read_value<R: Read>(r: &mut R, value_type: u32) -> Result<GgufValue, GgufError> {
    match value_type {
        0 | 1 | 7 => {
            let b = read_exact_n(r, 1, "u8/bool")?;
            if value_type == 7 {
                Ok(GgufValue::Bool(b[0] != 0))
            } else {
                Ok(GgufValue::Other)
            }
        }
        2 | 3 => {
            read_exact_n(r, 2, "u16/i16")?;
            Ok(GgufValue::Other)
        }
        4 => Ok(GgufValue::U32(read_u32(r)?)),
        5 => {
            let b = read_exact_n(r, 4, "i32")?;
            Ok(GgufValue::I32(i32::from_le_bytes([b[0], b[1], b[2], b[3]])))
        }
        6 => {
            let b = read_exact_n(r, 4, "f32")?;
            Ok(GgufValue::F32Bits(u32::from_le_bytes([
                b[0], b[1], b[2], b[3],
            ])))
        }
        8 => Ok(GgufValue::Str(read_string(r)?)),
        9 => {
            let element_type = read_u32(r)?;
            let n = read_u64(r)? as usize;
            let mut strings = Vec::new();
            let mut raw = Vec::new();
            let mut ints = Vec::new();
            for _ in 0..n {
                match element_type {
                    8 => {
                        let bytes = read_string_bytes(r)?;
                        strings.push(String::from_utf8_lossy(&bytes).into_owned());
                        raw.push(bytes);
                    }
                    5 => {
                        let b = read_exact_n(r, 4, "i32 element")?;
                        ints.push(i32::from_le_bytes([b[0], b[1], b[2], b[3]]));
                    }
                    other => {
                        read_value(r, other)?;
                    }
                }
            }
            if element_type == 8 {
                Ok(GgufValue::StrArray(strings, raw))
            } else if element_type == 5 {
                Ok(GgufValue::I32Array(ints))
            } else {
                Ok(GgufValue::Other)
            }
        }
        10..=12 => {
            read_exact_n(r, 8, "u64/i64/f64")?;
            Ok(GgufValue::Other)
        }
        other => Err(GgufError::Malformed(format!(
            "unsupported value type {other}"
        ))),
    }
}

// ADR-022 amendment (2026-10-06): tokenizer keys a GGUF may legitimately
// omit hash as null — absence itself is identity, never an error and never
// a guessed default. Applies to add_bos_token and padding_token_id (both
// observed absent in Qwen3.5-family conversions); every other member of
// the ADR-022 tokenizer object stays fail-closed.
fn nullable_bool(metadata: &BTreeMap<String, GgufValue>, key: &str) -> Result<Value, GgufError> {
    match get(metadata, key) {
        Ok(GgufValue::Bool(b)) => Ok(Value::Bool(*b)),
        Ok(_) => Err(GgufError::BadValue(key.to_string())),
        Err(GgufError::MissingKey(_)) => Ok(Value::Null),
        Err(e) => Err(e),
    }
}

fn nullable_u32(metadata: &BTreeMap<String, GgufValue>, key: &str) -> Result<Value, GgufError> {
    match get(metadata, key) {
        Ok(GgufValue::U32(v)) => Ok(Value::Number((*v).into())),
        Ok(_) => Err(GgufError::BadValue(key.to_string())),
        Err(GgufError::MissingKey(_)) => Ok(Value::Null),
        Err(e) => Err(e),
    }
}

/// Derives the three ADR-022 identity hashes from GGUF metadata.
pub fn identity_hashes(
    metadata: &BTreeMap<String, GgufValue>,
) -> Result<GgufIdentityHashes, GgufError> {
    let arch = get_str(metadata, "general.architecture")?;

    // ---- tokenizer_hash -------------------------------------------------
    let mut tokenizer = Map::new();
    tokenizer.insert(
        "add_bos_token".into(),
        nullable_bool(metadata, "tokenizer.ggml.add_bos_token")?,
    );
    tokenizer.insert(
        "bos_token_id".into(),
        nullable_u32(metadata, "tokenizer.ggml.bos_token_id")?,
    );
    tokenizer.insert(
        "eos_token_id".into(),
        u32_value(metadata, "tokenizer.ggml.eos_token_id")?,
    );
    tokenizer.insert(
        "merges".into(),
        Value::Array(
            get_str_array(metadata, "tokenizer.ggml.merges")?
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    tokenizer.insert(
        "model".into(),
        Value::String(get_str(metadata, "tokenizer.ggml.model")?.to_string()),
    );
    tokenizer.insert(
        "padding_token_id".into(),
        nullable_u32(metadata, "tokenizer.ggml.padding_token_id")?,
    );
    tokenizer.insert(
        "pre".into(),
        Value::String(get_str(metadata, "tokenizer.ggml.pre")?.to_string()),
    );
    tokenizer.insert(
        "token_type".into(),
        Value::Array(
            get_i32_array(metadata, "tokenizer.ggml.token_type")?
                .into_iter()
                .map(|v| Value::Number(v.into()))
                .collect(),
        ),
    );
    tokenizer.insert(
        "tokens".into(),
        Value::Array(
            get_str_array(metadata, "tokenizer.ggml.tokens")?
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    let tokens = get_str_array(metadata, "tokenizer.ggml.tokens")?;
    let types = get_i32_array(metadata, "tokenizer.ggml.token_type")?;
    if tokens.len() != types.len() {
        return Err(GgufError::BadValue(
            "tokenizer.ggml.tokens/token_type length mismatch".into(),
        ));
    }

    // ---- architecture_hash (ADR-022 subset) ------------------------------
    let mut architecture = Map::new();
    architecture.insert(
        "general.architecture".into(),
        Value::String(arch.to_string()),
    );
    architecture.insert(
        "attention.head_count".into(),
        u32_value(metadata, &format!("{arch}.attention.head_count"))?,
    );
    architecture.insert(
        "attention.head_count_kv".into(),
        u32_value(metadata, &format!("{arch}.attention.head_count_kv"))?,
    );
    architecture.insert(
        "attention.layer_norm_rms_epsilon_bits".into(),
        f32_bits_value(
            metadata,
            &format!("{arch}.attention.layer_norm_rms_epsilon"),
        )?,
    );
    architecture.insert(
        "block_count".into(),
        u32_value(metadata, &format!("{arch}.block_count"))?,
    );
    architecture.insert(
        "context_length".into(),
        u32_value(metadata, &format!("{arch}.context_length"))?,
    );
    architecture.insert(
        "embedding_length".into(),
        u32_value(metadata, &format!("{arch}.embedding_length"))?,
    );
    architecture.insert(
        "feed_forward_length".into(),
        u32_value(metadata, &format!("{arch}.feed_forward_length"))?,
    );
    architecture.insert(
        "file_type".into(),
        u32_value(metadata, "general.file_type")?,
    );
    architecture.insert(
        "rope.freq_base_bits".into(),
        f32_bits_value(metadata, &format!("{arch}.rope.freq_base"))?,
    );

    // ---- chat_template_hash ----------------------------------------------
    let template = get_str(metadata, "tokenizer.chat_template")?;

    Ok(GgufIdentityHashes {
        tokenizer_hash: hash_canonical(Value::Object(tokenizer))?,
        chat_template_hash: hex_sha256(template.as_bytes()),
        architecture_hash: hash_canonical(Value::Object(architecture))?,
    })
}

fn hash_canonical(value: Value) -> Result<String, GgufError> {
    let canonical = canonical_json(&value)
        .map_err(|e| GgufError::Malformed(format!("canonical serialization: {e}")))?;
    Ok(hex_sha256(canonical.as_bytes()))
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn get<'a>(
    metadata: &'a BTreeMap<String, GgufValue>,
    key: &str,
) -> Result<&'a GgufValue, GgufError> {
    metadata
        .get(key)
        .ok_or_else(|| GgufError::MissingKey(key.to_string()))
}

fn get_str<'a>(metadata: &'a BTreeMap<String, GgufValue>, key: &str) -> Result<&'a str, GgufError> {
    match get(metadata, key)? {
        GgufValue::Str(s) => Ok(s),
        _ => Err(GgufError::BadValue(key.to_string())),
    }
}

fn get_str_array(
    metadata: &BTreeMap<String, GgufValue>,
    key: &str,
) -> Result<Vec<String>, GgufError> {
    match get(metadata, key)? {
        GgufValue::StrArray(v, _) => Ok(v.clone()),
        _ => Err(GgufError::BadValue(key.to_string())),
    }
}

fn get_i32_array(metadata: &BTreeMap<String, GgufValue>, key: &str) -> Result<Vec<i32>, GgufError> {
    match get(metadata, key)? {
        GgufValue::I32Array(v) => Ok(v.clone()),
        _ => Err(GgufError::BadValue(key.to_string())),
    }
}

fn u32_value(metadata: &BTreeMap<String, GgufValue>, key: &str) -> Result<Value, GgufError> {
    match get(metadata, key)? {
        GgufValue::U32(v) => Ok(Value::Number((*v).into())),
        _ => Err(GgufError::BadValue(key.to_string())),
    }
}

fn f32_bits_value(metadata: &BTreeMap<String, GgufValue>, key: &str) -> Result<Value, GgufError> {
    match get(metadata, key)? {
        GgufValue::F32Bits(v) => Ok(Value::Number((*v).into())),
        _ => Err(GgufError::BadValue(key.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal GGUF v3 writer for the identity keys ADR-022 requires.
    struct GgufWriter {
        buf: Vec<u8>,
    }

    impl GgufWriter {
        fn new() -> Self {
            let mut buf = b"GGUF".to_vec();
            buf.extend_from_slice(&3u32.to_le_bytes());
            buf.extend_from_slice(&0u64.to_le_bytes()); // tensor count
            buf.extend_from_slice(&0u64.to_le_bytes()); // kv count (patched in finish)
            Self { buf }
        }

        fn raw(&mut self, len: u64) {
            self.buf.extend_from_slice(&len.to_le_bytes());
        }

        fn key(&mut self, k: &str) {
            self.raw(k.len() as u64);
            self.buf.extend_from_slice(k.as_bytes());
        }

        fn str(&mut self, k: &str, v: &str) {
            self.key(k);
            self.buf.extend_from_slice(&8u32.to_le_bytes());
            self.raw(v.len() as u64);
            self.buf.extend_from_slice(v.as_bytes());
        }

        fn u32(&mut self, k: &str, v: u32) {
            self.key(k);
            self.buf.extend_from_slice(&4u32.to_le_bytes());
            self.buf.extend_from_slice(&v.to_le_bytes());
        }

        fn f32(&mut self, k: &str, bits: u32) {
            self.key(k);
            self.buf.extend_from_slice(&6u32.to_le_bytes());
            self.buf.extend_from_slice(&bits.to_le_bytes());
        }

        fn boolean(&mut self, k: &str, v: bool) {
            self.key(k);
            self.buf.extend_from_slice(&7u32.to_le_bytes());
            self.buf.push(v as u8);
        }

        fn str_array(&mut self, k: &str, values: &[&str]) {
            self.key(k);
            self.buf.extend_from_slice(&9u32.to_le_bytes());
            self.buf.extend_from_slice(&8u32.to_le_bytes()); // element type: string
            self.raw(values.len() as u64);
            for v in values {
                self.raw(v.len() as u64);
                self.buf.extend_from_slice(v.as_bytes());
            }
        }

        fn str_array_raw(&mut self, k: &str, values: &[Vec<u8>]) {
            self.key(k);
            self.buf.extend_from_slice(&9u32.to_le_bytes());
            self.buf.extend_from_slice(&8u32.to_le_bytes());
            self.buf
                .extend_from_slice(&(values.len() as u64).to_le_bytes());
            for v in values {
                self.buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
                self.buf.extend_from_slice(v);
            }
        }

        fn i32_array(&mut self, k: &str, values: &[i32]) {
            self.key(k);
            self.buf.extend_from_slice(&9u32.to_le_bytes());
            self.buf.extend_from_slice(&5u32.to_le_bytes()); // element type: i32
            self.raw(values.len() as u64);
            for v in values {
                self.buf.extend_from_slice(&v.to_le_bytes());
            }
        }

        fn finish(mut self, kv_count: u64) -> Vec<u8> {
            self.buf[16..24].copy_from_slice(&kv_count.to_le_bytes());
            self.buf
        }
    }

    fn synthetic_gguf() -> Vec<u8> {
        let mut w = GgufWriter::new();
        w.str("general.architecture", "qwen2");
        w.u32("qwen2.attention.head_count", 14);
        w.u32("qwen2.attention.head_count_kv", 2);
        w.f32("qwen2.attention.layer_norm_rms_epsilon", 897_988_541);
        w.u32("qwen2.block_count", 24);
        w.u32("qwen2.context_length", 32_768);
        w.u32("qwen2.embedding_length", 896);
        w.u32("qwen2.feed_forward_length", 4_864);
        w.u32("general.file_type", 15);
        w.f32("qwen2.rope.freq_base", 1_232_348_160);
        w.boolean("tokenizer.ggml.add_bos_token", false);
        w.u32("tokenizer.ggml.bos_token_id", 151_643);
        w.u32("tokenizer.ggml.eos_token_id", 151_645);
        w.str_array("tokenizer.ggml.merges", &["a b", "c d"]);
        w.str("tokenizer.ggml.model", "gpt2");
        w.u32("tokenizer.ggml.padding_token_id", 151_643);
        w.str("tokenizer.ggml.pre", "qwen2");
        w.i32_array("tokenizer.ggml.token_type", &[1, 2, 3]);
        w.str_array("tokenizer.ggml.tokens", &["<a>", "b", "<c>"]);
        w.str("tokenizer.chat_template", "{%- im_start %}");
        w.finish(20)
    }

    #[test]
    fn parses_and_hashes_synthetic_gguf() {
        let bytes = synthetic_gguf();
        let metadata = read_metadata_from(bytes.as_slice()).expect("parse");
        let hashes = identity_hashes(&metadata).expect("hashes");

        // Deterministic across runs and independent of key insertion order.
        let again = identity_hashes(&read_metadata_from(bytes.as_slice()).unwrap()).unwrap();
        assert_eq!(hashes, again);

        // chat_template_hash is sha256 of the raw template string.
        assert_eq!(
            hashes.chat_template_hash,
            hex::encode(Sha256::digest(b"{%- im_start %}".as_slice()))
        );

        // 64 lowercase hex each.
        for h in [&hashes.tokenizer_hash, &hashes.architecture_hash] {
            assert_eq!(h.len(), 64);
            assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn absent_tokenizer_keys_hash_as_null_amendment() {
        // ADR-022 amendment (2026-10-06): GGUFs may omit add_bos_token and
        // padding_token_id (Qwen3.5-family conversions do). Absence hashes
        // as null — never an error, never a guessed default. The pinned
        // digest is the node resolver's canonical-JSON sha256 of the same
        // object (cross-runtime parity lock).
        let bytes = {
            let mut w = GgufWriter::new();
            w.str("general.architecture", "qwen2");
            w.u32("qwen2.attention.head_count", 14);
            w.u32("qwen2.attention.head_count_kv", 2);
            w.f32("qwen2.attention.layer_norm_rms_epsilon", 897_988_541);
            w.u32("qwen2.block_count", 24);
            w.u32("qwen2.context_length", 32_768);
            w.u32("qwen2.embedding_length", 896);
            w.u32("qwen2.feed_forward_length", 4_864);
            w.u32("general.file_type", 15);
            w.f32("qwen2.rope.freq_base", 1_232_348_160);
            // NOTE: no tokenizer.ggml.add_bos_token, no padding_token_id.
            w.u32("tokenizer.ggml.bos_token_id", 0);
            w.u32("tokenizer.ggml.eos_token_id", 1);
            w.str_array("tokenizer.ggml.merges", &["a"]);
            w.str("tokenizer.ggml.model", "gpt2");
            w.str("tokenizer.ggml.pre", "qwen2");
            w.i32_array("tokenizer.ggml.token_type", &[0]);
            w.str_array("tokenizer.ggml.tokens", &["a"]);
            w.str("tokenizer.chat_template", "{%- im_start %}");
            w.finish(18)
        };
        let metadata = read_metadata_from(bytes.as_slice()).expect("parse");
        let hashes = identity_hashes(&metadata).expect("absent keys must hash as null");
        assert_eq!(
            hashes.tokenizer_hash,
            "02400c13858ae8f711fa52f3a7d1469018f303b910b61ea8b3b2a94694a86e20",
            "cross-runtime parity with the node resolver's canonical derivation"
        );
    }

    #[test]
    fn absent_bos_token_id_hashes_as_null_amendment_2() {
        // Second ADR-022 amendment (2026-10-06): unsloth's Qwen3.5-9B GGUF
        // also omits tokenizer.ggml.bos_token_id. Same rule — absence is
        // identity-relevant and hashes as null; eos_token_id stays REQUIRED
        // (decode termination depends on it). Digest = resolver parity lock.
        let bytes = {
            let mut w = GgufWriter::new();
            w.str("general.architecture", "qwen2");
            w.u32("qwen2.attention.head_count", 14);
            w.u32("qwen2.attention.head_count_kv", 2);
            w.f32("qwen2.attention.layer_norm_rms_epsilon", 897_988_541);
            w.u32("qwen2.block_count", 24);
            w.u32("qwen2.context_length", 32_768);
            w.u32("qwen2.embedding_length", 896);
            w.u32("qwen2.feed_forward_length", 4_864);
            w.u32("general.file_type", 15);
            w.f32("qwen2.rope.freq_base", 1_232_348_160);
            // NOTE: no add_bos_token, no padding_token_id, NO bos_token_id.
            w.u32("tokenizer.ggml.eos_token_id", 1);
            w.str_array("tokenizer.ggml.merges", &["a"]);
            w.str("tokenizer.ggml.model", "gpt2");
            w.str("tokenizer.ggml.pre", "qwen2");
            w.i32_array("tokenizer.ggml.token_type", &[0]);
            w.str_array("tokenizer.ggml.tokens", &["a"]);
            w.str("tokenizer.chat_template", "{%- im_start %}");
            w.finish(17)
        };
        let metadata = read_metadata_from(bytes.as_slice()).expect("parse");
        let hashes = identity_hashes(&metadata).expect("absent bos must hash as null");
        assert_eq!(
            hashes.tokenizer_hash,
            "d525b0cfd4a0590d0b91a2c6efa5c93649c3d26a2edf34d94138aaef6179e900",
            "cross-runtime parity with the node resolver's canonical derivation"
        );
    }

    #[test]
    fn token_vocab_raw_bytes_for_sentencepiece_and_gpt2_decoding() {
        // --- sentencepiece-style: tokens are raw bytes (no gpt2 model tag
        // here), so an invalid-UTF-8 token maps EXACTLY with no lossiness.
        let bytes = {
            let mut w = GgufWriter::new();
            write_all_identity_keys(&mut w);
            w.str_array_raw(
                "tokenizer.ggml.tokens",
                &[b"ok".to_vec(), vec![0xFF], b"a".to_vec()],
            );
            w.str("tokenizer.ggml.model", "llama");
            w.i32_array("tokenizer.ggml.token_type", &[1, 6, 1]);
            w.str_array("tokenizer.ggml.merges", &["a b"]);
            w.finish(21)
        };
        let metadata = read_metadata_bytes(&bytes).unwrap();
        let vocab = token_vocab(&metadata).expect("vocab");
        assert_eq!(vocab.bytes_to_id.get(b"ok".as_slice()), Some(&0));
        assert_eq!(vocab.bytes_to_id.get(&[0xFF][..]), Some(&1));
        assert_eq!(vocab.bytes_to_id.get(b"a".as_slice()), Some(&2));
        assert_eq!(vocab.eos_id, Some(7));

        // --- gpt2 byte-level BPE: GGUF stores the remapped alphabet, so
        // "ĠI" (U+0120 'I' = 0xC4 0xA0 0x49) must decode to real bytes " I"
        // [32, 73] — the form inference servers report.
        let bytes = {
            let mut w = GgufWriter::new();
            write_all_identity_keys(&mut w);
            w.str_array_raw(
                "tokenizer.ggml.tokens",
                &["ĠI".as_bytes().to_vec(), b"<|im_end|>".to_vec()],
            );
            w.str("tokenizer.ggml.model", "gpt2");
            w.i32_array("tokenizer.ggml.token_type", &[1, 3]);
            w.str_array("tokenizer.ggml.merges", &["a b"]);
            w.finish(21)
        };
        let metadata = read_metadata_bytes(&bytes).unwrap();
        let vocab = token_vocab(&metadata).expect("vocab");
        assert_eq!(vocab.bytes_to_id.get(b" I".as_slice()), Some(&0));
        assert_eq!(vocab.bytes_to_id.get(b"<|im_end|>".as_slice()), Some(&1));
    }

    /// Writes every ADR-022 identity key once (shared by vocab tests).
    fn write_all_identity_keys(w: &mut GgufWriter) {
        w.str("general.architecture", "qwen2");
        w.u32("qwen2.attention.head_count", 14);
        w.u32("qwen2.attention.head_count_kv", 2);
        w.f32("qwen2.attention.layer_norm_rms_epsilon", 1);
        w.u32("qwen2.block_count", 24);
        w.u32("qwen2.context_length", 32);
        w.u32("qwen2.embedding_length", 896);
        w.u32("qwen2.feed_forward_length", 4_864);
        w.u32("general.file_type", 15);
        w.f32("qwen2.rope.freq_base", 1);
        w.boolean("tokenizer.ggml.add_bos_token", false);
        w.u32("tokenizer.ggml.bos_token_id", 0);
        w.u32("tokenizer.ggml.eos_token_id", 7);
        w.str("tokenizer.ggml.model", "gpt2");
        w.u32("tokenizer.ggml.padding_token_id", 0);
        w.str("tokenizer.ggml.pre", "qwen2");
        w.str("tokenizer.chat_template", "tpl");
    }

    #[test]
    fn missing_required_key_fails_closed() {
        let bytes = synthetic_gguf();
        let metadata = read_metadata_from(bytes.as_slice()).unwrap();
        drop(bytes);
        let mut stripped = metadata.clone();
        stripped.remove("tokenizer.chat_template");
        match identity_hashes(&stripped) {
            Err(GgufError::MissingKey(k)) => assert_eq!(k, "tokenizer.chat_template"),
            other => panic!("expected MissingKey, got {other:?}"),
        }
    }

    #[test]
    fn bad_magic_and_version_rejected() {
        assert!(matches!(
            read_metadata_from(b"NOPE".as_slice()),
            Err(GgufError::NotGguf)
        ));
        let mut v2 = b"GGUF".to_vec();
        v2.extend_from_slice(&2u32.to_le_bytes());
        assert!(matches!(
            read_metadata_from(v2.as_slice()),
            Err(GgufError::UnsupportedVersion(2))
        ));
    }

    /// Cross-language parity against the Node resolver on the REAL artifact:
    /// set MSP_REAL_GGUF=<path to qwen2.5-0.5b-instruct-q4_k_m.gguf>.
    /// Values are the live manifest's hashes (catalogVersion 3).
    #[test]
    #[ignore = "set MSP_REAL_GGUF to the real Qwen2.5-0.5B Q4_K_M GGUF path"]
    fn real_artifact_hashes_match_manifest() {
        let path = std::env::var("MSP_REAL_GGUF").expect("MSP_REAL_GGUF not set");
        let metadata = read_metadata(&path).expect("read real gguf");
        let hashes = identity_hashes(&metadata).expect("hash real gguf");
        assert_eq!(
            hashes.tokenizer_hash,
            "a5adafe8431c310a24bb7c8dc69867c8ba9dad33be7cf057800aef827daf6f71"
        );
        assert_eq!(
            hashes.chat_template_hash,
            "d5495a1e5db0611132a97e46a65dbb64a642a499421228b9c8b93229097fa9a4"
        );
        assert_eq!(
            hashes.architecture_hash,
            "de0876a123e974f4761efae28354c0fe5d267d71a5d8ed8ef8741054aa769d08"
        );
    }
}
