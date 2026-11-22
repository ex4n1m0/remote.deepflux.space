//! Model-artifact download and possession verification (Phase H2, ADR-011
//! §possession / ADR-022).
//!
//! `ensure_artifact` is the one call the desktop setup flow needs: given a
//! verified-catalog manifest it guarantees that, on success, the exact
//! artifact bytes sit at `<data_dir>/models/<profile>/<file>` with
//!
//! 1. the full-artifact SHA-256 matching `artifact_hashes` (streamed while
//!    downloading, re-verified on every subsequent call),
//! 2. the ADR-022 identity hashes (tokenizer / chat template / architecture)
//!    re-derived from the GGUF bytes and equal to the manifest values, and
//! 3. a `verified` row in the node store.
//!
//! Downloads stream to a `.part` sibling and finalize with an atomic rename;
//! a failed verification never leaves a partial file behind. No resume in
//! v1 — a dropped connection restarts the transfer (beta-internal scope,
//! recorded in the phase-h notes). Tests inject a canned host via
//! [`ArtifactManager::with_hf_base`].

use std::path::PathBuf;
use std::time::Duration;

use futures_util::StreamExt;
use modelswarm_store::Store;
use modelswarm_types::{identity_hashes, read_metadata, ModelProfileManifest};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("network: {0}")]
    Network(String),
    #[error("http {status}: {body}")]
    Http { status: u16, body: String },
    #[error("artifact sha256 mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("gguf identity verification failed: {0}")]
    Identity(String),
    #[error("io: {0}")]
    Io(String),
    #[error("unsupported manifest: {0}")]
    Unsupported(String),
}

/// Where an artifact lives plus its verified size.
#[derive(Debug, Clone)]
pub struct EnsuredArtifact {
    pub path: PathBuf,
    pub bytes: u64,
}

/// Downloads and re-verifies model artifacts under a data directory.
pub struct ArtifactManager {
    data_dir: PathBuf,
    http: reqwest::Client,
    /// Overrides the download host for tests (serves `<base>/<file>`).
    hf_base_override: Option<String>,
}

impl ArtifactManager {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            http: modelswarm_dns::apply(reqwest::Client::builder())
                .timeout(Duration::from_secs(600))
                .build()
                .expect("reqwest client"),
            hf_base_override: None,
        }
    }

    /// Points downloads at a canned HTTP host (tests only).
    pub fn with_hf_base(mut self, base: impl Into<String>) -> Self {
        self.hf_base_override = Some(base.into());
        self
    }

    /// Final on-disk location for a profile's single artifact.
    pub fn artifact_path(&self, manifest: &ModelProfileManifest) -> Result<PathBuf, ArtifactError> {
        let file = artifact_file_name(manifest)?;
        let safe_profile = manifest.derive_profile_id().replace(':', "_");
        Ok(self
            .data_dir
            .join("models")
            .join(safe_profile)
            .join(sanitize_file_name(&file)))
    }

    /// Guarantees the artifact is present and fully verified (download +
    /// sha256 + ADR-022 identity hashes + store row). `progress` receives
    /// `(bytes_so_far, total_bytes_if_known)` during any transfer.
    pub async fn ensure_artifact(
        &self,
        manifest: &ModelProfileManifest,
        store: &std::sync::Mutex<Store>,
        mut progress: impl FnMut(u64, Option<u64>),
    ) -> Result<EnsuredArtifact, ArtifactError> {
        let dest = self.artifact_path(manifest)?;
        let expected_sha = manifest
            .artifact_hashes()
            .first()
            .expect("artifact_path validated the entry")
            .sha256()
            .to_string();

        // Already present and intact? Re-verify possession from disk.
        if dest.exists() {
            let existing = tokio::task::spawn_blocking({
                let dest = dest.clone();
                move || file_sha256(&dest)
            })
            .await
            .map_err(|e| ArtifactError::Io(e.to_string()))?;
            match existing {
                Ok(actual) if actual == expected_sha => {
                    let bytes = self.finish_verification(manifest, &dest, store).await?;
                    return Ok(EnsuredArtifact { path: dest, bytes });
                }
                Ok(_) => {
                    // Corrupt or stale: drop it and re-download.
                    std::fs::remove_file(&dest).map_err(|e| ArtifactError::Io(e.to_string()))?;
                }
                Err(e) => return Err(ArtifactError::Io(e.to_string())),
            }
        }

        // Download to a .part sibling, hashing while streaming.
        std::fs::create_dir_all(dest.parent().expect("artifact dir parent"))
            .map_err(|e| ArtifactError::Io(e.to_string()))?;
        let tmp = dest.with_extension("part");
        let url = artifact_url(&self.hf_base_override, manifest)?;
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| ArtifactError::Network(e.to_string()))?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(ArtifactError::Http {
                status,
                body: response
                    .text()
                    .await
                    .unwrap_or_default()
                    .chars()
                    .take(200)
                    .collect(),
            });
        }
        let total = response.content_length();
        let mut file = tokio::io::BufWriter::new(
            tokio::fs::File::create(&tmp)
                .await
                .map_err(|e| ArtifactError::Io(e.to_string()))?,
        );
        let mut hasher = Sha256::new();
        let mut written: u64 = 0;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                ArtifactError::Network(e.to_string())
            })?;
            hasher.update(&chunk);
            file.write_all(&chunk).await.map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                ArtifactError::Io(e.to_string())
            })?;
            written += chunk.len() as u64;
            progress(written, total);
        }
        file.flush().await.map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            ArtifactError::Io(e.to_string())
        })?;
        drop(file);

        let actual = hex::encode(hasher.finalize());
        if actual != expected_sha {
            let _ = std::fs::remove_file(&tmp);
            return Err(ArtifactError::HashMismatch {
                expected: expected_sha,
                actual,
            });
        }
        std::fs::rename(&tmp, &dest).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            ArtifactError::Io(e.to_string())
        })?;

        let bytes = self.finish_verification(manifest, &dest, store).await?;
        Ok(EnsuredArtifact { path: dest, bytes })
    }

    /// ADR-022 identity hashes from the GGUF bytes + store row.
    async fn finish_verification(
        &self,
        manifest: &ModelProfileManifest,
        dest: &std::path::Path,
        store: &std::sync::Mutex<Store>,
    ) -> Result<u64, ArtifactError> {
        let hashes = {
            let dest = dest.to_path_buf();
            let result = tokio::task::spawn_blocking(move || {
                let metadata =
                    read_metadata(&dest).map_err(|e| ArtifactError::Identity(e.to_string()))?;
                identity_hashes(&metadata).map_err(|e| ArtifactError::Identity(e.to_string()))
            })
            .await
            .map_err(|e| ArtifactError::Io(e.to_string()))?;
            result?
        };
        let expected = (
            manifest.tokenizer_hash().to_string(),
            manifest.chat_template_hash().to_string(),
            manifest.architecture_hash().to_string(),
        );
        let actual = (
            hashes.tokenizer_hash,
            hashes.chat_template_hash,
            hashes.architecture_hash,
        );
        if actual != expected {
            return Err(ArtifactError::Identity(format!(
                "re-derived {actual:?} != manifest {expected:?}"
            )));
        }
        let bytes = std::fs::metadata(dest)
            .map_err(|e| ArtifactError::Io(e.to_string()))?
            .len();
        // Short lock scope; no await while held (rusqlite Connection is
        // Send but not Sync).
        store
            .lock()
            .map_err(|_| ArtifactError::Io("store lock poisoned".into()))?
            .record_artifact(
                &manifest.derive_profile_id(),
                &dest.display().to_string(),
                &expected.0,
                bytes as i64,
                "verified",
            )
            .map_err(|e| ArtifactError::Io(e.to_string()))?;
        Ok(bytes)
    }
}

/// The single artifact a Phase H manifest pins (multi-artifact profiles are
/// rejected until a profile needs one).
fn artifact_file_name(manifest: &ModelProfileManifest) -> Result<String, ArtifactError> {
    let entries = manifest.artifact_hashes();
    if entries.len() != 1 {
        return Err(ArtifactError::Unsupported(
            "exactly one artifact hash is required (multi-artifact profiles not supported yet)"
                .into(),
        ));
    }
    let path = entries[0].path();
    let file = path
        .rsplit('/')
        .next()
        .filter(|f| !f.is_empty())
        .ok_or_else(|| ArtifactError::Unsupported("artifact path has no file name".into()))?;
    Ok(file.to_string())
}

/// HF resolve URL per ADR-022 §7 (or the injected canned host).
fn artifact_url(
    base_override: &Option<String>,
    manifest: &ModelProfileManifest,
) -> Result<String, ArtifactError> {
    let path = manifest.artifact_hashes()[0].path();
    if let Some(base) = base_override {
        return Ok(format!(
            "{}/{}",
            base.trim_end_matches('/'),
            sanitize_file_name(&artifact_file_name(manifest)?)
        ));
    }
    Ok(format!(
        "https://huggingface.co/{}/resolve/{}/{}",
        manifest.hf_repo(),
        manifest.hf_revision(),
        path
    ))
}

fn sanitize_file_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Streaming SHA-256 of a file (blocking; run via `spawn_blocking`).
fn file_sha256(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Canned HTTP server: serves `payload` for every request, counts hits.
    fn canned_server(payload: Vec<u8>) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                hits_clone.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf); // consume request head
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(&payload).unwrap();
            }
        });
        (format!("http://{addr}"), hits)
    }

    // ---- minimal GGUF writer (mirrors the ADR-022 key set) ----------------

    struct GgufBuilder {
        buf: Vec<u8>,
        kv_count: u64,
    }

    impl GgufBuilder {
        fn new() -> Self {
            let mut buf = b"GGUF".to_vec();
            buf.extend_from_slice(&3u32.to_le_bytes());
            buf.extend_from_slice(&0u64.to_le_bytes());
            buf.extend_from_slice(&0u64.to_le_bytes());
            Self { buf, kv_count: 0 }
        }

        fn key(&mut self, k: &str) {
            self.buf.extend_from_slice(&(k.len() as u64).to_le_bytes());
            self.buf.extend_from_slice(k.as_bytes());
        }

        fn put_str(&mut self, k: &str, v: &str) {
            self.key(k);
            self.buf.extend_from_slice(&8u32.to_le_bytes());
            self.buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
            self.buf.extend_from_slice(v.as_bytes());
            self.kv_count += 1;
        }

        fn put_u32(&mut self, k: &str, v: u32) {
            self.key(k);
            self.buf.extend_from_slice(&4u32.to_le_bytes());
            self.buf.extend_from_slice(&v.to_le_bytes());
            self.kv_count += 1;
        }

        fn put_bits(&mut self, k: &str, v: u32) {
            self.key(k);
            self.buf.extend_from_slice(&6u32.to_le_bytes());
            self.buf.extend_from_slice(&v.to_le_bytes());
            self.kv_count += 1;
        }

        fn put_bool(&mut self, k: &str, v: bool) {
            self.key(k);
            self.buf.extend_from_slice(&7u32.to_le_bytes());
            self.buf.push(v as u8);
            self.kv_count += 1;
        }

        fn put_arr_str(&mut self, k: &str, v: &[&str]) {
            self.key(k);
            self.buf.extend_from_slice(&9u32.to_le_bytes());
            self.buf.extend_from_slice(&8u32.to_le_bytes());
            self.buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
            for s in v {
                self.buf.extend_from_slice(&(s.len() as u64).to_le_bytes());
                self.buf.extend_from_slice(s.as_bytes());
            }
            self.kv_count += 1;
        }

        fn put_arr_i32(&mut self, k: &str, v: &[i32]) {
            self.key(k);
            self.buf.extend_from_slice(&9u32.to_le_bytes());
            self.buf.extend_from_slice(&5u32.to_le_bytes());
            self.buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
            for i in v {
                self.buf.extend_from_slice(&i.to_le_bytes());
            }
            self.kv_count += 1;
        }

        fn finish(mut self) -> Vec<u8> {
            self.buf[16..24].copy_from_slice(&self.kv_count.to_le_bytes());
            self.buf
        }
    }

    fn synthetic_gguf() -> Vec<u8> {
        let mut w = GgufBuilder::new();
        w.put_str("general.architecture", "qwen2");
        w.put_u32("qwen2.attention.head_count", 14);
        w.put_u32("qwen2.attention.head_count_kv", 2);
        w.put_bits("qwen2.attention.layer_norm_rms_epsilon", 897_988_541);
        w.put_u32("qwen2.block_count", 24);
        w.put_u32("qwen2.context_length", 32_768);
        w.put_u32("qwen2.embedding_length", 896);
        w.put_u32("qwen2.feed_forward_length", 4_864);
        w.put_u32("general.file_type", 15);
        w.put_bits("qwen2.rope.freq_base", 1_232_348_160);
        w.put_bool("tokenizer.ggml.add_bos_token", false);
        w.put_u32("tokenizer.ggml.bos_token_id", 151_643);
        w.put_u32("tokenizer.ggml.eos_token_id", 151_645);
        w.put_arr_str("tokenizer.ggml.merges", &["a b"]);
        w.put_str("tokenizer.ggml.model", "gpt2");
        w.put_u32("tokenizer.ggml.padding_token_id", 151_643);
        w.put_str("tokenizer.ggml.pre", "qwen2");
        w.put_arr_i32("tokenizer.ggml.token_type", &[1, 2]);
        w.put_arr_str("tokenizer.ggml.tokens", &["<a>", "b"]);
        w.put_str("tokenizer.chat_template", "tpl");
        w.finish()
    }

    fn test_manifest(gguf: &[u8]) -> ModelProfileManifest {
        let metadata = modelswarm_types::read_metadata_bytes(gguf).unwrap();
        let hashes = identity_hashes(&metadata).unwrap();
        let artifact_sha = hex::encode(Sha256::digest(gguf));
        serde_json::from_value(json!({
            "schema_version": 2,
            "hf_repo": "test/repo",
            "hf_revision": "0123456789abcdef0123456789abcdef01234567",
            "artifact_hashes": [{ "path": "model.gguf", "sha256": artifact_sha }],
            "tokenizer_hash": hashes.tokenizer_hash,
            "chat_template_hash": hashes.chat_template_hash,
            "architecture_hash": hashes.architecture_hash,
            "quantization": { "method": "q4_k_m", "bits": 4 },
            "runtime": { "name": "llama.cpp", "version": "b11407",
                         "build_hash": "353c4aab423bff5cb6dc0e1d32e41a447990ab3d69a411b7f58ff48187c91a03" },
            "decoding_abi_version": 1,
            "speculative_capabilities": ["proposal_tokens"]
        }))
        .unwrap()
    }

    fn temp_store(dir: &std::path::Path) -> std::sync::Mutex<Store> {
        std::sync::Mutex::new(Store::open(dir.join("state.sqlite")).unwrap())
    }

    #[tokio::test]
    async fn downloads_verifies_and_reuses() {
        let tmp = tempfile::tempdir().unwrap();
        let gguf = synthetic_gguf();
        let manifest = test_manifest(&gguf);
        let (base, hits) = canned_server(gguf.clone());

        let manager = ArtifactManager::new(tmp.path()).with_hf_base(&base);
        let store = temp_store(tmp.path());

        let mut events = 0u32;
        let ensured = manager
            .ensure_artifact(&manifest, &store, |done, total| {
                assert_eq!(total, Some(gguf.len() as u64));
                assert!(done > 0);
                events += 1;
            })
            .await
            .expect("first ensure");
        assert!(events > 0);
        assert!(ensured.path.exists());
        assert_eq!(ensured.bytes, gguf.len() as u64);
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

        let row = store
            .lock()
            .unwrap()
            .get_artifact(&manifest.derive_profile_id())
            .unwrap();
        assert!(row.is_some());

        // Second call re-verifies from disk without another download.
        manager
            .ensure_artifact(&manifest, &store, |_, _| panic!("no transfer expected"))
            .await
            .expect("second ensure");
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn hash_mismatch_fails_closed_and_cleans_up() {
        let tmp = tempfile::tempdir().unwrap();
        let gguf = synthetic_gguf();
        let mut manifest_value = serde_json::to_value(test_manifest(&gguf)).unwrap();
        // Point the artifact hash somewhere else: bytes won't match.
        manifest_value["artifact_hashes"][0]["sha256"] =
            json!("1111111111111111111111111111111111111111111111111111111111111111");
        let manifest: ModelProfileManifest = serde_json::from_value(manifest_value).unwrap();

        let (base, _hits) = canned_server(gguf);
        let manager = ArtifactManager::new(tmp.path()).with_hf_base(&base);
        let store = temp_store(tmp.path());

        let err = manager
            .ensure_artifact(&manifest, &store, |_, _| {})
            .await
            .expect_err("must fail");
        assert!(matches!(err, ArtifactError::HashMismatch { .. }), "{err}");
        // No finalized artifact, no .part left behind.
        assert!(!manager.artifact_path(&manifest).unwrap().exists());
        assert!(store
            .lock()
            .unwrap()
            .get_artifact(&manifest.derive_profile_id())
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn corrupt_existing_file_triggers_redownload() {
        let tmp = tempfile::tempdir().unwrap();
        let gguf = synthetic_gguf();
        let manifest = test_manifest(&gguf);
        let (base, hits) = canned_server(gguf.clone());

        let manager = ArtifactManager::new(tmp.path()).with_hf_base(&base);
        let store = temp_store(tmp.path());

        // Pre-place a corrupt file where the artifact should live.
        let dest = manager.artifact_path(&manifest).unwrap();
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&dest, b"corrupt bytes").unwrap();

        let ensured = manager
            .ensure_artifact(&manifest, &store, |_, _| {})
            .await
            .expect("recovered by redownload");
        assert_eq!(ensured.bytes, gguf.len() as u64);
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
