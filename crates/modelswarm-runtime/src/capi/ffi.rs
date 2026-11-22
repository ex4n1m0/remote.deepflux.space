//! Raw C-API bindings for the PINNED llama.cpp shared library (P16 spike).
//!
//! This is the only file in the workspace where `unsafe` is allowed: the
//! crate opts out of the workspace `unsafe_code = "forbid"` lint to `deny`
//! (see `Cargo.toml`) and this module carries the single `allow`. The safe
//! wrapper API below is what [`super`] consumes — the adapter itself stays
//! unsafe-free.
//!
//! Identity/build story (ADR-022/ADR-024 lineage): we do NOT compile or
//! vendor any engine code. We `LoadLibrary` the exact `llama.dll`
//! (`libllama.so`/`libllama.dylib` on other OSes) that already ships in the
//! pinned, per-OS, sha256-verified engine bundle of `runtime-pins.json` —
//! the same binary `llama-server` links. The struct mirrors below are
//! derived mechanically from the pinned release's public `include/llama.h`
//! (tag `b11407`); every function pointer is resolved by name at load time
//! and a missing/renamed symbol fails closed at construction instead of
//! silently misbehaving. When the engine pin moves, the required-symbol
//! manifest here is the ABI contract that must be re-checked.

#![allow(unsafe_code)]
// Raw-pointer arguments on the wrapper methods are OPAQUE ENGINE HANDLES
// produced only by this module (model → vocab) and consumed only under the
// adapter's per-handle mutex; callers cannot form them.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::c_void;
use std::path::Path;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

/// `llama_token` / `llama_pos` / `llama_seq_id` (include/llama.h b11407).
pub type LlamaToken = i32;
pub type LlamaPos = i32;
pub type LlamaSeqId = i32;

/// Opaque engine types (only ever handled by pointer).
#[repr(C)]
pub struct LlamaModel {
    _private: [u8; 0],
}
#[repr(C)]
pub struct LlamaContext {
    _private: [u8; 0],
}
#[repr(C)]
pub struct LlamaVocab {
    _private: [u8; 0],
}
#[repr(C)]
pub struct LlamaMemory {
    _private: [u8; 0],
}
#[repr(C)]
pub struct LlamaSampler {
    _private: [u8; 0],
}

/// `struct llama_model_params` (b11407, 80 bytes, alignment 8). Field order
/// and sizes are mechanical mirrors of the pinned header; we only ever
/// round-trip the value of `llama_model_default_params()` (GPU layer
/// auto-fit is engine-side per ADR-024 — nothing is pinned here).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LlamaModelParams {
    pub devices: *mut c_void,
    pub tensor_buft_overrides: *const c_void,
    pub n_gpu_layers: i32,
    pub split_mode: i32,
    pub load_mode: i32,
    pub lazy_mode: i32,
    pub main_gpu: i32,
    pub tensor_split: *const f32,
    pub progress_callback: Option<unsafe extern "C" fn(f32, *mut c_void) -> bool>,
    pub progress_callback_user_data: *mut c_void,
    pub kv_overrides: *const c_void,
    pub vocab_only: bool,
    pub check_tensors: bool,
    pub use_extra_bufts: bool,
    pub no_host: bool,
    pub no_alloc: bool,
    pub load_mtp: bool,
}

/// `struct llama_context_params` (b11407, 160 bytes, alignment 8). We write
/// only the leading scalar block (`n_ctx`, `n_batch`, `n_threads`,
/// `n_threads_batch` — offsets 0/4/28/32, pinned by the layout tests below)
/// and round-trip the remainder of `llama_context_default_params()` verbatim.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LlamaContextParams {
    pub n_ctx: u32,
    pub n_batch: u32,
    pub n_ubatch: u32,
    pub n_seq_max: u32,
    pub n_rs_seq: u32,
    pub n_outputs_max: u32,
    pub n_outputs_max_per_seq: u32,
    pub n_threads: i32,
    pub n_threads_batch: i32,
    pub ctx_type: i32,
    pub rope_scaling_type: i32,
    pub pooling_type: i32,
    pub attention_type: i32,
    pub flash_attn_type: i32,
    pub rope_freq_base: f32,
    pub rope_freq_scale: f32,
    pub yarn_ext_factor: f32,
    pub yarn_attn_factor: f32,
    pub yarn_beta_fast: f32,
    pub yarn_beta_slow: f32,
    pub yarn_orig_ctx: u32,
    pub defrag_thold: f32,
    pub cb_eval: Option<unsafe extern "C" fn()>,
    pub cb_eval_user_data: *mut c_void,
    pub type_k: i32,
    pub type_v: i32,
    pub abort_callback: Option<unsafe extern "C" fn(*mut c_void) -> bool>,
    pub abort_callback_data: *mut c_void,
    pub embeddings: bool,
    pub offload_kqv: bool,
    pub no_perf: bool,
    pub op_offload: bool,
    pub swa_full: bool,
    pub kv_unified: bool,
    pub samplers: *mut c_void,
    pub n_samplers: usize,
    pub ctx_other: *mut c_void,
}

/// `struct llama_batch` (b11407, 56 bytes, alignment 8). Built by the engine
/// via `llama_batch_init`; we fill `token[]` and `logits[]` and leave
/// `pos`/`seq_id` null so the engine auto-tracks positions for sequence 0
/// (documented b11407 batch semantics).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LlamaBatch {
    pub n_tokens: i32,
    pub token: *mut LlamaToken,
    pub embd: *mut f32,
    pub pos: *mut LlamaPos,
    pub n_seq_id: *mut i32,
    pub seq_id: *mut *mut LlamaSeqId,
    pub logits: *mut i8,
}

/// `struct llama_sampler_chain_params` (1 byte).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LlamaSamplerChainParams {
    pub no_perf: bool,
}

// Raw C function-pointer types (signatures transcribed from the pinned
// include/llama.h of b11407).
type FnBackendInit = unsafe extern "C" fn();
type FnBackendLoadAllFromPath = unsafe extern "C" fn(*const i8);
type FnModelDefaultParams = unsafe extern "C" fn() -> LlamaModelParams;
type FnModelLoadFromFile = unsafe extern "C" fn(*const i8, LlamaModelParams) -> *mut LlamaModel;
type FnModelFree = unsafe extern "C" fn(*mut LlamaModel);
type FnModelGetVocab = unsafe extern "C" fn(*const LlamaModel) -> *const LlamaVocab;
type FnContextDefaultParams = unsafe extern "C" fn() -> LlamaContextParams;
type FnInitFromModel =
    unsafe extern "C" fn(*mut LlamaModel, LlamaContextParams) -> *mut LlamaContext;
type FnFree = unsafe extern "C" fn(*mut LlamaContext);
type FnNCtx = unsafe extern "C" fn(*const LlamaContext) -> u32;
type FnNBatch = unsafe extern "C" fn(*const LlamaContext) -> u32;
type FnGetMemory = unsafe extern "C" fn(*const LlamaContext) -> *mut LlamaMemory;
type FnMemorySeqRm = unsafe extern "C" fn(*mut LlamaMemory, LlamaSeqId, LlamaPos, LlamaPos) -> bool;
type FnMemorySeqPosMax = unsafe extern "C" fn(*mut LlamaMemory, LlamaSeqId) -> LlamaPos;
type FnBatchInit = unsafe extern "C" fn(i32, i32, i32) -> LlamaBatch;
type FnBatchFree = unsafe extern "C" fn(LlamaBatch);
type FnDecode = unsafe extern "C" fn(*mut LlamaContext, LlamaBatch) -> i32;
type FnGetLogitsIth = unsafe extern "C" fn(*mut LlamaContext, i32) -> *mut f32;
type FnVocabNTokens = unsafe extern "C" fn(*const LlamaVocab) -> i32;
type FnTokenize = unsafe extern "C" fn(
    *const LlamaVocab,
    *const u8,
    i32,
    *mut LlamaToken,
    i32,
    bool,
    bool,
) -> i32;
type FnTokenToPiece =
    unsafe extern "C" fn(*const LlamaVocab, LlamaToken, *mut u8, i32, i32, bool) -> i32;
type FnVocabEos = unsafe extern "C" fn(*const LlamaVocab) -> LlamaToken;
type FnVocabIsEog = unsafe extern "C" fn(*const LlamaVocab, LlamaToken) -> bool;
type FnSamplerChainDefaultParams = unsafe extern "C" fn() -> LlamaSamplerChainParams;
type FnSamplerChainInit = unsafe extern "C" fn(LlamaSamplerChainParams) -> *mut LlamaSampler;
type FnSamplerChainAdd = unsafe extern "C" fn(*mut LlamaSampler, *mut LlamaSampler);
type FnSamplerFree = unsafe extern "C" fn(*mut LlamaSampler);
type FnSamplerInitGreedy = unsafe extern "C" fn() -> *mut LlamaSampler;
type FnSamplerInitTemp = unsafe extern "C" fn(f32) -> *mut LlamaSampler;
type FnSamplerInitTopK = unsafe extern "C" fn(i32) -> *mut LlamaSampler;
type FnSamplerInitTopP = unsafe extern "C" fn(f32, usize) -> *mut LlamaSampler;
type FnSamplerInitDist = unsafe extern "C" fn(u32) -> *mut LlamaSampler;
type FnSamplerSample =
    unsafe extern "C" fn(*mut LlamaSampler, *mut LlamaContext, i32) -> LlamaToken;
type FnStateGetSize = unsafe extern "C" fn(*mut LlamaContext) -> usize;
type FnModelNLayer = unsafe extern "C" fn(*const LlamaModel) -> i32;
type FnModelNEmbd = unsafe extern "C" fn(*const LlamaModel) -> i32;
type FnModelNHead = unsafe extern "C" fn(*const LlamaModel) -> i32;
type FnModelNHeadKv = unsafe extern "C" fn(*const LlamaModel) -> i32;

/// Which batch rows request logits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Logits {
    /// No rows (pure prefill — skips the lm_head work entirely).
    None,
    /// Only the final token of the batch (streaming decode step).
    Last,
    /// Every token of the batch (draft verification needs each position).
    All,
}

impl Logits {
    /// ADR-031 §5.1 uniform-output promotion: `None` becomes `Last` so the
    /// engine never switches away from its ≥1-output graph slot (b11407
    /// caches two graph results, `gf_res_prev[n_outputs > 0]`, and only
    /// reuses the slot the PREVIOUS decode used — switching pays a
    /// scheduler reset + re-allocation). `Last`/`All` are unchanged.
    #[must_use]
    pub fn promote(self) -> Self {
        match self {
            Logits::None => Logits::Last,
            other => other,
        }
    }
}

// ---- owned pointer wrappers ------------------------------------------------
//
// Safety (Send/Sync): these wrap raw engine pointers, but every dereference
// happens inside `LlamaLib` methods invoked by the adapter while holding the
// owning context's mutex; serialization is external and documented in
// `super`. The engine is a single-threaded C API from our point of view.

/// Owned `llama_model*` (freed by `llama_model_free` on drop). Shared by all
/// contexts of one adapter.
pub struct ModelPtr {
    lib: Arc<LlamaLib>,
    ptr: *mut LlamaModel,
}

// Safety: see module note — all engine calls are serialized by the adapter.
unsafe impl Send for ModelPtr {}
// Safety: see module note.
unsafe impl Sync for ModelPtr {}

impl Drop for ModelPtr {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { (self.lib.model_free)(self.ptr) };
        }
    }
}

/// Owned `llama_context*` (freed by `llama_free` on drop). One per handle.
pub struct ContextPtr {
    lib: Arc<LlamaLib>,
    ptr: *mut LlamaContext,
    mem: *mut LlamaMemory,
}

// Safety: see module note.
unsafe impl Send for ContextPtr {}
// Safety: see module note.
unsafe impl Sync for ContextPtr {}

impl Drop for ContextPtr {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { (self.lib.free)(self.ptr) };
        }
    }
}

/// Owned per-handle pooled batch (freed by `llama_batch_free` on drop).
/// ADR-031 §5.1 shape-stable batching: allocated ONCE per handle at the
/// adapter's full batch capacity and reused for every decode, so
/// steady-state decodes perform no per-call `llama_batch_init`/`free`.
pub struct PooledBatch {
    lib: Arc<LlamaLib>,
    raw: LlamaBatch,
    capacity: i32,
}

// Safety: raw engine pointers, but every dereference happens inside
// `LlamaLib::decode_pooled` while the adapter holds the owning handle's
// mutex (same serialization discipline as the context wrappers).
unsafe impl Send for PooledBatch {}
// Safety: see module note.
unsafe impl Sync for PooledBatch {}

impl Drop for PooledBatch {
    fn drop(&mut self) {
        unsafe { (self.lib.batch_free)(self.raw) };
    }
}

/// Owned sampler chain (freed by `llama_sampler_free` on drop).
pub struct SamplerChain {
    lib: Arc<LlamaLib>,
    ptr: *mut LlamaSampler,
}

// Safety: chains are created and consumed under the same context mutex.
unsafe impl Send for SamplerChain {}
// Safety: see module note.
unsafe impl Sync for SamplerChain {}

impl Drop for SamplerChain {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { (self.lib.sampler_free)(self.ptr) };
        }
    }
}

/// The loaded pinned `llama` shared library with every required symbol
/// resolved. Construction fails closed, so an engine-pin bump that renames
/// anything surfaces as a construction error, never silent UB.
pub struct LlamaLib {
    #[allow(dead_code)]
    lib: libloading::Library,
    /// Second handle for the ggml library in the same bundle (backend
    /// registry lives there, not in llama).
    #[allow(dead_code)]
    ggml_lib: Option<libloading::Library>,
    bundle_dir: std::path::PathBuf,
    backend_init: FnBackendInit,
    backend_load_all_from_path: Option<FnBackendLoadAllFromPath>,
    model_default_params: FnModelDefaultParams,
    model_load_from_file: FnModelLoadFromFile,
    model_free: FnModelFree,
    model_get_vocab: FnModelGetVocab,
    context_default_params: FnContextDefaultParams,
    init_from_model: FnInitFromModel,
    free: FnFree,
    n_ctx: FnNCtx,
    n_batch: FnNBatch,
    get_memory: FnGetMemory,
    memory_seq_rm: FnMemorySeqRm,
    memory_seq_pos_max: FnMemorySeqPosMax,
    batch_init: FnBatchInit,
    batch_free: FnBatchFree,
    decode: FnDecode,
    get_logits_ith: FnGetLogitsIth,
    vocab_n_tokens: FnVocabNTokens,
    tokenize: FnTokenize,
    token_to_piece: FnTokenToPiece,
    vocab_eos: FnVocabEos,
    vocab_is_eog: FnVocabIsEog,
    sampler_chain_default_params: FnSamplerChainDefaultParams,
    sampler_chain_init: FnSamplerChainInit,
    sampler_chain_add: FnSamplerChainAdd,
    sampler_free: FnSamplerFree,
    sampler_init_greedy: FnSamplerInitGreedy,
    sampler_init_temp: FnSamplerInitTemp,
    sampler_init_top_k: FnSamplerInitTopK,
    sampler_init_top_p: FnSamplerInitTopP,
    sampler_init_dist: FnSamplerInitDist,
    sampler_sample: FnSamplerSample,
    state_get_size: FnStateGetSize,
    model_n_layer: FnModelNLayer,
    model_n_embd: FnModelNEmbd,
    model_n_head: FnModelNHead,
    model_n_head_kv: FnModelNHeadKv,
    /// Vocabulary size cached at adapter construction (logits rows).
    vocab_size: AtomicU32,
}

impl LlamaLib {
    /// File name of the C-API library inside the pinned bundle, per OS.
    pub fn library_file_name() -> &'static str {
        if cfg!(windows) {
            "llama.dll"
        } else if cfg!(target_os = "macos") {
            "libllama.dylib"
        } else {
            "libllama.so"
        }
    }

    /// Loads the pinned C-API library from `dir` and resolves all required
    /// symbols. `dir` is the hash-verified engine bundle directory.
    pub fn load(dir: &Path) -> Result<Self, String> {
        let dll = dir.join(Self::library_file_name());
        if !dll.is_file() {
            return Err(format!("pinned C-API library not found: {}", dll.display()));
        }
        // Canonicalized absolute path so the engine bundle directory also
        // resolves the ggml*.dll/.so dependencies next to it.
        let dll = std::fs::canonicalize(&dll).map_err(|e| format!("canonicalize: {e}"))?;
        let lib = load_library(&dll).map_err(|e| {
            format!(
                "failed to load pinned {}: {e} (dependencies must sit in the same bundle directory)",
                Self::library_file_name()
            )
        })?;

        macro_rules! require {
            ($name:literal, $ty:ty) => {{
                match unsafe { lib.get::<$ty>(concat!($name, "\0").as_bytes()) } {
                    Ok(symbol) => *symbol,
                    Err(e) => return Err(format!("pinned b11407 C-API export {}: {e}", $name)),
                }
            }};
        }

        let mut result = Self {
            backend_init: require!("llama_backend_init", FnBackendInit),
            model_default_params: require!("llama_model_default_params", FnModelDefaultParams),
            model_load_from_file: require!("llama_model_load_from_file", FnModelLoadFromFile),
            model_free: require!("llama_model_free", FnModelFree),
            model_get_vocab: require!("llama_model_get_vocab", FnModelGetVocab),
            context_default_params: require!(
                "llama_context_default_params",
                FnContextDefaultParams
            ),
            init_from_model: require!("llama_init_from_model", FnInitFromModel),
            free: require!("llama_free", FnFree),
            n_ctx: require!("llama_n_ctx", FnNCtx),
            n_batch: require!("llama_n_batch", FnNBatch),
            get_memory: require!("llama_get_memory", FnGetMemory),
            memory_seq_rm: require!("llama_memory_seq_rm", FnMemorySeqRm),
            memory_seq_pos_max: require!("llama_memory_seq_pos_max", FnMemorySeqPosMax),
            batch_init: require!("llama_batch_init", FnBatchInit),
            batch_free: require!("llama_batch_free", FnBatchFree),
            decode: require!("llama_decode", FnDecode),
            get_logits_ith: require!("llama_get_logits_ith", FnGetLogitsIth),
            vocab_n_tokens: require!("llama_vocab_n_tokens", FnVocabNTokens),
            tokenize: require!("llama_tokenize", FnTokenize),
            token_to_piece: require!("llama_token_to_piece", FnTokenToPiece),
            vocab_eos: require!("llama_vocab_eos", FnVocabEos),
            vocab_is_eog: require!("llama_vocab_is_eog", FnVocabIsEog),
            sampler_chain_default_params: require!(
                "llama_sampler_chain_default_params",
                FnSamplerChainDefaultParams
            ),
            sampler_chain_init: require!("llama_sampler_chain_init", FnSamplerChainInit),
            sampler_chain_add: require!("llama_sampler_chain_add", FnSamplerChainAdd),
            sampler_free: require!("llama_sampler_free", FnSamplerFree),
            sampler_init_greedy: require!("llama_sampler_init_greedy", FnSamplerInitGreedy),
            sampler_init_temp: require!("llama_sampler_init_temp", FnSamplerInitTemp),
            sampler_init_top_k: require!("llama_sampler_init_top_k", FnSamplerInitTopK),
            sampler_init_top_p: require!("llama_sampler_init_top_p", FnSamplerInitTopP),
            sampler_init_dist: require!("llama_sampler_init_dist", FnSamplerInitDist),
            sampler_sample: require!("llama_sampler_sample", FnSamplerSample),
            state_get_size: require!("llama_state_get_size", FnStateGetSize),
            model_n_layer: require!("llama_model_n_layer", FnModelNLayer),
            model_n_embd: require!("llama_model_n_embd", FnModelNEmbd),
            model_n_head: require!("llama_model_n_head", FnModelNHead),
            model_n_head_kv: require!("llama_model_n_head_kv", FnModelNHeadKv),
            lib,
            // The ggml library ships next to the llama library in every
            // pinned bundle; resolving the backend registry loader from it
            // is REQUIRED on bundles with separate ggml-cpu-*.dll backends
            // (every OS we pin) — llama_model_load_from_file fails with
            // "no backends are loaded" otherwise.
            ggml_lib: Some(
                load_library(&dir.join(Self::ggml_library_file_name()))
                    .map_err(|e| format!("ggml library load: {e}"))?,
            ),
            backend_load_all_from_path: None, // set right below
            bundle_dir: dir.to_path_buf(),
            vocab_size: AtomicU32::new(0),
        };
        // Resolve ggml_backend_load_all_from_path from the ggml library and
        // register the bundle's backends immediately (guarded by the same
        // process Once as backend_init by the caller; registering twice
        // would duplicate backends).
        if let Some(ggml) = result.ggml_lib.as_ref() {
            let sym = unsafe {
                ggml.get::<FnBackendLoadAllFromPath>(b"ggml_backend_load_all_from_path\0")
            };
            match sym {
                Ok(f) => result.backend_load_all_from_path = Some(*f),
                Err(e) => {
                    return Err(format!(
                        "pinned b11407 ggml export ggml_backend_load_all_from_path: {e}"
                    ))
                }
            }
        }
        Ok(result)
    }

    /// `ggml_backend_load_all_from_path(<bundle dir>)` — registers the
    /// ggml-cpu/ggml-vulkan backend libraries that ship in the pinned
    /// bundle (modern llama.cpp refuses to load a model without them).
    /// Call exactly once per process, after `backend_init`.
    pub fn load_bundle_backends(&self) -> Result<(), String> {
        let Some(load_all) = self.backend_load_all_from_path else {
            return Err("ggml backend registry unavailable".into());
        };
        let dir = self
            .bundle_dir
            .to_str()
            .ok_or_else(|| "bundle dir is not UTF-8".to_string())?;
        let c_dir = std::ffi::CString::new(dir).map_err(|e| format!("bundle dir: {e}"))?;
        unsafe { load_all(c_dir.as_ptr()) };
        Ok(())
    }

    /// `llama_backend_init` — process-global; callers guard with a `Once`.
    pub fn backend_init(&self) {
        unsafe { (self.backend_init)() };
    }

    /// Default model params of the pinned build (for the record + tests).
    pub fn model_default_params(&self) -> LlamaModelParams {
        unsafe { (self.model_default_params)() }
    }

    /// Default context params of the pinned build (ABI canary for tests).
    pub fn context_default_params(&self) -> LlamaContextParams {
        unsafe { (self.context_default_params)() }
    }

    /// Loads the model from a GGUF path with (default) params.
    pub fn load_model(
        self: &Arc<Self>,
        path: &Path,
        params: LlamaModelParams,
    ) -> Result<ModelPtr, String> {
        let Some(path_str) = path.to_str() else {
            return Err(format!("model path is not UTF-8: {}", path.display()));
        };
        // The engine takes a UTF-8 `const char *` on every platform we pin.
        let c_path = std::ffi::CString::new(path_str).map_err(|e| format!("model path: {e}"))?;
        let ptr = unsafe { (self.model_load_from_file)(c_path.as_ptr(), params) };
        if ptr.is_null() {
            return Err(format!("llama_model_load_from_file failed for {path_str}"));
        }
        Ok(ModelPtr {
            lib: Arc::clone(self),
            ptr,
        })
    }

    /// The model's vocabulary handle.
    pub fn vocab(&self, model: &ModelPtr) -> *const LlamaVocab {
        unsafe { (self.model_get_vocab)(model.ptr) }
    }

    /// Creates a context from the model with (modified default) params.
    pub fn init_context(
        self: &Arc<Self>,
        model: &ModelPtr,
        params: LlamaContextParams,
    ) -> Result<ContextPtr, String> {
        let ptr = unsafe { (self.init_from_model)(model.ptr, params) };
        if ptr.is_null() {
            return Err("llama_init_from_model failed (check n_ctx/n_threads)".into());
        }
        let mem = unsafe { (self.get_memory)(ptr) };
        Ok(ContextPtr {
            lib: Arc::clone(self),
            ptr,
            mem,
        })
    }

    /// Context size actually allocated.
    pub fn n_ctx(&self, ctx: &ContextPtr) -> u32 {
        unsafe { (self.n_ctx)(ctx.ptr) }
    }

    /// Logical batch limit.
    pub fn n_batch(&self, ctx: &ContextPtr) -> u32 {
        unsafe { (self.n_batch)(ctx.ptr) }
    }

    /// Vocabulary size (logits row width).
    pub fn vocab_n_tokens(&self, vocab: *const LlamaVocab) -> u32 {
        unsafe { (self.vocab_n_tokens)(vocab) }.max(0) as u32
    }

    /// Caches the vocab size (used to slice logits rows without re-querying).
    pub fn set_cached_vocab_n_tokens(&self, n: u32) {
        self.vocab_size
            .store(n, std::sync::atomic::Ordering::Relaxed);
    }

    /// The vocabulary's EOS token id (`-1` when the model has none).
    pub fn vocab_eos(&self, vocab: *const LlamaVocab) -> i32 {
        unsafe { (self.vocab_eos)(vocab) }
    }

    /// End-of-generation check (covers the EOS/EOT class of tokens).
    pub fn vocab_is_eog(&self, vocab: *const LlamaVocab, token: u32) -> bool {
        unsafe { (self.vocab_is_eog)(vocab, token as LlamaToken) }
    }

    /// Tokenizes text with explicit special-token flags (server `/tokenize`
    /// parity is pinned by the loopback test).
    pub fn tokenize(
        &self,
        vocab: *const LlamaVocab,
        text: &str,
        add_special: bool,
        parse_special: bool,
    ) -> Result<Vec<u32>, String> {
        let bytes = text.as_bytes();
        let len = i32::try_from(bytes.len()).map_err(|_| "text too long".to_string())?;
        // Sizing contract: a negative return reports the NEGATED required
        // token count (the documented b11407 behavior when the buffer is
        // too small; with capacity 0 every non-empty text sizes this way).
        let raw = unsafe {
            (self.tokenize)(
                vocab,
                bytes.as_ptr(),
                len,
                std::ptr::null_mut(),
                0,
                add_special,
                parse_special,
            )
        };
        let mut capacity = if raw < 0 {
            (-raw) as usize
        } else {
            // Empty text or a caller-friendly build: non-negative sizes too.
            raw as usize
        };
        let mut out = vec![0 as LlamaToken; capacity];
        let mut written = unsafe {
            (self.tokenize)(
                vocab,
                bytes.as_ptr(),
                len,
                out.as_mut_ptr(),
                capacity as i32,
                add_special,
                parse_special,
            )
        };
        if written < 0 {
            // Grow once if the sizing estimate was tight.
            capacity = (-written) as usize;
            out.resize(capacity, 0);
            written = unsafe {
                (self.tokenize)(
                    vocab,
                    bytes.as_ptr(),
                    len,
                    out.as_mut_ptr(),
                    capacity as i32,
                    add_special,
                    parse_special,
                )
            };
        }
        if written < 0 || written as usize > out.len() {
            return Err(format!("llama_tokenize failed: {written}"));
        }
        out.truncate(written as usize);
        Ok(out.into_iter().map(|t| t.max(0) as u32).collect())
    }

    /// Detokenizes ids to text (pieces concatenated, specials rendered —
    /// server `/detokenize` parity asserted in the loopback test).
    pub fn detokenize(&self, vocab: *const LlamaVocab, ids: &[u32]) -> Result<String, String> {
        let mut text = String::new();
        let mut buf = vec![0u8; 256];
        for &id in ids {
            if id > i32::MAX as u32 {
                return Err(format!("token id {id} out of range"));
            }
            // Same sizing convention as tokenize: negative = needed size.
            let mut written = unsafe {
                (self.token_to_piece)(
                    vocab,
                    id as LlamaToken,
                    buf.as_mut_ptr(),
                    buf.len() as i32,
                    0,
                    true,
                )
            };
            if written < 0 {
                buf.resize((-written) as usize, 0);
                written = unsafe {
                    (self.token_to_piece)(
                        vocab,
                        id as LlamaToken,
                        buf.as_mut_ptr(),
                        buf.len() as i32,
                        0,
                        true,
                    )
                };
            }
            if written < 0 || written as usize > buf.len() {
                return Err(format!(
                    "llama_token_to_piece failed for id {id}: {written}"
                ));
            }
            text.push_str(&String::from_utf8_lossy(&buf[..written as usize]));
        }
        Ok(text)
    }

    /// Largest KV position currently in sequence 0 (`-1` when empty).
    pub fn memory_seq_pos_max(&self, ctx: &ContextPtr) -> LlamaPos {
        unsafe { (self.memory_seq_pos_max)(ctx.mem, 0) }
    }

    /// Removes KV positions `[p0, inf)` of sequence 0 (rollback). `false`
    /// means the memory refused a partial removal — surfaced as an error by
    /// the adapter.
    pub fn memory_seq_rm(&self, ctx: &ContextPtr, p0: LlamaPos) -> bool {
        unsafe { (self.memory_seq_rm)(ctx.mem, 0, p0, -1) }
    }

    /// Removes the WHOLE of sequence 0 from the KV (documented b11407
    /// semantics: removing a whole sequence never fails). Used by the
    /// load-time warmup to leave zero KV behind.
    pub fn memory_seq_rm_all(&self, ctx: &ContextPtr) -> bool {
        unsafe { (self.memory_seq_rm)(ctx.mem, 0, -1, -1) }
    }

    /// Decodes `tokens` into the context's KV (sequence 0) through the
    /// handle's POOLED batch (ADR-031 §5.1: shape-stable batching — the
    /// batch buffer is allocated once per handle and reused, so steady-state
    /// decodes perform no engine-side batch allocation). `logits` selects
    /// which rows request logits; returns the KV position the FIRST token
    /// landed on; errors carry the engine's `llama_decode` return code.
    ///
    /// Batch construction follows the engine's own examples:
    /// `llama_batch_init` returns allocated-but-PARTIALLY-UNINITIALIZED
    /// arrays (`pos` is raw malloc, `n_seq_id`/`seq_id`/`logits` are
    /// zeroed), so EVERY field is written explicitly here — sequence 0,
    /// consecutive positions starting at the KV tail.
    pub fn decode_pooled(
        &self,
        ctx: &mut ContextPtr,
        batch: &mut PooledBatch,
        tokens: &[u32],
        logits: Logits,
    ) -> Result<u32, i32> {
        if tokens.is_empty() {
            return Err(-1);
        }
        let n = i32::try_from(tokens.len()).map_err(|_| -1)?;
        if n > batch.capacity {
            // Caller bug, never a runtime shape: the pool is sized for the
            // adapter's full context at load time.
            return Err(-1);
        }
        let start = unsafe { (self.memory_seq_pos_max)(ctx.mem, 0) } + 1;
        let raw = &mut batch.raw;
        raw.n_tokens = n;
        for (i, token) in tokens.iter().enumerate() {
            if *token > i32::MAX as u32 {
                return Err(-1);
            }
            unsafe {
                *raw.token.add(i) = *token as LlamaToken;
                *raw.pos.add(i) = start + i as LlamaPos;
                *raw.n_seq_id.add(i) = 1;
                *(*raw.seq_id.add(i)) = 0;
                let want = match logits {
                    Logits::None => 0,
                    Logits::All => 1,
                    Logits::Last => i8::from(i + 1 == tokens.len()),
                };
                *raw.logits.add(i) = want;
            }
        }
        let rc = unsafe { (self.decode)(ctx.ptr, *raw) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(start.max(0) as u32)
    }

    /// Allocates the per-handle pooled batch (`llama_batch_init` once,
    /// `llama_batch_free` on drop) with room for `capacity` tokens.
    pub fn pooled_batch(self: &Arc<Self>, capacity: u32) -> Result<PooledBatch, String> {
        let n = i32::try_from(capacity).map_err(|_| "batch capacity out of range".to_string())?;
        let raw = unsafe { (self.batch_init)(n, 0, 1) };
        Ok(PooledBatch {
            lib: Arc::clone(self),
            raw,
            capacity: n,
        })
    }

    /// `llama_state_get_size` — the engine-reported size in bytes of the
    /// context's serializable state (KV cache contents + output buffers).
    /// Used for per-handle KV RAM accounting (an upper-bound proxy: the
    /// physical KV allocation exists from load, this measures the used
    /// state).
    pub fn state_get_size(&self, ctx: &ContextPtr) -> u64 {
        unsafe { (self.state_get_size)(ctx.ptr) as u64 }
    }

    /// Model layer count (KV accounting input).
    pub fn model_n_layer(&self, model: &ModelPtr) -> u32 {
        unsafe { (self.model_n_layer)(model.ptr) }.max(0) as u32
    }

    /// Model embedding width (head size derivation for KV accounting).
    pub fn model_n_embd(&self, model: &ModelPtr) -> u32 {
        unsafe { (self.model_n_embd)(model.ptr) }.max(0) as u32
    }

    /// Model attention head count.
    pub fn model_n_head(&self, model: &ModelPtr) -> u32 {
        unsafe { (self.model_n_head)(model.ptr) }.max(0) as u32
    }

    /// Model KV head count (GQA-aware).
    pub fn model_n_head_kv(&self, model: &ModelPtr) -> u32 {
        unsafe { (self.model_n_head_kv)(model.ptr) }.max(0) as u32
    }

    /// The logits row for output index `row` (negative indexes from the
    /// back), as a slice over the full vocabulary. `None` when the index is
    /// invalid (no such output in the last decode).
    pub fn logits_row(&self, ctx: &mut ContextPtr, row: i32) -> Option<&[f32]> {
        let ptr = unsafe { (self.get_logits_ith)(ctx.ptr, row) };
        if ptr.is_null() {
            return None;
        }
        let n = self.vocab_size.load(std::sync::atomic::Ordering::Relaxed);
        if n == 0 {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(ptr, n as usize) })
    }

    /// Builds a sampler chain mirroring the HTTP adapter's `sampling_body`
    /// semantics: default-equal or `temperature == 0` → pure greedy (server
    /// parity); otherwise temp → top_k → top_p → dist (seeded when given).
    pub fn build_chain(
        self: &Arc<Self>,
        sampling: &crate::SamplingParams,
    ) -> Result<SamplerChain, String> {
        let params = unsafe { (self.sampler_chain_default_params)() };
        let chain = unsafe { (self.sampler_chain_init)(params) };
        if chain.is_null() {
            return Err("llama_sampler_chain_init failed".into());
        }
        let chain = SamplerChain {
            lib: Arc::clone(self),
            ptr: chain,
        };
        if *sampling == crate::SamplingParams::default() || sampling.temperature == 0.0 {
            let greedy = unsafe { (self.sampler_init_greedy)() };
            if greedy.is_null() {
                return Err("llama_sampler_init_greedy failed".into());
            }
            unsafe { (self.sampler_chain_add)(chain.ptr, greedy) };
            return Ok(chain);
        }
        // Order mirrors the llama.cpp server chain: temperature first, then
        // truncation, then the distribution draw.
        let temp = unsafe { (self.sampler_init_temp)(sampling.temperature) };
        let top_k = unsafe { (self.sampler_init_top_k)(sampling.top_k as i32) };
        let top_p = unsafe { (self.sampler_init_top_p)(sampling.top_p, 1) };
        // u32 narrowing of the u64 seed is documented spike behavior.
        let dist = unsafe { (self.sampler_init_dist)(sampling.seed.unwrap_or(0) as u32) };
        for sampler in [temp, top_k, top_p, dist] {
            if sampler.is_null() {
                return Err("sampler allocation failed".into());
            }
            unsafe { (self.sampler_chain_add)(chain.ptr, sampler) };
        }
        Ok(chain)
    }

    /// Samples output row `row` of the context's last decode through the
    /// chain — the same sampler machinery the pinned server uses, so greedy
    /// results are bit-identical to the HTTP adapter's.
    pub fn sample(&self, chain: &mut SamplerChain, ctx: &mut ContextPtr, row: i32) -> u32 {
        unsafe { (self.sampler_sample)(chain.ptr, ctx.ptr, row) }.max(0) as u32
    }

    /// File name of the ggml library inside the pinned bundle, per OS.
    fn ggml_library_file_name() -> &'static str {
        if cfg!(windows) {
            "ggml.dll"
        } else if cfg!(target_os = "macos") {
            "libggml.dylib"
        } else {
            "libggml.so"
        }
    }
}

#[cfg(windows)]
fn load_library(path: &Path) -> Result<libloading::Library, libloading::Error> {
    // ALTERED_SEARCH_PATH: resolve ggml*.dll dependencies from the bundle
    // directory of the canonicalized llama.dll path.
    use libloading::os::windows::{Library as OsLibrary, LOAD_WITH_ALTERED_SEARCH_PATH};
    let os_library = unsafe { OsLibrary::load_with_flags(path, LOAD_WITH_ALTERED_SEARCH_PATH) };
    os_library.map(libloading::Library::from)
}

#[cfg(not(windows))]
fn load_library(path: &Path) -> Result<libloading::Library, libloading::Error> {
    // Safety: identical acceptance to the Windows branch above — `path` is
    // the canonicalized `libllama.so`/`libllama.dylib` inside the sha256-
    // verified engine bundle of `runtime-pins.json`, and we accept that
    // dlopen runs the library's constructors (libloading 0.8.9 marks
    // `Library::new` unsafe for exactly that reason; the Windows
    // `load_with_flags` call takes the same risk under its own unsafe
    // block). Found by the 0.2.21 desktop-installer matrix: this branch
    // compiles nowhere else in CI (check job is windows-latest, where it
    // is cfg'd out).
    unsafe { libloading::Library::new(path) }
}

/// `Send`/`Sync` for the engine core declared in `super`: its only raw
/// pointer beyond the owned wrappers is `EngineInner::vocab` (derived from
/// the owned `ModelPtr`, freed together), and every engine call is
/// serialized by the owning handle's mutex.
// Safety: see comment; mirrors the wrapper impls above.
unsafe impl Send for super::EngineInner {}
// Safety: see comment.
unsafe impl Sync for super::EngineInner {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_layout_matches_pinned_header() {
        // include/llama.h b11407: int32 + 6 pointers, alignment 8 → 56 bytes.
        assert_eq!(std::mem::size_of::<LlamaBatch>(), 56);
        assert_eq!(std::mem::align_of::<LlamaBatch>(), 8);
    }

    #[test]
    fn context_params_layout_matches_pinned_header() {
        // 160 bytes per the mechanical mirror of b11407's
        // `struct llama_context_params`. The leading scalar offsets we
        // write are pinned exactly:
        assert_eq!(std::mem::offset_of!(LlamaContextParams, n_ctx), 0);
        assert_eq!(std::mem::offset_of!(LlamaContextParams, n_batch), 4);
        assert_eq!(std::mem::offset_of!(LlamaContextParams, n_threads), 28);
        assert_eq!(
            std::mem::offset_of!(LlamaContextParams, n_threads_batch),
            32
        );
        assert_eq!(std::mem::size_of::<LlamaContextParams>(), 160);
        assert_eq!(std::mem::align_of::<LlamaContextParams>(), 8);
    }

    #[test]
    fn model_params_layout_matches_pinned_header() {
        assert_eq!(std::mem::size_of::<LlamaModelParams>(), 80);
        assert_eq!(std::mem::align_of::<LlamaModelParams>(), 8);
    }

    #[test]
    fn loading_from_a_missing_directory_fails_closed() {
        let err = match LlamaLib::load(Path::new("Z:/definitely/not/here")) {
            Err(err) => err,
            Ok(_) => panic!("loading from a missing directory must fail"),
        };
        assert!(err.contains("not found"), "{err}");
    }
}
