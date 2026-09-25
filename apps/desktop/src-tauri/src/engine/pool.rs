//! Process-lifetime codec/capture pool (the m2_rig F26 pattern):
//! `MfEncoder`/`MfDecoder` drop paths retain committed memory, threads,
//! and handles (measured by `crates/node-runtime/examples/leak_probe.rs`),
//! and every `DxgiCapture` instance commits a full-resolution surface ring
//! (~128 MiB at 4K) that is not decommitted on drop. The pool hands the
//! instance to each session's stage threads and takes it back when they
//! exit; session boundaries are a `reset()` + forced IDR, not a new MFT.
//!
//! Exception (M4): a *quality preset* change needs a new encoder config
//! (bitrate/resolution are fixed at MFT creation), so the pool's encoder
//! slot is replaced — the one known drop-path leak per change, counted by
//! the engine (`encoder_rebuilds`) and bounded by user action.

use std::sync::{Arc, Mutex};

use capture_windows::DxgiCapture;
use codec_windows::{MfDecoder, MfEncoder};

#[derive(Default)]
pub struct CodecPool {
    pub encoder: Arc<Mutex<Option<MfEncoder>>>,
    pub decoder: Arc<Mutex<Option<MfDecoder>>>,
    pub capture: Arc<Mutex<Option<DxgiCapture>>>,
}

impl CodecPool {
    pub fn new() -> Self {
        Self::default()
    }
}
