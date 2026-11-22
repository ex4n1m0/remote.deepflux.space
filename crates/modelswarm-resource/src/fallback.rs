//! Fallback [`SampleSource`] for OSes without an implemented path (macOS
//! today): every field is an honest `None`/error rather than a guess. The
//! availability matrix in the crate docs is the contract.

use std::io;
use std::time::Instant;

use crate::source::{GpuLive, SampleSource, SystemMemory, TreeSnapshot};

pub struct FallbackSource {
    cores: u32,
}

impl FallbackSource {
    pub fn new() -> Self {
        Self {
            cores: std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(0),
        }
    }
}

impl Default for FallbackSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SampleSource for FallbackSource {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn logical_cores(&self) -> u32 {
        self.cores
    }

    fn process_tree(&self) -> io::Result<TreeSnapshot> {
        Err(io::Error::other(
            "resource sampling not implemented on this OS (honest n/a)",
        ))
    }

    fn system_memory(&self) -> io::Result<SystemMemory> {
        Err(io::Error::other(
            "resource sampling not implemented on this OS (honest n/a)",
        ))
    }

    fn gpu(&mut self) -> Option<GpuLive> {
        None
    }
}
