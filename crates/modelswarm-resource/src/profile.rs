//! Static machine geometry (the M1 profiler's home). The LIVE side of this
//! crate is [`crate::ResourceSampler`]; this module is the once-per-process
//! detection that never runs per sample.
//!
//! Seed status (gate D19): full M1 profiling (thermal, battery,
//! foreground-state awareness) lands here in later tasks. Today this covers
//! the fields the monitor panel's static labels need. GPU geometry is
//! deliberately NOT re-detected here: the bundled engine's
//! `--list-devices` listing (the same backend that will serve) is the
//! authoritative static source and is already parsed by the desktop —
//! inject it with [`HardwareProfile::with_gpu`] instead of spawning
//! processes again.

/// Static GPU geometry from the M1 detection pass (the engine's own device
/// listing): name plus total dedicated VRAM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuGeometry {
    pub name: String,
    pub total_vram_bytes: u64,
}

/// Machine geometry detected once per process. Zero values mean "unknown"
/// (an honest unknown, never a guess).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HardwareProfile {
    /// Logical processors. `available_parallelism` semantics: may be lower
    /// than the physical core count when the process runs with a restricted
    /// affinity mask.
    pub logical_cpus: u32,
    /// Total physical RAM, bytes (0 = unknown).
    pub total_ram_bytes: u64,
    /// Largest GPU, per the engine's device listing (None = none detected).
    pub gpu: Option<GpuGeometry>,
}

impl HardwareProfile {
    /// Cheap static detection of CPU count and total RAM. GPU geometry is
    /// injected by the caller via [`HardwareProfile::with_gpu`] (the
    /// engine-`--list-devices` flow the desktop already owns).
    pub fn detect() -> Self {
        Self {
            logical_cpus: std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(0),
            total_ram_bytes: detect_total_ram_bytes(),
            gpu: None,
        }
    }

    /// Builder: attach the GPU geometry from the caller's M1 detection.
    pub fn with_gpu(mut self, name: impl Into<String>, total_vram_bytes: u64) -> Self {
        self.gpu = Some(GpuGeometry {
            name: name.into(),
            total_vram_bytes,
        });
        self
    }
}

fn detect_total_ram_bytes() -> u64 {
    #[cfg(windows)]
    {
        // The sanctioned Windows seam (modelswarm-winjob), reused rather
        // than re-declared.
        modelswarm_winjob::total_ram_bytes()
    }
    #[cfg(not(windows))]
    {
        // /proc/meminfo "MemTotal:  N kB"; macOS and friends stay honestly 0
        // (unknown) — no shelling out from detect.
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/meminfo")
                .ok()
                .and_then(|s| crate::parsers::parse_meminfo_kib(&s).map(|(total_kib, _)| total_kib))
                .map(|kib| kib.saturating_mul(1024))
                .unwrap_or(0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    }
}
