//! Windows implementation of [`SampleSource`] — the product's primary OS,
//! implemented fully:
//!
//! - process tree: one Toolhelp32 snapshot per poll (pid/ppid graph),
//!   then `GetProcessTimes` + `GetProcessMemoryInfo` per tree member —
//!   deltas over process CPU time, Task-Manager style;
//! - system RAM: `GlobalMemoryStatusEx`;
//! - GPU: PDH performance counters — `\GPU Engine(*)\Utilization
//!   Percentage` and `\GPU Process Memory(*)\Local Usage`, the same
//!   data Task Manager shows, vendor-neutral on Win8+. The query is
//!   opened once (baseline collect at open; utilization is a rate counter
//!   needing two collects) and collected once per poll. Any failure
//!   (no GPU, stripped-down SKU, PDH denied) degrades the GPU fields to
//!   `None` permanently — an honest "n/a", never a guess.
//!
//! All raw FFI in this crate lives here (and only here), mirroring the
//! modelswarm-winjob isolation pattern; everything above
//! [`SampleSource`] stays platform-neutral.

use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterArrayW,
    PdhOpenQueryW, PDH_CSTATUS_NEW_DATA, PDH_CSTATUS_VALID_DATA, PDH_FMT_COUNTERVALUE,
    PDH_FMT_COUNTERVALUE_ITEM_W, PDH_FMT_DOUBLE, PDH_FMT_LARGE, PDH_MORE_DATA,
};
use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::SystemInformation::{
    GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

use crate::source::{
    descendant_pids, luid_of_instance, GpuLive, ProcSample, ProcessScope, SampleSource,
    SystemMemory, TreeSnapshot,
};

/// PDH counter path (English, via PdhAddEnglishCounterW): per-engine GPU
/// utilization instances, named like
/// `pid_1234_luid_0x00000000_0x0000C3B7_phys_0_eng_0_engtype_3D`.
const GPU_ENGINE_UTILIZATION: &str = "\\GPU Engine(*)\\Utilization Percentage";
/// PDH counter path: per-process dedicated VRAM instances
/// (`pid_..._luid_..._phys_N`), value in bytes.
const GPU_PROCESS_LOCAL_USAGE: &str = "\\GPU Process Memory(*)\\Local Usage";

/// Windows sampling source. Cheap per poll (one snapshot + one PDH
/// collect). Keep usage single-threaded: PDH query handles are not
/// documented as thread-safe, so poll from one task (the UI timer).
pub struct WindowsSource {
    scope: ProcessScope,
    cores: u32,
    gpu: Option<GpuQuery>,
}

impl WindowsSource {
    /// Opens the source and takes the PDH baseline collect, so the first
    /// `gpu()` poll (one collect later) can already format rate counters.
    pub fn new(scope: ProcessScope) -> Self {
        Self {
            scope,
            cores: logical_processor_count(),
            gpu: GpuQuery::open(),
        }
    }
}

impl SampleSource for WindowsSource {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn logical_cores(&self) -> u32 {
        self.cores
    }

    fn process_tree(&self) -> io::Result<TreeSnapshot> {
        let table = process_table()?;
        let pids = descendant_pids(&table, &self.scope.root_pids());
        let mut procs = Vec::with_capacity(pids.len());
        for pid in pids {
            // A member that disappears between snapshot and open (engine
            // restart) is skipped this tick — an undercount for one poll,
            // never a failure of the whole sample.
            if let Some(sample) = read_process(pid) {
                procs.push(sample);
            }
        }
        Ok(TreeSnapshot { procs })
    }

    fn system_memory(&self) -> io::Result<SystemMemory> {
        unsafe {
            let mut status: MEMORYSTATUSEX = std::mem::zeroed();
            status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
            if GlobalMemoryStatusEx(&mut status) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(SystemMemory {
                total_bytes: status.ullTotalPhys,
                available_bytes: status.ullAvailPhys,
            })
        }
    }

    fn gpu(&mut self) -> Option<GpuLive> {
        self.gpu.as_mut().and_then(GpuQuery::poll)
    }
}

/// pid -> ppid for every process on the machine (one Toolhelp pass).
fn process_table() -> io::Result<HashMap<u32, u32>> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut table = HashMap::new();
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                table.insert(entry.th32ProcessID, entry.th32ParentProcessID);
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        Ok(table)
    }
}

/// CPU time (kernel+user) and working set of one process. `None` when the
/// process could not be opened (gone, or access denied for an elevated
/// process from a standard one — an honest undercount).
fn read_process(pid: u32) -> Option<ProcSample> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut creation = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut kernel = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut user = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut cpu_time = Duration::ZERO;
        if GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) != 0 {
            cpu_time = filetime_duration(&user) + filetime_duration(&kernel);
        }
        let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let working_set = (GetProcessMemoryInfo(handle, &mut counters, counters.cb) != 0)
            .then_some(counters.WorkingSetSize as u64);
        CloseHandle(handle);
        Some(ProcSample {
            pid,
            cpu_time,
            working_set,
        })
    }
}

/// FILETIME (100 ns ticks since 1601) -> `Duration` of CPU time consumed.
fn filetime_duration(ft: &FILETIME) -> Duration {
    let ticks = ((ft.dwHighDateTime as u64) << 32) | u64::from(ft.dwLowDateTime);
    Duration::from_nanos(ticks.saturating_mul(100))
}

/// Total logical processors of the machine (not the affinity mask of this
/// process), so 100% means "all cores of the machine", like Task Manager.
fn logical_processor_count() -> u32 {
    unsafe {
        let mut info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut info);
        if info.dwNumberOfProcessors == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(1)
        } else {
            info.dwNumberOfProcessors
        }
    }
}

fn wide(path: &str) -> Vec<u16> {
    path.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A persistent PDH query for the two GPU counter sets. Rate counters
/// (`Utilization Percentage`) only format after two collects separated in
/// time; `open()` performs the baseline collect, so the first `poll()`
/// (>= 1 s later at UI cadence) already carries values.
struct GpuQuery {
    query: isize,
    engine: isize,
    /// `\GPU Process Memory(*)\Local Usage` handle; 0 when the counter set
    /// is absent (older/stripped SKUs) — VRAM stays honestly `None`.
    memory: isize,
}

impl GpuQuery {
    fn open() -> Option<Self> {
        unsafe {
            let mut query: isize = 0;
            if PdhOpenQueryW(std::ptr::null(), 0, &mut query) != 0 {
                return None;
            }
            let engine_path = wide(GPU_ENGINE_UTILIZATION);
            let mut engine: isize = 0;
            if PdhAddEnglishCounterW(query, engine_path.as_ptr(), 0, &mut engine) != 0 {
                PdhCloseQuery(query);
                return None; // no GPU Engine counters on this system
            }
            let memory_path = wide(GPU_PROCESS_LOCAL_USAGE);
            let mut memory: isize = 0;
            if PdhAddEnglishCounterW(query, memory_path.as_ptr(), 0, &mut memory) != 0 {
                memory = 0; // optional: utilization without VRAM is fine
            }
            let q = Self {
                query,
                engine,
                memory,
            };
            if PdhCollectQueryData(q.query) != 0 {
                return None; // cannot even baseline; degrade permanently
            }
            Some(q)
        }
    }

    /// One collect + format. `Some(GpuLive)` with inner `None`s when the
    /// counters exist but currently have no instances.
    fn poll(&mut self) -> Option<GpuLive> {
        unsafe {
            if PdhCollectQueryData(self.query) != 0 {
                return None; // this tick only; the query stays usable
            }
        }
        // Utilization per adapter: sum that adapter's engine instances
        // (concurrent 3D + decode can exceed 100 pre-clamp), keep the
        // busiest adapter.
        let mut util_by_luid: HashMap<String, f64> = HashMap::new();
        if let Some(items) = formatted_array(self.engine, PDH_FMT_DOUBLE) {
            for (name, value) in items {
                if !status_ok(&value) {
                    continue;
                }
                let v = unsafe { value.Anonymous.doubleValue };
                if let Some(luid) = luid_of_instance(&name) {
                    if v.is_finite() && v >= 0.0 {
                        *util_by_luid.entry(luid).or_insert(0.0) += v;
                    }
                }
            }
        }
        // Dedicated VRAM per adapter: sum Local Usage (bytes) per LUID.
        let mut vram_by_luid: HashMap<String, u64> = HashMap::new();
        if self.memory != 0 {
            if let Some(items) = formatted_array(self.memory, PDH_FMT_LARGE) {
                for (name, value) in items {
                    if !status_ok(&value) {
                        continue;
                    }
                    let v = unsafe { value.Anonymous.largeValue };
                    if let Some(luid) = luid_of_instance(&name) {
                        *vram_by_luid.entry(luid).or_insert(0) += v.max(0) as u64;
                    }
                }
            }
        }
        let busiest = util_by_luid
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal));
        let utilization_percent = busiest.map(|(_, v)| v.clamp(0.0, 100.0));
        // VRAM follows the busiest adapter; with no active engines at all,
        // fall back to the adapter holding the most memory.
        let vram_used_bytes = match busiest {
            Some((luid, _)) => vram_by_luid.get(luid).copied(),
            None => vram_by_luid.values().max().copied(),
        };
        Some(GpuLive {
            utilization_percent,
            vram_used_bytes,
        })
    }
}

impl Drop for GpuQuery {
    fn drop(&mut self) {
        unsafe {
            // PdhCloseQuery also closes the counters inside the query.
            PdhCloseQuery(self.query);
        }
    }
}

fn status_ok(value: &PDH_FMT_COUNTERVALUE) -> bool {
    value.CStatus == PDH_CSTATUS_VALID_DATA || value.CStatus == PDH_CSTATUS_NEW_DATA
}

/// Reads a wildcard counter's formatted instance array. `None` on any PDH
/// failure (including "not enough samples yet" on the very first polls of
/// a rate counter).
fn formatted_array(counter: isize, fmt: u32) -> Option<Vec<(String, PDH_FMT_COUNTERVALUE)>> {
    unsafe {
        let mut size: u32 = 0;
        let mut count: u32 = 0;
        let rc =
            PdhGetFormattedCounterArrayW(counter, fmt, &mut size, &mut count, std::ptr::null_mut());
        if rc != PDH_MORE_DATA || size == 0 || count == 0 {
            return None;
        }
        // usize-typed storage keeps the buffer pointer-aligned for the
        // item struct (a plain Vec<u8> would only guarantee alignment 1).
        let words = (size as usize).div_ceil(std::mem::size_of::<usize>());
        let mut buf: Vec<usize> = vec![0; words];
        let rc = PdhGetFormattedCounterArrayW(
            counter,
            fmt,
            &mut size,
            &mut count,
            buf.as_mut_ptr() as *mut PDH_FMT_COUNTERVALUE_ITEM_W,
        );
        if rc != 0 {
            return None;
        }
        let items = std::slice::from_raw_parts(
            buf.as_ptr() as *const PDH_FMT_COUNTERVALUE_ITEM_W,
            count as usize,
        );
        Some(
            items
                .iter()
                .filter_map(|it| Some((pwstr_to_string(it.szName)?, it.FmtValue)))
                .collect(),
        )
    }
}

/// Copies a PDH instance name (nul-terminated UTF-16) into a `String`.
unsafe fn pwstr_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    Some(String::from_utf16_lossy(std::slice::from_raw_parts(
        ptr, len,
    )))
}
