//! Linux implementation of [`SampleSource`] — the trivial `/proc` path:
//! CPU/RAM/working set come from `/proc/<pid>/stat`, `/proc/<pid>/statm`,
//! and `/proc/meminfo`. GPU counters have no vendor-neutral `/proc`
//! source, so they are honestly `None` (see the crate availability
//! matrix).
//!
//! Documented assumptions (deliberately not queried, per the
//! cross-platform-honesty instruction to keep this path trivial):
//! `USER_HZ == 100` (10 ms per tick) and 4 KiB pages — true on every
//! mainstream distro.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::time::{Duration, Instant};

use crate::parsers::{parse_meminfo_kib, parse_proc_stat, parse_proc_statm_rss_pages};
use crate::source::{
    descendant_pids, GpuLive, ProcSample, ProcessScope, SampleSource, SystemMemory, TreeSnapshot,
};

/// 4 KiB pages (assumption; see module docs).
const PAGE_SIZE: u64 = 4096;
/// 100 Hz scheduler tick (assumption; see module docs).
const TICK: Duration = Duration::from_millis(10);

pub struct LinuxSource {
    scope: ProcessScope,
    cores: u32,
}

impl LinuxSource {
    pub fn new(scope: ProcessScope) -> Self {
        Self {
            scope,
            cores: logical_processor_count(),
        }
    }
}

impl SampleSource for LinuxSource {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn logical_cores(&self) -> u32 {
        self.cores
    }

    fn process_tree(&self) -> io::Result<TreeSnapshot> {
        // One stat read per process gives the pid/ppid graph; a second
        // (statm) read is done only for tree members.
        let mut stats: HashMap<u32, (u32, u64, u64)> = HashMap::new(); // pid -> (ppid, utime, stime)
        let mut parent_of: HashMap<u32, u32> = HashMap::new();
        for pid in numeric_proc_dirs()? {
            if let Ok((ppid, utime, stime)) = read_stat(&pid) {
                parent_of.insert(pid, ppid);
                stats.insert(pid, (ppid, utime, stime));
            }
            // unreadable = process died mid-read: skip it this tick
        }
        let pids = descendant_pids(&parent_of, &self.scope.root_pids());
        let mut procs = Vec::with_capacity(pids.len());
        for pid in pids {
            let Some(&(_, utime, stime)) = stats.get(&pid) else {
                continue;
            };
            let ticks = utime.saturating_add(stime);
            let cpu_time =
                Duration::from_nanos((ticks as u128).saturating_mul(TICK.as_nanos()) as u64);
            let working_set = fs::read_to_string(format!("/proc/{pid}/statm"))
                .ok()
                .and_then(|s| parse_proc_statm_rss_pages(&s))
                .map(|pages| pages.saturating_mul(PAGE_SIZE));
            procs.push(ProcSample {
                pid,
                cpu_time,
                working_set,
            });
        }
        Ok(TreeSnapshot { procs })
    }

    fn system_memory(&self) -> io::Result<SystemMemory> {
        let content = fs::read_to_string("/proc/meminfo")?;
        let (total_kib, available_kib) =
            parse_meminfo_kib(&content).ok_or_else(|| io::Error::other("meminfo parse failed"))?;
        Ok(SystemMemory {
            total_bytes: total_kib.saturating_mul(1024),
            available_bytes: available_kib.saturating_mul(1024),
        })
    }

    fn gpu(&mut self) -> Option<GpuLive> {
        None // no vendor-neutral /proc GPU source; honest n/a
    }
}

/// Every PID with a `/proc/<pid>` directory.
fn numeric_proc_dirs() -> io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Ok(pid) = name.parse::<u32>() {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    Ok(pids)
}

/// Reads `/proc/<pid>/stat` into `(ppid, utime_ticks, stime_ticks)`.
fn read_stat(pid: &u32) -> io::Result<(u32, u64, u64)> {
    let line = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_proc_stat(&line).ok_or_else(|| io::Error::other("stat parse failed"))
}

/// Counts `processor` entries in `/proc/cpuinfo`; falls back to
/// `available_parallelism`.
fn logical_processor_count() -> u32 {
    let from_cpuinfo = fs::read_to_string("/proc/cpuinfo")
        .map(|s| {
            s.lines()
                .filter(|l| l.starts_with("processor"))
                .count()
                .max(1) as u32
        })
        .unwrap_or(0);
    if from_cpuinfo > 0 {
        from_cpuinfo
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1)
    }
}
