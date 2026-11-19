//! Windows FFI helpers for the desktop node: kill-on-close job objects
//! for supervised engine children, plus total-RAM detection. Kept as the
//! workspace's single unsafe-sanctioned crate.
//!
//! Force-killing the desktop app (taskkill /F, crash) must never orphan a
//! llama-server (observed live 2026-10-06). A job object created with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` ties every assigned process to the
//! job-handle's lifetime: when our process dies — however it dies — Windows
//! closes the handle and terminates the engine. The graceful shutdown path
//! still kills the child first; this is the belt to that braces.
//!
//! Job handles are retained for the process lifetime on purpose. This crate
//! is Windows-only by nature; it compiles to nothing useful elsewhere (all
//! entry points are `#[cfg(windows)]`).

#[cfg(windows)]
mod imp {
    use std::mem::size_of;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_MORE_DATA};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicProcessIdList,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        JOBOBJECT_BASIC_PROCESS_ID_LIST, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
    };

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GlobalMemoryStatusEx(lpBuffer: *mut MemoryStatusEx) -> i32;
    }

    #[repr(C)]
    struct MemoryStatusEx {
        dw_length: u32,
        dw_memory_load: u32,
        ull_total_phys: u64,
        ull_avail_phys: u64,
        ull_total_page_file: u64,
        ull_avail_page_file: u64,
        ull_total_virtual: u64,
        ull_avail_virtual: u64,
        ull_avail_extended_virtual: u64,
    }

    /// Total physical RAM in bytes (0 = unknown).
    pub fn total_ram_bytes() -> u64 {
        unsafe {
            let mut status: MemoryStatusEx = std::mem::zeroed();
            status.dw_length = std::mem::size_of::<MemoryStatusEx>() as u32;
            if GlobalMemoryStatusEx(&mut status) == 0 {
                return 0;
            }
            status.ull_total_phys
        }
    }

    /// Opaque kernel job handle; Send+Sync because it is only ever used by
    /// the FFI calls in this module.
    #[derive(Clone, Copy)]
    struct JobHandle(*mut core::ffi::c_void);
    unsafe impl Send for JobHandle {}
    unsafe impl Sync for JobHandle {}

    fn retained_jobs() -> &'static Mutex<Vec<JobHandle>> {
        static JOBS: OnceLock<Mutex<Vec<JobHandle>>> = OnceLock::new();
        JOBS.get_or_init(|| Mutex::new(Vec::new()))
    }

    /// The resource-governor's remembered tree commit cap (M2, ADR-035 /
    /// gate D11): 0 = none armed. Kept OUTSIDE the retained-jobs mutex so
    /// job creation never nests locks; read once per assign, written only
    /// by [`apply_tree_memory_cap`].
    static TREE_COMMIT_CAP: AtomicU64 = AtomicU64::new(0);

    /// Sets a job's extended limits: ALWAYS kill-on-close (the crate's
    /// founding contract), plus the remembered commit cap when one is
    /// armed. Single `SetInformationJobObject` call, so the flags can
    /// never be observed half-applied.
    fn set_job_limits(job: *mut core::ffi::c_void, cap_bytes: u64) -> Result<(), String> {
        unsafe {
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if cap_bytes > 0 {
                flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
                info.ProcessMemoryLimit = cap_bytes as usize;
            }
            info.BasicLimitInformation.LimitFlags = flags;
            if SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &mut info as *mut _ as *mut core::ffi::c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                return Err(format!(
                    "SetInformationJobObject: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(())
        }
    }

    /// Safe entry point: assigns `pid` (the engine child) to a
    /// kill-on-close job. Opens the process handle internally so no raw
    /// pointer crosses the crate boundary.
    pub fn assign_child(pid: u32) -> Result<(), String> {
        let process = open_process_for_job(pid)?;
        assign_kill_on_close_job(process)
    }

    /// Opens a process handle with the rights AssignProcessToJobObject needs.
    fn open_process_for_job(pid: u32) -> Result<*mut core::ffi::c_void, String> {
        unsafe {
            let handle = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
            if handle.is_null() {
                return Err(format!(
                    "OpenProcess({pid}): {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(handle)
        }
    }

    /// Creates a kill-on-close job, assigns `process_handle`, and retains
    /// the job handle until process death. When a tree commit cap is
    /// armed ([`apply_tree_memory_cap`]), the new job is born with it —
    /// the cap must cover children assigned AFTER arming, not just the
    /// jobs that existed when it was set.
    pub fn assign_kill_on_close_job(process_handle: *mut core::ffi::c_void) -> Result<(), String> {
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err(format!(
                    "CreateJobObjectW: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if let Err(e) = set_job_limits(job, TREE_COMMIT_CAP.load(Ordering::SeqCst)) {
                CloseHandle(job);
                return Err(e);
            }
            if AssignProcessToJobObject(job, process_handle) == 0 {
                let e = format!(
                    "AssignProcessToJobObject: {}",
                    std::io::Error::last_os_error()
                );
                CloseHandle(job);
                return Err(e);
            }
            retained_jobs()
                .lock()
                .map_err(|e| e.to_string())?
                .push(JobHandle(job));
            Ok(())
        }
    }

    /// Resource-governor seam (M2, ADR-035 / gate D19): arms a
    /// committed-memory cap (`JOB_OBJECT_LIMIT_PROCESSMEMORY`) over EVERY
    /// retained kill-on-close job — the supervised engine tree — and
    /// remembers it so children assigned later inherit the same limit at
    /// assignment time. The kill-on-close contract is always preserved
    /// (both flags ride one `SetInformationJobObject` call). Returns the
    /// number of EXISTING jobs the cap was applied to (0 = nothing
    /// supervised right now; the remembered cap still covers future
    /// assigns). A job whose update fails is skipped and counted out —
    /// an honest undercount, never a failure of the whole call.
    ///
    /// Semantics note for the governor: the OS enforces this on COMMIT,
    /// while the admission projection is working-set arithmetic; mapped
    /// weights are largely section-backed and do not count against
    /// commit, so the cap bites at or before the point the projection
    /// would reach the enforced system ceiling — never later.
    pub fn apply_tree_memory_cap(bytes: u64) -> Result<usize, String> {
        if bytes == 0 {
            return Err(
                "apply_tree_memory_cap: 0 is not a cap (0 would fail every allocation)".to_string(),
            );
        }
        TREE_COMMIT_CAP.store(bytes, Ordering::SeqCst);
        let jobs = match retained_jobs().lock() {
            Ok(jobs) => jobs,
            Err(e) => return Err(e.to_string()),
        };
        let mut armed = 0;
        for &JobHandle(job) in jobs.iter() {
            // The handle came from CreateJobObjectW and is owned by the
            // retained list.
            if set_job_limits(job, bytes).is_ok() {
                armed += 1;
            }
        }
        Ok(armed)
    }

    /// The remembered tree commit cap (0 = none armed) — the governor's
    /// readback that arming landed and stuck.
    pub fn tree_memory_cap_bytes() -> u64 {
        TREE_COMMIT_CAP.load(Ordering::SeqCst)
    }

    /// Test hook: forgets the remembered cap (existing jobs keep whatever
    /// limits they already have; only future assigns are affected).
    pub fn reset_tree_memory_cap_for_test() {
        TREE_COMMIT_CAP.store(0, Ordering::SeqCst);
    }

    /// Per-retained-job commit caps via `QueryInformationJobObject` —
    /// diagnostic readback proving the cap reached the kernel objects
    /// (0 entries = nothing supervised; a 0 element = that job has no
    /// memory limit armed).
    pub fn retained_job_commit_caps() -> Vec<u64> {
        let jobs = match retained_jobs().lock() {
            Ok(jobs) => jobs,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for &JobHandle(job) in jobs.iter() {
            unsafe {
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                let ok = QueryInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &mut info as *mut _ as *mut core::ffi::c_void,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                );
                if ok != 0
                    && (info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_PROCESS_MEMORY)
                        != 0
                {
                    out.push(info.ProcessMemoryLimit as u64);
                } else {
                    out.push(0);
                }
            }
        }
        out
    }

    /// Test hook: closes one retained job handle (KILL_ON_JOB_CLOSE then
    /// terminates its processes). Returns CloseHandle's result (1 = closed).
    pub fn close_one_retained_job_for_test() -> usize {
        let job = retained_jobs()
            .lock()
            .ok()
            .and_then(|mut v| v.pop())
            .map(|JobHandle(h)| h)
            .unwrap_or(std::ptr::null_mut());
        if job.is_null() {
            return 0;
        }
        unsafe { CloseHandle(job) as usize }
    }

    /// Update-restart seam (auto-update owner request 2026-10-12): closes
    /// EVERY retained kill-on-close job handle now, terminating all
    /// supervised engine children synchronously with the call. The updater
    /// runs this in its `on_before_exit` hook — AFTER the update package's
    /// signature verified, BEFORE the NSIS installer is spawned — so the
    /// installer never races a live engine binary it is about to replace
    /// (the plain process-death path needs no call: handle close on exit
    /// does the same implicitly, however the process dies). Returns the
    /// number of jobs closed.
    pub fn close_all_retained_jobs() -> usize {
        let jobs = match retained_jobs().lock() {
            Ok(mut jobs) => std::mem::take(&mut *jobs),
            Err(_) => return 0,
        };
        let mut closed = 0;
        for JobHandle(job) in jobs {
            // SAFETY: the handle came from CreateJobObjectW and is owned by
            // the retained list (never closed elsewhere; the test hook above
            // pops from the same list, so no double close).
            if unsafe { CloseHandle(job) } != 0 {
                closed += 1;
            }
        }
        closed
    }

    /// PIDs currently assigned to this process's retained kill-on-close
    /// jobs — job-object MEMBERSHIP, i.e. exactly the supervised engine
    /// set (children inherit job membership on creation, so anything an
    /// engine spawned is included too). This is the resource monitor
    /// panel's scoping query (the sampler handoff 2026-10-12 §4 option
    /// (a): the panel's process tree equals the supervised set, immune to
    /// PID-reuse orphans). A job whose query fails is skipped — an honest
    /// per-job undercount, never a failure of the whole call.
    pub fn supervised_process_ids() -> Vec<u32> {
        let jobs = match retained_jobs().lock() {
            Ok(jobs) => jobs,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for &JobHandle(job) in jobs.iter() {
            out.extend(job_process_ids(job));
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// One job's member PIDs via `QueryInformationJobObject(
    /// JobObjectBasicProcessIdList)`. Starts with a 64-slot buffer (each
    /// job holds one engine child plus its own descendants — dozens is
    /// already exotic), doubles once on `ERROR_MORE_DATA` up to 1024, and
    /// returns empty on any other failure (a dead/raced handle reads as
    /// "no members", not as a panic).
    fn job_process_ids(job: *mut core::ffi::c_void) -> Vec<u32> {
        let mut capacity = 64usize;
        loop {
            // Layout: two u32 counters (one usize word) + capacity PIDs.
            let words = 1 + capacity;
            let mut buf: Vec<usize> = vec![0; words];
            let mut returned: u32 = 0;
            let ok = unsafe {
                QueryInformationJobObject(
                    job,
                    JobObjectBasicProcessIdList,
                    buf.as_mut_ptr().cast(),
                    (words * size_of::<usize>()) as u32,
                    &mut returned,
                )
            };
            if ok == 0 {
                let more_data =
                    std::io::Error::last_os_error().raw_os_error() == Some(ERROR_MORE_DATA as i32);
                if more_data && capacity < 1024 {
                    capacity *= 2;
                    continue;
                }
                return Vec::new();
            }
            let list = unsafe { &*(buf.as_ptr() as *const JOBOBJECT_BASIC_PROCESS_ID_LIST) };
            let count = list.NumberOfProcessIdsInList as usize;
            if count > capacity {
                return Vec::new();
            }
            let ids = unsafe { std::slice::from_raw_parts(list.ProcessIdList.as_ptr(), count) };
            return ids.iter().map(|&pid| pid as u32).collect();
        }
    }
}

#[cfg(windows)]
pub use imp::{
    apply_tree_memory_cap, assign_child, close_all_retained_jobs, close_one_retained_job_for_test,
    reset_tree_memory_cap_for_test, retained_job_commit_caps, supervised_process_ids,
    total_ram_bytes, tree_memory_cap_bytes,
};

#[cfg(test)]
mod tests {
    /// Both job tests share ONE retained-jobs stack, and
    /// `close_one_retained_job_for_test` pops LIFO: if they interleaved,
    /// one test's close could pop (and kill) the OTHER test's child. This
    /// lock serializes them for the whole assign→assert→cleanup span.
    /// cfg(windows): every caller is a windows-only test — un-gated, the
    /// helper is dead code in the non-Windows lib-test compile and fails
    /// the check-nonwindows-capi -D warnings gate (found by that gate on
    /// the 0.2.22 train; every run since ea47032 had been cancelled by
    /// the next push before this job finished, so it shipped unnoticed).
    #[cfg(windows)]
    fn job_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    #[cfg(windows)]
    fn job_handle_close_kills_assigned_child() {
        use std::process::Stdio;
        let _guard = job_test_lock();
        let mut child = std::process::Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ping");
        let pid = child.id();
        super::assign_child(pid).expect("assign job");

        let pid_bytes = pid.to_string().into_bytes();
        let alive = || {
            std::process::Command::new("tasklist")
                .args(["/FI", &format!("PID eq {pid}")])
                .output()
                .unwrap()
                .stdout
                .windows(pid_bytes.len())
                .any(|w| w == &pid_bytes[..])
        };
        assert!(alive(), "child must survive job assignment");

        assert_eq!(super::close_one_retained_job_for_test(), 1);
        std::thread::sleep(std::time::Duration::from_millis(1500));
        assert!(!alive(), "closing the job handle must kill the child");
        // Reap the killed child so the test leaves no zombie behind
        // (clippy::zombie_processes; the job kill delivers the exit).
        let _ = child.wait();
    }

    /// Job-object membership (the resource monitor panel's scoping query,
    /// sampler handoff §4 option (a)): an assigned child is reported by
    /// `supervised_process_ids`. Cleanup is a direct child kill + reap —
    /// `close_one_retained_job_for_test` pops an arbitrary retained job
    /// (tests run concurrently) and could kill ANOTHER test's child.
    #[test]
    #[cfg(windows)]
    fn supervised_process_ids_reports_assigned_children() {
        use std::process::Stdio;
        let _guard = job_test_lock();
        let mut child = std::process::Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ping");
        let pid = child.id();
        super::assign_child(pid).expect("assign job");
        let ids = super::supervised_process_ids();
        assert!(
            ids.contains(&pid),
            "job membership must include the assigned child {pid}: {ids:?}"
        );
        // The list is the deduped union across retained jobs.
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids, sorted, "membership is sorted + deduped");
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The updater's pre-install kill seam (auto-update owner request
    /// 2026-10-12): `close_all_retained_jobs` terminates EVERY supervised
    /// child at once — the state the NSIS installer requires before it may
    /// replace the engine files. Two children, one call, both dead, and
    /// the retained list is empty afterwards (idempotent second call).
    #[test]
    #[cfg(windows)]
    fn close_all_retained_jobs_kills_every_supervised_child() {
        use std::process::Stdio;
        let _guard = job_test_lock();
        let spawn = || {
            std::process::Command::new("ping")
                .args(["-n", "60", "127.0.0.1"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn ping")
        };
        let mut a = spawn();
        let mut b = spawn();
        super::assign_child(a.id()).expect("assign job a");
        super::assign_child(b.id()).expect("assign job b");
        assert_eq!(super::supervised_process_ids().len(), 2);

        assert_eq!(super::close_all_retained_jobs(), 2);
        // Idempotent: the retained list was drained, not just marked.
        assert_eq!(super::close_all_retained_jobs(), 0);

        let alive = |pid: u32| {
            let pid_bytes = pid.to_string().into_bytes();
            std::process::Command::new("tasklist")
                .args(["/FI", &format!("PID eq {pid}")])
                .output()
                .unwrap()
                .stdout
                .windows(pid_bytes.len())
                .any(|w| w == &pid_bytes[..])
        };
        std::thread::sleep(std::time::Duration::from_millis(1500));
        assert!(!alive(a.id()), "closing all jobs must kill child a");
        assert!(!alive(b.id()), "closing all jobs must kill child b");
        // Reap both so the test leaves no zombies behind.
        let _ = a.wait();
        let _ = b.wait();
    }

    /// The resource-governor commit-cap seam (M2, ADR-035): arming the
    /// tree cap (a) lands `JOB_OBJECT_LIMIT_PROCESSMEMORY` on every
    /// retained job as the KERNEL sees it (readback via
    /// `QueryInformationJobObject`, not the remembered value), (b) is
    /// remembered so a child assigned AFTER arming is born capped, and
    /// (c) never strips kill-on-close (both flags ride one call — the
    /// readback asserts the memory flag, and the child staying alive
    /// until we kill it shows the job still works). Cleanup: direct kill
    /// + reap + reset the remembered cap so later assigns are unaffected.
    #[test]
    #[cfg(windows)]
    fn tree_memory_cap_lands_and_sticks_for_children_assigned_later() {
        use std::process::Stdio;
        let _guard = job_test_lock();
        super::reset_tree_memory_cap_for_test();
        assert_eq!(super::tree_memory_cap_bytes(), 0);

        let mut first = std::process::Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ping");
        super::assign_child(first.id()).expect("assign first");
        // Sibling tests may leave drained/dead retained jobs behind, so
        // assert on VALUES not counts: nothing carries a cap yet.
        let before = super::retained_job_commit_caps();
        assert!(!before.is_empty(), "our job must be retained");
        assert!(before.iter().all(|&c| c == 0), "no cap yet: {before:?}");

        const CAP: u64 = 512 * 1024 * 1024;
        assert!(
            super::apply_tree_memory_cap(CAP).expect("arm cap") >= 1,
            "at least our job must have been capped"
        );
        assert_eq!(super::tree_memory_cap_bytes(), CAP);
        let capped = super::retained_job_commit_caps();
        assert!(
            capped.iter().all(|&c| c == CAP),
            "all jobs capped: {capped:?}"
        );
        assert_eq!(capped.len(), before.len(), "arming adds no jobs");

        // The sticky cap covers children assigned AFTER arming.
        let mut second = std::process::Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ping 2");
        super::assign_child(second.id()).expect("assign second");
        let after = super::retained_job_commit_caps();
        assert_eq!(after.len(), capped.len() + 1, "exactly one new job");
        assert!(
            after.iter().all(|&c| c == CAP),
            "new job born capped: {after:?}"
        );

        // Zero is refused (it would fail every allocation in the job).
        assert!(super::apply_tree_memory_cap(0).is_err());

        let _ = first.kill();
        let _ = second.kill();
        let _ = first.wait();
        let _ = second.wait();
        super::reset_tree_memory_cap_for_test();
    }
}
