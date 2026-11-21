//! Windows enforcement-path tests for the M2 governor (ADR-035 §6): the
//! winjob seam is EXERCISED FOR REAL here — the policy inputs are mocked
//! (deterministic verdicts, no dependency on machine load) but the cap
//! lands on actual kernel job objects, is read back through
//! `QueryInformationJobObject`, and the final test proves the armed cap
//! BITES on a real (bounded, 768 MiB-attempt) allocation: the capped
//! child cannot allocate past the cap while the uncapped control can.
//! Nothing here can freeze the machine — the cap IS the mechanism that
//! prevents exactly that, and the allocation attempt is small.

#![cfg(windows)]

use std::io;
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use modelswarm_resource::enforce::WinJobEnforcer;
use modelswarm_resource::governor::{AdmissionRequest, ResourceGovernor};
use modelswarm_resource::source::{ProcSample, SystemMemory, TreeSnapshot};
use modelswarm_resource::{GpuLive, MockSource, ResourceSampler};

const MB: u64 = 1_000_000;

/// Both tests mutate the process-global winjob state (retained jobs +
/// the remembered cap), so they serialize — same discipline as the
/// winjob crate's own `job_test_lock`.
fn enforcement_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn tree_with_working_set(ws: u64) -> TreeSnapshot {
    TreeSnapshot {
        procs: vec![ProcSample {
            pid: 1,
            cpu_time: Duration::ZERO,
            working_set: Some(ws),
        }],
    }
}

/// A deterministic one-evaluate machine: total/used RAM, tree WS, no GPU.
fn mocked_governor(total_mb: u64, used_mb: u64, tree_ws_mb: u64) -> ResourceGovernor {
    let t0 = Instant::now();
    let mk_tree = || tree_with_working_set(tree_ws_mb * MB);
    let mut src = MockSource::new(
        vec![t0, t0 + Duration::from_secs(1)],
        vec![Ok(mk_tree()), Ok(mk_tree())],
    );
    src.memory = Some(SystemMemory {
        total_bytes: total_mb * MB,
        available_bytes: (total_mb - used_mb) * MB,
    });
    src.gpu = Some(GpuLive {
        utilization_percent: None,
        vram_used_bytes: None,
    });
    ResourceGovernor::new(
        ResourceSampler::new(Box::new(src)),
        Box::new(WinJobEnforcer),
    )
}

/// The governor's Admit arms the cap on the REAL winjob job objects:
/// kernel-level readback (`retained_job_commit_caps`), remembered value
/// (`tree_memory_cap_bytes`), and exact cap arithmetic
/// (ceiling - outside-tree usage) all agree.
#[test]
fn governor_admit_arms_the_real_winjob_seam() {
    let _guard = enforcement_test_lock();
    modelswarm_winjob::reset_tree_memory_cap_for_test();

    // A supervised child exists first (the serving-sidecar shape).
    let mut child = Command::new("ping")
        .args(["-n", "60", "127.0.0.1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ping");
    modelswarm_winjob::assign_child(child.id()).expect("assign child");

    // 8 GB total, 2 GB used, 0.5 GB tree WS: ceiling 5.6 GB, cap =
    // 5.6 GB - 1.5 GB outside = 4.1 GB; +1 GB weights projects 3 GB.
    let mut gov = mocked_governor(8_000, 2_000, 500);
    let v = gov.evaluate(&AdmissionRequest {
        added_weights_bytes: 1_000 * MB,
        added_kv_bytes: None,
        added_copy_lands_in_vram: false,
        vram_total_bytes: None,
        arm_tree_commit_cap: true,
    });
    assert!(v.admitted(), "detail: {}", v.detail_line());
    assert!(v.enforcement.armed(), "record: {:?}", v.enforcement);
    assert_eq!(
        v.enforcement.label(),
        "winjob:JOB_OBJECT_LIMIT_PROCESS_MEMORY"
    );

    // Kernel truth, not bookkeeping: the retained job carries the cap.
    // The kernel may round the limit DOWN to its own granularity (a
    // 4_100_000_000 request read back as 4_099_997_696 on this
    // machine) — a strictly more restrictive bound, so the readback
    // asserts at most one page of downward slack and never an increase.
    assert_eq!(modelswarm_winjob::tree_memory_cap_bytes(), 4_100 * MB);
    let caps = modelswarm_winjob::retained_job_commit_caps();
    assert!(
        caps.iter()
            .all(|&c| (4_100 * MB - 4096..=4_100 * MB).contains(&c)),
        "every retained job capped (kernel may round down one page): {caps:?}"
    );

    let _ = child.kill();
    let _ = child.wait();
    modelswarm_winjob::reset_tree_memory_cap_for_test();
}

/// The honest memory-exhaustion bite (M2 exit criterion: exhaustion
/// cannot freeze the machine). A mocked tight machine arms a 450 MB cap
/// BEFORE the child exists; a PowerShell child assigned afterwards is
/// BORN capped and its 768 MiB NATIVE commit
/// (`Marshal::AllocHGlobal`) fails with OutOfMemoryException — the
/// script reports CAP_BIT — while the uncapped control run reports
/// ALLOCATED. The 768 MiB attempt is bounded and safe by construction:
/// the cap rejecting it is the entire point, and even uncapped the
/// transient commit is small.
///
/// Native-commit note (found while writing this test): the job cap
/// bites on COMMIT CHARGE — native allocations (`AllocHGlobal`,
/// malloc/VirtualAlloc: the llama.cpp engine's allocation class) —
/// while freshly-created .NET managed arrays commit lazily on first
/// touch and can slip under the cap until written. The protected class
/// (native engine code) is exactly the class that commits eagerly.
#[test]
fn armed_cap_bites_on_a_real_native_commit() {
    let _guard = enforcement_test_lock();
    modelswarm_winjob::reset_tree_memory_cap_for_test();

    // Arm first: 1 GB total, 300 MB used, 50 MB tree WS => ceiling
    // 700 MB, cap = 700 MB - 250 MB = 450 MB; +200 MB weights admits.
    let mut gov = mocked_governor(1_000, 300, 50);
    let v = gov.evaluate(&AdmissionRequest {
        added_weights_bytes: 200 * MB,
        added_kv_bytes: None,
        added_copy_lands_in_vram: false,
        vram_total_bytes: None,
        arm_tree_commit_cap: true,
    });
    assert!(v.admitted());
    assert_eq!(modelswarm_winjob::tree_memory_cap_bytes(), 450 * MB);

    // Sleep first so the assign below lands before the allocation; then
    // try to COMMIT 768 MiB natively and report which way it went.
    let script = "Start-Sleep -Milliseconds 1500; \
                  try { $h=[Runtime.InteropServices.Marshal]::AllocHGlobal(805306368); 'ALLOCATED' } \
                  catch { 'CAP_BIT' }";
    let spawn_ps = || {
        Command::new("powershell")
            .args(["-NoProfile", "-Command", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn powershell")
    };

    // Capped run: assigned AFTER arming, so born with the 450 MB cap.
    let capped = spawn_ps();
    modelswarm_winjob::assign_child(capped.id()).expect("assign capped child");
    let capped_out = wait_and_read(capped).expect("capped run terminates");
    assert_eq!(
        capped_out.trim(),
        "CAP_BIT",
        "the 768 MiB native commit must fail under the 450 MB cap"
    );

    modelswarm_winjob::reset_tree_memory_cap_for_test();
    // Control run: same script, never assigned to a job — the commit
    // succeeds, proving the capped outcome was the cap and nothing else.
    let control = spawn_ps();
    let control_out = wait_and_read(control).expect("control run terminates");
    assert_eq!(
        control_out.trim(),
        "ALLOCATED",
        "uncapped control must commit fine"
    );
}

/// Waits for the child (bounded at 90 s so a pathological hang fails the
/// test instead of hanging CI) and returns its stdout.
fn wait_and_read(mut child: std::process::Child) -> io::Result<String> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match child.try_wait()? {
            Some(_status) => {
                let out = child.wait_with_output()?;
                return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
            }
            None => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io::Error::other("child did not terminate within 90 s"));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}
