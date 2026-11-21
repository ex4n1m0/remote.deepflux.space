//! Real-system smoke test for the Windows sampler (the READ, not the math:
//! the math is pinned by unit tests that run on every OS).
//!
//! Assertions are range/sanity checks only — nothing here can flake on
//! machine load. Fields that are legitimately absent (GPU on a machine
//! without PDH GPU counters) must come back `None`, never out of range.

#![cfg(windows)]

use modelswarm_resource::{ProcessScope, ResourceSampler};

#[test]
fn windows_live_sampler_smoke() {
    let mut sampler = ResourceSampler::platform(ProcessScope::CurrentTree);

    // First poll right away (also exercises "no zero-division on short
    // intervals"), then one after a real interval: two PDH collects and
    // two tree snapshots 400 ms apart.
    let _first = sampler.sample();
    std::thread::sleep(std::time::Duration::from_millis(400));
    let s = sampler.sample();

    // CPU: guaranteed present on Windows (two successful snapshots with a
    // positive wall interval), normalized and clamped.
    let cpu = s.process_tree_cpu_percent.expect("cpu percent on windows");
    assert!((0.0..=100.0).contains(&cpu), "cpu out of range: {cpu}");

    // RAM: GlobalMemoryStatusEx must succeed; > 1 GiB total on any
    // machine able to run this build.
    let ram = s.system_ram_used_percent.expect("memory status on windows");
    assert!(
        (0.0..=100.0).contains(&ram),
        "ram percent out of range: {ram}"
    );
    assert!(
        s.system_ram_total_bytes.unwrap_or(0) > (1 << 30),
        "implausible total ram: {:?}",
        s.system_ram_total_bytes
    );
    assert!(
        s.system_ram_used_bytes.unwrap_or(0) <= s.system_ram_total_bytes.unwrap_or(0),
        "used > total"
    );

    // Working set: this test process itself is in the tree.
    assert!(
        s.process_tree_working_set_bytes.unwrap_or(0) > 0,
        "own working set must be reported"
    );

    // GPU: honestly None or a sane value — never wrong-looking numbers.
    if let Some(util) = s.gpu_utilization_percent {
        assert!(
            (0.0..=100.0).contains(&util),
            "gpu util out of range: {util}"
        );
    }
    if let Some(vram) = s.gpu_vram_used_bytes {
        assert!(vram < (1 << 40), "implausible vram: {vram}"); // < 1 TiB
    }
    // Both None only when PDH is wholly unavailable — on a normal Win10+
    // machine at least one GPU field should have been readable.
    assert!(
        s.gpu_utilization_percent.is_some() || s.gpu_vram_used_bytes.is_some(),
        "expected at least one live GPU field on this machine: {s:?}"
    );
}

#[test]
fn windows_scoped_roots_cover_spawned_children() {
    use std::process::Stdio;
    // Spawn a short-lived child and verify it is counted inside the tree
    // (pid is our direct child => descendant).
    let mut child = std::process::Command::new("ping")
        .args(["-n", "2", "127.0.0.1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ping");
    let child_pid = child.id();

    let source = modelswarm_resource::windows::WindowsSource::new(ProcessScope::CurrentTree);
    let tree =
        modelswarm_resource::SampleSource::process_tree(&source).expect("process tree snapshot");
    let own = std::process::id();
    assert!(
        tree.procs.iter().any(|p| p.pid == own),
        "own pid must be in tree"
    );
    assert!(
        tree.procs.iter().any(|p| p.pid == child_pid),
        "spawned child must be in tree"
    );
    let _ = child.wait();
}
