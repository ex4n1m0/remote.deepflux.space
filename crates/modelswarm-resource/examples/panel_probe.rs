//! Panel-rate probe: prints five samples at the intended 1 Hz UI cadence.
//! Run with `cargo run -p modelswarm-resource --example panel_probe`.
//! This is the usage sketch for the desktop monitor panel (Windows
//! Product): construct once, poll `sample()` once per second, read fields
//! defensively (`Option` = "n/a", never a placeholder number).

use modelswarm_resource::{ProcessScope, ResourceSampler};

fn main() {
    let hw = modelswarm_resource::HardwareProfile::detect();
    println!(
        "static profile: {} logical cpus, {} MiB ram, gpu: {}",
        hw.logical_cpus,
        hw.total_ram_bytes / (1024 * 1024),
        hw.gpu
            .as_ref()
            .map(|g| format!(
                "{} ({} MiB vram)",
                g.name,
                g.total_vram_bytes / (1024 * 1024)
            ))
            .unwrap_or_else(|| "n/a (inject via with_gpu from the engine device listing)".into())
    );
    let mut sampler = ResourceSampler::platform(ProcessScope::CurrentTree);
    for i in 0..5 {
        let s = sampler.sample();
        println!(
            "tick {i}: cpu={:>5.1}%  ram={:>5.1}% ({:>5} MiB)  ws={:>5} MiB  gpu={:>5} vram={:>5} MiB",
            s.process_tree_cpu_percent.unwrap_or(f64::NAN),
            s.system_ram_used_percent.unwrap_or(f64::NAN),
            s.system_ram_used_bytes.unwrap_or(0) / (1024 * 1024),
            s.process_tree_working_set_bytes.unwrap_or(0) / (1024 * 1024),
            match s.gpu_utilization_percent {
                Some(v) => format!("{v:>5.1}%"),
                None => "  n/a".into(),
            },
            s.gpu_vram_used_bytes.unwrap_or(0) / (1024 * 1024),
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
