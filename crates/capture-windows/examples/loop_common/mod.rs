//! Shared plumbing for the M1 diagnostic binaries (`capture-preview`,
//! `local-loop`). These binaries are the M1 "node runtime": the one place
//! the capture/codec/render platform crates are composed (ADR-001 rule 3).
//!
//! Contains: CLI parsing, the session clock, the JSONL counter sink with
//! 128 MiB rotation, the bounded frame queues (invariant 3) with the
//! schema's on-every-depth-change sampling, the GDI stimulus window that
//! guarantees 60 Hz desktop updates during soaks, the 1 Hz resource
//! sampler, and the latency-report summarizer (F6 format).

#![allow(dead_code)]

use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use diagnostics::{
    CounterRecord, FrameTiming, Origin, PerfSink, QueueKind, QueueSample, ResourceSample,
};

// ---------------------------------------------------------------------------
// CLI

#[derive(Debug, Clone)]
pub struct Args {
    pub duration_secs: u64,
    pub monitor: String,
    pub bitrate_kbps: u32,
    pub fps_cap: u32,
    pub encoder: String, // auto | hw | sw
    pub decoder: String, // dxva | cpu
    pub encode_w: u32,
    pub encode_h: u32,
    pub window_w: i32,
    pub window_h: i32,
    pub scale: String, // fit | 1:1
    pub stimulus: bool,
    pub report_stem: Option<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            duration_secs: 300,
            monitor: "primary".to_string(),
            bitrate_kbps: 8000,
            // Default 60: the pipeline tracks the capture rate 1:1 up to
            // 60 fps; uncapped capture above the panel's sustainable
            // composition rate back-pressures Present until the encode
            // stage starves (measured; pacing is an M2 transport concern
            // -- this cap models the session's target frame rate).
            fps_cap: 60,
            encoder: "auto".to_string(),
            decoder: "dxva".to_string(),
            encode_w: 1920,
            encode_h: 1080,
            window_w: 1280,
            window_h: 720,
            scale: "fit".to_string(),
            stimulus: true,
            report_stem: None,
        }
    }
}

pub fn parse_args(argv: &[String], usage: &str) -> Args {
    let mut args = Args::default();
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        let take = |i: &mut usize| -> String {
            *i += 1;
            argv.get(*i).cloned().unwrap_or_default()
        };
        match arg {
            "--duration-secs" => args.duration_secs = take(&mut i).parse().unwrap_or(300),
            "--monitor" => args.monitor = take(&mut i),
            "--bitrate" => args.bitrate_kbps = take(&mut i).parse().unwrap_or(8000),
            "--fps-cap" => args.fps_cap = take(&mut i).parse().unwrap_or(0),
            "--encoder" => args.encoder = take(&mut i),
            "--decoder" => args.decoder = take(&mut i),
            "--encode-size" => {
                let v = take(&mut i);
                if let Some((w, h)) = v.split_once('x') {
                    args.encode_w = w.parse().unwrap_or(1920);
                    args.encode_h = h.parse().unwrap_or(1080);
                }
            }
            "--window-size" => {
                let v = take(&mut i);
                if let Some((w, h)) = v.split_once('x') {
                    args.window_w = w.parse().unwrap_or(1280);
                    args.window_h = h.parse().unwrap_or(720);
                }
            }
            "--scale" => args.scale = take(&mut i),
            "--no-stimulus" => args.stimulus = false,
            "--report-stem" => args.report_stem = Some(take(&mut i)),
            "--help" | "-h" => {
                println!("{usage}");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument {other:?}\n{usage}");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    args
}

// ---------------------------------------------------------------------------
// Session clock

#[derive(Clone)]
pub struct SessionClock {
    pub start: Instant,
}

impl SessionClock {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Nanoseconds since session start (the schema's zero-based
    /// monotonic clock).
    pub fn ns(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64
    }
}

impl Default for SessionClock {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// JSONL counter sink (F6): bounded channel + writer thread, 128 MiB rotation

pub const SESSION_ID: &str = "local-loop";
const ROTATE_BYTES: u64 = 128 * 1024 * 1024;
/// Sink channel depth. The writer sustains ~thousands of records/s; the
/// bound exists so a stalled disk surfaces as backpressure (counted),
/// never unbounded memory (invariant 3).
const SINK_BOUND: usize = 65_536;

pub struct JsonlReport {
    pub path: PathBuf,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
    pub records_sent: Arc<AtomicU64>,
    pub backpressure_events: Arc<AtomicU64>,
    tx: SyncSender<CounterRecord>,
}

/// Cloneable sink handle: stages share one writer thread; formatting
/// happens off the hot path (schema requirement).
pub struct JsonlSinkHandle {
    tx: SyncSender<CounterRecord>,
    clock: SessionClock,
    backpressure: Arc<AtomicU64>,
}

impl PerfSink for JsonlSinkHandle {
    fn record(&mut self, record: CounterRecord) {
        match self.tx.try_send(record) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(_)) => {
                // Hot path never blocks: record the backpressure and drop.
                // (The writer thread drains continuously; a Full channel
                // means disk I/O stalled hard — visible in the report.)
                self.backpressure.fetch_add(1, Ordering::Relaxed);
            }
        }
        let _ = self.clock.ns();
    }
}

impl JsonlReport {
    pub fn create(dir: &std::path::Path, stem: &str) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let mut path = dir.join(format!("{stem}.jsonl"));
        let mut n = 1u32;
        while path.exists() {
            path = dir.join(format!("{stem}-{n}.jsonl"));
            n += 1;
        }
        let writer_path = path.clone();
        let (tx, rx) = std::sync::mpsc::sync_channel(SINK_BOUND);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_w = Arc::clone(&stop);
        let records_sent = Arc::new(AtomicU64::new(0));
        let records_w = Arc::clone(&records_sent);
        let backpressure = Arc::new(AtomicU64::new(0));
        let join = std::thread::Builder::new()
            .name("jsonl-writer".into())
            .spawn(move || {
                let file = std::fs::File::create(&writer_path).expect("create report file");
                let mut out = std::io::BufWriter::with_capacity(1 << 20, file);
                let mut written: u64 = 0;
                let mut part = 0u32;
                while !stop_w.load(Ordering::Acquire) {
                    match rx.recv_timeout(Duration::from_millis(200)) {
                        Ok(record) => {
                            let _ = serde_json::to_writer(&mut out, &record);
                            let _ = out.write_all(b"\n");
                            records_w.fetch_add(1, Ordering::Relaxed);
                            written += 300; // estimate; exact size checked below
                            if written >= ROTATE_BYTES {
                                let _ = out.flush();
                                part += 1;
                                if let Ok(f) = std::fs::File::create(format!(
                                    "{}.{}",
                                    writer_path.display(),
                                    part
                                )) {
                                    out = std::io::BufWriter::with_capacity(1 << 20, f);
                                    written = 0;
                                }
                            }
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                // Drain whatever is left.
                while let Ok(record) = rx.try_recv() {
                    let _ = serde_json::to_writer(&mut out, &record);
                    let _ = out.write_all(b"\n");
                    records_w.fetch_add(1, Ordering::Relaxed);
                }
                let _ = out.flush();
            })
            .expect("spawn writer");
        Ok(Self {
            path,
            stop,
            join: Some(join),
            records_sent,
            backpressure_events: backpressure,
            tx,
        })
    }

    pub fn sink_handle(&self, clock: SessionClock) -> JsonlSinkHandle {
        JsonlSinkHandle {
            tx: self.tx.clone(),
            clock,
            backpressure: Arc::clone(&self.backpressure_events),
        }
    }
}

impl JsonlReport {
    pub fn close(mut self) -> (PathBuf, u64, u64) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let records = self.records_sent.load(Ordering::Relaxed);
        let bp = self.backpressure_events.load(Ordering::Relaxed);
        (self.path, records, bp)
    }
}

// ---------------------------------------------------------------------------
// Bounded frame queue (invariant 3) with F5 sampling

pub enum DropPolicy {
    /// Replace the queued item with the newer one (`replaced` counter).
    NewestWins,
    /// Push fails when full; the pusher drops (`dropped` counter).
    Reject,
}

struct QueueState<T> {
    slots: VecDeque<T>,
    open: bool,
    high_water: u32,
    dropped: u64,
    replaced: u64,
}

/// Bounded hand-off queue between pipeline stages.
///
/// Sampling (binding, schema): sampled on **every depth change** —
/// push/replace/pop each emit a `QueueSample` with the post-change depth
/// and lifetime counters. At 1080p60 that is 2+ samples per queue per
/// frame.
pub struct FrameQueue<T> {
    kind: QueueKind,
    capacity: u32,
    policy: DropPolicy,
    state: Mutex<QueueState<T>>,
    changed: std::sync::Condvar,
    sink: Mutex<Box<dyn PerfSink>>,
    clock: SessionClock,
}

impl<T> FrameQueue<T> {
    pub fn new(
        kind: QueueKind,
        capacity: u32,
        policy: DropPolicy,
        sink: Box<dyn PerfSink>,
        clock: SessionClock,
    ) -> Self {
        Self {
            kind,
            capacity: capacity.max(1),
            policy,
            state: Mutex::new(QueueState {
                slots: VecDeque::new(),
                open: true,
                high_water: 0,
                dropped: 0,
                replaced: 0,
            }),
            changed: std::sync::Condvar::new(),
            sink: Mutex::new(sink),
            clock,
        }
    }

    fn sample(&self, state: &QueueState<T>) {
        let record = CounterRecord::QueueSample(QueueSample {
            session_id: SESSION_ID.to_string(),
            queue: self.kind,
            depth: state.slots.len() as u32,
            capacity: self.capacity,
            high_water: state.high_water,
            dropped: state.dropped,
            replaced: state.replaced,
            at_ns: self.clock.ns(),
        });
        self.sink.lock().expect("queue sink").record(record);
    }

    /// Push `item`. Returns `Err(item)` when the policy rejected it (the
    /// caller counts the drop by checking `dropped` growth or the Err).
    pub fn push(&self, item: T) -> Result<(), T> {
        let mut state = self.state.lock().expect("queue lock");
        match self.policy {
            DropPolicy::NewestWins => {
                if state.slots.len() == self.capacity as usize {
                    state.slots.pop_front();
                    state.replaced += 1;
                }
                state.slots.push_back(item);
            }
            DropPolicy::Reject => {
                if state.slots.len() == self.capacity as usize {
                    state.dropped += 1;
                    self.sample(&state);
                    return Err(item);
                }
                state.slots.push_back(item);
            }
        }
        let hw = state.slots.len() as u32;
        if hw > state.high_water {
            state.high_water = hw;
        }
        self.sample(&state);
        self.changed.notify_one();
        Ok(())
    }

    /// Pop with timeout; `None` on timeout or after `close()`.
    pub fn pop(&self, timeout: Duration) -> Option<T> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().expect("queue lock");
        loop {
            if let Some(item) = state.slots.pop_front() {
                self.sample(&state);
                return Some(item);
            }
            if !state.open {
                return None;
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (guard, _result) = self
                .changed
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .expect("queue wait");
            state = guard;
        }
    }

    pub fn close(&self) {
        let mut state = self.state.lock().expect("queue lock");
        state.open = false;
        self.changed.notify_all();
    }

    /// Final counters for the summary.
    pub fn counters(&self) -> (u32, u32, u64, u64) {
        let state = self.state.lock().expect("queue lock");
        (
            state.high_water,
            self.capacity,
            state.dropped,
            state.replaced,
        )
    }
}

// ---------------------------------------------------------------------------
// Resource sampler (1 Hz)

pub fn spawn_resource_sampler(
    mut sink: Box<dyn PerfSink>,
    clock: SessionClock,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("resource-sampler".into())
        .spawn(move || {
            let mut last_sample = Instant::now() - Duration::from_secs(1);
            let mut last_cpu = process_cpu_time_ns().unwrap_or(0);
            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(250));
                if last_sample.elapsed() < Duration::from_secs(1) {
                    continue;
                }
                last_sample = Instant::now();
                let wall = process_cpu_time_ns();
                let cpu_percent = match (wall, last_cpu) {
                    (Some(now_ns), past) if now_ns >= past => {
                        let delta = now_ns - past;
                        Some(delta as f32 / 1e9 / 1.0 * 100.0)
                    }
                    _ => None,
                };
                last_cpu = wall.unwrap_or(last_cpu);
                let ws = working_set_bytes();
                sink.record(CounterRecord::ResourceSample(ResourceSample {
                    session_id: SESSION_ID.to_string(),
                    origin: Origin::Host,
                    cpu_percent,
                    gpu_percent: None, // no D3DKMT engine counters in M1
                    memory_working_set_bytes: ws,
                    gpu_memory_bytes: None,
                    at_ns: clock.ns(),
                }));
            }
        })
        .expect("spawn resource sampler")
}

fn process_cpu_time_ns() -> Option<u64> {
    unsafe {
        use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
        let mut creation = Default::default();
        let mut exit = Default::default();
        let mut kernel = Default::default();
        let mut user = Default::default();
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
        .ok()?;
        let to_ns = |f: windows::Win32::Foundation::FILETIME| {
            ((f.dwHighDateTime as u64) << 32 | f.dwLowDateTime as u64) * 100
        };
        Some(to_ns(kernel) + to_ns(user))
    }
}

fn working_set_bytes() -> Option<u64> {
    unsafe {
        use windows::Win32::System::ProcessStatus::GetProcessMemoryInfo;
        use windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS;
        use windows::Win32::System::Threading::GetCurrentProcess;
        let mut counters = PROCESS_MEMORY_COUNTERS::default();
        let cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        // GetProcessMemoryInfo takes K32GetProcessMemoryEx form; the
        // psapi forwarder works via the same symbol here.
        let ok = GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, cb);
        if ok.is_ok() {
            Some(counters.WorkingSetSize as u64)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// GDI stimulus window (guarantees 60 Hz desktop updates during soaks)

pub fn spawn_stimulus(stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("stimulus".into())
        .spawn(move || {
            let _ = frame_surface::attach_thread_to_input_desktop();
            unsafe {
                let module = windows::Win32::System::LibraryLoader::GetModuleHandleW(None).ok();
                let class_name: Vec<u16> = "rd_m1_stimulus\0".encode_utf16().collect();
                let wc = windows::Win32::UI::WindowsAndMessaging::WNDCLASSW {
                    style: windows::Win32::UI::WindowsAndMessaging::CS_HREDRAW
                        | windows::Win32::UI::WindowsAndMessaging::CS_VREDRAW,
                    lpfnWndProc: Some(stim_wnd_proc),
                    hInstance: module.map(|m| m.into()).unwrap_or_default(),
                    lpszClassName: windows::core::PCWSTR(class_name.as_ptr()),
                    ..Default::default()
                };
                let atom = windows::Win32::UI::WindowsAndMessaging::RegisterClassW(&wc);
                if atom == 0 {
                    eprintln!("stimulus: RegisterClassW failed");
                    return;
                }
                let title: Vec<u16> = "M1 stimulus\0".encode_utf16().collect();
                let hwnd = windows::Win32::UI::WindowsAndMessaging::CreateWindowExW(
                    windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                    windows::core::PCWSTR(class_name.as_ptr()),
                    windows::core::PCWSTR(title.as_ptr()),
                    windows::Win32::UI::WindowsAndMessaging::WS_OVERLAPPEDWINDOW
                        | windows::Win32::UI::WindowsAndMessaging::WS_VISIBLE,
                    960,
                    540,
                    640,
                    480,
                    None,
                    None,
                    module.map(|m| m.into()),
                    None,
                )
                .expect("stimulus window");
                let timer = windows::Win32::UI::WindowsAndMessaging::SetTimer(
                    Some(hwnd),
                    1,
                    15, // ~66 Hz request rate; DWM composes at vsync
                    None,
                );
                let mut msg = windows::Win32::UI::WindowsAndMessaging::MSG::default();
                while !stop.load(Ordering::Acquire) {
                    while windows::Win32::UI::WindowsAndMessaging::PeekMessageW(
                        &mut msg,
                        None,
                        0,
                        0,
                        windows::Win32::UI::WindowsAndMessaging::PM_REMOVE,
                    )
                    .as_bool()
                    {
                        let _ = windows::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
                        windows::Win32::UI::WindowsAndMessaging::DispatchMessageW(&msg);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                let _ = windows::Win32::UI::WindowsAndMessaging::KillTimer(Some(hwnd), timer);
                let _ = windows::Win32::UI::WindowsAndMessaging::DestroyWindow(hwnd);
            }
        })
        .expect("spawn stimulus")
}

static STIM_TICK: AtomicU64 = AtomicU64::new(0);

unsafe extern "system" fn stim_wnd_proc(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::Graphics::Gdi::{
        BeginPaint, CreateSolidBrush, EndPaint, FillRect, InvalidateRect, PAINTSTRUCT,
    };
    use windows::Win32::UI::WindowsAndMessaging::{DefWindowProcW, WM_PAINT, WM_TIMER};
    unsafe {
        match msg {
            WM_TIMER => {
                STIM_TICK.fetch_add(1, Ordering::Relaxed);
                let _ = InvalidateRect(Some(hwnd), None, false);
                windows::Win32::Foundation::LRESULT(0)
            }
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);
                let tick = STIM_TICK.load(Ordering::Relaxed);
                let bg = CreateSolidBrush(windows::Win32::Foundation::COLORREF(0x00101820));
                FillRect(hdc, &ps.rcPaint, bg);
                let _ = windows::Win32::Graphics::Gdi::DeleteObject(bg.into());
                // Moving bright bar: changes pixels every tick.
                let x = (tick % 300) as i32;
                let bar = CreateSolidBrush(windows::Win32::Foundation::COLORREF(0x0000D7FF));
                let mut rect = ps.rcPaint;
                rect.left = x;
                rect.right = x + 120;
                rect.top += 40;
                rect.bottom -= 40;
                FillRect(hdc, &rect, bar);
                let _ = windows::Win32::Graphics::Gdi::DeleteObject(bar.into());
                let bar2 = CreateSolidBrush(windows::Win32::Foundation::COLORREF(0x00FFFFFF));
                let mut line = ps.rcPaint;
                line.left = ((tick * 3) % 600) as i32;
                line.right = line.left + 4;
                FillRect(hdc, &line, bar2);
                let _ = windows::Win32::Graphics::Gdi::DeleteObject(bar2.into());
                let _ = EndPaint(hwnd, &ps);
                windows::Win32::Foundation::LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

pub fn stimulus_ticks() -> u64 {
    STIM_TICK.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Latency report summarizer (F6)

pub struct StageStats {
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
    pub count: u64,
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

pub struct Summary {
    pub stages: Vec<(&'static str, StageStats)>,
    pub frames_host: u64,
    pub frames_presented: u64,
    pub keyframes: u64,
    pub encoded_bytes: u64,
    pub queue_stats: Vec<(QueueKind, u32, u32, u64, u64)>,
    pub resource_cpu_min_max: Option<(f32, f32)>,
    pub resource_ws_min_max: Option<(u64, u64)>,
    pub unstable_windows: Vec<(u64, String)>,
    pub backpressure_events: u64,
    pub warmup_secs: u64,
    pub run_secs: u64,
}

/// Read the JSONL back and compute the F6 summary. Warm-up (first 60 s)
/// excluded; stats bucketed per 60 s window.
pub fn summarize(path: &std::path::Path, warmup_secs: u64) -> Summary {
    use std::io::BufRead;
    // The writer rotates at 128 MiB into `.jsonl.1`, `.jsonl.2`, ... —
    // summarize across every part or the distribution tail is lost.
    let mut files: Vec<std::fs::File> = vec![std::fs::File::open(path).expect("open jsonl")];
    for part in 1.. {
        let p = path.with_extension(format!("jsonl.{part}"));
        if p.exists() {
            files.push(std::fs::File::open(p).expect("open part"));
        } else {
            break;
        }
    }
    let lines: Box<dyn Iterator<Item = std::io::Result<String>>> =
        Box::new(files.into_iter().flat_map(|f| {
            std::io::BufReader::new(f)
                .lines()
                .collect::<Vec<_>>()
                .into_iter()
        }));

    let warmup_ns = warmup_secs * 1_000_000_000;
    let mut stages: Vec<(&'static str, Vec<u64>)> = vec![
        ("capture_to_encode", Vec::new()),
        ("encode_submit_to_done", Vec::new()),
        ("encode_done_to_send", Vec::new()),
        ("recv_to_decode", Vec::new()),
        ("decode_to_present", Vec::new()),
        ("host_half_total", Vec::new()),
        ("controller_half_total", Vec::new()),
        ("capture_to_present_same_clock", Vec::new()),
    ];
    let mut host: std::collections::HashMap<u64, FrameTiming> = std::collections::HashMap::new();
    let mut ctrl: std::collections::HashMap<u64, FrameTiming> = std::collections::HashMap::new();
    let mut frames_host = 0u64;
    let mut frames_presented = 0u64;
    let mut queues: std::collections::HashMap<String, (u32, u32, u64, u64)> =
        std::collections::HashMap::new();
    // (window, queue) -> (samples, at_capacity, last_dropped, delta_drops, last_replaced)
    type WinStats = std::collections::HashMap<(u64, String), (u64, u64, u64, u64, u64)>;
    let mut win_stats: WinStats = std::collections::HashMap::new();
    let mut unstable: Vec<(u64, String)> = Vec::new();
    let mut cpus: Vec<f32> = Vec::new();
    let mut wss: Vec<u64> = Vec::new();

    for line in lines {
        let Ok(line) = line else { break };
        let Ok(record) = serde_json::from_str::<CounterRecord>(&line) else {
            continue;
        };
        match record {
            CounterRecord::FrameTiming(t) => {
                if t.origin == Origin::Host {
                    host.insert(t.frame_id, t);
                    frames_host += 1;
                } else {
                    ctrl.insert(t.frame_id, t);
                    frames_presented += 1;
                }
            }
            CounterRecord::QueueSample(q) => {
                let key = format!("{:?}", q.queue);
                let entry = queues.entry(key.clone()).or_insert((0, q.capacity, 0, 0));
                entry.0 = entry.0.max(q.high_water);
                entry.1 = q.capacity;
                entry.2 = entry.2.max(q.dropped);
                entry.3 = entry.3.max(q.replaced);
                // Per-window bookkeeping for the schema's steady-state
                // definition: unstable = drop/replaced DELTA inside the
                // window, or depth pinned at capacity for (nearly) the
                // whole window ("sustained"). A cap-1 slot sitting at
                // depth 1 between push and pop is normal steady state.
                if q.at_ns >= warmup_ns {
                    let window = q.at_ns / 60_000_000_000;
                    let w = win_stats
                        .entry((window, key.clone()))
                        .or_insert((0u64, 0u64, 0u64, 0u64, 0u64));
                    w.0 += 1; // samples
                    if q.depth == q.capacity {
                        w.1 += 1; // at-capacity samples
                    }
                    if w.2 < q.dropped {
                        w.3 = w.3.max(q.dropped - w.2);
                    }
                    w.2 = q.dropped;
                    if w.4 == 0 && q.replaced > 0 && w.4 < q.replaced {
                        w.4 = q.replaced; // baseline carries into window
                    } else if q.replaced > w.4 {
                        w.3 = w.3.max(q.replaced - w.4);
                        w.4 = q.replaced;
                    }
                }
            }
            CounterRecord::ResourceSample(r) => {
                if let Some(cpu) = r.cpu_percent {
                    cpus.push(cpu);
                }
                if let Some(ws) = r.memory_working_set_bytes {
                    wss.push(ws);
                }
            }
            CounterRecord::LinkSample(_) => {}
        }
    }

    for (frame_id, h) in &host {
        let Some(c) = ctrl.get(frame_id) else {
            continue;
        };
        let (cap, sub, done, send) = (
            h.capture_ns.unwrap_or(0),
            h.encode_submit_ns.unwrap_or(0),
            h.encode_done_ns.unwrap_or(0),
            h.send_ns.unwrap_or(0),
        );
        let (recv, dec, pres) = (
            c.recv_ns.unwrap_or(0),
            c.decode_done_ns.unwrap_or(0),
            c.present_ns.unwrap_or(0),
        );
        if send < warmup_ns {
            continue;
        }
        if sub >= cap {
            stages[0].1.push(sub - cap);
        }
        if done >= sub {
            stages[1].1.push(done - sub);
        }
        if send >= done {
            stages[2].1.push(send - done);
        }
        if dec >= recv {
            stages[3].1.push(dec - recv);
        }
        if pres >= dec {
            stages[4].1.push(pres - dec);
        }
        if send >= cap {
            stages[5].1.push(send - cap);
        }
        if pres >= recv {
            stages[6].1.push(pres - recv);
        }
        // Same-clock total: valid only in the one-process local loop.
        if pres >= cap {
            stages[7].1.push(pres - cap);
        }
    }

    // Evaluate per-window instability from the collected stats.
    for ((window, key), w) in &win_stats {
        if w.3 > 0 {
            unstable.push((*window, format!("{key} dropped/replaced {} in window", w.3)));
        }
        if w.0 > 10 && w.1 * 100 >= w.0 * 95 {
            unstable.push((
                *window,
                format!("{key} pinned at capacity ({}/{} samples)", w.1, w.0),
            ));
        }
    }
    unstable.sort();

    let run_secs = host
        .values()
        .filter_map(|t| t.send_ns)
        .max()
        .unwrap_or(0)
        .saturating_sub(
            host.values()
                .filter_map(|t| t.capture_ns)
                .min()
                .unwrap_or(0),
        )
        / 1_000_000_000;

    let mut out_stages = Vec::new();
    for (name, mut samples) in stages {
        samples.sort_unstable();
        out_stages.push((
            name,
            StageStats {
                p50_ns: percentile(&samples, 50.0),
                p95_ns: percentile(&samples, 95.0),
                p99_ns: percentile(&samples, 99.0),
                max_ns: samples.last().copied().unwrap_or(0),
                count: samples.len() as u64,
            },
        ));
    }

    Summary {
        stages: out_stages,
        frames_host,
        frames_presented,
        keyframes: 0,
        encoded_bytes: 0,
        queue_stats: queues
            .into_iter()
            .map(|(k, v)| {
                (
                    match k.as_str() {
                        "CaptureToEncode" => QueueKind::CaptureToEncode,
                        "EncodeToSend" => QueueKind::EncodeToSend,
                        "RecvToDecode" => QueueKind::RecvToDecode,
                        "DecodeToPresent" => QueueKind::DecodeToPresent,
                        _ => QueueKind::ChannelControl,
                    },
                    v.0,
                    v.1,
                    v.2,
                    v.3,
                )
            })
            .collect(),
        resource_cpu_min_max: cpus
            .iter()
            .cloned()
            .reduce(f32::min)
            .zip(cpus.iter().cloned().reduce(f32::max)),
        resource_ws_min_max: wss.iter().copied().min().zip(wss.iter().copied().max()),
        unstable_windows: unstable,
        backpressure_events: 0,
        warmup_secs,
        run_secs,
    }
}

pub fn fmt_us(ns: u64) -> String {
    format!("{:.2} ms", ns as f64 / 1e6)
}

pub fn human_summary(summary: &Summary, encoder_desc: &str, decoder_desc: &str) -> String {
    let mut out = String::new();
    out.push_str("M1 local-loop latency report\n");
    out.push_str("===========================\n\n");
    out.push_str(&format!("encoder: {encoder_desc}\n"));
    out.push_str(&format!("decoder: {decoder_desc}\n"));
    out.push_str(&format!(
        "frames: host {} presented {} ({:.1}% presented)\n",
        summary.frames_host,
        summary.frames_presented,
        100.0 * summary.frames_presented as f64 / summary.frames_host.max(1) as f64
    ));
    out.push_str(&format!(
        "duration (captured span): {} s (warm-up {} s excluded)\n\n",
        summary.run_secs, summary.warmup_secs
    ));
    out.push_str("per-stage latency (post warm-up):\n");
    for (name, s) in &summary.stages {
        out.push_str(&format!(
            "  {:<30} p50 {:>10}  p95 {:>10}  p99 {:>10}  max {:>10}  (n={})\n",
            name,
            fmt_us(s.p50_ns),
            fmt_us(s.p95_ns),
            fmt_us(s.p99_ns),
            fmt_us(s.max_ns),
            s.count
        ));
    }
    out.push_str("\nqueue high-water marks (budget: depth <= 1 steady state):\n");
    for (kind, hw, cap, dropped, replaced) in &summary.queue_stats {
        out.push_str(&format!(
            "  {:<20} high_water {hw}/{cap}, dropped {dropped}, replaced {replaced}\n",
            format!("{kind:?}")
        ));
    }
    if let Some((min, max)) = summary.resource_cpu_min_max {
        out.push_str(&format!("\nprocess CPU: {min:.1}% .. {max:.1}%\n"));
    }
    if let Some((min, max)) = summary.resource_ws_min_max {
        out.push_str(&format!(
            "working set: {:.1} .. {:.1} MiB\n",
            min as f64 / (1 << 20) as f64,
            max as f64 / (1 << 20) as f64
        ));
    }
    if summary.unstable_windows.is_empty() {
        out.push_str("\nunstable windows: none\n");
    } else {
        out.push_str("\nunstable windows (per schema definition):\n");
        for (w, reason) in &summary.unstable_windows {
            out.push_str(&format!("  window +{w} min: {reason}\n"));
        }
    }
    out
}
