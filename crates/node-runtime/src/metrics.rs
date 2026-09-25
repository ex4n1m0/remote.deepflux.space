//! Rig metrics support: schema-exact JSONL counter sink (F6), 1 Hz
//! resource sampler, and the bounded pipeline hand-off queues with the
//! F5 on-every-depth-change sampling.
//!
//! This is the M2 evolution of the M1 `loop_common` plumbing, now
//! session-scoped (every record carries the *protocol* session id — the
//! rig updates the shared [`SessionSlot`] on `SessionEstablished`, so a
//! reconnect never aliases two sessions' frames) and reusable from the
//! library (the M1 version lives inside a crate example).

use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use diagnostics::{CounterRecord, Origin, PerfSink, QueueKind, QueueSample, ResourceSample};

/// Shared current-session id (controller-minted protocol id, or a
/// pre-session placeholder). Updated by the node observer; read by every
/// recording site.
pub struct SessionSlot {
    id: Mutex<String>,
}

impl SessionSlot {
    pub fn new(initial: &str) -> Self {
        Self {
            id: Mutex::new(initial.to_owned()),
        }
    }

    pub fn set(&self, id: &str) {
        *self.id.lock().expect("session slot") = id.to_owned();
    }

    pub fn get(&self) -> String {
        self.id.lock().expect("session slot").clone()
    }
}

/// Sink channel depth: the writer thread sustains thousands of records/s;
/// the bound turns a stalled disk into counted backpressure instead of
/// unbounded memory (invariant 3).
const SINK_BOUND: usize = 65_536;

/// Bounded-channel JSONL sink with a dedicated writer thread. Formatting
/// happens off the hot path (schema requirement).
pub struct JsonlReport {
    pub path: PathBuf,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
    pub records_written: Arc<AtomicU64>,
    pub backpressure_events: Arc<AtomicU64>,
    tx: SyncSender<CounterRecord>,
}

pub struct JsonlSinkHandle {
    tx: SyncSender<CounterRecord>,
    session: Arc<SessionSlot>,
    backpressure: Arc<AtomicU64>,
}

impl JsonlSinkHandle {
    /// Current session id for scoping records.
    pub fn session_id(&self) -> String {
        self.session.get()
    }
}

impl PerfSink for JsonlSinkHandle {
    fn record(&mut self, record: CounterRecord) {
        match self.tx.try_send(record) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(_)) => {
                // Never block the measured stage; visible in the summary.
                self.backpressure.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl JsonlReport {
    /// M6 soak F79 (sink-off mode): a report that writes nothing — no
    /// file is created, no writer thread spawns, zero metrics IO. Every
    /// `record` through its sink handles is a no-op: the channel's
    /// receiver is dropped at construction, so `try_send` reports
    /// `Disconnected`, which [`JsonlSinkHandle`] already treats as
    /// "writer gone, drop" (never backpressure). Exists so short rig/soak
    /// runs can skip the JSONL entirely while every call site keeps a
    /// single type; the default (`create`) path is unchanged.
    pub fn disabled() -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(SINK_BOUND);
        drop(rx);
        Self {
            path: PathBuf::new(),
            stop: Arc::new(AtomicBool::new(false)),
            join: None,
            records_written: Arc::new(AtomicU64::new(0)),
            backpressure_events: Arc::new(AtomicU64::new(0)),
            tx,
        }
    }

    /// Create `<dir>/<stem>.jsonl` (suffixing `-1`, `-2`, ... if taken).
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
        let records = Arc::new(AtomicU64::new(0));
        let records_w = Arc::clone(&records);
        let join = std::thread::Builder::new()
            .name("jsonl-writer".into())
            .spawn(move || {
                let file = std::fs::File::create(&writer_path).expect("create report file");
                let mut out = std::io::BufWriter::with_capacity(1 << 20, file);
                // F6 rotation: split at 128 MiB into `.jsonl.1`, `.jsonl.2`,
                // ... (tooling safety; all parts retained by the caller).
                const ROTATE_BYTES: usize = 128 * 1024 * 1024;
                let mut written: usize = 0;
                let mut part: u32 = 0;
                loop {
                    let record = match rx.recv_timeout(Duration::from_millis(200)) {
                        Ok(record) => record,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            if stop_w.load(Ordering::Acquire) {
                                break;
                            }
                            continue;
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    let line = serde_json::to_string(&record).unwrap_or_default();
                    let _ = out.write_all(line.as_bytes());
                    let _ = out.write_all(b"\n");
                    written += line.len() + 1;
                    records_w.fetch_add(1, Ordering::Relaxed);
                    if written >= ROTATE_BYTES
                        && let Ok(next) =
                            std::fs::File::create(format!("{}.{}", writer_path.display(), part + 1))
                    {
                        let _ = out.flush();
                        part += 1;
                        written = 0;
                        out = std::io::BufWriter::with_capacity(1 << 20, next);
                    }
                }
                while let Ok(record) = rx.try_recv() {
                    let line = serde_json::to_string(&record).unwrap_or_default();
                    let _ = out.write_all(line.as_bytes());
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
            records_written: records,
            backpressure_events: Arc::new(AtomicU64::new(0)),
            tx,
        })
    }

    pub fn sink_handle(&self, session: Arc<SessionSlot>) -> JsonlSinkHandle {
        JsonlSinkHandle {
            tx: self.tx.clone(),
            session,
            backpressure: Arc::clone(&self.backpressure_events),
        }
    }

    pub fn close(mut self) -> (PathBuf, u64, u64) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        (
            self.path,
            self.records_written.load(Ordering::Relaxed),
            self.backpressure_events.load(Ordering::Relaxed),
        )
    }
}

// ---------------------------------------------------------------------------
// Bounded hand-off queues (invariant 3, F5 sampling)
// ---------------------------------------------------------------------------

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

/// Time-source handle shared across pipeline threads.
pub type ClockFn = std::sync::Arc<dyn Fn() -> u64 + Send + Sync>;

/// Bounded pipeline queue sampled on every depth change (schema cadence).
pub struct FrameQueue<T> {
    kind: QueueKind,
    capacity: u32,
    policy: DropPolicy,
    state: Mutex<QueueState<T>>,
    changed: std::sync::Condvar,
    sink: Mutex<Box<dyn PerfSink>>,
    session: Arc<SessionSlot>,
    clock: ClockFn,
}

impl<T> FrameQueue<T> {
    pub fn new(
        kind: QueueKind,
        capacity: u32,
        policy: DropPolicy,
        sink: Box<dyn PerfSink>,
        session: Arc<SessionSlot>,
        clock: ClockFn,
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
            session,
            clock,
        }
    }

    fn sample(&self, state: &QueueState<T>) {
        let record = CounterRecord::QueueSample(QueueSample {
            session_id: self.session.get(),
            queue: self.kind,
            depth: state.slots.len() as u32,
            capacity: self.capacity,
            high_water: state.high_water,
            dropped: state.dropped,
            replaced: state.replaced,
            at_ns: (self.clock)(),
        });
        self.sink.lock().expect("queue sink").record(record);
    }

    /// Push; `Err(item)` when the policy rejected.
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
        let depth = state.slots.len() as u32;
        if depth > state.high_water {
            state.high_water = depth;
        }
        self.sample(&state);
        self.changed.notify_one();
        Ok(())
    }

    /// Pop with timeout; `None` on timeout or after close.
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
            let (guard, _timed_out) = self
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

    /// Still open? Pipeline threads distinguish "no item yet" (pop
    /// timeout) from "shut down" (closed) — a dry spell must not read as
    /// end-of-stream.
    pub fn is_open(&self) -> bool {
        self.state.lock().expect("queue lock").open
    }

    /// (high_water, capacity, dropped, replaced) for the summary.
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
// Resource sampler (>= 1 Hz)
// ---------------------------------------------------------------------------

/// Spawn a 1 Hz `ResourceSample` thread (process CPU %, working set).
pub fn spawn_resource_sampler(
    mut sink: Box<dyn PerfSink>,
    session: Arc<SessionSlot>,
    origin: Origin,
    stop: Arc<AtomicBool>,
    clock: ClockFn,
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
                        Some((now_ns - past) as f32 / 1e9 / 1.0 * 100.0)
                    }
                    _ => None,
                };
                last_cpu = wall.unwrap_or(last_cpu);
                sink.record(CounterRecord::ResourceSample(ResourceSample {
                    session_id: session.get(),
                    origin,
                    cpu_percent,
                    gpu_percent: None, // no D3DKMT engine counters yet
                    memory_working_set_bytes: working_set_bytes(),
                    gpu_memory_bytes: None,
                    at_ns: clock(),
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
        use windows::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows::Win32::System::Threading::GetCurrentProcess;
        let mut counters = PROCESS_MEMORY_COUNTERS::default();
        let cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let ok = GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, cb);
        if ok.is_ok() {
            Some(counters.WorkingSetSize as u64)
        } else {
            None
        }
    }
}

/// A capacity-1 latest-value slot for lossy side channels (host cursor
/// deltas): the newest value replaces the old one (counted), the consumer
/// takes whatever is current. Same newest-wins policy as `input-fast`.
pub struct LatestSlot<T> {
    value: Mutex<Option<T>>,
    replaced: AtomicU64,
    taken: AtomicU64,
}

impl<T> LatestSlot<T> {
    pub fn new() -> Self {
        Self {
            value: Mutex::new(None),
            replaced: AtomicU64::new(0),
            taken: AtomicU64::new(0),
        }
    }

    pub fn put(&self, value: T) {
        let mut slot = self.value.lock().expect("latest slot");
        if slot.is_some() {
            self.replaced.fetch_add(1, Ordering::Relaxed);
        }
        *slot = Some(value);
    }

    pub fn take(&self) -> Option<T> {
        let mut slot = self.value.lock().expect("latest slot");
        if slot.is_some() {
            self.taken.fetch_add(1, Ordering::Relaxed);
        }
        slot.take()
    }

    pub fn counters(&self) -> (u64, u64) {
        (
            self.replaced.load(Ordering::Relaxed),
            self.taken.load(Ordering::Relaxed),
        )
    }
}

impl<T> Default for LatestSlot<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diagnostics::NullSink;

    fn queue(cap: u32, policy: DropPolicy) -> FrameQueue<u32> {
        let session = Arc::new(SessionSlot::new("test"));
        FrameQueue::new(
            QueueKind::CaptureToEncode,
            cap,
            policy,
            Box::new(NullSink),
            session,
            std::sync::Arc::new(|| 0u64),
        )
    }

    #[test]
    fn newest_wins_queue_replaces_and_reject_queue_counts() {
        let q = queue(1, DropPolicy::NewestWins);
        q.push(1).unwrap();
        q.push(2).unwrap(); // replaces 1
        assert_eq!(q.pop(Duration::from_millis(10)), Some(2));
        let (hw, cap, dropped, replaced) = q.counters();
        assert_eq!((hw, cap, dropped, replaced), (1, 1, 0, 1));

        let q = queue(1, DropPolicy::Reject);
        q.push(1).unwrap();
        assert!(q.push(2).is_err());
        let (hw, cap, dropped, replaced) = q.counters();
        assert_eq!((hw, cap, dropped, replaced), (1, 1, 1, 0));
    }

    /// F79: the sink-off report is silent — no file, no records, no
    /// backpressure accounting, and the hot path never blocks.
    #[test]
    fn disabled_report_is_a_silent_noop_sink() {
        let report = JsonlReport::disabled();
        let session = Arc::new(SessionSlot::new("test"));
        let mut sink = report.sink_handle(session);
        for i in 0..10_000u64 {
            sink.record(CounterRecord::QueueSample(QueueSample {
                session_id: "s".to_owned(),
                queue: QueueKind::ChannelControl,
                depth: 1,
                capacity: 2,
                high_water: 1,
                dropped: 0,
                replaced: 0,
                at_ns: i,
            }));
        }
        assert_eq!(
            report
                .backpressure_events
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a disconnected channel is a no-op, not backpressure"
        );
        let (path, records, backpressure) = report.close();
        assert_eq!(records, 0, "nothing was written");
        assert_eq!(backpressure, 0);
        assert!(
            path.as_os_str().is_empty(),
            "sink-off mode owns no file path"
        );
    }

    #[test]
    fn latest_slot_newest_wins() {
        let slot = LatestSlot::new();
        slot.put("a");
        slot.put("b");
        assert_eq!(slot.take(), Some("b"));
        assert_eq!(slot.take(), None);
        assert_eq!(slot.counters(), (1, 1));
    }
}
