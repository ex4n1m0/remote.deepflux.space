//! Segmented HTTPS download engine for the assistant's `download_file`
//! tool (and, via agent-to-agent delegation, for a paired machine's
//! assistant).
//!
//! Design ported from the Deeptorrent `dlmgr` (same author, MIT; Python):
//! HEAD probe → strict Content-Range verification → pre-allocated
//! destination with direct offset writes (no merge step) → `.dfresume`
//! per-segment maps so interrupted downloads re-fetch only missing
//! ranges. The ported review lessons (2026-09-15 there) are load-bearing:
//! a 206 whose Content-Range window does not EXACTLY match the request
//! is an error, `If-Range` detects a resource that changed mid-download,
//! resume state lives beside the exact target file, and per-segment
//! workers own their file handle (no shared-cursor races).
//!
//! Invariant 3: fixed 64 KiB buffers, a bounded job registry, and no
//! channels — workers communicate through atomics and one small mutex.
//! Concurrency is capped (max 3 active jobs, max 6 segments each) and
//! every job is size-capped up front.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Hard size cap per download (probe-rejected up front; streamed bodies
/// are aborted if they exceed it).
pub const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Segment count = clamp(total / SEGMENT_MIN, 1, MAX_SEGMENTS); files at
/// or below SEGMENT_THRESHOLD download as a single stream.
const SEGMENT_MIN: u64 = 512 * 1024;
const SEGMENT_THRESHOLD: u64 = 4 * 1024 * 1024;
const MAX_SEGMENTS: u64 = 6;
const CHUNK: usize = 64 * 1024;
/// Retries per segment (fresh connection each) before the job errors.
const MAX_RETRIES: u32 = 3;
/// Registry bound: the most recent jobs kept for status polling.
const MAX_JOBS_REMEMBERED: usize = 20;
/// Concurrent active downloads bound.
const MAX_ACTIVE: usize = 3;
/// Per-I/O timeouts: a server that sends nothing for this long errors
/// the segment out (retry logic takes over); there is deliberately NO
/// overall timeout on the streaming agent.
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Sentinel returned when the resource changed on the server
/// (If-Range ignored / size moved) — the engine restarts such a job
/// from scratch exactly once.
#[derive(Debug)]
struct ResourceChanged;

// ---------------------------------------------------------------------------
// Job registry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct JobInfo {
    pub id: String,
    pub url: String,
    pub host: String,
    pub filename: String,
    pub path: String,
    /// queued | probing | downloading | done | error
    pub status: String,
    pub total_bytes: u64,
    pub downloaded_bytes: u64,
    pub speed_bps: u64,
    pub segments: u32,
    pub done_segments: u32,
    pub error: String,
}

struct JobInner {
    id: String,
    url: String,
    host: String,
    filename: String,
    path: PathBuf,
    status: Mutex<String>,
    total_bytes: AtomicU64,
    downloaded: AtomicU64,
    done_count: AtomicU64,
    segment_count: AtomicU64,
    error: Mutex<String>,
    stop: AtomicBool,
    /// Per-segment completed bytes (bounded: ≤ MAX_SEGMENTS entries),
    /// written under a short lock per chunk — the resume-state source.
    seg_completed: Mutex<HashMap<u32, u64>>,
    /// (last sample instant, last sampled bytes, last speed) for the
    /// status endpoint's speed estimate.
    speed_sample: Mutex<(Instant, u64, u64)>,
}

impl JobInner {
    fn set_status(&self, status: &str) {
        if let Ok(mut s) = self.status.lock() {
            *s = status.to_owned();
        }
    }

    fn fail(&self, message: &str) {
        if let Ok(mut e) = self.error.lock() {
            *e = message.to_owned();
        }
        self.set_status("error");
    }

    fn info(&self) -> JobInfo {
        let downloaded = self.downloaded.load(Ordering::Relaxed);
        let mut speed = 0u64;
        if let Ok(mut sample) = self.speed_sample.lock() {
            let (at, bytes, last_speed) = *sample;
            let now = Instant::now();
            let dt = now.duration_since(at);
            if dt >= Duration::from_millis(400) {
                speed = ((downloaded.saturating_sub(bytes)) as f64 / dt.as_secs_f64()) as u64;
                *sample = (now, downloaded, speed);
            } else {
                speed = last_speed;
            }
        }
        JobInfo {
            id: self.id.clone(),
            url: self.url.clone(),
            host: self.host.clone(),
            filename: self.filename.clone(),
            path: self.path.display().to_string(),
            status: self.status.lock().map(|s| s.clone()).unwrap_or_default(),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            downloaded_bytes: downloaded,
            speed_bps: speed,
            segments: self.segment_count.load(Ordering::Relaxed) as u32,
            done_segments: self.done_count.load(Ordering::Relaxed) as u32,
            error: self.error.lock().map(|s| s.clone()).unwrap_or_default(),
        }
    }
}

fn registry() -> &'static Mutex<Vec<Arc<JobInner>>> {
    static REGISTRY: OnceLock<Mutex<Vec<Arc<JobInner>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

fn active_count() -> usize {
    registry()
        .lock()
        .map(|jobs| {
            jobs.iter()
                .filter(|j| {
                    j.status
                        .lock()
                        .map(|s| {
                            s.as_str() == "queued"
                                || s.as_str() == "probing"
                                || s.as_str() == "downloading"
                        })
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

/// Test-only redirect of the destination directory so engine tests never
/// touch the real Downloads folder. Engine tests serialize on a guard —
/// the override is process-global.
#[cfg(test)]
static TEST_DIR: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

#[cfg(test)]
static TEST_DIR_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(test)]
fn set_test_dir(dir: Option<PathBuf>) {
    let cell = TEST_DIR.get_or_init(|| Mutex::new(None));
    if let Ok(mut slot) = cell.lock() {
        *slot = dir;
    }
}

#[cfg(test)]
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("df-dl-test-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create test dl dir");
    dir
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Start a download into the user's Downloads folder. Returns the job
/// snapshot immediately; poll with [`status`] / [`wait`]. `enforce_https`
/// is the product rule (HTTPS only); tests use `false` against loopback.
pub fn start(
    url: &str,
    filename_hint: Option<&str>,
    enforce_https: bool,
) -> Result<JobInfo, String> {
    start_in_dir(url, filename_hint, enforce_https, None)
}

/// [`start`] with an explicit destination directory (the updater stages
/// its installer under app data instead of Downloads). `None` = the
/// Downloads folder, as before.
pub fn start_in_dir(
    url: &str,
    filename_hint: Option<&str>,
    enforce_https: bool,
    dir: Option<&Path>,
) -> Result<JobInfo, String> {
    let (url, host) = validate_url(url, enforce_https)?;
    if active_count() >= MAX_ACTIVE {
        return Err(format!(
            "too many concurrent downloads (max {MAX_ACTIVE}) — wait for one to finish"
        ));
    }
    let filename = match filename_hint {
        Some(hint) if !hint.trim().is_empty() => safe_filename(hint),
        _ => filename_from_url(&url).unwrap_or_else(|| "download.bin".to_owned()),
    };
    let dir = match dir {
        Some(dir) => {
            std::fs::create_dir_all(dir).map_err(|e| format!("create download dir: {e}"))?;
            dir.to_path_buf()
        }
        None => downloads_dir()?,
    };
    // Never silently overwrite a completed file; DO re-enter an
    // interrupted target that has resume state beside it.
    let mut path = dir.join(&filename);
    let mut n = 1;
    while is_occupied(&path) {
        n += 1;
        path = dir.join(format!("{n}-{filename}"));
    }
    let job = Arc::new(JobInner {
        id: new_job_id(),
        url,
        host,
        filename,
        path,
        status: Mutex::new("queued".to_owned()),
        total_bytes: AtomicU64::new(0),
        downloaded: AtomicU64::new(0),
        done_count: AtomicU64::new(0),
        segment_count: AtomicU64::new(0),
        error: Mutex::new(String::new()),
        stop: AtomicBool::new(false),
        seg_completed: Mutex::new(HashMap::new()),
        speed_sample: Mutex::new((Instant::now(), 0, 0)),
    });
    registry()
        .lock()
        .map_err(|_| "registry poisoned")?
        .push(Arc::clone(&job));
    trim_registry();
    let runner = Arc::clone(&job);
    std::thread::Builder::new()
        .name("dl-job".into())
        .spawn(move || run_job(runner))
        .map_err(|e| format!("spawn download thread: {e}"))?;
    Ok(job.info())
}

fn is_occupied(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    if resume_state_path(path).exists() {
        return false; // interrupted target: resume it
    }
    std::fs::metadata(path).map(|m| m.len() > 0).unwrap_or(true)
}

fn trim_registry() {
    if let Ok(mut jobs) = registry().lock() {
        while jobs.len() > MAX_JOBS_REMEMBERED {
            let finished = jobs
                .first()
                .and_then(|j| j.status.lock().ok())
                .map(|s| s.as_str() == "done" || s.as_str() == "error")
                .unwrap_or(true);
            if finished {
                jobs.remove(0);
            } else {
                break;
            }
        }
    }
}

/// Status of one job (by id), or all remembered jobs (oldest first).
pub fn status(job_id: Option<&str>) -> Vec<JobInfo> {
    let Ok(jobs) = registry().lock() else {
        return Vec::new();
    };
    let infos: Vec<JobInfo> = jobs.iter().map(|j| j.info()).collect();
    match job_id {
        Some(id) => infos.into_iter().filter(|j| j.id == id).collect(),
        None => infos,
    }
}

/// Block until the job reaches a terminal state or `max` elapses.
pub fn wait(job_id: &str, max: Duration) -> Option<JobInfo> {
    let deadline = Instant::now() + max;
    loop {
        let current = status(Some(job_id)).into_iter().next();
        let finished = current
            .as_ref()
            .is_some_and(|j| j.status == "done" || j.status == "error");
        if finished || Instant::now() >= deadline {
            return current;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Stop a running job: workers exit at their next check, resume state is
/// kept, so re-running the same download continues where it stopped.
pub fn cancel(job_id: &str) -> Result<(), String> {
    let jobs = registry().lock().map_err(|_| "registry poisoned")?;
    let job = jobs
        .iter()
        .find(|j| j.id == job_id)
        .ok_or_else(|| format!("no download job {job_id}"))?;
    job.stop.store(true, Ordering::Relaxed);
    Ok(())
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

fn run_job(job: Arc<JobInner>) {
    // One automatic restart when the resource changed under us: the
    // resume state is stale by definition.
    match run_job_once(Arc::clone(&job), false) {
        Ok(()) => {}
        Err(ResourceChanged) => {
            let _ = std::fs::remove_file(resume_state_path(&job.path));
            match run_job_once(Arc::clone(&job), true) {
                Ok(()) => {}
                Err(ResourceChanged) => {
                    job.fail("the file changed on the server mid-download");
                }
            }
        }
    }
}

fn run_job_once(job: Arc<JobInner>, fresh: bool) -> Result<(), ResourceChanged> {
    job.set_status("probing");
    let agent = node_runtime::http::https_agent_io(
        CONNECT_TIMEOUT,
        IO_TIMEOUT,
        "remote-desktop-downloader",
    );
    let probe = match probe(&agent, &job.url) {
        Ok(p) => p,
        Err(e) => {
            job.fail(&e);
            return Ok(());
        }
    };
    if probe.total > MAX_BYTES {
        job.fail(&format!(
            "file is {} bytes — over the {} byte download cap",
            probe.total, MAX_BYTES
        ));
        return Ok(());
    }
    job.total_bytes.store(probe.total, Ordering::Relaxed);
    *job.speed_sample.lock().unwrap_or_else(|e| e.into_inner()) = (Instant::now(), 0, 0);

    let plan = plan_segments(probe.total, probe.ranges);
    job.segment_count
        .store(plan.len() as u64, Ordering::Relaxed);

    // Resume: adopt a matching `.dfresume` (url/size/validators must
    // match what the server reports NOW); anything else is stale.
    let mut resumed: HashMap<u32, u64> = if fresh {
        HashMap::new()
    } else {
        load_resume(&job.path, &job.url, &probe).unwrap_or_default()
    };
    resumed.retain(|index, _| plan.iter().any(|s| s.index == *index));

    // Fresh targets are created and pre-allocated (known size;
    // unknown-size targets grow under the single streaming segment). A
    // resumed target keeps its bytes — truncating would erase adopted
    // progress — so only its length is reconciled.
    let prepare = if resumed.is_empty() {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&job.path)
    } else {
        std::fs::OpenOptions::new().write(true).open(&job.path)
    }
    .and_then(|f| {
        if probe.total > 0 {
            f.set_len(probe.total)?;
        }
        Ok(f)
    });
    if let Err(e) = prepare {
        job.fail(&format!("cannot prepare destination file: {e}"));
        return Ok(());
    }

    job.set_status("downloading");
    job.downloaded
        .store(resumed.values().sum(), Ordering::Relaxed);
    if let Ok(mut map) = job.seg_completed.lock() {
        *map = resumed.clone();
    }
    save_resume(&job, &probe, &plan);

    let mut handles = Vec::new();
    for seg in &plan {
        let already = resumed.get(&seg.index).copied().unwrap_or(0);
        let worker = {
            let job = Arc::clone(&job);
            let agent = agent.clone();
            let seg = *seg;
            let validator = probe.validator_header();
            move || segment_worker(job, agent, seg, already, probe.ranges, validator)
        };
        match std::thread::Builder::new()
            .name(format!("dl-seg-{}", seg.index))
            .spawn(worker)
        {
            Ok(h) => handles.push(h),
            Err(e) => {
                job.stop.store(true, Ordering::Relaxed);
                job.fail(&format!("spawn segment thread: {e}"));
                for h in handles {
                    let _ = h.join();
                }
                return Ok(());
            }
        }
    }

    let mut changed = false;
    let mut last_err = String::new();
    for h in handles {
        match h.join() {
            Ok(Ok(())) => {}
            Ok(Err(SegFail::Changed)) => changed = true,
            Ok(Err(SegFail::Other(e))) => last_err = e,
            Err(_) => last_err = "segment thread panicked".to_owned(),
        }
    }
    if changed {
        return Err(ResourceChanged);
    }
    if job.stop.load(Ordering::Relaxed) {
        save_resume(&job, &probe, &plan);
        job.fail("cancelled");
        return Ok(());
    }
    let done = job.done_count.load(Ordering::Relaxed) as usize == plan.len();
    if !done {
        save_resume(&job, &probe, &plan);
        job.fail(&format!("download incomplete: {last_err}"));
        return Ok(());
    }
    let written = job.downloaded.load(Ordering::Relaxed);
    if probe.total > 0 && written != probe.total {
        job.fail(&format!(
            "size mismatch: wrote {written} of {} bytes",
            probe.total
        ));
        return Ok(());
    }
    if let Err(e) = std::fs::OpenOptions::new()
        .write(true)
        .open(&job.path)
        .and_then(|f| f.sync_all())
    {
        job.fail(&format!("fsync failed: {e}"));
        return Ok(());
    }
    let _ = std::fs::remove_file(resume_state_path(&job.path));
    job.set_status("done");
    Ok(())
}

struct Probe {
    /// 0 = unknown (single streaming segment to EOF).
    total: u64,
    ranges: bool,
    etag: String,
    last_modified: String,
}

impl Probe {
    /// `If-Range` validator: ETag preferred, Last-Modified fallback — a
    /// resumed range request then detects a changed resource instead of
    /// silently mixing two versions into one file.
    fn validator_header(&self) -> Option<String> {
        if !self.etag.is_empty() {
            Some(self.etag.clone())
        } else if !self.last_modified.is_empty() {
            Some(self.last_modified.clone())
        } else {
            None
        }
    }
}

fn probe(agent: &ureq::Agent, url: &str) -> Result<Probe, String> {
    if let Ok(resp) = agent.head(url).call() {
        return Ok(Probe {
            total: content_length(&resp),
            ranges: header_str(&resp, "Accept-Ranges").eq_ignore_ascii_case("bytes"),
            etag: header_str(&resp, "ETag"),
            last_modified: header_str(&resp, "Last-Modified"),
        });
    }
    // HEAD unsupported or failed → a one-byte ranged GET answers both the
    // ranges question and the total size in one round trip.
    let resp = agent
        .get(url)
        .set("Range", "bytes=0-0")
        .call()
        .map_err(|e| format!("probe failed: {e}"))?;
    if resp.status() == 206 {
        let cr = header_str(&resp, "Content-Range");
        let (_, _, total) = parse_content_range(&cr)
            .ok_or_else(|| format!("probe 206 with unparseable Content-Range: {cr}"))?;
        Ok(Probe {
            total: total.unwrap_or(0),
            ranges: true,
            etag: header_str(&resp, "ETag"),
            last_modified: header_str(&resp, "Last-Modified"),
        })
    } else {
        Ok(Probe {
            total: content_length(&resp),
            ranges: false,
            etag: header_str(&resp, "ETag"),
            last_modified: header_str(&resp, "Last-Modified"),
        })
    }
}

fn content_length(resp: &ureq::Response) -> u64 {
    resp.header("Content-Length")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug)]
struct Segment {
    index: u32,
    start: u64,
    /// `None` = unknown total: single streaming segment to EOF.
    end: Option<u64>,
}

impl Segment {
    fn size(&self) -> Option<u64> {
        self.end.map(|end| end - self.start + 1)
    }
}

fn plan_segments(total: u64, ranges: bool) -> Vec<Segment> {
    if total == 0 {
        return vec![Segment {
            index: 0,
            start: 0,
            end: None,
        }];
    }
    if !ranges || total <= SEGMENT_THRESHOLD {
        return vec![Segment {
            index: 0,
            start: 0,
            end: Some(total - 1),
        }];
    }
    let n = (total / SEGMENT_MIN).clamp(1, MAX_SEGMENTS);
    let seg = total / n;
    (0..n)
        .map(|i| Segment {
            index: i as u32,
            start: i * seg,
            end: if i == n - 1 {
                Some(total - 1)
            } else {
                Some((i + 1) * seg - 1)
            },
        })
        .collect()
}

/// Why a segment worker gave up.
#[derive(Debug)]
enum SegFail {
    /// The resource changed under us (If-Range ignored / size moved) —
    /// the engine restarts the whole job from scratch exactly once.
    Changed,
    Other(String),
}

/// One segment worker: owns its file handle (own cursor → no seek races
/// between segments), streams 64 KiB chunks, retries with a fresh
/// connection per attempt, reports progress through the job's counters.
fn segment_worker(
    job: Arc<JobInner>,
    agent: ureq::Agent,
    seg: Segment,
    mut completed: u64,
    ranged: bool,
    validator: Option<String>,
) -> Result<(), SegFail> {
    let seg_size = seg.size();
    if let Some(size) = seg_size {
        completed = completed.min(size);
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&job.path)
        .map_err(|e| SegFail::Other(format!("open destination: {e}")))?;
    for attempt in 0..=MAX_RETRIES {
        if job.stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        if let Some(size) = seg_size
            && completed >= size
        {
            note_progress(&job, seg.index, completed);
            job.done_count.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let mut req = agent.get(&job.url);
        if ranged && let Some(end) = seg.end {
            let want_start = seg.start + completed;
            req = req.set("Range", &format!("bytes={want_start}-{end}"));
            if completed > 0
                && let Some(v) = &validator
            {
                req = req.set("If-Range", v);
            }
        }
        let resp = match req.call() {
            Ok(r) => r,
            Err(e) => {
                if attempt == MAX_RETRIES {
                    return Err(SegFail::Other(format!("segment {}: {e}", seg.index)));
                }
                std::thread::sleep(Duration::from_millis(400 * u64::from(attempt + 1)));
                continue;
            }
        };
        let status = resp.status();
        if ranged && seg.end.is_some() {
            if status == 200 && completed > 0 {
                // The server ignored If-Range → the resource changed.
                job.stop.store(true, Ordering::Relaxed);
                return Err(SegFail::Changed);
            }
            if status != 206 {
                if attempt == MAX_RETRIES {
                    return Err(SegFail::Other(format!(
                        "segment {}: expected 206, got {status}",
                        seg.index
                    )));
                }
                std::thread::sleep(Duration::from_millis(400 * u64::from(attempt + 1)));
                continue;
            }
            let cr = header_str(&resp, "Content-Range");
            let Some((s, e, total)) = parse_content_range(&cr) else {
                return Err(SegFail::Other(format!(
                    "segment {}: unparseable Content-Range: {cr}",
                    seg.index
                )));
            };
            let want_start = seg.start + completed;
            if s != want_start || Some(e) != seg.end {
                return Err(SegFail::Other(format!(
                    "segment {}: server returned bytes {s}-{e}, requested {want_start}-{}",
                    seg.index,
                    seg.end.unwrap_or(0)
                )));
            }
            if let Some(t) = total {
                let job_total = job.total_bytes.load(Ordering::Relaxed);
                if job_total > 0 && t != job_total {
                    job.stop.store(true, Ordering::Relaxed);
                    return Err(SegFail::Changed);
                }
            }
        } else if status != 200 {
            return Err(SegFail::Other(format!(
                "segment {}: expected 200, got {status}",
                seg.index
            )));
        }
        // Own handle: seek to the exact write position each attempt
        // (idempotent, and correct after partial progress).
        file.seek(SeekFrom::Start(seg.start + completed))
            .map_err(|e| SegFail::Other(format!("seek: {e}")))?;
        let mut reader = resp.into_reader();
        let mut buf = [0u8; CHUNK];
        loop {
            if job.stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    if attempt == MAX_RETRIES {
                        return Err(SegFail::Other(format!("segment {}: read: {e}", seg.index)));
                    }
                    break; // retry the remainder on the next attempt
                }
            };
            if let Some(size) = seg_size
                && completed + n as u64 > size
            {
                return Err(SegFail::Other(format!(
                    "segment {}: response body exceeded the requested byte window",
                    seg.index
                )));
            }
            if seg_size.is_none() && job.downloaded.load(Ordering::Relaxed) + n as u64 > MAX_BYTES {
                job.stop.store(true, Ordering::Relaxed);
                return Err(SegFail::Other("stream exceeded the size cap".into()));
            }
            if let Err(e) = file.write_all(&buf[..n]) {
                return Err(SegFail::Other(format!("segment {}: write: {e}", seg.index)));
            }
            completed += n as u64;
            job.downloaded.fetch_add(n as u64, Ordering::Relaxed);
            note_progress(&job, seg.index, completed);
        }
        match seg_size {
            Some(size) if completed >= size => {
                note_progress(&job, seg.index, completed);
                job.done_count.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            // Unknown-size stream ended at EOF: that IS the whole file.
            None if completed > 0 => {
                let got = job.downloaded.load(Ordering::Relaxed);
                job.total_bytes.store(got, Ordering::Relaxed);
                note_progress(&job, seg.index, completed);
                job.done_count.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            _ => {}
        }
        if attempt == MAX_RETRIES {
            return Err(SegFail::Other(format!(
                "segment {}: incomplete after {MAX_RETRIES} retries",
                seg.index
            )));
        }
        std::thread::sleep(Duration::from_millis(400 * u64::from(attempt + 1)));
    }
    Ok(())
}

fn note_progress(job: &JobInner, index: u32, bytes: u64) {
    if let Ok(mut map) = job.seg_completed.lock() {
        map.insert(index, bytes);
    }
}

// ---------------------------------------------------------------------------
// Resume state (`.dfresume`)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ResumeDoc {
    v: u8,
    url: String,
    etag: String,
    last_modified: String,
    total: u64,
    /// index → completed bytes.
    segments: Vec<(u32, u64)>,
}

fn resume_state_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".dfresume");
    PathBuf::from(s)
}

fn load_resume(path: &Path, url: &str, probe: &Probe) -> Option<HashMap<u32, u64>> {
    if probe.total == 0 {
        return None; // unknown-size streams restart from scratch
    }
    let doc: ResumeDoc =
        serde_json::from_str(&std::fs::read_to_string(resume_state_path(path)).ok()?).ok()?;
    if doc.url != url || doc.total != probe.total {
        return None;
    }
    if !probe.etag.is_empty() && !doc.etag.is_empty() && probe.etag != doc.etag {
        return None;
    }
    if !probe.last_modified.is_empty()
        && !doc.last_modified.is_empty()
        && probe.last_modified != doc.last_modified
    {
        return None;
    }
    if std::fs::metadata(path).ok()?.len() != probe.total {
        return None;
    }
    Some(doc.segments.into_iter().collect())
}

fn save_resume(job: &JobInner, probe: &Probe, plan: &[Segment]) {
    if probe.total == 0 {
        return;
    }
    let progress = job
        .seg_completed
        .lock()
        .map(|map| map.clone())
        .unwrap_or_default();
    let doc = ResumeDoc {
        v: 1,
        url: job.url.clone(),
        etag: probe.etag.clone(),
        last_modified: probe.last_modified.clone(),
        total: probe.total,
        segments: plan
            .iter()
            .filter_map(|seg| progress.get(&seg.index).map(|c| (seg.index, *c)))
            .collect(),
    };
    let final_path = resume_state_path(&job.path);
    let tmp = final_path.with_extension("dfresume.tmp");
    if let Ok(json) = serde_json::to_string(&doc)
        && let Ok(mut f) = std::fs::File::create(&tmp)
        && f.write_all(json.as_bytes()).is_ok()
    {
        let _ = std::fs::rename(&tmp, &final_path);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn header_str(resp: &ureq::Response, name: &str) -> String {
    resp.header(name).unwrap_or("").trim().to_owned()
}

/// Parse `bytes S-E/T` (T may be `*`). Returns (start, end, total?).
fn parse_content_range(value: &str) -> Option<(u64, u64, Option<u64>)> {
    let value = value.trim();
    let rest = value
        .strip_prefix("bytes")
        .or_else(|| value.strip_prefix("BYTES"))?;
    let rest = rest.trim();
    let (range, total) = rest.split_once('/')?;
    let (s, e) = range.split_once('-')?;
    let start = s.trim().parse::<u64>().ok()?;
    let end = e.trim().parse::<u64>().ok()?;
    let total = match total.trim() {
        "*" => None,
        t => Some(t.parse::<u64>().ok()?),
    };
    Some((start, end, total))
}

fn new_job_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("dl-{n:04}")
}

fn downloads_dir() -> Result<PathBuf, String> {
    #[cfg(test)]
    if let Some(dir) = TEST_DIR
        .get()
        .and_then(|slot| slot.lock().ok())
        .and_then(|slot| slot.clone())
    {
        return Ok(dir);
    }
    let profile = std::env::var("USERPROFILE")
        .map_err(|_| "USERPROFILE not set — cannot locate Downloads")?;
    let dir = PathBuf::from(profile).join("Downloads");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create Downloads dir: {e}"))?;
    Ok(dir)
}

/// Windows-reserved device names (with or without extension) must never
/// be used as a filename.
fn is_reserved_name(stem: &str) -> bool {
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    RESERVED.contains(&stem.to_ascii_uppercase().as_str())
}

/// Reduce any hint to a safe single filename component: strip paths,
/// illegal Windows characters, control bytes, trailing dots/spaces; cap
/// length; never empty, never reserved, never traversal.
pub fn safe_filename(hint: &str) -> String {
    let base = hint
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("");
    let mut cleaned: String = base
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' => '-',
            other => other,
        })
        .collect();
    let stem = cleaned
        .trim_end_matches(['.', ' '])
        .split_once('.')
        .map(|(s, _)| s)
        .unwrap_or_else(|| cleaned.trim_end_matches(['.', ' ']))
        .to_owned();
    if is_reserved_name(&stem) {
        cleaned = format!("file-{cleaned}");
    }
    while cleaned.chars().last().is_some_and(|c| c == '.' || c == ' ') {
        cleaned.pop();
    }
    if cleaned.is_empty() {
        cleaned = "download.bin".to_owned();
    }
    if cleaned.len() > 180 {
        let prefix: String = cleaned.chars().take(170).collect();
        cleaned = format!("{prefix}.bin");
    }
    cleaned
}

/// Best-effort filename from a URL path (before any probe).
fn filename_from_url(url: &str) -> Option<String> {
    let path = url.split_once("://")?.1;
    let path = path.split_once('/')?.1;
    let last = path.rsplit('/').next()?.trim();
    if last.is_empty() {
        return None;
    }
    Some(safe_filename(last))
}

/// Validate a download URL: http(s) scheme only, no embedded userinfo,
/// host required. `enforce_https` rejects plain http (product rule).
pub fn validate_url(url: &str, enforce_https: bool) -> Result<(String, String), String> {
    let url = url.trim();
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| "URL must be http(s)://…".to_owned())?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return Err("only http(s) URLs can be downloaded".into());
    }
    if enforce_https && scheme != "https" {
        return Err(
            "only HTTPS URLs can be downloaded (keeps plaintext off family machines)".into(),
        );
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return Err("URLs with embedded credentials are not allowed".into());
    }
    let host = authority
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if host.is_empty() || !host.contains('.') {
        return Err("URL has no usable host".into());
    }
    Ok((url.to_owned(), host))
}

/// Allowlist match: exact host or a subdomain of an allowed domain
/// (`example.com` allows `cdn.example.com`).
pub fn host_allowed(host: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| {
        let a = a.trim().to_ascii_lowercase();
        !a.is_empty() && (host == a || host.ends_with(&format!(".{a}")))
    })
}

// ---------------------------------------------------------------------------
// Test-only loopback HTTP server: serves `body` with Range support and
// records request lines so resume behavior is assertable.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod test_server {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    pub struct TestServer {
        pub url: String,
        requests: Arc<Mutex<Vec<String>>>,
        shutdown: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    #[derive(Default, Clone, Copy)]
    pub struct Behavior {
        /// Ignore Range headers → always 200 + full body.
        pub ignore_ranges: bool,
        /// Answer ranged requests with a deliberately wrong window.
        pub wrong_window: bool,
        /// HEAD without Accept-Ranges (drives the single-stream path).
        pub dumb_probe: bool,
        /// Delay GET responses by this many seconds (cancel determinism).
        pub stall_get_secs: u64,
    }

    impl TestServer {
        pub fn start(body: Arc<Vec<u8>>, behavior: Behavior) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
            let port = listener.local_addr().expect("addr").port();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let shutdown = Arc::new(AtomicBool::new(false));
            let handle = std::thread::Builder::new()
                .name("test-http".into())
                .spawn({
                    let shutdown = Arc::clone(&shutdown);
                    let requests = Arc::clone(&requests);
                    move || {
                        listener.set_nonblocking(true).ok();
                        loop {
                            if shutdown.load(Ordering::Relaxed) {
                                break;
                            }
                            match listener.accept() {
                                Ok((stream, _)) => {
                                    let body = Arc::clone(&body);
                                    let requests = Arc::clone(&requests);
                                    std::thread::spawn(move || {
                                        handle_conn(stream, body, requests, behavior)
                                    });
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    std::thread::sleep(Duration::from_millis(15));
                                }
                                Err(_) => break,
                            }
                        }
                    }
                })
                .expect("spawn test server");
            Self {
                url: format!("http://127.0.0.1:{port}/file.bin"),
                requests,
                shutdown,
                handle: Some(handle),
            }
        }

        pub fn request_lines(&self) -> Vec<String> {
            self.requests.lock().map(|r| r.clone()).unwrap_or_default()
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn handle_conn(
        mut stream: std::net::TcpStream,
        body: Arc<Vec<u8>>,
        requests: Arc<Mutex<Vec<String>>>,
        behavior: Behavior,
    ) {
        let peer = stream.try_clone().expect("clone test stream");
        let mut reader = BufReader::new(peer);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            return;
        }
        let mut range: Option<(u64, u64)> = None;
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let l = line.trim();
                    if l.is_empty() {
                        break;
                    }
                    if let Some(v) = l
                        .strip_prefix("Range:")
                        .or_else(|| l.strip_prefix("range:"))
                    {
                        let spec = v.trim().strip_prefix("bytes=").unwrap_or(v.trim());
                        if let Some((s, e)) = spec.split_once('-') {
                            let s: u64 = s.trim().parse().unwrap_or(0);
                            let e: u64 = if e.trim().is_empty() {
                                body.len() as u64 - 1
                            } else {
                                e.trim().parse().unwrap_or(0)
                            };
                            range = Some((s, e));
                        }
                    }
                }
                Err(_) => return,
            }
        }
        let head_only = request_line.starts_with("HEAD");
        if !head_only && behavior.stall_get_secs > 0 {
            std::thread::sleep(Duration::from_secs(behavior.stall_get_secs));
        }
        if let Ok(mut r) = requests.lock() {
            r.push(format!("{} range={:?}", request_line.trim(), range));
        }
        let len = body.len();
        let validators = "ETag: \"test-etag\"\r\nLast-Modified: Mon, 26 Oct 2026 00:00:00 GMT\r\n";
        let response: Vec<u8> = if head_only {
            if behavior.dumb_probe {
                format!("HTTP/1.1 200 OK\r\n{validators}Content-Length: {len}\r\nConnection: close\r\n\r\n")
            } else {
                format!("HTTP/1.1 200 OK\r\n{validators}Accept-Ranges: bytes\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n")
            }
            .into_bytes()
        } else if let (Some((s, e)), false, false) =
            (range, behavior.ignore_ranges, behavior.wrong_window)
        {
            let s = s.min(len as u64 - 1);
            let e = e.min(len as u64 - 1);
            let slice = &body[s as usize..=e as usize];
            format!(
                "HTTP/1.1 206 Partial Content\r\n{validators}Accept-Ranges: bytes\r\nContent-Range: bytes {s}-{e}/{len}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                slice.len()
            )
            .into_bytes()
            .into_iter()
            .chain(slice.iter().copied())
            .collect()
        } else if behavior.wrong_window
            && let Some((s, _)) = range
        {
            let s = s.min(len as u64 - 1);
            let e = (s + 16).min(len as u64 - 1);
            let slice = &body[s as usize..=e as usize];
            format!(
                "HTTP/1.1 206 Partial Content\r\n{validators}Accept-Ranges: bytes\r\nContent-Range: bytes {s}-{e}/{len}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                slice.len()
            )
            .into_bytes()
            .into_iter()
            .chain(slice.iter().copied())
            .collect()
        } else {
            let mut resp = format!(
                "HTTP/1.1 200 OK\r\n{validators}Accept-Ranges: bytes\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
            )
            .into_bytes();
            resp.extend_from_slice(&body);
            resp
        };
        let _ = stream.write_all(&response);
        let _ = stream.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::test_server::{Behavior, TestServer};
    use super::*;

    fn pattern(len: usize) -> Arc<Vec<u8>> {
        Arc::new((0..len).map(|i| (i % 251) as u8).collect())
    }

    /// Isolated destination dir per test: engine tests never touch the
    /// real Downloads folder, and they serialize on a guard because the
    /// override is process-global.
    struct TestDir(
        PathBuf,
        #[allow(dead_code)] Option<std::sync::MutexGuard<'static, ()>>,
    );

    impl TestDir {
        fn new(tag: &str) -> Self {
            let lock = TEST_DIR_LOCK.get_or_init(|| Mutex::new(())).lock().ok();
            let dir = temp_dir(tag);
            set_test_dir(Some(dir.clone()));
            Self(dir, lock)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            set_test_dir(None);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn safe_filename_table() {
        assert_eq!(safe_filename("video.mp4"), "video.mp4");
        assert_eq!(safe_filename("..\\..\\evil.exe"), "evil.exe");
        assert_eq!(safe_filename("../../etc/passwd"), "passwd");
        assert_eq!(safe_filename("a<b>c:d\"e|f*g"), "a-b-c-d-e-f-g");
        // '?' begins a query string — the name ends there.
        assert_eq!(safe_filename("setup.exe?token=1"), "setup.exe");
        assert_eq!(safe_filename("trailing... "), "trailing");
        assert_eq!(safe_filename(""), "download.bin");
        assert_eq!(safe_filename("CON"), "file-CON");
        assert!(safe_filename("com1.bat").starts_with("file-com1"));
        let long = "x".repeat(300);
        assert!(safe_filename(&long).len() <= 180);
    }

    #[test]
    fn url_validation_table() {
        assert!(validate_url("https://example.com/a.zip", true).is_ok());
        assert!(validate_url("http://example.com/a.zip", true).is_err());
        assert!(validate_url("http://127.0.0.1:9/a", false).is_ok());
        assert!(validate_url("ftp://example.com/a", false).is_err());
        assert!(validate_url("https://user:pass@example.com/a", true).is_err());
        assert!(validate_url("not a url", true).is_err());
        let (url, host) = validate_url("https://CDN.Example.COM:8443/x", true).unwrap();
        assert_eq!(host, "cdn.example.com");
        assert!(url.contains("CDN.Example.COM"));
    }

    #[test]
    fn host_allowlist_matching() {
        let list = vec!["example.com".to_owned()];
        assert!(host_allowed("example.com", &list));
        assert!(host_allowed("cdn.example.com", &list));
        assert!(!host_allowed("notexample.com", &list));
        assert!(!host_allowed("example.com.evil.io", &list));
        assert!(!host_allowed("example.com", &[]));
    }

    #[test]
    fn content_range_parsing() {
        assert_eq!(
            parse_content_range("bytes 0-99/1000"),
            Some((0, 99, Some(1000)))
        );
        assert_eq!(
            parse_content_range("bytes 500-999/*"),
            Some((500, 999, None))
        );
        assert_eq!(parse_content_range("garbage"), None);
        assert_eq!(parse_content_range("bytes x-y/10"), None);
    }

    #[test]
    fn segment_planning() {
        assert_eq!(plan_segments(0, true).len(), 1);
        assert_eq!(plan_segments(1024, true).len(), 1);
        assert_eq!(plan_segments(1024, false).len(), 1);
        // 8 MiB with ranges → 6 segments, last absorbs the remainder.
        let plan = plan_segments(8 * 1024 * 1024, true);
        assert_eq!(plan.len(), 6);
        assert_eq!(plan[5].end, Some(8 * 1024 * 1024 - 1));
        let covered: u64 = plan.iter().map(|s| s.size().unwrap()).sum();
        assert_eq!(covered, 8 * 1024 * 1024);
        for w in plan.windows(2) {
            assert!(w[0].end.unwrap() < w[1].start);
        }
    }

    #[test]
    fn end_to_end_segmented_download() {
        let _dir = TestDir::new("e2e");
        let body = pattern(8 * 1024 * 1024);
        let server = TestServer::start(Arc::clone(&body), Behavior::default());
        let info = start(&server.url, Some("big.bin"), false).expect("start");
        let done = wait(&info.id, Duration::from_secs(60)).expect("wait");
        assert_eq!(done.status, "done", "job: {done:?}");
        assert_eq!(done.total_bytes, body.len() as u64);
        assert_eq!(done.segments, 6);
        let on_disk = std::fs::read(&done.path).expect("read result");
        assert_eq!(on_disk, *body);
        assert!(!PathBuf::from(format!("{}.dfresume", done.path)).exists());
        assert!(
            server
                .request_lines()
                .iter()
                .filter(|l| l.starts_with("GET"))
                .all(|l| l.contains("range=Some"))
        );
    }

    #[test]
    fn resume_fetches_only_missing_ranges() {
        let _dir = TestDir::new("resume");
        let body = pattern(8 * 1024 * 1024);
        let server = TestServer::start(Arc::clone(&body), Behavior::default());
        // Simulate an interrupted job: segment 0 fully on disk, the rest
        // zeroed, `.dfresume` claiming exactly that.
        let path = downloads_dir().unwrap().join("resume.bin");
        let plan = plan_segments(body.len() as u64, true);
        let seg0_size = plan[0].size().unwrap();
        let mut partial = vec![0u8; body.len()];
        partial[..seg0_size as usize].copy_from_slice(&body[..seg0_size as usize]);
        std::fs::write(&path, &partial).expect("write partial");
        let doc = ResumeDoc {
            v: 1,
            url: server.url.clone(),
            etag: "\"test-etag\"".to_owned(),
            last_modified: String::new(),
            total: body.len() as u64,
            segments: vec![(0, seg0_size)],
        };
        std::fs::write(
            resume_state_path(&path),
            serde_json::to_string(&doc).unwrap(),
        )
        .expect("write resume state");

        let info = start(&server.url, Some("resume.bin"), false).expect("start");
        let done = wait(&info.id, Duration::from_secs(60)).expect("wait");
        assert_eq!(done.status, "done", "job: {done:?}");
        let on_disk = std::fs::read(&done.path).expect("read result");
        assert_eq!(on_disk, *body);
        // No GET ever re-requested segment 0's bytes: every ranged GET
        // starts at or after segment 1's start.
        let gets: Vec<String> = server
            .request_lines()
            .iter()
            .filter(|l| l.starts_with("GET") && l.contains("range=Some"))
            .cloned()
            .collect();
        assert!(!gets.is_empty(), "expected ranged GETs");
        for get in &gets {
            let spec = get.split("range=Some((").nth(1).unwrap_or("");
            let start: u64 = spec.split(',').next().unwrap_or("").parse().unwrap_or(0);
            assert!(
                start >= plan[1].start,
                "re-fetched segment 0 bytes in {get}"
            );
        }
    }

    #[test]
    fn wrong_window_is_rejected() {
        let _dir = TestDir::new("wrong");
        let body = pattern(8 * 1024 * 1024);
        let server = TestServer::start(
            Arc::clone(&body),
            Behavior {
                wrong_window: true,
                ..Default::default()
            },
        );
        let info = start(&server.url, Some("wrong.bin"), false).expect("start");
        let done = wait(&info.id, Duration::from_secs(60)).expect("wait");
        assert_eq!(done.status, "error", "job: {done:?}");
        assert!(
            done.error.contains("bytes") || done.error.contains("window"),
            "error: {}",
            done.error
        );
    }

    #[test]
    fn no_range_server_single_stream() {
        let _dir = TestDir::new("single");
        let body = pattern(1024 * 1024);
        let server = TestServer::start(
            Arc::clone(&body),
            Behavior {
                dumb_probe: true,
                ..Default::default()
            },
        );
        let info = start(&server.url, Some("single.bin"), false).expect("start");
        let done = wait(&info.id, Duration::from_secs(60)).expect("wait");
        assert_eq!(done.status, "done", "job: {done:?}");
        assert_eq!(done.segments, 1);
        let on_disk = std::fs::read(&done.path).expect("read");
        assert_eq!(on_disk, *body);
    }

    #[test]
    fn cancel_stops_the_job_and_keeps_resume_state() {
        let _dir = TestDir::new("cancel");
        let body = pattern(1024);
        let server = TestServer::start(
            Arc::clone(&body),
            Behavior {
                stall_get_secs: 4,
                ..Default::default()
            },
        );
        let info = start(&server.url, Some("cancel.bin"), false).expect("start");
        std::thread::sleep(Duration::from_millis(500));
        cancel(&info.id).expect("cancel");
        let done = wait(&info.id, Duration::from_secs(30)).expect("wait");
        assert_eq!(done.status, "error", "job: {done:?}");
        assert_eq!(done.error, "cancelled");
    }

    #[test]
    fn existing_completed_file_is_not_overwritten() {
        let _dir = TestDir::new("dupe");
        let dir = downloads_dir().unwrap();
        std::fs::write(dir.join("dupe.bin"), b"previous").expect("seed");
        let body = pattern(2048);
        let server = TestServer::start(Arc::clone(&body), Behavior::default());
        let info = start(&server.url, Some("dupe.bin"), false).expect("start");
        let done = wait(&info.id, Duration::from_secs(60)).expect("wait");
        assert_eq!(done.status, "done");
        assert!(done.path.ends_with("2-dupe.bin"), "path: {}", done.path);
        assert_eq!(std::fs::read(dir.join("dupe.bin")).unwrap(), b"previous");
    }

    #[test]
    fn status_shape_stays_bounded() {
        let all = status(None);
        assert!(all.len() <= MAX_JOBS_REMEMBERED);
        for job in &all {
            assert!(!job.id.is_empty());
            assert!(
                ["queued", "probing", "downloading", "done", "error"]
                    .contains(&job.status.as_str())
            );
        }
    }
}
