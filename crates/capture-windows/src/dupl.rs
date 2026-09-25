//! DXGI Desktop Duplication implementation of [`CaptureSource`].

use std::time::{Duration, Instant};

use windows::Win32::Foundation::{E_ACCESSDENIED, RECT};
use windows::Win32::Graphics::Direct3D11::ID3D11Texture2D;
use windows::Win32::Graphics::Dxgi::{
    DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_DEVICE_REMOVED, DXGI_ERROR_DEVICE_RESET,
    DXGI_ERROR_NOT_CURRENTLY_AVAILABLE, DXGI_ERROR_NOT_FOUND, DXGI_ERROR_WAIT_TIMEOUT,
    DXGI_OUTDUPL_DESC, DXGI_OUTDUPL_FRAME_INFO, DXGI_OUTDUPL_MOVE_RECT,
    DXGI_OUTDUPL_POINTER_SHAPE_INFO, IDXGIAdapter1, IDXGIDevice, IDXGIOutput, IDXGIOutput1,
    IDXGIOutputDuplication, IDXGIResource,
};
use windows::core::Interface;

use frame_surface::{FrameSurface, GpuDevice};

use crate::cursor::{normalize_position, shape_to_cursor_message};
use crate::recovery::{RecoveryDecision, recovery_decision};
use crate::{
    CaptureError, CaptureMetadata, CaptureSource, CapturedFrame, DirtyRect, MonitorId, MoveRect,
};

/// How many pool textures the capture ring keeps. The duplication surface
/// must be released before the next acquire, so every frame is copied into
/// a pool slot; a ring of 4 gives downstream stages (queues cap 1 + encode
/// in flight) ~3 frame intervals of grace before a slot is reused.
const POOL_DEPTH: usize = 4;

/// One duplicated-able monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorInfo {
    pub monitor_id: MonitorId,
    /// Human-readable adapter/output name for diagnostics.
    pub description: String,
    /// Desktop coordinates (virtual desktop space).
    pub desktop_left: i32,
    pub desktop_top: i32,
    pub width: i32,
    pub height: i32,
    pub is_primary: bool,
}

/// Enumerate all desktop-attached outputs of the given device's adapter,
/// primary first. Pure enumeration — safe to call to re-check the topology
/// after a [`CaptureError::DisplayChanged`].
pub fn enumerate_monitors(device: &GpuDevice) -> Result<Vec<MonitorInfo>, CaptureError> {
    unsafe {
        let dxgi_dev: IDXGIDevice = device
            .device()
            .cast()
            .map_err(|e| CaptureError::api("cast IDXGIDevice", e.code().0, "enumerate"))?;
        let adapter: IDXGIAdapter1 = dxgi_dev
            .GetAdapter()
            .map_err(|e| CaptureError::api("GetAdapter", e.code().0, "enumerate"))?
            .cast()
            .map_err(|e| CaptureError::api("cast IDXGIAdapter1", e.code().0, "enumerate"))?;

        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            let output: IDXGIOutput = match adapter.EnumOutputs(index) {
                Ok(o) => o,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => return Err(CaptureError::api("EnumOutputs", e.code().0, "enumerate")),
            };
            index += 1;
            let desc = output
                .GetDesc()
                .map_err(|e| CaptureError::api("IDXGIOutput::GetDesc", e.code().0, "enumerate"))?;
            if !desc.AttachedToDesktop.as_bool() {
                continue;
            }
            let name_len = desc
                .DeviceName
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(desc.DeviceName.len());
            let monitor_id = String::from_utf16_lossy(&desc.DeviceName[..name_len]);
            let left = desc.DesktopCoordinates.left;
            let top = desc.DesktopCoordinates.top;
            let w = desc.DesktopCoordinates.right - left;
            let h = desc.DesktopCoordinates.bottom - top;
            out.push(MonitorInfo {
                description: format!("{monitor_id} ({w}x{h} @ {left},{top})"),
                is_primary: left == 0 && top == 0,
                monitor_id,
                desktop_left: left,
                desktop_top: top,
                width: w,
                height: h,
            });
        }
        out.sort_by(|a, b| {
            b.is_primary
                .cmp(&a.is_primary)
                .then(a.monitor_id.cmp(&b.monitor_id))
        });
        Ok(out)
    }
}

/// DXGI Desktop Duplication of one output, behind [`CaptureSource`].
pub struct DxgiCapture {
    device: GpuDevice,
    monitor_id: MonitorId,
    output: Option<IDXGIOutput>,
    duplication: Option<IDXGIOutputDuplication>,
    desc: Option<DXGI_OUTDUPL_DESC>,
    pool: Vec<FrameSurface>,
    pool_next: usize,
    last_surface: Option<FrameSurface>,
    next_frame_id: u64,
    cursor_seq: u64,
    shape_id: u32,
    last_shape_size: u32,
    last_cursor: Option<(i32, i32, bool)>,
    session_start: Instant,
    move_buffer: Vec<DXGI_OUTDUPL_MOVE_RECT>,
    dirty_buffer: Vec<RECT>,
    shape_buffer: Vec<u8>,
    /// Session clock injected by the node runtime so `capture_ns` shares
    /// the loop's zero-based monotonic clock (F17: the schema pins
    /// `capture_ns` at "DXGI AcquireNextFrame returned", which only this
    /// stage can stamp). Falls back to the capture's own start Instant.
    clock: Option<Box<dyn Fn() -> u64 + Send>>,
    /// F71 typed irrecoverable state. `Some(reason)` once the reinit
    /// budget is exhausted or a non-retryable failure (device removed)
    /// hit; sticky for the object's life — every `next_frame`/`reinit`
    /// returns [`CaptureError::Dead`] so callers cannot mistake death for
    /// a transient blip and freeze the session.
    dead: Option<String>,
    /// Transient-reinit bookkeeping (the F71 policy, `recovery.rs`):
    /// attempts burned, when the next attempt is allowed (backoff), and
    /// the pending cause reported while the backoff window is open.
    reinit_attempts: u32,
    reinit_next_at: Option<Instant>,
    reinit_last: Option<CaptureError>,
}

impl DxgiCapture {
    /// Duplicate `monitor` (device name like `\\.\DISPLAY5`; `"primary"`
    /// or `""` picks the primary output). `device` must be the device the
    /// output's adapter owns (the one from [`GpuDevice::create_hardware`]
    /// this process created).
    pub fn new(device: GpuDevice, monitor: &str) -> Result<Self, CaptureError> {
        // Duplication is denied on a non-input desktop (agent/service
        // spawn contexts); attach first. Harmless when already attached.
        let _ = frame_surface::attach_thread_to_input_desktop();
        let monitors = enumerate_monitors(&device)?;
        let want = if monitor.is_empty() || monitor == "primary" {
            monitors
                .iter()
                .find(|m| m.is_primary)
                .or_else(|| monitors.first())
        } else if let Ok(index) = monitor.parse::<usize>() {
            monitors.get(index)
        } else {
            monitors.iter().find(|m| m.monitor_id == monitor)
        };
        let Some(want) = want else {
            return Err(CaptureError::Invalid(format!(
                "monitor {monitor:?} not found among {:?}",
                monitors
                    .iter()
                    .map(|m| m.monitor_id.clone())
                    .collect::<Vec<_>>()
            )));
        };
        let output = find_output(&device, &want.monitor_id)?;
        let mut capture = Self {
            device,
            monitor_id: want.monitor_id.clone(),
            output: Some(output),
            duplication: None,
            desc: None,
            pool: Vec::new(),
            pool_next: 0,
            last_surface: None,
            next_frame_id: 1,
            cursor_seq: 0,
            shape_id: 0,
            last_shape_size: 0,
            last_cursor: None,
            session_start: Instant::now(),
            move_buffer: Vec::new(),
            dirty_buffer: Vec::new(),
            shape_buffer: Vec::new(),
            clock: None,
            dead: None,
            reinit_attempts: 0,
            reinit_next_at: None,
            reinit_last: None,
        };
        capture.start_duplication()?;
        Ok(capture)
    }

    pub fn monitor_id(&self) -> &str {
        &self.monitor_id
    }

    /// Set the timestamp source used for `CapturedFrame::timestamp_ns`
    /// (`capture_ns`). The node runtime passes its session clock so all
    /// stages share one clock domain; without one, the capture's own
    /// construction-time `Instant` is used (still monotonic, different
    /// origin — fine for isolated use, wrong for joined diagnostics).
    pub fn set_clock(&mut self, clock: Box<dyn Fn() -> u64 + Send>) {
        self.clock = Some(clock);
    }

    /// Duplicated output geometry (set once duplication is live).
    pub fn dimensions(&self) -> (u32, u32) {
        self.desc
            .as_ref()
            .map(|d| (d.ModeDesc.Width, d.ModeDesc.Height))
            .unwrap_or((0, 0))
    }

    fn start_duplication(&mut self) -> Result<(), CaptureError> {
        let Some(output) = self.output.clone() else {
            return Err(CaptureError::Invalid("no output".into()));
        };
        let dupl = duplicate_output(&self.device, &output)?;
        // Commit (construction path — nothing live to preserve).
        self.desc = Some(unsafe { dupl.GetDesc() });
        self.duplication = Some(dupl);
        // Mode may have changed since the pool was built.
        self.release_pool();
        self.last_surface = None;
        Ok(())
    }

    /// Recovery path for [`CaptureError::AccessLost`]: re-duplicate the
    /// same output. F71 contract:
    ///
    /// * **Release-first is required by DDA**: the driver refuses a second
    ///   `DuplicateOutput` on an output while any previous duplication
    ///   object is alive — including an already access-lost stale one
    ///   (measured `E_INVALIDARG`). So `reinit` drops the stale object
    ///   before re-duplicating, and on failure `duplication` is `None`.
    ///   That state is *not* the F71 dead state: [`CaptureSource::next_frame`]
    ///   reports the retryable [`CaptureError::AccessLost`] (driving every
    ///   caller's existing reinit loop) instead of the old silent
    ///   `Invalid("duplication not started")` that froze the M6 soak for
    ///   14.7 minutes while the session stayed `Connected`.
    /// * transient failures are retried with the bounded exponential
    ///   backoff of [`crate::recovery`] (calls inside the backoff window
    ///   are no-ops that re-report the pending cause — the caller's loop
    ///   cadence drives timing, this function never sleeps);
    /// * when the budget is exhausted, or the failure is device removal,
    ///   the capture transitions to the sticky typed dead state
    ///   ([`CaptureError::Dead`]) — callers must end the session.
    pub fn reinit(&mut self) -> Result<(), CaptureError> {
        if let Some(reason) = self.dead.clone() {
            return Err(CaptureError::Dead(reason));
        }
        if let Some(at) = self.reinit_next_at
            && Instant::now() < at
            && let Some(pending) = self.reinit_last.clone()
        {
            // Backoff window still open: report the pending transient
            // cause without touching DXGI.
            return Err(pending);
        }
        // Release-first (see doc comment); the stale duplication is
        // already invalid — an access-lost object cannot acquire frames.
        self.duplication.take();
        let attempt = (|| -> Result<(IDXGIOutput, IDXGIOutputDuplication), CaptureError> {
            let output = find_output(&self.device, &self.monitor_id)?;
            let dupl = duplicate_output(&self.device, &output)?;
            Ok((output, dupl))
        })();
        match attempt {
            Ok((output, dupl)) => {
                // Commit: swap in the fresh objects, release the old ring.
                self.output = Some(output);
                self.desc = Some(unsafe { dupl.GetDesc() });
                self.duplication = Some(dupl);
                self.release_pool();
                self.last_surface = None;
                self.reinit_attempts = 0;
                self.reinit_next_at = None;
                self.reinit_last = None;
                Ok(())
            }
            Err(e) => match recovery_decision(&e, self.reinit_attempts) {
                RecoveryDecision::Retry {
                    delay,
                    attempts,
                    cause: _,
                } => {
                    self.reinit_attempts = attempts;
                    self.reinit_next_at = Some(Instant::now() + delay);
                    self.reinit_last = Some(e.clone());
                    Err(e)
                }
                RecoveryDecision::Die { reason } => {
                    self.dead = Some(reason.clone());
                    self.reinit_next_at = None;
                    self.reinit_last = None;
                    Err(CaptureError::Dead(reason))
                }
            },
        }
    }

    /// F71: typed irrecoverable state reached (sticky).
    pub fn is_dead(&self) -> bool {
        self.dead.is_some()
    }

    /// The reason this capture died, if it has (F71 diagnostics).
    pub fn dead_reason(&self) -> Option<&str> {
        self.dead.as_deref()
    }

    /// Test seam (F71 integration evidence): force the typed dead state on
    /// a healthy capture so a rig run can prove the session ends within
    /// seconds instead of freezing `Connected`. Never call from product
    /// paths.
    #[doc(hidden)]
    pub fn kill_for_test(&mut self, reason: &str) {
        self.dead = Some(reason.to_owned());
    }

    /// Release the output duplication and ring WITHOUT ending the capture
    /// object's life (M6 e2e regression: DDA refuses a second
    /// `DuplicateOutput` on an output while any previous duplication
    /// object in this process is alive — `E_INVALIDARG` — so a monitor
    /// switch or display-change rebuild that constructs the replacement
    /// `DxgiCapture` first fails whenever old and new target the same
    /// output, e.g. `primary` == `\\.\DISPLAY5`). Call before constructing
    /// the replacement; on construction failure [`DxgiCapture::reinit`]
    /// is the recovery (transactional, policy-bounded).
    pub fn release_duplication(&mut self) {
        self.duplication.take();
        self.desc = None;
        self.release_pool();
    }

    /// Decommit the capture ring (F72): drop the pool surfaces and the
    /// last-surface reference, then `Flush` the immediate context so the
    /// driver retires the freed allocations now instead of holding several
    /// full-resolution rings in its deferred-release queue (measured
    /// +128 MiB private at 1080p before the flush; M2 F26b / M6 F72).
    ///
    /// COM lifetime note: each `FrameSurface` clone is one `IUnknown`
    /// reference on the same `ID3D11Texture2D`; `clear()`/`take()` drop the
    /// last references this struct holds. Downstream stages that still
    /// carry a clone keep their texture alive independently — flushing
    /// never pulls a surface out from under the encoder or renderer.
    fn release_pool(&mut self) {
        if self.pool.is_empty() && self.last_surface.is_none() {
            return;
        }
        self.pool.clear();
        self.last_surface = None;
        unsafe { self.device.context().Flush() };
    }

    fn now_ns(&self) -> u64 {
        self.session_start.elapsed().as_nanos() as u64
    }

    fn next_pool_slot(&mut self) -> Result<FrameSurface, CaptureError> {
        let (w, h) = self.dimensions();
        if self.pool.is_empty() {
            for _ in 0..POOL_DEPTH {
                self.pool.push(
                    FrameSurface::new_private(
                        &self.device,
                        w,
                        h,
                        frame_surface::SurfaceFormat::Bgra8,
                    )
                    .map_err(|e| CaptureError::api("pool alloc", e.hr, e.to_string()))?,
                );
            }
        }
        let slot = self.pool[self.pool_next].clone();
        self.pool_next = (self.pool_next + 1) % self.pool.len();
        Ok(slot)
    }

    /// Cursor delta extraction from one acquired frame info.
    fn cursor_update(
        &mut self,
        info: &DXGI_OUTDUPL_FRAME_INFO,
        duplication: &IDXGIOutputDuplication,
        desktop_left: i32,
        desktop_top: i32,
        width: i32,
        height: i32,
    ) -> Option<protocol::wire::CursorMessage> {
        unsafe {
            let mut cursor_event = None;
            let pos = info.PointerPosition;
            let visible = pos.Visible.as_bool();

            // Shape change? DXGI reports a non-zero shape buffer size on
            // the frame that changed the shape.
            if info.PointerShapeBufferSize > 0 {
                self.shape_buffer.clear();
                self.shape_buffer
                    .resize(info.PointerShapeBufferSize as usize, 0);
                let mut shape_info = DXGI_OUTDUPL_POINTER_SHAPE_INFO::default();
                let hr = duplication.GetFramePointerShape(
                    info.PointerShapeBufferSize,
                    self.shape_buffer.as_mut_ptr() as *mut core::ffi::c_void,
                    std::ptr::null_mut(),
                    &mut shape_info,
                );
                if hr.is_ok() {
                    if info.PointerShapeBufferSize != self.last_shape_size {
                        self.shape_id = self.shape_id.wrapping_add(1).max(1);
                        self.last_shape_size = info.PointerShapeBufferSize;
                    }
                    if let Some(shape) =
                        shape_to_cursor_message(&shape_info, &self.shape_buffer, self.shape_id)
                    {
                        cursor_event = Some(shape);
                    }
                }
            }

            // Position/hide delta.
            let now = (pos.Position.x, pos.Position.y, visible);
            let changed = self.last_cursor != Some(now);
            self.last_cursor = Some(now);
            if cursor_event.is_none() && changed {
                if visible {
                    self.cursor_seq += 1;
                    cursor_event = Some(normalize_position(
                        pos.Position.x,
                        pos.Position.y,
                        desktop_left,
                        desktop_top,
                        width,
                        height,
                        self.cursor_seq,
                    ));
                } else {
                    cursor_event = Some(protocol::wire::CursorMessage::Hide);
                }
            }
            cursor_event
        }
    }

    fn metadata(
        &mut self,
        duplication: &IDXGIOutputDuplication,
        total: u32,
        accumulated: u32,
    ) -> CaptureMetadata {
        let mut meta = CaptureMetadata {
            accumulated_frames: accumulated,
            ..Default::default()
        };
        if total == 0 {
            return meta;
        }
        unsafe {
            // Move rects first, then dirty rects — each call reports the
            // actual byte size, so no ambiguous buffer splitting.
            self.move_buffer.clear();
            self.move_buffer.resize(
                total as usize / size_of::<DXGI_OUTDUPL_MOVE_RECT>() + 1,
                DXGI_OUTDUPL_MOVE_RECT::default(),
            );
            let mut actual = 0u32;
            if duplication
                .GetFrameMoveRects(
                    (self.move_buffer.len() * size_of::<DXGI_OUTDUPL_MOVE_RECT>()) as u32,
                    self.move_buffer.as_mut_ptr(),
                    &mut actual,
                )
                .is_ok()
            {
                let count = actual as usize / size_of::<DXGI_OUTDUPL_MOVE_RECT>();
                for mr in &self.move_buffer[..count] {
                    meta.move_rects.push(MoveRect {
                        source_x: mr.SourcePoint.x,
                        source_y: mr.SourcePoint.y,
                        destination: DirtyRect {
                            left: mr.DestinationRect.left,
                            top: mr.DestinationRect.top,
                            right: mr.DestinationRect.right,
                            bottom: mr.DestinationRect.bottom,
                        },
                    });
                }
            }
            self.dirty_buffer.clear();
            self.dirty_buffer
                .resize(total as usize / size_of::<RECT>() + 1, RECT::default());
            let mut actual = 0u32;
            if duplication
                .GetFrameDirtyRects(
                    (self.dirty_buffer.len() * size_of::<RECT>()) as u32,
                    self.dirty_buffer.as_mut_ptr(),
                    &mut actual,
                )
                .is_ok()
            {
                let count = actual as usize / size_of::<RECT>();
                for r in &self.dirty_buffer[..count] {
                    meta.dirty_rects.push(DirtyRect {
                        left: r.left,
                        top: r.top,
                        right: r.right,
                        bottom: r.bottom,
                    });
                }
            }
        }
        meta
    }
}

/// Duplicate `output` on `device` without touching any capture state —
/// the building block both construction and the F71 transactional
/// `reinit` commit through (nothing is mutated until this succeeds).
fn duplicate_output(
    device: &GpuDevice,
    output: &IDXGIOutput,
) -> Result<IDXGIOutputDuplication, CaptureError> {
    unsafe {
        let out1: IDXGIOutput1 = output
            .cast()
            .map_err(|e| CaptureError::api("cast IDXGIOutput1", e.code().0, "duplicate"))?;
        out1.DuplicateOutput(device.device())
            .map_err(|e| classify_duplication_error(e.code()))
    }
}

fn find_output(device: &GpuDevice, monitor_id: &str) -> Result<IDXGIOutput, CaptureError> {
    unsafe {
        let dxgi_dev: IDXGIDevice = device
            .device()
            .cast()
            .map_err(|e| CaptureError::api("cast IDXGIDevice", e.code().0, "find output"))?;
        let adapter: IDXGIAdapter1 = dxgi_dev
            .GetAdapter()
            .map_err(|e| CaptureError::api("GetAdapter", e.code().0, "find output"))?
            .cast()
            .map_err(|e| CaptureError::api("cast IDXGIAdapter1", e.code().0, "find output"))?;
        let mut index = 0u32;
        loop {
            let output: IDXGIOutput = match adapter.EnumOutputs(index) {
                Ok(o) => o,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => {
                    return Err(CaptureError::DisplayChanged(format!(
                        "output {monitor_id:?} no longer exists"
                    )));
                }
                Err(e) => return Err(CaptureError::api("EnumOutputs", e.code().0, "find output")),
            };
            index += 1;
            let desc = output
                .GetDesc()
                .map_err(|e| CaptureError::api("GetDesc", e.code().0, "find output"))?;
            let name_len = desc
                .DeviceName
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(desc.DeviceName.len());
            if String::from_utf16_lossy(&desc.DeviceName[..name_len]) == monitor_id {
                return Ok(output);
            }
        }
    }
}

/// Map a duplication HRESULT to the typed recovery (the documented DXGI
/// failure modes). Exposed for tests.
pub fn classify_duplication_error(hr: windows::core::HRESULT) -> CaptureError {
    if hr == DXGI_ERROR_ACCESS_LOST {
        CaptureError::AccessLost(format!("DXGI_ERROR_ACCESS_LOST (0x{:08X})", hr.0 as u32))
    } else if hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET {
        CaptureError::DeviceLost(format!("device removed/reset (0x{:08X})", hr.0 as u32))
    } else if hr == E_ACCESSDENIED {
        CaptureError::AccessDenied(format!(
            "E_ACCESSDENIED — protected content or secure desktop (0x{:08X})",
            hr.0 as u32
        ))
    } else if hr == DXGI_ERROR_NOT_CURRENTLY_AVAILABLE {
        CaptureError::Exhausted(format!(
            "DXGI_ERROR_NOT_CURRENTLY_AVAILABLE — too many duplications (0x{:08X})",
            hr.0 as u32
        ))
    } else if hr == DXGI_ERROR_NOT_FOUND {
        CaptureError::DisplayChanged(format!("DXGI_ERROR_NOT_FOUND (0x{:08X})", hr.0 as u32))
    } else {
        CaptureError::Api {
            op: "DuplicateOutput",
            hr: hr.0,
            detail: hr.message().to_string(),
        }
    }
}

impl CaptureSource for DxgiCapture {
    fn monitors(&mut self) -> Result<Vec<MonitorInfo>, CaptureError> {
        enumerate_monitors(&self.device)
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<CapturedFrame>, CaptureError> {
        // F71: a dead capture reports death — typed, sticky, impossible to
        // mistake for the old "invalid state" spin.
        if let Some(reason) = self.dead.clone() {
            return Err(CaptureError::Dead(reason));
        }
        let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        let Some(duplication) = self.duplication.clone() else {
            // Only reachable between a failed (release-first) reinit and
            // the next retry: report the retryable cause that drives every
            // caller's reinit loop. The F71 bug was this branch returning
            // `Invalid` forever with no escalation path — a frozen stream.
            return Err(CaptureError::AccessLost(
                "duplication released for reinit; retry pending".into(),
            ));
        };
        // Desktop geometry for cursor normalization comes from the output
        // description (stable for the life of the duplication).
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;
        let hr = unsafe { duplication.AcquireNextFrame(timeout_ms, &mut info, &mut resource) };
        if let Err(e) = hr {
            let code = e.code();
            if code == DXGI_ERROR_WAIT_TIMEOUT {
                return Ok(None);
            }
            return Err(classify_acquire_error(code));
        }

        // F17: stamp exactly where the schema pins it — AcquireNextFrame
        // returned, *before* metadata fetch, the pool copy, and
        // ReleaseFrame — so the DDA acquire+copy work is inside the
        // measured capture→encode stage instead of outside every stage.
        let acquire_ns = self
            .clock
            .as_ref()
            .map(|c| c())
            .unwrap_or_else(|| self.now_ns());

        let (desc_w, desc_h) = self.dimensions();
        let (desk_left, desk_top, desk_w, desk_h) = unsafe {
            let d = self
                .output
                .as_ref()
                .and_then(|o| o.GetDesc().ok())
                .map(|d| {
                    (
                        d.DesktopCoordinates.left,
                        d.DesktopCoordinates.top,
                        d.DesktopCoordinates.right - d.DesktopCoordinates.left,
                        d.DesktopCoordinates.bottom - d.DesktopCoordinates.top,
                    )
                });
            d.unwrap_or((0, 0, desc_w as i32, desc_h as i32))
        };

        let cursor = self.cursor_update(&info, &duplication, desk_left, desk_top, desk_w, desk_h);

        // Cursor-only update: LastPresentTime == 0 means no new pixels.
        if info.LastPresentTime == 0 {
            unsafe {
                let _ = duplication.ReleaseFrame();
            };
            let Some(surface) = self.last_surface.clone() else {
                // Shape arrived before any pixel frame; nothing to show.
                return Ok(None);
            };
            return Ok(Some(CapturedFrame {
                frame_id: self.next_frame_id.saturating_sub(1),
                timestamp_ns: acquire_ns,
                width_px: desc_w,
                height_px: desc_h,
                surface,
                metadata: CaptureMetadata {
                    accumulated_frames: 0,
                    only_cursor_update: true,
                    ..Default::default()
                },
                cursor,
            }));
        }

        // Copy the acquired surface into our pool slot, then release the
        // duplication frame immediately.
        let acquired: Option<ID3D11Texture2D> =
            resource.and_then(|r| r.cast::<ID3D11Texture2D>().ok());
        let result = (|| -> Result<CapturedFrame, CaptureError> {
            let tex = acquired
                .clone()
                .ok_or_else(|| CaptureError::api("AcquireNextFrame", 0, "no surface resource"))?;
            let slot = self.next_pool_slot()?;
            let src = FrameSurface::from_texture(
                tex,
                desc_w,
                desc_h,
                frame_surface::SurfaceFormat::Bgra8,
            );
            slot.copy_from(&self.device, &src)
                .map_err(|e| CaptureError::api("copy_from", e.hr, e.to_string()))?;
            let frame_id = self.next_frame_id;
            self.next_frame_id += 1;
            let surface = slot.with_frame_id(frame_id);
            let meta = self.metadata(
                &duplication,
                info.TotalMetadataBufferSize,
                info.AccumulatedFrames,
            );
            Ok(CapturedFrame {
                frame_id,
                timestamp_ns: acquire_ns,
                width_px: desc_w,
                height_px: desc_h,
                surface: surface.clone(),
                metadata: meta,
                cursor,
            })
        })();
        unsafe {
            let _ = duplication.ReleaseFrame();
        };
        let frame = result?;
        self.last_surface = Some(frame.surface.clone());
        Ok(Some(frame))
    }
}

/// `AcquireNextFrame` failure mapping (see `classify_duplication_error`
/// for the duplication-creation variant). Exposed for tests.
pub fn classify_acquire_error(hr: windows::core::HRESULT) -> CaptureError {
    if hr == DXGI_ERROR_ACCESS_LOST {
        CaptureError::AccessLost(format!("DXGI_ERROR_ACCESS_LOST (0x{:08X})", hr.0 as u32))
    } else if hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET {
        CaptureError::DeviceLost(format!("device removed/reset (0x{:08X})", hr.0 as u32))
    } else if hr == E_ACCESSDENIED {
        CaptureError::AccessDenied(format!(
            "E_ACCESSDENIED — protected content or secure desktop (0x{:08X})",
            hr.0 as u32
        ))
    } else {
        CaptureError::Api {
            op: "AcquireNextFrame",
            hr: hr.0,
            detail: hr.message().to_string(),
        }
    }
}

// The duplication path wraps the acquired resource with
// `FrameSurface::from_texture` before copying it into a pool slot; the
// surface is only used as a copy source and never escapes this crate.

/// F72 drop-path teardown. Release order matters and is deliberate:
///
/// 1. `IDXGIOutputDuplication` first — DDA holds one full-resolution
///    surface per output and the driver refuses a second `DuplicateOutput`
///    on the same output while the old object is alive (the
///    `DXGI_ERROR_NOT_CURRENTLY_AVAILABLE` / `Exhausted` class).
/// 2. The pool ring + last-surface reference (via [`DxgiCapture::release_pool`])
///    — each `FrameSurface` drop is a COM `Release`; the trailing
///    `ID3D11DeviceContext::Flush` retires the freed allocations now.
///    Without it the driver parked several full-resolution rings in its
///    deferred-release queue (measured +128 MiB private bytes at 1080p
///    across create/drop cycles — M2 F26b, re-measured as M6 F72).
/// 3. `IDXGIOutput` last (the duplication no longer references it).
///
/// COM lifetime note: the shared `GpuDevice` outlives every capture
/// (process-lifetime by design), so the flush target is always valid here.
/// Clones of pool surfaces held downstream (encoder in flight, renderer)
/// keep their textures alive through their own references — this drop
/// never invalidates a surface another stage still owns.
impl Drop for DxgiCapture {
    fn drop(&mut self) {
        self.duplication.take();
        self.release_pool();
        self.output.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_error_mapping() {
        assert!(matches!(
            classify_acquire_error(DXGI_ERROR_ACCESS_LOST),
            CaptureError::AccessLost(_)
        ));
        assert!(matches!(
            classify_acquire_error(DXGI_ERROR_DEVICE_REMOVED),
            CaptureError::DeviceLost(_)
        ));
        assert!(matches!(
            classify_duplication_error(DXGI_ERROR_NOT_CURRENTLY_AVAILABLE),
            CaptureError::Exhausted(_)
        ));
        assert!(matches!(
            classify_duplication_error(windows::core::HRESULT(0x8000FFFFu32 as i32)),
            CaptureError::Api { .. }
        ));
    }

    #[test]
    fn fatal_errors_are_dead_or_device_lost() {
        assert!(CaptureError::Dead("budget".into()).is_fatal());
        assert!(CaptureError::DeviceLost("removed".into()).is_fatal());
        for not_fatal in [
            CaptureError::AccessLost("churn".into()),
            CaptureError::AccessDenied("secure".into()),
            CaptureError::DisplayChanged("gone".into()),
            CaptureError::Exhausted("limit".into()),
            CaptureError::Invalid("contract".into()),
            CaptureError::Api {
                op: "DuplicateOutput",
                hr: 1,
                detail: String::new(),
            },
        ] {
            assert!(!not_fatal.is_fatal());
        }
    }

    /// Requires a real interactive desktop; run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "requires an interactive desktop session (DXGI duplication)"]
    fn duplication_acquires_real_frames() {
        let device = GpuDevice::create_hardware().expect("hardware device");
        let mut cap = DxgiCapture::new(device, "primary").expect("duplicate primary");
        let (w, h) = cap.dimensions();
        assert!(w >= 640 && h >= 480, "unexpected mode {w}x{h}");
        // Wait for any update within 2 s (move the mouse while it runs).
        for _ in 0..40 {
            if let Some(frame) = cap
                .next_frame(Duration::from_millis(50))
                .expect("next_frame")
            {
                assert_eq!(frame.width_px, w);
                assert_eq!(frame.height_px, h);
                assert!(frame.frame_id >= 1);
                return;
            }
        }
        panic!("no desktop update within 2 s — is something animating on screen?");
    }

    /// F71, live desktop: reinit is transactional — a successful reinit
    /// keeps frames flowing, and a killed capture reports sticky typed
    /// death from both `next_frame` and `reinit` (never `Invalid`).
    /// Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "requires an interactive desktop session (DXGI duplication)"]
    fn reinit_is_transactional_and_death_is_sticky() {
        let device = GpuDevice::create_hardware().expect("hardware device");
        let mut cap = DxgiCapture::new(device, "primary").expect("duplicate primary");
        // Healthy reinit: same output, fresh duplication object.
        cap.reinit().expect("reinit on a live desktop");
        assert!(!cap.is_dead());
        let (w, h) = cap.dimensions();
        assert!(w > 0 && h > 0);

        // Typed death is sticky across every entry point (F71's exact
        // regression: the old code returned `Invalid` forever, which no
        // caller escalated).
        cap.kill_for_test("test: forced death");
        assert!(cap.is_dead());
        assert!(matches!(
            cap.next_frame(Duration::from_millis(50)),
            Err(CaptureError::Dead(reason)) if reason.contains("forced")
        ));
        assert!(matches!(cap.reinit(), Err(CaptureError::Dead(_))));
        // A dead capture must not be mistaken for a recoverable state by
        // callers keying on AccessLost/Invalid.
        assert!(
            cap.next_frame(Duration::from_millis(50))
                .expect_err("dead capture must error")
                .is_fatal()
        );
    }
}
