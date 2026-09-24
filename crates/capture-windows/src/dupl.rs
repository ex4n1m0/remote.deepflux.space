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
        };
        capture.start_duplication()?;
        Ok(capture)
    }

    pub fn monitor_id(&self) -> &str {
        &self.monitor_id
    }

    /// Duplicated output geometry (set once duplication is live).
    pub fn dimensions(&self) -> (u32, u32) {
        self.desc
            .as_ref()
            .map(|d| (d.ModeDesc.Width, d.ModeDesc.Height))
            .unwrap_or((0, 0))
    }

    fn start_duplication(&mut self) -> Result<(), CaptureError> {
        unsafe {
            let Some(output) = self.output.clone() else {
                return Err(CaptureError::Invalid("no output".into()));
            };
            let out1: IDXGIOutput1 = output
                .cast()
                .map_err(|e| CaptureError::api("cast IDXGIOutput1", e.code().0, "duplicate"))?;
            match out1.DuplicateOutput(self.device.device()) {
                Ok(dupl) => {
                    self.desc = Some(dupl.GetDesc());
                    self.duplication = Some(dupl);
                    // Mode may have changed since the pool was built.
                    self.pool.clear();
                    self.last_surface = None;
                    Ok(())
                }
                Err(e) => Err(classify_duplication_error(e.code())),
            }
        }
    }

    /// Recovery path for [`CaptureError::AccessLost`]: drop the stale
    /// duplication and re-duplicate the same output. If the output itself
    /// is gone (monitor unplugged / topology change) returns
    /// [`CaptureError::DisplayChanged`] — the caller must re-enumerate.
    pub fn reinit(&mut self) -> Result<(), CaptureError> {
        self.duplication = None;
        // Re-check the output still exists under the same device name.
        self.output = match find_output(&self.device, &self.monitor_id) {
            Ok(o) => Some(o),
            Err(e @ CaptureError::DisplayChanged(_)) => return Err(e),
            Err(e) => return Err(e),
        };
        self.start_duplication()
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
        let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        let Some(duplication) = self.duplication.clone() else {
            return Err(CaptureError::Invalid("duplication not started".into()));
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
                timestamp_ns: self.now_ns(),
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
                timestamp_ns: self.now_ns(),
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
        let mut frame = result?;
        self.last_surface = Some(frame.surface.clone());
        frame.timestamp_ns = self.now_ns();
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
}
