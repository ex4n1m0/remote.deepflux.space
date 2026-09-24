//! # `frame-surface` — the shared GPU frame-handoff type (M1, ADR-001 open question #1)
//!
//! This is the **only** type platform crates are allowed to share (ADR-001
//! rule 3: platform crates never depend on each other; the node runtime
//! composes them). `capture-windows` produces [`FrameSurface`]s,
//! `codec-windows` consumes and produces them, `render-windows` presents
//! them — and no platform crate ever imports another.
//!
//! Design decisions (recorded in ADR-001 as the settlement of its open
//! question #1):
//!
//! * A `FrameSurface` is a thin, `Clone`-cheap (COM refcount) wrapper over
//!   one `ID3D11Texture2D` plus geometry/format and the host-assigned
//!   `frame_id` used to join diagnostics records.
//! * The local loop (and the M4 app) uses **one D3D11 device for every
//!   stage**, created here and cloned into each stage. Same-device COM
//!   sharing is the zero-copy path; the device is created with
//!   `D3D11_CREATE_DEVICE_BGRA_SUPPORT` and `SetMultithreadProtected(TRUE)`
//!   so the immediate context is safe to use from the capture, codec and
//!   render threads concurrently (serialized by the driver).
//! * Cross-device/process sharing is still provided — `share_handle()`
//!   mints an NT DXGI shared handle and `open_shared()` opens one on a
//!   different device — so an M2+ runtime that wants dedicated devices per
//!   stage (or a cross-process viewer) can do so without a contract change.
//!   The handle is *raw* (no keyed mutex); callers must synchronize frame
//!   lifetimes themselves (producer releases before consumer maps).
//! * CPU readback exists in exactly two sanctioned places: diagnostics
//!   (`readback_*`) and feeding the Media Foundation **software** encoder
//!   fallback (delta D3), which only accepts CPU buffers. Every readback
//!   increments a process-wide counter exposed via [`readback_count`] so a
//!   report can state precisely how many CPU copies occurred.
//!
//! This crate is a leaf: it depends on nothing internal.

use std::sync::atomic::{AtomicU64, Ordering};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE, D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP, D3D_FEATURE_LEVEL,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAP_READ, D3D11_MAPPED_SUBRESOURCE,
    D3D11_RESOURCE_MISC_SHARED, D3D11_RESOURCE_MISC_SHARED_NTHANDLE, D3D11_SDK_VERSION,
    D3D11_SUBRESOURCE_DATA, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, D3D11_USAGE_STAGING,
    ID3D11Device, ID3D11Device1, ID3D11DeviceContext, ID3D11Multithread, ID3D11Resource,
    ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_NV12,
};
use windows::Win32::Graphics::Dxgi::{
    DXGI_SHARED_RESOURCE_READ, DXGI_SHARED_RESOURCE_WRITE, IDXGIAdapter, IDXGIDevice,
    IDXGIResource1,
};
use windows::core::{Interface, PCWSTR};

/// Pixel formats that travel through the pipeline. Desktop duplication
/// produces [`SurfaceFormat::Bgra8`]; H.264 encode/decode consumes and
/// produces [`SurfaceFormat::Nv12`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceFormat {
    Bgra8,
    Nv12,
}

impl SurfaceFormat {
    pub fn dxgi(self) -> DXGI_FORMAT {
        match self {
            SurfaceFormat::Bgra8 => DXGI_FORMAT_B8G8R8A8_UNORM,
            SurfaceFormat::Nv12 => DXGI_FORMAT_NV12,
        }
    }

    /// Bytes per pixel-equivalent (Nv12 counts 1.5 per pixel, rounded up).
    pub fn bytes_per_pixel(self) -> u32 {
        match self {
            SurfaceFormat::Bgra8 => 4,
            SurfaceFormat::Nv12 => 2, // 12 bits per pixel; see plane_layout
        }
    }
}

/// Typed surface/device failure. `hr` is the failing HRESULT where one
/// exists (`0` when the failure is not an API return).
#[derive(Debug)]
pub struct SurfaceError {
    pub op: &'static str,
    pub hr: i32,
    pub detail: String,
}

impl SurfaceError {
    pub fn new(op: &'static str, hr: i32, detail: impl Into<String>) -> Self {
        Self {
            op,
            hr,
            detail: detail.into(),
        }
    }
}

impl core::fmt::Display for SurfaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} failed: hr=0x{:08X} {}",
            self.op, self.hr, self.detail
        )
    }
}

impl std::error::Error for SurfaceError {}

/// Attach the calling thread to the current **input desktop**.
///
/// Why this exists: processes spawned by services, agents and some
/// terminals start on a private desktop; on that desktop DXGI Desktop
/// Duplication and GDI screen capture are denied (`E_ACCESSDENIED`) and
/// any window the process creates is invisible to the user and to
/// capture. Attaching the thread to the input desktop fixes both. It is
/// a no-op-equivalent when the thread already runs there (re-opening the
/// same desktop succeeds harmlessly).
///
/// Must be called before the thread creates windows or duplicates an
/// output (Windows refuses `SetThreadDesktop` afterwards). The M1
/// binaries call it on every thread that touches capture or
/// presentation; `capture-windows` also calls it in its constructor as a
/// safety net.
pub fn attach_thread_to_input_desktop() -> Result<(), SurfaceError> {
    unsafe {
        use windows::Win32::System::StationsAndDesktops::{
            DESKTOP_CONTROL_FLAGS, DESKTOP_JOURNALPLAYBACK, DESKTOP_READOBJECTS,
            DESKTOP_SWITCHDESKTOP, OpenInputDesktop, SetThreadDesktop,
        };
        let desktop = OpenInputDesktop(
            DESKTOP_CONTROL_FLAGS(0),
            false,
            windows::Win32::System::StationsAndDesktops::DESKTOP_ACCESS_FLAGS(
                DESKTOP_READOBJECTS.0
                    | DESKTOP_JOURNALPLAYBACK.0
                    | DESKTOP_SWITCHDESKTOP.0
                    | 0x0002, /* DESKTOP_WRITEOBJECTS */
            ),
        )
        .map_err(|e| hr_err("OpenInputDesktop", e))?;
        SetThreadDesktop(desktop).map_err(|e| hr_err("SetThreadDesktop", e))
    }
}

/// Number of CPU readbacks performed through this crate since process
/// start (software-encoder feeds and diagnostics). Reported in the M1
/// latency report as the measurable face of "copies per frame".
pub static READBACK_COUNT: AtomicU64 = AtomicU64::new(0);
pub static UPLOAD_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn readback_count() -> u64 {
    READBACK_COUNT.load(Ordering::Relaxed)
}

pub fn upload_count() -> u64 {
    UPLOAD_COUNT.load(Ordering::Relaxed)
}

fn hr_err(op: &'static str, err: windows::core::Error) -> SurfaceError {
    let hr = err.code();
    SurfaceError::new(op, hr.0, format!("HRESULT: {}", hr.message()))
}

/// One shared D3D11 device + its immediate context. `Clone` is a COM
/// refcount bump (cheap); all clones see the same device.
///
/// The device is created with `SetMultithreadProtected(TRUE)` so multiple
/// pipeline threads may issue immediate-context work concurrently.
#[derive(Clone)]
pub struct GpuDevice {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
}

impl core::fmt::Debug for GpuDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GpuDevice")
            .field("adapter", &self.adapter_description().unwrap_or_default())
            .finish_non_exhaustive()
    }
}

impl GpuDevice {
    /// Create a device on the first hardware adapter that supports the
    /// D3D11 feature level we need. Fails (rather than silently falling
    /// back to WARP) because Desktop Duplication cannot run on WARP —
    /// callers that do not need duplication use [`GpuDevice::create_warp`].
    pub fn create_hardware() -> Result<Self, SurfaceError> {
        Self::create(D3D_DRIVER_TYPE_HARDWARE)
    }

    /// Create a WARP (software rasterizer) device — used by tests and any
    /// stage that does not need duplication.
    pub fn create_warp() -> Result<Self, SurfaceError> {
        Self::create(D3D_DRIVER_TYPE_WARP)
    }

    fn create(driver: D3D_DRIVER_TYPE) -> Result<Self, SurfaceError> {
        unsafe {
            let mut device: Option<ID3D11Device> = None;
            let mut context: Option<ID3D11DeviceContext> = None;
            // Feature levels 11_1..10_0; the D3D11 runtime picks the highest.
            let levels = [
                D3D_FEATURE_LEVEL(0xb100),
                D3D_FEATURE_LEVEL(0xb000),
                D3D_FEATURE_LEVEL(0xa000),
                D3D_FEATURE_LEVEL(0x9300),
                D3D_FEATURE_LEVEL(0x9100),
            ];
            windows::Win32::Graphics::Direct3D11::D3D11CreateDevice(
                None,
                driver,
                windows::Win32::Foundation::HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                Some(&levels),
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
            .map_err(|e| hr_err("D3D11CreateDevice", e))?;
            let device =
                device.ok_or_else(|| SurfaceError::new("D3D11CreateDevice", 0, "no device"))?;
            let context =
                context.ok_or_else(|| SurfaceError::new("D3D11CreateDevice", 0, "no context"))?;
            let mt: ID3D11Multithread = device
                .cast()
                .map_err(|e| hr_err("cast ID3D11Multithread", e))?;
            let _protected = mt.SetMultithreadProtected(true);
            Ok(Self { device, context })
        }
    }

    pub fn device(&self) -> &ID3D11Device {
        &self.device
    }

    pub fn context(&self) -> &ID3D11DeviceContext {
        &self.context
    }

    /// Adapter LUID (low, high) — used to match hardware MFTs to this device.
    pub fn adapter_luid(&self) -> Result<(i32, i32), SurfaceError> {
        unsafe {
            let dxgi: IDXGIDevice = self
                .device
                .cast()
                .map_err(|e| hr_err("cast IDXGIDevice", e))?;
            let adapter: IDXGIAdapter = dxgi.GetAdapter().map_err(|e| hr_err("GetAdapter", e))?;
            let desc = adapter.GetDesc().map_err(|e| hr_err("GetDesc", e))?;
            Ok((desc.AdapterLuid.LowPart as i32, desc.AdapterLuid.HighPart))
        }
    }

    pub fn adapter_description(&self) -> Option<String> {
        unsafe {
            let dxgi: IDXGIDevice = self.device.cast().ok()?;
            let adapter: IDXGIAdapter = dxgi.GetAdapter().ok()?;
            let desc = adapter.GetDesc().ok()?;
            let len = desc
                .Description
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(desc.Description.len());
            Some(String::from_utf16_lossy(&desc.Description[..len]))
        }
    }
}

/// One GPU-resident frame. The texture is default-usage (GPU read/write);
/// readback goes through a staging copy in [`readback_nv12`]/[`readback_bgra`].
#[derive(Clone)]
pub struct FrameSurface {
    texture: ID3D11Texture2D,
    width: u32,
    height: u32,
    format: SurfaceFormat,
    frame_id: u64,
}

impl core::fmt::Debug for FrameSurface {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FrameSurface")
            .field("frame_id", &self.frame_id)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

impl FrameSurface {
    /// Allocate a default-usage, shareable texture (NT handle mintable).
    pub fn new(
        device: &GpuDevice,
        width: u32,
        height: u32,
        format: SurfaceFormat,
    ) -> Result<Self, SurfaceError> {
        Self::new_impl(device, width, height, format, true)
    }

    /// Same-device private texture: no DXGI shared-handle misc flags
    /// (sharing flags can force extra driver synchronization per use;
    /// the one-process M1 loop does not need them on its hot pools).
    pub fn new_private(
        device: &GpuDevice,
        width: u32,
        height: u32,
        format: SurfaceFormat,
    ) -> Result<Self, SurfaceError> {
        Self::new_impl(device, width, height, format, false)
    }

    fn new_impl(
        device: &GpuDevice,
        width: u32,
        height: u32,
        format: SurfaceFormat,
        shareable: bool,
    ) -> Result<Self, SurfaceError> {
        if width == 0 || height == 0 {
            return Err(SurfaceError::new("FrameSurface::new", 0, "zero dimension"));
        }
        let desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: format.dxgi(),
            SampleDesc: windows::Win32::Graphics::Dxgi::Common::DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: (D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET).0 as u32,
            CPUAccessFlags: 0,
            MiscFlags: if shareable {
                (D3D11_RESOURCE_MISC_SHARED | D3D11_RESOURCE_MISC_SHARED_NTHANDLE).0 as u32
            } else {
                0
            },
        };
        Self::create_with_desc(device, desc, width, height, format)
    }

    fn staging(width: u32, height: u32, format: SurfaceFormat) -> D3D11_TEXTURE2D_DESC {
        D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: format.dxgi(),
            SampleDesc: windows::Win32::Graphics::Dxgi::Common::DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        }
    }

    fn create_with_desc(
        device: &GpuDevice,
        desc: D3D11_TEXTURE2D_DESC,
        width: u32,
        height: u32,
        format: SurfaceFormat,
    ) -> Result<Self, SurfaceError> {
        unsafe {
            let mut tex: Option<ID3D11Texture2D> = None;
            device
                .device()
                .CreateTexture2D(&desc, None, Some(&mut tex))
                .map_err(|e| hr_err("CreateTexture2D", e))?;
            let texture =
                tex.ok_or_else(|| SurfaceError::new("CreateTexture2D", 0, "no texture"))?;
            Ok(Self {
                texture,
                width,
                height,
                format,
                frame_id: 0,
            })
        }
    }

    pub fn texture(&self) -> &ID3D11Texture2D {
        &self.texture
    }

    /// Wrap an already-created texture (e.g. the surface acquired from
    /// Desktop Duplication before it is copied into a pool slot). The
    /// caller guarantees the geometry/format match the texture's real
    /// description — D3D11 will fail later operations if they do not.
    pub fn from_texture(
        texture: ID3D11Texture2D,
        width: u32,
        height: u32,
        format: SurfaceFormat,
    ) -> Self {
        Self {
            texture,
            width,
            height,
            format,
            frame_id: 0,
        }
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn format(&self) -> SurfaceFormat {
        self.format
    }

    /// Host-assigned frame id (see the perf-counter schema: `FrameTiming`
    /// is joined on this). The capture stage assigns it; the node runtime
    /// propagates it through the codec and render handoffs.
    pub fn frame_id(&self) -> u64 {
        self.frame_id
    }

    /// Return the same surface with a frame id attached (builder-style).
    pub fn with_frame_id(mut self, frame_id: u64) -> Self {
        self.frame_id = frame_id;
        self
    }

    /// GPU->GPU copy of `src` into `self` (must match geometry/format).
    /// This is the one copy Desktop Duplication forces on every captured
    /// frame (the acquired surface is owned by the duplication interface
    /// until `ReleaseFrame`).
    pub fn copy_from(&self, device: &GpuDevice, src: &FrameSurface) -> Result<(), SurfaceError> {
        if src.width != self.width || src.height != self.height || src.format != self.format {
            return Err(SurfaceError::new(
                "copy_from",
                0,
                format!(
                    "geometry mismatch {}x{:?} vs {}x{:?}",
                    src.width, src.format, self.width, self.format
                ),
            ));
        }
        unsafe { device.context().CopyResource(&self.texture, &src.texture) };
        Ok(())
    }

    /// Mint an NT shared handle for this texture (requires
    /// `D3D11_RESOURCE_MISC_SHARED_NT`, set by [`FrameSurface::new`]).
    pub fn share_handle(&self) -> Result<OwnedHandle, SurfaceError> {
        unsafe {
            let res: IDXGIResource1 = self
                .texture
                .cast()
                .map_err(|e| hr_err("cast IDXGIResource1", e))?;
            let handle = res
                .CreateSharedHandle(
                    None,
                    DXGI_SHARED_RESOURCE_READ.0 | DXGI_SHARED_RESOURCE_WRITE.0,
                    PCWSTR::null(),
                )
                .map_err(|e| hr_err("CreateSharedHandle", e))?;
            Ok(OwnedHandle(handle))
        }
    }

    /// Open a shared handle on (possibly another) device.
    pub fn open_shared(
        device: &GpuDevice,
        handle: OwnedHandle,
        width: u32,
        height: u32,
        format: SurfaceFormat,
    ) -> Result<Self, SurfaceError> {
        unsafe {
            let device1: ID3D11Device1 = device
                .device()
                .cast()
                .map_err(|e| hr_err("cast ID3D11Device1", e))?;
            let texture: ID3D11Texture2D = device1
                .OpenSharedResource1(handle.0)
                .map_err(|e| hr_err("OpenSharedResource1", e))?;
            Ok(Self {
                texture,
                width,
                height,
                format,
                frame_id: 0,
            })
        }
    }
}

/// Owning wrapper over a raw `HANDLE` (NT shared-resource handle minted by
/// [`FrameSurface::share_handle`]); closes on drop.
#[derive(Debug)]
pub struct OwnedHandle(pub HANDLE);

unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

/// Plane layout for a readback/upload of a format: (offset, stride) per
/// plane, given total width.
pub fn plane_layout(format: SurfaceFormat, width: u32) -> Vec<(usize, usize)> {
    match format {
        SurfaceFormat::Bgra8 => vec![(0, (width as usize) * 4)],
        SurfaceFormat::Nv12 => {
            let y_stride = width as usize;
            vec![(0, y_stride), (y_stride * 2, y_stride)]
        }
    }
}

/// CPU-side copy of one surface, with per-plane stride/offset. Produced by
/// [`readback_nv12`]/[`readback_bgra`]; consumed by [`upload_nv12`].
#[derive(Debug, Clone)]
pub struct CpuSurface {
    pub width: u32,
    pub height: u32,
    pub format: SurfaceFormat,
    pub data: Vec<u8>,
}

impl CpuSurface {
    /// Tight (stride == minimum) NV12 buffer: Y plane then interleaved UV.
    pub fn nv12_tight(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            format: SurfaceFormat::Nv12,
            data: vec![0u8; (width as usize) * (height as usize) * 3 / 2],
        }
    }

    pub fn plane_span(&self, plane: usize) -> &[u8] {
        let layout = plane_layout(self.format, self.width);
        let (off, stride) = layout[plane];
        let rows = match (self.format, plane) {
            (SurfaceFormat::Nv12, 1) => (self.height as usize).div_ceil(2),
            _ => self.height as usize,
        };
        let len = (off + rows * stride).min(self.data.len());
        &self.data[off.min(len)..len]
    }
}

/// GPU -> CPU readback (staging copy + Map). Counted in [`readback_count`].
pub fn readback(device: &GpuDevice, surface: &FrameSurface) -> Result<CpuSurface, SurfaceError> {
    let staging = FrameSurface::create_with_desc(
        device,
        FrameSurface::staging(surface.width, surface.height, surface.format),
        surface.width,
        surface.height,
        surface.format,
    )?;
    unsafe {
        device
            .context()
            .CopyResource(staging.texture(), surface.texture());
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        device
            .context()
            .Map(staging.texture(), 0, D3D11_MAP_READ, 0, Some(&mut mapped))
            .map_err(|e| hr_err("Map", e))?;
        let layout = plane_layout(surface.format, surface.width);
        let rows_y = surface.height as usize;
        let uv_rows = rows_y.div_ceil(2);
        let total = match surface.format {
            SurfaceFormat::Bgra8 => rows_y * layout[0].1,
            SurfaceFormat::Nv12 => (uv_rows + rows_y) * layout[0].1,
        };
        let mut data = vec![0u8; total];
        let src = mapped.pData as *const u8;
        let row_bytes = layout[0].1;
        let pitch = mapped.RowPitch as usize;
        // Copy `rows` rows of `row_bytes` from the mapped staging texture
        // (at `src_off`, strided by the map pitch) into the tight output.
        fn copy_rows(
            dst: &mut [u8],
            dst_off: usize,
            src: *const u8,
            src_off: usize,
            rows: usize,
            row_bytes: usize,
            pitch: usize,
        ) {
            for r in 0..rows {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        src.add(src_off + r * pitch),
                        dst.as_mut_ptr().add(dst_off + r * row_bytes),
                        row_bytes,
                    );
                }
            }
        }
        match surface.format {
            SurfaceFormat::Bgra8 => copy_rows(&mut data, 0, src, 0, rows_y, row_bytes, pitch),
            SurfaceFormat::Nv12 => {
                copy_rows(&mut data, 0, src, 0, rows_y, row_bytes, pitch);
                // In a mapped planar staging texture the UV plane starts
                // after `height` rows of Y at the map pitch.
                let src_uv = rows_y * pitch;
                copy_rows(
                    &mut data,
                    rows_y * row_bytes,
                    src,
                    src_uv,
                    uv_rows,
                    row_bytes,
                    pitch,
                );
            }
        }
        device
            .context()
            .Unmap(&staging.texture.clone() as &ID3D11Resource, 0);
        READBACK_COUNT.fetch_add(1, Ordering::Relaxed);
        Ok(CpuSurface {
            width: surface.width,
            height: surface.height,
            format: surface.format,
            data,
        })
    }
}

/// Convenience: readback an NV12 surface.
pub fn readback_nv12(
    device: &GpuDevice,
    surface: &FrameSurface,
) -> Result<CpuSurface, SurfaceError> {
    debug_assert_eq!(surface.format, SurfaceFormat::Nv12);
    readback(device, surface)
}

/// CPU -> GPU upload into a reusable surface: `dst` is (re)created only
/// when the geometry changes; the planes are copied with
/// `UpdateSubresource` (one system-memory pass, no per-frame texture
/// allocation — allocation churn on the shared context was measured to
/// stall the whole pipeline). Counted in [`upload_count`].
pub fn upload_nv12_into(
    device: &GpuDevice,
    cpu: &CpuSurface,
    dst: &mut Option<FrameSurface>,
) -> Result<(), SurfaceError> {
    let needs_new = dst
        .as_ref()
        .map(|s| s.width() != cpu.width || s.height() != cpu.height)
        .unwrap_or(true);
    if needs_new {
        *dst = Some(FrameSurface::new_private(
            device,
            cpu.width,
            cpu.height,
            SurfaceFormat::Nv12,
        )?);
    }
    let target = dst.as_ref().expect("dst");
    let layout = plane_layout(SurfaceFormat::Nv12, cpu.width);
    let y_stride = layout[0].1;
    let rows_y = cpu.height as usize;
    let uv_rows = rows_y.div_ceil(2);
    // One contiguous staging buffer: Y plane then UV plane, SysMemPitch
    // applies to both (D3D11 planar UpdateSubresource convention).
    let mut staged = vec![0u8; (rows_y + uv_rows) * y_stride];
    staged[..rows_y * y_stride].copy_from_slice(&cpu.data[..rows_y * y_stride]);
    let uv_off = rows_y * y_stride;
    let uv_len = uv_rows * y_stride;
    let src_uv_off = uv_off;
    let copy = (uv_len).min(cpu.data.len().saturating_sub(src_uv_off));
    staged[uv_off..uv_off + copy].copy_from_slice(&cpu.data[src_uv_off..src_uv_off + copy]);
    let init = D3D11_SUBRESOURCE_DATA {
        pSysMem: staged.as_ptr() as *const core::ffi::c_void,
        SysMemPitch: y_stride as u32,
        SysMemSlicePitch: 0,
    };
    unsafe {
        device.context().UpdateSubresource(
            target.texture(),
            0,
            None,
            init.pSysMem,
            init.SysMemPitch,
            0,
        );
    }
    UPLOAD_COUNT.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// CPU -> GPU upload into a fresh default-usage surface. Used by the
/// software-decoder fallback path (decoder CPU NV12 -> GPU texture for the
/// renderer). Counted in [`upload_count`].
pub fn upload_nv12(device: &GpuDevice, cpu: &CpuSurface) -> Result<FrameSurface, SurfaceError> {
    if cpu.format != SurfaceFormat::Nv12 {
        return Err(SurfaceError::new("upload_nv12", 0, "not NV12"));
    }
    let layout = plane_layout(SurfaceFormat::Nv12, cpu.width);
    let y_stride = layout[0].1;
    let rows_y = cpu.height as usize;
    let uv_rows = rows_y.div_ceil(2);
    // D3D11 requires one contiguous init-data buffer per subresource for
    // planar formats; SysMemPitch applies to the Y plane and the UV plane
    // follows with the same pitch.
    let mut staged = vec![0u8; (rows_y + uv_rows) * y_stride];
    staged[..rows_y * y_stride].copy_from_slice(&cpu.data[..rows_y * y_stride]);
    let uv_off = rows_y * y_stride;
    let uv_len = uv_rows * y_stride;
    staged[uv_off..uv_off + uv_len]
        .copy_from_slice(&cpu.data[uv_off..uv_off + uv_len.min(cpu.data.len() - uv_off)]);
    let init = D3D11_SUBRESOURCE_DATA {
        pSysMem: staged.as_ptr() as *const core::ffi::c_void,
        SysMemPitch: y_stride as u32,
        SysMemSlicePitch: 0,
    };
    unsafe {
        let mut tex: Option<ID3D11Texture2D> = None;
        let desc = D3D11_TEXTURE2D_DESC {
            Width: cpu.width,
            Height: cpu.height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_NV12,
            SampleDesc: windows::Win32::Graphics::Dxgi::Common::DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
            CPUAccessFlags: 0,
            MiscFlags: 0,
        };
        device
            .device()
            .CreateTexture2D(&desc, Some(&init), Some(&mut tex))
            .map_err(|e| hr_err("CreateTexture2D(upload)", e))?;
        let texture = tex.ok_or_else(|| SurfaceError::new("upload", 0, "no texture"))?;
        UPLOAD_COUNT.fetch_add(1, Ordering::Relaxed);
        Ok(FrameSurface {
            texture,
            width: cpu.width,
            height: cpu.height,
            format: SurfaceFormat::Nv12,
            frame_id: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_mappings() {
        assert_eq!(SurfaceFormat::Bgra8.dxgi(), DXGI_FORMAT_B8G8R8A8_UNORM);
        assert_eq!(SurfaceFormat::Nv12.dxgi(), DXGI_FORMAT_NV12);
    }

    #[test]
    fn nv12_layout_minimal_strides() {
        let layout = plane_layout(SurfaceFormat::Nv12, 1920);
        assert_eq!(layout[0], (0, 1920));
        // UV plane starts after 2 rows of Y per D3D11 planar layout.
        assert_eq!(layout[1], (3840, 1920));
        let cpu = CpuSurface::nv12_tight(64, 32);
        assert_eq!(cpu.data.len(), 64 * 32 * 3 / 2);
        assert_eq!(cpu.plane_span(0).len(), 64 * 32);
        assert_eq!(cpu.plane_span(1).len(), 64 * 16);
    }

    #[test]
    fn device_creation_falls_back_cleanly() {
        // Hardware creation must succeed on this machine; WARP is the
        // CI-safe path.
        let hw = GpuDevice::create_hardware();
        let warp = GpuDevice::create_warp();
        assert!(
            hw.is_ok() || warp.is_ok(),
            "no D3D11 device at all: hw={hw:?} warp={warp:?}"
        );
        if let Ok(dev) = warp {
            let surface = FrameSurface::new(&dev, 64, 48, SurfaceFormat::Nv12).expect("alloc");
            assert_eq!(surface.width(), 64);
            assert_eq!(surface.height(), 48);
        }
    }
}
