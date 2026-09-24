//! D3D11 swapchain + video-processor presentation.

use windows::Win32::Foundation::{HWND, RECT};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_TEX2D_VPIV, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE, D3D11_VIDEO_PROCESSOR_CONTENT_DESC,
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0,
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_STREAM,
    D3D11_VIDEO_USAGE_OPTIMAL_SPEED, D3D11_VPIV_DIMENSION_TEXTURE2D,
    D3D11_VPOV_DIMENSION_TEXTURE2D, ID3D11Texture2D, ID3D11VideoContext, ID3D11VideoContext1,
    ID3D11VideoDevice, ID3D11VideoProcessor, ID3D11VideoProcessorEnumerator,
    ID3D11VideoProcessorInputView, ID3D11VideoProcessorOutputView,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709, DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709,
    DXGI_FORMAT_B8G8R8A8_UNORM,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory2, DXGI_CREATE_FACTORY_FLAGS, DXGI_ERROR_DEVICE_REMOVED,
    DXGI_ERROR_DEVICE_RESET, DXGI_SWAP_CHAIN_DESC1, DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL,
    DXGI_USAGE_RENDER_TARGET_OUTPUT, IDXGISwapChain1,
};
use windows::core::Interface;

use frame_surface::{GpuDevice, SurfaceFormat};

use crate::{CursorOverlay, FrameRenderer, RenderError, RenderFrame, ScaleMode, fit_rect};

/// D3D11 flip-model swapchain presentation through `ID3D11VideoProcessor`
/// (NV12 or BGRA input -> BGRA backbuffer).
pub struct D3D11Renderer {
    device: GpuDevice,
    video_device: ID3D11VideoDevice,
    video_context: ID3D11VideoContext,
    video_context1: Option<ID3D11VideoContext1>,
    enumerator: ID3D11VideoProcessorEnumerator,
    processor: ID3D11VideoProcessor,
    swapchain: IDXGISwapChain1,
    backbuffer: Option<ID3D11Texture2D>,
    output_view: Option<ID3D11VideoProcessorOutputView>,
    target_size: (u32, u32),
    scale_mode: ScaleMode,
    cursor: Option<CursorOverlay>,
    /// Cached input views per source texture (decoded-surface rings
    /// reuse slots). A fresh view per frame leaked driver resources
    /// until device suspension — measured and fixed.
    input_views: std::collections::HashMap<usize, ID3D11VideoProcessorInputView>,
    pub frames_presented: u64,
}

impl D3D11Renderer {
    pub fn new(
        device: GpuDevice,
        hwnd: HWND,
        width: u32,
        height: u32,
    ) -> Result<Self, RenderError> {
        unsafe {
            let err = |op: &'static str, e: windows::core::Error| {
                let code = e.code();
                if code == DXGI_ERROR_DEVICE_REMOVED || code == DXGI_ERROR_DEVICE_RESET {
                    RenderError::DeviceLost(e.message().to_string())
                } else {
                    RenderError::api(op, code.0, e.message().to_string())
                }
            };
            let factory: windows::Win32::Graphics::Dxgi::IDXGIFactory2 =
                CreateDXGIFactory2(DXGI_CREATE_FACTORY_FLAGS(0))
                    .map_err(|e| err("CreateDXGIFactory2", e))?;
            let desc = DXGI_SWAP_CHAIN_DESC1 {
                Width: width.max(1),
                Height: height.max(1),
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                Stereo: false.into(),
                SampleDesc: windows::Win32::Graphics::Dxgi::Common::DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
                BufferCount: 2,
                Scaling: windows::Win32::Graphics::Dxgi::DXGI_SCALING_NONE,
                SwapEffect: DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL,
                AlphaMode: windows::Win32::Graphics::Dxgi::Common::DXGI_ALPHA_MODE_IGNORE,
                Flags: 0,
            };
            let swapchain = factory
                .CreateSwapChainForHwnd(device.device(), hwnd, &desc, None, None)
                .map_err(|e| err("CreateSwapChainForHwnd", e))?;

            let video_device: ID3D11VideoDevice = device
                .device()
                .cast()
                .map_err(|e| err("cast ID3D11VideoDevice", e))?;
            let video_context: ID3D11VideoContext = device
                .context()
                .cast()
                .map_err(|e| err("cast ID3D11VideoContext", e))?;
            let video_context1 = device.context().cast::<ID3D11VideoContext1>().ok();
            let content = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
                InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
                InputWidth: width.max(1),
                InputHeight: height.max(1),
                OutputWidth: width.max(1),
                OutputHeight: height.max(1),
                Usage: D3D11_VIDEO_USAGE_OPTIMAL_SPEED,
                ..Default::default()
            };
            let enumerator = video_device
                .CreateVideoProcessorEnumerator(&content)
                .map_err(|e| err("CreateVideoProcessorEnumerator", e))?;
            let processor = video_device
                .CreateVideoProcessor(&enumerator, 0)
                .map_err(|e| err("CreateVideoProcessor", e))?;

            let mut renderer = Self {
                device,
                video_device,
                video_context,
                video_context1,
                enumerator,
                processor,
                swapchain,
                backbuffer: None,
                output_view: None,
                target_size: (width, height),
                scale_mode: ScaleMode::Fit,
                cursor: None,
                input_views: std::collections::HashMap::new(),
                frames_presented: 0,
            };
            renderer.bind_backbuffer()?;
            Ok(renderer)
        }
    }

    fn bind_backbuffer(&mut self) -> Result<(), RenderError> {
        unsafe {
            let buffer: ID3D11Texture2D = self
                .swapchain
                .GetBuffer(0)
                .map_err(|e| RenderError::api("GetBuffer", e.code().0, "backbuffer"))?;
            let mut desc = Default::default();
            buffer.GetDesc(&mut desc);
            self.target_size = (desc.Width, desc.Height);
            let output_desc = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
                ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
                Anonymous: Default::default(),
            };
            let mut view: Option<ID3D11VideoProcessorOutputView> = None;
            self.video_device
                .CreateVideoProcessorOutputView(
                    &buffer,
                    &self.enumerator,
                    &output_desc,
                    Some(&mut view),
                )
                .map_err(|e| {
                    RenderError::api("CreateVideoProcessorOutputView", e.code().0, "present")
                })?;
            self.output_view = view;
            self.backbuffer = Some(buffer);
            Ok(())
        }
    }

    /// Resize the swapchain (call from WM_SIZE handling).
    pub fn resize(&mut self, width: u32, height: u32) -> Result<(), RenderError> {
        unsafe {
            self.output_view = None;
            self.backbuffer = None;
            self.swapchain
                .ResizeBuffers(
                    0,
                    width.max(1),
                    height.max(1),
                    DXGI_FORMAT_B8G8R8A8_UNORM,
                    Default::default(),
                )
                .map_err(|e| {
                    let code = e.code();
                    if code == DXGI_ERROR_DEVICE_REMOVED || code == DXGI_ERROR_DEVICE_RESET {
                        RenderError::DeviceLost(e.message().to_string())
                    } else {
                        RenderError::api("ResizeBuffers", code.0, e.message().to_string())
                    }
                })?;
            self.bind_backbuffer()
        }
    }

    pub fn client_size(&self) -> (u32, u32) {
        self.target_size
    }
}

impl FrameRenderer for D3D11Renderer {
    fn present(&mut self, frame: &RenderFrame) -> Result<(), RenderError> {
        unsafe {
            let Some(output_view) = self.output_view.clone() else {
                return Err(RenderError::Surface("no output view".into()));
            };
            let input_desc = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
                FourCC: Default::default(),
                ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
                Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                    Texture2D: D3D11_TEX2D_VPIV {
                        MipSlice: 0,
                        ArraySlice: 0,
                    },
                },
            };
            // Cached per source texture (the decoder's surface ring
            // reuses slots): a fresh view per frame leaked driver
            // resources — measured as a slow working-set climb until the
            // cache was added.
            let key = frame.surface.texture().as_raw() as usize;
            let input_view = match self.input_views.get(&key) {
                Some(view) => view.clone(),
                None => {
                    let mut input_view: Option<ID3D11VideoProcessorInputView> = None;
                    self.video_device
                        .CreateVideoProcessorInputView(
                            frame.surface.texture(),
                            &self.enumerator,
                            &input_desc,
                            Some(&mut input_view),
                        )
                        .map_err(|e| {
                            RenderError::api("CreateVideoProcessorInputView", e.code().0, "present")
                        })?;
                    let view =
                        input_view.ok_or_else(|| RenderError::Surface("no input view".into()))?;
                    if self.input_views.len() >= 16 {
                        // Ring rebuilt / resolution change: drop stale.
                        self.input_views.clear();
                    }
                    self.input_views.insert(key, view.clone());
                    view
                }
            };

            // Source: the visible area (DXVA surfaces may be padded).
            let src_rect = RECT {
                left: 0,
                top: 0,
                right: frame.width_px.min(frame.surface.width()) as i32,
                bottom: frame.height_px.min(frame.surface.height()) as i32,
            };
            // Destination: fit or 1:1 into the backbuffer.
            let (dx, dy, dw, dh) = match self.scale_mode {
                ScaleMode::Fit => fit_rect(
                    frame.width_px,
                    frame.height_px,
                    self.target_size.0,
                    self.target_size.1,
                ),
                ScaleMode::OneToOne => (
                    0,
                    0,
                    frame.width_px.min(self.target_size.0),
                    frame.height_px.min(self.target_size.1),
                ),
            };
            let dst_rect = RECT {
                left: dx,
                top: dy,
                right: dx + dw as i32,
                bottom: dy + dh as i32,
            };
            self.video_context.VideoProcessorSetStreamSourceRect(
                &self.processor,
                0,
                true,
                Some(&src_rect),
            );
            self.video_context.VideoProcessorSetStreamDestRect(
                &self.processor,
                0,
                true,
                Some(&dst_rect),
            );

            // Color space: the same pairing the encode-side converter
            // used, inverted. NV12 input is BT.709 studio; BGRA preview
            // input is sRGB full.
            match frame.surface.format() {
                SurfaceFormat::Nv12 => {
                    if let Some(vc1) = &self.video_context1 {
                        vc1.VideoProcessorSetStreamColorSpace1(
                            &self.processor,
                            0,
                            DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709,
                        );
                        vc1.VideoProcessorSetOutputColorSpace1(
                            &self.processor,
                            DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709,
                        );
                    }
                }
                SurfaceFormat::Bgra8 => {
                    if let Some(vc1) = &self.video_context1 {
                        vc1.VideoProcessorSetStreamColorSpace1(
                            &self.processor,
                            0,
                            DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709,
                        );
                        vc1.VideoProcessorSetOutputColorSpace1(
                            &self.processor,
                            DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709,
                        );
                    }
                }
            }

            let stream = D3D11_VIDEO_PROCESSOR_STREAM {
                Enable: true.into(),
                pInputSurface: core::mem::ManuallyDrop::new(Some(input_view)),
                ..Default::default()
            };
            self.video_context
                .VideoProcessorBlt(&self.processor, &output_view, 0, &[stream])
                .map_err(|e| RenderError::api("VideoProcessorBlt", e.code().0, "present"))?;

            // Present(0, 0): do not wait — present_ns measures submission.
            let hr = self.swapchain.Present(0, Default::default());
            if hr.is_err() {
                if hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET {
                    return Err(RenderError::DeviceLost(hr.message().to_string()));
                }
                return Err(RenderError::api("Present", hr.0, hr.message().to_string()));
            }
            self.frames_presented += 1;
            let _ = &self.device;
            let _ = &self.cursor;
            Ok(())
        }
    }

    fn set_cursor(&mut self, overlay: Option<CursorOverlay>) {
        // Stored only in M1 (delta D4); GPU compositing lands with the
        // cursor-channel wiring in M2.
        self.cursor = overlay;
    }

    fn set_scale_mode(&mut self, mode: ScaleMode) {
        self.scale_mode = mode;
    }
}
