//! BGRA -> NV12 (with scaling) via `ID3D11VideoProcessor`.
//!
//! This is the "GPU color conversion" stage of the source-plan host
//! pipeline (`DXGI capture -> dirty/move analysis -> GPU color conversion
//! -> H.264 encoder`). One `VideoProcessorBlt` per frame; the input is
//! the captured BGRA surface, the output is the encoder's NV12 input at
//! the encode resolution (e.g. 2560x1440 desktop -> 1920x1080 encode).
//! Color spaces: sRGB full-range RGB -> BT.709 studio-range YCbCr, the
//! standard remote-desktop pairing.

use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_TEX2D_VPIV, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE, D3D11_VIDEO_PROCESSOR_CONTENT_DESC,
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0,
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_STREAM,
    D3D11_VIDEO_USAGE_OPTIMAL_SPEED, D3D11_VPIV_DIMENSION_TEXTURE2D,
    D3D11_VPOV_DIMENSION_TEXTURE2D, ID3D11VideoContext, ID3D11VideoContext1, ID3D11VideoDevice,
    ID3D11VideoProcessor, ID3D11VideoProcessorEnumerator, ID3D11VideoProcessorInputView,
    ID3D11VideoProcessorOutputView,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709, DXGI_COLOR_SPACE_TYPE,
    DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709,
};
use windows::core::Interface;

use frame_surface::{FrameSurface, GpuDevice};

use crate::CodecError;

/// Reusable BGRA->NV12 converter bound to the shared device. Not `Send`
/// by COM rules — construct one per encode thread.
pub struct Nv12Converter {
    device: GpuDevice,
    video_device: ID3D11VideoDevice,
    video_context: ID3D11VideoContext,
    video_context1: Option<ID3D11VideoContext1>,
    enumerator: ID3D11VideoProcessorEnumerator,
    processor: ID3D11VideoProcessor,
    input_width: u32,
    input_height: u32,
    output_width: u32,
    output_height: u32,
    /// Per-texture view caches (pool rings reuse a handful of slots).
    input_views: std::collections::HashMap<usize, ID3D11VideoProcessorInputView>,
    output_views: std::collections::HashMap<usize, ID3D11VideoProcessorOutputView>,
}

impl Nv12Converter {
    /// `input` geometry is the capture size; `output` the encode size.
    /// Both must be even (NV12 chroma subsampling).
    pub fn new(
        device: GpuDevice,
        input_width: u32,
        input_height: u32,
        output_width: u32,
        output_height: u32,
    ) -> Result<Self, CodecError> {
        let err = |e: windows::core::Error| CodecError::Processing(e.message().to_string());
        unsafe {
            let video_device: ID3D11VideoDevice = device.device().cast().map_err(err)?;
            let video_context: ID3D11VideoContext = device.context().cast().map_err(|e| {
                CodecError::Processing(format!("cast ID3D11VideoContext: {}", e.message()))
            })?;
            let video_context1 = device.context().cast::<ID3D11VideoContext1>().ok();
            let desc = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
                InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
                InputWidth: input_width,
                InputHeight: input_height,
                OutputWidth: output_width,
                OutputHeight: output_height,
                Usage: D3D11_VIDEO_USAGE_OPTIMAL_SPEED,
                ..Default::default()
            };
            let enumerator = video_device
                .CreateVideoProcessorEnumerator(&desc)
                .map_err(|e| {
                    CodecError::Processing(format!(
                        "CreateVideoProcessorEnumerator: {}",
                        e.message()
                    ))
                })?;
            let processor = video_device
                .CreateVideoProcessor(&enumerator, 0)
                .map_err(|e| {
                    CodecError::Processing(format!("CreateVideoProcessor: {}", e.message()))
                })?;
            let mut converter = Self {
                device,
                video_device,
                video_context,
                video_context1,
                enumerator,
                processor,
                input_width,
                input_height,
                output_width,
                output_height,
                input_views: std::collections::HashMap::new(),
                output_views: std::collections::HashMap::new(),
            };
            converter.set_colorspaces()?;
            Ok(converter)
        }
    }

    /// The capture geometry this converter currently accepts.
    pub fn input_geometry(&self) -> (u32, u32) {
        (self.input_width, self.input_height)
    }

    fn set_colorspaces(&mut self) -> Result<(), CodecError> {
        unsafe {
            if let Some(vc1) = &self.video_context1 {
                // sRGB full range -> BT.709 limited range (void methods:
                // failure falls through to the legacy path silently).
                vc1.VideoProcessorSetStreamColorSpace1(
                    &self.processor,
                    0,
                    DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709,
                );
                vc1.VideoProcessorSetOutputColorSpace1(
                    &self.processor,
                    DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709,
                );
                return Ok(());
            }
            // Legacy fallback (pre-D3D11.1): bitfield-packed color space.
            // Layout: Usage:2 | RGB_Range:1 | YCbCr_Matrix:1 | Nominal_Range:3.
            // Stream: full-range RGB in; output: 709 matrix, studio range.
            let pack = |usage: u32, rgb_range: u32, matrix: u32, nominal: u32| {
                windows::Win32::Graphics::Direct3D11::D3D11_VIDEO_PROCESSOR_COLOR_SPACE {
                    _bitfield: usage | (rgb_range << 2) | (matrix << 3) | (nominal << 4),
                }
            };
            let cs = pack(0, 0, 1, 0);
            self.video_context
                .VideoProcessorSetStreamColorSpace(&self.processor, 0, &cs);
            let out = pack(0, 0, 1, 1);
            self.video_context
                .VideoProcessorSetOutputColorSpace(&self.processor, &out);
            Ok(())
        }
    }

    /// Convert `src` (BGRA, converter input size) into `dst` (NV12,
    /// converter output size). Full-frame scaling.
    pub fn convert(&mut self, src: &FrameSurface, dst: &FrameSurface) -> Result<(), CodecError> {
        unsafe {
            let src_desc_matches =
                src.width() == self.input_width && src.height() == self.input_height;
            debug_assert!(src_desc_matches, "converter input geometry mismatch");
            let _ = src_desc_matches;

            // Views are cached per texture (pool rings reuse a handful of
            // slots): recreating a view every frame costs tens of
            // milliseconds of driver sync and destroyed the encode rate
            // until this was measured and fixed.
            let src_key = src.texture().as_raw() as usize;
            let input_view = match self.input_views.get(&src_key) {
                Some(view) => view.clone(),
                None => {
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
                    let mut input_view: Option<ID3D11VideoProcessorInputView> = None;
                    self.video_device
                        .CreateVideoProcessorInputView(
                            src.texture(),
                            &self.enumerator,
                            &input_desc,
                            Some(&mut input_view),
                        )
                        .map_err(|e| {
                            CodecError::Processing(format!(
                                "CreateVideoProcessorInputView(src {}x{}, conv {}x{}): {}",
                                src.width(),
                                src.height(),
                                self.input_width,
                                self.input_height,
                                e.message()
                            ))
                        })?;
                    let view =
                        input_view.ok_or_else(|| CodecError::Processing("no input view".into()))?;
                    if self.input_views.len() >= 16 {
                        // Geometry change: drop stale entries (bounded).
                        self.input_views.clear();
                    }
                    self.input_views.insert(src_key, view.clone());
                    view
                }
            };

            let dst_key = dst.texture().as_raw() as usize;
            if !self.output_views.contains_key(&dst_key) {
                let output_desc = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
                    ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
                    Anonymous: Default::default(),
                };
                let mut view: Option<ID3D11VideoProcessorOutputView> = None;
                self.video_device
                    .CreateVideoProcessorOutputView(
                        dst.texture(),
                        &self.enumerator,
                        &output_desc,
                        Some(&mut view),
                    )
                    .map_err(|e| {
                        CodecError::Processing(format!(
                            "CreateVideoProcessorOutputView(dst {}x{} fmt={:?}): {}",
                            dst.width(),
                            dst.height(),
                            dst.format(),
                            e.message()
                        ))
                    })?;
                let view = view.ok_or_else(|| CodecError::Processing("no output view".into()))?;
                if self.output_views.len() >= 16 {
                    self.output_views.clear();
                }
                self.output_views.insert(dst_key, view);
            }
            let output_view = self
                .output_views
                .get(&dst_key)
                .expect("output view just created");

            let src_rect = RECT {
                left: 0,
                top: 0,
                right: self.input_width as i32,
                bottom: self.input_height as i32,
            };
            // Dest rect is in OUTPUT-surface coordinates (the processor
            // scales src -> dst); using the src rect here fails Blt with
            // E_INVALIDARG whenever input != output size.
            let dst_rect = RECT {
                left: 0,
                top: 0,
                right: self.output_width as i32,
                bottom: self.output_height as i32,
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

            let stream = D3D11_VIDEO_PROCESSOR_STREAM {
                Enable: true.into(),
                pInputSurface: core::mem::ManuallyDrop::new(Some(input_view)),
                ..Default::default()
            };
            let _ = &self.device;
            self.video_context
                .VideoProcessorBlt(&self.processor, output_view, 0, &[stream])
                .map_err(|e| {
                    CodecError::Processing(format!(
                        "VideoProcessorBlt(in {}x{} -> out {}x{}, dst {}x{}): {}",
                        self.input_width,
                        self.input_height,
                        self.output_width,
                        self.output_height,
                        dst.width(),
                        dst.height(),
                        e.message()
                    ))
                })?;
            let _: Option<DXGI_COLOR_SPACE_TYPE> = None;
            Ok(())
        }
    }
}
