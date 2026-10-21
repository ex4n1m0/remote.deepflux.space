//! Controller-side agent frame tap (ADR-004, RD-016).
//!
//! The only sanctioned path that turns a decoded video frame into
//! viewable pixels for a local AI agent: GPU readback → NV12/BGRA → RGB →
//! downscale → JPEG, on demand and at agent rates (≤ 2 fps), never on the
//! real-time video path. `frame_surface::readback` is sanctioned today for
//! diagnostics and the software-encoder fallback; ADR-004 adds this third,
//! narrow use, and every capture still increments the process-wide
//! `readback_count`. The JPEG stays in this process: it is served to a
//! local, explicitly authorized MCP client only, never through Tauri IPC.

use codec_windows::DecodedFrame;
use frame_surface::{GpuDevice, SurfaceFormat};

/// Result of one screenshot tap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShotMeta {
    /// Downscaled screenshot dimensions — the pixel space agents address.
    pub width: u32,
    pub height: u32,
    /// Full decoded-frame dimensions. Coordinate mapping for normalized
    /// wire input: `normalized = px * 65_535 / frame_dim`. Screenshots
    /// preserve aspect ratio, so `px / width == px / frame_width`.
    pub frame_width: u32,
    pub frame_height: u32,
    /// JPEG bytes (quality 80, long edge ≤ 1600).
    pub jpeg: Vec<u8>,
}

#[derive(Debug)]
pub enum ScreenshotError {
    Readback(frame_surface::SurfaceError),
    Encode(String),
}

/// On-demand tap. Stateless and cheap to clone; the caller (engine decode
/// thread) rate-limits it — one capture per request, requested at most
/// once per tool call.
#[derive(Debug, Clone, Copy)]
pub struct Screenshotter {
    max_edge: u32,
    jpeg_quality: u8,
}

impl Default for Screenshotter {
    fn default() -> Self {
        Self {
            max_edge: 1600,
            jpeg_quality: 80,
        }
    }
}

impl Screenshotter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(max_edge: u32, jpeg_quality: u8) -> Self {
        Self {
            max_edge,
            jpeg_quality,
        }
    }

    /// Capture one screenshot of `frame`'s surface (GPU → CPU → RGB →
    /// downscale → JPEG).
    pub fn capture(
        &self,
        device: &GpuDevice,
        frame: &DecodedFrame,
    ) -> Result<ShotMeta, ScreenshotError> {
        let cpu =
            frame_surface::readback(device, &frame.surface).map_err(ScreenshotError::Readback)?;
        let (frame_w, frame_h) = (cpu.width, cpu.height);
        let rgb = match cpu.format {
            SurfaceFormat::Bgra8 => bgra_to_rgb(&cpu.data),
            SurfaceFormat::Nv12 => nv12_to_rgb(&cpu.data, frame_w, frame_h),
        };
        let (w, h) = scale_dims(frame_w, frame_h, self.max_edge);
        let resized = if (w, h) == (frame_w, frame_h) {
            rgb
        } else {
            resize_rgb_bilinear(&rgb, frame_w, frame_h, w, h)
        };
        let jpeg =
            encode_jpeg(&resized, w, h, self.jpeg_quality).map_err(ScreenshotError::Encode)?;
        Ok(ShotMeta {
            width: w,
            height: h,
            frame_width: frame_w,
            frame_height: frame_h,
            jpeg,
        })
    }
}

/// Convert a tight BGRA buffer to tight RGB (alpha dropped — the desktop
/// capture has no meaningful alpha).
pub fn bgra_to_rgb(bgra: &[u8]) -> Vec<u8> {
    let (px, _) = bgra.as_chunks::<4>();
    let mut rgb = Vec::with_capacity(px.len() * 3);
    for p in px {
        rgb.extend_from_slice(&[p[2], p[1], p[0]]);
    }
    rgb
}

/// BT.601 full-range NV12 → RGB, integer math. Tight NV12 layout (Y plane,
/// then interleaved UV) as produced by `frame_surface::readback`.
pub fn nv12_to_rgb(nv12: &[u8], width: u32, height: u32) -> Vec<u8> {
    let (w, h) = (width as usize, height as usize);
    let y_plane = w * h;
    let uv_row = w;
    let mut rgb = vec![0u8; w * h * 3];
    for y in 0..h {
        let uv_y = y / 2;
        for x in 0..w {
            let luma = nv12[y * w + x] as i32;
            let uv_off = y_plane + uv_y * uv_row + (x / 2) * 2;
            let (u, v) = (nv12[uv_off] as i32 - 128, nv12[uv_off + 1] as i32 - 128);
            // Full-range BT.601 (approximation is fine: this is an agent
            // screenshot, not a color-graded output path).
            let r = luma + ((359 * v) >> 8);
            let g = luma - ((88 * u + 183 * v) >> 8);
            let b = luma + ((454 * u) >> 8);
            let out = &mut rgb[(y * w + x) * 3..][..3];
            out[0] = r.clamp(0, 255) as u8;
            out[1] = g.clamp(0, 255) as u8;
            out[2] = b.clamp(0, 255) as u8;
        }
    }
    rgb
}

/// Largest dimensions with `max_edge` as the long edge, preserving aspect
/// ratio (never upscaling). Screenshots stay in the source aspect so
/// normalized coordinate mapping is uniform across both axes.
pub fn scale_dims(w: u32, h: u32, max_edge: u32) -> (u32, u32) {
    let long = w.max(h);
    if long <= max_edge {
        return (w, h);
    }
    let (sw, sh) = (
        (u64::from(w) * u64::from(max_edge) / u64::from(long)) as u32,
        (u64::from(h) * u64::from(max_edge) / u64::from(long)) as u32,
    );
    (sw.max(1), sh.max(1))
}

/// Bilinear downscale of a tight RGB buffer (also fine for upscale-safe
/// same-size paths; callers only use it when `scale_dims` shrank).
/// Fixed-point (8 fractional bits) so a 1080p desktop screenshot resizes
/// in a few milliseconds on the agent loop.
pub fn resize_rgb_bilinear(src: &[u8], w: u32, h: u32, sw: u32, sh: u32) -> Vec<u8> {
    const FRAC: u32 = 8;
    const SCALE: u32 = 1 << FRAC;
    const MASK: u32 = SCALE - 1;
    let (w, h, sw, sh) = (w as usize, h as usize, sw as usize, sh as usize);
    let mut out = vec![0u8; sw * sh * 3];
    // Fixed-point source position per output pixel, center-biased (+0.5).
    let step_x = (w as u64 * SCALE as u64 / sw as u64) as u32;
    let step_y = (h as u64 * SCALE as u64 / sh as u64) as u32;
    for dy in 0..sh {
        let pos_y = (dy as u32 * step_y + (SCALE >> 1)).min((h - 1) as u32 * SCALE);
        let y0 = (pos_y >> FRAC) as usize;
        let y1 = (y0 + 1).min(h - 1);
        let fy = pos_y & MASK;
        for dx in 0..sw {
            let pos_x = (dx as u32 * step_x + (SCALE >> 1)).min((w - 1) as u32 * SCALE);
            let x0 = (pos_x >> FRAC) as usize;
            let x1 = (x0 + 1).min(w - 1);
            let fx = pos_x & MASK;
            let (w00, w01, w10, w11) = (
                (SCALE - fx) * (SCALE - fy),
                fx * (SCALE - fy),
                (SCALE - fx) * fy,
                fx * fy,
            );
            let (p00, p01, p10, p11) = (
                (y0 * w + x0) * 3,
                (y0 * w + x1) * 3,
                (y1 * w + x0) * 3,
                (y1 * w + x1) * 3,
            );
            let out_px = (dy * sw + dx) * 3;
            for c in 0..3 {
                let v = src[p00 + c] as u32 * w00
                    + src[p01 + c] as u32 * w01
                    + src[p10 + c] as u32 * w10
                    + src[p11 + c] as u32 * w11;
                out[out_px + c] = ((v + ((SCALE * SCALE) >> 1)) >> (2 * FRAC)) as u8;
            }
        }
    }
    out
}

/// Encode tight RGB as JPEG (baseline).
pub fn encode_jpeg(rgb: &[u8], w: u32, h: u32, quality: u8) -> Result<Vec<u8>, String> {
    use image::codecs::jpeg::JpegEncoder;
    let mut out = Vec::new();
    let mut enc = JpegEncoder::new_with_quality(&mut out, quality);
    enc.encode(rgb, w, h, image::ExtendedColorType::Rgb8)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nv12_extremes_and_gray() {
        let (w, h) = (2u32, 2u32);
        let mut nv12 = vec![0u8; w as usize * h as usize * 3 / 2];
        // Y all 0, UV all 128 → black.
        nv12[4..6].fill(128);
        let black = nv12_to_rgb(&nv12, w, h);
        assert_eq!(black, vec![0u8; 12]);
        // Y all 255, UV 128 → white.
        let mut nv12 = vec![0u8; w as usize * h as usize * 3 / 2];
        nv12[0..4].fill(255);
        nv12[4..6].fill(128);
        let white = nv12_to_rgb(&nv12, w, h);
        assert_eq!(white, vec![255u8; 12]);
        // Mid luma → mid gray.
        let mut nv12 = vec![0u8; w as usize * h as usize * 3 / 2];
        nv12[0..4].fill(128);
        nv12[4..6].fill(128);
        let gray = nv12_to_rgb(&nv12, w, h);
        assert!(gray.iter().all(|&v| (127..=130).contains(&v)));
    }

    #[test]
    fn bgra_drops_alpha_in_order() {
        let bgra = [10, 20, 30, 99, 40, 50, 60, 99];
        assert_eq!(bgra_to_rgb(&bgra), vec![30, 20, 10, 60, 50, 40]);
    }

    #[test]
    fn scale_dims_preserves_aspect_and_never_upscales() {
        assert_eq!(scale_dims(1920, 1080, 1600), (1600, 900));
        assert_eq!(scale_dims(1080, 1920, 1600), (900, 1600));
        assert_eq!(scale_dims(800, 600, 1600), (800, 600));
        assert_eq!(scale_dims(1600, 900, 1600), (1600, 900));
    }

    #[test]
    fn bilinear_averages_a_2x2_block() {
        let src = [
            0u8, 0, 0, 100, 100, 100, 0, 0, 0, 100, 100, 100, // two black / two white
        ];
        let out = resize_rgb_bilinear(&src, 2, 2, 1, 1);
        assert_eq!(out, vec![50, 50, 50]);
    }

    #[test]
    fn jpeg_output_has_jpeg_magic() {
        let rgb = vec![0u8; 16 * 16 * 3];
        let jpeg = encode_jpeg(&rgb, 16, 16, 80).expect("encode");
        assert_eq!(&jpeg[..2], &[0xFF, 0xD8]);
        assert!(jpeg.len() > 100);
    }

    /// Timing reference for the agent loop's local cost (ADR-004, RD-016):
    /// resize + JPEG of one 1080p frame, no GPU. Run in release:
    /// `cargo test -p node-runtime --lib screenshot --release -- --ignored --nocapture`
    #[test]
    #[ignore = "timing reference only (no assertions)"]
    fn timing_reference_1080p_resize_and_encode() {
        let (w, h) = (1920u32, 1088u32);
        let mut rgb = vec![0u8; w as usize * h as usize * 3];
        for y in 0..h as usize {
            for x in 0..w as usize {
                let p = (y * w as usize + x) * 3;
                rgb[p] = (x % 256) as u8;
                rgb[p + 1] = (y % 256) as u8;
                rgb[p + 2] = ((x ^ y) % 256) as u8;
            }
        }
        let (sw, sh) = scale_dims(w, h, 1600);
        let started = std::time::Instant::now();
        let resized = resize_rgb_bilinear(&rgb, w, h, sw, sh);
        let jpeg = encode_jpeg(&resized, sw, sh, 80).expect("encode");
        eprintln!(
            "resize {}x{} -> {}x{} + jpeg(q80, {} bytes): {:?}",
            w,
            h,
            sw,
            sh,
            jpeg.len(),
            started.elapsed()
        );
    }
}
