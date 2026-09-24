//! Cursor extraction: DXGI pointer metadata -> `protocol::wire::CursorMessage`.
//!
//! Pure conversion functions (no GPU state) so they are unit-testable with
//! synthetic buffers. The wire formats are fixed by
//! `crates/protocol/src/wire.rs` (`CursorFormat`):
//!
//! * `Bgra8` — 32-bit premultiplied BGRA, `width * 4` bytes per row
//!   (DXGI color cursor).
//! * `Monochrome` — 1-bpp AND mask followed by 1-bpp XOR mask, each
//!   `monochrome_pitch(width) * height` bytes; rows are WORD-aligned
//!   (`pitch = (width + 15) / 16 * 2`, the cursor-bitmap convention DXGI
//!   hands us).
//! * `MaskedColor` — 32-bit color with the 1-bpp transparency mask carried
//!   in the alpha byte (alpha `0x01` marks masked pixels) — Windows
//!   masked-color cursor, transported verbatim.

use protocol::wire::{CursorFormat, CursorMessage};

/// Row pitch of one mask plane in a monochrome (or masked-color AND-plane)
/// cursor bitmap: rows are aligned to 16 bits.
pub fn monochrome_pitch(width: u16) -> usize {
    (width as usize).div_ceil(16) * 2
}

/// Convert one `GetFramePointerShape` buffer into a `CursorMessage::Shape`.
///
/// `id` is a caller-assigned shape id (the capture stage assigns a new one
/// whenever the reported shape size changes — i.e., on every new shape).
///
/// Returns `None` on a malformed buffer (wrong size for the claimed
/// geometry) — a corrupt shape must not become a garbage wire message.
pub fn shape_to_cursor_message(
    info: &windows::Win32::Graphics::Dxgi::DXGI_OUTDUPL_POINTER_SHAPE_INFO,
    buffer: &[u8],
    id: u32,
) -> Option<CursorMessage> {
    use windows::Win32::Graphics::Dxgi::{
        DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR, DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR,
        DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME,
    };

    let w = u16::try_from(info.Width).ok()?;
    let h = u16::try_from(info.Height).ok()?;
    if w == 0 || h == 0 {
        return None;
    }

    let format = if info.Type == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME.0 as u32 {
        CursorFormat::Monochrome
    } else if info.Type == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR.0 as u32 {
        CursorFormat::Bgra8
    } else if info.Type == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR.0 as u32 {
        CursorFormat::MaskedColor
    } else {
        return None; // unknown shape type — refuse, never guess
    };

    let expected = match format {
        CursorFormat::Monochrome => monochrome_pitch(w) * h as usize * 2,
        CursorFormat::Bgra8 | CursorFormat::MaskedColor => w as usize * h as usize * 4,
    };
    if buffer.len() < expected {
        return None;
    }

    let hotspot_x = u16::try_from(info.HotSpot.x).unwrap_or(0).min(w);
    let hotspot_y = u16::try_from(info.HotSpot.y).unwrap_or(0).min(h);

    Some(CursorMessage::Shape {
        id,
        width: w,
        height: h,
        hotspot_x,
        hotspot_y,
        format,
        pixels: buffer[..expected].to_vec(),
    })
}

/// Normalize a cursor position (desktop coordinates) into the
/// `0..=65535` space of `CursorMessage::Position` relative to the
/// captured output's desktop rectangle.
pub fn normalize_position(
    x: i32,
    y: i32,
    desktop_left: i32,
    desktop_top: i32,
    width: i32,
    height: i32,
    seq: u64,
) -> CursorMessage {
    let clamp = |v: i32, lo: i32, hi: i32| v.clamp(lo, hi);
    let nx = if width > 0 {
        ((clamp(x, desktop_left, desktop_left + width) - desktop_left) as u64 * 65_535)
            / width as u64
    } else {
        0
    };
    let ny = if height > 0 {
        ((clamp(y, desktop_top, desktop_top + height) - desktop_top) as u64 * 65_535)
            / height as u64
    } else {
        0
    };
    CursorMessage::Position {
        seq,
        x: nx as u16,
        y: ny as u16,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::{POINT, RECT};

    fn shape_info(
        kind: u32,
        w: u32,
        h: u32,
        hx: i32,
        hy: i32,
    ) -> windows::Win32::Graphics::Dxgi::DXGI_OUTDUPL_POINTER_SHAPE_INFO {
        windows::Win32::Graphics::Dxgi::DXGI_OUTDUPL_POINTER_SHAPE_INFO {
            Type: kind,
            Width: w,
            Height: h,
            Pitch: 0,
            HotSpot: POINT { x: hx, y: hy },
        }
    }

    #[test]
    fn monochrome_pitch_is_word_aligned() {
        assert_eq!(monochrome_pitch(1), 2);
        assert_eq!(monochrome_pitch(16), 2);
        assert_eq!(monochrome_pitch(17), 4);
        assert_eq!(monochrome_pitch(32), 4);
        assert_eq!(monochrome_pitch(33), 6);
    }

    #[test]
    fn color_shape_round_trips_with_exact_geometry() {
        // 3x2 color cursor: 3*4 bytes/row * 2 rows = 24 bytes.
        let info = shape_info(
            2, /* DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR */
            3, 2, 1, 1,
        );
        let buf = vec![0xA5u8; 24];
        let msg = shape_to_cursor_message(&info, &buf, 7).expect("shape");
        match msg {
            CursorMessage::Shape {
                id,
                width,
                height,
                hotspot_x,
                hotspot_y,
                format,
                pixels,
            } => {
                assert_eq!(id, 7);
                assert_eq!((width, height), (3, 2));
                assert_eq!((hotspot_x, hotspot_y), (1, 1));
                assert_eq!(format, CursorFormat::Bgra8);
                assert_eq!(pixels.len(), 24);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn monochrome_shape_wants_two_mask_planes() {
        // 16x16 mono: pitch 2 * 16 rows * 2 planes = 64 bytes.
        let info = shape_info(1, 16, 16, 0, 0);
        assert!(shape_to_cursor_message(&info, &[0; 63], 1).is_none());
        let msg = shape_to_cursor_message(&info, &[0x55; 64], 1).expect("shape");
        match msg {
            CursorMessage::Shape { format, pixels, .. } => {
                assert_eq!(format, CursorFormat::Monochrome);
                assert_eq!(pixels.len(), 64);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn masked_color_shape_maps() {
        let info = shape_info(4 /* MASKED_COLOR */, 8, 8, 2, 3);
        let msg = shape_to_cursor_message(&info, &vec![0; 8 * 8 * 4], 9).expect("shape");
        match msg {
            CursorMessage::Shape { format, pixels, .. } => {
                assert_eq!(format, CursorFormat::MaskedColor);
                assert_eq!(pixels.len(), 8 * 8 * 4);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn truncated_or_unknown_shapes_are_rejected() {
        let info = shape_info(2, 64, 64, 0, 0);
        assert!(shape_to_cursor_message(&info, &[0; 100], 1).is_none());
        assert!(shape_to_cursor_message(&shape_info(99, 8, 8, 0, 0), &vec![0; 256], 1).is_none());
        assert!(shape_to_cursor_message(&shape_info(2, 0, 0, 0, 0), &[0; 0], 1).is_none());
    }

    #[test]
    fn position_normalizes_into_0_65535() {
        let rect = RECT {
            left: -1920,
            top: 0,
            right: -1920 + 2560,
            bottom: 1440,
        };
        let p = normalize_position(-1920, 0, rect.left, rect.top, 2560, 1440, 1);
        match p {
            CursorMessage::Position { seq, x, y } => {
                assert_eq!((seq, x, y), (1, 0, 0));
            }
            other => panic!("wrong variant: {other:?}"),
        }
        match normalize_position(-1280, 720, rect.left, rect.top, 2560, 1440, 2) {
            CursorMessage::Position { x, y, .. } => {
                assert_eq!(x, 16383); // floor(0.25 * 65535)
                assert_eq!(y, 32767); // floor(0.5 * 65535)
            }
            other => panic!("wrong variant: {other:?}"),
        }
        // Out-of-range clamps instead of wrapping.
        match normalize_position(99_999, 99_999, rect.left, rect.top, 2560, 1440, 3) {
            CursorMessage::Position { x, y, .. } => assert_eq!((x, y), (65_535, 65_535)),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
