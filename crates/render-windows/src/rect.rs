//! Pure geometry helpers (unit-tested): fit/1:1 destination rectangles.

use crate::ScaleMode;

/// Letterbox-fit `frame_w x frame_h` into `client_w x client_h`.
/// Returns `(x, y, w, h)` of the destination rectangle (centered,
/// aspect preserved).
pub fn fit_rect(frame_w: u32, frame_h: u32, client_w: u32, client_h: u32) -> (i32, i32, u32, u32) {
    if frame_w == 0 || frame_h == 0 || client_w == 0 || client_h == 0 {
        return (0, 0, 0, 0);
    }
    let scale_w = client_w as f64 / frame_w as f64;
    let scale_h = client_h as f64 / frame_h as f64;
    let scale = scale_w.min(scale_h);
    let w = ((frame_w as f64 * scale).round() as u32).max(1);
    let h = ((frame_h as f64 * scale).round() as u32).max(1);
    let x = (client_w.saturating_sub(w) / 2) as i32;
    let y = (client_h.saturating_sub(h) / 2) as i32;
    (x, y, w, h)
}

/// The destination rectangle `present` composites a `frame_w x frame_h`
/// frame into for `scale` mode (M4 QA F48: the single source of truth the
/// presenter's input mapping must normalize over — `D3D11Renderer::present`
/// delegates here, so the drawn rect and the queryable rect cannot drift).
///
/// * `Fit`: letterboxed, centered, aspect-preserved ([`fit_rect`]);
/// * `OneToOne`: 1:1 pixels anchored at the top-left, cropped to the
///   target when the window is smaller than the frame.
pub fn destination_rect(
    scale: ScaleMode,
    frame_w: u32,
    frame_h: u32,
    target_w: u32,
    target_h: u32,
) -> (i32, i32, u32, u32) {
    match scale {
        ScaleMode::Fit => fit_rect(frame_w, frame_h, target_w, target_h),
        ScaleMode::OneToOne => (0, 0, frame_w.min(target_w), frame_h.min(target_h)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_rect_matches_the_present_geometry() {
        // Fit letterbox: 16:9 frame into an 8:5 client → bars top/bottom.
        assert_eq!(
            destination_rect(ScaleMode::Fit, 3840, 2160, 1600, 1000),
            (0, 50, 1600, 900)
        );
        // Fit pillarbox: 4:3 frame into a 16:9 client → bars left/right.
        assert_eq!(
            destination_rect(ScaleMode::Fit, 1024, 768, 1920, 1080),
            (240, 0, 1440, 1080)
        );
        // Fit with matching aspect: the rect IS the client.
        assert_eq!(
            destination_rect(ScaleMode::Fit, 1280, 720, 1280, 720),
            (0, 0, 1280, 720)
        );
        // 1:1, window smaller than the frame: top-left crop.
        assert_eq!(
            destination_rect(ScaleMode::OneToOne, 3840, 2160, 1280, 720),
            (0, 0, 1280, 720)
        );
        // 1:1, window larger than the frame: frame-sized at the origin.
        assert_eq!(
            destination_rect(ScaleMode::OneToOne, 1280, 720, 1920, 1080),
            (0, 0, 1280, 720)
        );
        // Degenerate sizes: a zero rect (callers drop mapping).
        assert_eq!(
            destination_rect(ScaleMode::Fit, 0, 2160, 1600, 1000),
            (0, 0, 0, 0)
        );
    }
}
