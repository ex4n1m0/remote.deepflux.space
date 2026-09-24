//! Pure geometry helpers (unit-tested): fit/1:1 destination rectangles.

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
