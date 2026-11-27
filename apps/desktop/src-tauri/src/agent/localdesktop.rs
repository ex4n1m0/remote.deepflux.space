//! Native computer use on THIS machine (ADR-015): the assistant looks at
//! its own screen and acts on it directly — no remote session, and no
//! keystroke scripts pushed through the shell. (Owner direction
//! 2026-11-25: the first live agent-to-agent desktop task failed because
//! the instructed machine's assistant could not operate its own desktop.)
//!
//! What lives here:
//! * **See** — a GDI copy of the primary monitor into a top-down DIB,
//!   turned into a JPEG by the pure helpers in `node_runtime::screenshot`
//!   (same 1600 px long edge and quality as the remote screenshot).
//! * **Act** — the SAME `input_windows::SendInputSink` the host role uses
//!   for remote control (invariant 7: injection stays behind the narrow
//!   trait; coordinate mapping, held-state tracking and release-all are the
//!   product's, not a second implementation). A fresh sink per tool call,
//!   wrapped in a drop guard that releases anything still held, so a step
//!   that fails half-way cannot leave a modifier or a button down.
//! * **Stay out of its own app** — the guards in [`mouse_refusal`] and
//!   [`key_refusal`]: no click inside a window of this process, no typing
//!   while this app is in front (Win shortcuts excepted — they hand
//!   control to the shell), and nothing at all while a consent prompt is
//!   waiting for the human.
//!
//! The two reviewed Win32 touches follow the `agent/winctl.rs` precedent
//! (the `apps/desktop` scope note in AGENTS.md). Typed text, coordinates
//! and key names never reach a log line (invariant 6): results carry
//! counts and labels only.

use std::ffi::c_void;
use std::fmt;
use std::time::Duration;

use input_windows::{InputSink, MonitorRect, SendInputSink};
use node_runtime::screenshot::{bgra_to_rgb, encode_jpeg, resize_rgb_bilinear, scale_dims};
use protocol::wire::{AllKeysUpTrigger, ButtonState, InputEvent, MouseButton};
use windows::Win32::Foundation::POINT;
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CAPTUREBLT, CreateCompatibleDC, CreateDIBSection,
    DIB_RGB_COLORS, DeleteDC, DeleteObject, GdiFlush, GetDC, HGDIOBJ, ReleaseDC, SRCCOPY,
    SelectObject,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GA_ROOT, GA_ROOTOWNER, GetAncestor, GetCursorPos, GetForegroundWindow, GetSystemMetrics,
    GetWindowThreadProcessId, SM_CXSCREEN, SM_CYSCREEN, WindowFromPoint,
};

/// Long edge of a local screenshot — the same limit as the remote one.
const MAX_EDGE: u32 = 1600;
const JPEG_QUALITY: u8 = 80;
/// A corrupt screen metric must not make the capture allocate without
/// bound. Room for an 8K primary monitor (7680 × 4320), no more.
const MAX_SCREEN_PIXELS: u64 = 4096 * 4096 * 4;
/// `Text` events go out in chunks of at most this many UTF-16 code units
/// (the sink's own cap is higher; small batches keep each call light).
const TEXT_CHUNK_UNITS: usize = 400;
/// One `local_type_text` call types at most this much; the model sends
/// longer text in parts, and a text full of newlines cannot keep pressing
/// Enter for minutes.
const TEXT_MAX_UNITS: usize = 4000;
const TEXT_MAX_LINES: usize = 100;
/// One wheel notch (Windows' fixed `WHEEL_DELTA`).
const WHEEL_NOTCH: i32 = 120;
/// Wheel notches per call, either way.
pub(crate) const WHEEL_MAX_NOTCHES: i64 = 10;
/// Clicks per call (1 = single, 2 = double, 3 = triple).
pub(crate) const CLICKS_MAX: u64 = 3;
/// Taps per `local_press_key` call.
pub(crate) const KEYS_MAX: u64 = 3;
/// Seconds per `local_wait` call.
pub(crate) const WAIT_MAX_SECS: u64 = 30;
/// A drag travels in this many moves, so windows see motion, not a jump.
const DRAG_STEPS: usize = 14;
/// Enter (set-1 scan code) — pressed between the lines of a typed text.
const ENTER_SCAN_CODE: (u16, bool) = (0x1C, false);

// ---------------------------------------------------------------------------
// Seeing
// ---------------------------------------------------------------------------

/// The pixel space of the latest local screenshot: what the model addresses
/// (`width` / `height`) and the monitor it was taken from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalSpace {
    pub width: u32,
    pub height: u32,
    pub screen_width: u32,
    pub screen_height: u32,
}

/// One fresh picture of this machine's primary monitor.
pub struct LocalShot {
    pub space: LocalSpace,
    /// JPEG bytes (quality 80, long edge ≤ 1600).
    pub jpeg: Vec<u8>,
    /// Pointer position in screenshot pixels, when it is on this monitor.
    pub cursor: Option<(u32, u32)>,
}

/// Capture this machine's primary monitor: GDI copy → RGB → downscale →
/// JPEG. Every call takes a fresh picture.
pub fn screenshot() -> Result<LocalShot, String> {
    let (bgra, screen_width, screen_height) = capture_primary_monitor()?;
    let rgb = bgra_to_rgb(&bgra);
    let (width, height) = scale_dims(screen_width, screen_height, MAX_EDGE);
    let resized = if (width, height) == (screen_width, screen_height) {
        rgb
    } else {
        resize_rgb_bilinear(&rgb, screen_width, screen_height, width, height)
    };
    let jpeg = encode_jpeg(&resized, width, height, JPEG_QUALITY)?;
    Ok(LocalShot {
        cursor: cursor_position()
            .and_then(|(x, y)| fit_to_shot(x, y, width, height, screen_width, screen_height)),
        space: LocalSpace {
            width,
            height,
            screen_width,
            screen_height,
        },
        jpeg,
    })
}

/// Monitor pixel → screenshot pixel; `None` when the point is off the
/// captured monitor.
pub(crate) fn fit_to_shot(
    x: i32,
    y: i32,
    shot_width: u32,
    shot_height: u32,
    screen_width: u32,
    screen_height: u32,
) -> Option<(u32, u32)> {
    if x < 0 || y < 0 || x as u32 >= screen_width || y as u32 >= screen_height {
        return None;
    }
    Some((
        (x as u64 * u64::from(shot_width) / u64::from(screen_width)) as u32,
        (y as u64 * u64::from(shot_height) / u64::from(screen_height)) as u32,
    ))
}

/// BGRA pixels (top-down, 32 bpp), width and height of the primary monitor.
fn capture_primary_monitor() -> Result<(Vec<u8>, u32, u32), String> {
    // SAFETY: plain GDI calls. Every handle is checked before use, the DIB
    // bits pointer is read only while its bitmap is alive and selected,
    // and each handle is released on every path, success or failure.
    unsafe {
        let metric_width = GetSystemMetrics(SM_CXSCREEN);
        let metric_height = GetSystemMetrics(SM_CYSCREEN);
        if metric_width <= 0 || metric_height <= 0 {
            return Err("Windows reports no primary monitor".to_owned());
        }
        let (width, height) = (metric_width as u32, metric_height as u32);
        if u64::from(width) * u64::from(height) > MAX_SCREEN_PIXELS {
            return Err(format!(
                "primary monitor {width}x{height} is too large to capture"
            ));
        }
        let screen_dc = GetDC(None);
        if screen_dc.is_invalid() {
            return Err("could not open the screen for copying".to_owned());
        }
        let memory_dc = CreateCompatibleDC(Some(screen_dc));
        if memory_dc.is_invalid() {
            ReleaseDC(None, screen_dc);
            return Err("could not create a drawing surface".to_owned());
        }
        let mut info = BITMAPINFO::default();
        info.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        info.bmiHeader.biWidth = width as i32;
        // A negative height asks for top-down rows: no flip before encoding.
        info.bmiHeader.biHeight = -(height as i32);
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 32;
        info.bmiHeader.biCompression = BI_RGB.0;
        let mut bits: *mut c_void = std::ptr::null_mut();
        let bitmap =
            match CreateDIBSection(Some(memory_dc), &info, DIB_RGB_COLORS, &mut bits, None, 0) {
                Ok(bitmap) => bitmap,
                Err(err) => {
                    let _ = DeleteDC(memory_dc);
                    ReleaseDC(None, screen_dc);
                    return Err(format!("could not create a capture bitmap: {err}"));
                }
            };
        let previous = SelectObject(memory_dc, HGDIOBJ(bitmap.0));
        let copied = BitBlt(
            memory_dc,
            0,
            0,
            width as i32,
            height as i32,
            Some(screen_dc),
            0,
            0,
            SRCCOPY | CAPTUREBLT,
        );
        // GDI batches calls; the DIB is only complete once they are flushed.
        let _ = GdiFlush();
        // 32 bpp rows are already a multiple of four bytes: no padding.
        let stride = width as usize * 4;
        let pixels = if copied.is_ok() && !bits.is_null() {
            Some(std::slice::from_raw_parts(bits.cast::<u8>(), stride * height as usize).to_vec())
        } else {
            None
        };
        // Restore before deleting: a bitmap still selected into a DC
        // cannot be deleted.
        SelectObject(memory_dc, previous);
        let _ = DeleteObject(HGDIOBJ(bitmap.0));
        let _ = DeleteDC(memory_dc);
        ReleaseDC(None, screen_dc);
        match (copied, pixels) {
            (Ok(()), Some(pixels)) => Ok((pixels, width, height)),
            (Err(err), _) => Err(format!("could not copy the screen: {err}")),
            (Ok(()), None) => Err("the screen copy returned no pixels".to_owned()),
        }
    }
}

fn cursor_position() -> Option<(i32, i32)> {
    // SAFETY: GetCursorPos only writes through the valid out-pointer.
    let mut point = POINT::default();
    unsafe { GetCursorPos(&mut point) }.ok()?;
    Some((point.x, point.y))
}

// ---------------------------------------------------------------------------
// Staying out of this app's own windows
// ---------------------------------------------------------------------------

/// Why an action on this machine's own desktop is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A consent prompt is on screen, waiting for the human.
    ConsentWaiting,
    /// The point lies inside a window of this app.
    OwnWindow,
    /// This app is in front, so keystrokes would land in it.
    OwnForeground,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::ConsentWaiting => {
                "not done: a connection consent prompt is waiting for the human on this \
                 machine — only they can answer it. Wait (local_wait) or look with \
                 local_screenshot; if it does not clear, say so in your answer"
            }
            Self::OwnWindow => {
                "not done: that point is inside this app's own window — the assistant never \
                 operates its own app. Aim at the window you want to operate"
            }
            Self::OwnForeground => {
                "not done: this app's own window is in front, so the keystrokes would land \
                 in it. Click the window you want (local_click) or focus it (window_focus); \
                 Win shortcuts are allowed"
            }
        };
        f.write_str(text)
    }
}

/// True when the window under a monitor pixel belongs to this app's
/// process — its top-level window, or a popup owned by one (menus and
/// dialogs the webview pops up can be separate top-level windows).
fn point_is_own_window(x: i32, y: i32) -> bool {
    // SAFETY: WindowFromPoint has no preconditions; GetAncestor returns a
    // null handle for a window with no such ancestor (checked).
    unsafe {
        let hit = WindowFromPoint(POINT { x, y });
        if hit.is_invalid() {
            return false;
        }
        [
            hit,
            GetAncestor(hit, GA_ROOT),
            GetAncestor(hit, GA_ROOTOWNER),
        ]
        .into_iter()
        .filter(|window| !window.is_invalid())
        .any(window_belongs_to_this_process)
    }
}

/// True when `window` was created by this app's process.
fn window_belongs_to_this_process(window: windows::Win32::Foundation::HWND) -> bool {
    // SAFETY: no preconditions; the out-pointer is valid.
    unsafe {
        let mut pid: u32 = 0;
        let _ = GetWindowThreadProcessId(window, Some(&mut pid));
        pid == std::process::id()
    }
}

/// True when the foreground window belongs to this app's process.
fn foreground_is_own_process() -> bool {
    // SAFETY: GetForegroundWindow has no preconditions.
    let window = unsafe { GetForegroundWindow() };
    !window.is_invalid() && window_belongs_to_this_process(window)
}

/// Mouse guard. `point` is the target in monitor pixels (`None` = no
/// target, a wheel turn at the pointer).
pub(crate) fn mouse_refusal(point: Option<(i32, i32)>, consent_waiting: bool) -> Option<Refusal> {
    if consent_waiting {
        return Some(Refusal::ConsentWaiting);
    }
    if point.is_some_and(|(x, y)| point_is_own_window(x, y)) {
        return Some(Refusal::OwnWindow);
    }
    None
}

/// Keyboard guard. `key` is `None` for typed text. A chord that hands
/// control to Windows (Start, Run, the task switcher) is allowed even
/// while this app is in front: it never lands in the app.
pub(crate) fn key_refusal(
    key: Option<(u16, bool)>,
    modifiers: &[Modifier],
    consent_waiting: bool,
) -> Option<Refusal> {
    if consent_waiting {
        return Some(Refusal::ConsentWaiting);
    }
    let hands_off = key.is_some_and(|key| hands_off_to_windows(key, modifiers));
    if foreground_is_own_process() && !hands_off {
        return Some(Refusal::OwnForeground);
    }
    None
}

/// Esc = 0x01 and Tab = 0x0F (set-1 scan codes, not extended); the left
/// Windows key = 0x5B, extended.
const ESC_SCAN_CODE: (u16, bool) = (0x01, false);
const TAB_SCAN_CODE: (u16, bool) = (0x0F, false);
const WIN_SCAN_CODE: (u16, bool) = (0x5B, true);

/// The bare Windows key (Start), any Win chord, `ctrl+escape` (Start) and
/// `alt+tab` (switcher). The bare key matters most: it is how a task starts
/// the moment after the human typed it into this app.
fn hands_off_to_windows(key: (u16, bool), modifiers: &[Modifier]) -> bool {
    let only = |wanted: Modifier| modifiers.len() == 1 && modifiers[0] == wanted;
    key == WIN_SCAN_CODE
        || modifiers.contains(&Modifier::Win)
        || (key == ESC_SCAN_CODE && only(Modifier::Ctrl))
        || (key == TAB_SCAN_CODE && only(Modifier::Alt))
}

// ---------------------------------------------------------------------------
// Acting
// ---------------------------------------------------------------------------

/// One wire key with a modifier held for the chord.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Modifier {
    Ctrl,
    Shift,
    Alt,
    Win,
}

impl Modifier {
    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "ctrl" | "control" => Some(Self::Ctrl),
            "shift" => Some(Self::Shift),
            "alt" => Some(Self::Alt),
            "win" | "windows" => Some(Self::Win),
            _ => None,
        }
    }

    fn scan_code(self) -> (u16, bool) {
        match self {
            Self::Ctrl => (0x1D, false),
            Self::Shift => (0x2A, false),
            Self::Alt => (0x38, false),
            Self::Win => (0x5B, true),
        }
    }
}

/// A fresh sink per tool call. Every call is self-contained (press AND
/// release inside it); the drop guard releases anything still held when a
/// step fails half-way, so no modifier or button can stay down.
struct LocalInput(SendInputSink);

impl LocalInput {
    fn open() -> Result<Self, String> {
        let monitor = MonitorRect::primary().map_err(|err| err.to_string())?;
        let sink = SendInputSink::new(monitor).map_err(|err| err.to_string())?;
        Ok(Self(sink))
    }

    fn send(&mut self, events: &[InputEvent]) -> Result<(), String> {
        for event in events {
            self.0
                .inject(event)
                .map_err(|err| format!("could not inject input: {err}"))?;
        }
        Ok(())
    }
}

impl Drop for LocalInput {
    fn drop(&mut self) {
        // The release path reports, it never panics (the sink's contract).
        // A release Windows refuses is retried a few times: a key left
        // down outlives this sink, and nothing else would know about it.
        for attempt in 0..3 {
            let _ = InputSink::release_all(&mut self.0, AllKeysUpTrigger::Disconnect);
            if InputSink::held_count(&self.0) == 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(40 * (attempt + 1)));
        }
    }
}

/// What a running plan asks before every group of events. The desktop can
/// change under a plan (a consent prompt appears and pulls this app to the
/// front, the human alt-tabs back into it) between the first check and a
/// later step, so the guards are live, not once.
type LiveGuard<'a> = &'a dyn Fn() -> Result<(), String>;

fn refuse(refusal: Option<Refusal>) -> Result<(), String> {
    match refusal {
        Some(refusal) => Err(refusal.to_string()),
        None => Ok(()),
    }
}

fn mouse_guard<'a>(
    point: Option<(i32, i32)>,
    consent: &'a dyn Fn() -> bool,
) -> impl Fn() -> Result<(), String> + 'a {
    move || refuse(mouse_refusal(point, consent()))
}

fn key_guard<'a>(
    key: Option<(u16, bool)>,
    modifiers: &'a [Modifier],
    consent: &'a dyn Fn() -> bool,
) -> impl Fn() -> Result<(), String> + 'a {
    move || refuse(key_refusal(key, modifiers, consent()))
}

/// One thing to do on the input stream: hand off a group of events, or
/// wait so the previous group lands before the next starts.
enum Step {
    Events(Vec<InputEvent>),
    Pause(Duration),
}

/// Builds a sequence of [`Step`]s. Consecutive events without a pause
/// between them share one group; `seq` only orders events inside a group.
#[derive(Default)]
struct Plan {
    seq: u64,
    steps: Vec<Step>,
}

impl Plan {
    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn pause(&mut self, millis: u64) {
        self.steps.push(Step::Pause(Duration::from_millis(millis)));
    }

    fn push(&mut self, event: InputEvent) {
        match self.steps.last_mut() {
            Some(Step::Events(events)) => events.push(event),
            _ => self.steps.push(Step::Events(vec![event])),
        }
    }

    fn move_to(&mut self, x: u16, y: u16) {
        let seq = self.next_seq();
        self.push(InputEvent::MouseMove { seq, x, y });
    }

    fn button(&mut self, button: MouseButton, state: ButtonState) {
        let seq = self.next_seq();
        self.push(InputEvent::MouseButton { seq, button, state });
    }

    fn key(&mut self, scan_code: u16, extended: bool, state: ButtonState) {
        let seq = self.next_seq();
        self.push(InputEvent::Key {
            seq,
            scan_code,
            extended,
            state,
        });
    }

    fn text(&mut self, chunk: &str) {
        let seq = self.next_seq();
        self.push(InputEvent::Text {
            seq,
            code_points: chunk.to_owned(),
        });
    }

    fn wheel(&mut self, delta_v: i32) {
        let seq = self.next_seq();
        self.push(InputEvent::Wheel {
            seq,
            delta_v,
            delta_h: 0,
        });
    }

    /// Press, let it land, release.
    fn tap(&mut self, key: (u16, bool)) {
        self.key(key.0, key.1, ButtonState::Pressed);
        self.pause(30);
        self.key(key.0, key.1, ButtonState::Released);
    }
}

fn play(sink: &mut LocalInput, steps: &[Step], guard: LiveGuard<'_>) -> Result<(), String> {
    for step in steps {
        match step {
            // Asked again right before EVERY group. A refusal ends the
            // plan here; the sink's drop guard releases whatever it holds.
            Step::Events(events) => {
                guard()?;
                sink.send(events)?;
            }
            Step::Pause(delay) => std::thread::sleep(*delay),
        }
    }
    Ok(())
}

/// Click `clicks` times at normalized (`x`, `y`) on the primary monitor.
/// `point` (monitor pixels) is only for the own-window guard.
pub(crate) fn click(
    point: (i32, i32),
    x: u16,
    y: u16,
    button: MouseButton,
    clicks: u64,
    consent: &dyn Fn() -> bool,
) -> Result<String, String> {
    mouse_guard(Some(point), consent)()?;
    let mut sink = LocalInput::open()?;
    let mut plan = Plan::default();
    plan.move_to(x, y);
    plan.pause(60);
    for _ in 0..clicks {
        plan.button(button, ButtonState::Pressed);
        plan.pause(35);
        plan.button(button, ButtonState::Released);
        plan.pause(70);
    }
    play(&mut sink, &plan.steps, &mouse_guard(Some(point), consent))?;
    Ok(format!(
        "clicked {} time(s) with the {button:?} button on this machine",
        clicks.max(1)
    ))
}

/// Left-button drag from (`x`, `y`) to (`to_x`, `to_y`), both normalized.
/// `from_point` / `to_point` (monitor pixels) are for the own-window
/// guard: neither end of the drag may be inside this app's window.
pub(crate) fn drag(
    from_point: (i32, i32),
    to_point: (i32, i32),
    from: (u16, u16),
    to: (u16, u16),
    consent: &dyn Fn() -> bool,
) -> Result<String, String> {
    mouse_guard(Some(from_point), consent)?;
    mouse_guard(Some(to_point), consent)?;
    let mut sink = LocalInput::open()?;
    let mut plan = Plan::default();
    plan.move_to(from.0, from.1);
    plan.pause(60);
    plan.button(MouseButton::Left, ButtonState::Pressed);
    plan.pause(80);
    for step in 1..=DRAG_STEPS {
        let t = step as f64 / DRAG_STEPS as f64;
        let mix = |a: u16, b: u16| {
            (f64::from(a) + (f64::from(b) - f64::from(a)) * t)
                .round()
                .clamp(0.0, 65_535.0) as u16
        };
        plan.move_to(mix(from.0, to.0), mix(from.1, to.1));
        plan.pause(15);
    }
    plan.pause(80);
    plan.button(MouseButton::Left, ButtonState::Released);
    // The drop is what could land on this app: asked at the very end too.
    let guard = mouse_guard(Some(to_point), consent);
    let live = move || guard().and_then(|()| mouse_guard(Some(from_point), consent)());
    play(&mut sink, &plan.steps, &live)?;
    Ok("dragged with the left button on this machine".to_owned())
}

/// Split `text` into chunks of at most `limit` UTF-16 code units without
/// ever cutting a surrogate pair (emoji and other astral characters).
pub(crate) fn split_utf16(text: &str, limit: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut units = 0usize;
    for ch in text.chars() {
        let needed = ch.len_utf16();
        if units + needed > limit && !current.is_empty() {
            chunks.push(std::mem::take(&mut current));
            units = 0;
        }
        current.push(ch);
        units += needed;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// The keystrokes for `text`: each line as Unicode `Text` events (chunked,
/// surrogate pairs kept whole) and an Enter press between lines.
fn text_plan(text: &str) -> Vec<Step> {
    let mut plan = Plan::default();
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            plan.tap(ENTER_SCAN_CODE);
            plan.pause(20);
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        for chunk in split_utf16(line, TEXT_CHUNK_UNITS) {
            plan.text(&chunk);
            plan.pause(15);
        }
    }
    plan.steps
}

/// Type `text` into whatever is focused on this machine.
pub(crate) fn type_text(text: &str, consent: &dyn Fn() -> bool) -> Result<String, String> {
    if text.encode_utf16().count() > TEXT_MAX_UNITS || text.lines().count() > TEXT_MAX_LINES {
        return Err(format!(
            "text is too long for one call (at most {TEXT_MAX_LINES} lines and \
             {TEXT_MAX_UNITS} characters) — send it in parts"
        ));
    }
    key_guard(None, &[], consent)?;
    let mut sink = LocalInput::open()?;
    let steps = text_plan(text);
    play(&mut sink, &steps, &key_guard(None, &[], consent))?;
    let chars = text.chars().filter(|ch| *ch != '\r').count();
    Ok(format!("typed {chars} character(s) on this machine"))
}

/// The keystrokes for one chord: modifiers down (as given), the key tapped
/// `count` times, modifiers up in REVERSE order.
fn key_plan(key: (u16, bool), modifiers: &[Modifier], count: u64) -> Vec<Step> {
    let mut plan = Plan::default();
    for modifier in modifiers {
        let (scan_code, extended) = modifier.scan_code();
        plan.key(scan_code, extended, ButtonState::Pressed);
    }
    if !modifiers.is_empty() {
        plan.pause(40);
    }
    for _ in 0..count {
        plan.tap(key);
        plan.pause(40);
    }
    for modifier in modifiers.iter().rev() {
        let (scan_code, extended) = modifier.scan_code();
        plan.key(scan_code, extended, ButtonState::Released);
    }
    plan.steps
}

/// Press a key `count` times on this machine, with `modifiers` held.
pub(crate) fn press_key(
    key: (u16, bool),
    modifiers: &[Modifier],
    count: u64,
    consent: &dyn Fn() -> bool,
) -> Result<String, String> {
    key_guard(Some(key), modifiers, consent)?;
    let mut sink = LocalInput::open()?;
    let steps = key_plan(key, modifiers, count);
    play(&mut sink, &steps, &key_guard(Some(key), modifiers, consent))?;
    Ok(format!(
        "pressed the key {} time(s) on this machine",
        count.max(1)
    ))
}

/// Turn the wheel `notches` times (positive = up, negative = down), at
/// normalized (`x`, `y`) when a point is given, else at the pointer.
/// `point` (monitor pixels) is for the own-window guard.
pub(crate) fn scroll(
    notches: i64,
    at: Option<(u16, u16)>,
    point: Option<(i32, i32)>,
    consent: &dyn Fn() -> bool,
) -> Result<String, String> {
    mouse_guard(point, consent)?;
    let notches = notches.clamp(-WHEEL_MAX_NOTCHES, WHEEL_MAX_NOTCHES);
    let mut sink = LocalInput::open()?;
    let mut plan = Plan::default();
    if let Some((x, y)) = at {
        plan.move_to(x, y);
        plan.pause(60);
    }
    for _ in 0..notches.unsigned_abs() {
        plan.wheel(if notches > 0 {
            WHEEL_NOTCH
        } else {
            -WHEEL_NOTCH
        });
        plan.pause(30);
    }
    play(&mut sink, &plan.steps, &mouse_guard(point, consent))?;
    Ok(format!(
        "scrolled {} notch(es) {} on this machine",
        notches.unsigned_abs(),
        if notches > 0 { "up" } else { "down" }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plan as labels, pauses dropped (the order of input is what the
    /// tests pin). Test-only: never used for logging.
    fn outline(steps: &[Step]) -> Vec<String> {
        let mut out = Vec::new();
        for step in steps {
            match step {
                Step::Events(events) => {
                    for event in events {
                        out.push(match event {
                            InputEvent::Key {
                                scan_code, state, ..
                            } => format!("{state:?} {scan_code:#04x}"),
                            InputEvent::Text { code_points, .. } => {
                                format!("text {code_points:?}")
                            }
                            InputEvent::MouseMove { x, y, .. } => format!("move {x} {y}"),
                            InputEvent::MouseButton { button, state, .. } => {
                                format!("{state:?} {button:?}")
                            }
                            InputEvent::Wheel { delta_v, .. } => format!("wheel {delta_v}"),
                            InputEvent::AllKeysUp { .. } => "all up".to_owned(),
                        });
                    }
                }
                Step::Pause(_) => {}
            }
        }
        out
    }

    #[test]
    fn utf16_chunks_keep_surrogate_pairs_whole() {
        assert_eq!(split_utf16("hello", 5), vec!["hello"]);
        assert_eq!(split_utf16("hello", 2), vec!["he", "ll", "o"]);
        assert!(split_utf16("", 4).is_empty());
        // 'a' (1 unit), the emoji (2 units), 'b' (1 unit).
        assert_eq!(split_utf16("a😀b", 2), vec!["a", "😀", "b"]);
        assert_eq!(split_utf16("a😀b", 3), vec!["a😀", "b"]);
        assert_eq!(
            split_utf16("a😀b", 1),
            vec!["a", "😀", "b"],
            "a limit below one pair still never splits it"
        );
        let long = "x".repeat(1000);
        let chunks = split_utf16(&long, TEXT_CHUNK_UNITS);
        assert_eq!(
            chunks.iter().map(String::len).collect::<Vec<_>>(),
            vec![400, 400, 200]
        );
    }

    #[test]
    fn typed_text_presses_enter_between_lines() {
        assert_eq!(
            outline(&text_plan("ab\ncd")),
            vec![
                "text \"ab\"",
                "Pressed 0x1c",
                "Released 0x1c",
                "text \"cd\""
            ]
        );
        // Windows line endings and empty lines.
        assert_eq!(
            outline(&text_plan("a\r\n\r\nb")),
            vec![
                "text \"a\"",
                "Pressed 0x1c",
                "Released 0x1c",
                "Pressed 0x1c",
                "Released 0x1c",
                "text \"b\"",
            ]
        );
        let long = "y".repeat(900);
        let typed = outline(&text_plan(&long))
            .into_iter()
            .filter(|line| line.starts_with("text"))
            .count();
        assert_eq!(typed, 3, "900 characters arrive as three chunks");
    }

    #[test]
    fn a_chord_holds_modifiers_around_the_key_and_releases_in_reverse() {
        let key = (0x2Eu16, false); // 'c'
        assert_eq!(
            outline(&key_plan(key, &[Modifier::Ctrl], 1)),
            vec![
                "Pressed 0x1d",
                "Pressed 0x2e",
                "Released 0x2e",
                "Released 0x1d"
            ]
        );
        assert_eq!(
            outline(&key_plan(key, &[Modifier::Ctrl, Modifier::Shift], 2)),
            vec![
                "Pressed 0x1d",
                "Pressed 0x2a",
                "Pressed 0x2e",
                "Released 0x2e",
                "Pressed 0x2e",
                "Released 0x2e",
                "Released 0x2a",
                "Released 0x1d",
            ]
        );
        assert_eq!(
            outline(&key_plan((0x5Bu16, true), &[], 1)),
            vec!["Pressed 0x5b", "Released 0x5b"]
        );
    }

    #[test]
    fn modifiers_parse_case_insensitively_and_nothing_else() {
        assert_eq!(Modifier::parse("CTRL"), Some(Modifier::Ctrl));
        assert_eq!(Modifier::parse(" Shift "), Some(Modifier::Shift));
        assert_eq!(Modifier::parse("alt"), Some(Modifier::Alt));
        assert_eq!(Modifier::parse("Windows"), Some(Modifier::Win));
        assert_eq!(Modifier::parse("x"), None);
        assert_eq!(Modifier::parse(""), None);
        assert_eq!(Modifier::Win.scan_code(), (0x5B, true));
    }

    #[test]
    fn only_shell_shortcuts_hand_control_to_windows() {
        let esc = (0x01u16, false);
        let tab = (0x0Fu16, false);
        let r = (0x13u16, false);
        assert!(hands_off_to_windows((0x5Bu16, true), &[]), "bare Win");
        assert!(hands_off_to_windows(r, &[Modifier::Win]), "win+r");
        assert!(hands_off_to_windows(esc, &[Modifier::Ctrl]), "ctrl+esc");
        assert!(hands_off_to_windows(tab, &[Modifier::Alt]), "alt+tab");
        assert!(!hands_off_to_windows(r, &[]), "plain r types into the app");
        assert!(
            !hands_off_to_windows(r, &[Modifier::Ctrl]),
            "ctrl+r stays in it"
        );
        assert!(!hands_off_to_windows(tab, &[]));
    }

    #[test]
    fn monitor_pixels_map_into_the_screenshot_and_off_it() {
        let shot = (1600u32, 900u32);
        let screen = (1920u32, 1080u32);
        assert_eq!(
            fit_to_shot(960, 540, shot.0, shot.1, screen.0, screen.1),
            Some((800, 450))
        );
        assert_eq!(
            fit_to_shot(1919, 1079, shot.0, shot.1, screen.0, screen.1),
            Some((1599, 899))
        );
        assert_eq!(fit_to_shot(-1, 5, shot.0, shot.1, screen.0, screen.1), None);
        assert_eq!(
            fit_to_shot(1920, 0, shot.0, shot.1, screen.0, screen.1),
            None
        );
        assert_eq!(
            fit_to_shot(5, 1080, shot.0, shot.1, screen.0, screen.1),
            None
        );
    }

    /// Runs on a real desktop (the developer machine) and on CI, where
    /// there may be none to copy from: it must never panic either way and,
    /// when a picture comes back, it must be a well-formed downscaled JPEG.
    #[test]
    fn a_capture_is_a_well_formed_jpeg_or_a_typed_error() {
        match screenshot() {
            Ok(shot) => {
                assert!(shot.space.width > 0 && shot.space.height > 0);
                assert!(shot.space.width.max(shot.space.height) <= MAX_EDGE);
                assert!(shot.space.screen_width >= shot.space.width);
                assert_eq!(&shot.jpeg[..2], &[0xFF, 0xD8], "JPEG magic");
                if let Some((x, y)) = shot.cursor {
                    assert!(x < shot.space.width && y < shot.space.height);
                }
            }
            Err(err) => eprintln!("no desktop to capture here: {err}"),
        }
    }

    #[test]
    fn oversized_text_is_refused_before_anything_is_typed() {
        let never = || false;
        let too_many_lines = "a\n".repeat(TEXT_MAX_LINES + 1);
        assert!(
            type_text(&too_many_lines, &never)
                .unwrap_err()
                .contains("too long")
        );
        let too_long = "x".repeat(TEXT_MAX_UNITS + 1);
        assert!(
            type_text(&too_long, &never)
                .unwrap_err()
                .contains("too long")
        );
    }

    /// A plan stops at the first group its live guard refuses — the desktop
    /// can change between one group and the next (a consent prompt appears
    /// and pulls this app to the front, the human alt-tabs back into it).
    #[test]
    fn a_plan_stops_at_the_first_refused_group() {
        let mut sink = match LocalInput::open() {
            Ok(sink) => sink,
            Err(err) => return eprintln!("no desktop to inject on here: {err}"),
        };
        // `AllKeysUp` with nothing held is the sink's documented no-op, so
        // this plan touches no window.
        let nothing = InputEvent::AllKeysUp {
            trigger: AllKeysUpTrigger::Disconnect,
        };
        let steps = vec![
            Step::Events(vec![nothing.clone()]),
            Step::Events(vec![nothing.clone()]),
            Step::Events(vec![nothing]),
        ];
        let groups = std::cell::Cell::new(0u32);
        let guard = || {
            groups.set(groups.get() + 1);
            if groups.get() < 3 {
                Ok(())
            } else {
                Err("refused".to_owned())
            }
        };
        assert_eq!(
            play(&mut sink, &steps, &guard),
            Err("refused".to_owned()),
            "the third group is where the guard says no"
        );
        assert_eq!(groups.get(), 3, "asked before every group");
    }
}
