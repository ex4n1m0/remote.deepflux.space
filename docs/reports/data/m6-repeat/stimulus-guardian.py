#!/usr/bin/env python
"""Stimulus guardian (repeat-soak harness, attempt 2).

Attempt 1 (attempt1-staticdesktop/) hit the M5-era static-desktop pitfall:
the controller's viewer window ("M2 rig controller (real desktop capture)",
created ~1 s after the host) covered the rig's GDI stimulus window, and
after one early decode reset the IDR gate waited for a keyframe the host
could never attach (no screen changes -> no captures) -- a stillness
fixpoint: 4 presents in 6 minutes while Connected, zero host captures.

The rig's own methodology comment (m2_rig.rs spawn_stimulus) says the
stimulus exists to "guarantee desktop updates during soaks". This harness
enforces that guarantee against window z-order chance: every 2 s it
re-asserts HWND_TOPMOST on the stimulus window. Environment control only --
no rig/product code is changed, and the soak configuration is identical to
the documented M6 run (congestion ON, loss=4, two processes).

Usage: python stimulus-guardian.py <stop_after_secs>

Attempt-3 addition (keep-awake): a password-protected screensaver locked
the console at minute ~40 of attempt 3 (input desktop "Screen-saver" ->
DDA E_ACCESSDENIED for the rest of the run; product held Connected and
polled per the F71 AccessDenied policy, memory flat -- see
attempt3-lockscreensaver/). ES_CONTINUOUS | ES_SYSTEM_REQUIRED |
ES_DISPLAY_REQUIRED holds the display "in use" so an idle screensaver
cannot engage during a soak. Environment control only.
"""
import sys
import time
import ctypes
import ctypes.wintypes as w

user32 = ctypes.windll.user32
FindWindowW = user32.FindWindowW
SetWindowPos = user32.SetWindowPos
IsWindowVisible = user32.IsWindowVisible

HWND_TOPMOST = w.HWND(-1)
SWP_NOMOVE = 0x0002
SWP_NOSIZE = 0x0001
SWP_NOACTIVATE = 0x0010
SWP_SHOWWINDOW = 0x0040


def main() -> int:
    stop_after = float(sys.argv[1]) if len(sys.argv) > 1 else 3800.0
    t0 = time.time()
    raised = 0
    # Keep-awake (attempt 3 lesson): block idle screensaver/lock.
    ES_CONTINUOUS = 0x80000000
    ES_SYSTEM_REQUIRED = 0x00000001
    ES_DISPLAY_REQUIRED = 0x00000002
    ctypes.windll.kernel32.SetThreadExecutionState(
        ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED
    )
    while time.time() - t0 < stop_after:
        hwnd = FindWindowW(None, "M2 rig stimulus")
        if hwnd:
            ok = SetWindowPos(
                hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW,
            )
            if ok:
                raised += 1
        time.sleep(2.0)
    print(f"guardian: raised stimulus {raised} times over {time.time()-t0:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
