/** Component tests (jsdom + testing-library). No Tauri imports here —
 * components receive data via props and report via callbacks. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { HostPanel } from "../components/HostPanel";
import { Favorites } from "../components/Favorites";
import { SessionControls } from "../components/ControllerPanel";
import { DiagnosticsOverlay } from "../components/DiagnosticsOverlay";
import { ErrorBanner } from "../components/Common";
import type { DiagSnapshot, Favorite } from "../types";

const monitor = (id: string, primary = false) => ({
  monitor_id: id,
  label: `${id} 1920x1080`,
  width_px: 1920,
  height_px: 1080,
  is_primary: primary,
  desktop_left: 0,
  desktop_top: 0,
});

afterEach(cleanup);

describe("HostPanel consent prompt", () => {
  it("shows accept/reject only while ConsentPrompted with a pending request", () => {
    const onAccept = vi.fn();
    const { rerender } = render(
      <HostPanel
        hostState="Online"
        consent={null}
        connectionCode="code"
        onStart={() => {}}
        onStop={() => {}}
        onAccept={onAccept}
        onReject={() => {}}
      />,
    );
    expect(screen.queryByRole("alertdialog")).toBeNull();

    rerender(
      <HostPanel
        hostState="ConsentPrompted"
        consent={{ controller_device_id: "ctrl-9", session_id: "s1" }}
        connectionCode="code"
        onStart={() => {}}
        onStop={() => {}}
        onAccept={onAccept}
        onReject={() => {}}
      />,
    );
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    expect(screen.getByText("ctrl-9")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Accept" }));
    expect(onAccept).toHaveBeenCalledTimes(1);
  });

  it("offers Share when idle and Stop when online", () => {
    const onStart = vi.fn();
    const onStop = vi.fn();
    const { rerender } = render(
      <HostPanel hostState="Idle" consent={null} connectionCode="c" onStart={onStart} onStop={onStop} onAccept={() => {}} onReject={() => {}} />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Share this machine" }));
    expect(onStart).toHaveBeenCalledTimes(1);
    rerender(
      <HostPanel hostState="Online" consent={null} connectionCode="c" onStart={onStart} onStop={onStop} onAccept={() => {}} onReject={() => {}} />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Stop sharing" }));
    expect(onStop).toHaveBeenCalledTimes(1);
  });
});

describe("Favorites", () => {
  const base = {
    peerOnline: {},
    canConnect: true,
    onConnect: vi.fn(),
    onAdd: vi.fn(async () => {}),
    onRemove: vi.fn(),
    onRename: vi.fn(),
  };
  const favs: Favorite[] = [
    { id: "f1", name: "Office PC", code: "aaaaaaaaaaaaaaaa" },
    { id: "f2", name: "", code: "bbbbbbbbbbbbbbbb" },
  ];

  it("adds via the form (code normalized by the caller wiring)", async () => {
    render(<Favorites {...base} favorites={[]} />);
    fireEvent.change(screen.getByLabelText("Connection code"), {
      target: { value: "CCCCDDDD" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add favorite" }));
    await waitFor(() => expect(base.onAdd).toHaveBeenCalled());
    expect(base.onAdd).toHaveBeenCalledWith("", "ccccdddd");
  });

  it("lists favorites with connect/remove/rename", () => {
    render(<Favorites {...base} favorites={favs} />);
    expect(screen.getByText("Office PC")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Connect to Office PC" }));
    expect(base.onConnect).toHaveBeenCalledWith("aaaaaaaaaaaaaaaa");
    fireEvent.click(screen.getByRole("button", { name: "Remove Office PC" }));
    expect(base.onRemove).toHaveBeenCalledWith("f1");
  });

  it("renames inline", () => {
    render(<Favorites {...base} favorites={favs} />);
    fireEvent.click(screen.getByRole("button", { name: "Rename Office PC" }));
    const input = screen.getByLabelText("New name for Office PC");
    fireEvent.change(input, { target: { value: "Workstation" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(base.onRename).toHaveBeenCalledWith("f1", "Workstation");
  });

  it("marks online favorites", () => {
    render(
      <Favorites {...base} favorites={favs} peerOnline={{ aaaaaaaaaaaaaaaa: true }} />,
    );
    const dot = screen.getByLabelText("online");
    expect(dot).toBeTruthy();
  });
});

describe("SessionControls", () => {
  const base = {
    activeMonitor: "\\\\.\\DISPLAY1",
    quality: "balanced",
    scale: "fit",
    viewerCreated: true,
    onQuality: vi.fn(),
    onMonitor: vi.fn(),
    onScale: vi.fn(),
    onFullscreen: vi.fn(),
    onDisconnect: vi.fn(),
  };

  it("picks monitors and quality, toggles scale and fullscreen, disconnects", () => {
    render(
      <SessionControls {...base} monitors={[monitor("\\\\.\\DISPLAY1", true), monitor("\\\\.\\DISPLAY2")]} />,
    );
    fireEvent.click(screen.getByLabelText(/DISPLAY2/));
    expect(base.onMonitor).toHaveBeenCalledWith("\\\\.\\DISPLAY2");
    fireEvent.click(screen.getByLabelText(/High \(1440p60/));
    expect(base.onQuality).toHaveBeenCalledWith("high");
    fireEvent.click(screen.getByLabelText("1:1 pixels"));
    expect(base.onScale).toHaveBeenCalledWith("one_to_one");
    fireEvent.click(screen.getByRole("button", { name: /Fullscreen/ }));
    expect(base.onFullscreen).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Disconnect" }));
    expect(base.onDisconnect).toHaveBeenCalledTimes(1);
  });

  it("waits for the host monitor list", () => {
    render(<SessionControls {...base} monitors={[]} />);
    expect(screen.getByText(/Waiting for the host's monitor list/)).toBeTruthy();
  });
});

describe("DiagnosticsOverlay", () => {
  const snapshot: DiagSnapshot = {
    session_id: "s1",
    origin: "controller",
    stages_ms: {
      decode_to_present: { p50_ms: 2.25, p95_ms: 4.5, count: 120 },
    },
    fps: { present: 59.7 },
    link: { send_bitrate_kbps: 120, recv_bitrate_kbps: 6100, rtt_ms: 0.31, loss_percent: 0 },
    queues: {
      decode_to_present: { depth: 0, capacity: 1, high_water: 1, dropped: 2, replaced: 3 },
    },
    input: { applied: 40, suppressed: 1, gaps: 0, all_keys_up: 2, held: 0, inject_errors: 0 },
    encoder: "enc (software)",
    encoder_kind: "software",
    encoder_rebuilds: 1,
    viewer_input_dropped: 0,
  };

  it("renders per-stage p50/p95, link, encoder kind, queues", () => {
    render(<DiagnosticsOverlay snapshot={snapshot} />);
    // The stage name also appears as a queue name (same schema key).
    expect(screen.getAllByText("decode_to_present").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("2.3 ms")).toBeTruthy();
    expect(screen.getByText("4.5 ms")).toBeTruthy();
    expect(screen.getByText(/rtt 0.31 ms/)).toBeTruthy();
    expect(screen.getByText(/present 60/)).toBeTruthy();
    expect(screen.getByText(/^software/)).toBeTruthy();
    expect(screen.getByText(/rebuilds 1/)).toBeTruthy();
    expect(screen.getByText(/all-up 2/)).toBeTruthy();
  });

  it("shows a waiting state without a snapshot", () => {
    render(<DiagnosticsOverlay snapshot={null} />);
    expect(screen.getByText(/Waiting for counters/)).toBeTruthy();
  });
});

describe("ErrorBanner", () => {
  it("shows the direct-connection hint when present", () => {
    const onDismiss = vi.fn();
    render(
      <ErrorBanner
        message="The direct connection failed or dropped."
        hint="This build supports direct connections only (no relay)."
        onDismiss={onDismiss}
      />,
    );
    expect(screen.getByRole("alert")).toBeTruthy();
    expect(screen.getByText(/direct connections only/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Dismiss error" }));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });
});
