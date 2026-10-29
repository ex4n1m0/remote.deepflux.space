/** Component tests (jsdom + testing-library). No Tauri imports here —
 * components receive data via props and report via callbacks (the one
 * exception, TrustedMachinesSection, mocks the ipc module). The
 * simplify pass (2026-10-26) replaced ConnectPanel/SessionControls with
 * the pinned SessionCard; HostPanel/Computers/Favorites were dead code
 * and are gone (host status lives in the rail's This-machine card). */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { SessionCard } from "../components/ControllerPanel";
import { DiagnosticsOverlay } from "../components/DiagnosticsOverlay";
import { ErrorBanner } from "../components/Common";
import { SettingsPanel } from "../components/IdentityCard";
import { TrustedMachinesSection } from "../components/TrustedMachines";
import { api } from "../ipc";
import type { DiagSnapshot, PairingInfo } from "../types";

vi.mock("../ipc", () => ({
  api: {
    pairingsList: vi.fn(),
    pairingRemove: vi.fn(async () => {}),
    pairingRename: vi.fn(async () => {}),
  },
  EVENT: {},
  ASSISTANT_EVENT: "assistant://log",
  CHAT_EVENT: "engine://chat",
}));

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

describe("SessionCard", () => {
  const base = {
    machineName: "Mom's PC",
    activeMonitor: "\\\\.\\DISPLAY1",
    quality: "balanced",
    scale: "fit",
    viewerCreated: true,
    agentSession: false,
    agentOrigin: false,
    onCancel: vi.fn(),
    onQuality: vi.fn(),
    onMonitor: vi.fn(),
    onScale: vi.fn(),
    onFullscreen: vi.fn(),
    onShowViewer: vi.fn(),
    onHideViewer: vi.fn(),
    onDisconnect: vi.fn(),
  };

  it("while asking: names the machine, offers cancel — no session controls yet", () => {
    render(<SessionCard {...base} controllerState="Requesting" monitors={[]} />);
    expect(screen.getByText(/Asking Mom's PC to allow control/i)).toBeTruthy();
    expect(screen.getByText(/Waiting for the host user to accept/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Cancel request" }));
    expect(base.onCancel).toHaveBeenCalledTimes(1);
    expect(screen.queryByText("Monitor")).toBeNull();
  });

  it("while live: names the machine, folds in the session controls, stops controlling", () => {
    render(
      <SessionCard
        {...base}
        controllerState="Connected"
        monitors={[monitor("\\\\.\\DISPLAY1", true), monitor("\\\\.\\DISPLAY2")]}
      />,
    );
    expect(screen.getByText(/Controlling Mom's PC/i)).toBeTruthy();
    fireEvent.click(screen.getByLabelText(/DISPLAY2/));
    expect(base.onMonitor).toHaveBeenCalledWith("\\\\.\\DISPLAY2");
    fireEvent.click(screen.getByLabelText(/High \(1440p60/));
    expect(base.onQuality).toHaveBeenCalledWith("high");
    fireEvent.click(screen.getByLabelText("1:1 pixels"));
    expect(base.onScale).toHaveBeenCalledWith("one_to_one");
    fireEvent.click(screen.getByRole("button", { name: /Fullscreen/ }));
    expect(base.onFullscreen).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Stop controlling" }));
    expect(base.onDisconnect).toHaveBeenCalledTimes(1);
  });

  it("waits for the host monitor list", () => {
    render(<SessionCard {...base} controllerState="Connected" monitors={[]} />);
    expect(screen.getByText(/Waiting for the host's monitor list/)).toBeTruthy();
  });

  it("falls back to a neutral name when the machine is unknown", () => {
    render(
      <SessionCard {...base} machineName={null} controllerState="Offering" monitors={[]} />,
    );
    expect(screen.getByText(/Asking the other machine to allow control/i)).toBeTruthy();
  });

  it("agent session: chat-only card offers Show the screen, no viewer controls", () => {
    const onShowViewer = vi.fn();
    const onDisconnect = vi.fn();
    render(
      <SessionCard
        {...base}
        controllerState="Connected"
        viewerCreated={false}
        agentSession
        monitors={[]}
        onShowViewer={onShowViewer}
        onDisconnect={onDisconnect}
      />,
    );
    expect(screen.getByText(/Agent session with Mom's PC/i)).toBeTruthy();
    expect(screen.queryByText("Monitor")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Show the screen" }));
    expect(onShowViewer).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Stop session" }));
    expect(onDisconnect).toHaveBeenCalledTimes(1);
  });

  it("agent session with the viewer attached renders the normal visual controls", () => {
    render(
      <SessionCard
        {...base}
        controllerState="Connected"
        viewerCreated
        agentSession
        monitors={[monitor("\\.\DISPLAY1", true)]}
      />,
    );
    expect(screen.getByText(/Controlling Mom's PC/i)).toBeTruthy();
    expect(screen.getByText("Monitor")).toBeTruthy();
  });

  it("agent session with the viewer attached offers hide: chat-only again, session stays", () => {
    const onHideViewer = vi.fn();
    render(
      <SessionCard
        {...base}
        controllerState="Connected"
        viewerCreated
        agentOrigin
        monitors={[]}
        onHideViewer={onHideViewer}
      />,
    );
    fireEvent.click(
      screen.getByRole("button", { name: /Hide the screen/ }),
    );
    expect(onHideViewer).toHaveBeenCalledTimes(1);
    // A visual session (no agent origin) never offers hide — closing
    // its viewer is the disconnect.
    cleanup();
    render(
      <SessionCard
        {...base}
        controllerState="Connected"
        viewerCreated
        monitors={[]}
      />,
    );
    expect(screen.queryByRole("button", { name: /Hide the screen/ })).toBeNull();
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
    input: { applied: 40, suppressed: 1, gaps: 0, all_keys_up: 2, held: 0, inject_errors: 3 },
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
    // F51: UIPI-blocked injections are visible in the overlay.
    expect(screen.getByText(/blocked 3/)).toBeTruthy();
  });

  it("omits the blocked counter when no injections failed", () => {
    render(
      <DiagnosticsOverlay
        snapshot={{
          ...snapshot,
          input: { ...snapshot.input, inject_errors: 0 },
        }}
      />,
    );
    expect(screen.queryByText(/blocked/)).toBeNull();
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

  it("defaults to a neutral title for non-connection errors", () => {
    render(<ErrorBanner message="favorite rename failed" hint={null} onDismiss={() => {}} />);
    expect(screen.getByRole("alert").textContent).toContain("Something went wrong");
    expect(screen.queryByText("Connection problem")).toBeNull();
  });
});

describe("SettingsPanel", () => {
  const settings = {
    device_id: "0011223344556677",
    device_name: "Office",
    signaling_base_url: "https://signaling.deepflux.space",
    default_quality: "balanced",
    default_viewer_scale: "fit",
    device_token: "t",
    host_sharing: true,
    agent_base_url: "https://api.deepseek.com/v1",
    agent_model: "deepseek-flash",
    launch_at_login: false,
    agent_download_domains: [] as string[],
    auto_update: true,
  } as const;

  it("shows the app version label (collapsed and open) when provided", () => {
    const { rerender } = render(
      <SettingsPanel settings={settings} onSave={vi.fn(async () => null)} version="0.4.4" />,
    );
    expect(screen.getByText(/App version:/).textContent).toContain("0.4.4");
    fireEvent.click(screen.getByRole("button", { name: "Open" }));
    rerender(
      <SettingsPanel settings={settings} onSave={vi.fn(async () => null)} version="0.4.4" />,
    );
    expect(screen.getByText(/App version:/).textContent).toContain("0.4.4");
  });

  it("hides the version label when the version is unavailable (tests/jsdom)", () => {
    render(<SettingsPanel settings={settings} onSave={vi.fn(async () => null)} version={null} />);
    expect(screen.queryByText(/App version:/)).toBeNull();
  });
});

describe("TrustedMachinesSection (ADR-009: the machine list)", () => {
  const pairing = (over: Partial<PairingInfo>): PairingInfo => ({
    code: "abcdef0123456789",
    secret_hex: "s",
    created_ms: 1,
    pending_ack: false,
    role: "host",
    name: null,
    ...over,
  });

  afterEach(() => vi.mocked(api.pairingsList).mockReset());

  it("shows the cached machine name beside the code; bare code when unnamed", async () => {
    vi.mocked(api.pairingsList).mockResolvedValue([
      pairing({ name: "MOMS-PC", code: "aaaaaaaaaaaaaaaa" }),
      pairing({ code: "bbbbbbbbbbbbbbbb" }),
    ]);
    render(<TrustedMachinesSection />);
    await waitFor(() => expect(screen.getByText("MOMS-PC")).toBeTruthy());
    expect(screen.getByText("aaaaaaaaaaaaaaaa")).toBeTruthy();
    // Unnamed rows show only the code.
    expect(screen.getByText("bbbbbbbbbbbbbbbb")).toBeTruthy();
  });

  it("renames a row through the rename verb", async () => {
    vi.mocked(api.pairingsList).mockResolvedValue([pairing({ code: "cccccccccccccccc" })]);
    render(<TrustedMachinesSection />);
    await waitFor(() => expect(screen.getByText("cccccccccccccccc")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Rename…" }));
    fireEvent.change(screen.getByLabelText(/Name for/), { target: { value: "Lab PC" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(api.pairingRename).toHaveBeenCalledWith("cccccccccccccccc", "Lab PC"),
    );
  });
});
