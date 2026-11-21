/** Swarm-enrollment component tests (ADR-013, jsdom + testing-library):
 * the join modal (userCode, countdown, dashboard link, cancel), the
 * rail's join entry + "This machine" chip, the Config → Swarm section,
 * and the hook wiring (modal close on rejection/failure, the post-listen
 * status re-fetch). Components receive state via props and report via
 * callbacks; the ipc module is mocked where a tree pulls it in. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, renderHook, screen, waitFor } from "@testing-library/react";
import { SwarmJoinModal } from "../components/SwarmJoinModal";
import { MachinesRail } from "../components/MachinesRail";
import { SwarmSection } from "../components/ConfigDialog";
import { useSwarm, useSwarmJoinModal, type SwarmBinding } from "../hooks/useSwarm";
import { SWARM_DASHBOARD_URL } from "../state/swarm";
import { api } from "../ipc";
import type { Mock } from "vitest";
import type { SwarmState } from "../types";

vi.mock("../ipc", () => ({
  api: {
    swarmStatus: vi.fn(),
    swarmJoin: vi.fn(async () => {}),
    swarmCancelJoin: vi.fn(async () => {}),
    swarmClaimAnswer: vi.fn(async () => {}),
    swarmRekey: vi.fn(async () => "NewId1111111111111111111111111111111111"),
    swarmLeave: vi.fn(async () => {}),
    pairingsList: vi.fn(),
    pairingRemove: vi.fn(async () => {}),
    pairingRename: vi.fn(async () => {}),
  },
  EVENT: {},
  ASSISTANT_EVENT: "assistant://log",
  CHAT_EVENT: "engine://chat",
  UPDATE_EVENT: "update://state",
  SWARM_EVENT: "swarm://state",
}));

// useSwarm lazily imports the event module; stub it so the listener
// installs and the post-listen re-fetch runs in jsdom.
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => {}),
}));

const joined: SwarmState = {
  status: "joined",
  installation_id: "9ZkdqFPeqQFMbAtgS2M8b1aVvzGk4TQsN1WjnUpeTXW2",
  session_expires_at_ms: Date.now() + 12 * 60 * 60 * 1000,
};

afterEach(cleanup);

const binding = (state: SwarmState | null, join?: () => Promise<void>): SwarmBinding => ({
  state,
  join: join ?? (vi.fn(async () => {}) as unknown as () => Promise<void>),
  cancelJoin: vi.fn(),
  leave: vi.fn(),
  claimAnswer: vi.fn(),
  rekey: vi.fn(async () => "NewId"),
});


describe("SwarmJoinModal", () => {
  const joining: SwarmState = {
    status: "joining",
    user_code: "AB2CDEFG",
    expires_at_ms: Date.now() + 9 * 60 * 1000 + 42_000,
  };

  it("shows the big userCode, the countdown, and the dashboard verb", () => {
    render(<SwarmJoinModal state={joining} onCancel={() => {}} onClaimAnswer={() => {}} />);
    expect(screen.getByText("AB2CDEFG")).toBeTruthy();
    expect(screen.getByRole("code")).toBeTruthy();
    // Countdown rides the status line ("expires in 9:4x" over the tick).
    expect(screen.getByText(/expires in 9:4\d/i)).toBeTruthy();
    expect(screen.getByText(/Approve this machine on the website/i)).toBeTruthy();
    const dash = screen.getByRole("button", { name: /Approve it on the website/i });
    expect(dash).toBeTruthy();
  });

  it("opens the tracker dashboard in the default browser (MenuBar precedent)", () => {
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    render(<SwarmJoinModal state={joining} onCancel={() => {}} onClaimAnswer={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /Approve it on the website/i }));
    expect(open).toHaveBeenCalledWith(SWARM_DASHBOARD_URL, "_blank", "noopener");
    open.mockRestore();
  });

  it("cancel fires the callback", () => {
    const onCancel = vi.fn();
    render(<SwarmJoinModal state={joining} onCancel={onCancel} onClaimAnswer={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("still renders (placeholder code) before the joining state lands", () => {
    render(<SwarmJoinModal state={null} onCancel={() => {}} onClaimAnswer={() => {}} />);
    expect(screen.getByText("…")).toBeTruthy();
    expect(screen.getByText(/Starting…/i)).toBeTruthy();
  });
});

describe("SwarmJoinModal claim handshake (gate (a))", () => {
  const claim: SwarmState = {
    status: "confirm_claim",
    claimed_by: "i***@example.com",
    expires_at_ms: Date.now() + 5 * 60 * 1000,
  };

  it("names the masked claimer and fires Allow/Deny", () => {
    const onClaimAnswer = vi.fn();
    render(<SwarmJoinModal state={claim} onCancel={() => {}} onClaimAnswer={onClaimAnswer} />);
    expect(screen.getByText(/Claimed by account i\*\*\*@example\.com/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Allow — add this machine/i }));
    expect(onClaimAnswer).toHaveBeenCalledWith(true);
    fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    expect(onClaimAnswer).toHaveBeenCalledWith(false);
    // The pairing-code view is replaced (no code shown during a claim).
    expect(screen.queryByText("AB2CDEFG")).toBeNull();
  });

  it("explain why denying is safe", () => {
    render(<SwarmJoinModal state={claim} onCancel={() => {}} onClaimAnswer={() => {}} />);
    expect(screen.getByText(/Denying returns the pairing code to pending/i)).toBeTruthy();
  });
});

describe("shouldCloseJoinModal over the claim handshake", () => {
  it("stays open through joining → confirm_claim → joining (deny); closes on resolve", async () => {
    const { result, rerender } = renderHook((p: SwarmBinding) => useSwarmJoinModal(p), {
      initialProps: binding({ status: "not_joined" }),
    });
    act(() => result.current.openJoin());
    rerender(binding({ status: "joining", user_code: "AB2CDEFG", expires_at_ms: 1 }));
    expect(result.current.open).toBe(true);
    rerender(
      binding({ status: "confirm_claim", claimed_by: "i***@example.com", expires_at_ms: 1 }),
    );
    expect(result.current.open).toBe(true);
    rerender(binding({ status: "joining", user_code: "AB2CDEFG", expires_at_ms: 1 }));
    expect(result.current.open).toBe(true);
    rerender(binding(joined));
    await waitFor(() => expect(result.current.open).toBe(false));
  });
});

describe("MachinesRail swarm entry + chip (ADR-013)", () => {
  const rail = (over: Partial<Parameters<typeof MachinesRail>[0]>) =>
    render(
      <MachinesRail
        machines={[]}
        thisCode="0123456789abcdef"
        thisName={null}
        hostState="Online"
        sharing={false}
        swarmChip={null}
        swarmJoinable={true}
        onJoinSwarm={() => {}}
        onPick={() => {}}
        onConnect={() => {}}
        onShare={() => {}}
        onStopShare={() => {}}
        {...over}
      />,
    );

  it("offers Join a swarm near the connection-code box; the verb fires", () => {
    const onJoinSwarm = vi.fn();
    rail({ onJoinSwarm });
    fireEvent.click(screen.getByRole("button", { name: /Join a swarm/i }));
    expect(onJoinSwarm).toHaveBeenCalledTimes(1);
  });

  it("hides the join entry when it is not joinable", () => {
    rail({ swarmJoinable: false });
    expect(screen.queryByRole("button", { name: /Join a swarm/i })).toBeNull();
  });

  it("pins the swarm chip on the This-machine card when joined", () => {
    rail({ swarmChip: "swarm · 9ZkdqFPe…" });
    expect(screen.getByText("swarm · 9ZkdqFPe…")).toBeTruthy();
    // and no chip when not joined
    cleanup();
    rail({ swarmChip: null });
    expect(screen.queryByText(/swarm · /)).toBeNull();
  });
});

describe("SwarmSection (Config → Swarm)", () => {
  it("joined: status line names the installation, Leave + dashboard verbs", () => {
    const onLeave = vi.fn();
    render(
      <SwarmSection state={joined} onJoin={() => {}} onLeave={onLeave} onRekey={vi.fn(async () => "NewId")} />,
    );
    expect(screen.getByText(/Joined as 9ZkdqFPe/i)).toBeTruthy();
    expect(screen.getByText(/Session valid until/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Join a swarm/i })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /Leave this swarm/i }));
    expect(onLeave).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: /Open the dashboard/i })).toBeTruthy();
  });

  it("not joined: the Join verb fires and there is no Leave", () => {
    const onJoin = vi.fn();
    render(
      <SwarmSection state={{ status: "not_joined" }} onJoin={onJoin} onLeave={() => {}} onRekey={vi.fn(async () => "NewId")} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /Join a swarm/i }));
    expect(onJoin).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: /Leave this swarm/i })).toBeNull();
  });

  it("needs_rejoin: the notice shows and the rejoin verb is offered", () => {
    const onJoin = vi.fn();
    render(
      <SwarmSection
        state={{ status: "needs_rejoin", reason: "removed on the website" }}
        onJoin={onJoin}
        onLeave={() => {}}
        onRekey={vi.fn(async () => "NewId")}
      />,
    );
    expect(screen.getByText(/removed on the website/i)).toBeTruthy();
    expect(screen.getByText(/needs to rejoin the swarm/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Join a swarm/i }));
    expect(onJoin).toHaveBeenCalledTimes(1);
  });

  it("failed: the reason surfaces verbatim", () => {
    render(
      <SwarmSection
        state={{ status: "failed", reason: "swarm enroll: HTTP 502" }}
        onJoin={() => {}}
        onLeave={() => {}}
        onRekey={vi.fn(async () => "NewId")}
      />,
    );
    expect(screen.getByText(/swarm enroll: HTTP 502/i)).toBeTruthy();
  });

  it("documents that leaving is local-only (dashboard revoke is authoritative)", () => {
    render(
      <SwarmSection state={joined} onJoin={() => {}} onLeave={() => {}} onRekey={vi.fn(async () => "NewId")} />,
    );
    expect(screen.getByText(/removing the machine for good happens on the\s+dashboard/i)).toBeTruthy();
  });
});

describe("useSwarmJoinModal", () => {

  afterEach(() => {
    vi.mocked(api.swarmJoin).mockReset();
    vi.mocked(api.swarmJoin).mockImplementation(async () => {});
  });

  it("closes the modal when the join invoke rejects", async () => {
    vi.mocked(api.swarmJoin).mockImplementationOnce(() => Promise.reject(new Error("ipc down")));
    const { result } = renderHook(() =>
      useSwarmJoinModal(binding({ status: "not_joined" }, api.swarmJoin)),
    );
    act(() => result.current.openJoin());
    expect(result.current.open).toBe(true);
    await waitFor(() => expect(result.current.open).toBe(false));
  });

  it("closes on a terminal failure reached without ever entering joining (failed start)", async () => {
    const { result, rerender } = renderHook((p: SwarmBinding) => useSwarmJoinModal(p), {
      initialProps: binding({ status: "not_joined" }),
    });
    act(() => result.current.openJoin());
    expect(result.current.open).toBe(true);
    // The start POST fails: not_joined → failed, never passing joining.
    rerender(binding({ status: "failed", reason: "swarm enroll: HTTP 500" }));
    await waitFor(() => expect(result.current.open).toBe(false));
  });

  it("stays open while the start is in flight, closes when the join resolves", async () => {
    const { result, rerender } = renderHook((p: SwarmBinding) => useSwarmJoinModal(p), {
      initialProps: binding({ status: "not_joined" }),
    });
    act(() => result.current.openJoin());
    expect(result.current.open).toBe(true);
    // Start landed: joining. Still open (countdown running).
    rerender(binding({ status: "joining", user_code: "AB2CDEFG", expires_at_ms: 1 }));
    expect(result.current.open).toBe(true);
    // Approved: joining → joined closes.
    rerender(binding(joined));
    await waitFor(() => expect(result.current.open).toBe(false));
  });

  it("cancel closes the modal and abandons the join", () => {
    const cancelJoin = vi.fn();
    const { result } = renderHook(() =>
      useSwarmJoinModal({
        state: null,
        join: vi.fn(async () => {}),
        cancelJoin,
        leave: vi.fn(),
        claimAnswer: vi.fn(),
        rekey: vi.fn(async () => "NewId"),
      }),
    );
    act(() => result.current.openJoin());
    act(() => result.current.cancel());
    expect(result.current.open).toBe(false);
    expect(cancelJoin).toHaveBeenCalledTimes(1);
  });
});

describe("useSwarm (startup-race cover)", () => {
  afterEach(() => vi.mocked(api.swarmStatus).mockReset());

  it("re-fetches swarm_status once after the listener installs", async () => {
    // The Rust side emitted Joined during the dynamic-import window —
    // the first pull (pre-listener) missed it, the re-pull must not.
    (api.swarmStatus as Mock)
      .mockResolvedValueOnce({ status: "not_joined" })
      .mockResolvedValueOnce(joined);
    const { result } = renderHook(() => useSwarm());
    await waitFor(() => expect(result.current.state?.status).toBe("joined"));
    expect(api.swarmStatus).toHaveBeenCalledTimes(2);
  });

  it("survives a bridge-less environment without state (jsdom fallback)", async () => {
    (api.swarmStatus as Mock).mockRejectedValueOnce(new Error("no bridge"));
    const { result } = renderHook(() => useSwarm());
    // Give the async effect its ticks; state stays null, nothing throws.
    await act(async () => {
      await Promise.resolve();
    });
    expect(result.current.state).toBeNull();
  });
});

describe("SwarmSection re-key (gate (d))", () => {
  it("arms with a warning, then rekeys and reports the new installation", async () => {
    const onRekey = vi.fn(async () => "NewIdentity11111111111111111111111111");
    render(
      <SwarmSection state={joined} onJoin={() => {}} onLeave={() => {}} onRekey={onRekey} />,
    );
    // Hidden until armed; arming shows the destructive-warning banner.
    expect(screen.queryByRole("button", { name: /Yes, reset the identity/i })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /Reset this machine's identity/i }));
    expect(screen.getByText(/suspected stolen/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Yes, reset the identity/i }));
    expect(onRekey).toHaveBeenCalledTimes(1);
    await waitFor(() =>
      expect(screen.getByText(/New device identity minted \(NewIdent/)).toBeTruthy(),
    );
  });

  it("arming can be walked back", () => {
    render(
      <SwarmSection state={joined} onJoin={() => {}} onLeave={() => {}} onRekey={vi.fn(async () => "NewId")} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /Reset this machine's identity/i }));
    fireEvent.click(screen.getByRole("button", { name: "Keep it" }));
    expect(screen.queryByRole("button", { name: /Yes, reset the identity/i })).toBeNull();
  });
});
