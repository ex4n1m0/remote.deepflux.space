/** Agent-first UI tests (ADR-005): machines unification + assistant panel. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import {
  MachinesRail,
  excludeSelf,
  filterMachines,
  unifiedMachines,
} from "../components/MachinesRail";
import { AssistantPanel } from "../components/AssistantPanel";
import type { AssistantBinding } from "../hooks/useAssistant";

afterEach(cleanup);

describe("unifiedMachines (ADR-003 union)", () => {
  const favorites = [
    { id: "f1", name: "Office", code: "aa" },
    { id: "f2", name: "Laptop", code: "bb" },
  ];

  it("signed out: favorites only, presence from session events", () => {
    const rows = unifiedMachines(favorites, null, [], { bb: true }, "bb");
    expect(rows.map((r) => r.code)).toEqual(["aa", "bb"]);
    expect(rows[0].online).toBeNull();
    expect(rows[1].online).toBe(true);
    expect(rows[1].active).toBe(true);
  });

  it("signed in: roster wins the name for shared codes, roster presence preferred", () => {
    const roster = [
      { id: "r1", name: "Mom's PC", code: "aa", added_at_ms: 0, updated_at_ms: 0, is_self: false },
    ];
    const rows = unifiedMachines(favorites, roster, ["aa"], {}, null);
    expect(rows).toHaveLength(2);
    expect(rows[0].name).toBe("Mom's PC");
    expect(rows[0].online).toBe(true);
    expect(rows[1].code).toBe("bb");
  });
});

describe("MachinesRail", () => {
  const base = {
    thisCode: "abcd1234efgh5678",
    hostState: "Idle" as const,
    sharing: false,
    onPick: vi.fn(),
    onConnect: vi.fn(),
    onAdd: vi.fn(async () => {}),
    onShare: vi.fn(),
    onStopShare: vi.fn(),
  };

  it("lists machines, marks selection, exposes one-step per-row control", () => {
    render(
      <MachinesRail
        {...base}
        machines={[
          { id: "1", name: "Mom's PC", code: "aa", online: true, active: true, trusted: false, fromCircle: false },
          { id: "2", name: "Office", code: "bb", online: null, active: false, trusted: false, fromCircle: false },
        ]}
      />,
    );
    expect(screen.getByText("Mom's PC")).toBeTruthy();
    expect(screen.getByText("This machine")).toBeTruthy();
    expect(screen.getByText("abcd1234efgh5678")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Control Mom's PC" }));
    expect(base.onConnect).toHaveBeenCalledWith("aa");
    expect(screen.getByRole("button", { name: "Share this machine" })).toBeTruthy();
  });

  it("teaches the one-list model in the header and empty state", () => {
    render(<MachinesRail {...base} machines={[]} />);
    expect(screen.getByText(/message or control — same list/i)).toBeTruthy();
    expect(screen.getByText(/No machines yet/i)).toBeTruthy();
    expect(
      screen.getByText(/one list is for messaging and remote control/i),
    ).toBeTruthy();
  });

  it("add form offers Save & control (save then connect in one step)", async () => {
    const onAdd = vi.fn(async () => {});
    const onConnect = vi.fn();
    render(<MachinesRail {...base} onAdd={onAdd} onConnect={onConnect} machines={[]} />);
    fireEvent.click(screen.getByRole("button", { name: "+ Add" }));
    fireEvent.change(screen.getByLabelText("Machine name"), {
      target: { value: "Lab PC" },
    });
    fireEvent.change(screen.getByLabelText("Connection code"), {
      target: { value: "CCCCDDDD" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save & control" }));
    await vi.waitFor(() => {
      expect(onAdd).toHaveBeenCalledWith("Lab PC", "ccccdddd");
      expect(onConnect).toHaveBeenCalledWith("ccccdddd");
    });
  });

  it("plain Save adds without connecting", async () => {
    const onAdd = vi.fn(async () => {});
    const onConnect = vi.fn();
    render(<MachinesRail {...base} onAdd={onAdd} onConnect={onConnect} machines={[]} />);
    fireEvent.click(screen.getByRole("button", { name: "+ Add" }));
    fireEvent.change(screen.getByLabelText("Connection code"), {
      target: { value: "ccccdddd" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await vi.waitFor(() => {
      expect(onAdd).toHaveBeenCalledWith("ccccdddd", "ccccdddd");
    });
    expect(onConnect).not.toHaveBeenCalled();
  });

  it("labels the This-machine chip with the friendly host status, not the state name", () => {
    render(
      <MachinesRail
        {...base}
        hostState="ConsentPrompted"
        machines={[]}
      />,
    );
    expect(screen.getByText("Connection request")).toBeTruthy();
    expect(screen.queryByText("ConsentPrompted")).toBeNull();
  });

  it("never claims connecting is unavailable (every Connect auto-starts)", () => {
    render(<MachinesRail {...base} machines={[]} />);
    expect(screen.queryByText(/connecting unavailable/i)).toBeNull();
  });

  it("empty state teaches the next action", () => {
    render(<MachinesRail {...base} machines={[]} />);
    expect(screen.getByText(/No machines yet/i)).toBeTruthy();
  });
});

describe("excludeSelf (self is never a connectable contact)", () => {
  const dir = [
    { device: "aaaaaaaaaaaaaaaa", name: "Mom's PC", online: true, refreshed_ms: 1, is_self: false },
    { device: "bbbbbbbbbbbbbbbb", name: "This PC", online: true, refreshed_ms: 1, is_self: true },
    { device: "cccccccccccccccc", name: "Lab", online: false, refreshed_ms: 1, is_self: false },
  ];

  it("drops the own row by is_self and by device id", () => {
    const rows = excludeSelf(dir, "cccccccccccccccc");
    expect(rows.map((r) => r.device)).toEqual(["aaaaaaaaaaaaaaaa"]);
  });

  it("keeps peers when identity has not loaded yet (is_self still applies)", () => {
    const rows = excludeSelf(dir, null);
    expect(rows.map((r) => r.device)).toEqual(["aaaaaaaaaaaaaaaa", "cccccccccccccccc"]);
  });
});

describe("AssistantPanel", () => {
  const makeAssistant = (over: Partial<AssistantBinding> = {}): AssistantBinding => ({
    messages: [],
    status: { configured: true, busy: false, base_url: "https://api.deepseek.com/v1", model: "deepseek-flash" },
    busy: false,
    send: vi.fn(async () => {}),
    configure: vi.fn(async () => {}),
    reset: vi.fn(async () => {}),
    ...over,
  });

  it("shows prompt starters when configured and idle", () => {
    render(<AssistantPanel assistant={makeAssistant()} />);
    expect(screen.getByText("Save a machine for me")).toBeTruthy();
    expect(screen.getByPlaceholderText(/ask anything/i)).toBeTruthy();
  });

  it("shows the key setup card when unconfigured and disables the composer", () => {
    render(
      <AssistantPanel
        assistant={makeAssistant({
          status: { configured: false, busy: false, base_url: "", model: "" },
        })}
      />,
    );
    expect(screen.getByLabelText("API key")).toBeTruthy();
    expect(screen.getByLabelText("Message the assistant")).toHaveProperty("disabled", true);
  });

  it("renders user, assistant, tool, and error messages", () => {
    render(
      <AssistantPanel
        assistant={makeAssistant({
          messages: [
            { kind: "user", content: "add mom's pc", id: 1 },
            { kind: "tool", name: "machine_add", summary: "saved machine", id: 2 },
            { kind: "assistant", content: "Saved it.", id: 3 },
            { kind: "error", message: "provider down", id: 4 },
          ],
        })}
      />,
    );
    expect(screen.getByText("add mom's pc")).toBeTruthy();
    expect(screen.getByText("machine_add")).toBeTruthy();
    expect(screen.getByText("Saved it.")).toBeTruthy();
    expect(screen.getByText("provider down")).toBeTruthy();
  });

  it("error cards are loud: alert role, heading, and the message", () => {
    render(
      <AssistantPanel
        assistant={makeAssistant({
          messages: [{ kind: "error", message: "provider request failed", id: 1 }],
        })}
      />,
    );
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("Something went wrong");
    expect(alert.textContent).toContain("provider request failed");
  });
});

// ---- ADR-006: circle merge, trust badges, search ----

describe("unifiedMachines with the circle directory (ADR-006)", () => {
  const favs = [{ id: "f1", name: "aaaaaaaaaaaaaaaa", code: "aaaaaaaaaaaaaaaa" }];
  const dir = [
    { device: "aaaaaaaaaaaaaaaa", name: "Mom's PC", online: true, refreshed_ms: 1, is_self: false },
    { device: "cccccccccccccccc", name: "Lab", online: false, refreshed_ms: 1, is_self: false },
  ];

  it("merges circle rows by code; a real favorite name beats the nickname", () => {
    const rows = unifiedMachines(favs, null, [], {}, "aaaaaaaaaaaaaaaa", dir, new Set());
    const merged = rows.find((r) => r.code === "aaaaaaaaaaaaaaaa");
    // The favorite's name IS the bare code here — the circle nickname wins
    // over the placeholder (UI-review decision).
    expect(merged?.name).toBe("Mom's PC");
    expect(rows.find((r) => r.code === "cccccccccccccccc")?.fromCircle).toBe(true);
    expect(merged?.fromCircle).toBe(false);
  });

  it("trusted codes produce the shield flag", () => {
    const rows = unifiedMachines([], null, [], {}, null, dir, new Set(["cccccccccccccccc"]));
    expect(rows.find((r) => r.code === "cccccccccccccccc")?.trusted).toBe(true);
    expect(rows.find((r) => r.code === "aaaaaaaaaaaaaaaa")?.trusted).toBe(false);
  });

  it("directory=null keeps the old behavior", () => {
    const rows = unifiedMachines(favs, null, [], {}, null, null, new Set());
    expect(rows).toHaveLength(1);
    expect(rows[0]?.trusted).toBe(false);
  });
});

describe("filterMachines (ADR-006 search)", () => {
  const rows = [
    { id: "1", name: "Mom's PC", code: "aaaaaaaaaaaaaaaa", online: true, active: false, trusted: false, fromCircle: false },
    { id: "2", name: "Lab", code: "bbbbbbbbbbbbbbbb", online: null, active: false, trusted: true, fromCircle: true },
  ];
  it("matches name case-insensitively, code substrings, and clears on empty", () => {
    expect(filterMachines(rows, "mom")).toHaveLength(1);
    expect(filterMachines(rows, "BBBB")).toHaveLength(1);
    expect(filterMachines(rows, "")).toHaveLength(2);
    expect(filterMachines(rows, "zzz")).toHaveLength(0);
  });
});
