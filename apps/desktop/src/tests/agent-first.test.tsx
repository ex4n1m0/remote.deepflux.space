/** Agent-first UI tests (ADR-005): machines unification + assistant panel. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MachinesRail, unifiedMachines } from "../components/MachinesRail";
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
    hostState: "Idle",
    sharing: false,
    canConnect: true,
    onPick: vi.fn(),
    onConnect: vi.fn(),
    onAdd: vi.fn(async () => {}),
    onShare: vi.fn(),
    onStopShare: vi.fn(),
  };

  it("lists machines, marks selection, exposes per-row connect", () => {
    render(
      <MachinesRail
        {...base}
        machines={[
          { id: "1", name: "Mom's PC", code: "aa", online: true, active: true },
          { id: "2", name: "Office", code: "bb", online: null, active: false },
        ]}
      />,
    );
    expect(screen.getByText("Mom's PC")).toBeTruthy();
    expect(screen.getByText("This machine")).toBeTruthy();
    expect(screen.getByText("abcd1234efgh5678")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Connect to Mom's PC" }));
    expect(base.onConnect).toHaveBeenCalledWith("aa");
    expect(screen.getByRole("button", { name: "Share this machine" })).toBeTruthy();
  });

  it("empty state teaches the next action", () => {
    render(<MachinesRail {...base} machines={[]} />);
    expect(screen.getByText(/No machines yet/i)).toBeTruthy();
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
});
