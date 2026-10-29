/** Agent-first UI tests (ADR-005): machines unification + assistant panel. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import {
  MachinesRail,
  RemoveMachineButton,
  excludeSelf,
  filterMachines,
  groupMachines,
  unifiedMachines,
} from "../components/MachinesRail";
import { AssistantPanel } from "../components/AssistantPanel";
import { AgentChat } from "../components/AgentChat";
import { Conversation } from "../components/Conversation";
import type { AssistantBinding } from "../hooks/useAssistant";
import type { MachineRow } from "../components/MachinesRail";

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
  addSignal: 0,
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
    confirm: null,
    answerConfirm: vi.fn(async () => {}),
    send: vi.fn(async () => {}),
    configure: vi.fn(async () => true),
    reset: vi.fn(async () => {}),
    ...over,
  });

  it("shows prompt starters when configured and idle", () => {
    render(<AssistantPanel assistant={makeAssistant()} onOpenConfig={() => {}} />);
    expect(screen.getByText("Save a machine for me")).toBeTruthy();
    expect(screen.getByPlaceholderText(/ask anything/i)).toBeTruthy();
  });

  it("points at Config for the key when unconfigured and disables the composer", () => {
    render(
      <AssistantPanel
        assistant={makeAssistant({
          status: { configured: false, busy: false, base_url: "", model: "" },
        })}
        onOpenConfig={() => {}}
      />,
    );
    expect(screen.getByText(/Config → Assistant/)).toBeTruthy();
    expect(screen.getByLabelText("Message the assistant")).toHaveProperty("disabled", true);
  });

  it("renders the download-confirmation card with the three answers", () => {
    const answerConfirm = vi.fn(async () => {});
    render(
      <AssistantPanel
        assistant={makeAssistant({
          confirm: {
            id: 7,
            question: "Allow downloading from example.com?",
            detail: "The assistant wants to download https://example.com/a.zip",
          },
          answerConfirm,
        })}
        onOpenConfig={() => {}}
      />,
    );
    expect(screen.getByText("Allow downloading from example.com?")).toBeTruthy();
    expect(screen.getByText(/No answer in 5 minutes/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Always allow this site" }));
    expect(answerConfirm).toHaveBeenCalledWith(true, true);
    fireEvent.click(screen.getByRole("button", { name: "Allow once" }));
    expect(answerConfirm).toHaveBeenCalledWith(true, false);
    fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    expect(answerConfirm).toHaveBeenCalledWith(false, false);
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
        onOpenConfig={() => {}}
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
        onOpenConfig={() => {}}
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

// ---- Where-am-I grouping (user request, 2026-10-26) ----

describe("groupMachines (three plain sections)", () => {
  const row = (over: Partial<MachineRow>): MachineRow => ({
    id: over.code ?? "x",
    name: over.code ?? "x",
    code: "x",
    online: null,
    active: false,
    trusted: false,
    fromCircle: false,
    ...over,
  });

  it("splits into accepted / awaiting / unadded and keeps source order", () => {
    const rows = [
      row({ id: "1", code: "added", name: "Added, not accepted" }),
      row({ id: "2", code: "ok", name: "Accepted", trusted: true }),
      row({ id: "3", code: "circ", name: "Circle only", fromCircle: true }),
      row({ id: "4", code: "okcirc", name: "Trusted circle", trusted: true, fromCircle: true }),
    ];
    const groups = groupMachines(rows);
    expect(groups.accepted.map((r) => r.code)).toEqual(["ok", "okcirc"]);
    expect(groups.awaiting.map((r) => r.code)).toEqual(["added"]);
    expect(groups.unadded.map((r) => r.code)).toEqual(["circ"]);
  });
});

describe("MachinesRail grouping render", () => {
  const base = {
  addSignal: 0,
    thisCode: "abcd1234efgh5678",
    hostState: "Idle" as const,
    sharing: false,
    onPick: vi.fn(),
    onConnect: vi.fn(),
    onAdd: vi.fn(async () => {}),
    onShare: vi.fn(),
    onStopShare: vi.fn(),
  };
  const machines = [
    { id: "1", name: "Mom's PC", code: "aa", online: true, active: true, trusted: true, fromCircle: false },
    { id: "2", name: "Office", code: "bb", online: null, active: false, trusted: false, fromCircle: false },
    { id: "3", name: "Lab", code: "cc", online: true, active: false, trusted: false, fromCircle: true },
  ];

  it("renders the three section headers with counts, rows under the right one", () => {
    const { container } = render(<MachinesRail {...base} machines={machines} />);
    expect(screen.getByText("Accepted (1)")).toBeTruthy();
    expect(screen.getByText("Added — awaiting their approval (1)")).toBeTruthy();
    expect(screen.getByText("Not added yet (1)")).toBeTruthy();
    // The whole rail list, top to bottom: group header, its rows, next.
    const texts = Array.from(container.querySelectorAll("ul.rail-list > li")).map((li) =>
      li.textContent?.replace(/\s+/g, " ").trim(),
    );
    expect(texts).toEqual([
      "Accepted (1)",
      "Mom's PC✓Control", // shield badge on trusted rows
      "Added — awaiting their approval (1)",
      "OfficeControl",
      "Not added yet (1)",
      "LabcircleControl", // circle tag on unsaved circle rows
    ]);
  });

  it("omits empty sections entirely", () => {
    render(
      <MachinesRail
        {...base}
        machines={[{ ...machines[1] }]} // one awaiting row only
      />,
    );
    expect(screen.getByText("Added — awaiting their approval (1)")).toBeTruthy();
    expect(screen.queryByText(/Accepted \(/)).toBeNull();
    expect(screen.queryByText(/Not added yet \(/)).toBeNull();
  });
});

describe("RemoveMachineButton (machine-page removal)", () => {
  it("two-step confirm: Remove… → Remove fires, Cancel does not", () => {
    const onRemove = vi.fn();
    render(<RemoveMachineButton name="Office" onRemove={onRemove} />);
    // Nothing fires on the first click — it only arms the confirm.
    fireEvent.click(screen.getByRole("button", { name: "Remove…" }));
    expect(onRemove).not.toHaveBeenCalled();
    expect(screen.getByRole("alertdialog", { name: "Remove machine" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(onRemove).toHaveBeenCalledTimes(1);
  });

  it("cancel disarms without removing", () => {
    const onRemove = vi.fn();
    render(<RemoveMachineButton name="Office" onRemove={onRemove} />);
    fireEvent.click(screen.getByRole("button", { name: "Remove…" }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onRemove).not.toHaveBeenCalled();
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });
});

/** Two chat boxes (2026-10-28): the human Conversation is always there;
 * the peer machine's assistant gets its OWN box (AgentChat) rendered by
 * App only while a live session with that machine exists. Each box
 * filters the shared history to its own senders. */
describe("Conversation / AgentChat split", () => {
  const chatBinding = (
    lines: Array<{ id: number; ts_ms: number; sender: string; body: string }> = [],
  ) => ({
    lines,
    sending: false,
    send: vi.fn(async () => {}),
    refresh: vi.fn(async () => {}),
  });

  const mixed = [
    { id: 1, ts_ms: 0, sender: "user", body: "hi mom" },
    { id: 2, ts_ms: 1, sender: "peer-user", body: "hello dear" },
    { id: 3, ts_ms: 2, sender: "to-agent", body: "clean temp files" },
    { id: 4, ts_ms: 3, sender: "peer-agent", body: "done, freed 3 GB" },
    { id: 5, ts_ms: 4, sender: "agent", body: "sent on your behalf" },
  ];

  const type = (text: string) => {
    const input = screen.getByRole("textbox") as HTMLInputElement;
    fireEvent.change(input, { target: { value: text } });
    fireEvent.keyDown(input, { key: "Enter" });
  };

  it("the human box carries the human conversation and sends without the agent flag", () => {
    const chat = chatBinding(mixed);
    render(<Conversation name="Office" chat={chat} />);
    expect(screen.getByText("hi mom")).toBeTruthy();
    expect(screen.getByText("hello dear")).toBeTruthy();
    expect(screen.getByText("sent on your behalf")).toBeTruthy();
    // Agent-traffic lines live in the other box, not here.
    expect(screen.queryByText("clean temp files")).toBeNull();
    expect(screen.queryByText("done, freed 3 GB")).toBeNull();
    type("see you sunday");
    expect(chat.send).toHaveBeenCalledWith("see you sunday", false);
  });

  it("the agent box carries only the assistant traffic and always sends with the agent flag", () => {
    const chat = chatBinding(mixed);
    render(<AgentChat name="Office" chat={chat} />);
    expect(screen.getByText("Office's assistant")).toBeTruthy();
    expect(screen.getByText("you → their assistant")).toBeTruthy();
    expect(screen.getByText("their assistant")).toBeTruthy();
    expect(screen.getByText("done, freed 3 GB")).toBeTruthy();
    expect(screen.queryByText("hi mom")).toBeNull();
    type("empty the recycle bin");
    expect(chat.send).toHaveBeenLastCalledWith("empty the recycle bin", true);
  });

  it("each box teaches its purpose when empty", () => {
    render(<Conversation name="Office" chat={chatBinding()} />);
    expect(screen.getByText(/messages wait sealed until the machine returns/i)).toBeTruthy();
    cleanup();
    render(<AgentChat name="Office" chat={chatBinding()} />);
    expect(screen.getByText(/Tell Office's assistant what to do/i)).toBeTruthy();
  });
});
