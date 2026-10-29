/** Agent-first UI tests (ADR-005, simplified by ADR-009): the
 * trusted-host rail (pairings + connect box) + assistant panel. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import {
  MachinesRail,
  RemoveMachineButton,
  filterMachines,
  machinesFromPairings,
} from "../components/MachinesRail";
import { AssistantPanel } from "../components/AssistantPanel";
import { AgentChat } from "../components/AgentChat";
import { Conversation } from "../components/Conversation";
import type { AssistantBinding } from "../hooks/useAssistant";
import type { MachineRow } from "../components/MachinesRail";
import type { PairingInfo } from "../types";

afterEach(cleanup);

describe("machinesFromPairings (the trusted-host list, ADR-009)", () => {
  const pairing = (over: Partial<PairingInfo>): PairingInfo => ({
    code: "abcdef0123456789",
    created_ms: 1,
    pending_ack: false,
    role: "host",
    name: null,
    ...over,
  });

  it("names rows from the cached wire name, falls back to the code", () => {
    const rows = machinesFromPairings(
      [
        pairing({ name: "MOMS-PC", code: "aaaaaaaaaaaaaaaa" }),
        pairing({ code: "bbbbbbbbbbbbbbbb" }),
      ],
      { bbbbbbbbbbbbbbbb: true },
      "bbbbbbbbbbbbbbbb",
    );
    expect(rows.map((r) => r.name)).toEqual(["MOMS-PC", "bbbbbbbbbbbbbbbb"]);
    // Online only while a session with the machine is live.
    expect(rows[0].online).toBeNull();
    expect(rows[1].online).toBe(true);
    expect(rows[1].active).toBe(true);
  });

  it("pending offers are untrusted and flagged", () => {
    const rows = machinesFromPairings(
      [pairing({ code: "cccccccccccccccc", pending_ack: true })],
      {},
      null,
    );
    expect(rows[0].trusted).toBe(false);
    expect(rows[0].pending).toBe(true);
  });
});

describe("MachinesRail", () => {
  const base = {
    thisCode: "abcd1234efgh5678",
    thisName: "Office PC",
    hostState: "Idle" as const,
    sharing: false,
    onPick: vi.fn(),
    onConnect: vi.fn(),
    onShare: vi.fn(),
    onStopShare: vi.fn(),
  };
  const machines: MachineRow[] = [
    { id: "1", name: "Mom's PC", code: "aa", online: true, active: true, trusted: true, pending: false },
    { id: "2", name: "Office", code: "bb", online: null, active: false, trusted: false, pending: true },
  ];

  it("lists machines, marks selection, exposes one-step per-row control", () => {
    render(<MachinesRail {...base} machines={machines} />);
    expect(screen.getByText("Mom's PC")).toBeTruthy();
    expect(screen.getByText("This machine")).toBeTruthy();
    expect(screen.getByText("abcd1234efgh5678")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Control Mom's PC" }));
    expect(base.onConnect).toHaveBeenCalledWith("aa", false);
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

  it("connect box: Control and Agent dial the entered code (ADR-009)", () => {
    render(<MachinesRail {...base} machines={[]} />);
    const input = screen.getByLabelText("Connection code");
    fireEvent.change(input, { target: { value: "ccccdddd11112222" } });
    fireEvent.click(screen.getByRole("button", { name: "Agent" }));
    expect(base.onConnect).toHaveBeenCalledWith("ccccdddd11112222", true);
    fireEvent.change(input, { target: { value: "eeeeffff33334444" } });
    fireEvent.click(screen.getByRole("button", { name: "Control" }));
    expect(base.onConnect).toHaveBeenCalledWith("eeeeffff33334444", false);
    // Enter in the box is the visual verb.
    fireEvent.change(input, { target: { value: "aaaabbbb55556666" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(base.onConnect).toHaveBeenLastCalledWith("aaaabbbb55556666", false);
  });

  it("connect box: a mistyped code is caught HERE, not blamed on the other machine (0.10.2)", () => {
    const onConnect = vi.fn();
    render(<MachinesRail {...base} onConnect={onConnect} machines={[]} />);
    const input = screen.getByLabelText("Connection code");
    fireEvent.change(input, { target: { value: "moms pc" } });
    fireEvent.click(screen.getByRole("button", { name: "Control" }));
    expect(onConnect).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toContain(
      "doesn't look like a connection code",
    );
    // A corrected code clears the error and dials.
    fireEvent.change(input, { target: { value: "ccccdddd11112222" } });
    expect(screen.queryByRole("alert")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Control" }));
    expect(onConnect).toHaveBeenCalledWith("ccccdddd11112222", false);
  });

  it("This-machine card shows this machine's name, the code, and a copy button", () => {
    render(<MachinesRail {...base} machines={[]} />);
    expect(screen.getByText("Office PC")).toBeTruthy();
    expect(screen.getByText(/family enter this code to reach you/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy code" })).toBeTruthy();
  });

  it("pending rows sit under the waiting hint; trusted rows carry the shield", () => {
    render(<MachinesRail {...base} machines={machines} />);
    expect(screen.getByText(/Waiting for their approval/i)).toBeTruthy();
    expect(screen.getByTitle("Trusted — connects without asking again")).toBeTruthy();
  });

  it("labels the This-machine chip with the friendly host status, not the state name", () => {
    render(<MachinesRail {...base} hostState="ConsentPrompted" machines={[]} />);
    expect(screen.getByText("Connection request")).toBeTruthy();
    expect(screen.queryByText("ConsentPrompted")).toBeNull();
  });

  it("never claims connecting is unavailable (every Connect auto-starts)", () => {
    render(<MachinesRail {...base} machines={[]} />);
    expect(screen.queryByText(/connecting unavailable/i)).toBeNull();
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
    expect(screen.getByText("Connect me to another machine")).toBeTruthy();
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
            { kind: "user", content: "list my machines", id: 1 },
            { kind: "tool", name: "machines_list", summary: "1 trusted machine", id: 2 },
            { kind: "assistant", content: "One: Mom's PC.", id: 3 },
            { kind: "error", message: "provider down", id: 4 },
          ],
        })}
        onOpenConfig={() => {}}
      />,
    );
    expect(screen.getByText("list my machines")).toBeTruthy();
    expect(screen.getByText("machines_list")).toBeTruthy();
    expect(screen.getByText("One: Mom's PC.")).toBeTruthy();
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

describe("filterMachines (search)", () => {
  const rows: MachineRow[] = [
    { id: "1", name: "Mom's PC", code: "aaaaaaaaaaaaaaaa", online: true, active: false, trusted: true, pending: false },
    { id: "2", name: "Lab", code: "bbbbbbbbbbbbbbbb", online: null, active: false, trusted: false, pending: true },
  ];
  it("matches name case-insensitively, code substrings, and clears on empty", () => {
    expect(filterMachines(rows, "mom")).toHaveLength(1);
    expect(filterMachines(rows, "BBBB")).toHaveLength(1);
    expect(filterMachines(rows, "")).toHaveLength(2);
    expect(filterMachines(rows, "zzz")).toHaveLength(0);
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
