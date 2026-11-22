/** Human-chat tests (ADR-013 D4/P3, jsdom + testing-library): the join modal
 * (word entry, cancel, inline rejection), the rail card (join/open verbs,
 * epoch chip), the room conversation (epoch indicator updates on rotation,
 * message rendering, send/rotate/leave), and the useHumanRooms hook (state
 * mirror, message tail, room-change clear, verb forwarding, bridge-less
 * fallback). Components receive state via props and report via callbacks;
 * the ipc module is mocked where a tree pulls it in (the swarm.test
 * doctrine). */
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, renderHook, screen, waitFor } from "@testing-library/react";
import { HumanRoomJoinModal } from "../components/HumanRoomJoinModal";
import { HumanChatCard } from "../components/HumanChatCard";
import { HumanRoomConversation } from "../components/HumanRoomConversation";
import { MachinesRail } from "../components/MachinesRail";
import { useHumanRooms, type HumanRoomsBinding } from "../hooks/useHumanRooms";
import { api } from "../ipc";
import type { HumanRoomMessage, HumanRoomState } from "../types";

// A controllable event bus: the hook's listen() installs handlers here so a
// test can push state/message/log events the way the Rust node thread does.
const { listeners, emit } = vi.hoisted(() => {
  const listeners = new Map<string, (event: { payload: unknown }) => void>();
  return {
    listeners,
    emit: (name: string, payload: unknown) => listeners.get(name)?.({ payload }),
  };
});

vi.mock("../ipc", () => ({
  api: {
    roomsState: vi.fn(),
    roomsJoin: vi.fn(async () => {}),
    roomsSend: vi.fn(async () => {}),
    roomsRotate: vi.fn(async () => {}),
    roomsLeave: vi.fn(async () => {}),
    pairingsList: vi.fn(),
  },
  EVENT: {},
  ASSISTANT_EVENT: "assistant://log",
  CHAT_EVENT: "engine://chat",
  UPDATE_EVENT: "update://state",
  SWARM_EVENT: "swarm://state",
  ACCOUNT_DIRECTORY_EVENT: "app://account-directory",
  HUMAN_ROOM_STATE_EVENT: "human-chat://state",
  HUMAN_ROOM_MESSAGE_EVENT: "human-chat://message",
  HUMAN_ROOM_LOG_EVENT: "human-chat://log",
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (name: string, cb: (event: { payload: unknown }) => void) => {
    listeners.set(name, cb);
    return () => {
      listeners.delete(name);
    };
  }),
}));

afterEach(() => {
  cleanup();
  listeners.clear();
  vi.mocked(api.roomsState).mockReset();
  vi.mocked(api.roomsJoin).mockReset();
  vi.mocked(api.roomsJoin).mockImplementation(async () => {});
  vi.mocked(api.roomsSend).mockReset();
  vi.mocked(api.roomsSend).mockImplementation(async () => {});
});

const idle: HumanRoomState = {
  joined: false,
  room: null,
  epoch: 0,
  we_are_host: false,
  status: "idle",
  peers: [],
  my_peer: null,
  presence_linked: false,
  online: 0,
  error: null,
};

const hosting: HumanRoomState = {
  ...idle,
  joined: true,
  room: "ab".repeat(32),
  epoch: 1,
  we_are_host: true,
  status: "hosting",
  my_peer: "12D3KooWSelfSelfSelfSelfSelfSelfSelfSelfSelfSelfSelfS",
  peers: [
    { peer: "12D3KooWSelfSelfSelfSelfSelfSelfSelfSelfSelfSelfSelfS", name: "This PC" },
    { peer: "12D3KooWPeerPeerPeerPeerPeerPeerPeerPeerPeerPeerPeerP", name: "MOMS-PC" },
  ],
};

const message = (over: Partial<HumanRoomMessage> = {}): HumanRoomMessage => ({
  room: "ab".repeat(32),
  sender: "12D3KooWPeerPeerPeerPeerPeerPeerPeerPeerPeerPeerPeerP",
  body: "hello room",
  epoch: 1,
  mine: false,
  via_site: false,
  ...over,
});

/** A binding backed by spies (component tests drive it via props). */
const binding = (over: Partial<HumanRoomsBinding> = {}): HumanRoomsBinding => ({
  state: hosting,
  messages: [],
  logs: [],
  join: vi.fn(async () => {}),
  send: vi.fn(async () => {}),
  rotate: vi.fn(),
  leave: vi.fn(),
  ...over,
});

describe("HumanRoomJoinModal", () => {
  it("joins with the trimmed word", async () => {
    const onJoin = vi.fn(async () => {});
    render(<HumanRoomJoinModal onJoin={onJoin} onCancel={() => {}} />);
    fireEvent.change(screen.getByLabelText("Room word"), { target: { value: "  purple-otter  " } });
    fireEvent.click(screen.getByRole("button", { name: /Join room/i }));
    await waitFor(() => expect(onJoin).toHaveBeenCalledWith("purple-otter"));
  });

  it("disables Join until a word is entered", () => {
    render(<HumanRoomJoinModal onJoin={vi.fn(async () => {})} onCancel={() => {}} />);
    expect(screen.getByRole("button", { name: /Join room/i })).toHaveProperty("disabled", true);
  });

  it("cancel fires the callback", () => {
    const onCancel = vi.fn();
    render(<HumanRoomJoinModal onJoin={vi.fn(async () => {})} onCancel={onCancel} />);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("surfaces an invoke-level rejection inline", async () => {
    const onJoin = vi.fn(async () => {
      throw new Error("human chat is not running yet");
    });
    render(<HumanRoomJoinModal onJoin={onJoin} onCancel={() => {}} />);
    fireEvent.change(screen.getByLabelText("Room word"), { target: { value: "otter" } });
    fireEvent.click(screen.getByRole("button", { name: /Join room/i }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toMatch(/not running yet/i));
  });
});

describe("HumanChatCard (rail entry)", () => {
  it("not joined: the Join a room verb fires", () => {
    const onJoin = vi.fn();
    render(<HumanChatCard room={idle} active={false} onJoin={onJoin} onOpen={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /Join a room/i }));
    expect(onJoin).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: /Open room/i })).toBeNull();
  });

  it("joined: shows the epoch + status and the Open verb fires", () => {
    const onOpen = vi.fn();
    render(<HumanChatCard room={hosting} active={false} onJoin={() => {}} onOpen={onOpen} />);
    expect(screen.getByText("epoch 1")).toBeTruthy();
    expect(screen.getByText("hosting")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Open room/i }));
    expect(onOpen).toHaveBeenCalledTimes(1);
  });
});

describe("HumanRoomConversation", () => {
  it("shows the epoch indicator and bumps it on a rotation", () => {
    const { rerender } = render(<HumanRoomConversation rooms={binding()} onClose={() => {}} />);
    expect(screen.getByText("epoch 1")).toBeTruthy();
    rerender(
      <HumanRoomConversation rooms={binding({ state: { ...hosting, epoch: 2 } })} onClose={() => {}} />,
    );
    expect(screen.getByText("epoch 2")).toBeTruthy();
  });

  it("renders incoming lines with the member name and own lines as you", () => {
    render(
      <HumanRoomConversation
        rooms={binding({ messages: [message(), message({ mine: true, sender: hosting.my_peer ?? "", body: "hi back" })] })}
        onClose={() => {}}
      />,
    );
    expect(screen.getByText("hello room")).toBeTruthy();
    expect(screen.getByText("MOMS-PC")).toBeTruthy();
    expect(screen.getByText("hi back")).toBeTruthy();
    expect(screen.getByText("you")).toBeTruthy();
  });

  it("send forwards the trimmed line to the room", async () => {
    const send = vi.fn(async () => {});
    render(<HumanRoomConversation rooms={binding({ send })} onClose={() => {}} />);
    fireEvent.change(screen.getByLabelText("Room message"), { target: { value: "  hey  " } });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(send).toHaveBeenCalledWith("hey"));
  });

  it("host sees Rotate key; a guest does not", () => {
    const rotate = vi.fn();
    const { rerender } = render(
      <HumanRoomConversation rooms={binding({ rotate })} onClose={() => {}} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /Rotate key/i }));
    expect(rotate).toHaveBeenCalledTimes(1);
    rerender(
      <HumanRoomConversation
        rooms={binding({ state: { ...hosting, we_are_host: false, status: "connected" } })}
        onClose={() => {}}
      />,
    );
    expect(screen.queryByRole("button", { name: /Rotate key/i })).toBeNull();
  });

  it("leave fires the leave verb", () => {
    const leave = vi.fn();
    render(<HumanRoomConversation rooms={binding({ leave })} onClose={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Leave" }));
    expect(leave).toHaveBeenCalledTimes(1);
  });

  it("compose is disabled until the room is ready", () => {
    render(
      <HumanRoomConversation
        rooms={binding({ state: { ...hosting, room: null, status: "searching" } })}
        onClose={() => {}}
      />,
    );
    expect(screen.getByLabelText("Room message")).toHaveProperty("disabled", true);
    expect(screen.getByRole("button", { name: "Send" })).toHaveProperty("disabled", true);
  });
});

describe("MachinesRail human-chat entry (ADR-013 D4/P3)", () => {
  const rail = (over: Partial<Parameters<typeof MachinesRail>[0]> = {}) =>
    render(
      <MachinesRail
        machines={[]}
        thisCode="0123456789abcdef"
        thisName={null}
        hostState="Online"
        sharing={false}
        swarmChip={null}
        swarmJoinable={false}
        onJoinSwarm={() => {}}
        onPick={() => {}}
        onConnect={() => {}}
        onShare={() => {}}
        onStopShare={() => {}}
        {...over}
      />,
    );

  it("offers Join a room when the human-chat handlers are wired", () => {
    const onJoinHumanRoom = vi.fn();
    rail({ humanRoom: idle, onJoinHumanRoom, onOpenHumanRoom: () => {} });
    fireEvent.click(screen.getByRole("button", { name: /Join a room/i }));
    expect(onJoinHumanRoom).toHaveBeenCalledTimes(1);
  });

  it("renders no human-chat card without the handlers (machine-list-only callers)", () => {
    rail();
    expect(screen.queryByRole("button", { name: /Join a room/i })).toBeNull();
  });
});

describe("useHumanRooms", () => {
  it("mirrors the pulled state and accumulates message events", async () => {
    vi.mocked(api.roomsState).mockResolvedValue(hosting);
    const { result } = renderHook(() => useHumanRooms());
    await waitFor(() => expect(result.current.state?.joined).toBe(true));
    act(() => emit("human-chat://message", message()));
    await waitFor(() => expect(result.current.messages).toHaveLength(1));
    expect(result.current.messages[0].body).toBe("hello room");
  });

  it("appends the sender's own line optimistically on send (the node does not echo it)", async () => {
    vi.mocked(api.roomsState).mockResolvedValue(hosting);
    const { result } = renderHook(() => useHumanRooms());
    await waitFor(() => expect(result.current.state?.joined).toBe(true));
    await act(async () => {
      await result.current.send("my line");
    });
    expect(api.roomsSend).toHaveBeenCalledWith("my line");
    await waitFor(() => expect(result.current.messages).toHaveLength(1));
    expect(result.current.messages[0]).toMatchObject({ body: "my line", mine: true });
  });

  it("skips a mine echo from the message event (own lines are optimistic)", async () => {
    vi.mocked(api.roomsState).mockResolvedValue(hosting);
    const { result } = renderHook(() => useHumanRooms());
    await waitFor(() => expect(result.current.state?.joined).toBe(true));
    act(() => emit("human-chat://message", message({ mine: true })));
    await act(async () => {
      await Promise.resolve();
    });
    expect(result.current.messages).toHaveLength(0);
  });

  it("updates the epoch on a state push (rotation)", async () => {
    vi.mocked(api.roomsState).mockResolvedValue(hosting);
    const { result } = renderHook(() => useHumanRooms());
    await waitFor(() => expect(result.current.state?.epoch).toBe(1));
    act(() => emit("human-chat://state", { ...hosting, epoch: 5 }));
    await waitFor(() => expect(result.current.state?.epoch).toBe(5));
  });

  it("clears the message tail when the room changes (leave)", async () => {
    vi.mocked(api.roomsState).mockResolvedValue(hosting);
    const { result } = renderHook(() => useHumanRooms());
    await waitFor(() => expect(result.current.state?.joined).toBe(true));
    act(() => emit("human-chat://message", message()));
    await waitFor(() => expect(result.current.messages).toHaveLength(1));
    act(() => emit("human-chat://state", idle));
    await waitFor(() => expect(result.current.state?.joined).toBe(false));
    expect(result.current.messages).toHaveLength(0);
  });

  it("forwards join/send/rotate/leave to the ipc verbs", async () => {
    vi.mocked(api.roomsState).mockResolvedValue(idle);
    const { result } = renderHook(() => useHumanRooms());
    await waitFor(() => expect(result.current.state).not.toBeNull());
    await act(async () => {
      await result.current.join("otter");
    });
    expect(api.roomsJoin).toHaveBeenCalledWith("otter");
    await act(async () => {
      await result.current.send("hi");
    });
    expect(api.roomsSend).toHaveBeenCalledWith("hi");
    act(() => result.current.rotate());
    expect(api.roomsRotate).toHaveBeenCalledTimes(1);
    act(() => result.current.leave());
    expect(api.roomsLeave).toHaveBeenCalledTimes(1);
  });

  it("survives a bridge-less environment without state (jsdom fallback)", async () => {
    vi.mocked(api.roomsState).mockRejectedValue(new Error("no bridge"));
    const { result } = renderHook(() => useHumanRooms());
    await act(async () => {
      await Promise.resolve();
    });
    expect(result.current.state).toBeNull();
    expect(result.current.messages).toHaveLength(0);
  });
});
