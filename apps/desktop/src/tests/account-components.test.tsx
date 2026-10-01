/** Accounts-phase component tests (jsdom + testing-library, props-only —
 * no Tauri imports; components receive data via props and report via
 * callbacks). */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Onboarding, usernameValid } from "../components/Onboarding";
import { Computers } from "../components/Computers";
import type { Computer } from "../types";

afterEach(cleanup);

describe("Onboarding", () => {
  const base = {
    busy: false,
    error: null as string | null,
    onModeChange: vi.fn(),
    onSignIn: vi.fn(),
    onCreate: vi.fn(),
    onUnlock: vi.fn(),
    onDismissError: vi.fn(),
    onSkip: vi.fn(),
  };

  it("defaults to sign-in and switches to create-account", () => {
    render(<Onboarding {...base} mode="signin" />);
    expect(screen.getByRole("tab", { name: "Sign in" }).getAttribute("aria-selected")).toBe(
      "true",
    );
    fireEvent.click(screen.getByRole("tab", { name: "Create account" }));
    expect(base.onModeChange).toHaveBeenCalledWith("create");
  });

  it("validates username + password before calling back", () => {
    render(<Onboarding {...base} mode="create" />);
    fireEvent.change(screen.getByLabelText(/Username/), { target: { value: "Alice!" } });
    fireEvent.change(screen.getByLabelText(/Password/), { target: { value: "longenough" } });
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(base.onCreate).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toContain("Username");

    fireEvent.change(screen.getByLabelText(/Username/), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText(/Password/), { target: { value: "short" } });
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(base.onCreate).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toContain("8 characters");

    fireEvent.change(screen.getByLabelText(/Password/), { target: { value: "longenough" } });
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(base.onCreate).toHaveBeenCalledWith("alice", "longenough");
  });

  it("normalizes the username before submit", () => {
    render(<Onboarding {...base} mode="signin" />);
    fireEvent.change(screen.getByLabelText(/Username/), { target: { value: "  Alice.X " } });
    fireEvent.change(screen.getByLabelText(/Password/), { target: { value: "longenough" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(base.onSignIn).toHaveBeenCalledWith("alice.x", "longenough");
  });

  it("unlock mode shows the saved username, one field, and the unlock path", () => {
    render(<Onboarding {...base} mode="unlock" username="alice" />);
    expect(screen.getByText(/Welcome back, @alice/)).toBeTruthy();
    expect(screen.queryByLabelText(/Username/)).toBeNull();
    fireEvent.change(screen.getByLabelText(/Password/), { target: { value: "longenough" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock" }));
    expect(base.onUnlock).toHaveBeenCalledWith("longenough");
  });

  it("surfaces mapped service errors and maps codes to friendly copy", () => {
    render(
      <Onboarding {...base} mode="signin" error="service error 409 username_taken: nope" />,
    );
    expect(screen.getByRole("alert").textContent).toContain("already taken");
    fireEvent.click(screen.getByRole("button", { name: "Dismiss error" }));
    expect(base.onDismissError).toHaveBeenCalledTimes(1);
  });

  it("skips via the quiet link and disables submit while busy", () => {
    render(<Onboarding {...base} mode="signin" busy />);
    expect(screen.getByRole("button", { name: "Working…" }).hasAttribute("disabled")).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: /Skip for now/ }));
    expect(base.onSkip).toHaveBeenCalledTimes(1);
  });

  it("usernameValid mirrors the wire rules", () => {
    expect(usernameValid("alice")).toBe(true);
    expect(usernameValid("a.b_c-d")).toBe(true);
    expect(usernameValid("ab")).toBe(false);
    expect(usernameValid("Alice")).toBe(false);
    expect(usernameValid("-alice")).toBe(false);
    expect(usernameValid("a".repeat(33))).toBe(false);
  });
});

describe("Computers", () => {
  const computers: Computer[] = [
    { id: "f1", name: "Office PC", code: "aaaaaaaaaaaaaaaa", added_at_ms: 1, updated_at_ms: 2, is_self: false },
    { id: "f2", name: "This PC", code: "bbbbbbbbbbbbbbbb", added_at_ms: 1, updated_at_ms: 2, is_self: true },
    { id: "f3", name: "Cabin PC", code: "cccccccccccccccc", added_at_ms: 1, updated_at_ms: 2, is_self: false },
  ];
  const base = {
    computers,
    online: ["aaaaaaaaaaaaaaaa"],
    canConnect: true,
    onConnect: vi.fn(),
    onAdd: vi.fn(async () => {}),
    onAddThis: vi.fn(),
    onRemove: vi.fn(),
    onRename: vi.fn(),
    onViewCode: vi.fn(),
  };

  it("renders rows with online dots, code chips, and actions", () => {
    render(<Computers {...base} />);
    expect(screen.getByText("Office PC")).toBeTruthy();
    expect(screen.getByText("aaaaaaaaaaaaaaaa")).toBeTruthy();
    expect(screen.getByLabelText("online")).toBeTruthy();
    expect(screen.getByLabelText("offline")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Connect to Office PC" }));
    expect(base.onConnect).toHaveBeenCalledWith("aaaaaaaaaaaaaaaa");
  });

  it("badges this computer instead of connecting; header swaps add→view code", () => {
    render(<Computers {...base} />);
    expect(screen.getByLabelText("this computer")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Connect to This PC" })).toBeNull();
    expect(screen.getByRole("button", { name: /Sharing — view code/ })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Sharing — view code/ }));
    expect(base.onViewCode).toHaveBeenCalledTimes(1);
    expect(base.onAddThis).not.toHaveBeenCalled();
  });

  it("offers Add this computer when the roster lacks this machine", () => {
    render(<Computers {...base} computers={[computers[0]]} />);
    fireEvent.click(screen.getByRole("button", { name: "Add this computer" }));
    expect(base.onAddThis).toHaveBeenCalledTimes(1);
  });

  it("adds by code through the inline form (normalized by the caller wiring)", async () => {
    render(<Computers {...base} computers={[]} />);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Laptop" } });
    fireEvent.change(screen.getByLabelText("Connection code"), {
      target: { value: "CCCCDDDD" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add by code" }));
    await waitFor(() => expect(base.onAdd).toHaveBeenCalledWith("Laptop", "ccccdddd"));
  });

  it("renames inline and removes with the row actions", () => {
    render(<Computers {...base} />);
    fireEvent.click(screen.getByRole("button", { name: "Rename Office PC" }));
    fireEvent.change(screen.getByLabelText("New name for Office PC"), {
      target: { value: "Workstation" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(base.onRename).toHaveBeenCalledWith("f1", "Workstation");
    fireEvent.click(screen.getByRole("button", { name: "Remove This PC" }));
    expect(base.onRemove).toHaveBeenCalledWith("f2");
  });

  it("shows a local error when the add callback rejects", async () => {
    const onAdd = vi.fn(async () => {
      throw new Error("service error 409 roster_conflict");
    });
    render(<Computers {...base} computers={[]} onAdd={onAdd} />);
    fireEvent.change(screen.getByLabelText("Connection code"), {
      target: { value: "ccccdddd" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add by code" }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("roster_conflict"));
  });
});
