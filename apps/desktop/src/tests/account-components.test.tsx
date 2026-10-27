/** Accounts-phase component tests (jsdom + testing-library, props-only —
 * no Tauri imports; components receive data via props and report via
 * callbacks). */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { Onboarding, usernameValid } from "../components/Onboarding";

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

  it("validates username + name + password before calling back", () => {
    render(<Onboarding {...base} mode="create" />);
    fireEvent.change(screen.getByLabelText(/Username/), { target: { value: "Alice!" } });
    fireEvent.change(screen.getByLabelText(/Your name/), { target: { value: "Alice" } });
    fireEvent.change(screen.getByLabelText(/Password/), { target: { value: "longenough" } });
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(base.onCreate).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toContain("Username");

    fireEvent.change(screen.getByLabelText(/Username/), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText(/Your name/), { target: { value: "   " } });
    fireEvent.change(screen.getByLabelText(/Password/), { target: { value: "short" } });
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(base.onCreate).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toContain("Your name");

    fireEvent.change(screen.getByLabelText(/Your name/), { target: { value: "Alice" } });
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(base.onCreate).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toContain("8 characters");

    fireEvent.change(screen.getByLabelText(/Password/), { target: { value: "longenough" } });
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(base.onCreate).toHaveBeenCalledWith("alice", "Alice", "longenough");
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

describe("Onboarding reason line (ADR-007)", () => {
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
  it("shows why the card opened when a reason is given", () => {
    render(
      <Onboarding
        {...base}
        mode="create"
        reason="Controlling another machine needs an account with your name."
      />,
    );
    expect(screen.getByRole("status").textContent).toContain("needs an account with your name");
  });

  it("omits the reason line by default", () => {
    render(<Onboarding {...base} mode="signin" />);
    expect(screen.queryByRole("status")).toBeNull();
  });
});
