/** ADR-008 update-banner tests: the visible states render the right
 * verbs, the verbs fire the right callbacks, session-live disables the
 * install, and the quiet idle renders nothing. Pure presentational — no
 * bridge mocking needed. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { UpdateBanner, updateErrorTitle } from "../components/UpdateBanner";
import type { UpdateState } from "../ipc";

afterEach(cleanup);

function state(partial: Partial<UpdateState>): UpdateState {
  return {
    status: "idle",
    stage: "",
    current_version: "0.8.1",
    latest_version: "0.9.0",
    notes: "faster sessions",
    size_text: "7.3 MB",
    progress_percent: 0,
    error: "",
    ...partial,
  };
}

const noop = () => {};
function banner(s: UpdateState, extra: Partial<Parameters<typeof UpdateBanner>[0]> = {}) {
  return render(
    <UpdateBanner
      state={s}
      sessionLive={false}
      onUpdate={noop}
      onInstall={noop}
      onRetry={noop}
      onDismiss={noop}
      {...extra}
    />,
  );
}

describe("UpdateBanner (ADR-008)", () => {
  it("renders nothing while idle", () => {
    const { container } = banner(state({ status: "idle" }));
    expect(container.childElementCount).toBe(0);
  });

  it("checking and none (up to date) render a passive line", () => {
    banner(state({ status: "checking" }));
    expect(screen.getByText(/Checking for updates…/)).toBeTruthy();
    cleanup();
    banner(state({ status: "none" }));
    expect(screen.getByText(/up to date \(v0\.8\.1\)/)).toBeTruthy();
  });

  it("available: Update now downloads, Not now dismisses", () => {
    const onUpdate = vi.fn();
    const onDismiss = vi.fn();
    banner(state({ status: "available" }), { onUpdate, onDismiss });
    expect(screen.getByText(/DeepFlux 0\.9\.0 is available/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Update now" }));
    expect(onUpdate).toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Not now" }));
    expect(onDismiss).toHaveBeenCalled();
  });

  it("downloading: passive progress, no buttons, percent outside the live region", () => {
    banner(state({ status: "downloading", progress_percent: 42 }));
    expect(screen.getByRole("progressbar", { name: /progress/i })).toBeTruthy();
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.getByText("42%")).toBeTruthy();
  });

  it("ready: names the cost (closes DeepFlux), installs, Not now dismisses", () => {
    const onInstall = vi.fn();
    const onDismiss = vi.fn();
    banner(state({ status: "ready" }), { onInstall, onDismiss });
    expect(screen.getByText(/closes DeepFlux for a moment/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Restart & update/i }));
    expect(onInstall).toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Not now" }));
    expect(onDismiss).toHaveBeenCalled();
  });

  it("ready during a live session: install disabled with the reason", () => {
    banner(state({ status: "ready" }), { sessionLive: true });
    const button = screen.getByRole("button", { name: /Restart & update/i }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(screen.getByText(/Finish the remote session first/)).toBeTruthy();
  });

  it("installing renders the closing line; error retries by stage", () => {
    const onRetry = vi.fn();
    banner(state({ status: "installing" }));
    expect(screen.getByText(/app restarts by itself/)).toBeTruthy();
    cleanup();
    banner(
      state({ status: "error", stage: "check", error: "couldn't reach the service" }),
      { onRetry },
    );
    expect(screen.getByText(/Couldn't check for updates\./)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalled();
  });

  it("error titles split by stage", () => {
    expect(updateErrorTitle("check")).toContain("check");
    expect(updateErrorTitle("download")).toContain("didn't finish");
    expect(updateErrorTitle("install")).toContain("couldn't start");
    expect(updateErrorTitle("")).toContain("didn't finish");
  });
});
