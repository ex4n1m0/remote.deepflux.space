/** 0.8.0 GUI tests: the passive circle-notice toast (its self-dismiss
 * timer must survive the shell's 1–2 s poll re-renders — the original
 * deps-bound version restarted forever and the banner never went away)
 * and the top menu bar's open/pick behavior. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { CircleNoticeToast } from "../App";
import { MenuBar } from "../components/MenuBar";

afterEach(cleanup);

describe("CircleNoticeToast (ADR-006 §5, passive since 0.8.0)", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("self-dismisses after 12 s even when the parent re-renders every second", () => {
    const onDone = vi.fn();
    // A NEW inline-arrow identity per render is exactly what App produces.
    const { rerender } = render(<CircleNoticeToast onDone={() => onDone()} />);
    for (let i = 0; i < 15; i++) {
      vi.advanceTimersByTime(1_000);
      rerender(<CircleNoticeToast onDone={() => onDone()} />);
    }
    expect(onDone).toHaveBeenCalled();
  });

  it("dismisses immediately on click", () => {
    const onDone = vi.fn();
    render(<CircleNoticeToast onDone={onDone} />);
    fireEvent.click(screen.getByRole("status"));
    expect(onDone).toHaveBeenCalled();
  });
});

describe("MenuBar (File / Config / Help)", () => {
  const noop = () => {};

  function renderBar(picks: { add?: () => void; quit?: () => void; config?: () => void; about?: () => void } = {}) {
    return render(
      <MenuBar
        version="0.8.0"
        onAddMachine={picks.add ?? noop}
        onOpenConfig={() => picks.config?.()}
        onAbout={picks.about ?? noop}
        onDiagnostics={noop}
        onQuit={picks.quit ?? noop}
      />,
    );
  }

  it("opens a menu on click and closes on Escape", () => {
    renderBar();
    fireEvent.click(screen.getByRole("button", { name: "Config" }));
    expect(screen.getByRole("menu")).toBeTruthy();
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("closes on click-outside", () => {
    renderBar();
    fireEvent.click(screen.getByRole("button", { name: "File" }));
    expect(screen.getByRole("menuitem", { name: /Add machine/ })).toBeTruthy();
    fireEvent.mouseDown(document.body);
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("fires the picked item (Config → Settings…)", () => {
    const config = vi.fn();
    renderBar({ config });
    fireEvent.click(screen.getByRole("button", { name: "Config" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Settings…" }));
    expect(config).toHaveBeenCalled();
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("fires Quit from the File menu", () => {
    const quit = vi.fn();
    renderBar({ quit });
    fireEvent.click(screen.getByRole("button", { name: "File" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Quit DeepFlux" }));
    expect(quit).toHaveBeenCalled();
  });
});
