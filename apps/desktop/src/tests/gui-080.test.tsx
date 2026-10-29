/** 0.8.0 GUI tests: the top menu bar's open/pick behavior (the circle
 * toast and Add-machine item died with ADR-009). */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MenuBar } from "../components/MenuBar";

afterEach(cleanup);

describe("MenuBar (File / Config / Help)", () => {
  const noop = () => {};

  function renderBar(
    picks: { quit?: () => void; config?: () => void; about?: () => void; checkUpdates?: () => void } = {},
  ) {
    return render(
      <MenuBar
        version="0.10.0"
        onOpenConfig={() => picks.config?.()}
        onAbout={picks.about ?? noop}
        onDiagnostics={noop}
        onCheckForUpdates={picks.checkUpdates ?? noop}
        onQuit={picks.quit ?? noop}
      />,
    );
  }

  it("fires Check for updates from the Help menu (ADR-008)", () => {
    const checkUpdates = vi.fn();
    renderBar({ checkUpdates });
    fireEvent.click(screen.getByRole("button", { name: "Help" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Check for updates…" }));
    expect(checkUpdates).toHaveBeenCalled();
  });

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
    expect(screen.getByRole("menuitem", { name: "Quit DeepFlux" })).toBeTruthy();
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
