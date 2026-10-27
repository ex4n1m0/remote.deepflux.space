/** Top menu bar (0.8.0 GUI restructure): File / Config / Help. Everything
 * configurable moves off the main surface into these menus — the workspace
 * keeps only machines, chat, sessions, and the assistant. In-app HTML (not
 * a native OS menu) so it matches the shell's styling; no extra Tauri
 * permissions. Click-outside and Esc close; items are real buttons. */
import { useEffect, useRef, useState } from "react";

export type MenuId = "file" | "config" | "help";

export interface MenuItemDef {
  id: string;
  label: string;
  /** Right-aligned hint (shortcut, e.g. "Ctrl+Shift+D"). */
  hint?: string;
  onPick: () => void;
}

export interface MenuBarProps {
  version: string | null;
  onAddMachine: () => void;
  onOpenConfig: (section: "settings" | "circle" | "trusted" | "assistant") => void;
  onAbout: () => void;
  onDiagnostics: () => void;
  onQuit: () => void;
}

const WEBSITE_URL = "https://remote.deepflux.space";

export function MenuBar({
  version,
  onAddMachine,
  onOpenConfig,
  onAbout,
  onDiagnostics,
  onQuit,
}: MenuBarProps) {
  const [open, setOpen] = useState<MenuId | null>(null);
  const barRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (event: MouseEvent) => {
      if (barRef.current && !barRef.current.contains(event.target as Node)) {
        setOpen(null);
      }
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(null);
    };
    window.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const menu = (id: MenuId, label: string, items: MenuItemDef[]) => (
    <div className="menu" key={id}>
      <button
        type="button"
        className={`menu-button${open === id ? " menu-open" : ""}`}
        aria-haspopup="menu"
        aria-expanded={open === id}
        onClick={() => setOpen((current) => (current === id ? null : id))}
      >
        {label}
      </button>
      {open === id ? (
        <div className="menu-dropdown" role="menu">
          {items.map((item) => (
            <button
              key={item.id}
              type="button"
              role="menuitem"
              className="menu-item"
              onClick={() => {
                setOpen(null);
                item.onPick();
              }}
            >
              <span>{item.label}</span>
              {item.hint ? <span className="menu-hint">{item.hint}</span> : null}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );

  return (
    <div className="menu-bar" ref={barRef} role="menubar" aria-label="Application menu">
      {menu("file", "File", [
        { id: "add", label: "Add machine…", onPick: onAddMachine },
        { id: "quit", label: "Quit DeepFlux", onPick: onQuit },
      ])}
      {menu("config", "Config", [
        { id: "settings", label: "Settings…", onPick: () => onOpenConfig("settings") },
        { id: "circle", label: "Family circle…", onPick: () => onOpenConfig("circle") },
        { id: "trusted", label: "Trusted machines…", onPick: () => onOpenConfig("trusted") },
        { id: "assistant", label: "Assistant…", onPick: () => onOpenConfig("assistant") },
      ])}
      {menu("help", "Help", [
        {
          id: "about",
          label: "About DeepFlux",
          hint: version ? `v${version}` : undefined,
          onPick: onAbout,
        },
        { id: "diag", label: "Diagnostics", hint: "Ctrl+Shift+D", onPick: onDiagnostics },
        { id: "site", label: "Open website", onPick: () => void openSite() },
      ])}
    </div>
  );
}

async function openSite(): Promise<void> {
  // No opener plugin (capabilities stay core-only): the site opens in the
  // default browser via target=_blank.
  window.open(WEBSITE_URL, "_blank", "noopener");
}
