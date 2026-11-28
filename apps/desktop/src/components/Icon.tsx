/** Line icons (one stroke style, drawn as SVG — no emoji, no icon font).
 * Every symbol is `currentColor`, so a button's icon follows its label. */
import type { ReactNode } from "react";

export type IconName =
  | "monitor"
  | "bot"
  | "sparkle"
  | "trash"
  | "copy"
  | "check"
  | "search"
  | "send"
  | "x"
  | "sliders"
  | "link"
  | "share"
  | "stop"
  | "users"
  | "message"
  | "alert"
  | "eye"
  | "pointer"
  | "keyboard"
  | "wheel"
  | "move"
  | "clock"
  | "terminal"
  | "file"
  | "download"
  | "power"
  | "list"
  | "tool"
  | "refresh";

const PATHS: Record<IconName, ReactNode> = {
  monitor: (
    <>
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <path d="M8 20h8M12 16v4" />
    </>
  ),
  bot: (
    <>
      <path d="M12 4v4" />
      <rect x="4" y="8" width="16" height="11" rx="3" />
      <path d="M9 13h.01M15 13h.01M9 16h6" />
    </>
  ),
  sparkle: (
    <>
      <path d="M11 3l1.9 5.1L18 10l-5.1 1.9L11 17l-1.9-5.1L4 10l5.1-1.9L11 3z" />
      <path d="M19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9L19 15z" />
    </>
  ),
  trash: (
    <path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3" />
  ),
  copy: (
    <>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15V6a2 2 0 0 1 2-2h9" />
    </>
  ),
  check: <path d="M5 12.5l4.5 4.5L19 7.5" />,
  search: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="M20 20l-3.5-3.5" />
    </>
  ),
  send: <path d="M4.5 12L20 4l-6 16-3-7-6.5-1zM20 4l-9 9" />,
  x: <path d="M6 6l12 12M18 6L6 18" />,
  sliders: (
    <>
      <path d="M4 6h8M18 6h2M4 12h2M12 12h8M4 18h10M20 18v.01" />
      <circle cx="15" cy="6" r="2" />
      <circle cx="9" cy="12" r="2" />
      <circle cx="17" cy="18" r="2" />
    </>
  ),
  link: (
    <path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1.2 1.2M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1.2-1.2" />
  ),
  share: (
    <>
      <path d="M12 14V3M8 7l4-4 4 4" />
      <path d="M5 14v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4" />
    </>
  ),
  stop: <rect x="6" y="6" width="12" height="12" rx="2" />,
  users: (
    <>
      <circle cx="9" cy="8" r="3.5" />
      <path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 15a5 5 0 0 1 5.5 5" />
      <circle cx="17" cy="9" r="2.5" />
    </>
  ),
  message: <path d="M6 5h12a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H10l-5 4V7a2 2 0 0 1 1-2z" />,
  alert: (
    <>
      <path d="M12 3l10 18H2L12 3z" />
      <path d="M12 10v5M12 18h.01" />
    </>
  ),
  eye: (
    <>
      <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6z" />
      <circle cx="12" cy="12" r="2.5" />
    </>
  ),
  pointer: <path d="M5 3l14 8-6 1.5L11 19 5 3z" />,
  keyboard: (
    <>
      <rect x="3" y="6" width="18" height="12" rx="2" />
      <path d="M7 10h.01M11 10h.01M15 10h.01M7 14h10" />
    </>
  ),
  wheel: (
    <>
      <rect x="8" y="3" width="8" height="18" rx="4" />
      <path d="M12 7v4" />
    </>
  ),
  move: <path d="M12 3v18M3 12h18M9 6l3-3 3 3M9 18l3 3 3-3M6 9l-3 3 3 3M18 9l3 3-3 3" />,
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
  terminal: (
    <>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path d="M7 9l3 3-3 3M13 15h4" />
    </>
  ),
  file: (
    <>
      <path d="M7 3h7l4 4v14H7V3z" />
      <path d="M14 3v4h4M10 12h5M10 16h5" />
    </>
  ),
  download: (
    <>
      <path d="M12 4v11M8 11l4 4 4-4" />
      <path d="M5 19h14" />
    </>
  ),
  power: (
    <>
      <path d="M12 3v8" />
      <path d="M6.3 6.5a8 8 0 1 0 11.4 0" />
    </>
  ),
  list: <path d="M9 6h11M9 12h11M9 18h11M4 6h.01M4 12h.01M4 18h.01" />,
  tool: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1" />
    </>
  ),
  refresh: <path d="M20 12a8 8 0 1 1-2.5-5.8M20 4v5h-5" />,
};

export function Icon({ name, size = 16 }: { name: IconName; size?: number }) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[name]}
    </svg>
  );
}
