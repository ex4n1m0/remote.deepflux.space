/** ADR-006 ConsentDialog tests, updated for the one-request simplify pass
 * (2026-10-26): the copy matrix (nickname+code, human vs AI-session), the
 * explicit three-button choice (Allow once / Always allow / Decline), the
 * claimed-trusted warning, and the passive trusted-reconnect card. */

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(cleanup);
import { ConsentDialog, TrustedConnectCard, consentCopy } from "../components/ConsentDialog";
import type { ConsentEvent } from "../types";

const consent = (over: Partial<ConsentEvent>): ConsentEvent => ({
  controller_device_id: "0123456789abcdef",
  session_id: "s1",
  ai_session: false,
  paired: false,
  pairing_proof_ok: false,
  requester_name: null,
  ...over,
});

describe("consentCopy", () => {
  it("human with nickname shows nickname AND code", () => {
    const c = consentCopy(consent({ requester_name: "Mom's PC" }));
    expect(c.title).toContain("Mom's PC (0123456789abcdef)");
    expect(c.title).toContain("asks to control");
    expect(c.alwaysHint).toContain("Trusted machines");
  });

  it("bare code when no nickname; distinct AI-session copy", () => {
    expect(consentCopy(consent({})).title).toContain("0123456789abcdef asks");
    // ADR-007: with a name, the AI title says WHOSE assistant; without
    // one, the code only (no weird possessive on a hex id).
    const ai = consentCopy(consent({ ai_session: true, requester_name: "Lab PC" }));
    expect(ai.title).toContain("Lab PC's AI assistant (0123456789abcdef) asks to control");
    const aiBare = consentCopy(consent({ ai_session: true }));
    expect(aiBare.title).toContain("An AI assistant (0123456789abcdef) asks to control");
    expect(ai.alwaysHint.toLowerCase()).toContain("ai assistant");
  });
});

describe("ConsentDialog", () => {
  it("is a non-modal dialog (no alertdialog) with a polite live announcement", () => {
    render(
      <ConsentDialog
        consent={consent({ requester_name: "Mom's PC" })}
        onAccept={() => {}}
        onReject={() => {}}
      />,
    );
    const dialog = screen.getByRole("dialog", { name: "Connection request" });
    expect(dialog).toBeTruthy();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    // The incoming request itself is spoken: aria-live region above the
    // card carries the request text.
    const live = document.querySelector('p[aria-live="polite"]');
    expect(live?.textContent).toContain("Mom's PC (0123456789abcdef) asks to control");
    const position = live?.compareDocumentPosition(dialog) ?? 0;
    expect(position & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("one request, three plain verbs: Allow once / Always allow / Decline", () => {
    const onAccept = vi.fn();
    render(<ConsentDialog consent={consent({})} onAccept={onAccept} onReject={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Allow once" }));
    expect(onAccept).toHaveBeenCalledWith(false);
    fireEvent.click(screen.getByRole("button", { name: "Always allow this machine" }));
    expect(onAccept).toHaveBeenCalledWith(true);
    expect(screen.getByRole("button", { name: "Decline" })).toBeTruthy();
  });

  it("no checkbox left in the prompt — the choice is explicit buttons", () => {
    render(<ConsentDialog consent={consent({})} onAccept={() => {}} onReject={() => {}} />);
    expect(screen.queryByRole("checkbox")).toBeNull();
  });

  it("AI sessions carry the agent wording under the same three buttons", () => {
    const onAccept = vi.fn();
    render(
      <ConsentDialog
        consent={consent({ ai_session: true })}
        onAccept={onAccept}
        onReject={() => {}}
      />,
    );
    // Title text appears twice by design (dialog + the screen-reader
    // live region) — assert at least one match, then the button wiring.
    expect(screen.getAllByText(/AI assistant \(0123456789abcdef\) asks to control/i).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Allow once" }));
    expect(onAccept).toHaveBeenCalledWith(false);
  });

  it("warns when a claimed-trusted machine cannot prove it", () => {
    render(
      <ConsentDialog
        consent={consent({ paired: true, pairing_proof_ok: false })}
        onAccept={() => {}}
        onReject={() => {}}
      />,
    );
    expect(screen.getByText(/could not prove it/i)).toBeTruthy();
  });

  it("reject wiring", () => {
    const onReject = vi.fn();
    render(<ConsentDialog consent={consent({})} onAccept={() => {}} onReject={onReject} />);
    fireEvent.click(screen.getByRole("button", { name: "Decline" }));
    expect(onReject).toHaveBeenCalledTimes(1);
  });
});

describe("TrustedConnectCard", () => {
  it("is a passive status card, not a dialog", () => {
    render(<TrustedConnectCard consent={consent({ pairing_proof_ok: true })} />);
    expect(screen.getByRole("status")).toBeTruthy();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(screen.getByText(/remembered machine/i)).toBeTruthy();
  });
});
