/** ADR-006 ConsentDialog tests: the copy matrix (nickname+code, human vs
 * AI-session), the remember default (ON for humans, OFF for agents), the
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
    expect(c.rememberHint).toContain("Trusted machines");
  });

  it("bare code when no nickname; distinct AI-session copy", () => {
    expect(consentCopy(consent({})).title).toContain("0123456789abcdef asks");
    const ai = consentCopy(consent({ ai_session: true, requester_name: "Lab PC" }));
    expect(ai.title).toContain("AI-agent control");
    expect(ai.rememberHint.toLowerCase()).toContain("agent");
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

  it("defaults remember ON for humans and wires the choice", () => {
    const onAccept = vi.fn();
    render(<ConsentDialog consent={consent({})} onAccept={onAccept} onReject={() => {}} />);
    expect(screen.getByRole("button", { name: "Accept & remember" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Accept & remember" }));
    expect(onAccept).toHaveBeenCalledWith(true);
  });

  it("defaults remember OFF for AI sessions", () => {
    const onAccept = vi.fn();
    render(
      <ConsentDialog
        consent={consent({ ai_session: true })}
        onAccept={onAccept}
        onReject={() => {}}
      />,
    );
    expect(screen.getByRole("button", { name: "Accept once" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Accept once" }));
    expect(onAccept).toHaveBeenCalledWith(false);
  });

  it("unchecking remember accepts once", () => {
    const onAccept = vi.fn();
    render(<ConsentDialog consent={consent({})} onAccept={onAccept} onReject={() => {}} />);
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Accept once" }));
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
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    expect(onReject).toHaveBeenCalledTimes(1);
  });
});

describe("TrustedConnectCard", () => {
  it("is a passive status card, not a dialog", () => {
    render(<TrustedConnectCard consent={consent({ pairing_proof_ok: true })} />);
    expect(screen.getByRole("status")).toBeTruthy();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(screen.getByText(/trusted machine/i)).toBeTruthy();
  });
});
