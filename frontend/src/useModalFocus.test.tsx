// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import React, { useState } from "react";
import { useModalFocus } from "./components/useModalFocus";

function TestModal({
  onClose,
  initialSelector,
  enabled = true,
  withInputs = true,
}: {
  onClose: () => void;
  initialSelector?: string;
  enabled?: boolean;
  withInputs?: boolean;
}) {
  const dialogRef = useModalFocus(onClose, initialSelector, enabled);
  return (
    <div className="oars-modal-overlay" role="presentation">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        className="oars-modal"
      >
        <h2 id="modal-title">Test Modal</h2>
        {withInputs ? (
          <>
            <input data-testid="input-1" placeholder="First input" />
            <input data-testid="input-2" placeholder="Second input" />
            <button data-testid="submit-btn">Submit</button>
            <button data-testid="cancel-btn" onClick={onClose}>
              Cancel
            </button>
          </>
        ) : (
          <p>No interactive elements here</p>
        )}
      </div>
    </div>
  );
}

function Wrapper() {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button data-testid="open-modal-btn" onClick={() => setOpen(true)}>
        Open Modal
      </button>
      {open && <TestModal onClose={() => setOpen(false)} />}
    </div>
  );
}

describe("useModalFocus", () => {
  afterEach(() => {
    cleanup();
  });

  it("traps focus and focuses initial element via RAF", async () => {
    const onClose = vi.fn();
    render(<TestModal onClose={onClose} />);

    await waitFor(() => {
      expect(document.activeElement).toBe(screen.getByTestId("input-1"));
    });
  });

  it("focuses specific initialFocusSelector if provided", async () => {
    const onClose = vi.fn();
    render(<TestModal onClose={onClose} initialSelector="[data-testid='submit-btn']" />);

    await waitFor(() => {
      expect(document.activeElement).toBe(screen.getByTestId("submit-btn"));
    });
  });

  it("traps Tab from last element to first element", async () => {
    const onClose = vi.fn();
    render(<TestModal onClose={onClose} />);

    const cancelBtn = screen.getByTestId("cancel-btn");
    const firstInput = screen.getByTestId("input-1");

    cancelBtn.focus();
    expect(document.activeElement).toBe(cancelBtn);

    fireEvent.keyDown(window, { key: "Tab" });
    expect(document.activeElement).toBe(firstInput);
  });

  it("traps Shift+Tab from first element to last element", async () => {
    const onClose = vi.fn();
    render(<TestModal onClose={onClose} />);

    const firstInput = screen.getByTestId("input-1");
    const cancelBtn = screen.getByTestId("cancel-btn");

    firstInput.focus();
    expect(document.activeElement).toBe(firstInput);

    fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(cancelBtn);
  });

  it("calls onClose when Escape key is pressed", () => {
    const onClose = vi.fn();
    render(<TestModal onClose={onClose} />);

    fireEvent.keyDown(window, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("lets only the topmost dialog handle Escape", () => {
    const closeFirst = vi.fn();
    const closeSecond = vi.fn();
    render(
      <>
        <TestModal onClose={closeFirst} />
        <TestModal onClose={closeSecond} />
      </>,
    );

    fireEvent.keyDown(window, { key: "Escape" });

    expect(closeFirst).not.toHaveBeenCalled();
    expect(closeSecond).toHaveBeenCalledTimes(1);
  });

  it("ignores Escape when defaultPrevented is set (e.g. inner autocomplete)", () => {
    const onClose = vi.fn();
    render(<TestModal onClose={onClose} />);

    const event = new KeyboardEvent("keydown", { key: "Escape", cancelable: true, bubbles: true });
    event.preventDefault();
    window.dispatchEvent(event);

    expect(onClose).not.toHaveBeenCalled();
  });

  it("restores focus to previous activeElement on unmount", async () => {
    render(<Wrapper />);

    const openBtn = screen.getByTestId("open-modal-btn");
    openBtn.focus();
    expect(document.activeElement).toBe(openBtn);

    fireEvent.click(openBtn);

    await waitFor(() => {
      expect(screen.getByTestId("input-1")).toBeTruthy();
    });

    const cancelBtn = screen.getByTestId("cancel-btn");
    fireEvent.click(cancelBtn);

    await waitFor(() => {
      expect(screen.queryByTestId("input-1")).toBeNull();
      expect(document.activeElement).toBe(openBtn);
    });
  });

  it("falls back to container focus with tabIndex=-1 when no focusable children exist", async () => {
    const onClose = vi.fn();
    render(<TestModal onClose={onClose} withInputs={false} />);

    const dialog = screen.getByRole("dialog");
    await waitFor(() => {
      expect(dialog.getAttribute("tabindex")).toBe("-1");
      expect(document.activeElement).toBe(dialog);
    });
  });
});
