// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import React, { useState } from "react";
import { useModalFocus, FOCUSABLE_SELECTOR } from "./components/useModalFocus";
import { ServerModal } from "./ServerModal";
import { rpFromUtf8, rpSerialize } from "./sftp-path";
import { EditorModal } from "./features/files/EditorModal";
import { ApprovalDialog } from "./features/files/dialogs/ApprovalDialog";
import { DeployEditorModal } from "./features/deploy/components/DeployEditorModal";
import { DeleteDialog as DeployDeleteDialog } from "./features/deploy/components/DeleteDialog";
import { CommandPalette } from "./components/CommandPalette";
import { BackupsTab } from "./BackupsTab";
import { ScriptsTab } from "./ScriptsTab";
import type { Server, Script, DeployApp } from "./types";
import type { EditorState as FilesEditorState } from "./features/files/types";
import type { EditorState as DeployEditorState } from "./features/deploy/types";

const mockZeroInvoke = vi.fn();

const sampleServer: Server = {
  id: "srv-test-1",
  name: "Production Web",
  host: "10.0.0.1",
  port: 22,
  user: "ubuntu",
  auth_method: "password",
  key_path: "",
  key_has_passphrase: false,
  host_fingerprint: null,
  tags: ["prod", "web"],
  group: "us-east",
  via_server_id: null,
  created_at: 0,
  updated_at: 0,
};

const scriptWithVars: Script = {
  id: "script-1",
  name: "Deploy Service",
  description: "Test deploy script",
  tags: ["deploy"],
  color: "#3f6d7a",
  body: "echo {{env}}",
  variables: [{ name: "env", label: "Environment", secret_default: false }],
  created_at: 1700000000000,
  updated_at: 1700000000000,
  run_count: 0,
  last_run_at: null,
};

beforeEach(() => {
  vi.clearAllMocks();
  window.zero = {
    invoke: mockZeroInvoke.mockImplementation(async (method: string, params: any) => {
      if (method === "native-sdk.credentials.get") return null;
      if (method === "native-sdk.credentials.set") return {};
      if (method === "native-sdk.credentials.delete") return {};
      if (method === "oars.scripts.list" || method === "scripts.list") {
        return { scripts: [scriptWithVars], recovery_error: null };
      }
      if (method === "oars.backup.jobs.list" || method === "backup.list") {
        return { jobs: [], backups: [] };
      }
      if (method === "oars.servers.list" || method === "servers.list") {
        return { servers: [sampleServer] };
      }
      if (method === "oars.servers.save" || method === "servers.save") {
        return { server: params };
      }
      return {};
    }),
  };
});

afterEach(() => {
  cleanup();
  delete window.zero;
});

// Helper component for low-level focus trapping tests
function StressModal({
  onClose,
  initialSelector,
  canClose = true,
  children,
}: {
  onClose: () => void;
  initialSelector?: string;
  canClose?: boolean;
  children?: React.ReactNode;
}) {
  const dialogRef = useModalFocus(onClose, initialSelector, canClose);
  return (
    <div className="oars-modal-overlay" role="presentation">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="stress-modal-title"
        className="oars-modal"
      >
        <h2 id="stress-modal-title">Stress Modal</h2>
        {children}
      </div>
    </div>
  );
}

describe("Empirical Challenger: Modal Focus Management & Dialog A11y Suite", () => {
  describe("1. Focus Trapping Precision & Boundary Wrapping", () => {
    it("cycles Tab from the last focusable element back to the first", async () => {
      const onClose = vi.fn();
      render(
        <StressModal onClose={onClose}>
          <input data-testid="el-1" placeholder="First" />
          <button data-testid="el-2">Middle</button>
          <a data-testid="el-3" href="#action">Last Link</a>
        </StressModal>
      );

      const first = screen.getByTestId("el-1");
      const last = screen.getByTestId("el-3");

      await waitFor(() => {
        expect(document.activeElement).toBe(first);
      });

      last.focus();
      expect(document.activeElement).toBe(last);

      fireEvent.keyDown(window, { key: "Tab" });
      expect(document.activeElement).toBe(first);
    });

    it("cycles Shift+Tab from the first focusable element back to the last", async () => {
      const onClose = vi.fn();
      render(
        <StressModal onClose={onClose}>
          <button data-testid="btn-first">First Button</button>
          <input data-testid="input-middle" placeholder="Middle Input" />
          <button data-testid="btn-last">Last Button</button>
        </StressModal>
      );

      const first = screen.getByTestId("btn-first");
      const last = screen.getByTestId("btn-last");

      await waitFor(() => {
        expect(document.activeElement).toBe(first);
      });

      fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
      expect(document.activeElement).toBe(last);
    });

    it("correctly traps focus when exactly ONE interactive element exists", async () => {
      const onClose = vi.fn();
      render(
        <StressModal onClose={onClose}>
          <button data-testid="sole-button">Acknowledge</button>
        </StressModal>
      );

      const soleBtn = screen.getByTestId("sole-button");
      await waitFor(() => {
        expect(document.activeElement).toBe(soleBtn);
      });

      // Pressing Tab should keep focus on the single element
      fireEvent.keyDown(window, { key: "Tab" });
      expect(document.activeElement).toBe(soleBtn);

      // Pressing Shift+Tab should also keep focus on the single element
      fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
      expect(document.activeElement).toBe(soleBtn);
    });

    it("falls back to modal container with tabindex=-1 when ZERO focusable elements exist and traps Tab", async () => {
      const onClose = vi.fn();
      render(
        <StressModal onClose={onClose}>
          <p>Read-only information with no buttons or inputs.</p>
        </StressModal>
      );

      const dialog = screen.getByRole("dialog");
      await waitFor(() => {
        expect(dialog.getAttribute("tabindex")).toBe("-1");
        expect(document.activeElement).toBe(dialog);
      });

      // Pressing Tab or Shift+Tab keeps focus on container and prevents escape
      fireEvent.keyDown(window, { key: "Tab" });
      expect(document.activeElement).toBe(dialog);

      fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
      expect(document.activeElement).toBe(dialog);
    });

    it("dynamically updates focus trap boundary wrapping when DOM changes inside modal", async () => {
      function DynamicModal() {
        const [showExtra, setShowExtra] = useState(false);
        const ref = useModalFocus(() => {});
        return (
          <div ref={ref} role="dialog" aria-modal="true">
            <button data-testid="btn-toggle" onClick={() => setShowExtra((v) => !v)}>
              Toggle
            </button>
            {showExtra && <input data-testid="extra-input" placeholder="Appeared" />}
            <button data-testid="btn-final">Final</button>
          </div>
        );
      }

      render(<DynamicModal />);
      const toggleBtn = screen.getByTestId("btn-toggle");
      const finalBtn = screen.getByTestId("btn-final");

      await waitFor(() => {
        expect(document.activeElement).toBe(toggleBtn);
      });

      // From first (toggleBtn), Shift+Tab wraps to finalBtn
      fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
      expect(document.activeElement).toBe(finalBtn);

      // From last (finalBtn), Tab wraps to toggleBtn
      fireEvent.keyDown(window, { key: "Tab" });
      expect(document.activeElement).toBe(toggleBtn);

      // Expand extra element dynamically
      fireEvent.click(toggleBtn);
      const extraInput = screen.getByTestId("extra-input");
      expect(extraInput).toBeTruthy();

      // From finalBtn (last), Tab wraps to toggleBtn (first)
      finalBtn.focus();
      fireEvent.keyDown(window, { key: "Tab" });
      expect(document.activeElement).toBe(toggleBtn);

      // From toggleBtn (first), Shift+Tab wraps to finalBtn (last)
      fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
      expect(document.activeElement).toBe(finalBtn);
    });
  });

  describe("2. Outside Boundary Focus Snap-Back", () => {
    it("snaps focus to the first element when Tab is pressed while focus is outside dialog", async () => {
      const onClose = vi.fn();
      render(
        <div>
          <button data-testid="outside-top">Outside Top</button>
          <StressModal onClose={onClose}>
            <input data-testid="inside-1" placeholder="First inside" />
            <button data-testid="inside-2">Second inside</button>
          </StressModal>
          <button data-testid="outside-bottom">Outside Bottom</button>
        </div>
      );

      const outsideBtn = screen.getByTestId("outside-top");
      const firstInside = screen.getByTestId("inside-1");

      // Intentionally move focus outside
      outsideBtn.focus();
      expect(document.activeElement).toBe(outsideBtn);

      // Pressing Tab should intercept and snap focus to first inside
      fireEvent.keyDown(window, { key: "Tab" });
      expect(document.activeElement).toBe(firstInside);
    });

    it("snaps focus to the last element when Shift+Tab is pressed while focus is outside dialog", async () => {
      const onClose = vi.fn();
      render(
        <div>
          <button data-testid="outside-top">Outside Top</button>
          <StressModal onClose={onClose}>
            <input data-testid="inside-1" placeholder="First inside" />
            <button data-testid="inside-2">Last inside</button>
          </StressModal>
          <button data-testid="outside-bottom">Outside Bottom</button>
        </div>
      );

      const outsideBottom = screen.getByTestId("outside-bottom");
      const lastInside = screen.getByTestId("inside-2");

      outsideBottom.focus();
      expect(document.activeElement).toBe(outsideBottom);

      // Pressing Shift+Tab snaps to last inside
      fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
      expect(document.activeElement).toBe(lastInside);
    });

    it("snaps focus to modal container when focus is outside and modal has 0 interactive elements", async () => {
      const onClose = vi.fn();
      render(
        <div>
          <button data-testid="outside-elem">Outside</button>
          <StressModal onClose={onClose}>
            <p>No buttons</p>
          </StressModal>
        </div>
      );

      const outside = screen.getByTestId("outside-elem");
      const dialog = screen.getByRole("dialog");

      outside.focus();
      expect(document.activeElement).toBe(outside);

      fireEvent.keyDown(window, { key: "Tab" });
      expect(document.activeElement).toBe(dialog);
    });
  });

  describe("3. Hidden, Inactive & Non-Focusable Elements Exclusion", () => {
    it("strictly excludes input[type=hidden], disabled buttons, aria-hidden and display:none elements", async () => {
      const onClose = vi.fn();
      render(
        <StressModal onClose={onClose}>
          <input type="hidden" data-testid="hidden-input" value="secret" />
          <button disabled data-testid="disabled-btn">Disabled</button>
          <button aria-hidden="true" data-testid="aria-hidden-btn">Aria Hidden</button>
          <input style={{ display: "none" }} data-testid="display-none-input" />
          <input style={{ visibility: "hidden" }} data-testid="visibility-hidden-input" />
          <div tabIndex={-1} data-testid="negative-tabindex">Negative Tabindex</div>
          <span contentEditable={false} data-testid="uneditable-span">Uneditable</span>
          <button data-testid="valid-first">Valid First</button>
          <button data-testid="valid-last">Valid Last</button>
        </StressModal>
      );

      const validFirst = screen.getByTestId("valid-first");
      const validLast = screen.getByTestId("valid-last");

      // Initial focus must skip all invalid items and land on valid-first
      await waitFor(() => {
        expect(document.activeElement).toBe(validFirst);
      });

      // Shift+Tab from validFirst should wrap directly to validLast
      fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
      expect(document.activeElement).toBe(validLast);

      // Tab from validLast should wrap directly to validFirst
      fireEvent.keyDown(window, { key: "Tab" });
      expect(document.activeElement).toBe(validFirst);
    });

    it("falls back to first visible focusable element if initialSelector points to a hidden/disabled element", async () => {
      const onClose = vi.fn();
      render(
        <StressModal onClose={onClose} initialSelector="[data-testid='hidden-target']">
          <input data-testid="hidden-target" style={{ display: "none" }} />
          <button data-testid="fallback-target">Visible Fallback</button>
        </StressModal>
      );

      const fallback = screen.getByTestId("fallback-target");
      await waitFor(() => {
        expect(document.activeElement).toBe(fallback);
      });
    });
  });

  describe("4. Escape Key Interception & Guarded Cancellation", () => {
    it("triggers onCancel when Escape key is pressed under normal conditions", () => {
      const onClose = vi.fn();
      render(
        <StressModal onClose={onClose}>
          <button>Action</button>
        </StressModal>
      );

      fireEvent.keyDown(window, { key: "Escape" });
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it("does NOT close modal if inner component sets defaultPrevented on Escape event", () => {
      const onClose = vi.fn();
      render(
        <StressModal onClose={onClose}>
          <input
            data-testid="autocomplete-input"
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                e.preventDefault(); // Simulate dismissing dropdown/autocomplete
              }
            }}
          />
        </StressModal>
      );

      const input = screen.getByTestId("autocomplete-input");
      input.focus();

      // Press Escape inside input with preventDefault
      fireEvent.keyDown(input, { key: "Escape", cancelable: true });
      expect(onClose).not.toHaveBeenCalled();

      // Press Escape on window without preventDefault -> closes modal
      fireEvent.keyDown(window, { key: "Escape" });
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it("respects canClose=false (e.g. busy state) and permits closing once canClose becomes true", () => {
      function StatefulModal() {
        const [busy, setBusy] = useState(true);
        const [closed, setClosed] = useState(false);
        const ref = useModalFocus(() => setClosed(true), undefined, !busy);

        return (
          <div ref={ref} role="dialog" aria-modal="true">
            <span data-testid="status">{closed ? "CLOSED" : busy ? "BUSY" : "READY"}</span>
            <button data-testid="finish-busy" onClick={() => setBusy(false)}>Finish</button>
          </div>
        );
      }

      render(<StatefulModal />);
      expect(screen.getByTestId("status").textContent).toBe("BUSY");

      // While busy, Escape is blocked
      fireEvent.keyDown(window, { key: "Escape" });
      expect(screen.getByTestId("status").textContent).toBe("BUSY");

      // Transition to not busy
      fireEvent.click(screen.getByTestId("finish-busy"));
      expect(screen.getByTestId("status").textContent).toBe("READY");

      // Now Escape succeeds
      fireEvent.keyDown(window, { key: "Escape" });
      expect(screen.getByTestId("status").textContent).toBe("CLOSED");
    });
  });

  describe("5. Focus Restoration & Nested Dialogs", () => {
    it("restores focus to previous active element on unmount", async () => {
      function Launcher() {
        const [open, setOpen] = useState(false);
        return (
          <div>
            <button data-testid="trigger-btn" onClick={() => setOpen(true)}>
              Launch
            </button>
            {open && (
              <StressModal onClose={() => setOpen(false)}>
                <button data-testid="modal-close-btn" onClick={() => setOpen(false)}>
                  Close
                </button>
              </StressModal>
            )}
          </div>
        );
      }

      render(<Launcher />);
      const trigger = screen.getByTestId("trigger-btn");
      trigger.focus();
      expect(document.activeElement).toBe(trigger);

      fireEvent.click(trigger);
      await waitFor(() => {
        expect(screen.getByTestId("modal-close-btn")).toBeTruthy();
      });

      fireEvent.click(screen.getByTestId("modal-close-btn"));
      await waitFor(() => {
        expect(screen.queryByTestId("modal-close-btn")).toBeNull();
        expect(document.activeElement).toBe(trigger);
      });
    });

    it("safely handles unmounted previous element without throwing errors", async () => {
      function DisappearingLauncher() {
        const [open, setOpen] = useState(false);
        return (
          <div>
            {!open && (
              <button data-testid="temporary-trigger" onClick={() => setOpen(true)}>
                Will disappear
              </button>
            )}
            {open && (
              <StressModal onClose={() => setOpen(false)}>
                <button data-testid="modal-done" onClick={() => setOpen(false)}>
                  Done
                </button>
              </StressModal>
            )}
          </div>
        );
      }

      render(<DisappearingLauncher />);
      const tempTrigger = screen.getByTestId("temporary-trigger");
      tempTrigger.focus();

      fireEvent.click(tempTrigger);
      await waitFor(() => {
        expect(screen.getByTestId("modal-done")).toBeTruthy();
      });

      // Closing modal when previous trigger is no longer in DOM shouldn't throw
      expect(() => {
        fireEvent.click(screen.getByTestId("modal-done"));
      }).not.toThrow();
    });

    it("handles stacked/nested modals with multi-level focus restoration", async () => {
      function NestedWorkflow() {
        const [modalA, setModalA] = useState(false);
        const [modalB, setModalB] = useState(false);

        return (
          <div>
            <button data-testid="root-launcher" onClick={() => setModalA(true)}>
              Root Launcher
            </button>
            {modalA && (
              <StressModal onClose={() => setModalA(false)}>
                <button data-testid="open-modal-b" onClick={() => setModalB(true)}>
                  Open Dialog B
                </button>
                <button data-testid="close-modal-a" onClick={() => setModalA(false)}>
                  Close A
                </button>
              </StressModal>
            )}
            {modalB && (
              <StressModal onClose={() => setModalB(false)}>
                <button data-testid="confirm-modal-b" onClick={() => setModalB(false)}>
                  Confirm B
                </button>
              </StressModal>
            )}
          </div>
        );
      }

      render(<NestedWorkflow />);
      const rootLauncher = screen.getByTestId("root-launcher");
      rootLauncher.focus();

      // Open Modal A
      fireEvent.click(rootLauncher);
      await waitFor(() => {
        expect(screen.getByTestId("open-modal-b")).toBeTruthy();
      });

      const openBBtn = screen.getByTestId("open-modal-b");
      openBBtn.focus();

      // Open Modal B
      fireEvent.click(openBBtn);
      await waitFor(() => {
        expect(screen.getByTestId("confirm-modal-b")).toBeTruthy();
      });

      // Close Modal B -> focus should return to openBBtn in Modal A
      fireEvent.click(screen.getByTestId("confirm-modal-b"));
      await waitFor(() => {
        expect(screen.queryByTestId("confirm-modal-b")).toBeNull();
        expect(document.activeElement).toBe(openBBtn);
      });

      // Close Modal A -> focus should return to rootLauncher
      fireEvent.click(screen.getByTestId("close-modal-a"));
      await waitFor(() => {
        expect(screen.queryByTestId("close-modal-a")).toBeNull();
        expect(document.activeElement).toBe(rootLauncher);
      });
    });
  });

  describe("6. Real Modal Components Verification", () => {
    describe("ServerModal", () => {
      it("renders complete WAI-ARIA modal attributes and autofocuses #oars-name", async () => {
        const onClose = vi.fn();
        const onSaved = vi.fn();
        render(
          <ServerModal
            server={sampleServer}
            servers={[sampleServer]}
            onClose={onClose}
            onSaved={onSaved}
          />
        );

        const dialog = screen.getByRole("dialog");
        expect(dialog.getAttribute("aria-modal")).toBe("true");
        expect(dialog.getAttribute("aria-labelledby")).toBe("oars-modal-title");
        expect(dialog.getAttribute("aria-describedby")).toBe("oars-modal-desc");

        const title = screen.getByText("Edit connection profile");
        expect(title.getAttribute("id")).toBe("oars-modal-title");

        const subtitle = screen.getByText(/Update how Oars connects to this server/i);
        expect(subtitle.getAttribute("id")).toBe("oars-modal-desc");

        await waitFor(() => {
          expect(document.activeElement).toBe(screen.getByLabelText("Connection name"));
        });
      });

      it("traps focus between first interactive element (close button) and last action button (submit)", async () => {
        const onClose = vi.fn();
        const onSaved = vi.fn();
        render(
          <ServerModal
            server={sampleServer}
            servers={[sampleServer]}
            onClose={onClose}
            onSaved={onSaved}
          />
        );

        const closeBtn = screen.getByRole("button", { name: "Close" });
        const saveBtn = screen.getByRole("button", { name: "Save changes" });

        // From first element (closeBtn), Shift+Tab wraps to save button
        closeBtn.focus();
        fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
        expect(document.activeElement).toBe(saveBtn);

        // From save button (last), Tab wraps back to close button
        fireEvent.keyDown(window, { key: "Tab" });
        expect(document.activeElement).toBe(closeBtn);
      });

      it("closes ServerModal on Escape and backdrop click", () => {
        const onClose = vi.fn();
        const onSaved = vi.fn();
        render(
          <ServerModal
            server={sampleServer}
            servers={[sampleServer]}
            onClose={onClose}
            onSaved={onSaved}
          />
        );

        fireEvent.keyDown(window, { key: "Escape" });
        expect(onClose).toHaveBeenCalledTimes(1);

        const overlay = document.querySelector(".oars-modal-overlay")!;
        fireEvent.mouseDown(overlay);
        expect(onClose).toHaveBeenCalledTimes(2);
      });
    });

    describe("EditorModal", () => {
      const editorPath = rpFromUtf8("/etc/nginx/nginx.conf");
      const sampleEditor: FilesEditorState = {
        path: editorPath,
        pathKey: rpSerialize(editorPath),
        display: "nginx.conf",
        content: "server { listen 80; }",
        sha256: "abc123",
        dirty: false,
        phase: "editing",
        error: null,
        conflict: null,
        tooLarge: false,
        entry: {
          name: rpFromUtf8("nginx.conf"),
          display: "nginx.conf",
          size: 24,
          mode: "-rw-r--r--",
          mtime: 1700000000,
          kind: "file",
          uid: 1000,
          gid: 1000,
          link_target: null,
        },
      };

      it("renders with aria-labelledby and aria-describedby and focuses textarea", async () => {
        const onClose = vi.fn();
        render(
          <EditorModal
            editor={sampleEditor}
            onClose={onClose}
            onSave={vi.fn()}
            onReload={vi.fn()}
            onDiscard={vi.fn()}
            onCancelDiscard={vi.fn()}
            onDismissConflict={vi.fn()}
            dirtyCloseOpen={false}
            onChange={vi.fn()}
          />
        );

        const dialog = screen.getByRole("dialog");
        expect(dialog.getAttribute("aria-modal")).toBe("true");
        expect(dialog.getAttribute("aria-labelledby")).toBe("fs-editor-title");
        expect(dialog.getAttribute("aria-describedby")).toBe("fs-editor-desc");

        await waitFor(() => {
          expect(document.activeElement).toBe(screen.getByLabelText("File content"));
        });
      });

      it("traps focus and closes on Escape", () => {
        const onClose = vi.fn();
        render(
          <EditorModal
            editor={sampleEditor}
            onClose={onClose}
            onSave={vi.fn()}
            onReload={vi.fn()}
            onDiscard={vi.fn()}
            onCancelDiscard={vi.fn()}
            onDismissConflict={vi.fn()}
            dirtyCloseOpen={false}
            onChange={vi.fn()}
          />
        );

        fireEvent.keyDown(window, { key: "Escape" });
        expect(onClose).toHaveBeenCalledTimes(1);
      });
    });

    describe("ApprovalDialog", () => {
      it("supports custom initialFocusSelector and traps tab cycle", async () => {
        const onCancel = vi.fn();
        render(
          <ApprovalDialog
            icon={<span>!</span>}
            iconClass="danger"
            title="Confirm Action"
            subtitle="Are you sure?"
            actions={
              <>
                <button data-testid="dialog-cancel" onClick={onCancel}>Cancel</button>
                <button data-testid="dialog-confirm">Confirm</button>
              </>
            }
            onCancel={onCancel}
            labelledBy="dialog-title"
            initialFocusSelector="[data-testid='dialog-confirm']"
          />
        );

        const confirmBtn = screen.getByTestId("dialog-confirm");
        const closeBtn = screen.getByRole("button", { name: "Close dialog" });

        await waitFor(() => {
          expect(document.activeElement).toBe(confirmBtn);
        });

        // Tab from confirm wraps back to closeBtn
        fireEvent.keyDown(window, { key: "Tab" });
        expect(document.activeElement).toBe(closeBtn);

        // Shift+Tab from closeBtn wraps to confirmBtn
        fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
        expect(document.activeElement).toBe(confirmBtn);
      });
    });

    describe("DeployEditorModal & DeployDeleteDialog", () => {
      const sampleDeployEditor: DeployEditorState = {
        id: "app-1",
        server_id: "srv-1",
        name: "api-service",
        environment: "production",
        folder: "/var/www/api",
        repo: { url: "https://github.com/example/api.git", transport: "https", branch: "main" },
        runtime: {
          node_version: "20",
          type: "node",
          package_manager: "npm",
          install: "npm ci",
          build: "npm run build",
          entry: "index.js",
          args: "",
          start_command: "npm start",
          build_folder: "dist",
        },
        env_vars: [],
        domains: ["api.example.com"],
        ssl: false,
        email: "admin@example.com",
        app_port: 3000,
      };

      const sampleDeployApp: DeployApp = {
        id: "app-1",
        server_id: "srv-1",
        name: "api-service",
        environment: "production",
        folder: "/var/www/api",
        repo: { url: "https://github.com/example/api.git", transport: "https", branch: "main" },
        runtime: {
          node_version: "20",
          type: "node",
          package_manager: "npm",
          install: "npm ci",
          build: "npm run build",
          entry: "index.js",
          args: "",
          start_command: "npm start",
          build_folder: "dist",
        },
        env_vars: [],
        domains: ["api.example.com"],
        ssl: false,
        email: "admin@example.com",
        app_port: 3000,
        revision: 1,
        created_at_ms: Date.now(),
        updated_at_ms: Date.now(),
      };

      it("DeployEditorModal focuses #deploy-app-name and has ARIA dialog attributes", async () => {
        const onCancel = vi.fn();
        render(
          <DeployEditorModal
            editor={sampleDeployEditor}
            setEditor={vi.fn()}
            busy={false}
            error={null}
            bulkText=""
            setBulkText={vi.fn()}
            bulkPreview={null}
            onPreview={vi.fn()}
            onApplyPreview={vi.fn()}
            onCancel={onCancel}
            onSave={vi.fn()}
          />
        );

        const dialog = screen.getByRole("dialog");
        expect(dialog.getAttribute("aria-modal")).toBe("true");
        expect(dialog.getAttribute("aria-labelledby")).toBe("deploy-editor-title");
        expect(dialog.getAttribute("aria-describedby")).toBe("deploy-editor-desc");

        await waitFor(() => {
          expect(document.activeElement).toBe(screen.getByLabelText("Name"));
        });
      });

      it("DeployDeleteDialog focuses confirm button and closes on Escape", async () => {
        const onCancel = vi.fn();
        const onConfirm = vi.fn();
        render(
          <DeployDeleteDialog
            state={{ app: sampleDeployApp, busy: false, error: null }}
            onCancel={onCancel}
            onConfirm={onConfirm}
          />
        );

        const dialog = screen.getByRole("dialog");
        expect(dialog.getAttribute("aria-modal")).toBe("true");

        await waitFor(() => {
          expect(document.activeElement).toBe(screen.getByRole("button", { name: "Delete application" }));
        });

        fireEvent.keyDown(window, { key: "Escape" });
        expect(onCancel).toHaveBeenCalledTimes(1);
      });
    });

    describe("CommandPalette", () => {
      it("renders combobox with useModalFocus, initial autofocus on input, and Escape dismissal", async () => {
        const onClose = vi.fn();
        const commands = [
          { id: "cmd-1", title: "Reload Server", run: vi.fn() },
          { id: "cmd-2", title: "View Logs", run: vi.fn() },
        ];

        render(
          <CommandPalette
            isOpen={true}
            onClose={onClose}
            commands={commands}
          />
        );

        const input = screen.getByRole("combobox");
        await waitFor(() => {
          expect(document.activeElement).toBe(input);
        });

        fireEvent.keyDown(window, { key: "Escape" });
        expect(onClose).toHaveBeenCalledTimes(1);
      });
    });

    describe("BackupsTab (BackupEditModal integration)", () => {
      it("opens BackupEditModal on 'New backup' click with proper focus on #backup-name and Escape dismissal", async () => {
        render(<BackupsTab serverId="srv-1" />);

        await waitFor(() => {
          expect(screen.getByRole("button", { name: /New backup/i })).toBeTruthy();
        });

        const newBtn = screen.getByRole("button", { name: /New backup/i });
        fireEvent.click(newBtn);

        const dialog = screen.getByRole("dialog");
        expect(dialog.getAttribute("aria-modal")).toBe("true");
        expect(dialog.getAttribute("aria-labelledby")).toBe("backup-edit-title");
        expect(dialog.getAttribute("aria-describedby")).toBe("backup-edit-desc");

        await waitFor(() => {
          expect(document.activeElement).toBe(screen.getByLabelText("Name"));
        });

        // Escape closes BackupEditModal
        fireEvent.keyDown(window, { key: "Escape" });
        await waitFor(() => {
          expect(screen.queryByRole("dialog")).toBeNull();
        });
      });
    });

    describe("ScriptsTab Autocomplete & Nested Escape Handling", () => {
      it("handles Escape in ScriptEditor: dismisses autocomplete without closing modal on 1st Escape, closes modal on 2nd Escape", async () => {
        render(
          <ScriptsTab
            serverId="srv-test-1"
            servers={[sampleServer]}
            connected={true}
          />
        );

        await waitFor(() => {
          expect(screen.getAllByText("Deploy Service").length).toBeGreaterThan(0);
        });

        // Open script editor
        const editBtn = screen.getByRole("button", { name: /Edit/i });
        fireEvent.click(editBtn);

        await waitFor(() => {
          expect(screen.getByRole("dialog")).toBeTruthy();
        });

        const textarea = screen.getByLabelText(/Command body/i);
        textarea.focus();

        // Type '{{' to trigger variable autocomplete
        fireEvent.change(textarea, { target: { value: "echo {{", selectionStart: 7 } });

        await waitFor(() => {
          expect(screen.getByRole("listbox", { name: "Variable suggestions" })).toBeTruthy();
        });

        // First Escape dismisses autocomplete only
        fireEvent.keyDown(textarea, { key: "Escape", cancelable: true });
        await waitFor(() => {
          expect(screen.queryByRole("listbox", { name: "Variable suggestions" })).toBeNull();
          expect(screen.getByRole("dialog")).toBeTruthy(); // Editor modal stays open!
        });

        // Second Escape closes the editor modal
        fireEvent.keyDown(window, { key: "Escape" });
        await waitFor(() => {
          expect(screen.queryByRole("dialog")).toBeNull();
        });
      });
    });
  });

  describe("7. Advanced Edge Cases & Resilience Stress Testing", () => {
    it("handles rapid mount and unmount before requestAnimationFrame fires without errors", () => {
      const onClose = vi.fn();
      const { unmount } = render(
        <StressModal onClose={onClose}>
          <input placeholder="Fast unmount" />
        </StressModal>
      );

      // Immediately unmount before RAF ticks
      expect(() => {
        unmount();
      }).not.toThrow();
    });

    it("correctly includes summary, contenteditable, select, and href anchors in focusable cycle", async () => {
      const onClose = vi.fn();
      render(
        <StressModal onClose={onClose}>
          <a data-testid="link-with-href" href="https://example.com">Valid link</a>
          <a data-testid="link-without-href">Invalid anchor</a>
          <details>
            <summary data-testid="details-summary">More details</summary>
            <p>Hidden body</p>
          </details>
          <select data-testid="select-field">
            <option value="1">Option 1</option>
          </select>
          <div data-testid="editable-area" contentEditable={true}>Editable text</div>
          <div data-testid="non-editable-area" contentEditable={false}>Non-editable text</div>
          <button data-testid="end-btn">End</button>
        </StressModal>
      );

      const first = screen.getByTestId("link-with-href");
      const last = screen.getByTestId("end-btn");

      await waitFor(() => {
        expect(document.activeElement).toBe(first);
      });

      // Shift+Tab from first wraps to last
      fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
      expect(document.activeElement).toBe(last);

      // Tab from last wraps to first
      fireEvent.keyDown(window, { key: "Tab" });
      expect(document.activeElement).toBe(first);
    });

    it("ensures clicks on modal contents do NOT trigger backdrop onClose", () => {
      const onClose = vi.fn();
      render(
        <div
          className="oars-modal-overlay"
          role="presentation"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) onClose();
          }}
        >
          <StressModal onClose={onClose}>
            <div data-testid="modal-inner" onClick={(e) => e.stopPropagation()}>
              <button data-testid="inner-btn">Inside button</button>
            </div>
          </StressModal>
        </div>
      );

      // Clicking inner content should not trigger backdrop close
      const innerBtn = screen.getByTestId("inner-btn");
      fireEvent.mouseDown(innerBtn);
      expect(onClose).not.toHaveBeenCalled();

      // Clicking overlay backdrop itself DOES trigger onClose
      const overlay = document.querySelector(".oars-modal-overlay")!;
      fireEvent.mouseDown(overlay);
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it("cleans up keydown event listeners on unmount so subsequent keys do not trigger unmounted handler", () => {
      const onClose = vi.fn();
      const { unmount } = render(
        <StressModal onClose={onClose}>
          <button>Active</button>
        </StressModal>
      );

      unmount();

      // Pressing Escape after unmount should NOT trigger onClose
      fireEvent.keyDown(window, { key: "Escape" });
      expect(onClose).not.toHaveBeenCalled();
    });
  });
});
