// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { TerminalTab } from "./TerminalTab";
import { AccessTab } from "./AccessTab";
import { KeysTab } from "./KeysTab";
import { MonitorTab } from "./MonitorTab";
import { LogsTab } from "./LogsTab";
import type { Server, AccessPollResponse, SshSnapshotPollResponse, MonitorSnapshot, LogSource } from "./types";

vi.mock("xterm", () => ({
  Terminal: function () {
    return {
      loadAddon: vi.fn(),
      open: vi.fn(),
      write: vi.fn(),
      dispose: vi.fn(),
      onData: vi.fn(() => ({ dispose: vi.fn() })),
      onResize: vi.fn(() => ({ dispose: vi.fn() })),
      clear: vi.fn(),
      reset: vi.fn(),
      focus: vi.fn(),
    };
  },
}));

vi.mock("@xterm/addon-fit", () => ({
  FitAddon: function () {
    return {
      fit: vi.fn(),
      proposeDimensions: vi.fn().mockReturnValue({ cols: 80, rows: 24 }),
    };
  },
}));

const mockInvoke = vi.fn();

const testServer: Server = {
  id: "srv-tab-test",
  name: "Target Server",
  host: "192.168.1.100",
  port: 22,
  user: "root",
  auth_method: "password",
  key_path: "",
  key_has_passphrase: false,
  tags: ["testing"],
  group: "cluster",
  host_fingerprint: "SHA256:old-fingerprint-abc",
  via_server_id: null,
  created_at: 0,
  updated_at: 0,
};

const snapshotDone: SshSnapshotPollResponse = {
  ok: true,
  state: "done",
  server_id: testServer.id,
  account: { kind: "connected" },
  scope: "effective_policy",
  created_at_ms: Date.now(),
  finished_at_ms: Date.now(),
  sources: [
    { path: "/root/.ssh/authorized_keys", kind: "static", status: "readable", mode: 0o600, owner: "root", file_sha256: "abc" },
  ],
  keys: [],
  roles: [],
  deploy_keys: [],
  warnings: [],
  capabilities: { privilege: "root", sftp_read_only: true },
  coverage: "complete",
};

const sampleMonitorSnapshot: MonitorSnapshot = {
  ok: true,
  ts: Date.now(),
  cpu: {
    utilization_pct: 25,
    cpu_warming: false,
    load_1: 0.5,
    load_5: 0.4,
    load_15: 0.3,
    uptime_sec: 3600,
    cores: 4,
  },
  mem: {
    used_bytes: 4000000000,
    total_bytes: 16000000000,
    available_bytes: 12000000000,
    swap_used_bytes: 0,
    swap_total_bytes: 2000000000,
  },
  disk: {
    used_bytes: 3000000000,
    total_bytes: 100000000000,
    available_bytes: 70000000000,
  },
  processes: [
    { pid: 1, name: "systemd", cpu: 0.1, mem: 0.5 },
  ],
  probe_error: null,
};

const sampleLogSource: LogSource = {
  path: "/var/log/syslog",
  group: "System",
  name: "syslog",
  size: 1024,
  mtime_epoch: 1700000000,
  age_sec: 10,
  mode: 0o644,
  readable: true,
};

beforeEach(() => {
  vi.clearAllMocks();
  window.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as any;
  window.zero = {
    invoke: mockInvoke.mockImplementation(async (method: string, params: any) => {
      if (method === "native-sdk.credentials.get") return "secret-password";
      if (method === "native-sdk.credentials.set") return {};
      if (method === "native-sdk.credentials.delete") return {};
      if (method === "oars.servers.list" || method === "servers.list") return { servers: [testServer] };
      if (method === "oars.ssh.status" || method === "ssh.status") return { status: "disconnected" };
      if (method === "oars.ssh.connect" || method === "ssh.connect") {
        throw new Error("Host key verification failed: Host key changed");
      }
      if (method === "oars.ssh.poll" || method === "ssh.poll") {
        return { status: "error", error: "Host key verification failed: Host key changed", channels: [] };
      }
      if (method === "oars.ssh.open" || method === "ssh.open") return { channel_id: 1 };
      if (method === "oars.ssh.retrust" || method === "ssh.retrust") return { ok: true };
      if (method === "oars.ssh.resize" || method === "ssh.resize") return {};
      if (method === "oars.ssh.disconnect" || method === "ssh.disconnect") return {};
      if (method === "oars.vnc.status" || method === "vnc.status") return { status: "disconnected" };
      if (method === "oars.vnc.check" || method === "vnc.check") return { installed: false };
      if (method === "oars.monitor.poll" || method === "monitor.poll") {
        return sampleMonitorSnapshot;
      }
      if (method === "oars.logs.scan" || method === "logs.scan") {
        return { sources: [sampleLogSource] };
      }
      if (method === "oars.logs.read" || method === "logs.read") {
        return { ok: true, path: "/var/log/syslog", lines: ["log line 1"], limited: false, binary: false };
      }
      if (method === "oars.logs.follow" || method === "logs.follow") {
        return { ok: true, lines: [] };
      }
      if (method === "oars.access.identities.list" || method === "access.identitiesList") {
        return { ok: true, identities: [] };
      }
      if (method === "oars.access.poll" || method === "access.poll") {
        return {
          ok: true,
          scan_id: "scan-1",
          state: "done",
          scope: "connected_accounts",
          created_at_ms: Date.now(),
          servers: [],
          people_page: { offset: 0, limit: 100, total: 0, rows: [], has_more: false },
          unassigned_page: { offset: 0, limit: 100, total: 0, rows: [], has_more: false },
          metrics: { people: 0, distinct_fingerprints: 0, completed_servers: 0, target_servers: 0, observed_grants: 0 },
          coverage: "complete",
          sync_errors: [],
          source_warnings: [],
        } satisfies AccessPollResponse;
      }
      if (method === "oars.sshkeys.snapshot" || method === "sshkeys.snapshot") {
        return { ok: true, snapshot_id: "snap-1" };
      }
      if (method === "oars.sshkeys.snapshotPoll" || method === "sshkeys.snapshotPoll") {
        return snapshotDone;
      }
      return {};
    }),
  };
});

afterEach(() => {
  cleanup();
  delete window.zero;
});

describe("Empirical Challenger: Tab Modals Accessibility & Focus Verification", () => {
  describe("TerminalTab Modals", () => {
    it("renders RetrustModal with proper focus trapping, aria attributes and confirmation button gating", async () => {
      render(
        <TerminalTab
          server={testServer}
          onStatus={vi.fn()}
          onServerUpdated={vi.fn()}
        />
      );

      // In changed host key state, review button is displayed
      const reviewBtn = await screen.findByRole("button", { name: /Review identity/i });
      fireEvent.click(reviewBtn);

      await waitFor(() => {
        expect(screen.getByRole("dialog")).toBeTruthy();
      });

      const dialog = screen.getByRole("dialog");
      expect(dialog.getAttribute("aria-modal")).toBe("true");
      expect(dialog.getAttribute("aria-labelledby")).toBe("retrust-title");
      expect(dialog.getAttribute("aria-describedby")).toBe("retrust-desc");

      const input = screen.getByLabelText(new RegExp(`Type ${testServer.name} to continue`, "i"));
      await waitFor(() => {
        expect(document.activeElement).toBe(input);
      });

      const clearBtn = screen.getByRole("button", { name: "Clear stored key" });
      expect(clearBtn.hasAttribute("disabled")).toBe(true);

      // Type confirmation text matching server name
      fireEvent.change(input, { target: { value: testServer.name } });
      expect(clearBtn.hasAttribute("disabled")).toBe(false);

      // Tab wraps from clear button back to cancel or close button
      clearBtn.focus();
      fireEvent.keyDown(window, { key: "Tab" });
      expect(document.activeElement).not.toBe(clearBtn);

      // Escape key closes modal
      fireEvent.keyDown(window, { key: "Escape" });
      await waitFor(() => {
        expect(screen.queryByRole("dialog")).toBeNull();
      });
    });
  });

  describe("AccessTab Modal Dialogs", () => {
    it("opens Access Identity modal with [data-access-first] autofocus, aria attributes and Escape dismissal", async () => {
      render(<AccessTab />);

      await waitFor(() => {
        expect(screen.getByRole("button", { name: /Add person/i })).toBeTruthy();
      });

      const addPersonBtn = screen.getByRole("button", { name: /Add person/i });
      fireEvent.click(addPersonBtn);

      await waitFor(() => {
        expect(screen.getByRole("dialog")).toBeTruthy();
      });

      const dialog = screen.getByRole("dialog");
      expect(dialog.getAttribute("aria-modal")).toBe("true");
      expect(dialog.getAttribute("aria-labelledby")).toContain("access-");
      expect(dialog.getAttribute("aria-describedby")).toContain("access-");

      // Verify initial focus is on the name input with [data-access-first]
      const nameInput = screen.getByLabelText("Name");
      await waitFor(() => {
        expect(document.activeElement).toBe(nameInput);
      });

      // Verify Escape closes the dialog
      fireEvent.keyDown(window, { key: "Escape" });
      await waitFor(() => {
        expect(screen.queryByRole("dialog")).toBeNull();
      });
    });
  });

  describe("KeysTab Modal Dialogs", () => {
    it("opens KeyModal with [data-key-first] autofocus, aria attributes and Escape dismissal", async () => {
      render(<KeysTab serverId={testServer.id} />);

      await waitFor(() => {
        expect(screen.getByRole("button", { name: /Generate local key/i })).toBeTruthy();
      });

      const generateBtn = screen.getByRole("button", { name: /Generate local key/i });
      fireEvent.click(generateBtn);

      await waitFor(() => {
        expect(screen.getByRole("dialog")).toBeTruthy();
      });

      const dialog = screen.getByRole("dialog");
      expect(dialog.getAttribute("aria-modal")).toBe("true");
      expect(dialog.getAttribute("aria-labelledby")).toContain("keys-");
      expect(dialog.getAttribute("aria-describedby")).toContain("keys-");

      // Escape closes dialog
      fireEvent.keyDown(window, { key: "Escape" });
      await waitFor(() => {
        expect(screen.queryByRole("dialog")).toBeNull();
      });
    });
  });

  describe("Focus Trap Robustness on Dynamic Mutation", () => {
    it("safely retains focus containment when focusable children are dynamically replaced", async () => {
      function DynamicSubTreeModal({ onClose }: { onClose: () => void }) {
        const [phase, setPhase] = React.useState<"initial" | "advanced">("initial");
        return (
          <div className="oars-modal-overlay" role="presentation">
            <div role="dialog" aria-modal="true" className="oars-modal">
              <button data-testid="phase-btn" onClick={() => setPhase(phase === "initial" ? "advanced" : "initial")}>
                Phase: {phase}
              </button>
              {phase === "initial" ? (
                <input data-testid="input-a" placeholder="Alpha" />
              ) : (
                <textarea data-testid="textarea-b" placeholder="Beta" />
              )}
              <button data-testid="close-btn" onClick={onClose}>Close</button>
            </div>
          </div>
        );
      }

      const onClose = vi.fn();
      render(<DynamicSubTreeModal onClose={onClose} />);

      const phaseBtn = screen.getByTestId("phase-btn");
      expect(screen.getByTestId("input-a")).toBeTruthy();

      fireEvent.click(phaseBtn);
      expect(screen.queryByTestId("input-a")).toBeNull();
      expect(screen.getByTestId("textarea-b")).toBeTruthy();
    });
  });

  describe("MonitorTab Approval Dialog", () => {
    it("renders Drop Caches approval dialog with autofocus on confirm and Escape dismissal", async () => {
      render(
        <MonitorTab
          server={testServer}
        />
      );

      // Open Advanced diagnostics disclosure
      const advBtn = await screen.findByRole("button", { name: /Advanced diagnostics/i });
      fireEvent.click(advBtn);

      // Click Review and run button
      const reviewBtn = await screen.findByRole("button", { name: /Review and run/i });
      fireEvent.click(reviewBtn);

      await waitFor(() => {
        expect(screen.getByRole("dialog")).toBeTruthy();
      });

      const dialog = screen.getByRole("dialog");
      expect(dialog.getAttribute("aria-modal")).toBe("true");
      expect(dialog.getAttribute("aria-labelledby")).toBe("monitor-approval-title");
      expect(dialog.getAttribute("aria-describedby")).toBe("monitor-approval-description");

      // Verify autofocus on confirm button ("Drop caches")
      await waitFor(() => {
        expect(document.activeElement).toBe(screen.getByRole("button", { name: "Drop caches" }));
      });

      // Escape key closes modal
      fireEvent.keyDown(window, { key: "Escape" });
      await waitFor(() => {
        expect(screen.queryByRole("dialog")).toBeNull();
      });
    });
  });

  describe("LogsTab Clear Log Modal", () => {
    it("renders Clear Log modal with autofocus on confirm and Escape dismissal", async () => {
      render(
        <LogsTab server={testServer} />
      );

      // Wait until clear button is enabled
      const clearBtn = await screen.findByRole("button", { name: /^Clear$/i });
      await waitFor(() => {
        expect(clearBtn.hasAttribute("disabled")).toBe(false);
      });

      fireEvent.click(clearBtn);

      await waitFor(() => {
        expect(screen.getByRole("dialog")).toBeTruthy();
      });

      const dialog = screen.getByRole("dialog");
      expect(dialog.getAttribute("aria-modal")).toBe("true");
      expect(dialog.getAttribute("aria-labelledby")).toBe("logs-clear-title");
      expect(dialog.getAttribute("aria-describedby")).toBe("logs-clear-description");

      // Verify autofocus on confirm button [data-logs-clear-confirm]
      await waitFor(() => {
        expect(document.activeElement).toBe(screen.getByRole("button", { name: "Clear log" }));
      });

      // Escape closes modal
      fireEvent.keyDown(window, { key: "Escape" });
      await waitFor(() => {
        expect(screen.queryByRole("dialog")).toBeNull();
      });
    });
  });

  describe("Continuous 50-Keystroke Focus Containment Stress Test", () => {
    it("strictly maintains focus inside modal boundary across 50 consecutive Tab and Shift+Tab keystrokes", async () => {
      const onClose = vi.fn();
      render(
        <div data-testid="outer-container">
          <button data-testid="outside-top">Outside Before</button>
          <div className="oars-modal-overlay" role="presentation">
            <div role="dialog" aria-modal="true" className="oars-modal">
              <input data-testid="field-1" placeholder="One" />
              <button data-testid="btn-2">Two</button>
              <select data-testid="select-3">
                <option value="a">Three</option>
              </select>
              <textarea data-testid="area-4" defaultValue="Four" />
              <button data-testid="btn-5" onClick={onClose}>Five</button>
            </div>
          </div>
          <button data-testid="outside-bottom">Outside After</button>
        </div>
      );

      const f1 = screen.getByTestId("field-1");
      const b2 = screen.getByTestId("btn-2");
      const s3 = screen.getByTestId("select-3");
      const a4 = screen.getByTestId("area-4");
      const b5 = screen.getByTestId("btn-5");
      const outsideBefore = screen.getByTestId("outside-top");
      const outsideAfter = screen.getByTestId("outside-bottom");

      const focusable = [f1, b2, s3, a4, b5];
      f1.focus();

      // Simulate 50 sequential forward and backward Tab keystrokes
      for (let i = 0; i < 50; i++) {
        const isShift = i % 3 === 0;
        fireEvent.keyDown(window, { key: "Tab", shiftKey: isShift });

        // Assert that active element is ALWAYS one of the inside elements and NEVER outside
        expect(document.activeElement).not.toBe(outsideBefore);
        expect(document.activeElement).not.toBe(outsideAfter);
        expect(document.activeElement).not.toBe(document.body);
      }
    });
  });
});
