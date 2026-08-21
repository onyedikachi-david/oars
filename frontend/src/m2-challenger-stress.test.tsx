// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, renderHook, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React, { useRef, useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Components & Hooks under test
import { CommandPalette, type CommandItem, type PaletteItem } from "./components/CommandPalette";
import { useRovingListNav } from "./components/useRovingListNav";
import { FileListView } from "./features/files/components/FileListView";
import { LocalListPane } from "./features/files/LocalListPane";
import { DeployListRail } from "./features/deploy/components/DeployListRail";
import { DeployOutputPane } from "./features/deploy/components/DeployOutputPane";
import { TransferDrawer } from "./features/files/TransferDrawer";
import { AccessTab } from "./AccessTab";
import { LogsTab } from "./LogsTab";
import { ScriptsTab } from "./ScriptsTab";

// Models & Types
import { emptySelection, selectionSelectOnly } from "./file-state";
import { ROOT, rpFromUtf8 } from "./sftp-path";
import type { AccessPollResponse, AccessScanResponse, DeployApp, LocalEntry, LogScanResult, SftpEntry, Script, Server } from "./types";

// Setup mocks for bridge
const bridgeMocks = vi.hoisted(() => ({
  scriptsList: vi.fn(),
  scriptsSave: vi.fn(),
  scriptsDelete: vi.fn(),
  scriptsRun: vi.fn(),
  scriptsValidate: vi.fn(),
  scriptsBroadcastPrepare: vi.fn(),
  scriptsBroadcast: vi.fn(),
  scriptsBroadcastPrepareCancel: vi.fn(),
  scriptsBroadcastPoll: vi.fn(),
  scriptsBroadcastCancel: vi.fn(),
  sshPoll: vi.fn(),
  sshCloseChannel: vi.fn(),
  logsScan: vi.fn(),
  logsRead: vi.fn(),
  logsFollow: vi.fn(),
  logsClear: vi.fn(),
  accessScan: vi.fn(),
  accessPoll: vi.fn(),
  accessScanCancel: vi.fn(),
  accessIdentitiesList: vi.fn(),
  accessIdentitiesSave: vi.fn(),
  accessExport: vi.fn(),
  sftpLs: vi.fn(),
}));

vi.mock("./bridge", () => ({
  BridgeError: class BridgeError extends Error {
    code: string;
    constructor(code: string, message: string) {
      super(message);
      this.code = code;
    }
  },
  api: {
    scripts: {
      list: bridgeMocks.scriptsList,
      save: bridgeMocks.scriptsSave,
      delete: bridgeMocks.scriptsDelete,
      run: bridgeMocks.scriptsRun,
      validate: bridgeMocks.scriptsValidate,
      broadcastPrepare: bridgeMocks.scriptsBroadcastPrepare,
      broadcast: bridgeMocks.scriptsBroadcast,
      broadcastPrepareCancel: bridgeMocks.scriptsBroadcastPrepareCancel,
      broadcastPoll: bridgeMocks.scriptsBroadcastPoll,
      broadcastCancel: bridgeMocks.scriptsBroadcastCancel,
    },
    ssh: {
      poll: bridgeMocks.sshPoll,
      closeChannel: bridgeMocks.sshCloseChannel,
    },
    logs: {
      scan: bridgeMocks.logsScan,
      read: bridgeMocks.logsRead,
      follow: bridgeMocks.logsFollow,
      clear: bridgeMocks.logsClear,
    },
    access: {
      scan: bridgeMocks.accessScan,
      poll: bridgeMocks.accessPoll,
      scanCancel: bridgeMocks.accessScanCancel,
      identitiesList: bridgeMocks.accessIdentitiesList,
      identitiesSave: bridgeMocks.accessIdentitiesSave,
      export: bridgeMocks.accessExport,
    },
    sftp: {
      ls: bridgeMocks.sftpLs,
    },
  },
}));

const mockServer: Server = {
  id: "srv-test-1",
  name: "Production Server",
  host: "prod.example.com",
  port: 22,
  user: "ubuntu",
  auth_method: "key",
  key_path: "~/.ssh/id_rsa",
  key_has_passphrase: false,
  host_fingerprint: null,
  group: "Web",
  tags: ["prod", "web"],
  via_server_id: null,
  created_at: 1000,
  updated_at: 1000,
};

describe("Milestone 2 Empirical Challenger Test Suite", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  // =========================================================================
  // 1. COMMAND PALETTE EMPIRICAL CHALLENGES
  // =========================================================================
  describe("1. Command Palette: Keyboard Navigation, A11y & Edge Cases", () => {
    const sampleCommands: CommandItem[] = [
      {
        id: "cmd-1",
        title: "Add Server",
        subtitle: "Register a new remote host",
        category: "Servers",
        keywords: ["ssh", "connect", "new"],
        run: vi.fn(),
      },
      {
        id: "cmd-2",
        title: "Deploy App",
        subtitle: "Execute build and release",
        category: "Deploy",
        keywords: ["release", "git", "build"],
        run: vi.fn(),
      },
      {
        id: "cmd-3",
        title: "View Logs",
        subtitle: "Stream server system logs",
        category: "Monitoring",
        keywords: ["syslog", "nginx", "tail"],
        run: vi.fn(),
      },
      {
        id: "cmd-4",
        title: "Scan Access",
        subtitle: "Audit authorized keys",
        category: "Security",
        keywords: ["keys", "audit", "compliance"],
        run: vi.fn(),
      },
    ];

    it("verifies strict WAI-ARIA combobox structure and synchronized aria-activedescendant", () => {
      const onClose = vi.fn();
      render(<CommandPalette commands={sampleCommands} onClose={onClose} />);

      const combobox = screen.getByRole("combobox");
      expect(combobox.getAttribute("aria-expanded")).toBe("true");
      expect(combobox.getAttribute("aria-haspopup")).toBe("listbox");
      expect(combobox.getAttribute("aria-autocomplete")).toBe("list");
      expect(combobox.getAttribute("aria-controls")).toBe("cmd-palette-listbox");
      expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-0");

      const listbox = screen.getByRole("listbox");
      expect(listbox.getAttribute("id")).toBe("cmd-palette-listbox");

      const options = screen.getAllByRole("option");
      expect(options).toHaveLength(4);
      options.forEach((opt, idx) => {
        expect(opt.getAttribute("id")).toBe(`cmd-palette-opt-${idx}`);
        expect(opt.getAttribute("aria-selected")).toBe(idx === 0 ? "true" : "false");
      });
    });

    it("tests full cyclic wrap-around: ArrowDown from last to first, ArrowUp from first to last", () => {
      const onClose = vi.fn();
      render(<CommandPalette commands={sampleCommands} onClose={onClose} />);

      const combobox = screen.getByRole("combobox");

      // 0 -> 1 -> 2 -> 3
      fireEvent.keyDown(combobox, { key: "ArrowDown" });
      expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-1");

      fireEvent.keyDown(combobox, { key: "ArrowDown" });
      expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-2");

      fireEvent.keyDown(combobox, { key: "ArrowDown" });
      expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-3");

      // Wrap around to 0
      fireEvent.keyDown(combobox, { key: "ArrowDown" });
      expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-0");

      // Wrap backward to 3
      fireEvent.keyDown(combobox, { key: "ArrowUp" });
      expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-3");

      // Backward 3 -> 2 -> 1 -> 0
      fireEvent.keyDown(combobox, { key: "ArrowUp" });
      expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-2");
      fireEvent.keyDown(combobox, { key: "ArrowUp" });
      expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-1");
      fireEvent.keyDown(combobox, { key: "ArrowUp" });
      expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-0");
    });

    it("tests Home and End keys for jumping directly to bounds", () => {
      const onClose = vi.fn();
      render(<CommandPalette commands={sampleCommands} onClose={onClose} />);

      const combobox = screen.getByRole("combobox");

      fireEvent.keyDown(combobox, { key: "End" });
      expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-3");
      expect(screen.getAllByRole("option")[3].getAttribute("aria-selected")).toBe("true");

      fireEvent.keyDown(combobox, { key: "Home" });
      expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-0");
      expect(screen.getAllByRole("option")[0].getAttribute("aria-selected")).toBe("true");
    });

    it("tests Enter key execution of the selected item and dismissal", () => {
      const onClose = vi.fn();
      render(<CommandPalette commands={sampleCommands} onClose={onClose} />);

      const combobox = screen.getByRole("combobox");

      // Navigate to cmd-3 (View Logs)
      fireEvent.keyDown(combobox, { key: "ArrowDown" });
      fireEvent.keyDown(combobox, { key: "ArrowDown" });
      expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-2");

      fireEvent.keyDown(combobox, { key: "Enter" });
      expect(sampleCommands[2].run).toHaveBeenCalledTimes(1);
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it("tests Escape key dismissal without executing any commands", () => {
      const onClose = vi.fn();
      render(<CommandPalette commands={sampleCommands} onClose={onClose} />);

      fireEvent.keyDown(window, { key: "Escape" });
      expect(onClose).toHaveBeenCalledTimes(1);
      sampleCommands.forEach((cmd) => {
        expect(cmd.run).not.toHaveBeenCalled();
      });
    });

    it("tests input filtering across title, subtitle, category, and keywords", () => {
      const onClose = vi.fn();
      render(<CommandPalette commands={sampleCommands} onClose={onClose} />);

      const combobox = screen.getByRole("combobox");

      // Match by keyword "syslog"
      fireEvent.change(combobox, { target: { value: "syslog" } });
      let options = screen.getAllByRole("option");
      expect(options).toHaveLength(1);
      expect(options[0].textContent).toContain("View Logs");

      // Match by subtitle "remote host"
      fireEvent.change(combobox, { target: { value: "remote host" } });
      options = screen.getAllByRole("option");
      expect(options).toHaveLength(1);
      expect(options[0].textContent).toContain("Add Server");

      // Match by category "Security"
      fireEvent.change(combobox, { target: { value: "security" } });
      options = screen.getAllByRole("option");
      expect(options).toHaveLength(1);
      expect(options[0].textContent).toContain("Scan Access");
    });

    it("stress-tests list shrinking: resets/clamps selectedIndex and updates aria-activedescendant", () => {
      const onClose = vi.fn();
      render(<CommandPalette commands={sampleCommands} onClose={onClose} />);

      const combobox = screen.getByRole("combobox");

      // Navigate to index 3 (last item)
      fireEvent.keyDown(combobox, { key: "End" });
      expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-3");

      // Filter query narrows list from 4 items down to 1 item ("deploy")
      fireEvent.change(combobox, { target: { value: "deploy" } });

      const options = screen.getAllByRole("option");
      expect(options).toHaveLength(1);
      expect(options[0].textContent).toContain("Deploy App");

      // Clamped/reset index to 0, ensuring aria-activedescendant is valid opt-0 (NOT opt-3)
      expect(combobox.getAttribute("aria-activedescendant")).toBe("cmd-palette-opt-0");
      expect(options[0].getAttribute("aria-selected")).toBe("true");
    });

    it("stress-tests empty query results: verifies role=status announcement and undefined active descendant", () => {
      const onClose = vi.fn();
      render(<CommandPalette commands={sampleCommands} onClose={onClose} />);

      const combobox = screen.getByRole("combobox");
      fireEvent.change(combobox, { target: { value: "xyz_nonexistent_command_12345" } });

      expect(screen.queryByRole("option")).toBeNull();
      const status = screen.getByRole("status");
      expect(status.textContent).toContain("No matching commands");
      expect(combobox.getAttribute("aria-activedescendant")).toBeNull();

      // Ensure pressing Enter or arrow keys on empty result does not crash or throw
      expect(() => {
        fireEvent.keyDown(combobox, { key: "Enter" });
        fireEvent.keyDown(combobox, { key: "ArrowDown" });
        fireEvent.keyDown(combobox, { key: "ArrowUp" });
        fireEvent.keyDown(combobox, { key: "Home" });
        fireEvent.keyDown(combobox, { key: "End" });
      }).not.toThrow();
      expect(onClose).not.toHaveBeenCalled();
    });

    it("stress-tests regex special characters in search input: does not crash on syntax chars", () => {
      const onClose = vi.fn();
      render(<CommandPalette commands={sampleCommands} onClose={onClose} />);

      const combobox = screen.getByRole("combobox");

      // Query with regex metacharacters: [ ] ( ) * + ? . \ ^ $
      expect(() => {
        fireEvent.change(combobox, { target: { value: "[.*+?^${}()|/]" } });
      }).not.toThrow();

      expect(screen.getByRole("status").textContent).toContain("No matching commands");
    });

    it("tests external items prop adapter mapping and execution", () => {
      const onClose = vi.fn();
      const mockAction = vi.fn();
      const paletteItems: PaletteItem[] = [
        { label: "Go to Dashboard", action: mockAction, group: "Navigation" },
        { label: "Switch to Dark Mode", action: mockAction, group: "Preferences" },
      ];

      render(<CommandPalette items={paletteItems} onClose={onClose} />);

      const options = screen.getAllByRole("option");
      expect(options).toHaveLength(2);
      expect(options[0].textContent).toContain("Go to Dashboard");
      expect(options[0].textContent).toContain("Navigation");

      fireEvent.click(options[0]);
      expect(mockAction).toHaveBeenCalledTimes(1);
      expect(onClose).toHaveBeenCalledTimes(1);
    });
  });

  // =========================================================================
  // 2. USE ROVING LIST NAV HOOK EMPIRICAL CHALLENGES
  // =========================================================================
  describe("2. useRovingListNav: Comprehensive State & Keyboard Matrix", () => {
    function TestRovingComponent({
      itemCount,
      initialIndex = 0,
      wrap = true,
      orientation = "vertical" as "vertical" | "horizontal" | "both",
      onSelect,
    }: {
      itemCount: number;
      initialIndex?: number;
      wrap?: boolean;
      orientation?: "vertical" | "horizontal" | "both";
      onSelect?: (index: number) => void;
    }) {
      const containerRef = useRef<HTMLDivElement>(null);
      const { focusedIndex, getItemProps, moveFocus, handleKeyDown } = useRovingListNav({
        itemCount,
        initialIndex,
        wrap,
        orientation,
        onSelect,
        containerRef,
      });

      return (
        <div ref={containerRef} role="listbox" aria-label="Roving test list">
          {Array.from({ length: itemCount }).map((_, i) => {
            const props = getItemProps(i);
            return (
              <button
                key={i}
                data-testid={`roving-item-${i}`}
                {...props}
              >
                Item {i}
              </button>
            );
          })}
        </div>
      );
    }

    it("verifies Single Tab Entrance rule: exactly ONE item has tabIndex=0, all N-1 have tabIndex=-1", () => {
      render(<TestRovingComponent itemCount={5} initialIndex={2} />);

      const items = screen.getAllByRole("option");
      expect(items).toHaveLength(5);

      const zeroTabIndexItems = items.filter((el) => el.getAttribute("tabindex") === "0");
      const minusOneTabIndexItems = items.filter((el) => el.getAttribute("tabindex") === "-1");

      expect(zeroTabIndexItems).toHaveLength(1);
      expect(minusOneTabIndexItems).toHaveLength(4);
      expect(items[2].getAttribute("tabindex")).toBe("0");
    });

    it("tests orientation=vertical: ignores ArrowLeft/ArrowRight, responds to ArrowUp/ArrowDown", () => {
      render(<TestRovingComponent itemCount={3} orientation="vertical" />);

      const item0 = screen.getByTestId("roving-item-0");
      const item1 = screen.getByTestId("roving-item-1");

      // Horizontal keys do nothing in vertical orientation
      fireEvent.keyDown(item0, { key: "ArrowRight" });
      expect(item0.getAttribute("tabindex")).toBe("0");
      expect(item1.getAttribute("tabindex")).toBe("-1");

      // Vertical keys move focus
      fireEvent.keyDown(item0, { key: "ArrowDown" });
      expect(item0.getAttribute("tabindex")).toBe("-1");
      expect(item1.getAttribute("tabindex")).toBe("0");
    });

    it("tests orientation=horizontal: ignores ArrowUp/ArrowDown, responds to ArrowLeft/ArrowRight", () => {
      render(<TestRovingComponent itemCount={3} orientation="horizontal" />);

      const item0 = screen.getByTestId("roving-item-0");
      const item1 = screen.getByTestId("roving-item-1");

      // Vertical keys do nothing in horizontal orientation
      fireEvent.keyDown(item0, { key: "ArrowDown" });
      expect(item0.getAttribute("tabindex")).toBe("0");
      expect(item1.getAttribute("tabindex")).toBe("-1");

      // Horizontal keys move focus
      fireEvent.keyDown(item0, { key: "ArrowRight" });
      expect(item0.getAttribute("tabindex")).toBe("-1");
      expect(item1.getAttribute("tabindex")).toBe("0");
    });

    it("tests boundary clamping when wrap=false", () => {
      render(<TestRovingComponent itemCount={3} wrap={false} />);

      const item0 = screen.getByTestId("roving-item-0");
      const item2 = screen.getByTestId("roving-item-2");

      // ArrowUp at top does not wrap to bottom
      fireEvent.keyDown(item0, { key: "ArrowUp" });
      expect(item0.getAttribute("tabindex")).toBe("0");

      // Navigate to end
      fireEvent.keyDown(item0, { key: "End" });
      expect(item2.getAttribute("tabindex")).toBe("0");

      // ArrowDown at bottom does not wrap to top
      fireEvent.keyDown(item2, { key: "ArrowDown" });
      expect(item2.getAttribute("tabindex")).toBe("0");
    });

    it("tests PageUp and PageDown keyboard navigation shortcuts", () => {
      render(<TestRovingComponent itemCount={10} initialIndex={5} />);

      const item5 = screen.getByTestId("roving-item-5");
      const item0 = screen.getByTestId("roving-item-0");
      const item9 = screen.getByTestId("roving-item-9");

      fireEvent.keyDown(item5, { key: "PageUp" });
      expect(item0.getAttribute("tabindex")).toBe("0");

      fireEvent.keyDown(item0, { key: "PageDown" });
      expect(item9.getAttribute("tabindex")).toBe("0");
    });

    it("tests onSelect trigger with both Enter and Space keys", () => {
      const onSelect = vi.fn();
      render(<TestRovingComponent itemCount={4} initialIndex={1} onSelect={onSelect} />);

      const item1 = screen.getByTestId("roving-item-1");

      fireEvent.keyDown(item1, { key: "Enter" });
      expect(onSelect).toHaveBeenCalledWith(1);

      fireEvent.keyDown(item1, { key: " " });
      expect(onSelect).toHaveBeenCalledWith(1);
      expect(onSelect).toHaveBeenCalledTimes(2);
    });

    it("stress-tests dynamic resizing: itemCount drops from 10 to 3 while focusedIndex=8", () => {
      const { rerender } = render(<TestRovingComponent itemCount={10} initialIndex={8} />);

      expect(screen.getByTestId("roving-item-8").getAttribute("tabindex")).toBe("0");

      // Rerender with only 3 items
      rerender(<TestRovingComponent itemCount={3} initialIndex={0} />);

      // Index 8 is now gone, focusedIndex must clamp to 2
      expect(screen.getByTestId("roving-item-2").getAttribute("tabindex")).toBe("0");
      expect(screen.getByTestId("roving-item-0").getAttribute("tabindex")).toBe("-1");
      expect(screen.getByTestId("roving-item-1").getAttribute("tabindex")).toBe("-1");
    });

    it("stress-tests empty list: itemCount=0 does not throw and focusedIndex is -1", () => {
      const { result } = renderHook(() => useRovingListNav({ itemCount: 0 }));
      expect(result.current.focusedIndex).toBe(-1);

      // Trigger key down on empty list
      expect(() => {
        result.current.handleKeyDown({
          key: "ArrowDown",
          preventDefault: vi.fn(),
        } as any);
      }).not.toThrow();
    });
  });

  // =========================================================================
  // 3. INTEGRATION ACROSS 5 LISTS & RAILS
  // =========================================================================
  describe("3. Roving Tabindex Across 5 Production Lists & Rails", () => {
    // 3.1 Remote File List
    it("Remote File List (FileListView): roving tabindex and keyboard navigation", () => {
      const entries: SftpEntry[] = [
        { name: rpFromUtf8("docs"), display: "docs", kind: "dir", size: 4096, mtime: 1000, mode: "drwxr-xr-x", uid: 1000, gid: 1000, link_target: null },
        { name: rpFromUtf8("app.js"), display: "app.js", kind: "file", size: 1024, mtime: 2000, mode: "-rw-r--r--", uid: 1000, gid: 1000, link_target: null },
        { name: rpFromUtf8("config.json"), display: "config.json", kind: "file", size: 512, mtime: 3000, mode: "-rw-r--r--", uid: 1000, gid: 1000, link_target: null },
      ];

      const dir = {
        serverId: "srv-1",
        path: ROOT,
        pathKey: "/",
        listing: { entries, truncated: false },
        loading: false,
        refreshing: false,
        error: null,
        loadedAt: Date.now(),
      };

      const onRowClick = vi.fn();
      const onRowKeyDown = vi.fn();
      const onOpenEntry = vi.fn();

      render(
        <FileListView
          dir={dir}
          selection={emptySelection()}
          sizes={new Map()}
          dropTarget={null}
          displayedEntries={entries}
          onClearError={vi.fn()}
          onRowClick={onRowClick}
          onRowKeyDown={onRowKeyDown}
          onOpenEntry={onOpenEntry}
          onSetDropTarget={vi.fn()}
          onDrop={vi.fn()}
        />
      );

      const rows = screen.getAllByRole("option");
      expect(rows).toHaveLength(3);

      // Exactly row 0 has tabIndex=0
      expect(rows[0].getAttribute("tabindex")).toBe("0");
      expect(rows[1].getAttribute("tabindex")).toBe("-1");
      expect(rows[2].getAttribute("tabindex")).toBe("-1");

      // ArrowDown shifts focus to row 1
      fireEvent.keyDown(rows[0], { key: "ArrowDown" });
      expect(rows[1].getAttribute("tabindex")).toBe("0");
      expect(rows[0].getAttribute("tabindex")).toBe("-1");

      // End key shifts focus to row 2
      fireEvent.keyDown(rows[1], { key: "End" });
      expect(rows[2].getAttribute("tabindex")).toBe("0");

      // Home key shifts focus back to row 0
      fireEvent.keyDown(rows[2], { key: "Home" });
      expect(rows[0].getAttribute("tabindex")).toBe("0");
    });

    // 3.2 Local File List
    it("Local File List (LocalListPane): roving tabindex and header kicker strong tag", () => {
      const localEntries: LocalEntry[] = [
        { name: "Projects", path: "/Users/dev/Projects", kind: "dir", size: 0, mtime: 1000 },
        { name: "package.json", path: "/Users/dev/package.json", kind: "file", size: 850, mtime: 2000 },
        { name: "README.md", path: "/Users/dev/README.md", kind: "file", size: 2100, mtime: 3000 },
      ];

      const onLoadLocal = vi.fn();
      const onToggleEntry = vi.fn();

      render(
        <LocalListPane
          local={{ path: "/Users/dev", entries: localEntries, loading: false, error: null, selected: [], truncated: false }}
          selectedLocalEntries={[]}
          onLoadLocal={onLoadLocal}
          onChooseFolder={vi.fn()}
          onToggleEntry={onToggleEntry}
          onRequestUpload={vi.fn()}
        />
      );

      // Verify header kicker alignment
      expect(screen.getByText("Local files").tagName).toBe("STRONG");

      const rows = screen.getAllByRole("option");
      expect(rows).toHaveLength(3);
      expect(rows[0].getAttribute("tabindex")).toBe("0");
      expect(rows[1].getAttribute("tabindex")).toBe("-1");
      expect(rows[2].getAttribute("tabindex")).toBe("-1");

      // ArrowDown shifts tabIndex
      fireEvent.keyDown(rows[0], { key: "ArrowDown" });
      expect(rows[1].getAttribute("tabindex")).toBe("0");

      // Enter on dir triggers onLoadLocal
      fireEvent.keyDown(rows[0], { key: "Enter" });
      expect(onLoadLocal).toHaveBeenCalledWith("/Users/dev/Projects");
    });

    // 3.3 Deploy Rail
    it("Deploy Rail (DeployListRail): roving tabindex, keyboard selection, and plus button", () => {
      const apps: DeployApp[] = [
        {
          id: "app-1",
          server_id: "srv-1",
          name: "API Service",
          folder: "/var/www/api",
          environment: "production",
          repo: { url: "https://github.com/org/api", transport: "https", branch: "main" },
          runtime: { node_version: "24", type: "node", package_manager: "npm", install: "npm ci", build: "npm run build", entry: "index.js", args: "", start_command: "", build_folder: "dist" },
          env_vars: [],
          domains: [],
          ssl: false,
          email: "",
          app_port: 3000,
          revision: 1,
          created_at_ms: 1000,
          updated_at_ms: 1000,
        },
        {
          id: "app-2",
          server_id: "srv-1",
          name: "Web Frontend",
          folder: "/var/www/web",
          environment: "production",
          repo: { url: "https://github.com/org/web", transport: "https", branch: "main" },
          runtime: { node_version: "24", type: "react", package_manager: "npm", install: "npm ci", build: "npm run build", entry: "", args: "", start_command: "", build_folder: "dist" },
          env_vars: [],
          domains: [],
          ssl: false,
          email: "",
          app_port: 3000,
          revision: 1,
          created_at_ms: 2000,
          updated_at_ms: 2000,
        },
      ];

      const onSelectApp = vi.fn();
      const onNewApp = vi.fn();

      render(
        <DeployListRail
          apps={apps}
          selectedId="app-1"
          loading={false}
          onSelectApp={onSelectApp}
          onNewApp={onNewApp}
          onRefresh={vi.fn()}
        />
      );

      const rows = screen.getAllByRole("option");
      expect(rows).toHaveLength(2);
      expect(rows[0].getAttribute("tabindex")).toBe("0");
      expect(rows[1].getAttribute("tabindex")).toBe("-1");

      // ArrowDown moves focus
      fireEvent.keyDown(rows[0], { key: "ArrowDown" });
      expect(rows[1].getAttribute("tabindex")).toBe("0");

      // Enter selects app
      fireEvent.keyDown(rows[1], { key: "Enter" });
      expect(onSelectApp).toHaveBeenCalledWith("app-2");
    });

    // 3.4 Scripts Rail
    it("Scripts Rail (ScriptsTab): roving tabindex across script library rows", async () => {
      const mockScripts: Script[] = [
        {
          id: "script-1",
          name: "Restart Nginx",
          description: "Reloads nginx configuration",
          tags: ["web"],
          color: "#2563eb",
          body: "systemctl reload nginx",
          variables: [],
          created_at: 1000,
          updated_at: 1000,
          run_count: 5,
          last_run_at: 2000,
        },
        {
          id: "script-2",
          name: "Flush Redis",
          description: "Clears cache databases",
          tags: ["db", "destructive"],
          color: "#dc2626",
          body: "redis-cli flushall",
          variables: [],
          created_at: 3000,
          updated_at: 3000,
          run_count: 2,
          last_run_at: 4000,
        },
      ];

      bridgeMocks.scriptsList.mockResolvedValue({ ok: true, scripts: mockScripts, recovery_error: null });

      render(
        <ScriptsTab
          serverId={mockServer.id}
          servers={[mockServer]}
          connected={true}
          statuses={new Map([[mockServer.id, "ready"]])}
        />
      );

      // Wait for script library listbox to render
      await waitFor(() => {
        expect(screen.getByRole("listbox", { name: "Script library" })).toBeTruthy();
      });

      const listbox = screen.getByRole("listbox", { name: "Script library" });
      const rows = within(listbox).getAllByRole("option");
      expect(rows).toHaveLength(2);
      expect(rows[0].getAttribute("tabindex")).toBe("0");
      expect(rows[1].getAttribute("tabindex")).toBe("-1");

      // ArrowDown navigates to script 2
      fireEvent.keyDown(rows[0], { key: "ArrowDown" });
      expect(rows[1].getAttribute("tabindex")).toBe("0");
    });

    // 3.5 Logs Rail
    it("Logs Rail (LogsTab): roving tabindex across multiple grouped sources", async () => {
      const mockSources = [
        { name: "syslog", path: "/var/log/syslog", group: "system", size: 10240, age_sec: 120, readable: true },
        { name: "auth.log", path: "/var/log/auth.log", group: "system", size: 5120, age_sec: 300, readable: true },
        { name: "nginx/access.log", path: "/var/log/nginx/access.log", group: "web", size: 524288, age_sec: 10, readable: true },
      ];

      bridgeMocks.logsScan.mockResolvedValue({ ok: true, status: "ready", sources: mockSources, cursor: "cur-1", truncated: false });
      bridgeMocks.logsRead.mockResolvedValue({ ok: true, lines: ["Log line 1", "Log line 2"], cursor: "cur-2", eof: false });

      render(<LogsTab server={mockServer} />);

      await waitFor(() => {
        expect(screen.getByRole("listbox", { name: "Log sources" })).toBeTruthy();
      });

      const listbox = screen.getByRole("listbox", { name: "Log sources" });
      const sourceButtons = within(listbox).getAllByRole("option");
      expect(sourceButtons).toHaveLength(3);

      // Exactly the first source has tabIndex=0
      expect(sourceButtons[0].getAttribute("tabindex")).toBe("0");
      expect(sourceButtons[1].getAttribute("tabindex")).toBe("-1");
      expect(sourceButtons[2].getAttribute("tabindex")).toBe("-1");

      // ArrowDown navigates through group 1 to group 2 seamlessly
      fireEvent.keyDown(sourceButtons[0], { key: "ArrowDown" });
      expect(sourceButtons[1].getAttribute("tabindex")).toBe("0");

      fireEvent.keyDown(sourceButtons[1], { key: "ArrowDown" });
      expect(sourceButtons[2].getAttribute("tabindex")).toBe("0");

      // End key jumps to last item
      fireEvent.keyDown(sourceButtons[0], { key: "End" });
      expect(sourceButtons[2].getAttribute("tabindex")).toBe("0");

      // Home key jumps back to first item
      fireEvent.keyDown(sourceButtons[2], { key: "Home" });
      expect(sourceButtons[0].getAttribute("tabindex")).toBe("0");
    });
  });

  // =========================================================================
  // 4. ARIA LIVE REGIONS & PROGRESS BARS
  // =========================================================================
  describe("4. ARIA Live Regions & Progress Bars Verification", () => {
    it("verifies Live Region on DeployOutputPane with role=log, aria-live=polite, tabIndex=0", () => {
      const steps = [
        { id: "s1", label: "Run migrations", state: "running" as const, exit: null, error: undefined },
      ];
      const outputs = {
        s1: "Migrating database tables...\nApplied migration 001_init.sql\nDone.",
      };

      render(
        <DeployOutputPane
          runId={101}
          runStatus="running"
          steps={steps}
          outputs={outputs}
          gaps={{}}
          onCancel={vi.fn()}
          onClose={vi.fn()}
        />
      );

      const logRegion = screen.getByRole("log");
      expect(logRegion.getAttribute("aria-live")).toBe("polite");
      expect(logRegion.getAttribute("aria-atomic")).toBe("false");
      expect(logRegion.getAttribute("tabindex")).toBe("0");
      expect(logRegion.getAttribute("aria-label")).toBe("Output for Run migrations");
      expect(logRegion.textContent).toContain("Applied migration 001_init.sql");
    });

    it("verifies Live Region on LogsTab body container with role=log and aria-live=polite", async () => {
      const mockSources = [
        { name: "syslog", path: "/var/log/syslog", group: "system", size: 1024, age_sec: 10, readable: true },
      ];

      bridgeMocks.logsScan.mockResolvedValue({ ok: true, status: "ready", sources: mockSources, cursor: "c1", truncated: false });
      bridgeMocks.logsRead.mockResolvedValue({ ok: true, lines: ["Aug 18 10:00:00 systemd[1]: Started nginx"], cursor: "c2", eof: true });

      render(<LogsTab server={mockServer} />);

      await waitFor(() => {
        const logBody = screen.getByRole("log");
        expect(logBody).toBeTruthy();
        expect(logBody.getAttribute("aria-live")).toBe("polite");
        expect(logBody.getAttribute("aria-atomic")).toBe("false");
        expect(logBody.getAttribute("tabindex")).toBe("0");
        expect(logBody.getAttribute("aria-label")).toBe("Log lines");
      });
    });

    it("verifies TransferDrawer progressbar values, valuetext, and cancel button accessibility", () => {
      const onCancelUpload = vi.fn();
      const onCancelTransfer = vi.fn();

      const rows = [
        {
          id: "tx-1",
          key: "upload-tx-1",
          label: "backup.tar.gz",
          path: "backup.tar.gz",
          kind: "upload",
          bytes: 4000,
          total: 10000,
          status: "running" as const,
          upload: { transferId: "tx-1" },
        },
        {
          id: "tx-2",
          key: "backend-tx-2",
          label: "export.csv",
          path: "export.csv",
          kind: "download",
          bytes: 0,
          total: 0,
          status: "queued" as const,
          backend: { id: "tx-2" },
        },
      ];

      render(
        <TransferDrawer
          rows={rows}
          onCancelUpload={onCancelUpload}
          onCancelTransfer={onCancelTransfer}
        />
      );

      const progressbars = screen.getAllByRole("progressbar");
      expect(progressbars).toHaveLength(2);

      // Running upload: 4000 / 10000 bytes = 40%
      expect(progressbars[0].getAttribute("aria-valuenow")).toBe("40");
      expect(progressbars[0].getAttribute("aria-valuemin")).toBe("0");
      expect(progressbars[0].getAttribute("aria-valuemax")).toBe("100");
      expect(progressbars[0].getAttribute("aria-label")).toBe("Transfer progress for backup.tar.gz");
      expect(progressbars[0].getAttribute("aria-valuetext")).toContain("40%");

      // Queued download with 0 bytes/total
      expect(progressbars[1].getAttribute("aria-valuenow")).toBe("0");
      expect(progressbars[1].getAttribute("aria-valuetext")).toBe("Pending");

      // Verify accessible cancel buttons
      const cancelUploadBtn = screen.getByLabelText("Cancel upload of backup.tar.gz");
      expect(cancelUploadBtn).toBeTruthy();
      fireEvent.click(cancelUploadBtn);
      expect(onCancelUpload).toHaveBeenCalled();

      const cancelTransferBtn = screen.getByLabelText("Cancel transfer of export.csv");
      expect(cancelTransferBtn).toBeTruthy();
      fireEvent.click(cancelTransferBtn);
      expect(onCancelTransfer).toHaveBeenCalled();
    });

    it("verifies AccessTab progressbar during fleet scanning with target server metrics", async () => {
      const activeScan: AccessPollResponse = {
        ok: true,
        scan_id: "scan-99",
        state: "scanning",
        created_at_ms: 1000,
        scope: "connected_accounts",
        coverage: "complete",
        sync_errors: [],
        source_warnings: [],
        metrics: {
          target_servers: 8,
          completed_servers: 3,
          distinct_fingerprints: 12,
          observed_grants: 24,
          people: 0,
        },
        people_page: { rows: [], total: 0, offset: 0, limit: 20, has_more: false },
        unassigned_page: { rows: [], total: 0, offset: 0, limit: 20, has_more: false },
        servers: [],
      };

      bridgeMocks.accessScan.mockResolvedValue({ ok: true, scan_id: "scan-99" });
      bridgeMocks.accessPoll.mockResolvedValue(activeScan);
      bridgeMocks.accessIdentitiesList.mockResolvedValue({ ok: true, identities: [], revision: 1 });

      render(<AccessTab />);

      // Trigger a scan
      const scanBtn = screen.getByRole("button", { name: /Scan fleet access/i });
      fireEvent.click(scanBtn);

      const confirmBtn = screen.getByRole("button", { name: "Start scan" });
      fireEvent.click(confirmBtn);

      await waitFor(() => {
        const progressbar = screen.getByRole("progressbar");
        expect(progressbar).toBeTruthy();
        expect(progressbar.getAttribute("aria-valuemin")).toBe("0");
        expect(progressbar.getAttribute("aria-valuemax")).toBe("8");
        expect(progressbar.getAttribute("aria-valuenow")).toBe("3");
        expect(progressbar.getAttribute("aria-label")).toBe("Fleet access scan progress");
        expect(progressbar.getAttribute("aria-valuetext")).toBe("Scanning 3 of 8 servers");
      });
    });
  });
});
