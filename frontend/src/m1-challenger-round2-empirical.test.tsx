// @vitest-environment jsdom

import { act, cleanup, render, renderHook, screen, waitFor } from "@testing-library/react";
import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { vault } from "./bridge";
import { DeployTab } from "./DeployTab";
import { FilesTab } from "./FilesTab";
import { useDeployEditor } from "./features/deploy/hooks/useDeployEditor";
import { useFileEditor } from "./features/files/hooks/useFileEditor";
import { useFileOperations } from "./features/files/hooks/useFileOperations";
import { ROOT, rpFromUtf8 } from "./sftp-path";
import type { DeployApp, SftpEntry } from "./types";

const mockZeroInvoke = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
  window.zero = {
    invoke: mockZeroInvoke,
  };
  vault.clearCache();
});

afterEach(() => {
  cleanup();
  delete window.zero;
  vault.clearCache();
});

describe("Empirical Challenger Round 2: Adversarial Deep-Dive", () => {
  describe("A. useFileOperations & Edge Cases", () => {
    it("handles createFolder, rename, chmod, delete, and unzip mutations with refresh", async () => {
      const mockRefresh = vi.fn();
      const mockSetDialog = vi.fn();
      const mockSetSelection = vi.fn();
      const mockWatchTransfer = vi.fn();

      mockZeroInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === "oars.sftp.mkdir") return { ok: true };
        if (cmd === "oars.sftp.rename") return { ok: true };
        if (cmd === "oars.sftp.chmod") return { ok: true };
        if (cmd === "oars.sftp.rm") return { ok: true };
        if (cmd === "oars.sftp.unzip") return { ok: true, op_id: 1234 };
        return { ok: true };
      });

      const { result } = renderHook(() =>
        useFileOperations({
          serverId: "srv-ops",
          dirPath: ROOT,
          refreshAfterMutation: mockRefresh,
          watchTransfer: mockWatchTransfer,
          setDialog: mockSetDialog,
          setSelection: mockSetSelection,
        })
      );

      const targetEntry: SftpEntry = {
        name: rpFromUtf8("item.txt"),
        display: "item.txt",
        kind: "file",
        size: 100,
        mtime: 1,
        mode: "0644",
        uid: 1,
        gid: 1,
        link_target: null,
      };

      // 1. doMkdir
      await act(async () => {
        await result.current.doMkdir("new_folder");
      });
      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.mkdir", {
        server_id: "srv-ops",
        path: expect.anything(),
      });
      expect(mockRefresh).toHaveBeenCalledWith(ROOT);
      expect(mockSetDialog).toHaveBeenCalledWith(null);

      // 2. doRename
      await act(async () => {
        await result.current.doRename(targetEntry, "renamed.txt");
      });
      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.rename", {
        server_id: "srv-ops",
        from: expect.anything(),
        to: expect.anything(),
      });

      // 3. doChmod
      await act(async () => {
        await result.current.doChmod(targetEntry, 0o755);
      });
      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.chmod", {
        server_id: "srv-ops",
        path: expect.anything(),
        mode: 0o755,
      });

      // 4. doDelete
      await act(async () => {
        await result.current.doDelete([targetEntry], false);
      });
      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.rm", {
        server_id: "srv-ops",
        path: expect.anything(),
        recursive: false,
      });

      // 5. doUnzip
      const zipEntry: SftpEntry = {
        ...targetEntry,
        name: rpFromUtf8("archive.zip"),
        display: "archive.zip",
      };
      await act(async () => {
        await result.current.doUnzip(zipEntry);
      });
      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.unzip", {
        server_id: "srv-ops",
        zip_path: expect.anything(),
        dest_dir: expect.anything(),
        overwrite: false,
      });
      expect(mockWatchTransfer).toHaveBeenCalledWith(1234);
    });
  });

  describe("B. useFileEditor Optimistic Concurrency & Multi-request safety", () => {
    it("handles fast rapid switching of opened files without clobbering editor content", async () => {
      let resolveFile1!: (val: any) => void;
      const file1Promise = new Promise((res) => {
        resolveFile1 = res;
      });

      mockZeroInvoke.mockImplementation(async (cmd: string, payload: any) => {
        if (cmd === "oars.sftp.read") {
          const pathStr = JSON.stringify(payload.path);
          if (pathStr.includes("file1")) return file1Promise;
          return {
            ok: true,
            base64: btoa("File 2 Content"),
            eof: true,
          };
        }
        return { ok: true };
      });

      const { result } = renderHook(() =>
        useFileEditor({
          serverId: "srv-edit",
          onRefreshAfterMutation: vi.fn(),
        })
      );

      const entry1: SftpEntry = {
        name: rpFromUtf8("file1.txt"),
        display: "file1.txt",
        kind: "file",
        size: 50,
        mtime: 1,
        mode: "0644",
        uid: 1,
        gid: 1,
        link_target: null,
      };

      const entry2: SftpEntry = {
        name: rpFromUtf8("file2.txt"),
        display: "file2.txt",
        kind: "file",
        size: 50,
        mtime: 1,
        mode: "0644",
        uid: 1,
        gid: 1,
        link_target: null,
      };

      // Open file 1 (pending)
      act(() => {
        void result.current.openEditor(entry1, entry1.name);
      });
      expect(result.current.editor?.phase).toBe("loading");
      expect(result.current.editor?.display).toBe("file1.txt");

      // Quickly open file 2 (resolves immediately)
      await act(async () => {
        await result.current.openEditor(entry2, entry2.name);
      });
      expect(result.current.editor?.phase).toBe("editing");
      expect(result.current.editor?.content).toBe("File 2 Content");

      // Old file 1 finally arrives
      await act(async () => {
        resolveFile1({
          ok: true,
          base64: btoa("Stale File 1 Content"),
          eof: true,
        });
      });

      // Editor must retain file 2 content
      expect(result.current.editor?.display).toBe("file2.txt");
      expect(result.current.editor?.content).toBe("File 2 Content");
    });
  });

  describe("C. useDeployEditor Rollback & Fault Tolerance", () => {
    const sampleApp: DeployApp = {
      id: "app-rollback",
      server_id: "srv-rb",
      name: "Rollback Test",
      environment: "staging",
      folder: "/var/www/rb",
      repo: { url: "git@github.com:test/rb.git", branch: "main", transport: "ssh" },
      runtime: {
        node_version: "22",
        type: "node",
        package_manager: "npm",
        install: "npm install",
        build: "",
        entry: "server.js",
        args: "",
        start_command: "node server.js",
        build_folder: "",
      },
      env_vars: [
        { name: "OLD_SECRET", secret: true, value: "••••", has_value: true },
        { name: "PUBLIC_VAR", secret: false, value: "hello", has_value: true },
      ],
      domains: ["staging.example.com"],
      ssl: false,
      email: "",
      app_port: 4000,
      revision: 1,
      created_at_ms: 0,
      updated_at_ms: 0,
    };

    it("restores original state in vault and deploy API if saving secrets fails mid-way", async () => {
      // Seed vault with old secret
      mockZeroInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === "native-sdk.credentials.get") {
          return "old-secret-value";
        }
        if (cmd === "oars.deploy.apps.save") {
          return { ok: true, app: { ...sampleApp, revision: 2 } };
        }
        if (cmd === "native-sdk.credentials.set") {
          throw new Error("Vault storage failure");
        }
        return { ok: true };
      });

      const mockOnSaved = vi.fn();
      const mockOnError = vi.fn();

      const { result } = renderHook(() =>
        useDeployEditor("srv-rb", mockOnSaved, mockOnError)
      );

      act(() => {
        result.current.openEditor(sampleApp);
      });

      // Modify secret
      act(() => {
        if (result.current.editor) {
          result.current.setEditor({
            ...result.current.editor,
            env_vars: [
              { name: "OLD_SECRET", secret: true, value: "new-secret-value", has_value: true },
              { name: "PUBLIC_VAR", secret: false, value: "hello", has_value: true },
            ],
          });
        }
      });

      await act(async () => {
        await result.current.saveEditor();
      });

      expect(mockOnError).toHaveBeenCalledWith("Vault storage failure");
      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.deploy.apps.save", { app: sampleApp });
      expect(mockOnSaved).not.toHaveBeenCalled();
    });
  });

  describe("D. Full Component Tree Render & Lifecycle Integrity", () => {
    it("mounts FilesTab tree with all sub-panes and handles unmount cleanly", async () => {
      mockZeroInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === "oars.sftp.ls") return { ok: true, entries: [], truncated: false };
        if (cmd === "oars.sftp.poll") return { ok: true, transfers: [] };
        if (cmd === "oars.local.ls") return { ok: true, entries: [], truncated: false };
        return { ok: true };
      });

      const { container, unmount } = render(<FilesTab serverId="srv-mount-test" />);
      expect(container.querySelector(".fs-workspace")).toBeDefined();
      expect(screen.getByText(/Remote/)).toBeDefined();
      expect(screen.getByText(/Local/)).toBeDefined();

      expect(() => unmount()).not.toThrow();
    });

    it("mounts DeployTab tree with rail, detail, inspector and handles unmount cleanly", async () => {
      const sampleApps: DeployApp[] = [
        {
          id: "app-full",
          server_id: "srv-full",
          name: "Production App",
          environment: "production",
          folder: "/var/www/prod",
          repo: { url: "git@github.com:org/prod.git", branch: "main", transport: "ssh" },
          runtime: {
            node_version: "24",
            type: "next",
            package_manager: "npm",
            install: "npm install",
            build: "npm run build",
            entry: "",
            args: "",
            start_command: "npm start",
            build_folder: ".next",
          },
          env_vars: [],
          domains: ["prod.example.com"],
          ssl: true,
          email: "ops@example.com",
          app_port: 3000,
          revision: 1,
          created_at_ms: 0,
          updated_at_ms: 0,
        },
      ];

      mockZeroInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === "oars.deploy.apps.list") return { ok: true, apps: sampleApps };
        if (cmd === "oars.deploy.history") return { ok: true, runs: [] };
        return { ok: true };
      });

      const { container, unmount } = render(<DeployTab serverId="srv-full" />);
      await waitFor(() => expect(screen.getAllByText("Production App").length).toBeGreaterThan(0));
      expect(container.querySelector(".deploy-workspace")).toBeDefined();

      expect(() => unmount()).not.toThrow();
    });
  });
});
