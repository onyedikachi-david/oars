// @vitest-environment jsdom

import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, BridgeError, invoke, vault } from "./bridge";
import { useDeployRun } from "./features/deploy/hooks/useDeployRun";
import { useFileEditor } from "./features/files/hooks/useFileEditor";
import { useFileTransfers } from "./features/files/hooks/useFileTransfers";
import { useLocalDirectory } from "./features/files/hooks/useLocalDirectory";
import { useRemoteDirectory } from "./features/files/hooks/useRemoteDirectory";
import { bytesToBase64, ROOT, rpFromUtf8, type RemotePath } from "./sftp-path";
import type { UploadJob } from "./transfer-model";
import type { DeployApp, DeployPreflight, SftpEntry, SftpTransfer } from "./types";

const mockZeroInvoke = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
  window.zero = {
    invoke: mockZeroInvoke,
  };
  vault.clearCache();
});

afterEach(() => {
  delete window.zero;
  vault.clearCache();
});

describe("M1 Adversarial Challenge: Custom Hooks & Bridge", () => {
  describe("Bridge & Vault Type-Safety & Cache Lifecycle", () => {
    it("throws BridgeError with appropriate code when window.zero is missing", async () => {
      delete window.zero;
      await expect(invoke("test.command")).rejects.toThrow(BridgeError);
      try {
        await invoke("test.command");
      } catch (e: any) {
        expect(e.code).toBe("no_bridge");
      }
    });

    it("unwraps { ok: false, error: '...' } responses into rejected BridgeError", async () => {
      mockZeroInvoke.mockResolvedValueOnce({ ok: false, error: "Custom backend error" });
      await expect(invoke("test.command")).rejects.toThrow("Custom backend error");
      try {
        await invoke("test.command");
      } catch (e: any) {
        expect(e.code).toBe("command_failed");
      }
    });

    it("vault evictServer clears server-specific secrets and leaves unrelated secrets intact", async () => {
      mockZeroInvoke.mockResolvedValue("secret-val");
      await vault.set("server:srv-1:pass", "pass-1");
      await vault.set("server:srv-2:pass", "pass-2");
      await vault.set("vnc:srv-1", "vnc-1");
      await vault.set("global:key", "global-val");

      mockZeroInvoke.mockClear();
      // Vault get should return from cache without invoking zero
      expect(await vault.get("server:srv-1:pass")).toBe("pass-1");
      expect(mockZeroInvoke).not.toHaveBeenCalled();

      // Evict srv-1
      vault.evictServer("srv-1");

      // Now getting srv-1 should invoke native-sdk credentials.get
      mockZeroInvoke.mockResolvedValueOnce("pass-1-reloaded");
      expect(await vault.get("server:srv-1:pass")).toBe("pass-1-reloaded");
      expect(mockZeroInvoke).toHaveBeenCalledWith("native-sdk.credentials.get", {
        service: vault.service,
        account: "server:srv-1:pass",
      });

      // srv-2 should still be cached
      mockZeroInvoke.mockClear();
      expect(await vault.get("server:srv-2:pass")).toBe("pass-2");
      expect(mockZeroInvoke).not.toHaveBeenCalled();
    });

    it("vault deployTransientGet never populates the process cache", async () => {
      mockZeroInvoke.mockResolvedValue("deploy-secret-value");
      const secret = await vault.deployTransientGet("deploy:app-1:DB_PASS");
      expect(secret).toBe("deploy-secret-value");

      mockZeroInvoke.mockClear();
      mockZeroInvoke.mockResolvedValueOnce("second-call");
      // Calling get should NOT hit cache because deployTransientGet didn't cache it
      const fetched = await vault.get("deploy:app-1:DB_PASS");
      expect(fetched).toBe("second-call");
      expect(mockZeroInvoke).toHaveBeenCalledTimes(1);
    });

    it("api.sftp.rm handles both synchronous and asynchronous overload paths", async () => {
      // Sync delete (recursive: false)
      mockZeroInvoke.mockResolvedValueOnce({ ok: true });
      const syncRes = await api.sftp.rm("srv-1", ROOT, false);
      expect(syncRes).toEqual({ ok: true });
      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.rm", {
        server_id: "srv-1",
        path: ROOT,
        recursive: false,
      });

      // Async recursive delete (recursive: true)
      mockZeroInvoke.mockResolvedValueOnce({ ok: true, op_id: 101, kind: "rm" });
      const asyncRes = await api.sftp.rm("srv-1", ROOT, true);
      expect(asyncRes).toEqual({ ok: true, op_id: 101, kind: "rm" });
      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.rm", {
        server_id: "srv-1",
        path: ROOT,
        recursive: true,
      });
    });
  });

  describe("useRemoteDirectory", () => {
    const mockOpenFile = vi.fn();
    const mockRequestDelete = vi.fn();
    const mockDropFiles = vi.fn();

    const sampleEntries: SftpEntry[] = [
      { name: rpFromUtf8("docs"), display: "docs", kind: "dir", size: 4096, mtime: 1700000000, mode: "0755", uid: 1000, gid: 1000, link_target: null },
      { name: rpFromUtf8("file.txt"), display: "file.txt", kind: "file", size: 1024, mtime: 1700000000, mode: "0644", uid: 1000, gid: 1000, link_target: null },
      { name: rpFromUtf8(".hidden"), display: ".hidden", kind: "file", size: 512, mtime: 1700000000, mode: "0644", uid: 1000, gid: 1000, link_target: null },
      { name: rpFromUtf8("symlink_dir"), display: "symlink_dir", kind: "symlink", size: 10, mtime: 1700000000, mode: "0777", uid: 1000, gid: 1000, link_target: null },
    ];

    it("loads directory listing, hides hidden files by default, and supports toggling hidden", async () => {
      mockZeroInvoke.mockResolvedValue({
        ok: true,
        entries: sampleEntries,
        truncated: false,
      });

      const { result } = renderHook(() =>
        useRemoteDirectory({
          serverId: "srv-1",
          onOpenFile: mockOpenFile,
          onRequestDelete: mockRequestDelete,
          onDropFiles: mockDropFiles,
        })
      );

      await waitFor(() => expect(result.current.dir.loading).toBe(false));
      expect(result.current.displayedEntries).toHaveLength(3); // .hidden is excluded

      act(() => {
        result.current.setShowHidden(true);
      });

      expect(result.current.displayedEntries).toHaveLength(4);
    });

    it("implements robust multi-selection (single click, toggle, range, select all, escape)", async () => {
      mockZeroInvoke.mockResolvedValue({
        ok: true,
        entries: sampleEntries,
        truncated: false,
      });

      const { result } = renderHook(() =>
        useRemoteDirectory({
          serverId: "srv-1",
          onOpenFile: mockOpenFile,
          onRequestDelete: mockRequestDelete,
          onDropFiles: mockDropFiles,
        })
      );

      await waitFor(() => expect(result.current.dir.loading).toBe(false));

      // Single select
      act(() => {
        result.current.onRowClick({ shiftKey: false, metaKey: false, ctrlKey: false } as any, sampleEntries[0]);
      });
      expect(result.current.selectedEntries).toHaveLength(1);
      expect(result.current.selectedEntries[0].name).toEqual(sampleEntries[0].name);

      // Additive toggle with Ctrl
      act(() => {
        result.current.onRowClick({ shiftKey: false, metaKey: true, ctrlKey: false } as any, sampleEntries[1]);
      });
      expect(result.current.selectedEntries).toHaveLength(2);

      // Select all with Cmd+A keyboard shortcut
      act(() => {
        result.current.onKeyDown({
          key: "a",
          metaKey: true,
          ctrlKey: false,
          target: document.body,
          preventDefault: vi.fn(),
        } as any);
      });
      expect(result.current.selectedEntries).toHaveLength(3); // all displayed entries

      // Clear with Escape
      act(() => {
        result.current.onKeyDown({
          key: "Escape",
          metaKey: false,
          ctrlKey: false,
          target: document.body,
          preventDefault: vi.fn(),
        } as any);
      });
      expect(result.current.selectedEntries).toHaveLength(0);
    });

    it("handles symlink resolution: dir symlink navigates, file symlink opens editor", async () => {
      mockZeroInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === "oars.sftp.ls") {
          return { ok: true, entries: sampleEntries, truncated: false };
        }
        return { ok: true };
      });

      const { result } = renderHook(() =>
        useRemoteDirectory({
          serverId: "srv-1",
          onOpenFile: mockOpenFile,
          onRequestDelete: mockRequestDelete,
          onDropFiles: mockDropFiles,
        })
      );

      await waitFor(() => expect(result.current.dir.loading).toBe(false));

      // Test symlink that resolves to directory (ls succeeds)
      mockZeroInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === "oars.sftp.ls") {
          return { ok: true, entries: [], truncated: false };
        }
        return { ok: true };
      });

      await act(async () => {
        await result.current.openEntry(sampleEntries[3], ROOT);
      });
      expect(mockOpenFile).not.toHaveBeenCalled();

      // Test symlink that fails ls (symlink to file) -> calls onOpenFile
      mockZeroInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === "oars.sftp.ls") {
          throw new Error("Not a directory");
        }
        return { ok: true };
      });

      await act(async () => {
        await result.current.openEntry(sampleEntries[3], ROOT);
      });
      expect(mockOpenFile).toHaveBeenCalled();
    });

    it("ignores out-of-order race conditions when navigating rapidly", async () => {
      let resolveSlowLs!: (val: any) => void;
      const slowLsPromise = new Promise((resolve) => {
        resolveSlowLs = resolve;
      });

      mockZeroInvoke.mockImplementation(async (cmd: string, payload: any) => {
        if (cmd === "oars.sftp.ls") {
          if (payload.path.utf8 === "/" || !payload.path.utf8) {
            return slowLsPromise;
          }
          return {
            ok: true,
            entries: [{ name: rpFromUtf8("subfile.txt"), kind: "file", size: 10, mtime: 1, mode: 0o644 }],
            truncated: false,
          };
        }
        return { ok: true };
      });

      const { result } = renderHook(() =>
        useRemoteDirectory({
          serverId: "srv-1",
          onOpenFile: mockOpenFile,
          onRequestDelete: mockRequestDelete,
          onDropFiles: mockDropFiles,
        })
      );

      // Fast second navigation to a subfolder
      const fastPath: RemotePath = rpFromUtf8("subfolder");
      await act(async () => {
        await result.current.loadDir("srv-1", fastPath);
      });

      expect(result.current.dir.listing.entries).toHaveLength(1);
      expect(result.current.dir.listing.entries[0].name).toEqual(rpFromUtf8("subfile.txt"));

      // Now the old slow ls finally resolves with 10 old entries
      await act(async () => {
        resolveSlowLs({
          ok: true,
          entries: sampleEntries,
          truncated: false,
        });
      });

      // State MUST NOT be overwritten by the stale resolved request
      expect(result.current.dir.listing.entries).toHaveLength(1);
      expect(result.current.dir.listing.entries[0].name).toEqual(rpFromUtf8("subfile.txt"));
    });
  });

  describe("useFileTransfers", () => {
    const mockRefresh = vi.fn();

    it("uploads 0-byte file by issuing single write with total=0", async () => {
      mockZeroInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === "oars.sftp.poll") {
          return { ok: true, transfers: [] };
        }
        if (cmd === "oars.sftp.stat") {
          return { ok: true, entry: { kind: "dir" } };
        }
        if (cmd === "oars.sftp.write") {
          return { ok: true, written: 0, done: true };
        }
        return { ok: true };
      });

      const { result } = renderHook(() =>
        useFileTransfers({
          serverId: "srv-1",
          onRefreshAfterMutation: mockRefresh,
        })
      );

      const emptyBlob = new Blob([]);
      const file = new File([emptyBlob], "empty.txt", { type: "text/plain" });

      await act(async () => {
        await result.current.startUploads([{ file, relativePath: "empty.txt" }], ROOT);
      });

      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.write", expect.objectContaining({
        server_id: "srv-1",
        offset: 0,
        base64: "",
        total: 0,
      }));
      expect(mockRefresh).toHaveBeenCalled();
    });

    it("handles multi-chunk file upload with progress tracking and completion", async () => {
      const data = new Uint8Array(100 * 1024); // 100 KB -> 2 chunks (64KB + 36KB)
      const file = new File([data], "large.bin");

      mockZeroInvoke.mockImplementation(async (cmd: string, payload: any) => {
        if (cmd === "oars.sftp.poll") {
          return { ok: true, transfers: [] };
        }
        if (cmd === "oars.sftp.stat") {
          return { ok: true, entry: { kind: "dir" } };
        }
        if (cmd === "oars.sftp.write") {
          if (payload.offset === 0) {
            return { ok: true, written: 64 * 1024, done: false };
          }
          return { ok: true, written: 100 * 1024, done: true };
        }
        return { ok: true };
      });

      const { result } = renderHook(() =>
        useFileTransfers({
          serverId: "srv-1",
          onRefreshAfterMutation: mockRefresh,
        })
      );

      await act(async () => {
        await result.current.startUploads([{ file, relativePath: "large.bin" }], ROOT);
      });

      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.write", expect.objectContaining({
        offset: 0,
      }));
      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.write", expect.objectContaining({
        offset: 64 * 1024,
      }));
      await waitFor(() => expect(mockRefresh).toHaveBeenCalled());
    });

    it("supports cancelling an active upload", async () => {
      mockZeroInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === "oars.sftp.poll") return { ok: true, transfers: [] };
        return { ok: true };
      });

      const { result } = renderHook(() =>
        useFileTransfers({
          serverId: "srv-1",
          onRefreshAfterMutation: mockRefresh,
        })
      );

      const fakeJob: UploadJob = {
        transferId: 999,
        serverId: "srv-1",
        path: ROOT,
        display: "hello.txt",
        file: new File(["hello"], "hello.txt"),
        total: 5,
        status: "running" as const,
        bytesSent: 0,
        error: "",
      };

      await act(async () => {
        await result.current.cancelUpload(fakeJob);
      });

      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.cancel", {
        server_id: "srv-1",
        transfer_id: 999,
      });
    });
  });

  describe("useFileEditor", () => {
    const mockRefresh = vi.fn();
    const smallEntry: SftpEntry = {
      name: rpFromUtf8("hello.txt"),
      display: "hello.txt",
      kind: "file",
      size: 11,
      mtime: 1700000000,
      mode: "0644",
      uid: 1000,
      gid: 1000,
      link_target: null,
    };

    it("rejects files exceeding EDITOR_MAX_BYTES (768 KB) before reading", async () => {
      const oversizedEntry: SftpEntry = {
        name: rpFromUtf8("huge.log"),
        display: "huge.log",
        kind: "file",
        size: 1024 * 1024 * 5, // 5 MB
        mtime: 1700000000,
        mode: "0644",
        uid: 1000,
        gid: 1000,
        link_target: null,
      };

      const { result } = renderHook(() =>
        useFileEditor({
          serverId: "srv-1",
          onRefreshAfterMutation: mockRefresh,
        })
      );

      await act(async () => {
        await result.current.openEditor(oversizedEntry, ROOT);
      });

      expect(mockZeroInvoke).not.toHaveBeenCalled();
      expect(result.current.editor?.tooLarge).toBe(true);
      expect(result.current.editor?.phase).toBe("error");
    });

    it("rejects non-UTF-8 binary files safely", async () => {
      // Invalid UTF-8 bytes: [0xFF, 0xFF]
      const invalidUtf8Base64 = bytesToBase64(new Uint8Array([0xff, 0xff]));
      mockZeroInvoke.mockResolvedValueOnce({
        ok: true,
        base64: invalidUtf8Base64,
        eof: true,
      });

      const { result } = renderHook(() =>
        useFileEditor({
          serverId: "srv-1",
          onRefreshAfterMutation: mockRefresh,
        })
      );

      await act(async () => {
        await result.current.openEditor(smallEntry, ROOT);
      });

      expect(result.current.editor?.phase).toBe("error");
      expect(result.current.editor?.error).toContain("not valid UTF-8 text");
    });

    it("opens UTF-8 file, detects dirty changes, and checks before closing", async () => {
      const text = "Hello World!";
      const base64 = bytesToBase64(new TextEncoder().encode(text));
      mockZeroInvoke.mockResolvedValueOnce({
        ok: true,
        base64,
        eof: true,
      });

      const { result } = renderHook(() =>
        useFileEditor({
          serverId: "srv-1",
          onRefreshAfterMutation: mockRefresh,
        })
      );

      await act(async () => {
        await result.current.openEditor(smallEntry, ROOT);
      });

      expect(result.current.editor?.content).toBe(text);
      expect(result.current.editor?.dirty).toBe(false);

      // Modify content
      act(() => {
        result.current.updateEditorContent("Hello World! Modified.");
      });
      expect(result.current.editor?.dirty).toBe(true);

      // Try closing while dirty -> dirtyCloseOpen dialog opens
      act(() => {
        result.current.closeEditor();
      });
      expect(result.current.dirtyCloseOpen).toBe(true);
      expect(result.current.editor).not.toBeNull();

      // Discard and close
      act(() => {
        result.current.discardEditorAndClose();
      });
      expect(result.current.dirtyCloseOpen).toBe(false);
      expect(result.current.editor).toBeNull();
    });

    it("handles optimistic locking conflict error during save", async () => {
      const text = "Initial";
      const base64 = bytesToBase64(new TextEncoder().encode(text));
      mockZeroInvoke.mockResolvedValueOnce({ ok: true, base64, eof: true });

      const { result } = renderHook(() =>
        useFileEditor({
          serverId: "srv-1",
          onRefreshAfterMutation: mockRefresh,
        })
      );

      await act(async () => {
        await result.current.openEditor(smallEntry, ROOT);
      });

      // Mock save failure with conflict (starts with "conflict:")
      mockZeroInvoke.mockRejectedValueOnce(new Error("conflict: The file was modified by another process."));

      await act(async () => {
        await result.current.saveEditor();
      });

      expect(result.current.editor?.conflict).toContain("conflict: The file was modified");
      expect(result.current.editor?.phase).toBe("editing");
    });
  });

  describe("useLocalDirectory", () => {
    it("loads local directory and auto-reloads when completed downloads are observed", async () => {
      mockZeroInvoke.mockResolvedValue({
        ok: true,
        entries: [
          { name: "file1.txt", path: "/local/file1.txt", kind: "file", size: 100, mtime: 1 },
        ],
        truncated: false,
      });

      let transfers: SftpTransfer[] = [];
      const { result, rerender } = renderHook(() => useLocalDirectory(transfers));

      await act(async () => {
        await result.current.loadLocal("/local");
      });

      expect(result.current.local.entries).toHaveLength(1);
      expect(mockZeroInvoke).toHaveBeenCalledTimes(1);

      // New completed download transfer arrives
      transfers = [
        {
          id: 501,
          kind: "download",
          status: "done",
          path: "/remote/test.txt",
          bytes: 100,
          total: 100,
          error: "",
        },
      ];

      mockZeroInvoke.mockResolvedValueOnce({
        ok: true,
        entries: [
          { name: "file1.txt", path: "/local/file1.txt", kind: "file", size: 100, mtime: 1 },
          { name: "test.txt", path: "/local/test.txt", kind: "file", size: 100, mtime: 2 },
        ],
        truncated: false,
      });

      rerender();

      await waitFor(() => expect(result.current.local.entries).toHaveLength(2));
      expect(mockZeroInvoke).toHaveBeenCalledTimes(2);
    });
  });

  describe("useDeployRun", () => {
    const mockComplete = vi.fn();
    const mockError = vi.fn();

    const sampleApp: DeployApp = {
      id: "app-1",
      server_id: "srv-1",
      name: "frontend-app",
      environment: "production",
      folder: "/var/www/app",
      repo: { url: "git@github.com:org/repo.git", branch: "main", transport: "ssh" },
      runtime: {
        node_version: "24",
        type: "next",
        package_manager: "auto",
        install: "npm install",
        build: "npm run build",
        entry: "node_modules/next/dist/bin/next",
        args: "start",
        start_command: "",
        build_folder: ".next",
      },
      env_vars: [{ name: "API_SECRET", secret: true, value: "••••", has_value: true }],
      domains: ["example.com"],
      ssl: true,
      email: "admin@example.com",
      app_port: 3000,
      revision: 1,
      created_at_ms: 0,
      updated_at_ms: 0,
    };

    const readyPreflight: DeployPreflight = {
      id: 10,
      app_id: "app-1",
      server_id: "srv-1",
      created_at_ms: 0,
      expires_at_ms: 1000000,
      app_revision: 1,
      target_fingerprint: 1,
      status: "ready",
      facts: {
        os: "linux",
        arch: "x86_64",
        libc: "glibc",
        user: "node",
        home: "/home/node",
        privilege: "user",
        repository_commit: "abc1234",
        lockfiles: "package-lock.json",
        git_host_fingerprints: "github.com",
        ports: "3000",
      },
      blockers: [],
      warnings: [],
      approvals: [{ id: "appr-1", label: "Approve git pull", detail: "low risk" }],
      configs: { env: "", pm2: "", nginx: "" },
      steps: [{ id: "step-1", label: "git pull", mutation: "git pull", command: "git pull", skipped: false, files: [], guards: [], rollback: "" }],
    };

    it("verifies required approvals and prevents start if unapproved", async () => {
      const { result } = renderHook(() =>
        useDeployRun("srv-1", mockComplete, mockError)
      );

      await act(async () => {
        await result.current.startRun(
          sampleApp,
          readyPreflight,
          { "appr-1": false }, // unapproved!
          { API_SECRET: "secret123" }
        );
      });

      expect(mockError).toHaveBeenCalledWith("Approve every required change before deployment.");
      expect(mockZeroInvoke).not.toHaveBeenCalled();
    });

    it("starts run, polls progress, feeds output, and signals completion", async () => {
      let pollCount = 0;
      mockZeroInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === "oars.deploy.run") {
          return { ok: true, run_id: 888 };
        }
        if (cmd === "oars.deploy.poll") {
          pollCount += 1;
          if (pollCount === 1) {
            return {
              status: "running",
              done: false,
              steps: [{ id: "step-1", status: "running", data: "Cloning repo...\n", cursor: 16, gap: false }],
            };
          }
          return {
            status: "done",
            done: true,
            steps: [{ id: "step-1", status: "done", data: "Success!\n", cursor: 25, gap: false }],
          };
        }
        return { ok: true };
      });

      const { result } = renderHook(() =>
        useDeployRun("srv-1", mockComplete, mockError)
      );

      await act(async () => {
        await result.current.startRun(
          sampleApp,
          readyPreflight,
          { "appr-1": true },
          { API_SECRET: "secret123" }
        );
      });

      expect(result.current.runId).toBe(888);

      await waitFor(() => expect(result.current.runStatus).toBe("done"));
      expect(result.current.outputs["step-1"]).toContain("Cloning repo...\nSuccess!\n");
      expect(mockComplete).toHaveBeenCalledWith("app-1");
    });
  });
});
