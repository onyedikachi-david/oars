// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, renderHook, screen, waitFor } from "@testing-library/react";
import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "./bridge";
import { DeployTab } from "./DeployTab";
import { useDeployDelete } from "./features/deploy/hooks/useDeployDelete";
import { useDeployEditor } from "./features/deploy/hooks/useDeployEditor";
import { useDeployPreflight } from "./features/deploy/hooks/useDeployPreflight";
import { useDeployRun } from "./features/deploy/hooks/useDeployRun";
import { EditorModal } from "./features/files/EditorModal";
import { FilesTab } from "./features/files/FilesTab";
import { FileListView } from "./features/files/components/FileListView";
import { FilesDialogHost } from "./features/files/dialogs/FilesDialogHost";
import { useFileTransfers } from "./features/files/hooks/useFileTransfers";
import { useRemoteDirectory } from "./features/files/hooks/useRemoteDirectory";
import { TransferDrawer } from "./features/files/TransferDrawer";
import type { EditorState } from "./features/files/types";
import { FilesTab as RootFilesTab } from "./FilesTab";
import type { UploadJob } from "./transfer-model";
import {
  ROOT,
  rpBasename,
  rpBytes,
  rpFromUtf8,
  rpIsRoot,
  rpJoin,
  rpParent,
  rpSerialize,
  rpSplit,
  type RemotePath,
} from "./sftp-path";
import type {
  DeployApp,
  DeployPreflight,
  SftpEntry,
  SftpTransfer,
} from "./types";

const mockZeroInvoke = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
  window.zero = {
    invoke: mockZeroInvoke,
  };
});

afterEach(() => {
  cleanup();
  delete window.zero;
});

describe("M1 Empirical Stress Suite (Adversarial Challenger)", () => {
  describe("1. Active Transfers & Cancel Operations (Job vs Numeric ID)", () => {
    const mockRefresh = vi.fn();

    it("handles startUploads with empty list without triggering RPC or errors", async () => {
      const { result } = renderHook(() =>
        useFileTransfers({
          serverId: "srv-test",
          onRefreshAfterMutation: mockRefresh,
        })
      );

      await act(async () => {
        await result.current.startUploads([], ROOT);
      });

      expect(mockZeroInvoke).not.toHaveBeenCalledWith("oars.sftp.write", expect.anything());
      expect(result.current.uploads.jobs).toHaveLength(0);
    });

    it("handles startLocalUploads and downloadPaths with empty list gracefully", async () => {
      const { result } = renderHook(() =>
        useFileTransfers({
          serverId: "srv-test",
          onRefreshAfterMutation: mockRefresh,
        })
      );

      await act(async () => {
        await result.current.startLocalUploads([], ROOT);
        await result.current.downloadPaths([], ROOT, "/local/path");
      });

      expect(result.current.transfers).toHaveLength(0);
    });

    it("supports cancelUpload using an UploadJob object", async () => {
      mockZeroInvoke.mockResolvedValue({ ok: true });

      const { result } = renderHook(() =>
        useFileTransfers({
          serverId: "srv-alpha",
          onRefreshAfterMutation: mockRefresh,
        })
      );

      const fakeJob: UploadJob = {
        transferId: 777,
        serverId: "srv-custom",
        path: ROOT,
        display: "test.txt",
        file: new File(["data"], "test.txt"),
        total: 4,
        status: "running" as const,
        bytesSent: 2,
        error: "",
      };

      await act(async () => {
        await result.current.cancelUpload(fakeJob);
      });

      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.cancel", {
        server_id: "srv-custom",
        transfer_id: 777,
      });
    });

    it("supports cancelUpload using a numeric ID", async () => {
      mockZeroInvoke.mockResolvedValue({ ok: true });

      const { result } = renderHook(() =>
        useFileTransfers({
          serverId: "srv-default",
          onRefreshAfterMutation: mockRefresh,
        })
      );

      await act(async () => {
        await result.current.cancelUpload(444);
      });

      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.cancel", {
        server_id: "srv-default",
        transfer_id: 444,
      });
    });

    it("supports cancelBackendTransfer using SftpTransfer object and numeric ID", async () => {
      mockZeroInvoke.mockResolvedValue({ ok: true });

      const { result } = renderHook(() =>
        useFileTransfers({
          serverId: "srv-backend",
          onRefreshAfterMutation: mockRefresh,
        })
      );

      const transferObj: SftpTransfer = {
        id: 888,
        server_id: "srv-explicit",
        kind: "download",
        path: "/remote/path.log",
        bytes: 50,
        total: 100,
        status: "running",
        error: "",
      } as any;

      await act(async () => {
        await result.current.cancelBackendTransfer(transferObj);
      });

      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.cancel", {
        server_id: "srv-explicit",
        transfer_id: 888,
      });

      await act(async () => {
        await result.current.cancelBackendTransfer(999);
      });

      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.sftp.cancel", {
        server_id: "srv-backend",
        transfer_id: 999,
      });
    });

    it("swallows RPC failure when cancelling upload gracefully without uncaught rejection", async () => {
      mockZeroInvoke.mockRejectedValue(new Error("Connection reset"));

      const { result } = renderHook(() =>
        useFileTransfers({
          serverId: "srv-test",
          onRefreshAfterMutation: mockRefresh,
        })
      );

      await act(async () => {
        await expect(result.current.cancelUpload(123)).resolves.not.toThrow();
      });
    });
  });

  describe("2. TransferDrawer Edge Cases & Rendering", () => {
    it("renders TransferDrawer with empty list, active jobs, and canceled transfers", () => {
      const mockCancelUpload = vi.fn();
      const mockCancelTransfer = vi.fn();

      const transfers: SftpTransfer[] = [
        {
          id: 1,
          kind: "download",
          path: "/path/file%20name.dat",
          bytes: 512,
          total: 1024,
          status: "running",
          error: "",
        },
        {
          id: 2,
          kind: "rm",
          path: "/tmp/delete_me",
          bytes: 0,
          total: 0,
          status: "failed",
          error: "Permission denied",
        },
        {
          id: 3,
          kind: "unzip",
          path: "/archive.zip",
          bytes: 100,
          total: 100,
          status: "done",
          error: "",
        },
      ];

      const uploads: UploadJob[] = [
        {
          transferId: 201,
          serverId: "srv-1",
          path: ROOT,
          file: new File([], "empty.txt"),
          display: "empty.txt",
          total: 0,
          bytesSent: 0,
          status: "queued" as const,
          error: "",
        },
      ];

      const { getByTitle, getAllByText } = render(
        <TransferDrawer
          transfers={transfers}
          uploads={uploads}
          onCancelUpload={mockCancelUpload}
          onCancelTransfer={mockCancelTransfer}
        />
      );

      expect(getAllByText(/Transfers/)).toBeDefined();
      expect(getAllByText(/active/)).toBeDefined();

      const cancelTransferBtn = getByTitle("Cancel transfer");
      fireEvent.click(cancelTransferBtn);
      expect(mockCancelTransfer).toHaveBeenCalledWith(transfers[0]);

      const cancelUploadBtn = getByTitle("Cancel upload");
      fireEvent.click(cancelUploadBtn);
      expect(mockCancelUpload).toHaveBeenCalledWith(uploads[0]);
    });
  });

  describe("3. Rapid Directory Changes & Race Conditions", () => {
    const mockOpenFile = vi.fn();
    const mockRequestDelete = vi.fn();
    const mockDropFiles = vi.fn();

    it("resets state and discards in-flight requests when serverId changes rapidly", async () => {
      let resolveSrv1!: (val: any) => void;
      const srv1Promise = new Promise((res) => {
        resolveSrv1 = res;
      });

      mockZeroInvoke.mockImplementation(async (cmd: string, payload: any) => {
        if (cmd === "oars.sftp.ls") {
          if (payload.server_id === "srv-1") return srv1Promise;
          return {
            ok: true,
            entries: [
              {
                name: rpFromUtf8("srv2-file.txt"),
                display: "srv2-file.txt",
                kind: "file",
                size: 100,
                mtime: 1,
                mode: "0644",
                uid: 1,
                gid: 1,
                link_target: null,
              },
            ],
            truncated: false,
          };
        }
        return { ok: true };
      });

      const { result, rerender } = renderHook(
        ({ server }) =>
          useRemoteDirectory({
            serverId: server,
            onOpenFile: mockOpenFile,
            onRequestDelete: mockRequestDelete,
            onDropFiles: mockDropFiles,
          }),
        { initialProps: { server: "srv-1" } }
      );

      // Now switch quickly to srv-2 before srv-1 resolves
      rerender({ server: "srv-2" });

      await waitFor(() => expect(result.current.dir.loading).toBe(false));
      expect(result.current.dir.serverId).toBe("srv-2");
      expect(result.current.dir.listing.entries).toHaveLength(1);
      expect(result.current.dir.listing.entries[0].name).toEqual(rpFromUtf8("srv2-file.txt"));

      // Old srv-1 now resolves -> must NOT pollute srv-2 state
      await act(async () => {
        resolveSrv1({
          ok: true,
          entries: [
            {
              name: rpFromUtf8("srv1-stale.txt"),
              display: "srv1-stale.txt",
              kind: "file",
              size: 50,
              mtime: 1,
              mode: "0644",
              uid: 1,
              gid: 1,
              link_target: null,
            },
          ],
          truncated: false,
        });
      });

      expect(result.current.dir.serverId).toBe("srv-2");
      expect(result.current.dir.listing.entries).toHaveLength(1);
      expect(result.current.dir.listing.entries[0].name).toEqual(rpFromUtf8("srv2-file.txt"));
    });

    it("measures folder size and isolates error states per folder key", async () => {
      mockZeroInvoke.mockImplementation(async (cmd: string, payload: any) => {
        if (cmd === "oars.sftp.ls") return { ok: true, entries: [], truncated: false };
        if (cmd === "oars.sftp.folderSize") {
          if (payload.path.utf8 === "/fail") throw new Error("Permission denied for folder");
          return { ok: true, size: 2048576 };
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

      const okDir: SftpEntry = {
        name: rpFromUtf8("success"),
        display: "success",
        kind: "dir",
        size: 4096,
        mtime: 1,
        mode: "0755",
        uid: 1,
        gid: 1,
        link_target: null,
      };

      const failDir: SftpEntry = {
        name: rpFromUtf8("fail"),
        display: "fail",
        kind: "dir",
        size: 4096,
        mtime: 1,
        mode: "0755",
        uid: 1,
        gid: 1,
        link_target: null,
      };

      await act(async () => {
        await result.current.doFolderSize(okDir);
        await result.current.doFolderSize(failDir);
      });

      const okSize = result.current.sizes.get(rpSerialize(okDir.name));
      const failSize = result.current.sizes.get(rpSerialize(failDir.name));

      expect(okSize?.size).toBe(2048576);
      expect(okSize?.error).toBeNull();
      expect(failSize?.size).toBeNull();
      expect(failSize?.error).toContain("Permission denied");
    });
  });

  describe("4. FileListView Error & Truncated States", () => {
    it("renders error banner and dismiss button when dir.error is present", () => {
      const mockClearError = vi.fn();
      const dirSnapshot = {
        serverId: "srv-1",
        path: ROOT,
        pathKey: "u:/",
        listing: { entries: [], truncated: true },
        loading: false,
        refreshing: false,
        error: "Failed to connect to SFTP subsystem",
        loadedAt: Date.now(),
      };

      render(
        <FileListView
          dir={dirSnapshot}
          selection={{ keys: [], anchor: null }}
          sizes={new Map()}
          dropTarget={null}
          displayedEntries={[]}
          onClearError={mockClearError}
          onRowClick={vi.fn()}
          onRowKeyDown={vi.fn()}
          onOpenEntry={vi.fn()}
          onSetDropTarget={vi.fn()}
          onDrop={vi.fn()}
        />
      );

      expect(screen.getByRole("alert").textContent).toContain("Failed to connect to SFTP subsystem");
      expect(screen.getByText(/Only the first 5,000 remote entries are shown/)).toBeDefined();

      const dismissBtn = screen.getByLabelText("Dismiss");
      fireEvent.click(dismissBtn);
      expect(mockClearError).toHaveBeenCalled();
    });
  });

  describe("5. File Dialogs Host & Lifecycle", () => {
    it("renders MkdirDialog, handles validation and submission", () => {
      const mockMkdir = vi.fn();
      const mockClose = vi.fn();

      render(
        <FilesDialogHost
          dialog={{ kind: "mkdir" }}
          dirPath={ROOT}
          onClose={mockClose}
          onMkdir={mockMkdir}
          onRename={vi.fn()}
          onChmod={vi.fn()}
          onDelete={vi.fn()}
          onUnzip={vi.fn()}
          onStartUploads={vi.fn()}
          onStartLocalUploads={vi.fn()}
        />
      );

      const input = screen.getByRole("textbox");
      fireEvent.change(input, { target: { value: "invalid/folder" } });
      expect(screen.getByText("Names cannot contain a slash.")).toBeDefined();

      fireEvent.change(input, { target: { value: "valid_folder" } });
      const createBtn = screen.getByRole("button", { name: "Create folder" });
      fireEvent.click(createBtn);
      expect(mockMkdir).toHaveBeenCalledWith("valid_folder");
    });

    it("renders DeleteDialog with selected count and triggers onDelete", () => {
      const mockDelete = vi.fn();
      const mockClose = vi.fn();
      const entries: SftpEntry[] = [
        { name: rpFromUtf8("a.txt"), display: "a.txt", kind: "file", size: 1, mtime: 1, mode: "0644", uid: 1, gid: 1, link_target: null },
        { name: rpFromUtf8("b.txt"), display: "b.txt", kind: "file", size: 1, mtime: 1, mode: "0644", uid: 1, gid: 1, link_target: null },
      ];

      render(
        <FilesDialogHost
          dialog={{ kind: "delete", entries }}
          dirPath={ROOT}
          onClose={mockClose}
          onMkdir={vi.fn()}
          onRename={vi.fn()}
          onChmod={vi.fn()}
          onDelete={mockDelete}
          onUnzip={vi.fn()}
          onStartUploads={vi.fn()}
          onStartLocalUploads={vi.fn()}
        />
      );

      expect(screen.getByText("Delete 2 items?")).toBeDefined();
      const deleteBtn = screen.getByRole("button", { name: /Delete/ });
      fireEvent.click(deleteBtn);
      expect(mockDelete).toHaveBeenCalledWith(entries, true);
    });

    it("renders ChmodDialog and enforces octal characters", () => {
      const mockChmod = vi.fn();
      const entry: SftpEntry = {
        name: rpFromUtf8("script.sh"),
        display: "script.sh",
        kind: "file",
        size: 10,
        mtime: 1,
        mode: "0644",
        uid: 1,
        gid: 1,
        link_target: null,
      };

      render(
        <FilesDialogHost
          dialog={{ kind: "chmod", entry }}
          dirPath={ROOT}
          onClose={vi.fn()}
          onMkdir={vi.fn()}
          onRename={vi.fn()}
          onChmod={mockChmod}
          onDelete={vi.fn()}
          onUnzip={vi.fn()}
          onStartUploads={vi.fn()}
          onStartLocalUploads={vi.fn()}
        />
      );

      const input = screen.getByRole("textbox");
      fireEvent.change(input, { target: { value: "0755" } });
      expect(screen.getByText(/Will apply:\s*rwxr-xr-x/)).toBeDefined();

      const applyBtn = screen.getByRole("button", { name: "Apply permissions" });
      fireEvent.click(applyBtn);
      expect(mockChmod).toHaveBeenCalledWith(entry, 0o755);
    });
  });

  describe("6. Editor Modal, Dirty Confirmation, & Conflict Resolution", () => {
    const entry: SftpEntry = {
      name: rpFromUtf8("app.log"),
      display: "app.log",
      kind: "file",
      size: 1024,
      mtime: 1700000000,
      mode: "0644",
      uid: 1000,
      gid: 1000,
      link_target: null,
    };

    it("renders EditorModal, handles dirty close prompt and discard", () => {
      const mockClose = vi.fn();
      const mockSave = vi.fn();
      const mockReload = vi.fn();
      const mockDiscard = vi.fn();
      const mockCancelDiscard = vi.fn();
      const mockChange = vi.fn();

      const editorState: EditorState = {
        path: rpFromUtf8("/var/log/app.log"),
        pathKey: "u:/var/log/app.log",
        display: "/var/log/app.log",
        entry,
        content: "Line 1\nLine 2",
        sha256: "abc123",
        dirty: true,
        phase: "editing",
        conflict: null,
        error: null,
        tooLarge: false,
      };

      const { rerender } = render(
        <EditorModal
          editor={editorState}
          onClose={mockClose}
          onSave={mockSave}
          onReload={mockReload}
          onDiscard={mockDiscard}
          onCancelDiscard={mockCancelDiscard}
          onDismissConflict={vi.fn()}
          dirtyCloseOpen={false}
          onChange={mockChange}
        />
      );

      expect(screen.getByText("/var/log/app.log")).toBeDefined();
      expect(screen.getByText(/Unsaved changes/)).toBeDefined();

      // Open dirty confirmation dialog
      rerender(
        <EditorModal
          editor={editorState}
          onClose={mockClose}
          onSave={mockSave}
          onReload={mockReload}
          onDiscard={mockDiscard}
          onCancelDiscard={mockCancelDiscard}
          onDismissConflict={vi.fn()}
          dirtyCloseOpen={true}
          onChange={mockChange}
        />
      );

      expect(screen.getByText("Discard unsaved changes?")).toBeDefined();
      const discardBtn = screen.getByRole("button", { name: "Discard changes" });
      fireEvent.click(discardBtn);
      expect(mockDiscard).toHaveBeenCalled();
    });

    it("renders conflict banner with reload button when conflict occurs", () => {
      const mockReload = vi.fn();
      const editorState: EditorState = {
        path: rpFromUtf8("/etc/hosts"),
        pathKey: "u:/etc/hosts",
        display: "/etc/hosts",
        entry,
        content: "new text",
        sha256: "def456",
        dirty: true,
        phase: "editing",
        conflict: "conflict: The file was modified by another process (mtime changed).",
        error: null,
        tooLarge: false,
      };

      render(
        <EditorModal
          editor={editorState}
          onClose={vi.fn()}
          onSave={vi.fn()}
          onReload={mockReload}
          onDiscard={vi.fn()}
          onCancelDiscard={vi.fn()}
          onDismissConflict={vi.fn()}
          dirtyCloseOpen={false}
          onChange={vi.fn()}
        />
      );

      expect(screen.getByText(/The file was modified by another process/)).toBeDefined();
      const reloadBtn = screen.getByRole("button", { name: "Reload from server" });
      fireEvent.click(reloadBtn);
      expect(mockReload).toHaveBeenCalled();
    });
  });

  describe("7. Deploy Preflight, Run Output, & Delete Operations", () => {
    const sampleApp: DeployApp = {
      id: "app-test",
      server_id: "srv-1",
      name: "Test Deployment",
      environment: "production",
      folder: "/var/www/test",
      repo: { url: "git@github.com:test/repo.git", transport: "https", branch: "main" },
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
      env_vars: [{ name: "DB_HOST", secret: false, value: "localhost", has_value: true }],
      domains: ["example.com"],
      ssl: false,
      email: "",
      app_port: 3000,
      revision: 1,
      created_at_ms: 0,
      updated_at_ms: 0,
    };

    it("useDeployPreflight manages approval states and handles preflight cancellation", async () => {
      const mockPreflightObj: DeployPreflight = {
        id: 99,
        app_id: "app-test",
        server_id: "srv-1",
        created_at_ms: 0,
        expires_at_ms: 3600000,
        app_revision: 1,
        target_fingerprint: 1234,
        status: "ready",
        facts: {
          os: "linux",
          arch: "x86_64",
          libc: "glibc",
          user: "node",
          home: "/home/node",
          privilege: "user",
          repository_commit: "abc",
          lockfiles: "package-lock.json",
          git_host_fingerprints: "github.com",
          ports: "3000",
        },
        blockers: [],
        warnings: [],
        approvals: [{ id: "appr-1", label: "Schema change", detail: "Apply DB migrations" }],
        configs: { env: "", pm2: "", nginx: "" },
        steps: [],
      };

      mockZeroInvoke.mockResolvedValue({
        ok: true,
        preflight: mockPreflightObj,
      });

      const mockSetError = vi.fn();
      const { result } = renderHook(() =>
        useDeployPreflight("srv-1", sampleApp, mockSetError)
      );

      await act(async () => {
        await result.current.startPreflight();
      });

      expect(result.current.preflight).not.toBeNull();
      expect(result.current.preflight?.approvals).toHaveLength(1);

      act(() => {
        result.current.setApprovals({ "appr-1": true });
      });
      expect(result.current.approvals["appr-1"]).toBe(true);

      // Test cancel preflight
      act(() => {
        result.current.cancelPreflight();
      });
      expect(result.current.preflightBusy).toBe(false);
    });

    it("useDeployDelete handles open, cancel, and confirm deletion workflow", async () => {
      mockZeroInvoke.mockResolvedValue({ ok: true });
      const mockReload = vi.fn();

      const { result } = renderHook(() => useDeployDelete("srv-1", mockReload));

      act(() => {
        result.current.openDelete(sampleApp);
      });

      expect(result.current.deleteState).not.toBeNull();
      expect(result.current.deleteState?.app.id).toBe("app-test");

      await act(async () => {
        await result.current.confirmDelete();
      });

      expect(mockZeroInvoke).toHaveBeenCalledWith("oars.deploy.apps.delete", {
        server_id: "srv-1",
        app_id: "app-test",
      });
      expect(result.current.deleteState).toBeNull();
      expect(mockReload).toHaveBeenCalled();
    });

    it("useDeployEditor handles bulk environment variables preview and parse errors", () => {
      const mockReload = vi.fn();
      const mockSetError = vi.fn();

      const { result } = renderHook(() =>
        useDeployEditor("srv-1", mockReload, mockSetError)
      );

      act(() => {
        result.current.openEditor(sampleApp);
      });

      expect(result.current.editor).not.toBeNull();
      expect(result.current.editor?.name).toBe("Test Deployment");

      // Set bulk environment text
      act(() => {
        result.current.setBulkText("FOO=bar\nSECRET_KEY=supersecret\nINVALID_LINE_NO_EQUALS");
      });

      act(() => {
        result.current.previewBulk();
      });

      expect(result.current.bulkPreview).not.toBeNull();
      expect(result.current.bulkPreview?.rows).toHaveLength(2);
      expect(result.current.bulkPreview?.rejected).toHaveLength(1);
      expect(result.current.bulkPreview?.rejected[0]).toContain("INVALID_LINE_NO_EQUALS");

      // Apply valid subset
      act(() => {
        result.current.applyBulkPreview();
      });

      expect(result.current.editor?.env_vars).toHaveLength(3);
    });
  });

  describe("8. Backward Compatibility & Root Exports", () => {
    it("exports FilesTab and DeployTab from root and renders them without crashing", async () => {
      mockZeroInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === "oars.sftp.ls") return { ok: true, entries: [], truncated: false };
        if (cmd === "oars.sftp.poll") return { ok: true, transfers: [] };
        if (cmd === "oars.deploy.apps.list") return { ok: true, apps: [] };
        return { ok: true };
      });

      // Root exports check
      expect(RootFilesTab).toBe(FilesTab);
      expect(DeployTab).toBeDefined();

      // Render root FilesTab
      const { unmount: unmountFiles } = render(<RootFilesTab serverId="srv-test" />);
      expect(document.querySelector(".fs-workspace")).not.toBeNull();
      unmountFiles();

      // Render root DeployTab
      const { unmount: unmountDeploy } = render(<DeployTab serverId="srv-test" />);
      await waitFor(() => expect(document.querySelector(".deploy-workspace")).not.toBeNull());
      unmountDeploy();
    });

    it("sftp-path module exports all necessary path utilities and interfaces", () => {
      expect(ROOT).toEqual({ utf8: "/" });
      expect(rpIsRoot(ROOT)).toBe(true);
      expect(rpIsRoot({ utf8: "/foo" })).toBe(false);

      const pathA = rpFromUtf8("/var/www");
      const pathB = rpFromUtf8("app/dist");
      const joined = rpJoin(pathA, pathB);
      expect(rpSerialize(joined)).toBe("u:/var/www/app/dist");

      const parent = rpParent(joined);
      expect(rpSerialize(parent)).toBe("u:/var/www/app");

      const base = rpBasename(joined);
      expect(rpSerialize(base)).toBe("u:dist");

      const split = rpSplit(joined);
      expect(split).toHaveLength(5); // [ROOT, var, www, app, dist]

      const rawBytes = rpBytes({ utf8: "test" });
      expect(Array.from(rawBytes)).toEqual([116, 101, 115, 116]);
    });
  });
});
