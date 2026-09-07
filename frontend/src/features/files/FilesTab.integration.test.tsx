import { describe, expect, it, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { FilesTab } from "./FilesTab";
import { mockBridge, createMockFile } from "../../test/mock-bridge";

describe("FilesTab Integration Suite", () => {
  beforeEach(() => {
    mockBridge.reset();
    mockBridge.install();

    // Seed all virtual directory files at root /
    mockBridge.setVirtualFile("/report.txt", "Report content", 0o644);
    mockBridge.setVirtualFile("/notes.md", "# Notes\nSome notes here.", 0o644);
    mockBridge.setVirtualFile("/data.csv", "id,name\n1,Alpha\n2,Beta", 0o644);
    mockBridge.setVirtualFile("/archive.zip", "PK\x03\x04mockzipcontent", 0o644);
    mockBridge.setVirtualFile("/subfolder", new Uint8Array(0), 0o755, undefined, true);
    mockBridge.setVirtualFile("/big-data.iso", new Uint8Array(10 * 1024 * 1024));
    mockBridge.setVirtualFile("/server.js", "const x = 1;\n".repeat(8000));
    mockBridge.setVirtualFile("/editable.txt", "Initial text");
    mockBridge.setVirtualFile("/conflict.txt", "Initial server text");
    mockBridge.setVirtualFile("/binary.dat", new Uint8Array([0xff, 0xfe, 0xfd]));
    mockBridge.setVirtualFile("/huge.log", new Uint8Array(1024 * 1024));
  });

  async function openFileInEditor(filename: string) {
    const row = screen.getByText(filename).closest("button.fs-pane-row");
    fireEvent.click(row!);
    const editBtn = await screen.findByRole("button", { name: /Edit/i });
    fireEvent.click(editBtn);
  }

  it("Scenario 1: Directory navigation, row selection, and keyboard clear", async () => {
    render(<FilesTab serverId="srv-prod" onNavigateToDeploy={() => {}} />);

    // Wait for directory listing to load
    expect(await screen.findByText("report.txt")).toBeTruthy();
    expect(screen.getByText("notes.md")).toBeTruthy();
    expect(screen.getByText("subfolder")).toBeTruthy();

    const localPane = screen.getByRole("region", { name: "Local file browser" });
    const remotePane = screen.getByRole("region", { name: "Remote file browser" });
    expect(localPane.classList.contains("fs-browser-surface")).toBe(true);
    expect(remotePane.classList.contains("fs-browser-surface")).toBe(true);
    expect(localPane.querySelector(".fs-pane-header")).toBeTruthy();
    expect(remotePane.querySelector(".fs-pane-header")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Open applications in Deploy" })).toBeTruthy();

    const reportRow = screen.getByText("report.txt").closest("button.fs-pane-row");
    expect(reportRow).toBeTruthy();

    // Click row to select
    fireEvent.click(reportRow!);
    expect(reportRow!.getAttribute("aria-selected")).toBe("true");

    // Escape clears selection
    const workspace = screen.getByText("report.txt").closest(".fs-workspace");
    fireEvent.keyDown(workspace!, { key: "Escape" });
    expect(reportRow!.getAttribute("aria-selected")).toBe("false");
  });

  it("Scenario 2: Multi-chunk 150KB file upload via SFTP with progress updates", async () => {
    const writeSpy = mockBridge.spyOn("oars.sftp.write");
    render(<FilesTab serverId="srv-prod" onNavigateToDeploy={() => {}} />);
    await screen.findByText("report.txt");

    // Create 200KB mock file (requires 4 chunks of 64KB, 64KB, 64KB, 8KB)
    const largeFile = createMockFile("large-bundle.tar", new Uint8Array(200 * 1024));

    const fileInput = document.querySelector('input[type="file"]:not([webkitdirectory])') as HTMLInputElement;
    expect(fileInput).toBeTruthy();

    // Trigger file selection
    fireEvent.change(fileInput, { target: { files: [largeFile] } });

    // UploadDialog opens
    expect(await screen.findByText(/Upload 1 (file|item)/i)).toBeTruthy();

    const startBtn = await screen.findByRole("button", { name: /Start upload/i });
    fireEvent.click(startBtn);

    // Verify TransferDrawer renders and completes chunks
    await waitFor(() => {
      expect(writeSpy).toHaveBeenCalled();
    });

    await waitFor(
      () => {
        expect(writeSpy.mock.calls.length).toBeGreaterThanOrEqual(3);
      },
      { timeout: 3000 }
    );

    // Verify offsets passed to oars.sftp.write
    expect(writeSpy.mock.calls[0][0].offset).toBe(0);
    expect(writeSpy.mock.calls[1][0].offset).toBe(65536);
    expect(writeSpy.mock.calls[2][0].offset).toBe(131072);
  });

  it("Scenario 3: 0-byte file upload", async () => {
    const writeSpy = mockBridge.spyOn("oars.sftp.write");
    render(<FilesTab serverId="srv-prod" onNavigateToDeploy={() => {}} />);
    await screen.findByText("report.txt");

    const emptyFile = createMockFile("empty.txt", new Uint8Array(0));
    const fileInput = document.querySelector('input[type="file"]:not([webkitdirectory])') as HTMLInputElement;

    fireEvent.change(fileInput, { target: { files: [emptyFile] } });
    expect(await screen.findByText(/Upload 1 (file|item)/i)).toBeTruthy();

    const startBtn = await screen.findByRole("button", { name: /Start upload/i });
    fireEvent.click(startBtn);

    await waitFor(() => {
      expect(writeSpy).toHaveBeenCalled();
    });

    expect(writeSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        offset: 0,
        base64: "",
      })
    );
  });

  it("Scenario 4: Upload cancellation", async () => {
    const cancelSpy = mockBridge.spyOn("oars.sftp.cancel");

    // Make sftp.write delayed so we can click cancel
    mockBridge.setHandler("oars.sftp.write", async () => {
      await new Promise((r) => setTimeout(r, 50));
      return { ok: true, written: 65536, done: false };
    });

    render(<FilesTab serverId="srv-prod" onNavigateToDeploy={() => {}} />);
    await screen.findByText("report.txt");

    const file = createMockFile("cancelling.dat", new Uint8Array(200 * 1024));
    const fileInput = document.querySelector('input[type="file"]:not([webkitdirectory])') as HTMLInputElement;

    fireEvent.change(fileInput, { target: { files: [file] } });
    const startBtn = await screen.findByRole("button", { name: /Start upload/i });
    fireEvent.click(startBtn);

    // Cancel in drawer using title
    const cancelBtn = await screen.findByTitle("Cancel upload");
    fireEvent.click(cancelBtn);

    await waitFor(() => {
      expect(cancelSpy).toHaveBeenCalled();
    });
  });

  it("Scenario 5: Large file download via SFTP", async () => {
    const downloadSpy = mockBridge.spyOn("oars.sftp.download");

    render(<FilesTab serverId="srv-prod" onNavigateToDeploy={() => {}} />);
    expect(await screen.findByText("big-data.iso")).toBeTruthy();

    // Select file
    const fileRow = screen.getByText("big-data.iso").closest("button.fs-pane-row");
    fireEvent.click(fileRow!);

    // Click Download button in selection toolbar
    const downloadBtn = await screen.findByRole("button", { name: /^Download/i });
    fireEvent.click(downloadBtn);

    await waitFor(() => {
      expect(downloadSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          server_id: "srv-prod",
          local_path: "/mock/saved/file.tar.gz",
        })
      );
    });

    // Drawer should show transfer progress for big-data.iso
    const matches = await screen.findAllByText(/big-data\.iso/i);
    expect(matches.length).toBeGreaterThanOrEqual(1);
  });

  it("Scenario 6: File Editor chunked read and content display", async () => {
    render(<FilesTab serverId="srv-prod" onNavigateToDeploy={() => {}} />);
    expect(await screen.findByText("server.js")).toBeTruthy();

    await openFileInEditor("server.js");

    // EditorModal opens and displays content
    const textarea = (await screen.findByRole("textbox")) as HTMLTextAreaElement;
    expect(textarea).toBeTruthy();
    expect(textarea.value).toBe("const x = 1;\n".repeat(8000));
    expect(screen.getAllByText(/server\.js/).length).toBeGreaterThan(0);
  });

  it("Scenario 7: File Editor dirty discard confirmation dialogs", async () => {
    render(<FilesTab serverId="srv-prod" onNavigateToDeploy={() => {}} />);
    expect(await screen.findByText("editable.txt")).toBeTruthy();

    await openFileInEditor("editable.txt");

    const textarea = (await screen.findByRole("textbox")) as HTMLTextAreaElement;
    fireEvent.change(textarea, { target: { value: "Modified unsaved text" } });

    // Attempt to close dirty editor
    const closeBtn = screen.getByRole("button", { name: /Close editor/i });
    fireEvent.click(closeBtn);

    // Discard dialog appears
    expect(await screen.findByText("Discard unsaved changes?")).toBeTruthy();

    // Click "Keep editing"
    const keepEditingBtn = screen.getByRole("button", { name: /Keep editing/i });
    fireEvent.click(keepEditingBtn);
    expect(screen.queryByText("Discard unsaved changes?")).toBeNull();
    expect(screen.getByRole("textbox")).toBeTruthy();

    // Close again and click "Discard changes"
    fireEvent.click(closeBtn);
    const discardBtn = await screen.findByRole("button", { name: /Discard changes/i });
    fireEvent.click(discardBtn);

    // Modal closes
    await waitFor(() => {
      expect(screen.queryByRole("textbox")).toBeNull();
    });
  });

  it("Scenario 8: File Editor optimistic locking conflict banner and reload", async () => {
    render(<FilesTab serverId="srv-prod" onNavigateToDeploy={() => {}} />);
    expect(await screen.findByText("conflict.txt")).toBeTruthy();

    await openFileInEditor("conflict.txt");
    const textarea = (await screen.findByRole("textbox")) as HTMLTextAreaElement;

    fireEvent.change(textarea, { target: { value: "User edited text" } });

    // Simulate remote conflict on save
    mockBridge.setHandler("oars.sftp.save", () => {
      return { ok: false, error: "conflict: file modified remotely" };
    });

    const saveBtn = screen.getByRole("button", { name: /^Save$/i });
    fireEvent.click(saveBtn);

    // Confirm save in save dialog
    const confirmSaveBtn = await screen.findByRole("button", { name: /Save to server/i });
    fireEvent.click(confirmSaveBtn);

    // Conflict banner appears
    expect(await screen.findByText(/This file changed on the server since you opened it/i)).toBeTruthy();

    // Update server file and click Reload from server
    mockBridge.setVirtualFile("/conflict.txt", "New text from another user");
    const reloadBtn = screen.getByRole("button", { name: /Reload from server/i });
    fireEvent.click(reloadBtn);

    // Textarea reflects reloaded content and conflict banner clears
    await waitFor(() => {
      const reloadedTextarea = screen.getByRole("textbox") as HTMLTextAreaElement;
      expect(reloadedTextarea.value).toBe("New text from another user");
      expect(screen.queryByText(/This file changed on the server since you opened it/i)).toBeNull();
    });
  });

  it("Scenario 9: Non-UTF-8 binary file rejection in editor", async () => {
    render(<FilesTab serverId="srv-prod" onNavigateToDeploy={() => {}} />);
    expect(await screen.findByText("binary.dat")).toBeTruthy();

    await openFileInEditor("binary.dat");

    // Editor displays binary decode error
    const errors = await screen.findAllByText(/not valid UTF-8 text and cannot be edited/i);
    expect(errors.length).toBeGreaterThan(0);

    // Textarea is not rendered in error state
    expect(screen.queryByRole("textbox")).toBeNull();
  });

  it("Scenario 10: Oversized file rejection (>768KB) without issuing reads", async () => {
    const readSpy = mockBridge.spyOn("oars.sftp.read");

    render(<FilesTab serverId="srv-prod" onNavigateToDeploy={() => {}} />);
    expect(await screen.findByText("huge.log")).toBeTruthy();

    await openFileInEditor("huge.log");

    // Rejection message rendered immediately
    const errors = await screen.findAllByText(/the editor handles text files up to/i);
    expect(errors.length).toBeGreaterThan(0);

    // Verify sftp.read was not called
    expect(readSpy).not.toHaveBeenCalled();
  });
});
