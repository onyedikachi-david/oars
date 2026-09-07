import { describe, expect, it, beforeEach, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { mockBridge, createMockFile } from "./test/mock-bridge";
import {
  UPLOAD_CHUNK_BYTES,
  MAX_CONCURRENT_UPLOADS,
  nextUploadOffset,
  nextTransferId,
  uploadJobFor,
  uploadReducer,
  emptyUploadModel,
  validateUploadRelativePath,
  uploadDirectoryPaths,
  type UploadJob,
} from "./transfer-model";
import {
  EDITOR_MAX_BYTES,
  isConflictError,
  savedIdentityFallback,
  sha256Hex,
  chunkOffsets,
  editorSaveParams,
} from "./editor-state";
import {
  base64ToBytes,
  bytesToBase64,
  rpFromUtf8,
  rpDisplay,
  rpSerialize,
} from "./sftp-path";
import {
  uploadFileChunks,
  ensureRemoteDirectoryPath,
} from "./features/files/hooks/uploadTransport";
import {
  readRemoteFileChunks,
  writeRemoteFileAtomic,
} from "./features/files/hooks/editorIo";
import { useFileTransfers } from "./features/files/hooks/useFileTransfers";
import { useFileEditor } from "./features/files/hooks/useFileEditor";
import type { SftpEntry } from "./types";

describe("SFTP Transfer State Machine & Chunking Stress Harness", () => {
  beforeEach(() => {
    mockBridge.reset();
    mockBridge.install();
  });

  // --- 1. Multi-chunk upload boundary tests ---
  it("uploads 0-byte file with exact offset 0, empty base64, and total 0", async () => {
    const writeSpy = mockBridge.spyOn("oars.sftp.write");
    const zeroFile = createMockFile("zero.txt", new Uint8Array(0));
    const job = uploadJobFor("srv-test", rpFromUtf8("/remote/zero.txt"), zeroFile);

    const progressCalls: number[] = [];
    const completed = await uploadFileChunks(
      job,
      () => false,
      (bytesSent) => progressCalls.push(bytesSent)
    );

    expect(completed).toBe(true);
    expect(writeSpy).toHaveBeenCalledTimes(1);
    expect(writeSpy).toHaveBeenCalledWith({
      server_id: "srv-test",
      path: { utf8: "/remote/zero.txt/zero.txt" },
      offset: 0,
      base64: "",
      transfer_id: job.transferId,
      total: 0,
    });
  });

  it("uploads 1-byte file in single chunk", async () => {
    const writeSpy = mockBridge.spyOn("oars.sftp.write");
    const oneByte = new Uint8Array([0x42]);
    const file = createMockFile("one.txt", oneByte);
    const job = uploadJobFor("srv-test", rpFromUtf8("/remote"), file);

    const progressCalls: number[] = [];
    const completed = await uploadFileChunks(
      job,
      () => false,
      (bytesSent) => progressCalls.push(bytesSent)
    );

    expect(completed).toBe(true);
    expect(writeSpy).toHaveBeenCalledTimes(1);
    expect(writeSpy).toHaveBeenCalledWith({
      server_id: "srv-test",
      path: { utf8: "/remote/one.txt" },
      offset: 0,
      base64: bytesToBase64(oneByte),
      transfer_id: job.transferId,
      total: 1,
    });
    expect(progressCalls).toEqual([1]);
  });

  it("uploads exact 64KB chunk boundary file (65,536 bytes) in exactly 1 chunk", async () => {
    const writeSpy = mockBridge.spyOn("oars.sftp.write");
    const data = new Uint8Array(64 * 1024);
    for (let i = 0; i < data.length; i++) data[i] = i % 256;
    const file = createMockFile("exact64k.dat", data);
    const job = uploadJobFor("srv-test", rpFromUtf8("/remote"), file);

    const progressCalls: number[] = [];
    const completed = await uploadFileChunks(
      job,
      () => false,
      (bytesSent) => progressCalls.push(bytesSent)
    );

    expect(completed).toBe(true);
    expect(writeSpy).toHaveBeenCalledTimes(1);
    expect(writeSpy).toHaveBeenCalledWith({
      server_id: "srv-test",
      path: { utf8: "/remote/exact64k.dat" },
      offset: 0,
      base64: bytesToBase64(data),
      transfer_id: job.transferId,
      total: 65536,
    });
    expect(progressCalls).toEqual([65536]);
  });

  it("uploads 64KB + 1 byte boundary file (65,537 bytes) in exactly 2 chunks", async () => {
    const writeSpy = mockBridge.spyOn("oars.sftp.write");
    const data = new Uint8Array(65536 + 1);
    for (let i = 0; i < data.length; i++) data[i] = (i * 7) % 256;
    const file = createMockFile("boundary64k1.dat", data);
    const job = uploadJobFor("srv-test", rpFromUtf8("/remote"), file);

    const progressCalls: number[] = [];
    const completed = await uploadFileChunks(
      job,
      () => false,
      (bytesSent) => progressCalls.push(bytesSent)
    );

    expect(completed).toBe(true);
    expect(writeSpy).toHaveBeenCalledTimes(2);
    expect(writeSpy.mock.calls[0][0].offset).toBe(0);
    expect(writeSpy.mock.calls[0][0].total).toBe(65537);
    expect(writeSpy.mock.calls[1][0].offset).toBe(65536);
    expect(writeSpy.mock.calls[1][0].total).toBe(65537);
    expect(progressCalls).toEqual([65536, 65537]);

    // Verify reconstructed data integrity
    const chunk1Bytes = base64ToBytes(writeSpy.mock.calls[0][0].base64);
    const chunk2Bytes = base64ToBytes(writeSpy.mock.calls[1][0].base64);
    expect(chunk1Bytes.length).toBe(65536);
    expect(chunk2Bytes.length).toBe(1);
    expect(chunk2Bytes[0]).toBe(data[65536]);
  });

  it("uploads multi-chunk 500KB file (8 chunks) with complete byte integrity", async () => {
    const writeSpy = mockBridge.spyOn("oars.sftp.write");
    const totalBytes = 500 * 1024; // 512,000 bytes = 7 x 64KB + 53,248 B
    const data = new Uint8Array(totalBytes);
    for (let i = 0; i < data.length; i++) data[i] = (i ^ (i >> 8)) & 0xff;
    const file = createMockFile("multi500k.bin", data);
    const job = uploadJobFor("srv-test", rpFromUtf8("/remote"), file);

    const progressCalls: number[] = [];
    const completed = await uploadFileChunks(
      job,
      () => false,
      (bytesSent) => progressCalls.push(bytesSent)
    );

    expect(completed).toBe(true);
    expect(writeSpy).toHaveBeenCalledTimes(8);

    // Reconstruct full uploaded buffer
    const reconstructed = new Uint8Array(totalBytes);
    let offset = 0;
    for (let c = 0; c < 8; c++) {
      const call = writeSpy.mock.calls[c][0];
      expect(call.offset).toBe(offset);
      expect(call.total).toBe(totalBytes);
      const chunkBytes = base64ToBytes(call.base64);
      reconstructed.set(chunkBytes, offset);
      offset += chunkBytes.length;
    }
    expect(offset).toBe(totalBytes);
    expect(reconstructed).toEqual(data);
    expect(progressCalls.length).toBe(8);
    expect(progressCalls[7]).toBe(totalBytes);
  });

  // --- 2. Concurrency limit enforcement (MAX_CONCURRENT_UPLOADS = 3) ---
  it("strictly bounds concurrent uploads to MAX_CONCURRENT_UPLOADS (3) under high load", async () => {
    let currentConcurrent = 0;
    let maxObservedConcurrent = 0;

    // Simulate async server latency per chunk
    mockBridge.setHandler("oars.sftp.write", async (payload: any) => {
      currentConcurrent++;
      maxObservedConcurrent = Math.max(maxObservedConcurrent, currentConcurrent);
      await new Promise((r) => setTimeout(r, 20));
      currentConcurrent--;
      const chunkLen = base64ToBytes(payload.base64).length;
      return { ok: true, written: payload.offset + chunkLen, done: payload.offset + chunkLen >= payload.total };
    });

    const onRefresh = vi.fn();
    const { result } = renderHook(() =>
      useFileTransfers({ serverId: "srv-test", onRefreshAfterMutation: onRefresh })
    );

    // Enqueue 9 file uploads (each 100KB = 2 chunks)
    const files = Array.from({ length: 9 }, (_, i) => ({
      file: createMockFile(`load-${i}.bin`, new Uint8Array(100 * 1024)),
      relativePath: undefined,
    }));

    await act(async () => {
      await result.current.startUploads(files, rpFromUtf8("/target"));
    });

    // Wait for all uploads to complete
    await vi.waitFor(
      () => {
        expect(result.current.uploads.jobs.length).toBe(9);
        expect(result.current.uploads.jobs.every((j) => j.status === "done")).toBe(true);
      },
      { timeout: 4000 }
    );

    expect(maxObservedConcurrent).toBeLessThanOrEqual(MAX_CONCURRENT_UPLOADS);
    expect(maxObservedConcurrent).toBe(MAX_CONCURRENT_UPLOADS);
    expect(result.current.uploads.active).toBe(0);
    expect(onRefresh).toHaveBeenCalled();
  });

  // --- 3. Cancellation mid-flight and rapid cancellation stress ---
  it("cancels mid-flight multi-chunk upload immediately and cleans up backend", async () => {
    const cancelSpy = mockBridge.spyOn("oars.sftp.cancel");
    let chunkCount = 0;
    let cancelTriggered = false;

    const onRefresh = vi.fn();
    const { result } = renderHook(() =>
      useFileTransfers({ serverId: "srv-test", onRefreshAfterMutation: onRefresh })
    );

    mockBridge.setHandler("oars.sftp.write", async (payload: any) => {
      chunkCount++;
      if (chunkCount === 2 && !cancelTriggered) {
        cancelTriggered = true;
        // Trigger cancellation in the middle of chunk 2
        void result.current.cancelUpload(payload.transfer_id);
      }
      await new Promise((r) => setTimeout(r, 40));
      const chunkLen = base64ToBytes(payload.base64).length;
      return { ok: true, written: payload.offset + chunkLen, done: false };
    });

    const file = createMockFile("cancel-me.bin", new Uint8Array(500 * 1024)); // 8 chunks

    await act(async () => {
      void result.current.startUploads([{ file, relativePath: undefined }], rpFromUtf8("/target"));
    });

    await vi.waitFor(
      () => {
        expect(result.current.uploads.jobs[0]?.status).toBe("canceled");
      },
      { timeout: 3000 }
    );

    expect(cancelSpy).toHaveBeenCalled();
    expect(result.current.uploads.active).toBe(0);
    // Should NOT have sent all 8 chunks
    expect(chunkCount).toBeLessThan(8);
  });

  it("handles rapid cancellation storm across queued and running jobs without state corruption", async () => {
    mockBridge.setHandler("oars.sftp.write", async (payload: any) => {
      await new Promise((r) => setTimeout(r, 40));
      const chunkLen = base64ToBytes(payload.base64).length;
      return { ok: true, written: payload.offset + chunkLen, done: false };
    });

    const { result } = renderHook(() =>
      useFileTransfers({ serverId: "srv-test", onRefreshAfterMutation: () => {} })
    );

    const intents = Array.from({ length: 12 }, (_, i) => ({
      file: createMockFile(`storm-${i}.bin`, new Uint8Array(200 * 1024)),
      relativePath: undefined,
    }));

    await act(async () => {
      void result.current.startUploads(intents, rpFromUtf8("/target"));
    });

    // Rapidly cancel all jobs almost simultaneously
    await act(async () => {
      const jobs = result.current.uploads.jobs;
      await Promise.all(jobs.map((j) => result.current.cancelUpload(j.transferId)));
    });

    await vi.waitFor(() => {
      const jobs = result.current.uploads.jobs;
      expect(jobs.every((j) => j.status === "canceled")).toBe(true);
      expect(result.current.uploads.active).toBe(0);
    });
  });

  it("handles backend cancel RPC error gracefully during cancellation without unhandled rejection", async () => {
    mockBridge.setHandler("oars.sftp.cancel", async () => {
      throw new Error("Network timeout during cancel");
    });
    mockBridge.setHandler("oars.sftp.write", async (payload: any) => {
      await new Promise((r) => setTimeout(r, 20));
      const chunkLen = base64ToBytes(payload.base64).length;
      return { ok: true, written: payload.offset + chunkLen, done: false };
    });

    const file = createMockFile("cancel-err.bin", new Uint8Array(200 * 1024));
    const job = uploadJobFor("srv-test", rpFromUtf8("/target"), file);

    let isCancelled = false;
    setTimeout(() => {
      isCancelled = true;
    }, 5);

    const completed = await uploadFileChunks(
      job,
      () => isCancelled,
      () => {}
    );

    expect(completed).toBe(false);
  });

  // --- 4. Short write and server error fault injection ---
  it("rejects immediately on server short write (written !== expected)", async () => {
    mockBridge.setHandler("oars.sftp.write", async (payload: any) => {
      // Return partial write instead of full chunk
      return { ok: true, written: payload.offset + 1000, done: false };
    });

    const file = createMockFile("short.bin", new Uint8Array(65536 * 2));
    const job = uploadJobFor("srv-test", rpFromUtf8("/target"), file);

    await expect(
      uploadFileChunks(
        job,
        () => false,
        () => {}
      )
    ).rejects.toThrow(/short write/);
  });

  it("handles server write exception by failing job and resetting active count", async () => {
    mockBridge.setHandler("oars.sftp.write", async () => {
      throw new Error("Disk full (ENOSPC)");
    });

    const { result } = renderHook(() =>
      useFileTransfers({ serverId: "srv-test", onRefreshAfterMutation: () => {} })
    );

    const file = createMockFile("disk-full.bin", new Uint8Array(100 * 1024));

    await act(async () => {
      await result.current.startUploads([{ file, relativePath: undefined }], rpFromUtf8("/target"));
    });

    await vi.waitFor(() => {
      expect(result.current.uploads.jobs[0].status).toBe("failed");
      expect(result.current.uploads.jobs[0].error).toContain("Disk full (ENOSPC)");
      expect(result.current.uploads.active).toBe(0);
    });
  });

  // --- 5. Directory structure creation and path traversal validation ---
  it("validates and creates nested remote directories in parent-before-child order", async () => {
    const mkdirSpy = mockBridge.spyOn("oars.sftp.mkdir");

    mockBridge.setHandler("oars.sftp.stat", async () => {
      throw new Error("not found");
    });
    mockBridge.setHandler("oars.sftp.mkdir", async () => {
      return { ok: true };
    });

    const paths = uploadDirectoryPaths(rpFromUtf8("/srv/app"), [
      "src/components/Button.tsx",
      "src/utils/math.ts",
      "public/assets/logo.svg",
    ]);

    expect(paths).toEqual([
      { utf8: "/srv/app/src" },
      { utf8: "/srv/app/src/components" },
      { utf8: "/srv/app/src/utils" },
      { utf8: "/srv/app/public" },
      { utf8: "/srv/app/public/assets" },
    ]);

    for (const p of paths) {
      await ensureRemoteDirectoryPath("srv-test", p);
    }

    expect(mkdirSpy).toHaveBeenCalledTimes(5);
  });

  it("rejects path traversal attempts in relative paths", () => {
    expect(() => validateUploadRelativePath("../secret.pem")).toThrow("invalid folder name");
    expect(() => validateUploadRelativePath("/etc/passwd")).toThrow("stay inside the selected folder");
    expect(() => validateUploadRelativePath("foo\\bar")).toThrow("stay inside the selected folder");
    expect(() => validateUploadRelativePath("foo/\0/bar")).toThrow("invalid folder name");
    expect(() => validateUploadRelativePath("foo/./bar")).toThrow("invalid folder name");
  });
});

describe("SFTP File Editor State Model & I/O Stress Harness", () => {
  beforeEach(() => {
    mockBridge.reset();
    mockBridge.install();
  });

  // --- 1. Editor Chunk Reading Stress ---
  it("reads 0-byte file returning empty text and valid SHA-256", async () => {
    mockBridge.setVirtualFile("/empty.txt", new Uint8Array(0));
    const { text, sha256 } = await readRemoteFileChunks("srv-test", rpFromUtf8("/empty.txt"));

    expect(text).toBe("");
    expect(sha256).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("reads multi-chunk 200KB file with exact chunk assembly", async () => {
    const rawContent = "console.log('line');\n".repeat(10000); // ~210KB
    mockBridge.setVirtualFile("/code.js", rawContent);

    const progress: number[] = [];
    const { text, sha256 } = await readRemoteFileChunks(
      "srv-test",
      rpFromUtf8("/code.js"),
      (bytes) => progress.push(bytes)
    );

    expect(text).toBe(rawContent);
    expect(progress.length).toBeGreaterThanOrEqual(4);
    expect(sha256).toBe(await sha256Hex(new TextEncoder().encode(rawContent)));
  });

  it("throws descriptive error when server returns 0-byte chunk before EOF", async () => {
    mockBridge.setHandler("oars.sftp.read", async () => {
      return { ok: true, base64: "", eof: false };
    });

    await expect(readRemoteFileChunks("srv-test", rpFromUtf8("/stuck.txt"))).rejects.toThrow(
      "The remote file returned no data before EOF."
    );
  });

  // --- 2. 768KB Buffer Cap & Boundary Checks ---
  it("allows opening files up to exactly EDITOR_MAX_BYTES (768,000 bytes)", async () => {
    const exactMax = new Uint8Array(EDITOR_MAX_BYTES);
    exactMax.fill(0x61); // 'a'
    mockBridge.setVirtualFile("/max.txt", exactMax);

    const { text } = await readRemoteFileChunks("srv-test", rpFromUtf8("/max.txt"));
    expect(text.length).toBe(EDITOR_MAX_BYTES);
  });

  it("openEditor immediately rejects files exceeding EDITOR_MAX_BYTES without issuing reads", async () => {
    const readSpy = mockBridge.spyOn("oars.sftp.read");
    const { result } = renderHook(() =>
      useFileEditor({ serverId: "srv-test", onRefreshAfterMutation: () => {} })
    );

    const oversizedEntry: SftpEntry = {
      name: rpFromUtf8("huge.txt"),
      display: "huge.txt",
      kind: "file",
      size: 768_001,
      mode: "-rw-r--r--",
      mtime: 1700000000,
      uid: 1000,
      gid: 1000,
      link_target: null,
    };

    await act(async () => {
      await result.current.openEditor(oversizedEntry, rpFromUtf8("/huge.txt"));
    });

    expect(result.current.editor).not.toBeNull();
    expect(result.current.editor?.tooLarge).toBe(true);
    expect(result.current.editor?.phase).toBe("error");
    expect(result.current.editor?.error).toContain("the editor handles text files up to");
    expect(readSpy).not.toHaveBeenCalled();
  });

  it("detects and rejects files that grow beyond 768KB mid-read", async () => {
    // Initial read returns 500KB, next returns 300KB (total 800KB > 768KB)
    let call = 0;
    mockBridge.setHandler("oars.sftp.read", async () => {
      call++;
      if (call === 1) {
        return { ok: true, base64: bytesToBase64(new Uint8Array(500 * 1024)), eof: false };
      }
      return { ok: true, base64: bytesToBase64(new Uint8Array(300 * 1024)), eof: true };
    });

    await expect(readRemoteFileChunks("srv-test", rpFromUtf8("/growing.txt"))).rejects.toThrow(
      /grew beyond 750(\.0)? KB while it was opening/
    );
  });

  // --- 3. UTF-8 Strictness & Boundary Splitting ---
  it("correctly decodes multi-byte UTF-8 code points split across 64KB chunk boundaries", async () => {
    // Construct a buffer where a 4-byte emoji 🚀 (0xF0 0x9F 0x99 0x80) is split across 64KB boundary
    const chunk1 = new Uint8Array(65536);
    chunk1.fill(0x61); // 'a'
    // Put first 2 bytes of 4-byte character at chunk 1 end
    chunk1[65534] = 0xf0;
    chunk1[65535] = 0x9f;

    const chunk2 = new Uint8Array(100);
    // Put last 2 bytes of 4-byte character at chunk 2 start
    chunk2[0] = 0x9a;
    chunk2[1] = 0x80; // 🚀 = F0 9F 9A 80
    for (let i = 2; i < 100; i++) chunk2[i] = 0x62; // 'b'

    let call = 0;
    mockBridge.setHandler("oars.sftp.read", async () => {
      call++;
      if (call === 1) return { ok: true, base64: bytesToBase64(chunk1), eof: false };
      return { ok: true, base64: bytesToBase64(chunk2), eof: true };
    });

    const { text } = await readRemoteFileChunks("srv-test", rpFromUtf8("/split-utf8.txt"));
    expect(text.includes("🚀")).toBe(true);
    expect(text.length).toBe(65534 + 2 + 98); // 🚀 is 2 code units in JS UTF-16
  });

  it("strictly rejects non-UTF-8 binary data", async () => {
    const invalidUtf8 = new Uint8Array([0xff, 0xfe, 0xfd, 0x80, 0x81]);
    mockBridge.setVirtualFile("/binary.bin", invalidUtf8);

    await expect(readRemoteFileChunks("srv-test", rpFromUtf8("/binary.bin"))).rejects.toThrow(
      "This file is not valid UTF-8 text and cannot be edited in the browser."
    );
  });

  // --- 4. SHA-256 Computation & Optimistic Locking Conflict Detection ---
  it("computes NIST-compliant SHA-256 digests", async () => {
    // NIST Standard Vectors
    const emptySha = await sha256Hex(new Uint8Array(0));
    expect(emptySha).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const abcSha = await sha256Hex(new TextEncoder().encode("abc"));
    expect(abcSha).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    const foxSha = await sha256Hex(
      new TextEncoder().encode("The quick brown fox jumps over the lazy dog")
    );
    expect(foxSha).toBe("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
  });

  it("passes exact optimistic locking parameters during save", async () => {
    const saveSpy = mockBridge.spyOn("oars.sftp.save");
    mockBridge.setHandler("oars.sftp.save", async () => ({ ok: true }));

    const initialSha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const result = await writeRemoteFileAtomic("srv-test", rpFromUtf8("/test.txt"), "hello world", {
      size: 3,
      mtime: 1700000000,
      sha256: initialSha,
    });

    expect(saveSpy).toHaveBeenCalledWith({
      server_id: "srv-test",
      path: { utf8: "/test.txt" },
      base64: bytesToBase64(new TextEncoder().encode("hello world")),
      expected_size: 3,
      expected_mtime: 1700000000,
      expected_sha256: initialSha,
    });

    expect(result.sha256).toBe(await sha256Hex(new TextEncoder().encode("hello world")));
  });

  it("handles optimistic locking conflicts by setting conflict banner and preserving unsaved text", async () => {
    const initialText = "Initial server content";
    mockBridge.setVirtualFile("/conflict-target.txt", initialText);

    const onRefresh = vi.fn();
    const { result } = renderHook(() =>
      useFileEditor({ serverId: "srv-test", onRefreshAfterMutation: onRefresh })
    );

    const entry: SftpEntry = {
      name: rpFromUtf8("conflict-target.txt"),
      display: "conflict-target.txt",
      kind: "file",
      size: initialText.length,
      mode: "-rw-r--r--",
      mtime: 1700000000,
      uid: 1000,
      gid: 1000,
      link_target: null,
    };

    // Open file
    await act(async () => {
      await result.current.openEditor(entry, rpFromUtf8("/conflict-target.txt"));
    });

    expect(result.current.editor?.phase).toBe("editing");
    expect(result.current.editor?.content).toBe(initialText);

    // User edits content
    act(() => {
      result.current.updateEditorContent("My local unsaved edits");
    });
    expect(result.current.editor?.dirty).toBe(true);

    // Mock backend conflict refusal
    mockBridge.setHandler("oars.sftp.save", async () => {
      return { ok: false, error: "conflict: the file changed on the server (mtime); reload and review" };
    });

    // Save attempt
    await act(async () => {
      await result.current.saveEditor();
    });

    // Editor should be in conflict state, NOT generic error state, and user edits preserved!
    expect(result.current.editor?.phase).toBe("editing");
    expect(result.current.editor?.conflict).toContain("conflict:");
    expect(result.current.editor?.content).toBe("My local unsaved edits");
    expect(result.current.editor?.dirty).toBe(true);
    expect(result.current.editor?.error).toBeNull();
  });

  // --- 5. Race Conditions & Rapid Interactions in Editor ---
  it("discards stale async open responses when user rapidly switches files", async () => {
    mockBridge.setVirtualFile("/fileA.txt", "Content of File A");
    mockBridge.setVirtualFile("/fileB.txt", "Content of File B");

    // Make File A read take 100ms, File B read take 10ms
    mockBridge.setHandler("oars.sftp.read", async (payload: any) => {
      const isFileA = payload.path.utf8.includes("fileA");
      await new Promise((r) => setTimeout(r, isFileA ? 100 : 10));
      const content = isFileA ? "Content of File A" : "Content of File B";
      return { ok: true, base64: bytesToBase64(new TextEncoder().encode(content)), eof: true };
    });

    const { result } = renderHook(() =>
      useFileEditor({ serverId: "srv-test", onRefreshAfterMutation: () => {} })
    );

    const entryA: SftpEntry = { name: rpFromUtf8("fileA.txt"), display: "fileA.txt", kind: "file", size: 17, mode: "-rw-r--r--", mtime: 100, uid: 1000, gid: 1000, link_target: null };
    const entryB: SftpEntry = { name: rpFromUtf8("fileB.txt"), display: "fileB.txt", kind: "file", size: 17, mode: "-rw-r--r--", mtime: 200, uid: 1000, gid: 1000, link_target: null };

    await act(async () => {
      // Rapid sequential open
      void result.current.openEditor(entryA, rpFromUtf8("/fileA.txt"));
      void result.current.openEditor(entryB, rpFromUtf8("/fileB.txt"));
    });

    // Wait for all promises to settle
    await vi.waitFor(
      () => {
        expect(result.current.editor?.phase).toBe("editing");
        expect(result.current.editor?.content).toBe("Content of File B");
        expect(result.current.editor?.display).toBe("/fileB.txt");
      },
      { timeout: 500 }
    );

    // Ensure File A's delayed response never overwrote File B
    await new Promise((r) => setTimeout(r, 120));
    expect(result.current.editor?.content).toBe("Content of File B");
    expect(result.current.editor?.display).toBe("/fileB.txt");
  });

  it("resets editor state and ignores pending I/O when serverId switches", async () => {
    mockBridge.setVirtualFile("/file1.txt", "Content 1");
    mockBridge.setHandler("oars.sftp.read", async () => {
      await new Promise((r) => setTimeout(r, 50));
      return { ok: true, base64: bytesToBase64(new TextEncoder().encode("Content 1")), eof: true };
    });

    let currentServer = "srv-1";
    const { result, rerender } = renderHook(
      ({ serverId }) => useFileEditor({ serverId, onRefreshAfterMutation: () => {} }),
      { initialProps: { serverId: currentServer } }
    );

    const entry: SftpEntry = { name: rpFromUtf8("file1.txt"), display: "file1.txt", kind: "file", size: 9, mode: "-rw-r--r--", mtime: 100, uid: 1000, gid: 1000, link_target: null };

    act(() => {
      void result.current.openEditor(entry, rpFromUtf8("/file1.txt"));
    });

    // Immediately switch serverId
    currentServer = "srv-2";
    rerender({ serverId: currentServer });

    expect(result.current.editor).toBeNull();

    // Wait past the delay
    await new Promise((r) => setTimeout(r, 80));
    expect(result.current.editor).toBeNull();
  });
});
