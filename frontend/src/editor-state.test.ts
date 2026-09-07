import { describe, expect, it } from "vitest";
import {
  EDITOR_MAX_BYTES,
  chunkOffsets,
  editorSaveParams,
  isConflictError,
  savedIdentityFallback,
  sha256Hex,
} from "./editor-state";

describe("chunk offsets", () => {
  it("plans exact explicit offsets for a file read", () => {
    expect(chunkOffsets(150_000, 65_536)).toEqual([0, 65_536, 131_072]);
    expect(chunkOffsets(65_536, 65_536)).toEqual([0]);
    expect(chunkOffsets(0, 65_536)).toEqual([0]);
    expect(chunkOffsets(10, 4)).toEqual([0, 4, 8]);
  });

  it("handles non-positive total or chunkSize gracefully", () => {
    expect(chunkOffsets(-50, 65_536)).toEqual([0]);
    expect(chunkOffsets(100, 0)).toEqual([0]);
    expect(chunkOffsets(100, -10)).toEqual([0]);
    expect(chunkOffsets(0, 0)).toEqual([0]);
  });
});

describe("editor identity", () => {
  it("maps the opened identity to the save preflight payload", () => {
    expect(editorSaveParams({ size: 12, mtime: 1577836800, sha256: "ab".repeat(32) })).toEqual({
      expected_size: 12,
      expected_mtime: 1577836800,
      expected_sha256: "ab".repeat(32),
    });
  });

  it("recognizes backend conflict errors and nothing else", () => {
    expect(isConflictError("conflict: the file changed on the server (size); reload and review before saving")).toBe(true);
    expect(isConflictError("conflict:")).toBe(true);
    expect(isConflictError("Conflict: uppercase")).toBe(false);
    expect(isConflictError("some other error conflict: middle")).toBe(false);
    expect(isConflictError("permission denied")).toBe(false);
    expect(isConflictError("")).toBe(false);
  });

  it("caps the editor at the bridge payload budget", () => {
    expect(EDITOR_MAX_BYTES * (4 / 3)).toBeLessThanOrEqual(1024 * 1024 - 1024);
  });

  it("computes a hex sha256 and a same-second save fallback with flooring", async () => {
    const hex = await sha256Hex(new TextEncoder().encode("abc"));
    expect(hex).toMatch(/^[0-9a-f]{64}$/);

    const emptyHex = await sha256Hex(new Uint8Array(0));
    expect(emptyHex).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const fb = savedIdentityFallback(3, hex, 1000.85);
    expect(fb).toEqual({ size: 3, mtime: 1000, sha256: hex });
  });
});
