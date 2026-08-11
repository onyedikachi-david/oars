// Editor state helpers for the SFTP text editor (spec 05 §4.2). Pure
// functions: conflict discrimination, identity capture, and chunk math.

import type { SftpSaveParams } from "./types";

/**
 * The editor opens files up to this many bytes. The backend's inline
 * decode cap is 1 MiB, but the bridge payload budget is 1 MiB total
 * (SDK `max_message_bytes`), and a 1 MiB file base64-encodes to ~1.37 MB.
 * 768,000 bytes → exactly 1,024,000 base64 chars, which fits with room
 * for the JSON envelope. Larger files get an honest "too large" state.
 */
export const EDITOR_MAX_BYTES = 768_000;

/** The backend refuses a save with a "conflict:" message when the remote
 * file no longer matches the identity the editor opened. */
export function isConflictError(message: string): boolean {
  return message.startsWith("conflict:");
}

export interface EditorIdentity {
  size: number;
  mtime: number;
  /** Hex-encoded SHA-256 of the opened content. */
  sha256: string;
}

export function editorSaveParams(identity: EditorIdentity): SftpSaveParams {
  return {
    expected_size: identity.size,
    expected_mtime: identity.mtime,
    expected_sha256: identity.sha256,
  };
}

/** The identity after a successful save: the saved bytes are the new
 * content, but the remote mtime is only knowable from a fresh stat — the
 * editor re-stats after saving rather than guessing. This is the fallback
 * for the brief window before the stat lands. */
export function savedIdentityFallback(size: number, sha256: string, nowSec: number): EditorIdentity {
  return { size, mtime: Math.floor(nowSec), sha256 };
}

/** Hex-encoded SHA-256 of raw bytes (Web Crypto; the packaged WebView is
 * a secure context). */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  // A fresh, exactly-sized buffer: crypto.subtle needs a BufferSource and
  // a shared backing store would hash the wrong range.
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", copy.buffer);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Explicit-offset read plan: chunk starts for `total` bytes in
 * `chunkSize` pieces (spec 05 §5 — reads use exact offsets). */
export function chunkOffsets(total: number, chunkSize: number): number[] {
  if (total <= 0 || chunkSize <= 0) return [0];
  const offsets: number[] = [];
  for (let off = 0; off < total; off += chunkSize) offsets.push(off);
  return offsets;
}
