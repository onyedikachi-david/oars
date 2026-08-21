import { api } from "../../../bridge";
import {
  EDITOR_MAX_BYTES,
  editorSaveParams,
  sha256Hex,
  type EditorIdentity,
} from "../../../editor-state";
import {
  base64ToBytes,
  bytesToBase64,
  type RemotePath,
} from "../../../sftp-path";
import type { SftpSaveParams } from "../../../types";
import { fmtBytes } from "../formatters";

export async function readRemoteFileChunks(
  serverId: string,
  path: RemotePath,
  onProgress?: (loadedBytes: number) => void,
): Promise<{ text: string; sha256: string }> {
  const chunks: Uint8Array[] = [];
  let offset = 0;

  while (true) {
    const remaining = EDITOR_MAX_BYTES - offset;
    const max = Math.min(64 * 1024, Math.max(1, remaining + 1));
    const r = await api.sftp.read(serverId, path, offset, max);
    const chunk = base64ToBytes(r.base64);

    if (offset + chunk.length > EDITOR_MAX_BYTES) {
      throw new Error(
        `This file grew beyond ${fmtBytes(EDITOR_MAX_BYTES)} while it was opening. Reload after the remote write finishes.`,
      );
    }

    chunks.push(chunk);
    offset += chunk.length;
    onProgress?.(offset);

    if (r.eof) break;
    if (chunk.length === 0) {
      throw new Error("The remote file returned no data before EOF.");
    }
  }

  const merged = new Uint8Array(offset);
  let writeOffset = 0;
  for (const c of chunks) {
    merged.set(c, writeOffset);
    writeOffset += c.length;
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(merged);
  } catch {
    throw new Error("This file is not valid UTF-8 text and cannot be edited in the browser.");
  }
  const sha = await sha256Hex(merged);
  return { text, sha256: sha };
}

export async function writeRemoteFileAtomic(
  serverId: string,
  path: RemotePath,
  content: string,
  expected?: EditorIdentity | SftpSaveParams,
): Promise<{ sha256: string; updatedPath: RemotePath }> {
  const bytes = new TextEncoder().encode(content);
  const base64 = bytesToBase64(bytes);
  const params =
    expected && "sha256" in expected
      ? editorSaveParams(expected)
      : expected;

  await api.sftp.save(serverId, path, base64, params);

  const sha = await sha256Hex(bytes);
  return {
    sha256: sha,
    updatedPath: path,
  };
}
