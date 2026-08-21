import { api } from "../../../bridge";
import {
  bytesToBase64,
  rpDisplay,
  type RemotePath,
} from "../../../sftp-path";
import {
  nextUploadOffset,
  UPLOAD_CHUNK_BYTES,
  type UploadJob,
} from "../../../transfer-model";

export async function ensureRemoteDirectoryPath(
  serverId: string,
  path: RemotePath,
): Promise<void> {
  try {
    const existing = await api.sftp.stat(serverId, path);
    if (existing.entry.kind !== "dir") {
      throw new Error(`${rpDisplay(path)} already exists and is not a folder.`);
    }
    return;
  } catch (statError) {
    try {
      await api.sftp.mkdir(serverId, path);
    } catch (mkdirError) {
      try {
        const raced = await api.sftp.stat(serverId, path);
        if (raced.entry.kind === "dir") return;
      } catch {
        // surface the mkdir failure below
      }
      throw mkdirError instanceof Error ? mkdirError : statError;
    }
  }
}

export async function uploadFileChunks(
  job: UploadJob,
  isCancelled: (transferId: number) => boolean,
  onProgress: (bytesSent: number) => void,
): Promise<boolean> {
  const { transferId, serverId: server, path, file, total } = job;
  let offset = 0;

  if (total === 0) {
    const empty = await api.sftp.write(server, path, 0, "", transferId, 0);
    if (!empty.done || empty.written !== 0) {
      throw new Error("The server did not finalize the empty file.");
    }
    return true;
  }

  while (offset < total) {
    if (isCancelled(transferId)) {
      await api.sftp.cancel(server, transferId).catch(() => {});
      return false;
    }
    const chunk = file.slice(offset, Math.min(offset + UPLOAD_CHUNK_BYTES, total));
    const buf = new Uint8Array(await chunk.arrayBuffer());
    const r = await api.sftp.write(
      server,
      path,
      offset,
      bytesToBase64(buf),
      transferId,
      total,
    );
    offset = nextUploadOffset(offset, buf.length, r.written, total);
    onProgress(offset);
  }

  return true;
}
