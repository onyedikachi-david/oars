// Upload/download transfer model for the SFTP workspace (spec 05 §5).
// Pure state machine for upload jobs (chunk loop progress, cancel,
// failure) plus the transfer-id generator. The backend's `oars.sftp.poll`
// snapshot carries every transfer (uploads register under the
// frontend's id on the first chunk); the local model adds the File
// handle, exact offsets, and display metadata.

import type { RemotePath, SftpEntry } from "./types";
import { rpDisplay, rpFromBytes, rpFromUtf8, rpJoin, rpSerialize, utf8ToBytes } from "./sftp-path";

export const UPLOAD_CHUNK_BYTES = 64 * 1024;
export const MAX_CONCURRENT_UPLOADS = 3;

/** Nonzero, cryptographically random transfer id (spec 05 §5: the id is
 * the frontend's unguessable handle into the worker's transfer map). */
export function nextTransferId(): number {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  const id = buf[0] >>> 0;
  return id === 0 ? 1 : id;
}

export type UploadStatus = "queued" | "running" | "done" | "failed" | "canceled";

export interface UploadJob {
  transferId: number;
  serverId: string;
  /** Full remote destination path (raw bytes). */
  path: RemotePath;
  /** UI display of the destination (never used for operations). */
  display: string;
  file: File;
  bytesSent: number;
  total: number;
  status: UploadStatus;
  error: string;
}

export interface UploadModel {
  jobs: UploadJob[];
  /** Number of jobs currently running their chunk loop (≤ 3). */
  active: number;
}

export function emptyUploadModel(): UploadModel {
  return { jobs: [], active: 0 };
}

/** Builds the upload job for a local File. `relativePath` (when present,
 * from `webkitRelativePath`) makes the destination mirror the local
 * folder structure — this is what makes directory upload real instead of
 * a flat fake. */
export function uploadJobFor(
  serverId: string,
  parent: RemotePath,
  file: File,
  relativePath?: string,
): UploadJob {
  const name = rpFromBytes(utf8ToBytes(relativePath ?? file.name));
  const path = rpJoin(parent, name);
  return {
    transferId: nextTransferId(),
    serverId,
    path,
    display: rpDisplay(path),
    file,
    bytesSent: 0,
    total: file.size,
    status: "queued",
    error: "",
  };
}

/** Validate a browser-supplied relative path before it becomes a remote path. */
export function validateUploadRelativePath(relativePath: string): string[] {
  if (relativePath.startsWith("/") || relativePath.includes("\\")) {
    throw new Error("Upload paths must stay inside the selected folder.");
  }
  const parts = relativePath.split("/");
  if (parts.length === 0 || parts.some((part) => part.length === 0 || part === "." || part === ".." || /[\0-\x1f\x7f]/.test(part))) {
    throw new Error("Upload path contains an invalid folder name.");
  }
  return parts;
}

/** Return unique remote directories in parent-before-child order. */
export function uploadDirectoryPaths(parent: RemotePath, relativePaths: Array<string | undefined>): RemotePath[] {
  const unique = new Map<string, RemotePath>();
  for (const relativePath of relativePaths) {
    if (!relativePath) continue;
    const parts = validateUploadRelativePath(relativePath);
    let current = parent;
    for (const part of parts.slice(0, -1)) {
      current = rpJoin(current, rpFromUtf8(part));
      unique.set(rpSerialize(current), current);
    }
  }
  return [...unique.values()];
}

/** The worker reports the cumulative partial-file size after each write. */
export function nextUploadOffset(offset: number, chunkLength: number, written: number, total: number): number {
  const expected = offset + chunkLength;
  if (!Number.isSafeInteger(written) || written !== expected || written > total) {
    throw new Error(`short write: remote offset ${written}, expected ${expected}`);
  }
  return written;
}

// --- Pure reducer -----------------------------------------------------------

export type UploadEvent =
  | { type: "register"; job: UploadJob }
  | { type: "start"; transferId: number }
  | { type: "progress"; transferId: number; bytesSent: number }
  | { type: "done"; transferId: number }
  | { type: "failed"; transferId: number; error: string }
  | { type: "canceled"; transferId: number };

export function uploadReducer(model: UploadModel, event: UploadEvent): UploadModel {
  switch (event.type) {
    case "register":
      return { jobs: [...model.jobs, event.job], active: model.active };
    case "start":
      if (!model.jobs.some((j) => j.transferId === event.transferId && j.status === "queued")) return model;
      return {
        jobs: model.jobs.map((j) => (j.transferId === event.transferId && j.status === "queued" ? { ...j, status: "running" } : j)),
        active: model.active + 1,
      };
    case "progress":
      return {
        jobs: model.jobs.map((j) => (j.transferId === event.transferId ? { ...j, bytesSent: event.bytesSent } : j)),
        active: model.active,
      };
    case "done": {
      const wasRunning = model.jobs.some((j) => j.transferId === event.transferId && j.status === "running");
      return {
        jobs: model.jobs.map((j) => (j.transferId === event.transferId ? { ...j, bytesSent: j.total, status: "done" } : j)),
        active: Math.max(0, model.active - (wasRunning ? 1 : 0)),
      };
    }
    case "failed": {
      const wasRunning = model.jobs.some((j) => j.transferId === event.transferId && j.status === "running");
      return {
        jobs: model.jobs.map((j) => (j.transferId === event.transferId ? { ...j, status: "failed", error: event.error } : j)),
        active: Math.max(0, model.active - (wasRunning ? 1 : 0)),
      };
    }
    case "canceled": {
      const wasRunning = model.jobs.some((j) => j.transferId === event.transferId && j.status === "running");
      return {
        jobs: model.jobs.map((j) => (j.transferId === event.transferId ? { ...j, status: "canceled", error: "" } : j)),
        active: Math.max(0, model.active - (wasRunning ? 1 : 0)),
      };
    }
  }
}

export function uploadActive(job: UploadJob): boolean {
  return job.status === "queued" || job.status === "running";
}

/** Directory upload feature detection (spec 05 §6): the packaged WebView
 * only supports directory upload when its File objects carry relative
 * paths. We never fake a flat upload when they are absent. */
export function directoryUploadSupported(): boolean {
  try {
    return "webkitRelativePath" in File.prototype;
  } catch {
    return false;
  }
}

export function fileRelativePath(file: File): string | undefined {
  const rel = (file as File & { webkitRelativePath?: string }).webkitRelativePath;
  return rel && rel.length > 0 ? rel : undefined;
}
