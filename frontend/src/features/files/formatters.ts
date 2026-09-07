import { BridgeError } from "../../bridge";
import type { SftpEntry } from "../../types";

export function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function fmtTime(epoch: number): string {
  if (!epoch) return "—";
  const d = new Date(epoch * 1000);
  return `${d.toLocaleDateString([], { month: "short", day: "numeric" })} ${d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

export function errMessage(e: unknown): string {
  return e instanceof BridgeError ? e.message : e instanceof Error ? e.message : String(e);
}

export function transferDisplay(path: string): string {
  try {
    return decodeURIComponent(escape(path));
  } catch {
    return "\uFFFD".repeat(path.length) || path;
  }
}

export function kindLabel(kind: SftpEntry["kind"]): string {
  return kind === "file" ? "File" : kind === "dir" ? "Folder" : kind === "symlink" ? "Symlink" : "Other";
}

export function isZipEntry(entry: SftpEntry): boolean {
  return entry.kind === "file" && entry.display.toLowerCase().endsWith(".zip");
}

export function modeString(mode: number): string {
  const chars = ["r", "w", "x"];
  let out = "";
  for (let g = 0; g < 3; g++) {
    for (let b = 0; b < 3; b++) {
      out += (mode >> ((2 - g) * 3 + (2 - b))) & 1 ? chars[b] : "-";
    }
  }
  if (mode & 0o4000) out = out.slice(0, 2) + (out[2] === "x" ? "s" : "S") + out.slice(3);
  if (mode & 0o2000) out = out.slice(0, 5) + (out[5] === "x" ? "s" : "S") + out.slice(6);
  if (mode & 0o1000) out = out.slice(0, 8) + (out[8] === "x" ? "t" : "T");
  return out;
}
