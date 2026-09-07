// Raw remote-path identity for the SFTP workspace (spec 05 §5).
// A `RemotePath` is either `{utf8}` (valid UTF-8 text) or `{base64}` (raw server bytes).
import type { RemotePath, SftpEntry } from "./types";
export type { RemotePath, SftpEntry };

const DOT = 0x2e; // "."
const SLASH = 0x2f; // "/"

export function utf8ToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** True when `bytes` is well-formed UTF-8. */
export function isValidUtf8(bytes: Uint8Array): boolean {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
}

/** Raw bytes of a RemotePath — the only form used to build operations. */
export function rpBytes(rp: RemotePath): Uint8Array {
  if (rp.utf8 !== undefined) return utf8ToBytes(rp.utf8);
  if (rp.base64 !== undefined) return base64ToBytes(rp.base64);
  return new Uint8Array(0);
}

/** Encode raw bytes as a RemotePath: utf8 when valid, else base64. */
export function rpFromBytes(bytes: Uint8Array): RemotePath {
  if (isValidUtf8(bytes)) return { utf8: new TextDecoder("utf-8").decode(bytes) };
  return { base64: bytesToBase64(bytes) };
}

export function rpFromUtf8(s: string): RemotePath {
  return { utf8: s };
}

export const ROOT: RemotePath = { utf8: "/" };

/** Stable identity string for React keys and cache maps. Two RemotePaths
 * with the same raw bytes always serialize identically. */
export function rpSerialize(rp: RemotePath): string {
  if (rp.utf8 !== undefined) return `u:${rp.utf8}`;
  if (rp.base64 !== undefined) return `b64:${rp.base64}`;
  return "u:";
}

/** UI display text: the utf8 form as-is, or raw bytes with invalid
 * sequences replaced (mirrors the backend's displayName). */
export function rpDisplay(rp: RemotePath): string {
  if (rp.utf8 !== undefined) return rp.utf8;
  if (rp.base64 !== undefined) return new TextDecoder("utf-8").decode(base64ToBytes(rp.base64));
  return "";
}

export function rpIsRoot(rp: RemotePath): boolean {
  const bytes = rpBytes(rp);
  return bytes.length === 1 && bytes[0] === SLASH;
}

/** Byte-level join: `parent + "/" + child`. A parent that already ends
 * with "/" (the root) contributes no extra separator. */
export function rpJoin(parent: RemotePath, child: RemotePath): RemotePath {
  const p = rpBytes(parent);
  const c = rpBytes(child);
  if (p.length === 0) return child;
  const sep = p[p.length - 1] === SLASH ? 0 : 1;
  const joined = new Uint8Array(p.length + sep + c.length);
  joined.set(p, 0);
  if (sep === 1) joined[p.length] = SLASH;
  joined.set(c, p.length + sep);
  return rpFromBytes(joined);
}

/** Byte-level dirname: everything before the final "/" ("" for a bare
 * name, "/" for a top-level entry). */
export function rpParent(rp: RemotePath): RemotePath {
  const bytes = rpBytes(rp);
  let last = -1;
  for (let i = bytes.length - 1; i >= 0; i--) {
    if (bytes[i] === SLASH) {
      last = i;
      break;
    }
  }
  if (last < 0) return ROOT;
  if (last === 0) return ROOT;
  return rpFromBytes(bytes.subarray(0, last));
}

/** Byte-level basename. */
export function rpBasename(rp: RemotePath): RemotePath {
  const bytes = rpBytes(rp);
  let start = bytes.length;
  for (let i = bytes.length - 1; i >= 0; i--) {
    if (bytes[i] === SLASH) {
      start = i + 1;
      break;
    }
  }
  return rpFromBytes(bytes.subarray(start));
}

/** Breadcrumb trail: [root, segment1, segment2, …] as RemotePaths, each
 * segment independently re-encoded so non-UTF-8 components stay raw. */
export function rpSplit(rp: RemotePath): RemotePath[] {
  const bytes = rpBytes(rp);
  const parts: RemotePath[] = [ROOT];
  let start = 0;
  const segments: Uint8Array[] = [];
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === SLASH) {
      if (i > start) segments.push(bytes.subarray(start, i));
      start = i + 1;
    }
  }
  if (start < bytes.length) segments.push(bytes.subarray(start));
  for (const seg of segments) parts.push(rpFromBytes(seg));
  return parts;
}

/** Cumulative path identities for breadcrumbs: root, /a, /a/b, ... */
export function rpBreadcrumbPaths(rp: RemotePath): RemotePath[] {
  const parts = rpSplit(rp);
  const paths: RemotePath[] = [ROOT];
  let current = ROOT;
  for (const part of parts.slice(1)) {
    current = rpJoin(current, part);
    paths.push(current);
  }
  return paths;
}

/** A rename or mkdir input is one POSIX path component, never a path. */
export function validateLeafName(name: string): string | null {
  if (name.length === 0) return "Enter a name.";
  if (name === "." || name === "..") return "Use a name other than . or ...";
  if (name.includes("/")) return "Names cannot contain a slash.";
  if (/[\0-\x1f\x7f]/.test(name)) return "Names cannot contain control characters.";
  return null;
}

/** Zip-destination stem: basename minus its final extension (spec 05 §5:
 * a folder named after the archive appears next to it). */
export function rpStem(rp: RemotePath): RemotePath {
  const base = rpBytes(rpBasename(rp));
  let cut = base.length;
  for (let i = base.length - 1; i >= 0; i--) {
    if (base[i] === DOT && i > 0) {
      cut = i;
      break;
    }
  }
  return rpFromBytes(base.subarray(0, cut));
}

/** Raw name bytes of an entry (decoded from name.base64 when present —
 * never from `display`). */
export function entryNameBytes(entry: SftpEntry): Uint8Array {
  return rpBytes(entry.name);
}

/** Stable React key for an entry row: serialized raw name bytes. */
export function entryKey(entry: SftpEntry): string {
  return rpSerialize(entry.name);
}

/** Hidden-item rule (spec 05 §4.1): the raw first byte is a dot. */
export function entryHidden(entry: SftpEntry): boolean {
  const bytes = entryNameBytes(entry);
  return bytes.length > 0 && bytes[0] === DOT;
}

/** True when the raw name is exactly "." or ".." (never sent by the
 * backend, but harmless to guard). */
export function entryIsDot(entry: SftpEntry): boolean {
  const bytes = entryNameBytes(entry);
  return (bytes.length === 1 && bytes[0] === DOT) || (bytes.length === 2 && bytes[0] === DOT && bytes[1] === DOT);
}
