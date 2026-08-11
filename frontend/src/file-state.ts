// Directory state machine and selection model for the SFTP workspace
// (spec 05 §4.1/§4.3). Pure functions — no React, no bridge — so stale
// responses, the 30 s directory cache, and selection ranges are all
// unit-testable.

import type { RemotePath, SftpEntry } from "./types";
import { rpSerialize } from "./sftp-path";

export const DIR_CACHE_TTL_MS = 30_000;

export interface DirListing {
  entries: SftpEntry[];
  truncated: boolean;
}

export interface DirSnapshot {
  serverId: string;
  /** The path the snapshot belongs to — a late response for another
   * server or path must never replace the current listing. */
  path: RemotePath;
  pathKey: string;
  listing: DirListing;
  /** True while the authoritative fetch is in flight (first load or an
   * explicit refresh after the cache expired). */
  loading: boolean;
  /** True while a background refresh (cache hit) is in flight. */
  refreshing: boolean;
  error: string | null;
  /** Epoch ms of the last successful load; drives the 30 s cache. */
  loadedAt: number;
}

export interface DirRequestToken {
  generation: number;
  serverId: string;
  pathKey: string;
}

/** Source-bound identity check: a response only applies when its
 * generation, server, and path all match the current request. */
export function isCurrentDirRequest(
  token: DirRequestToken,
  generation: number,
  serverId: string,
  pathKey: string,
): boolean {
  return token.generation === generation && token.serverId === serverId && token.pathKey === pathKey;
}

export function emptySnapshot(serverId: string, path: RemotePath): DirSnapshot {
  return {
    serverId,
    path,
    pathKey: rpSerialize(path),
    listing: { entries: [], truncated: false },
    loading: false,
    refreshing: false,
    error: null,
    loadedAt: 0,
  };
}

/** In-memory 30 s directory cache (spec 05 §4.3): navigating back to a
 * recently listed directory is instant; the UI then refreshes in the
 * background. */
export class DirCache {
  private entries = new Map<string, { listing: DirListing; loadedAt: number }>();

  get(serverId: string, pathKey: string, now: number): DirListing | null {
    const hit = this.entries.get(`${serverId}\u0000${pathKey}`);
    if (!hit) return null;
    if (now - hit.loadedAt > DIR_CACHE_TTL_MS) {
      this.entries.delete(`${serverId}\u0000${pathKey}`);
      return null;
    }
    return hit.listing;
  }

  set(serverId: string, pathKey: string, listing: DirListing, now: number): void {
    this.entries.set(`${serverId}\u0000${pathKey}`, { listing, loadedAt: now });
  }

  clear(): void {
    this.entries.clear();
  }
}

// --- Selection model ---------------------------------------------------------

export interface SelectionModel {
  /** Ordered keys (insertion order); order drives download-as-zip. */
  keys: string[];
  /** The anchor for shift-click ranges. */
  anchor: string | null;
}

export function emptySelection(): SelectionModel {
  return { keys: [], anchor: null };
}

/** Plain click: select exactly this entry and make it the anchor. */
export function selectionSelectOnly(sel: SelectionModel, key: string): SelectionModel {
  return { keys: [key], anchor: key };
}

/** ⌘/Ctrl-click: toggle membership; the anchor follows when added. */
export function selectionToggle(sel: SelectionModel, key: string): SelectionModel {
  const keys = sel.keys.includes(key) ? sel.keys.filter((k) => k !== key) : [...sel.keys, key];
  return { keys, anchor: sel.keys.includes(key) ? sel.anchor : key };
}

/** Shift-click: select the displayed range from the anchor to `toKey`. */
export function selectionRange(sel: SelectionModel, displayed: string[], toKey: string): SelectionModel {
  if (sel.anchor === null || !displayed.includes(toKey)) return selectionSelectOnly(sel, toKey);
  const from = displayed.indexOf(sel.anchor);
  const to = displayed.indexOf(toKey);
  const [lo, hi] = from <= to ? [from, to] : [to, from];
  const keys = [...new Set([...sel.keys, ...displayed.slice(lo, hi + 1)])];
  return { keys, anchor: sel.anchor };
}

export function selectionAdd(sel: SelectionModel, key: string): SelectionModel {
  return sel.keys.includes(key) ? sel : { keys: [...sel.keys, key], anchor: sel.anchor };
}

export function selectionClear(): SelectionModel {
  return emptySelection();
}

export function selectionAll(keys: string[]): SelectionModel {
  return { keys: [...keys], anchor: keys.length > 0 ? keys[keys.length - 1] : null };
}

export function selectionHas(sel: SelectionModel, key: string): boolean {
  return sel.keys.includes(key);
}

/** Convert an ls-style permission string to the editable octal form. */
export function permissionStringToOctal(mode: string): string {
  const bits = mode.length >= 10 ? mode.slice(-9) : mode.slice(0, 9);
  if (bits.length !== 9) return "";
  let value = 0;
  for (let i = 0; i < bits.length; i++) {
    const ch = bits[i];
    if (ch !== "-") value |= 1 << (8 - i);
  }
  if (bits[2] === "s" || bits[2] === "S") value |= 0o4000;
  if (bits[5] === "s" || bits[5] === "S") value |= 0o2000;
  if (bits[8] === "t" || bits[8] === "T") value |= 0o1000;
  return value.toString(8).padStart(value > 0o777 ? 4 : 3, "0");
}
