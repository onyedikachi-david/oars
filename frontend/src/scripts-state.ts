// Pure state helpers for the Scripts workspace (spec 06). No React, no
// bridge: every rule here is unit-tested in scripts-state.test.ts.
//
// The backend owns expansion, validation, and redaction (spec 06 §5 — a
// client-side copy of the Zig lexer can never be authoritative). These
// helpers only shape UI state.

import type { BroadcastServerResult, Script, ScriptRunVars, ScriptVariable } from "./types";

/** The backend's exact variable-name charset: `[A-Za-z_][A-Za-z0-9_]*`
 *  (src/scripts.zig validName). Detects `{{name}}` placeholders only —
 *  anything else the backend rejects stays invisible in the editor table. */
const PLACEHOLDER_RE = /\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}/g;

export function detectVariables(body: string): string[] {
  const names: string[] = [];
  const seen = new Set<string>();
  let match: RegExpExecArray | null;
  PLACEHOLDER_RE.lastIndex = 0;
  while ((match = PLACEHOLDER_RE.exec(body)) !== null) {
    const name = match[1];
    if (!seen.has(name)) {
      seen.add(name);
      names.push(name);
    }
  }
  return names;
}

/** Reconciles detected placeholders with saved definitions so an edit
 *  preserves labels and secret defaults. Saved definitions for variables
 *  no longer in the body are kept (unused definitions are shown, not
 *  silently dropped). */
export function reconcileVariables(
  detected: string[],
  saved: ScriptVariable[]
): ScriptVariable[] {
  const out: ScriptVariable[] = detected.map((name) => {
    const existing = saved.find((v) => v.name === name);
    return existing ?? { name, label: "", secret_default: false };
  });
  for (const v of saved) {
    if (!out.some((o) => o.name === v.name)) out.push({ ...v });
  }
  return out;
}

/** Library filter: name + description + tags, case-insensitive. */
export function filterScripts(scripts: Script[], q: string, tag = ""): Script[] {
  const needle = q.trim().toLowerCase();
  const wantedTag = tag.trim().toLowerCase();
  return scripts.filter((s) => {
    const textMatches = !needle || `${s.name} ${s.description} ${s.tags.join(" ")}`.toLowerCase().includes(needle);
    const tagMatches = !wantedTag || s.tags.some((item) => item.toLowerCase() === wantedTag);
    return textMatches && tagMatches;
  });
}

export type RunValueMemory = Record<string, Record<string, string>>;

export function prefillRunValues(memory: RunValueMemory, script: Script): {
  values: Record<string, string>;
  promoted: Record<string, boolean>;
} {
  const remembered = memory[script.id] ?? {};
  return {
    values: Object.fromEntries(
      script.variables
        .filter((definition) => !definition.secret_default && remembered[definition.name] !== undefined)
        .map((definition) => [definition.name, remembered[definition.name]])
    ),
    promoted: {},
  };
}

/** Keep only non-secret values, scoped to one script. Effective secrets are
 * removed immediately so a later run cannot demote or expose them. */
export function rememberRunValues(memory: RunValueMemory, script: Script, vars: ScriptRunVars): RunValueMemory {
  const next: RunValueMemory = { ...memory };
  const perScript = { ...(next[script.id] ?? {}) };
  for (const definition of script.variables) {
    const value = vars[definition.name];
    if (!value || definition.secret_default || value.secret) {
      delete perScript[definition.name];
    } else {
      perScript[definition.name] = value.value;
    }
  }
  if (Object.keys(perScript).length === 0) delete next[script.id];
  else next[script.id] = perScript;
  return next;
}

/** Last-run display (timestamps arrive as integer milliseconds after the
 *  bridge conversion; spec 06 §4.1: "no runs yet"). */
export function formatLastRun(last_run_at: number | null, run_count: number): string {
  if (run_count === 0 || last_run_at === null) return "no runs yet";
  const diffMs = Date.now() - last_run_at;
  const minutes = Math.floor(diffMs / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} d ago`;
  return new Date(last_run_at).toLocaleDateString();
}

/** Retained-output cap for a single run pane or one broadcast server
 *  (spec 06 §9: bounded streams; the backend retains per-channel too). */
export const OUTPUT_CAP = 200_000;

/** Appends one poll delta to the accumulated output. A reported gap
 *  (dropped bytes / cursor jump) is surfaced once per run, not repeated
 *  on every poll. */
export function appendOutput(
  acc: string,
  data: string | undefined,
  gap: number | undefined,
  alreadyReported: boolean
): { text: string; gapReported: boolean } {
  const gapReported = alreadyReported || (gap !== undefined && gap > 0);
  if (!data) return { text: acc, gapReported };
  let text = acc + data;
  if (text.length > OUTPUT_CAP) text = text.slice(text.length - OUTPUT_CAP);
  return { text, gapReported };
}

export interface BroadcastSummary {
  total: number;
  queued: number;
  checking: number;
  running: number;
  done: number;
  failed: number;
  canceled: number;
  skipped: number;
}

export function summarizeBroadcast(servers: BroadcastServerResult[]): BroadcastSummary {
  const summary: BroadcastSummary = {
    total: servers.length,
    queued: 0,
    checking: 0,
    running: 0,
    done: 0,
    failed: 0,
    canceled: 0,
    skipped: 0,
  };
  for (const s of servers) {
    switch (s.status) {
      case "queued":
        summary.queued += 1;
        break;
      case "checking":
        summary.checking += 1;
        break;
      case "running":
        summary.running += 1;
        break;
      case "done":
        summary.done += 1;
        break;
      case "failed":
        summary.failed += 1;
        break;
      case "canceled":
        summary.canceled += 1;
        break;
      case "skipped":
        summary.skipped += 1;
        break;
    }
  }
  return summary;
}

/** The six product color swatches (spec 06 §4.1: a color picker with six
 *  swatches; the backend accepts only "" or a value starting with `#`). */
export const SCRIPT_COLORS = [
  "#d97757", // clay (destructive family)
  "#b98a2f", // brass
  "#3f6d7a", // cobalt
  "#5d7a52", // moss
  "#7a5c8f", // plum
  "#8a6f5c", // tobacco
];

export function isValidColor(color: string): boolean {
  return color === "" || SCRIPT_COLORS.includes(color);
}

/** Destructive-tag rule (spec 06 §4.2): an exact, case-insensitive
 *  `destructive` tag. Color alone never marks a script destructive. */
export function isDestructiveTagged(tags: string[]): boolean {
  return tags.some((t) => t.toLowerCase() === "destructive");
}
