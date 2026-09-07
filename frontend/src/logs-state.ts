import type { LogSource } from "./types";

export const GROUP_ORDER = ["web", "runtime", "system", "custom"] as const;
export type LogGroup = (typeof GROUP_ORDER)[number];

export const GROUP_LABEL: Record<string, string> = {
  web: "Web servers",
  runtime: "Runtime & apps",
  system: "System",
  custom: "Custom",
};

export const LINE_COUNTS = [200, 500, 1000, 5000] as const;
export type LineCount = (typeof LINE_COUNTS)[number];

export const LINE_RENDER_CAP = 64 * 1024;
export const FOLLOW_MAX_CHARS = 1024 * 1024;

export function ageLabel(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return "0s";
  if (sec < 60) return `${Math.floor(sec)}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h`;
  return `${Math.floor(sec / 86400)}d`;
}

export function sizeLabel(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

export function modeLabel(mode: number): string {
  const bits: Array<[number, string]> = [
    [0o400, "r"], [0o200, "w"], [0o100, "x"],
    [0o040, "r"], [0o020, "w"], [0o010, "x"],
    [0o004, "r"], [0o002, "w"], [0o001, "x"],
  ];
  return bits.map(([bit, ch]) => (mode & bit ? ch : "-")).join("");
}

export function formatMtime(epochSeconds: number): string {
  if (!epochSeconds) return "—";
  return new Date(epochSeconds * 1000).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function filterLogSources(sources: LogSource[], query: string): LogSource[] {
  const q = query.trim().toLowerCase();
  if (!q) return sources;
  return sources.filter((source) =>
    source.path.toLowerCase().includes(q) ||
    source.name.toLowerCase().includes(q) ||
    (source.group && source.group.toLowerCase().includes(q)),
  );
}

export function groupLogSources(sources: LogSource[]): Array<{ group: string; label: string; items: LogSource[] }> {
  const buckets: Record<string, LogSource[]> = {
    web: [],
    runtime: [],
    system: [],
    custom: [],
  };

  for (const source of sources) {
    const g = source.group && source.group in buckets ? source.group : "custom";
    buckets[g].push(source);
  }

  return GROUP_ORDER.map((group) => ({
    group,
    label: GROUP_LABEL[group] ?? "Custom",
    items: buckets[group],
  })).filter((entry) => entry.items.length > 0);
}

export function countViewerMatches(lines: string[], query: string): number {
  const q = query.trim().toLowerCase();
  if (!q) return 0;
  let count = 0;
  for (const line of lines) {
    let pos = 0;
    const lower = line.toLowerCase();
    while ((pos = lower.indexOf(q, pos)) !== -1) {
      count += 1;
      pos += q.length;
    }
  }
  return count;
}

export function parseFollowLines(buffer: string): string[] {
  if (!buffer) return [];
  let normalized = buffer;
  if (normalized.endsWith("\r\n")) {
    normalized = normalized.slice(0, -2);
  } else if (normalized.endsWith("\n")) {
    normalized = normalized.slice(0, -1);
  }
  if (!normalized) return [];
  return normalized.split(/\r?\n/);
}

export function truncateLine(line: string, cap = LINE_RENDER_CAP): { text: string; truncated: boolean } {
  if (line.length > cap) {
    return { text: line.slice(0, cap), truncated: true };
  }
  return { text: line, truncated: false };
}

export function computeLogLevelCounts(lines: string[]): { error: number; warn: number; info: number } {
  let error = 0;
  let warn = 0;
  let info = 0;

  for (const line of lines) {
    const lower = line.toLowerCase();
    if (/\b(error|fatal|panic|crit|critical|err)\b/.test(lower)) {
      error += 1;
    } else if (/\b(warn|warning)\b/.test(lower)) {
      warn += 1;
    } else if (/\b(info|notice)\b/.test(lower)) {
      info += 1;
    }
  }

  return { error, warn, info };
}
