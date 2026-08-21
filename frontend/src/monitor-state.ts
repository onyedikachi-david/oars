import type { MonitorSnapshot, ProcessSample } from "./types";

export type GaugeTone = "healthy" | "watch" | "tight" | "critical" | "muted";
export type DiskPlan = "journal" | "apt";
export type ProcessSortKey = "cpu" | "mem";

export interface MonitorHistory {
  cpu: number[];
  memory: number[];
  storage: number[];
}

export const DISK_PLANS: Record<
  DiskPlan,
  { title: string; description: string; estimateCommand: string; cleanupCommand: string }
> = {
  journal: {
    title: "System journal",
    description: "Review current journal use, then remove archived entries older than three days.",
    estimateCommand: "journalctl --disk-usage",
    cleanupCommand: "journalctl --vacuum-time=3d",
  },
  apt: {
    title: "APT package cache",
    description: "Review the package download cache, then remove cached package files.",
    estimateCommand: "du -sb /var/cache/apt",
    cleanupCommand: "apt-get clean",
  },
};

export function gaugeTone(percent: number | null): GaugeTone {
  if (percent === null || !Number.isFinite(percent)) return "muted";
  if (percent >= 90) return "critical";
  if (percent >= 80) return "tight";
  if (percent >= 60) return "watch";
  return "healthy";
}

export function toneLabel(tone: GaugeTone): string {
  return {
    healthy: "Healthy",
    watch: "Watch",
    tight: "Tight",
    critical: "Critical",
    muted: "Waiting",
  }[tone];
}

export function highestTone(tones: GaugeTone[]): GaugeTone {
  const priority: GaugeTone[] = ["critical", "tight", "watch", "healthy", "muted"];
  return priority.find((tone) => tones.includes(tone)) ?? "muted";
}

export function bytesToGiB(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "0.0";
  return (bytes / 1024 ** 3).toFixed(1);
}

export function formatUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "0m";
  const days = Math.floor(seconds / 86400);
  if (days > 0) return `${days}d`;
  const hours = Math.floor(seconds / 3600);
  if (hours > 0) return `${hours}h`;
  return `${Math.floor(seconds / 60)}m`;
}

export function snapshotMilliseconds(timestamp: number): number {
  if (!Number.isFinite(timestamp) || timestamp <= 0) return 0;
  if (timestamp > 1e15) return timestamp / 1e6;
  if (timestamp > 1e12) return timestamp;
  return timestamp * 1000;
}

export function formatSnapshotAge(timestamp: number, nowMs = Date.now()): string {
  if (!timestamp) return "Waiting for first sample";
  const snapMs = snapshotMilliseconds(timestamp);
  if (!snapMs) return "Waiting for first sample";
  const ageSeconds = Math.max(0, Math.round((nowMs - snapMs) / 1000));
  if (ageSeconds < 5) return "Updated just now";
  if (ageSeconds < 60) return `Updated ${ageSeconds}s ago`;
  return `Updated ${Math.floor(ageSeconds / 60)}m ago`;
}

export function extractResourcePercentages(snapshot: MonitorSnapshot): {
  cpuPercent: number | null;
  memoryPercent: number | null;
  storagePercent: number | null;
} {
  const cpuPercent = snapshot.cpu?.utilization_pct ?? null;
  const memoryPercent = snapshot.mem && snapshot.mem.total_bytes > 0
    ? (snapshot.mem.used_bytes / snapshot.mem.total_bytes) * 100
    : null;
  const storagePercent = snapshot.disk && snapshot.disk.total_bytes > 0
    ? (snapshot.disk.used_bytes / snapshot.disk.total_bytes) * 100
    : null;

  return { cpuPercent, memoryPercent, storagePercent };
}

export function determineOverallTone(probeError: string | null, tones: GaugeTone[]): GaugeTone {
  if (probeError) return "watch";
  return highestTone(tones);
}

export function appendHistorySample(
  history: MonitorHistory,
  cpu: number | null,
  memory: number | null,
  storage: number | null,
  maxSamples = 120,
): MonitorHistory {
  return {
    cpu: cpu === null || !Number.isFinite(cpu) ? history.cpu : [...history.cpu, cpu].slice(-maxSamples),
    memory: memory === null || !Number.isFinite(memory) ? history.memory : [...history.memory, memory].slice(-maxSamples),
    storage: storage === null || !Number.isFinite(storage) ? history.storage : [...history.storage, storage].slice(-maxSamples),
  };
}

export function sortProcessList(processes: ProcessSample[], sortBy: ProcessSortKey): ProcessSample[] {
  return [...processes].sort((left, right) => {
    const leftValue = sortBy === "cpu" ? (left.cpu ?? -1) : (left.mem ?? -1);
    const rightValue = sortBy === "cpu" ? (right.cpu ?? -1) : (right.mem ?? -1);
    return rightValue - leftValue;
  });
}

export function dropCachesCommand(level: 1 | 2 | 3): string {
  return `sync; echo ${level} > /proc/sys/vm/drop_caches`;
}
