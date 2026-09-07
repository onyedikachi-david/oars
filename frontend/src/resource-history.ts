import type { MonitorSnapshot } from "./types";
import { snapshotMilliseconds } from "./monitor-state";

export interface ResourceSample { time: number; cpu: number | null; memory: number | null; storage: number | null }
const percent = (value: number | null | undefined) => value != null && Number.isFinite(value) ? Math.min(100, Math.max(0, value)) : null;
/** Keep all resources on the same clock. A missing reading is a gap, never zero. */
export function appendResourceSample(previous: ResourceSample[], snapshot: MonitorSnapshot, limit = 120): ResourceSample[] {
  const time = snapshotMilliseconds(snapshot.ts);
  if (!time || snapshot.status === "not_ready") return previous;
  const sample: ResourceSample = {
    time,
    cpu: percent(snapshot.cpu?.utilization_pct),
    memory: percent(snapshot.mem && snapshot.mem.total_bytes > 0 ? snapshot.mem.used_bytes / snapshot.mem.total_bytes * 100 : null),
    storage: percent(snapshot.disk && snapshot.disk.total_bytes > 0 ? snapshot.disk.used_bytes / snapshot.disk.total_bytes * 100 : null),
  };
  const last = previous.at(-1);
  if (last && time <= last.time) return previous;
  // A delayed probe must not draw an uninterrupted trend across a lost connection.
  const gap: ResourceSample[] = last && time - last.time > 15000 ? [{ time: last.time + 1, cpu: null, memory: null, storage: null }] : [];
  return [...previous, ...gap, sample].slice(-limit);
}
