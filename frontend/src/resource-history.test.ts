import { describe, expect, it } from "vitest";
import { appendResourceSample } from "./resource-history";
import type { MonitorSnapshot } from "./types";
const snapshot = (ts: number, cpu: number | null = 20): MonitorSnapshot => ({ ok: true, ts, cpu: cpu === null ? null : { utilization_pct: cpu, cores: 4, uptime_sec: 10, load_1: 1, load_5: 1, load_15: 1, cpu_warming: false }, mem: null, disk: null, processes: [], probe_error: null });
describe("resource timelines", () => {
  it("keeps missing resources aligned and skips duplicate or older snapshots", () => {
    const first = appendResourceSample([], snapshot(1788750000));
    expect(first[0]).toEqual({ time: 1788750000000, cpu: 20, memory: null, storage: null });
    expect(appendResourceSample(first, snapshot(1788750000))).toBe(first);
    expect(appendResourceSample(first, snapshot(1788749999))).toBe(first);
    const missing = appendResourceSample(first, snapshot(1788750002, null));
    expect(missing).toHaveLength(2); expect(missing[1].cpu).toBeNull();
  });
  it("leaves a gap after a lost probe and bounds retained history", () => {
    const first = appendResourceSample([], snapshot(1788750000));
    const resumed = appendResourceSample(first, snapshot(1788750060));
    expect(resumed).toHaveLength(3); expect(resumed[1].cpu).toBeNull();
    expect(appendResourceSample(resumed, snapshot(1788750062), 3)).toHaveLength(3);
    expect(appendResourceSample(first, snapshot(0))).toBe(first);
  });
});
