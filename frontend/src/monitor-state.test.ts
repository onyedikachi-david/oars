import { describe, expect, it } from "vitest";
import {
  gaugeTone,
  toneLabel,
  highestTone,
  bytesToGiB,
  formatUptime,
  snapshotMilliseconds,
  formatSnapshotAge,
  extractResourcePercentages,
  determineOverallTone,
  appendHistorySample,
  sortProcessList,
  dropCachesCommand,
  DISK_PLANS,
  type MonitorHistory,
} from "./monitor-state";
import type { MonitorSnapshot, ProcessSample } from "./types";

describe("monitor-state pure model", () => {
  describe("gaugeTone and toneLabel", () => {
    it("classifies percentage utilization into standard tones", () => {
      expect(gaugeTone(null)).toBe("muted");
      expect(gaugeTone(NaN)).toBe("muted");
      expect(gaugeTone(0)).toBe("healthy");
      expect(gaugeTone(45)).toBe("healthy");
      expect(gaugeTone(59.9)).toBe("healthy");
      expect(gaugeTone(60)).toBe("watch");
      expect(gaugeTone(79.9)).toBe("watch");
      expect(gaugeTone(80)).toBe("tight");
      expect(gaugeTone(89.9)).toBe("tight");
      expect(gaugeTone(90)).toBe("critical");
      expect(gaugeTone(100)).toBe("critical");
    });

    it("returns human-readable tone labels", () => {
      expect(toneLabel("healthy")).toBe("Healthy");
      expect(toneLabel("watch")).toBe("Watch");
      expect(toneLabel("tight")).toBe("Tight");
      expect(toneLabel("critical")).toBe("Critical");
      expect(toneLabel("muted")).toBe("Waiting");
    });
  });

  describe("highestTone", () => {
    it("determines maximum severity tone from a list", () => {
      expect(highestTone(["healthy", "watch", "tight"])).toBe("tight");
      expect(highestTone(["healthy", "muted"])).toBe("healthy");
      expect(highestTone(["critical", "tight", "watch"])).toBe("critical");
      expect(highestTone([])).toBe("muted");
    });
  });

  describe("bytesToGiB", () => {
    it("converts bytes to GiB string with 1 decimal place", () => {
      expect(bytesToGiB(0)).toBe("0.0");
      expect(bytesToGiB(1073741824)).toBe("1.0");
      expect(bytesToGiB(16106127360)).toBe("15.0");
      expect(bytesToGiB(-100)).toBe("0.0");
    });
  });

  describe("formatUptime", () => {
    it("formats uptime in days, hours, and minutes", () => {
      expect(formatUptime(0)).toBe("0m");
      expect(formatUptime(120)).toBe("2m");
      expect(formatUptime(3599)).toBe("59m");
      expect(formatUptime(7200)).toBe("2h");
      expect(formatUptime(86399)).toBe("23h");
      expect(formatUptime(172800)).toBe("2d");
      expect(formatUptime(259200)).toBe("3d");
    });
  });

  describe("snapshotMilliseconds and formatSnapshotAge", () => {
    it("normalizes nanoseconds, milliseconds, and seconds", () => {
      expect(snapshotMilliseconds(1700000000000000000)).toBe(1700000000000);
      expect(snapshotMilliseconds(1700000000000)).toBe(1700000000000);
      expect(snapshotMilliseconds(1700000000)).toBe(1700000000000);
      expect(snapshotMilliseconds(0)).toBe(0);
    });

    it("formats snapshot age text based on elapsed time", () => {
      const now = 1700000010000;
      expect(formatSnapshotAge(0)).toBe("Waiting for first sample");
      expect(formatSnapshotAge(1700000008000, now)).toBe("Updated just now");
      expect(formatSnapshotAge(1700000000000, now)).toBe("Updated 10s ago");
      expect(formatSnapshotAge(1699999800000, now)).toBe("Updated 3m ago");
    });
  });

  describe("extractResourcePercentages", () => {
    it("calculates percentages from snapshot metrics", () => {
      const snapshot: MonitorSnapshot = {
        ok: true,
        ts: 1700000000000,
        probe_error: null,
        cpu: { cores: 4, utilization_pct: 35.5, load_1: 1.0, load_5: 0.8, load_15: 0.5, uptime_sec: 1000, cpu_warming: false },
        mem: { used_bytes: 4000, total_bytes: 10000, available_bytes: 6000, swap_used_bytes: 0, swap_total_bytes: 0 },
        disk: { used_bytes: 8000, total_bytes: 10000, available_bytes: 2000 },
        processes: [],
      };

      const result = extractResourcePercentages(snapshot);
      expect(result.cpuPercent).toBe(35.5);
      expect(result.memoryPercent).toBe(40);
      expect(result.storagePercent).toBe(80);
    });

    it("handles missing snapshot sections safely", () => {
      const empty: MonitorSnapshot = {
        ok: true,
        ts: 0,
        probe_error: null,
        cpu: null,
        mem: null,
        disk: null,
        processes: [],
      };
      const result = extractResourcePercentages(empty);
      expect(result.cpuPercent).toBeNull();
      expect(result.memoryPercent).toBeNull();
      expect(result.storagePercent).toBeNull();
    });
  });

  describe("determineOverallTone", () => {
    it("flags watch if probe_error exists, else highest tone", () => {
      expect(determineOverallTone("socket timeout", ["healthy", "healthy"])).toBe("watch");
      expect(determineOverallTone(null, ["healthy", "tight"])).toBe("tight");
      expect(determineOverallTone(null, ["healthy", "healthy"])).toBe("healthy");
    });
  });

  describe("appendHistorySample", () => {
    it("appends non-null samples and enforces sample capacity window", () => {
      let history: MonitorHistory = { cpu: [10, 20], memory: [30], storage: [] };
      history = appendHistorySample(history, 25, 35, 45, 3);
      expect(history.cpu).toEqual([10, 20, 25]);
      expect(history.memory).toEqual([30, 35]);
      expect(history.storage).toEqual([45]);

      // Add another and check capacity
      history = appendHistorySample(history, 30, null, 50, 3);
      expect(history.cpu).toEqual([20, 25, 30]);
      expect(history.memory).toEqual([30, 35]); // unchanged when null
      expect(history.storage).toEqual([45, 50]);
    });
  });

  describe("sortProcessList", () => {
    const procs: ProcessSample[] = [
      { pid: 101, name: "node", cpu: 15.5, mem: 40.0 },
      { pid: 102, name: "nginx", cpu: 55.0, mem: 10.0 },
      { pid: 103, name: "redis", cpu: null, mem: 80.0 },
    ];

    it("sorts by cpu descending", () => {
      const sorted = sortProcessList(procs, "cpu");
      expect(sorted.map((p) => p.pid)).toEqual([102, 101, 103]);
    });

    it("sorts by mem descending", () => {
      const sorted = sortProcessList(procs, "mem");
      expect(sorted.map((p) => p.pid)).toEqual([103, 101, 102]);
    });
  });

  describe("dropCachesCommand & DISK_PLANS", () => {
    it("generates valid sync and drop_caches command strings", () => {
      expect(dropCachesCommand(1)).toBe("sync; echo 1 > /proc/sys/vm/drop_caches");
      expect(dropCachesCommand(2)).toBe("sync; echo 2 > /proc/sys/vm/drop_caches");
      expect(dropCachesCommand(3)).toBe("sync; echo 3 > /proc/sys/vm/drop_caches");
    });

    it("provides predefined disk cleanup plans", () => {
      expect(DISK_PLANS.journal.estimateCommand).toBe("journalctl --disk-usage");
      expect(DISK_PLANS.journal.cleanupCommand).toBe("journalctl --vacuum-time=3d");
      expect(DISK_PLANS.apt.cleanupCommand).toBe("apt-get clean");
    });
  });
});
