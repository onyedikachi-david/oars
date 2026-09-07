import { describe, expect, it } from "vitest";
import {
  ageLabel,
  sizeLabel,
  modeLabel,
  formatMtime,
  filterLogSources,
  groupLogSources,
  countViewerMatches,
  parseFollowLines,
  truncateLine,
  computeLogLevelCounts,
  LINE_RENDER_CAP,
} from "./logs-state";
import type { LogSource } from "./types";

describe("logs-state pure model", () => {
  describe("ageLabel", () => {
    it("formats seconds, minutes, hours, and days correctly", () => {
      expect(ageLabel(0)).toBe("0s");
      expect(ageLabel(45)).toBe("45s");
      expect(ageLabel(59)).toBe("59s");
      expect(ageLabel(60)).toBe("1m");
      expect(ageLabel(900)).toBe("15m");
      expect(ageLabel(3599)).toBe("59m");
      expect(ageLabel(3600)).toBe("1h");
      expect(ageLabel(14400)).toBe("4h");
      expect(ageLabel(86399)).toBe("23h");
      expect(ageLabel(86400)).toBe("1d");
      expect(ageLabel(259200)).toBe("3d");
    });

    it("handles invalid or negative inputs safely", () => {
      expect(ageLabel(-10)).toBe("0s");
      expect(ageLabel(NaN)).toBe("0s");
    });
  });

  describe("sizeLabel", () => {
    it("formats bytes, KB, MB, and GB boundaries", () => {
      expect(sizeLabel(0)).toBe("0 B");
      expect(sizeLabel(500)).toBe("500 B");
      expect(sizeLabel(1023)).toBe("1023 B");
      expect(sizeLabel(1024)).toBe("1.0 KB");
      expect(sizeLabel(2048)).toBe("2.0 KB");
      expect(sizeLabel(1048576)).toBe("1.0 MB");
      expect(sizeLabel(10485760)).toBe("10.0 MB");
      expect(sizeLabel(1073741824)).toBe("1.0 GB");
      expect(sizeLabel(5368709120)).toBe("5.0 GB");
    });

    it("handles invalid or negative numbers", () => {
      expect(sizeLabel(-1)).toBe("0 B");
      expect(sizeLabel(NaN)).toBe("0 B");
    });
  });

  describe("modeLabel", () => {
    it("converts octal mode bits to standard 9-char string", () => {
      expect(modeLabel(0o755)).toBe("rwxr-xr-x");
      expect(modeLabel(0o644)).toBe("rw-r--r--");
      expect(modeLabel(0o700)).toBe("rwx------");
      expect(modeLabel(0o777)).toBe("rwxrwxrwx");
      expect(modeLabel(0o000)).toBe("---------");
    });
  });

  describe("formatMtime", () => {
    it("formats epoch seconds to localized timestamp string", () => {
      expect(formatMtime(0)).toBe("—");
      const formatted = formatMtime(1700000000);
      expect(typeof formatted).toBe("string");
      expect(formatted.length).toBeGreaterThan(0);
    });
  });

  describe("filterLogSources", () => {
    const mockSources: LogSource[] = [
      { name: "nginx-access", path: "/var/log/nginx/access.log", group: "web", size: 100, mtime_epoch: 1, age_sec: 10, mode: 0o644, readable: true },
      { name: "nginx-error", path: "/var/log/nginx/error.log", group: "web", size: 100, mtime_epoch: 1, age_sec: 10, mode: 0o644, readable: true },
      { name: "syslog", path: "/var/log/syslog", group: "system", size: 100, mtime_epoch: 1, age_sec: 10, mode: 0o644, readable: true },
      { name: "app-runtime", path: "/opt/app/logs/out.log", group: "runtime", size: 100, mtime_epoch: 1, age_sec: 10, mode: 0o644, readable: true },
    ];

    it("returns all sources when query is empty or whitespace", () => {
      expect(filterLogSources(mockSources, "")).toEqual(mockSources);
      expect(filterLogSources(mockSources, "   ")).toEqual(mockSources);
    });

    it("filters sources case-insensitively across name, path, and group", () => {
      expect(filterLogSources(mockSources, "NGINX")).toHaveLength(2);
      expect(filterLogSources(mockSources, "syslog")).toHaveLength(1);
      expect(filterLogSources(mockSources, "/opt/app")).toHaveLength(1);
      expect(filterLogSources(mockSources, "web")).toHaveLength(2);
      expect(filterLogSources(mockSources, "nonexistent")).toHaveLength(0);
    });
  });

  describe("groupLogSources", () => {
    const mockSources: LogSource[] = [
      { name: "nginx", path: "/var/log/nginx.log", group: "web", size: 100, mtime_epoch: 1, age_sec: 10, mode: 0o644, readable: true },
      { name: "syslog", path: "/var/log/syslog", group: "system", size: 100, mtime_epoch: 1, age_sec: 10, mode: 0o644, readable: true },
      { name: "pm2", path: "/root/.pm2/logs", group: "runtime", size: 100, mtime_epoch: 1, age_sec: 10, mode: 0o644, readable: true },
      { name: "custom-job", path: "/tmp/custom.log", group: "unknown-group", size: 100, mtime_epoch: 1, age_sec: 10, mode: 0o644, readable: true },
    ];

    it("groups sources into ordered categories and maps unknown groups to custom", () => {
      const groups = groupLogSources(mockSources);
      expect(groups.map((g) => g.group)).toEqual(["web", "runtime", "system", "custom"]);
      expect(groups.find((g) => g.group === "web")?.items).toHaveLength(1);
      expect(groups.find((g) => g.group === "system")?.items).toHaveLength(1);
      expect(groups.find((g) => g.group === "runtime")?.items).toHaveLength(1);
      expect(groups.find((g) => g.group === "custom")?.items).toHaveLength(1);
    });

    it("omits empty groups", () => {
      const singleSource: LogSource[] = [
        { name: "nginx", path: "/var/log/nginx.log", group: "web", size: 100, mtime_epoch: 1, age_sec: 10, mode: 0o644, readable: true },
      ];
      const groups = groupLogSources(singleSource);
      expect(groups).toHaveLength(1);
      expect(groups[0].group).toBe("web");
    });
  });

  describe("countViewerMatches", () => {
    it("counts occurrences across lines case-insensitively", () => {
      const lines = [
        "2026-08-17 ERROR: database error occurred",
        "2026-08-17 INFO: retry succeeded",
        "2026-08-17 error in worker thread: Error code 500",
      ];
      expect(countViewerMatches(lines, "error")).toBe(4);
      expect(countViewerMatches(lines, "INFO")).toBe(1);
      expect(countViewerMatches(lines, "notfound")).toBe(0);
      expect(countViewerMatches(lines, "")).toBe(0);
      expect(countViewerMatches(lines, "   ")).toBe(0);
    });
  });

  describe("parseFollowLines", () => {
    it("parses newline-delimited stream buffer without trailing empty line", () => {
      expect(parseFollowLines("line1\nline2\nline3\n")).toEqual(["line1", "line2", "line3"]);
      expect(parseFollowLines("line1\r\nline2\r\n")).toEqual(["line1", "line2"]);
      expect(parseFollowLines("line1\n\nline2\n")).toEqual(["line1", "", "line2"]);
      expect(parseFollowLines("")).toEqual([]);
    });
  });

  describe("truncateLine", () => {
    it("truncates lines exceeding cap and leaves shorter lines unchanged", () => {
      const short = "hello world";
      expect(truncateLine(short)).toEqual({ text: "hello world", truncated: false });

      const long = "a".repeat(LINE_RENDER_CAP + 50);
      const res = truncateLine(long);
      expect(res.truncated).toBe(true);
      expect(res.text).toHaveLength(LINE_RENDER_CAP);
    });
  });

  describe("computeLogLevelCounts", () => {
    it("counts error, warning, and info lines accurately", () => {
      const lines = [
        "10:00:00 [ERROR] Failed to connect to socket",
        "10:00:01 [FATAL] Crash detected",
        "10:00:02 [WARN] High memory usage",
        "10:00:03 [WARNING] Disk 85% full",
        "10:00:04 [INFO] Request received",
        "10:00:05 [NOTICE] Restarted service",
        "10:00:06 Normal debug line",
      ];
      const counts = computeLogLevelCounts(lines);
      expect(counts).toEqual({
        error: 2,
        warn: 2,
        info: 2,
      });
    });
  });
});
