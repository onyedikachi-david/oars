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
  type GaugeTone,
} from "./monitor-state";
import {
  grantKey,
  phaseLabel,
  defaultRoleAccountName,
  isValidLinuxAccountName,
  parseFingerprintsInput,
  validateIdentityInput,
  validateOnboardTargets,
  buildOnboardTargets,
  computeAccessStatusText,
  type OnboardTargetChoice,
} from "./access-state";
import type { AccessGrant, AccessServerView, LogSource, MonitorSnapshot, ProcessSample } from "./types";

describe("M1 Adversarial Challenge: Pure State Models", () => {
  describe("logs-state edge cases & boundaries", () => {
    describe("ageLabel", () => {
      it("handles boundary transitions accurately", () => {
        expect(ageLabel(0)).toBe("0s");
        expect(ageLabel(0.4)).toBe("0s");
        expect(ageLabel(59.9)).toBe("59s");
        expect(ageLabel(60)).toBe("1m");
        expect(ageLabel(60.9)).toBe("1m");
        expect(ageLabel(3599.9)).toBe("59m");
        expect(ageLabel(3600)).toBe("1h");
        expect(ageLabel(86399.9)).toBe("23h");
        expect(ageLabel(86400)).toBe("1d");
        expect(ageLabel(86400 * 365)).toBe("365d");
      });

      it("handles non-finite, negative, and invalid numbers safely", () => {
        expect(ageLabel(-1)).toBe("0s");
        expect(ageLabel(-100000)).toBe("0s");
        expect(ageLabel(NaN)).toBe("0s");
        expect(ageLabel(Infinity)).toBe("0s");
        expect(ageLabel(-Infinity)).toBe("0s");
      });
    });

    describe("sizeLabel", () => {
      it("handles byte boundary steps accurately", () => {
        expect(sizeLabel(0)).toBe("0 B");
        expect(sizeLabel(1)).toBe("1 B");
        expect(sizeLabel(1023)).toBe("1023 B");
        expect(sizeLabel(1024)).toBe("1.0 KB");
        expect(sizeLabel(1024 * 1024 - 1)).toBe("1024.0 KB");
        expect(sizeLabel(1024 * 1024)).toBe("1.0 MB");
        expect(sizeLabel(1024 * 1024 * 1024 - 1)).toBe("1024.0 MB");
        expect(sizeLabel(1024 * 1024 * 1024)).toBe("1.0 GB");
        expect(sizeLabel(1024 * 1024 * 1024 * 5.5)).toBe("5.5 GB");
      });

      it("handles invalid and negative sizes", () => {
        expect(sizeLabel(-10)).toBe("0 B");
        expect(sizeLabel(NaN)).toBe("0 B");
        expect(sizeLabel(Infinity)).toBe("0 B");
        expect(sizeLabel(-Infinity)).toBe("0 B");
      });
    });

    describe("modeLabel", () => {
      it("correctly converts standard and unusual octal permissions", () => {
        expect(modeLabel(0o000)).toBe("---------");
        expect(modeLabel(0o777)).toBe("rwxrwxrwx");
        expect(modeLabel(0o755)).toBe("rwxr-xr-x");
        expect(modeLabel(0o644)).toBe("rw-r--r--");
        expect(modeLabel(0o600)).toBe("rw-------");
        expect(modeLabel(0o400)).toBe("r--------");
        expect(modeLabel(0o200)).toBe("-w-------");
        expect(modeLabel(0o100)).toBe("--x------");
        expect(modeLabel(0o040)).toBe("---r-----");
        expect(modeLabel(0o020)).toBe("----w----");
        expect(modeLabel(0o010)).toBe("-----x---");
        expect(modeLabel(0o004)).toBe("------r--");
        expect(modeLabel(0o002)).toBe("-------w-");
        expect(modeLabel(0o001)).toBe("--------x");
      });

      it("masks higher-order file type bits correctly (e.g. S_IFREG 0o100000, S_IFDIR 0o040000)", () => {
        expect(modeLabel(0o100755)).toBe("rwxr-xr-x");
        expect(modeLabel(0o040700)).toBe("rwx------");
      });
    });

    describe("formatMtime", () => {
      it("returns dash for 0 or falsy timestamps", () => {
        expect(formatMtime(0)).toBe("—");
        expect(formatMtime(NaN)).toBe("—");
      });

      it("formats valid epoch timestamps", () => {
        const formatted = formatMtime(1700000000);
        expect(formatted).not.toBe("—");
        expect(typeof formatted).toBe("string");
      });
    });

    describe("filterLogSources", () => {
      const sources: LogSource[] = [
        { name: "auth.log", path: "/var/log/auth.log", group: "system", size: 100, mtime_epoch: 1, age_sec: 10, mode: 0o644, readable: true },
        { name: "access.log", path: "/var/log/nginx/access.log", group: "web", size: 200, mtime_epoch: 2, age_sec: 10, mode: 0o644, readable: true },
        { name: "app.log", path: "/opt/app/runtime.log", group: "runtime", size: 300, mtime_epoch: 3, age_sec: 10, mode: 0o644, readable: true },
        { name: "custom.log", path: "/tmp/custom.log", group: undefined as any, size: 400, mtime_epoch: 4, age_sec: 10, mode: 0o644, readable: true },
      ];

      it("handles empty query or whitespace gracefully", () => {
        expect(filterLogSources(sources, "")).toBe(sources);
        expect(filterLogSources(sources, "   ")).toBe(sources);
      });

      it("matches case-insensitively on name, path, or group", () => {
        expect(filterLogSources(sources, "AUTH")).toHaveLength(1);
        expect(filterLogSources(sources, "NGINX")).toHaveLength(1);
        expect(filterLogSources(sources, "SYSTEM")).toHaveLength(1);
        expect(filterLogSources(sources, "runtime")).toHaveLength(1);
      });

      it("does not throw on special regex characters", () => {
        expect(() => filterLogSources(sources, "/var/log/(.*)+[a-z]?")).not.toThrow();
        expect(filterLogSources(sources, "/var/log/(.*)+[a-z]?")).toHaveLength(0);
      });

      it("handles sources with undefined group safely", () => {
        expect(filterLogSources(sources, "custom")).toHaveLength(1);
      });
    });

    describe("groupLogSources", () => {
      it("maps unknown groups to custom and preserves order", () => {
        const sources: LogSource[] = [
          { name: "sys", path: "/var/log/sys", group: "system", size: 1, mtime_epoch: 1, age_sec: 10, mode: 0o644, readable: true },
          { name: "unknown", path: "/var/log/unk", group: "nonexistent", size: 1, mtime_epoch: 1, age_sec: 10, mode: 0o644, readable: true },
        ];
        const grouped = groupLogSources(sources);
        expect(grouped).toHaveLength(2);
        expect(grouped[0].group).toBe("system");
        expect(grouped[1].group).toBe("custom");
        expect(grouped[1].items[0].name).toBe("unknown");
      });

      it("returns empty array for empty source list", () => {
        expect(groupLogSources([])).toEqual([]);
      });
    });

    describe("countViewerMatches", () => {
      it("counts non-overlapping occurrences correctly", () => {
        const lines = ["foo bar foo", "FOO", "hello world", "foofoo"];
        expect(countViewerMatches(lines, "foo")).toBe(5);
        expect(countViewerMatches(lines, "BAR")).toBe(1);
        expect(countViewerMatches(lines, "baz")).toBe(0);
      });

      it("returns 0 on empty/whitespace query", () => {
        expect(countViewerMatches(["test line"], "")).toBe(0);
        expect(countViewerMatches(["test line"], "   ")).toBe(0);
      });
    });

    describe("parseFollowLines", () => {
      it("normalizes CRLF and LF streams without phantom trailing empty elements", () => {
        expect(parseFollowLines("a\r\nb\r\nc\r\n")).toEqual(["a", "b", "c"]);
        expect(parseFollowLines("a\nb\nc\n")).toEqual(["a", "b", "c"]);
        expect(parseFollowLines("a\nb\nc")).toEqual(["a", "b", "c"]);
        expect(parseFollowLines("")).toEqual([]);
        expect(parseFollowLines("\n")).toEqual([]);
        expect(parseFollowLines("\r\n")).toEqual([]);
      });

      it("preserves intentional interior empty lines", () => {
        expect(parseFollowLines("a\n\nb\n")).toEqual(["a", "", "b"]);
      });
    });

    describe("truncateLine", () => {
      it("respects default LINE_RENDER_CAP and custom caps", () => {
        const text = "x".repeat(100);
        expect(truncateLine(text, 50)).toEqual({ text: "x".repeat(50), truncated: true });
        expect(truncateLine(text, 150)).toEqual({ text, truncated: false });
        expect(truncateLine(text, 100)).toEqual({ text, truncated: false });
      });
    });

    describe("computeLogLevelCounts", () => {
      it("matches exact word boundaries for log levels and avoids false positives", () => {
        const lines = [
          "ERROR: something failed",
          "error in system",
          "fatal exception",
          "panic at kernel",
          "crit: low disk",
          "critical error",
          "[err] unexpected token",
          "terrorism is an unrelated word",
          "erroneous input should not count",
          "WARN: high load",
          "warning: deprecated flag",
          "warranty is an unrelated word",
          "INFO: server listening on :80",
          "notice: reloading config",
          "information is an unrelated word",
        ];
        const counts = computeLogLevelCounts(lines);
        expect(counts.error).toBe(7); // 7 valid error lines
        expect(counts.warn).toBe(2); // 2 valid warn lines
        expect(counts.info).toBe(2); // 2 valid info lines
      });
    });
  });

  describe("monitor-state edge cases & boundaries", () => {
    describe("gaugeTone", () => {
      it("maps boundaries exactly", () => {
        expect(gaugeTone(null)).toBe("muted");
        expect(gaugeTone(NaN)).toBe("muted");
        expect(gaugeTone(Infinity)).toBe("muted");
        expect(gaugeTone(-Infinity)).toBe("muted");
        expect(gaugeTone(-5)).toBe("healthy");
        expect(gaugeTone(0)).toBe("healthy");
        expect(gaugeTone(59.99)).toBe("healthy");
        expect(gaugeTone(60)).toBe("watch");
        expect(gaugeTone(79.99)).toBe("watch");
        expect(gaugeTone(80)).toBe("tight");
        expect(gaugeTone(89.99)).toBe("tight");
        expect(gaugeTone(90)).toBe("critical");
        expect(gaugeTone(100)).toBe("critical");
        expect(gaugeTone(150)).toBe("critical");
      });
    });

    describe("toneLabel", () => {
      it("maps all tones correctly", () => {
        const tones: GaugeTone[] = ["healthy", "watch", "tight", "critical", "muted"];
        expect(tones.map(toneLabel)).toEqual(["Healthy", "Watch", "Tight", "Critical", "Waiting"]);
      });
    });

    describe("highestTone", () => {
      it("enforces strict tone priority: critical > tight > watch > healthy > muted", () => {
        expect(highestTone(["healthy", "muted"])).toBe("healthy");
        expect(highestTone(["healthy", "watch"])).toBe("watch");
        expect(highestTone(["watch", "tight"])).toBe("tight");
        expect(highestTone(["tight", "critical"])).toBe("critical");
        expect(highestTone(["muted", "critical", "healthy"])).toBe("critical");
        expect(highestTone([])).toBe("muted");
      });
    });

    describe("bytesToGiB", () => {
      it("formats bytes accurately with single decimal precision", () => {
        expect(bytesToGiB(0)).toBe("0.0");
        expect(bytesToGiB(1024 ** 3)).toBe("1.0");
        expect(bytesToGiB(1024 ** 3 * 2.5)).toBe("2.5");
        expect(bytesToGiB(-100)).toBe("0.0");
        expect(bytesToGiB(NaN)).toBe("0.0");
        expect(bytesToGiB(Infinity)).toBe("0.0");
      });
    });

    describe("formatUptime", () => {
      it("formats intervals into d, h, m", () => {
        expect(formatUptime(0)).toBe("0m");
        expect(formatUptime(59)).toBe("0m");
        expect(formatUptime(60)).toBe("1m");
        expect(formatUptime(3599)).toBe("59m");
        expect(formatUptime(3600)).toBe("1h");
        expect(formatUptime(7200)).toBe("2h");
        expect(formatUptime(86399)).toBe("23h");
        expect(formatUptime(86400)).toBe("1d");
        expect(formatUptime(172800)).toBe("2d");
        expect(formatUptime(-10)).toBe("0m");
        expect(formatUptime(NaN)).toBe("0m");
      });
    });

    describe("snapshotMilliseconds & formatSnapshotAge", () => {
      it("normalizes nanoseconds, milliseconds, and seconds timestamps", () => {
        const expected = 1700000000000;
        expect(snapshotMilliseconds(1700000000000000000)).toBe(expected);
        expect(snapshotMilliseconds(1700000000000)).toBe(expected);
        expect(snapshotMilliseconds(1700000000)).toBe(expected);
        expect(snapshotMilliseconds(0)).toBe(0);
        expect(snapshotMilliseconds(-100)).toBe(0);
        expect(snapshotMilliseconds(NaN)).toBe(0);
      });

      it("formats snapshot age text with clamping for future timestamps", () => {
        const now = 1700000010000;
        expect(formatSnapshotAge(0, now)).toBe("Waiting for first sample");
        // Timestamp slightly in the future due to clock skew
        expect(formatSnapshotAge(now + 2000, now)).toBe("Updated just now");
        expect(formatSnapshotAge(now - 4000, now)).toBe("Updated just now");
        expect(formatSnapshotAge(now - 15000, now)).toBe("Updated 15s ago");
        expect(formatSnapshotAge(now - 120000, now)).toBe("Updated 2m ago");
      });
    });

    describe("extractResourcePercentages", () => {
      it("safely handles total_bytes = 0 without dividing by zero", () => {
        const snapshot: MonitorSnapshot = {
          ok: true,
          ts: 1700000000000,
          probe_error: null,
          cpu: { cores: 2, utilization_pct: 50, load_1: 1, load_5: 1, load_15: 1, uptime_sec: 100, cpu_warming: false },
          mem: { used_bytes: 0, total_bytes: 0, available_bytes: 0, swap_used_bytes: 0, swap_total_bytes: 0 },
          disk: { used_bytes: 0, total_bytes: 0, available_bytes: 0 },
          processes: [],
        };
        const res = extractResourcePercentages(snapshot);
        expect(res.cpuPercent).toBe(50);
        expect(res.memoryPercent).toBeNull();
        expect(res.storagePercent).toBeNull();
      });
    });

    describe("determineOverallTone", () => {
      it("returns watch when probeError exists regardless of tones", () => {
        expect(determineOverallTone("probe error", ["healthy", "healthy"])).toBe("watch");
        expect(determineOverallTone("probe error", ["critical"])).toBe("watch");
        expect(determineOverallTone(null, ["healthy", "critical"])).toBe("critical");
      });
    });

    describe("appendHistorySample", () => {
      it("ignores non-finite and null inputs while respecting capacity", () => {
        let history = { cpu: [10], memory: [20], storage: [30] };
        history = appendHistorySample(history, NaN, null, Infinity, 5);
        expect(history.cpu).toEqual([10]);
        expect(history.memory).toEqual([20]);
        expect(history.storage).toEqual([30]);

        history = appendHistorySample(history, 15, 25, 35, 2);
        expect(history.cpu).toEqual([10, 15]);
        history = appendHistorySample(history, 20, 30, 40, 2);
        expect(history.cpu).toEqual([15, 20]);
      });
    });

    describe("sortProcessList", () => {
      it("does not mutate original array and handles null metrics", () => {
        const original: ProcessSample[] = [
          { pid: 1, name: "proc1", cpu: null, mem: 50 },
          { pid: 2, name: "proc2", cpu: 80, mem: 10 },
          { pid: 3, name: "proc3", cpu: 20, mem: null },
        ];
        const copy = [...original];
        const sortedCpu = sortProcessList(original, "cpu");
        expect(original).toEqual(copy); // immutable check
        expect(sortedCpu.map((p) => p.pid)).toEqual([2, 3, 1]);

        const sortedMem = sortProcessList(original, "mem");
        expect(sortedMem.map((p) => p.pid)).toEqual([1, 2, 3]);
      });
    });

    describe("dropCachesCommand", () => {
      it("generates correct sync; echo {level} commands", () => {
        expect(dropCachesCommand(1)).toBe("sync; echo 1 > /proc/sys/vm/drop_caches");
        expect(dropCachesCommand(2)).toBe("sync; echo 2 > /proc/sys/vm/drop_caches");
        expect(dropCachesCommand(3)).toBe("sync; echo 3 > /proc/sys/vm/drop_caches");
      });
    });
  });

  describe("access-state edge cases & boundaries", () => {
    describe("grantKey", () => {
      it("creates deterministic string key from grant properties", () => {
        const grant: AccessGrant = {
          server_id: "s-99",
          server_name: "prod-server",
          user: "deploy",
          source_path: "/root/.ssh/authorized_keys",
          line_hash: "hash_abc",
          fingerprint: "SHA256:xyz",
          comment: "",
          sudo: "full",
          file_sha256: "sha256_placeholder",
        };
        expect(grantKey(grant)).toBe("s-99:deploy:/root/.ssh/authorized_keys:hash_abc");
      });
    });

    describe("phaseLabel", () => {
      it("provides human-readable labels for known phases and falls back to raw string", () => {
        expect(phaseLabel("queued")).toBe("Queued");
        expect(phaseLabel("identity")).toBe("Reading account");
        expect(phaseLabel("sudo_probe")).toBe("Checking policy");
        expect(phaseLabel("enumerate")).toBe("Finding accounts");
        expect(phaseLabel("read_accounts")).toBe("Reading key sources");
        expect(phaseLabel("sshd_config")).toBe("Checking SSH policy");
        expect(phaseLabel("done")).toBe("Done");
        expect(phaseLabel("error")).toBe("Sync error");
        expect(phaseLabel("unknown_phase_xyz")).toBe("unknown_phase_xyz");
      });
    });

    describe("defaultRoleAccountName", () => {
      it("sanitizes names, strips hyphens, caps stem length, and handles empty strings", () => {
        expect(defaultRoleAccountName("Jane Doe")).toBe("jane-doe-readonly");
        expect(defaultRoleAccountName("!@#$%^&*()")).toBe("access-readonly");
        expect(defaultRoleAccountName("---user---")).toBe("user-readonly");
        expect(defaultRoleAccountName("")).toBe("access-readonly");
        expect(defaultRoleAccountName("a".repeat(100))).toBe(`${"a".repeat(48)}-readonly`);
      });
    });

    describe("isValidLinuxAccountName", () => {
      it("validates Linux account naming rules strictly", () => {
        expect(isValidLinuxAccountName("root")).toBe(true);
        expect(isValidLinuxAccountName("ubuntu")).toBe(true);
        expect(isValidLinuxAccountName("_service")).toBe(true);
        expect(isValidLinuxAccountName("app-123_456")).toBe(true);
        expect(isValidLinuxAccountName("a")).toBe(true);
        expect(isValidLinuxAccountName("a".repeat(64))).toBe(true);

        // Invalid names
        expect(isValidLinuxAccountName("")).toBe(false);
        expect(isValidLinuxAccountName("-invalid")).toBe(false);
        expect(isValidLinuxAccountName("a".repeat(65))).toBe(false);
        expect(isValidLinuxAccountName("User")).toBe(false); // Capital letters
        expect(isValidLinuxAccountName("user.name")).toBe(false);
        expect(isValidLinuxAccountName("user@host")).toBe(false);
        expect(isValidLinuxAccountName("user name")).toBe(false);
        expect(isValidLinuxAccountName("user$")).toBe(false);
      });
    });

    describe("parseFingerprintsInput", () => {
      it("parses empty, newline, and comma delimited text cleanly", () => {
        expect(parseFingerprintsInput("")).toEqual([]);
        expect(parseFingerprintsInput("   \n\n  ")).toEqual([]);
        expect(parseFingerprintsInput("SHA256:1, SHA256:2\nSHA256:3,  \nSHA256:4")).toEqual([
          "SHA256:1",
          "SHA256:2",
          "SHA256:3",
          "SHA256:4",
        ]);
      });
    });

    describe("validateIdentityInput", () => {
      it("enforces both name and at least one fingerprint", () => {
        expect(validateIdentityInput("Alice", ["SHA256:abc"])).toEqual({ ok: true, error: null });
        expect(validateIdentityInput("", ["SHA256:abc"])).toEqual({
          ok: false,
          error: "Enter a name and at least one SHA-256 fingerprint.",
        });
        expect(validateIdentityInput("   ", ["SHA256:abc"])).toEqual({
          ok: false,
          error: "Enter a name and at least one SHA-256 fingerprint.",
        });
        expect(validateIdentityInput("Alice", [])).toEqual({
          ok: false,
          error: "Enter a name and at least one SHA-256 fingerprint.",
        });
      });
    });

    describe("validateOnboardTargets", () => {
      it("requires at least one enabled target with a valid Linux account name", () => {
        const target: OnboardTargetChoice = {
          serverId: "s1",
          serverName: "prod",
          enabled: true,
          kind: "account",
          name: "deploy",
          accounts: ["deploy"],
        };

        expect(validateOnboardTargets([target])).toEqual({ ok: true, error: null });

        expect(validateOnboardTargets([{ ...target, enabled: false }])).toEqual({
          ok: false,
          error: "Select at least one server target.",
        });

        expect(validateOnboardTargets([{ ...target, name: "invalid-name!" }])).toEqual({
          ok: false,
          error: "Each target needs a valid Linux account name.",
        });
      });
    });

    describe("buildOnboardTargets", () => {
      it("correctly filters skipped accounts and maps selected grants", () => {
        const servers: AccessServerView[] = [
          {
            server_id: "s1",
            name: "web-01",
            host: "10.0.0.1",
            phase: "done",
            sudo: "full",
            coverage: "complete",
            connected_user: "admin",
            accounts: [
              { user: "admin", home: "/home/admin", skipped: false, read: true, sudo: "full", key_count: 1 },
              { user: "systemd-resolve", home: "/run/systemd/resolve", skipped: true, read: false, sudo: "none", key_count: 0 },
            ],
            sources: ["/home/admin/.ssh/authorized_keys"],
          },
          {
            server_id: "s2",
            name: "web-02",
            host: "10.0.0.2",
            phase: "done",
            sudo: "full",
            coverage: "complete",
            connected_user: undefined,
            accounts: [{ user: "ubuntu", home: "/home/ubuntu", skipped: false, read: true, sudo: "full", key_count: 1 }],
            sources: [],
          },
        ];

        const grants: AccessGrant[] = [
          {
            server_id: "s1",
            server_name: "web-01",
            user: "custom-user",
            source_path: "/home/custom/.ssh/authorized_keys",
            line_hash: "h1",
            fingerprint: "SHA256:x",
            comment: "",
            sudo: "full",
            file_sha256: "sha256_placeholder",
          },
        ];

        const targets = buildOnboardTargets(servers, grants);
        expect(targets).toHaveLength(2);

        // Server 1 has grant
        expect(targets[0].serverId).toBe("s1");
        expect(targets[0].enabled).toBe(true);
        expect(targets[0].name).toBe("custom-user");
        expect(targets[0].accounts).toEqual(["admin"]);

        // Server 2 has no grant
        expect(targets[1].serverId).toBe("s2");
        expect(targets[1].enabled).toBe(false);
        expect(targets[1].name).toBe("ubuntu");
      });
    });

    describe("computeAccessStatusText", () => {
      it("computes status text for all valid combinations", () => {
        expect(computeAccessStatusText(undefined, undefined, null)).toBe("No access snapshot");
        expect(computeAccessStatusText("all_login_accounts", "scanning", null)).toBe("Scanning · Full-account scope");
        expect(computeAccessStatusText("connected_accounts", "scanning", null)).toBe("Scanning · Connected-account scope");
        expect(computeAccessStatusText("all_login_accounts", "canceled", null)).toBe("Scan canceled · Full-account scope");
        expect(computeAccessStatusText("connected_accounts", "canceled", null)).toBe("Scan canceled · Connected-account scope");
        expect(computeAccessStatusText("all_login_accounts", "done", "complete")).toBe("Full-account scope · complete for this scope");
        expect(computeAccessStatusText("connected_accounts", "done", "partial")).toBe("Connected-account scope · partial coverage");
      });
    });
  });
});
