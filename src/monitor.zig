//! Infra monitoring (spec 03): the probe command, pure parsers for each
//! section, the snapshot model, and the per-session cache.
//!
//! The probe is ONE exec. `%BEGIN_X%` markers delimit sections so parsing
//! never depends on positional guessing across variable-line sections
//! (df/ps) — every value in the command is a fixed string.
//!
//! CPU utilization comes from `/proc/stat` tick deltas between consecutive
//! probes; load averages are reported separately and never labeled as a
//! percentage. `ps` is capability-selected: GNU procps provides
//! CPU%/Mem% columns; busybox cannot (its `-o` supports only pid/comm/…),
//! so the fallback omits them and the payload carries `null` rather than
//! inventing zeros.

const std = @import("std");

pub const probe_command =
    "printf '%%BEGIN_STAT%%\\n'; cat /proc/stat; " ++
    "printf '%%BEGIN_LOADAVG%%\\n'; cat /proc/loadavg; " ++
    "printf '%%BEGIN_NPROC%%\\n'; nproc; " ++
    "printf '%%BEGIN_UPTIME%%\\n'; cat /proc/uptime; " ++
    "printf '%%BEGIN_MEMINFO%%\\n'; cat /proc/meminfo; " ++
    "printf '%%BEGIN_DF%%\\n'; df -kP /; " ++
    "printf '%%BEGIN_PS%%\\n'; (ps -eo pid=,comm=,%cpu=,%mem= --sort=-%cpu 2>/dev/null || ps -eo pid,comm) | head -n 11";

/// Itemized disk cleanup plans (spec 03 §6): fixed commands, each with its
/// own preview (estimate) and mutating execution. Log/tmp cleanup is out of
/// scope until Oars can prove ownership of every affected path.
pub const DiskPlan = enum {
    journal,
    apt,

    pub fn jsonName(self: DiskPlan) []const u8 {
        return switch (self) {
            .journal => "journal",
            .apt => "apt",
        };
    }

    pub fn fromJsonName(name: []const u8) ?DiskPlan {
        if (std.mem.eql(u8, name, "journal")) return .journal;
        if (std.mem.eql(u8, name, "apt")) return .apt;
        return null;
    }

    pub fn command(self: DiskPlan) []const u8 {
        return switch (self) {
            // systemd-journald's documented vacuum; non-root or non-systemd
            // systems fail honestly through the channel's exit code.
            .journal => "journalctl --vacuum-time=3d 2>&1 || true",
            // apt's documented cache cleaner.
            .apt => "apt-get clean 2>&1",
        };
    }

    pub fn estimateCommand(self: DiskPlan) []const u8 {
        return switch (self) {
            .journal => "journalctl --disk-usage 2>&1 || true",
            .apt => "du -sb /var/cache/apt 2>&1 || true",
        };
    }
};

/// Drop-caches levels are the kernel's documented values (1=page cache,
/// 2=reclaimable slab, 3=both); the default action is 3 (spec 03 §6).
pub const drop_cache_default: u8 = 3;

pub const drop_cache_command = "sync; echo {d} > /proc/sys/vm/drop_caches 2>&1";

pub const CpuInfo = struct {
    /// Percent utilization from /proc/stat tick deltas; null until a second
    /// valid probe provides a delta (cpu_warming then reports the state).
    utilization_pct: ?f32 = null,
    cpu_warming: bool = false,
    load_1: f32 = 0,
    load_5: f32 = 0,
    load_15: f32 = 0,
    uptime_sec: u64 = 0,
    cores: u32 = 0,
};

pub const MemInfo = struct {
    used_bytes: u64 = 0,
    total_bytes: u64 = 0,
    available_bytes: u64 = 0,
    swap_used_bytes: u64 = 0,
    swap_total_bytes: u64 = 0,
};

pub const DiskInfo = struct {
    used_bytes: u64 = 0,
    total_bytes: u64 = 0,
    available_bytes: u64 = 0,
};

pub const Process = struct {
    pid: u32,
    name: []const u8,
    /// Null when the platform's ps cannot report them (busybox fallback).
    cpu: ?f32 = null,
    mem: ?f32 = null,
};

/// The bridge payload shape for a ready snapshot (spec 03 §5).
pub const Snapshot = struct {
    ts: i64 = 0,
    cpu: CpuInfo = .{},
    mem: MemInfo = .{},
    disk: DiskInfo = .{},
    processes: []Process = &.{},
    probe_error: ?[]const u8 = null,

    pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        for (self.processes) |p| allocator.free(p.name);
        allocator.free(self.processes);
    }
};

/// Raw CPU tick totals from one /proc/stat sample, for delta utilization.
pub const CpuSample = struct {
    total: u64,
    idle: u64,
};

pub fn utilization(prev: CpuSample, cur: CpuSample) ?f32 {
    const total_delta = cur.total -| prev.total;
    const idle_delta = cur.idle -| prev.idle;
    if (total_delta == 0) return null;
    const busy: f32 = @floatFromInt(total_delta -| idle_delta);
    const total: f32 = @floatFromInt(total_delta);
    return @max(0, @min(100, busy / total * 100));
}

const ParseError = error{Invalid};

/// `/proc/stat` first line: `cpu  user nice system idle iowait irq softirq
/// steal guest guest_nice`. Idle counts idle + iowait (kernel convention).
pub fn parseStat(text: []const u8) ParseError!CpuSample {
    const line = firstLine(text) orelse return error.Invalid;
    var fields = std.mem.tokenizeAny(u8, line, " \t");
    const cpu = fields.next() orelse return error.Invalid;
    if (!std.mem.eql(u8, cpu, "cpu")) return error.Invalid;
    var total: u64 = 0;
    var idle: u64 = 0;
    var field_i: usize = 0;
    while (fields.next()) |f| : (field_i += 1) {
        const value = std.fmt.parseInt(u64, f, 10) catch return error.Invalid;
        total = total +| value;
        if (field_i == 3 or field_i == 4) idle = idle +| value;
    }
    if (field_i < 4) return error.Invalid;
    return .{ .total = total, .idle = idle };
}

/// `/proc/loadavg`: `0.61 0.61 0.55 3/828 22084` — the first three fields
/// are the 1/5/15-minute load averages.
pub fn parseLoadAvg(text: []const u8) ParseError!struct { f32, f32, f32 } {
    const line = firstLine(text) orelse return error.Invalid;
    var fields = std.mem.tokenizeAny(u8, line, " \t");
    const a = std.fmt.parseFloat(f32, fields.next() orelse return error.Invalid) catch return error.Invalid;
    const b = std.fmt.parseFloat(f32, fields.next() orelse return error.Invalid) catch return error.Invalid;
    const c = std.fmt.parseFloat(f32, fields.next() orelse return error.Invalid) catch return error.Invalid;
    return .{ a, b, c };
}

pub fn parseNproc(text: []const u8) ParseError!u32 {
    const line = firstLine(text) orelse return error.Invalid;
    return std.fmt.parseInt(u32, std.mem.trim(u8, line, " \t\r\n"), 10) catch error.Invalid;
}

/// `/proc/uptime`: `19500000.12 32000000.50` — seconds since boot.
pub fn parseUptime(text: []const u8) ParseError!u64 {
    const line = firstLine(text) orelse return error.Invalid;
    var fields = std.mem.tokenizeAny(u8, line, " \t");
    const secs = std.fmt.parseFloat(f64, fields.next() orelse return error.Invalid) catch return error.Invalid;
    return @intFromFloat(secs);
}

/// `/proc/meminfo`: `Key: value kB` lines. `MemAvailable` is the right
/// "available" value (kernel docs); `MemFree` is the fallback on kernels
/// that predate it.
pub fn parseMemInfo(text: []const u8) ParseError!MemInfo {
    var out = MemInfo{};
    var mem_free: ?u64 = null;
    var saw_available = false;
    var saw_total = false;
    var saw_swap_total = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        var fields = std.mem.tokenizeAny(u8, trimmed, " \t:");
        const key = fields.next() orelse continue;
        const value_kb = std.fmt.parseInt(u64, fields.next() orelse continue, 10) catch continue;
        const bytes = std.math.mul(u64, value_kb, 1024) catch continue;
        if (std.mem.eql(u8, key, "MemTotal")) {
            out.total_bytes = bytes;
            saw_total = true;
        } else if (std.mem.eql(u8, key, "MemAvailable")) {
            out.available_bytes = bytes;
            saw_available = true;
        } else if (std.mem.eql(u8, key, "MemFree")) {
            mem_free = bytes;
        } else if (std.mem.eql(u8, key, "SwapTotal")) {
            out.swap_total_bytes = bytes;
            saw_swap_total = true;
        } else if (std.mem.eql(u8, key, "SwapFree")) {
            out.swap_used_bytes = out.swap_total_bytes -| bytes;
        }
    }
    if (!saw_total) return error.Invalid;
    // Kernels without MemAvailable (pre-3.14) fall back to MemFree.
    if (!saw_available) out.available_bytes = mem_free orelse 0;
    out.used_bytes = out.total_bytes -| out.available_bytes;
    if (!saw_swap_total) out.swap_total_bytes = 0;
    return out;
}

/// `df -kP /` output: header + one line per filesystem, 1024-byte blocks.
/// The root filesystem is the line whose last whitespace token is `/`.
/// Handles GNU (`1024-blocks … Capacity`) and busybox (`1K-blocks … Use%`).
pub fn parseDf(text: []const u8) ParseError!DiskInfo {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        var tokens = std.mem.tokenizeAny(u8, trimmed, " \t");
        var fields: [6][]const u8 = undefined;
        var n: usize = 0;
        while (tokens.next()) |t| {
            if (n == fields.len) break; // not our root line; skip it
            fields[n] = t;
            n += 1;
        }
        if (n < 6) continue;
        if (!std.mem.eql(u8, fields[n - 1], "/")) continue;
        return .{
            .total_bytes = std.math.mul(u64, std.fmt.parseInt(u64, fields[1], 10) catch return error.Invalid, 1024) catch return error.Invalid,
            .used_bytes = std.math.mul(u64, std.fmt.parseInt(u64, fields[2], 10) catch return error.Invalid, 1024) catch return error.Invalid,
            .available_bytes = std.math.mul(u64, std.fmt.parseInt(u64, fields[3], 10) catch return error.Invalid, 1024) catch return error.Invalid,
        };
    }
    return error.Invalid;
}

/// `ps` rows: procps `PID COMM %CPU %MEM` (4 tokens) or the busybox
/// fallback `PID COMMAND` (2 tokens, cpu/mem unknown). Header lines (first
/// token non-numeric) are skipped; rows are capped at 10 after parse.
pub fn parsePs(allocator: std.mem.Allocator, text: []const u8) ParseError![]Process {
    var out: std.ArrayList(Process) = .empty;
    errdefer {
        for (out.items) |p| allocator.free(p.name);
        out.deinit(allocator);
    }
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (out.items.len == 10) break;
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        var tokens = std.mem.tokenizeAny(u8, trimmed, " \t");
        const pid_text = tokens.next() orelse continue;
        const pid = std.fmt.parseInt(u32, pid_text, 10) catch continue; // header row
        const name = tokens.next() orelse continue;
        var cpu: ?f32 = null;
        var mem: ?f32 = null;
        if (tokens.next()) |cpu_text| {
            // A third token without a fourth is a variant we cannot label
            // confidently — fail the section rather than misreport.
            const mem_text = tokens.next() orelse return error.Invalid;
            cpu = std.fmt.parseFloat(f32, cpu_text) catch return error.Invalid;
            mem = std.fmt.parseFloat(f32, mem_text) catch return error.Invalid;
        }
        out.append(allocator, .{
            .pid = pid,
            .name = allocator.dupe(u8, name) catch return error.Invalid,
            .cpu = cpu,
            .mem = mem,
        }) catch return error.Invalid;
    }
    return out.toOwnedSlice(allocator) catch return error.Invalid;
}

pub const ProbeResult = struct {
    snapshot: Snapshot,
    cpu_sample: ?CpuSample,
};

/// Composes a snapshot from the marker-delimited probe output. Any section
/// that is missing, empty, or unparseable sets `probe_error` (honest
/// degraded state — the UI never sees fabricated numbers). The CPU delta
/// uses the previous sample when one exists; the first valid sample warms
/// up instead of inventing a percentage.
pub fn parseProbeOutput(allocator: std.mem.Allocator, text: []const u8, previous_cpu: ?CpuSample) ProbeResult {
    var result = ProbeResult{ .snapshot = .{}, .cpu_sample = null };
    var section: []const u8 = "";
    var section_text: std.ArrayList(u8) = .empty;
    defer section_text.deinit(allocator);

    var failed: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len > 0 and line[0] == '%' and std.mem.endsWith(u8, line, "%")) {
            tryParseSection(allocator, section, section_text.items, previous_cpu, &result, &failed) catch {};
            section_text.clearRetainingCapacity();
            section = line;
            continue;
        }
        if (section.len == 0) continue; // bytes before the first marker
        if (section_text.items.len < 256 * 1024) {
            section_text.appendSlice(allocator, line) catch {};
            section_text.append(allocator, '\n') catch {};
        }
    }
    tryParseSection(allocator, section, section_text.items, previous_cpu, &result, &failed) catch {};

    if (failed) |msg| {
        result.snapshot.probe_error = msg;
        if (result.snapshot.processes.len > 0) {
            for (result.snapshot.processes) |p| allocator.free(p.name);
            allocator.free(result.snapshot.processes);
            result.snapshot.processes = &.{};
        }
    }
    return result;
}

fn tryParseSection(
    allocator: std.mem.Allocator,
    marker: []const u8,
    text: []const u8,
    previous_cpu: ?CpuSample,
    result: *ProbeResult,
    failed: *?[]const u8,
) !void {
    if (failed.* != null) return;
    const snap = &result.snapshot;
    if (std.mem.eql(u8, marker, "%BEGIN_STAT%")) {
        const sample = parseStat(text) catch {
            failed.* = "probe section 'stat' unreadable";
            return;
        };
        result.cpu_sample = sample;
        if (previous_cpu) |prev| {
            snap.cpu.utilization_pct = utilization(prev, sample);
            snap.cpu.cpu_warming = false;
        } else {
            snap.cpu.utilization_pct = null;
            snap.cpu.cpu_warming = true;
        }
    } else if (std.mem.eql(u8, marker, "%BEGIN_LOADAVG%")) {
        const loads = parseLoadAvg(text) catch {
            failed.* = "no /proc readable (loadavg empty)";
            return;
        };
        snap.cpu.load_1 = loads[0];
        snap.cpu.load_5 = loads[1];
        snap.cpu.load_15 = loads[2];
    } else if (std.mem.eql(u8, marker, "%BEGIN_NPROC%")) {
        snap.cpu.cores = parseNproc(text) catch {
            failed.* = "probe section 'nproc' unreadable";
            return;
        };
    } else if (std.mem.eql(u8, marker, "%BEGIN_UPTIME%")) {
        snap.cpu.uptime_sec = parseUptime(text) catch {
            failed.* = "probe section 'uptime' unreadable";
            return;
        };
    } else if (std.mem.eql(u8, marker, "%BEGIN_MEMINFO%")) {
        snap.mem = parseMemInfo(text) catch {
            failed.* = "probe section 'meminfo' unreadable";
            return;
        };
    } else if (std.mem.eql(u8, marker, "%BEGIN_DF%")) {
        snap.disk = parseDf(text) catch {
            failed.* = "probe section 'df' unreadable";
            return;
        };
    } else if (std.mem.eql(u8, marker, "%BEGIN_PS%")) {
        snap.processes = parsePs(allocator, text) catch {
            failed.* = "probe section 'ps' unreadable";
            return;
        };
    }
    // Unknown markers are ignored (forward compatibility).
}

fn firstLine(text: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \t\r").len > 0) return line;
    }
    return null;
}

/// Per-session probe cache. The worker commits snapshots; bridge handlers
/// serialize them under the same lock.
pub const Cache = struct {
    mutex: std.atomic.Mutex = .unlocked,
    snapshot: ?Snapshot = null,
    previous_cpu: ?CpuSample = null,

    pub fn lock(self: *Cache) void {
        lockSpin(&self.mutex);
    }

    pub fn unlock(self: *Cache) void {
        self.mutex.unlock();
    }

    pub fn current(self: *Cache) ?*const Snapshot {
        return if (self.snapshot) |*s| s else null;
    }

    /// Commits a parsed snapshot plus the CPU sample it was derived from
    /// (the sample advances even when other sections failed, so the next
    /// probe still gets a fresh delta).
    pub fn commit(self: *Cache, allocator: std.mem.Allocator, snap: Snapshot, cpu_sample: ?CpuSample) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.snapshot) |*old| old.deinit(allocator);
        self.snapshot = snap;
        self.previous_cpu = cpu_sample orelse self.previous_cpu;
    }

    pub fn deinit(self: *Cache, allocator: std.mem.Allocator) void {
        if (self.snapshot) |*s| s.deinit(allocator);
        self.snapshot = null;
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// --- tests ---------------------------------------------------------------

const fixtures = struct {
    const stat = "cpu  81234 4521 18734 890123 12034 782 901 0 0 0\ncpu0 40000 2000 9000 440000 6000 400 450 0 0 0\n";

    const loadavg = "0.61 0.61 0.55 3/828 22084\n";
    const loadavg_ws = "  0.61\t0.61   0.55  3/828 22084  \n";

    const meminfo =
        \\MemTotal:        8020488 kB
        \\MemFree:         2880488 kB
        \\MemAvailable:    5012345 kB
        \\Buffers:             224 kB
        \\Cached:           329004 kB
        \\SwapTotal:       2097148 kB
        \\SwapFree:        1048572 kB
        \\
    ;
    const meminfo_no_available =
        \\MemTotal:        8020488 kB
        \\MemFree:         2880488 kB
        \\SwapTotal:       2097148 kB
        \\
    ;

    const df_gnu = "Filesystem     1024-blocks    Used Available Capacity Mounted on\n/dev/sda1       20318208 10000000 10318208      50% /\n";
    const df_busybox = "Filesystem           1K-blocks    Used Available Use% Mounted on\noverlay               38076416   5302628  32773788  14% /\n";
    const df_multi = "Filesystem     1024-blocks    Used Available Capacity Mounted on\n/dev/sda1       20318208 10000000 10318208      50% /boot\n/dev/sda1       20318208 12000000  8318208      59% /\n";

    const ps_procps = "  1234 node 2.2 3.3\n  56 sshd 0.1 0.2\n";
    const ps_busybox = "PID   COMMAND\n    1 sh\n   13 ps\n   14 head\n";
    const ps_with_header = "  PID COMM %CPU %MEM\n 1234 node 2.2 3.3\n";
};

test "parseStat sums ticks and counts idle + iowait" {
    const sample = try parseStat(fixtures.stat);
    // 81234 + 4521 + 18734 + 890123 + 12034 + 782 + 901 = 1008329
    try std.testing.expectEqual(@as(u64, 1008329), sample.total);
    try std.testing.expectEqual(@as(u64, 902157), sample.idle);
    try std.testing.expectError(error.Invalid, parseStat("cpu  1 2\n"));
    try std.testing.expectError(error.Invalid, parseStat("proc 1 2 3 4 5\n"));
    try std.testing.expectError(error.Invalid, parseStat(""));
}

test "cpu utilization is computed from tick deltas and clamped" {
    const prev = CpuSample{ .total = 1000, .idle = 800 };
    const cur = CpuSample{ .total = 1200, .idle = 850 };
    const pct = utilization(prev, cur).?;
    // busy = 200 - 50 = 150 of 200 ticks = 75%
    try std.testing.expectApproxEqAbs(@as(f32, 75), pct, 0.01);

    // No total delta: no percentage, never a division by zero.
    try std.testing.expect(utilization(prev, prev) == null);
    // Clamped: more idle than busy is still 0..100.
    const backwards = utilization(CpuSample{ .total = 1000, .idle = 100 }, CpuSample{ .total = 1100, .idle = 1090 });
    try std.testing.expectApproxEqAbs(@as(f32, 0), backwards.?, 0.01);
}

test "loadavg, nproc, and uptime parse with flexible whitespace" {
    const loads = try parseLoadAvg(fixtures.loadavg);
    try std.testing.expectApproxEqAbs(@as(f32, 0.61), loads[0], 0.001);
    try std.testing.expectApproxEqAbs(@as(f32, 0.61), loads[1], 0.001);
    try std.testing.expectApproxEqAbs(@as(f32, 0.55), loads[2], 0.001);
    const loads_ws = try parseLoadAvg(fixtures.loadavg_ws);
    try std.testing.expectApproxEqAbs(@as(f32, 0.61), loads_ws[0], 0.001);

    try std.testing.expectEqual(@as(u32, 2), try parseNproc("2\n"));
    try std.testing.expectEqual(@as(u32, 8), try parseNproc("  8  \n"));
    try std.testing.expectError(error.Invalid, parseNproc("many\n"));

    try std.testing.expectEqual(@as(u64, 19500000), try parseUptime("19500000.12 32000000.50\n"));
    try std.testing.expectError(error.Invalid, parseUptime("soon\n"));
}

test "meminfo parses bytes, falls back to MemFree, and computes swap used" {
    const mem = try parseMemInfo(fixtures.meminfo);
    try std.testing.expectEqual(@as(u64, 8020488 * 1024), mem.total_bytes);
    try std.testing.expectEqual(@as(u64, 5012345 * 1024), mem.available_bytes);
    try std.testing.expectEqual(@as(u64, (8020488 - 5012345) * 1024), mem.used_bytes);
    try std.testing.expectEqual(@as(u64, 2097148 * 1024), mem.swap_total_bytes);
    try std.testing.expectEqual(@as(u64, (2097148 - 1048572) * 1024), mem.swap_used_bytes);

    // Kernels without MemAvailable fall back to MemFree (documented).
    const fallback = try parseMemInfo(fixtures.meminfo_no_available);
    try std.testing.expectEqual(@as(u64, 2880488 * 1024), fallback.available_bytes);

    try std.testing.expectError(error.Invalid, parseMemInfo("Bogus: 1 kB\n"));
}

test "df parses GNU and busybox layouts, picking the root filesystem" {
    const gnu = try parseDf(fixtures.df_gnu);
    try std.testing.expectEqual(@as(u64, 20318208 * 1024), gnu.total_bytes);
    try std.testing.expectEqual(@as(u64, 10000000 * 1024), gnu.used_bytes);
    try std.testing.expectEqual(@as(u64, 10318208 * 1024), gnu.available_bytes);

    const busybox = try parseDf(fixtures.df_busybox);
    try std.testing.expectEqual(@as(u64, 38076416 * 1024), busybox.total_bytes);

    // Multiple lines for the same device: the mount point "/" wins.
    const multi = try parseDf(fixtures.df_multi);
    try std.testing.expectEqual(@as(u64, 12000000 * 1024), multi.used_bytes);

    try std.testing.expectError(error.Invalid, parseDf("Filesystem 1K-blocks Used Available Use% Mounted on\n"));
}

test "ps parses procps rows, busybox fallback rows, and skips headers" {
    const allocator = std.testing.allocator;
    const procps = try parsePs(allocator, fixtures.ps_procps);
    defer {
        for (procps) |p| allocator.free(p.name);
        allocator.free(procps);
    }
    try std.testing.expectEqual(@as(usize, 2), procps.len);
    try std.testing.expectEqual(@as(u32, 1234), procps[0].pid);
    try std.testing.expectEqualStrings("node", procps[0].name);
    try std.testing.expectApproxEqAbs(@as(f32, 2.2), procps[0].cpu.?, 0.01);

    // Busybox: cpu/mem are null, never invented zeros.
    const busybox = try parsePs(allocator, fixtures.ps_busybox);
    defer {
        for (busybox) |p| allocator.free(p.name);
        allocator.free(busybox);
    }
    try std.testing.expectEqual(@as(usize, 3), busybox.len);
    try std.testing.expectEqual(@as(u32, 1), busybox[0].pid);
    try std.testing.expect(busybox[0].cpu == null);
    try std.testing.expect(busybox[0].mem == null);

    // A header line is skipped by the numeric pid check.
    const headed = try parsePs(allocator, fixtures.ps_with_header);
    defer {
        for (headed) |p| allocator.free(p.name);
        allocator.free(headed);
    }
    try std.testing.expectEqual(@as(usize, 1), headed.len);

    // A three-token row is a variant we cannot label: fail the section.
    try std.testing.expectError(error.Invalid, parsePs(allocator, "  1234 node 2.2\n"));
}

test "ps output is capped at 10 rows" {
    const allocator = std.testing.allocator;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    var i: usize = 0;
    while (i < 15) : (i += 1) {
        const line = try std.fmt.allocPrint(allocator, "  {d} proc{d} 1.0 2.0\n", .{ i + 100, i });
        defer allocator.free(line);
        try text.appendSlice(allocator, line);
    }
    const rows = try parsePs(allocator, text.items);
    defer {
        for (rows) |p| allocator.free(p.name);
        allocator.free(rows);
    }
    try std.testing.expectEqual(@as(usize, 10), rows.len);
}

test "probe output composes a full snapshot with cpu delta" {
    const allocator = std.testing.allocator;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    try text.appendSlice(allocator, "%BEGIN_STAT%\n");
    try text.appendSlice(allocator, fixtures.stat);
    try text.appendSlice(allocator, "%BEGIN_LOADAVG%\n");
    try text.appendSlice(allocator, fixtures.loadavg);
    try text.appendSlice(allocator, "%BEGIN_NPROC%\n2\n");
    try text.appendSlice(allocator, "%BEGIN_UPTIME%\n19500000.12 32000000.50\n");
    try text.appendSlice(allocator, "%BEGIN_MEMINFO%\n");
    try text.appendSlice(allocator, fixtures.meminfo);
    try text.appendSlice(allocator, "%BEGIN_DF%\n");
    try text.appendSlice(allocator, fixtures.df_busybox);
    try text.appendSlice(allocator, "%BEGIN_PS%\n");
    try text.appendSlice(allocator, fixtures.ps_procps);

    var first = parseProbeOutput(allocator, text.items, null);
    defer first.snapshot.deinit(allocator);
    try std.testing.expect(first.snapshot.probe_error == null);
    try std.testing.expect(first.snapshot.cpu.cpu_warming);
    try std.testing.expect(first.snapshot.cpu.utilization_pct == null);
    try std.testing.expectApproxEqAbs(@as(f32, 0.61), first.snapshot.cpu.load_1, 0.001);
    try std.testing.expectEqual(@as(u32, 2), first.snapshot.cpu.cores);
    try std.testing.expectEqual(@as(u64, 19500000), first.snapshot.cpu.uptime_sec);
    try std.testing.expect(first.snapshot.mem.total_bytes > 0);
    try std.testing.expect(first.snapshot.disk.total_bytes > 0);
    try std.testing.expectEqual(@as(usize, 2), first.snapshot.processes.len);
    try std.testing.expectEqual(@as(u64, 1008329), first.cpu_sample.?.total);

    // Second probe with the first sample: utilization is now real.
    var second = parseProbeOutput(allocator, text.items, first.cpu_sample);
    defer second.snapshot.deinit(allocator);
    try std.testing.expect(!second.snapshot.cpu.cpu_warming);
    // Identical samples: no total delta -> still null, never a fake 0%.
    try std.testing.expect(second.snapshot.cpu.utilization_pct == null);
}

test "probe output failure sets probe_error instead of fabricating data" {
    const allocator = std.testing.allocator;
    // Missing /proc: the loadavg section is empty -> explicit probe_error.
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    try text.appendSlice(allocator, "%BEGIN_STAT%\n");
    try text.appendSlice(allocator, fixtures.stat);
    try text.appendSlice(allocator, "%BEGIN_LOADAVG%\n%BEGIN_NPROC%\n2\n");

    var result = parseProbeOutput(allocator, text.items, null);
    defer result.snapshot.deinit(allocator);
    try std.testing.expect(result.snapshot.probe_error != null);
    try std.testing.expect(std.mem.indexOf(u8, result.snapshot.probe_error.?, "loadavg") != null);
    // Sections that parsed before the failure stay visible (degraded, not
    // wiped): the stat sample survives; nproc comes after the failing
    // section and is correctly skipped.
    try std.testing.expect(result.cpu_sample != null);
    try std.testing.expectEqual(@as(u32, 0), result.snapshot.cpu.cores);
}

test "probe command is fixed, marker-delimited, and has the busybox ps fallback" {
    try std.testing.expect(std.mem.indexOf(u8, probe_command, "%BEGIN_STAT%") != null);
    try std.testing.expect(std.mem.indexOf(u8, probe_command, "%BEGIN_LOADAVG%") != null);
    try std.testing.expect(std.mem.indexOf(u8, probe_command, "%BEGIN_NPROC%") != null);
    try std.testing.expect(std.mem.indexOf(u8, probe_command, "%BEGIN_UPTIME%") != null);
    try std.testing.expect(std.mem.indexOf(u8, probe_command, "%BEGIN_MEMINFO%") != null);
    try std.testing.expect(std.mem.indexOf(u8, probe_command, "%BEGIN_DF%") != null);
    try std.testing.expect(std.mem.indexOf(u8, probe_command, "%BEGIN_PS%") != null);
    try std.testing.expect(std.mem.indexOf(u8, probe_command, "--sort=-%cpu") != null);
    // The fallback must exist: busybox ps rejects %cpu (verified live).
    try std.testing.expect(std.mem.indexOf(u8, probe_command, "|| ps -eo pid,comm") != null);
}

test "cache commit replaces snapshots leak-free and keeps the cpu sample" {
    const allocator = std.testing.allocator;
    var cache = Cache{};
    defer cache.deinit(allocator);

    var snap = Snapshot{};
    snap.processes = try allocator.alloc(Process, 1);
    snap.processes[0] = .{ .pid = 1, .name = try allocator.dupe(u8, "x") };
    cache.commit(allocator, snap, .{ .total = 10, .idle = 5 });

    cache.lock();
    try std.testing.expect(cache.current() != null);
    try std.testing.expectEqual(@as(u64, 10), cache.previous_cpu.?.total);
    cache.unlock();

    // Replacing frees the old snapshot's processes (leak-checked). Never
    // commit while holding the cache lock: commit takes the same spinlock.
    cache.commit(allocator, Snapshot{}, null);
    cache.lock();
    try std.testing.expectEqual(@as(usize, 0), cache.current().?.processes.len);
    cache.unlock();
}
