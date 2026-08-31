//! AI Terminal (spec 11) native backend.
//!
//! Provider requests, credentials, durable turns, proposals, and approved
//! SSH execution stay in the native process. This root module also owns the
//! light server-context probe helpers used by the asynchronous context worker.
//!
//! The probe is marker-delimited like the monitor probe (spec 03) and
//! the logs scan (spec 04): `%BEGIN_OS%` (PRETTY_NAME with a `uname -sr`
//! fallback), `%BEGIN_HOSTNAME%` (/proc/sys/kernel/hostname), and
//! `%BEGIN_LOGS%` (one `stat -c '%Y %n'` line per configured source —
//! busybox-compatible, missing files skipped).

const std = @import("std");
const shellquote = @import("shellquote.zig");
const monitor = @import("monitor.zig");

pub const types = @import("ai/types.zig");
pub const provider_domain = @import("ai/provider.zig");
pub const credentials = @import("ai/credentials.zig");
pub const sse = @import("ai/sse.zig");
pub const proposal = @import("ai/proposal.zig");
pub const responses = @import("ai/responses.zig");
pub const chat = @import("ai/chat.zig");
pub const transport = @import("ai/transport.zig");
pub const events = @import("ai/events.zig");
pub const context = @import("ai/context.zig");
pub const provider_test = @import("ai/provider_test.zig");
pub const journal = @import("ai/journal.zig");
pub const request_slots = @import("ai/request_slots.zig");
pub const coordinator = @import("ai/coordinator.zig");

comptime {
    _ = types;
    _ = provider_domain;
    _ = credentials;
    _ = sse;
    _ = proposal;
    _ = responses;
    _ = chat;
    _ = transport;
    _ = events;
    _ = context;
    _ = provider_test;
    _ = journal;
    _ = request_slots;
    _ = coordinator;
}

/// The bundle carries at most this many log sources (most recently
/// written first — the spec's "defaults to the most recently active").
pub const max_active_logs = 10;
/// Exec audit detail is capped so a huge command cannot bloat the line.
pub const audit_cmd_cap = 120;

// --- context bundle probe -------------------------------------------------

pub const LogProbe = struct {
    /// Views the probe output (never allocated).
    path: []const u8,
    last_write: u64,
};

pub const ProbeParse = struct {
    os: []const u8 = "",
    hostname: []const u8 = "",
    /// Views the probe output; the caller filters and owns what it keeps.
    logs: []const LogProbe = &.{},
};

/// One exec: OS identity, hostname, monitor facts, and a `stat` per
/// configured log source. The AI context does not depend on the Monitor tab
/// having populated its separate on-demand cache first.
pub fn buildProbeCommand(allocator: std.mem.Allocator, log_paths: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "printf '%%BEGIN_OS%%\\n'; (grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null || uname -sr); printf '%%BEGIN_HOSTNAME%%\\n'; cat /proc/sys/kernel/hostname 2>/dev/null; printf '%%BEGIN_LOGS%%\\n'; for p in ");
    for (log_paths) |path| {
        const q = try shellquote.quote(allocator, path);
        defer allocator.free(q);
        try out.append(allocator, ' ');
        try out.appendSlice(allocator, q);
    }
    try out.appendSlice(allocator, "; do stat -c '%Y %n' \"$p\" 2>/dev/null; done; true; ");
    try out.appendSlice(allocator, monitor.probe_command);
    return out.toOwnedSlice(allocator);
}

fn cleanOsLine(line: []const u8) []const u8 {
    var s = std.mem.trim(u8, line, " \t\r");
    if (std.mem.startsWith(u8, s, "PRETTY_NAME=")) s = s["PRETTY_NAME=".len..];
    s = std.mem.trim(u8, s, "\"");
    return std.mem.trim(u8, s, " \t\r");
}

/// Splits the marker-delimited probe output into views over `text`.
pub fn parseProbeOutput(allocator: std.mem.Allocator, text: []const u8) !ProbeParse {
    var logs: std.ArrayList(LogProbe) = .empty;
    errdefer logs.deinit(allocator);
    var result = ProbeParse{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    var section: enum { none, os, hostname, logs } = .none;
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (std.mem.eql(u8, trimmed, "%BEGIN_OS%")) {
            section = .os;
            continue;
        }
        if (std.mem.eql(u8, trimmed, "%BEGIN_HOSTNAME%")) {
            section = .hostname;
            continue;
        }
        if (std.mem.eql(u8, trimmed, "%BEGIN_LOGS%")) {
            section = .logs;
            continue;
        }
        if (std.mem.startsWith(u8, trimmed, "%BEGIN_") and std.mem.endsWith(u8, trimmed, "%")) {
            section = .none;
            continue;
        }
        if (trimmed.len == 0) continue;
        switch (section) {
            .none => {},
            .os => {
                if (result.os.len == 0) result.os = cleanOsLine(trimmed);
            },
            .hostname => {
                if (result.hostname.len == 0) result.hostname = trimmed;
            },
            .logs => {
                const sp = std.mem.indexOfScalar(u8, trimmed, ' ') orelse continue;
                const epoch = std.fmt.parseInt(u64, trimmed[0..sp], 10) catch continue;
                try logs.append(allocator, .{ .path = std.mem.trim(u8, trimmed[sp + 1 ..], " \t"), .last_write = epoch });
            },
        }
    }
    result.logs = try logs.toOwnedSlice(allocator);
    return result;
}

/// One configured log source with its last-write time (owned).
pub const LogInfo = struct {
    path: []const u8,
    last_write: u64,

    pub fn deinit(self: *LogInfo, allocator: std.mem.Allocator) void {
        if (self.path.len > 0) allocator.free(self.path);
    }
};

fn lessByWriteDesc(_: void, a: LogInfo, b: LogInfo) bool {
    return a.last_write > b.last_write;
}

/// Filters the parsed log lines to the configured sources, sorts by
/// last-write (most recent first), and caps the list.
pub fn buildActiveLogs(
    allocator: std.mem.Allocator,
    parsed: []const LogProbe,
    configured: []const []const u8,
    cap: usize,
) ![]LogInfo {
    var out: std.ArrayList(LogInfo) = .empty;
    errdefer {
        for (out.items) |*l| l.deinit(allocator);
        out.deinit(allocator);
    }
    for (parsed) |lp| {
        for (configured) |c| {
            if (std.mem.eql(u8, lp.path, c)) {
                try out.append(allocator, .{ .path = try allocator.dupe(u8, lp.path), .last_write = lp.last_write });
                break;
            }
        }
    }
    std.mem.sort(LogInfo, out.items, {}, lessByWriteDesc);
    if (out.items.len > cap) {
        for (out.items[cap..]) |*l| l.deinit(allocator);
        out.items.len = cap;
    }
    return out.toOwnedSlice(allocator);
}

// --- registry -------------------------------------------------------------

pub const Registry = struct {
    allocator: std.mem.Allocator,
    providers: provider_domain.Store = .{},
    journal_store: journal.Store = undefined,
    request_limiter: request_slots.Limiter = .{},
    credential_facade: credentials.Facade = .{},
    context_ops: context.Registry = undefined,
    provider_tests: ?provider_test.Registry = null,
    turns: ?coordinator.Registry = null,

    pub fn init(allocator: std.mem.Allocator, provider_path: []const u8, journal_path: []const u8) Registry {
        return .{
            .allocator = allocator,
            .providers = .{ .allocator = allocator, .path = provider_path },
            .journal_store = .{ .allocator = allocator, .path = journal_path },
            .context_ops = .{ .allocator = allocator },
        };
    }

    pub fn startProviderTests(self: *Registry, io: std.Io) void {
        if (self.provider_tests == null) self.provider_tests = provider_test.Registry.init(self.allocator, io, &self.providers, &self.request_limiter);
        if (self.turns == null) self.turns = coordinator.Registry.init(self.allocator, io, &self.providers, &self.journal_store, &self.request_limiter);
    }

    pub fn stopProviderTests(self: *Registry) void {
        if (self.provider_tests) |*tests| tests.deinit();
        self.provider_tests = null;
        if (self.turns) |*turns| turns.deinit();
        self.turns = null;
    }

    pub fn deinit(self: *Registry) void {
        self.stopProviderTests();
        self.journal_store.deinit();
        self.context_ops.deinit();
    }
};

// --- unit tests -----------------------------------------------------------

test "probe command quotes log paths and is busybox-shaped" {
    const allocator = std.testing.allocator;
    const paths = [_][]const u8{ "/var/log/nginx/access.log", "/var/log/my app.log" };
    const cmd = try buildProbeCommand(allocator, &paths);
    defer allocator.free(cmd);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "%BEGIN_OS%") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "%BEGIN_HOSTNAME%") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "%BEGIN_LOGS%") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "%BEGIN_DF%") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "%BEGIN_PS%") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "'/var/log/nginx/access.log'") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "'/var/log/my app.log'") != null);
}

test "probe output parses os, hostname, and log mtimes (views)" {
    const allocator = std.testing.allocator;
    const text =
        "%BEGIN_OS%\nPRETTY_NAME=\"Alpine Linux v3.20\"\n" ++
        "%BEGIN_HOSTNAME%\n79f4a1c2d3e4\n" ++
        "%BEGIN_LOGS%\n1754000000 /var/log/nginx/access.log\n" ++
        "1753999900 /var/log/my app.log\n";
    const parsed = try parseProbeOutput(allocator, text);
    defer allocator.free(parsed.logs);
    try std.testing.expectEqualStrings("Alpine Linux v3.20", parsed.os);
    try std.testing.expectEqualStrings("79f4a1c2d3e4", parsed.hostname);
    try std.testing.expectEqual(@as(usize, 2), parsed.logs.len);
    try std.testing.expectEqualStrings("/var/log/nginx/access.log", parsed.logs[0].path); // output order preserved
    try std.testing.expectEqual(@as(u64, 1754000000), parsed.logs[0].last_write);
    try std.testing.expectEqualStrings("/var/log/my app.log", parsed.logs[1].path); // space survives

    const with_monitor =
        "%BEGIN_LOGS%\n1754000000 /var/log/nginx/access.log\n" ++
        "%BEGIN_PS%\n1234 node 2.2 3.3\n";
    const parsed_with_monitor = try parseProbeOutput(allocator, with_monitor);
    defer allocator.free(parsed_with_monitor.logs);
    try std.testing.expectEqual(@as(usize, 1), parsed_with_monitor.logs.len);
    try std.testing.expectEqual(@as(u64, 1753999900), parsed.logs[1].last_write);

    // uname fallback and garbage lines.
    const fallback =
        "%BEGIN_OS%\nLinux 6.8.0\n" ++
        "%BEGIN_HOSTNAME%\nbox\n" ++
        "%BEGIN_LOGS%\nnot-a-number /x\n" ++
        "1754000000 /only-this.log\n";
    const parsed2 = try parseProbeOutput(allocator, fallback);
    defer allocator.free(parsed2.logs);
    try std.testing.expectEqualStrings("Linux 6.8.0", parsed2.os);
    try std.testing.expectEqualStrings("box", parsed2.hostname);
    try std.testing.expectEqual(@as(usize, 1), parsed2.logs.len);
    try std.testing.expectEqualStrings("/only-this.log", parsed2.logs[0].path);
}

test "active logs filter to configured sources, newest first, capped" {
    const allocator = std.testing.allocator;
    const parsed = try parseProbeOutput(allocator, "%BEGIN_LOGS%\n100 /var/log/a.log\n200 /var/log/b.log\n300 /var/log/c.log\n400 /var/log/d.log\n" ++
        "500 /var/log/not-configured.log\n");
    defer allocator.free(parsed.logs);
    const configured = [_][]const u8{ "/var/log/a.log", "/var/log/b.log", "/var/log/c.log", "/var/log/d.log" };
    const logs = try buildActiveLogs(allocator, parsed.logs, &configured, 3);
    defer {
        for (logs) |*l| l.deinit(allocator);
        allocator.free(logs);
    }
    try std.testing.expectEqual(@as(usize, 3), logs.len);
    try std.testing.expectEqualStrings("/var/log/d.log", logs[0].path); // newest first
    try std.testing.expectEqualStrings("/var/log/c.log", logs[1].path);
    try std.testing.expectEqualStrings("/var/log/b.log", logs[2].path);
    // Missing sources simply don't appear.
    const none = try buildActiveLogs(allocator, parsed.logs, &.{}, 10);
    defer {
        for (none) |*l| l.deinit(allocator);
        allocator.free(none);
    }
    try std.testing.expectEqual(@as(usize, 0), none.len);
}
