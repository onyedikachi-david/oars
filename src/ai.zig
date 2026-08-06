//! AI Terminal (spec 11) backend: provider config storage and the server
//! context bundle.
//!
//! The AI call itself is frontend-side (spec 11 §6: Zig adds only
//! `oars.ai.context` and history filtering). This module provides:
//!   - the provider store (`<data>/ai.json`: adapter, base URL, model,
//!     explicit capabilities — never the API key, which lives in the
//!     frontend Keychain under `ai:<base_url>`),
//!   - the context probe command + parser (OS, hostname, and per-source
//!     log mtimes; the monitor snapshot is composed by the bridge
//!     handler from the spec 03 cache),
//!   - the ≤ 5 s per-server context cache.
//!
//! The probe is marker-delimited like the monitor probe (spec 03) and
//! the logs scan (spec 04): `%BEGIN_OS%` (PRETTY_NAME with a `uname -sr`
//! fallback), `%BEGIN_HOSTNAME%` (/proc/sys/kernel/hostname), and
//! `%BEGIN_LOGS%` (one `stat -c '%Y %n'` line per configured source —
//! busybox-compatible, missing files skipped).

const std = @import("std");
const shellquote = @import("shellquote.zig");

pub const max_base_url_len = 512;
pub const max_model_len = 256;
pub const max_adapter_len = 32;
/// The context probe result is cached per server for 5 s (spec 11 §5).
pub const context_cache_ttl_ns: i128 = 5 * std.time.ns_per_s;
/// Servers with a cached probe result (a small ring; evicts oldest).
pub const max_cached_servers = 16;
/// The bundle carries at most this many log sources (most recently
/// written first — the spec's "defaults to the most recently active").
pub const max_active_logs = 10;
pub const history_default_limit: usize = 20;
pub const history_max_limit: usize = 100;
/// Exec audit detail is capped so a huge command cannot bloat the line.
pub const audit_cmd_cap = 120;

// --- provider config ------------------------------------------------------

pub const Adapter = enum(u8) {
    /// Chat Completions baseline with reviewed defaults (spec 11 §13).
    openai_compatible,
    /// User picks role/streaming/structured-output explicitly.
    custom,

    pub fn jsonName(self: Adapter) []const u8 {
        return @tagName(self);
    }

    pub fn fromJsonName(name: []const u8) ?Adapter {
        if (std.mem.eql(u8, name, "openai_compatible")) return .openai_compatible;
        if (std.mem.eql(u8, name, "custom")) return .custom;
        return null;
    }
};

pub const Capabilities = struct {
    /// `developer` (OpenAI-style) or `system` — never assumed (spec 11
    /// §13: compatible providers differ).
    instruction_role: []const u8 = "system",
    streaming: bool = true,
    structured_output: bool = false,
};

pub const Provider = struct {
    adapter: Adapter,
    base_url: []const u8,
    model: []const u8,
    capabilities: Capabilities = .{},
    updated_at_ns: i64 = 0,

    pub fn deinit(self: *Provider, allocator: std.mem.Allocator) void {
        // Validated non-empty (validate()); free unconditionally is safe.
        allocator.free(self.base_url);
        allocator.free(self.model);
        allocator.free(self.capabilities.instruction_role);
    }
};

pub const ProviderInput = struct {
    adapter: []const u8,
    base_url: []const u8,
    model: []const u8,
    capabilities: Capabilities = .{},
};

pub const SaveError = error{
    InvalidAdapter,
    InvalidBaseUrl,
    InvalidModel,
    InvalidCapabilities,
    StoreCorrupt,
    SerializeFailed,
    OutOfMemory,
};

fn hasControlChars(s: []const u8) bool {
    for (s) |ch| {
        if (ch == 0 or ch < 0x20 or ch == 0x7f) return true;
    }
    return false;
}

/// HTTPS always; plain HTTP only for loopback hosts (a user-chosen local
/// model server — spec 11 §5: "HTTPS is required except for
/// user-approved loopback URLs").
pub fn validBaseUrl(url: []const u8) bool {
    if (url.len == 0 or url.len > max_base_url_len) return false;
    if (hasControlChars(url)) return false;
    const scheme_end = std.mem.indexOf(u8, url, "://") orelse return false;
    const scheme = url[0..scheme_end];
    const rest = url[scheme_end + 3 ..];
    if (rest.len == 0) return false;
    if (std.mem.eql(u8, scheme, "https")) return true;
    if (!std.mem.eql(u8, scheme, "http")) return false;
    const host_end = std.mem.indexOfAny(u8, rest, "/:") orelse rest.len;
    var host = rest[0..host_end];
    if (host.len > 0 and host[0] == '[') {
        // Bracketed IPv6: the split at ':' lands inside the brackets.
        const close = std.mem.indexOfScalar(u8, rest, ']') orelse return false;
        host = rest[0 .. close + 1];
    }
    return std.mem.eql(u8, host, "localhost") or
        std.mem.eql(u8, host, "127.0.0.1") or
        std.mem.eql(u8, host, "[::1]") or
        std.mem.eql(u8, host, "::1");
}

pub fn validate(input: ProviderInput) SaveError!void {
    if (Adapter.fromJsonName(input.adapter) == null) return error.InvalidAdapter;
    const base_url = std.mem.trim(u8, input.base_url, " \t\r\n");
    if (!validBaseUrl(base_url)) return error.InvalidBaseUrl;
    const model = std.mem.trim(u8, input.model, " \t\r\n");
    if (model.len == 0 or model.len > max_model_len or hasControlChars(model)) return error.InvalidModel;
    const role = input.capabilities.instruction_role;
    if (!std.mem.eql(u8, role, "developer") and !std.mem.eql(u8, role, "system")) return error.InvalidCapabilities;
}

/// The persisted provider config — one JSON object (or `null`), no key.
pub const ProviderStore = struct {
    allocator: std.mem.Allocator = undefined,
    path: []const u8 = "",
    mutex: std.atomic.Mutex = .unlocked,

    pub const Loaded = struct {
        parsed: std.json.Parsed(?Provider),
        content: ?[]u8,
        quarantined: ?[]const u8 = null,

        pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
            self.parsed.deinit();
            if (self.content) |c| allocator.free(c);
            if (self.quarantined) |q| allocator.free(q);
        }
    };

    pub fn get(self: *ProviderStore, io: std.Io) !?Provider {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        const p = loaded.parsed.value orelse return null;
        return try cloneProvider(self.allocator, p);
    }

    pub fn set(self: *ProviderStore, io: std.Io, input: ProviderInput, now_ns: i64) SaveError!Provider {
        try validate(input);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const adapter = Adapter.fromJsonName(input.adapter) orelse return error.InvalidAdapter;
        const base_url = std.mem.trim(u8, input.base_url, " \t\r\n");
        const model = std.mem.trim(u8, input.model, " \t\r\n");
        var saved = Provider{
            .adapter = adapter,
            .base_url = try self.allocator.dupe(u8, base_url),
            .model = try self.allocator.dupe(u8, model),
            .capabilities = .{
                .instruction_role = try self.allocator.dupe(u8, input.capabilities.instruction_role),
                .streaming = input.capabilities.streaming,
                .structured_output = input.capabilities.structured_output,
            },
            .updated_at_ns = now_ns,
        };
        errdefer saved.deinit(self.allocator);
        self.saveLocked(io, &saved) catch return error.SerializeFailed;
        return saved;
    }

    fn cloneProvider(allocator: std.mem.Allocator, p: Provider) !Provider {
        return .{
            .adapter = p.adapter,
            .base_url = try allocator.dupe(u8, p.base_url),
            .model = try allocator.dupe(u8, p.model),
            .capabilities = .{
                .instruction_role = try allocator.dupe(u8, p.capabilities.instruction_role),
                .streaming = p.capabilities.streaming,
                .structured_output = p.capabilities.structured_output,
            },
            .updated_at_ns = p.updated_at_ns,
        };
    }

    fn loadLocked(self: *ProviderStore, io: std.Io) !Loaded {
        const cwd = std.Io.Dir.cwd();
        const content = cwd.readFileAlloc(io, self.path, self.allocator, .limited(1024 * 1024)) catch {
            // No store yet — an absent config is `null`, not corruption.
            return .{
                .parsed = try std.json.parseFromSlice(?Provider, self.allocator, "null", .{}),
                .content = null,
            };
        };
        const parsed = std.json.parseFromSlice(?Provider, self.allocator, content, .{}) catch {
            self.allocator.free(content);
            var loaded = Loaded{
                .parsed = try std.json.parseFromSlice(?Provider, self.allocator, "null", .{}),
                .content = null,
            };
            loaded.quarantined = self.quarantine(io) catch null;
            return loaded;
        };
        return .{ .parsed = parsed, .content = content };
    }

    fn quarantine(self: *ProviderStore, io: std.Io) !?[]const u8 {
        const now = std.Io.Timestamp.now(io, .real).nanoseconds;
        var buf: [512]u8 = undefined;
        const dir = std.fs.path.dirname(self.path) orelse return null;
        const base = std.fs.path.basename(self.path);
        const new_path = try std.fmt.bufPrint(&buf, "{s}/{s}.corrupt-{d}", .{ dir, base, now });
        std.Io.Dir.renameAbsolute(self.path, new_path, io) catch return null;
        return try self.allocator.dupe(u8, new_path);
    }

    fn saveLocked(self: *ProviderStore, io: std.Io, p: *const Provider) !void {
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(self.path)) |dir| try cwd.createDirPath(io, dir);
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        std.json.Stringify.value(p, .{ .whitespace = .indent_2 }, &out.writer) catch return error.SerializeFailed;
        var file = try cwd.createFile(io, self.path, .{});
        defer file.close(io);
        if (file.stat(io)) |stat| {
            if (stat.permissions.toMode() & 0o077 != 0) file.setPermissions(io, .fromMode(0o600)) catch {};
        } else |_| {}
        try file.writeStreamingAll(io, out.writer.buffered());
        try file.sync(io);
    }
};

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

/// One exec: OS identity, hostname, and a `stat` per configured log
/// source. Busybox-compatible (`stat -c '%Y %n'`, `grep -m1`, /proc).
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
    try out.appendSlice(allocator, "; do stat -c '%Y %n' \"$p\" 2>/dev/null; done; true");
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

// --- per-server context cache (≤ 5 s) -------------------------------------

pub const ContextCache = struct {
    allocator: std.mem.Allocator = undefined,
    mutex: std.atomic.Mutex = .unlocked,
    entries: std.ArrayList(CacheEntry) = .empty,

    pub const CacheEntry = struct {
        server_id: []const u8,
        os: []const u8,
        hostname: []const u8,
        active_logs: []LogInfo,
        ts_ns: i128 = 0,

        pub fn deinit(self: *CacheEntry, allocator: std.mem.Allocator) void {
            if (self.server_id.len > 0) allocator.free(self.server_id);
            if (self.os.len > 0) allocator.free(self.os);
            if (self.hostname.len > 0) allocator.free(self.hostname);
            for (self.active_logs) |*l| l.deinit(allocator);
            allocator.free(self.active_logs);
        }
    };

    /// Fresh entry for the server, or null (missing or older than 5 s).
    /// The pointer stays valid until the next `put` — bridge handlers
    /// run on one thread.
    pub fn fresh(self: *ContextCache, server_id: []const u8, now_ns: i128) ?*CacheEntry {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, e.server_id, server_id)) {
                if (now_ns - e.ts_ns < context_cache_ttl_ns) return e;
                return null;
            }
        }
        return null;
    }

    /// Takes ownership of `entry`: replaces the server's previous entry,
    /// or evicts the oldest when at capacity.
    pub fn put(self: *ContextCache, entry: CacheEntry) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.entries.items, 0..) |*e, i| {
            if (std.mem.eql(u8, e.server_id, entry.server_id)) {
                var old = self.entries.items[i];
                self.entries.items[i] = entry;
                old.deinit(self.allocator);
                return;
            }
        }
        if (self.entries.items.len >= max_cached_servers) {
            var oldest: usize = 0;
            for (self.entries.items, 0..) |*e, i| {
                if (e.ts_ns < self.entries.items[oldest].ts_ns) oldest = i;
            }
            var removed = self.entries.orderedRemove(oldest);
            removed.deinit(self.allocator);
        }
        try self.entries.append(self.allocator, entry);
    }

    pub fn deinit(self: *ContextCache) void {
        for (self.entries.items) |*e| e.deinit(self.allocator);
        self.entries.deinit(self.allocator);
    }
};

// --- registry -------------------------------------------------------------

pub const Registry = struct {
    allocator: std.mem.Allocator,
    provider: ProviderStore = .{},
    cache: ContextCache = .{},

    pub fn init(allocator: std.mem.Allocator, provider_path: []const u8) Registry {
        return .{
            .allocator = allocator,
            .provider = .{ .allocator = allocator, .path = provider_path },
            .cache = .{ .allocator = allocator },
        };
    }

    pub fn deinit(self: *Registry) void {
        self.cache.deinit();
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// --- unit tests -----------------------------------------------------------

test "base URL validation: https always, http only on loopback" {
    try std.testing.expect(validBaseUrl("https://api.openai.com/v1"));
    try std.testing.expect(validBaseUrl("https://127.0.0.1:8443/v1"));
    try std.testing.expect(validBaseUrl("http://localhost:11434/v1"));
    try std.testing.expect(validBaseUrl("http://127.0.0.1:8000"));
    try std.testing.expect(validBaseUrl("http://[::1]:8080"));
    try std.testing.expect(!validBaseUrl("http://::1:8080")); // bare IPv6 is not a URI
    try std.testing.expect(!validBaseUrl("http://example.com/v1"));
    try std.testing.expect(!validBaseUrl("http://10.0.0.5/v1"));
    try std.testing.expect(!validBaseUrl("ftp://example.com"));
    try std.testing.expect(!validBaseUrl("api.openai.com/v1"));
    try std.testing.expect(!validBaseUrl("https://"));
    try std.testing.expect(!validBaseUrl("https://api.openai.com/v1\n"));
    try std.testing.expect(!validBaseUrl(""));
}

test "provider validation rejects bad adapters, models, and roles" {
    const good = ProviderInput{
        .adapter = "openai_compatible",
        .base_url = "https://api.openai.com/v1",
        .model = "gpt-4o-mini",
    };
    try validate(good);

    var bad_adapter = good;
    bad_adapter.adapter = "claude";
    try std.testing.expectError(error.InvalidAdapter, validate(bad_adapter));

    var bad_url = good;
    bad_url.base_url = "http://evil.example/v1";
    try std.testing.expectError(error.InvalidBaseUrl, validate(bad_url));

    var bad_model = good;
    bad_model.model = "  ";
    try std.testing.expectError(error.InvalidModel, validate(bad_model));

    var bad_role = good;
    bad_role.capabilities.instruction_role = "assistant";
    try std.testing.expectError(error.InvalidCapabilities, validate(bad_role));

    var custom = good;
    custom.adapter = "custom";
    custom.capabilities = .{ .instruction_role = "developer", .streaming = false, .structured_output = true };
    try validate(custom);
}

test "provider store round trip: set, get, replace, no secrets, quarantine" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [160]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-ai-itest-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var path_buf: [200]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/ai.json", .{dir});
    var store = ProviderStore{ .allocator = allocator, .path = path };

    try std.testing.expect((try store.get(io)) == null); // absent config

    var saved = try store.set(io, .{
        .adapter = "openai_compatible",
        .base_url = "https://api.openai.com/v1",
        .model = "gpt-4o-mini",
    }, 1000);
    defer saved.deinit(allocator);
    try std.testing.expectEqualStrings("openai_compatible", saved.adapter.jsonName());
    try std.testing.expectEqualStrings("gpt-4o-mini", saved.model);
    try std.testing.expectEqual(@as(i64, 1000), saved.updated_at_ns);

    var got = (try store.get(io)).?;
    defer got.deinit(allocator);
    try std.testing.expectEqualStrings("https://api.openai.com/v1", got.base_url);
    try std.testing.expectEqualStrings("system", got.capabilities.instruction_role);

    // Replace preserves nothing stale and moves updated_at forward.
    var replaced = try store.set(io, .{
        .adapter = "custom",
        .base_url = "http://localhost:11434/v1",
        .model = "llama3",
        .capabilities = .{ .instruction_role = "developer", .streaming = false, .structured_output = true },
    }, 2000);
    defer replaced.deinit(allocator);
    var got2 = (try store.get(io)).?;
    defer got2.deinit(allocator);
    try std.testing.expectEqualStrings("http://localhost:11434/v1", got2.base_url);
    try std.testing.expectEqual(.custom, got2.adapter);
    try std.testing.expect(!got2.capabilities.streaming);
    try std.testing.expectEqual(@as(i64, 2000), got2.updated_at_ns);

    // The persisted file is config only — key material never appears.
    const content = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024));
    defer allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "sk-") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"adapter\"") != null);

    // A corrupt file is quarantined (renamed away) and reads back as absent.
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "{corrupt" });
    try std.testing.expect((try store.get(io)) == null);
    const gone = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024)) catch |err| err;
    try std.testing.expect(gone == error.FileNotFound);
}

test "probe command quotes log paths and is busybox-shaped" {
    const allocator = std.testing.allocator;
    const paths = [_][]const u8{ "/var/log/nginx/access.log", "/var/log/my app.log" };
    const cmd = try buildProbeCommand(allocator, &paths);
    defer allocator.free(cmd);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "%BEGIN_OS%") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "%BEGIN_HOSTNAME%") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "%BEGIN_LOGS%") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "'/var/log/nginx/access.log'") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "'/var/log/my app.log'") != null);
    try std.testing.expect(std.mem.endsWith(u8, cmd, "done; true"));
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

test "context cache: fresh hit, ttl expiry, replacement, eviction" {
    const allocator = std.testing.allocator;
    var cache = ContextCache{ .allocator = allocator };
    defer cache.deinit();

    try std.testing.expect(cache.fresh("s1", 1000) == null);

    const e1 = ContextCache.CacheEntry{
        .server_id = try allocator.dupe(u8, "s1"),
        .os = try allocator.dupe(u8, "Alpine"),
        .hostname = try allocator.dupe(u8, "box"),
        .active_logs = &.{},
        .ts_ns = 1000,
    };
    try cache.put(e1);
    try std.testing.expect(cache.fresh("s1", 1001) != null);
    try std.testing.expectEqualStrings("Alpine", cache.fresh("s1", 1001).?.os);
    try std.testing.expect(cache.fresh("s1", 1000 + 5 * std.time.ns_per_s + 1) == null); // expired

    // Replacement frees the old entry (leak-checked by the allocator).
    const e2 = ContextCache.CacheEntry{
        .server_id = try allocator.dupe(u8, "s1"),
        .os = try allocator.dupe(u8, "Debian"),
        .hostname = "",
        .active_logs = &.{},
        .ts_ns = 10_000,
    };
    try cache.put(e2);
    try std.testing.expectEqualStrings("Debian", cache.fresh("s1", 10_001).?.os);

    // Eviction: fill past capacity, oldest goes.
    var i: usize = 0;
    while (i < max_cached_servers + 2) : (i += 1) {
        var id_buf: [16]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "s{d}", .{i + 10});
        try cache.put(.{
            .server_id = try allocator.dupe(u8, id),
            .os = "",
            .hostname = "",
            .active_logs = &.{},
            .ts_ns = 20_000 + @as(i128, @intCast(i)),
        });
    }
    try std.testing.expectEqual(@as(usize, max_cached_servers), cache.entries.items.len);
}
