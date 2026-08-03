//! Log management (spec 04): scan parsing, grouping, the per-server source
//! store (`logs.json`), and the per-session scan cache.
//!
//! The scan is ONE exec, marker-delimited like the monitor probe:
//! `%BEGIN_DATE%` carries the remote clock, `%BEGIN_SCAN%` carries NUL-
//! delimited records (`path\0size\0mtime\0mode\0`) from GNU `find -printf`
//! or the busybox `-print0` + `stat` fallback (both verified live). The
//! parser never positions-guesses; malformed records degrade to
//! `partial:true` with a reason instead of fabricated data.

const std = @import("std");

/// Scan bounds (spec 04 §5): discovery is capped by entry count and output
/// bytes; anything beyond reports `partial` with a reason.
pub const max_entries: usize = 500;
pub const max_scan_bytes: usize = 1024 * 1024;
pub const max_probe_paths: usize = 100;

pub const ScanEntry = struct {
    path: []const u8,
    /// Static group label: web | runtime | system | custom.
    group: []const u8,
    name: []const u8,
    size: u64 = 0,
    mtime_epoch: u64 = 0,
    age_sec: u64 = 0,
    /// Permission bits (0o644 etc.), for the clear identity check.
    mode: u32 = 0,
    readable: bool = false,
};

pub const ScanResult = struct {
    entries: []ScanEntry = &.{},
    partial: bool = false,
    /// Static reason strings only.
    reason: []const u8 = "",

    pub fn deinit(self: *ScanResult, allocator: std.mem.Allocator) void {
        for (self.entries) |e| {
            allocator.free(e.path);
            allocator.free(e.name);
        }
        allocator.free(self.entries);
    }
};

const ParseError = error{ Invalid, OutOfMemory };

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    outer: for (0..haystack.len - needle.len + 1) |i| {
        for (needle, 0..) |nc, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(nc)) continue :outer;
        }
        return true;
    }
    return false;
}

fn endsWithIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    const tail = haystack[haystack.len - needle.len ..];
    for (needle, 0..) |nc, i| {
        if (std.ascii.toLower(tail[i]) != std.ascii.toLower(nc)) return false;
    }
    return true;
}

/// Grouping rules (spec 04 §5): `nginx|apache` → web; `pm2` or
/// `-out.log`/`-err.log` (the pm2 naming convention) → runtime;
/// syslog/auth/kern → system; everything else → custom.
pub fn groupFor(path: []const u8) []const u8 {
    if (containsIgnoreCase(path, "nginx") or containsIgnoreCase(path, "apache")) return "web";
    if (containsIgnoreCase(path, "pm2")) return "runtime";
    if (endsWithIgnoreCase(path, "-out.log") or endsWithIgnoreCase(path, "-err.log")) return "runtime";
    if (containsIgnoreCase(path, "syslog") or
        containsIgnoreCase(path, "auth") or
        containsIgnoreCase(path, "kern")) return "system";
    return "custom";
}

/// Display name: web-grouped logs get "Nginx · access" style labels (parent
/// dir title + basename without .log); everything else shows the basename.
pub fn displayName(allocator: std.mem.Allocator, path: []const u8, group: []const u8) ![]const u8 {
    const base = std.fs.path.basename(path);
    if (!std.mem.eql(u8, group, "web")) return allocator.dupe(u8, base);
    const dir = std.fs.path.dirname(path) orelse return allocator.dupe(u8, base);
    const parent = std.fs.path.basename(dir);
    const stripped = if (std.mem.endsWith(u8, base, ".log")) base[0 .. base.len - 4] else base;
    var title: [64]u8 = undefined;
    if (parent.len > title.len) return allocator.dupe(u8, base);
    for (parent, 0..) |ch, i| {
        title[i] = if (i == 0) std.ascii.toUpper(ch) else ch;
    }
    return std.fmt.allocPrint(allocator, "{s} · {s}", .{ title[0..parent.len], stripped });
}

/// Validates a user-supplied log path: absolute, no control characters,
/// no trailing slash (a directory is not a log source).
pub fn validatePath(path: []const u8) error{ RelativePath, InvalidChar, TrailingSlash }!void {
    if (path.len == 0 or path[0] != '/') return error.RelativePath;
    if (path[path.len - 1] == '/') return error.TrailingSlash;
    for (path) |ch| {
        if (ch < 0x20 or ch == 0x7f) return error.InvalidChar;
    }
}

/// Parses the marker-delimited scan output. `remote_now` is the remote
/// clock (from `%BEGIN_DATE%`); ages are clamped so future mtimes read 0
/// rather than mixing local and remote clocks.
pub fn parseScanOutput(allocator: std.mem.Allocator, text: []const u8) ParseError!ScanResult {
    var result = ScanResult{};
    errdefer result.deinit(allocator);

    var section: []const u8 = "";
    var date_text: []const u8 = "";
    // The scan section is reconstructed byte-exactly (lines re-joined with
    // '\n'): NUL-delimited records are one line, but records for paths
    // containing newlines span several — splitting loses nothing.
    var scan_buf: std.ArrayList(u8) = .empty;
    defer scan_buf.deinit(allocator);
    var scan_seen = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len > 0 and line[0] == '%' and std.mem.endsWith(u8, line, "%")) {
            section = line;
            continue;
        }
        if (std.mem.eql(u8, section, "%BEGIN_DATE%")) {
            if (date_text.len == 0) date_text = std.mem.trim(u8, line, " \t\r");
        } else if (std.mem.eql(u8, section, "%BEGIN_SCAN%")) {
            if (scan_seen) {
                scan_buf.append(allocator, '\n') catch return error.OutOfMemory;
            } else {
                scan_seen = true;
            }
            scan_buf.appendSlice(allocator, line) catch return error.OutOfMemory;
        }
    }
    const scan_text = scan_buf.items;

    const remote_now: i64 = std.fmt.parseInt(i64, date_text, 10) catch return error.Invalid;

    if (std.mem.indexOfScalar(u8, scan_text, 0) != null) {
        try parseNulRecords(allocator, scan_text, remote_now, &result);
    } else {
        // Degraded fallback: bare newline-delimited paths only (no stat
        // support). Sizes are unknown, so partial is honest.
        try parseBarePaths(allocator, scan_text, &result);
        result.partial = true;
        result.reason = "size and timestamps unavailable (no stat support)";
    }
    if (result.entries.len > max_entries) {
        for (result.entries[max_entries..]) |e| {
            allocator.free(e.path);
            allocator.free(e.name);
        }
        result.entries = result.entries[0..max_entries];
        result.partial = true;
        result.reason = "scan exceeded the entry cap";
    }
    return result;
}

fn parseNulRecords(allocator: std.mem.Allocator, text: []const u8, remote_now: i64, result: *ScanResult) ParseError!void {
    var out: std.ArrayList(ScanEntry) = .empty;
    errdefer {
        for (out.items) |e| {
            allocator.free(e.path);
            allocator.free(e.name);
        }
        out.deinit(allocator);
    }
    var fields = std.mem.splitScalar(u8, text, 0);
    var field: [4][]const u8 = undefined;
    var n: usize = 0;
    while (fields.next()) |f| {
        if (n == 4) {
            out.append(allocator, try makeEntry(allocator, field[0], field[1], field[2], field[3], remote_now)) catch return error.Invalid;
            n = 0;
        }
        if (f.len == 0) {
            if (n == 0) continue; // trailing NUL after a complete record
            return error.Invalid; // empty field mid-record
        }
        field[n] = f;
        n += 1;
    }
    if (n != 0) return error.Invalid; // truncated record: the scan is suspect
    result.entries = out.toOwnedSlice(allocator) catch return error.Invalid;
}

fn makeEntry(
    allocator: std.mem.Allocator,
    path: []const u8,
    size_text: []const u8,
    mtime_text: []const u8,
    mode_text: []const u8,
    remote_now: i64,
) !ScanEntry {
    const mtime_f = std.fmt.parseFloat(f64, mtime_text) catch return error.Invalid;
    const mtime: u64 = @intFromFloat(mtime_f);
    const mtime_i: i64 = @intCast(mtime);
    const age: i64 = if (mtime_i > remote_now) 0 else remote_now - mtime_i;
    return .{
        .path = try allocator.dupe(u8, path),
        .group = groupFor(path),
        .name = try displayName(allocator, path, groupFor(path)),
        .size = std.fmt.parseInt(u64, size_text, 10) catch return error.Invalid,
        .mtime_epoch = mtime,
        .age_sec = @intCast(age),
        .mode = std.fmt.parseInt(u32, mode_text, 8) catch return error.Invalid,
    };
}

fn parseBarePaths(allocator: std.mem.Allocator, text: []const u8, result: *ScanResult) ParseError!void {
    var out: std.ArrayList(ScanEntry) = .empty;
    errdefer {
        for (out.items) |e| {
            allocator.free(e.path);
            allocator.free(e.name);
        }
        out.deinit(allocator);
    }
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const path = std.mem.trim(u8, line, " \t\r");
        if (path.len == 0) continue;
        if (out.items.len == max_entries) break;
        const entry = ScanEntry{
            .path = allocator.dupe(u8, path) catch return error.Invalid,
            .group = groupFor(path),
            .name = displayName(allocator, path, groupFor(path)) catch return error.Invalid,
        };
        out.append(allocator, entry) catch return error.Invalid;
    }
    result.entries = out.toOwnedSlice(allocator) catch return error.Invalid;
}

/// Parses the batched readability probe output: one `0`/`1` line per path,
/// in probe order (spec 04 §5: `test -r` per source).
pub fn applyReadability(entries: []ScanEntry, probe_output: []const u8) void {
    var lines = std.mem.splitScalar(u8, probe_output, '\n');
    var i: usize = 0;
    while (lines.next()) |line| {
        if (i >= entries.len) break;
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (std.mem.eql(u8, trimmed, "1")) entries[i].readable = true;
        i += 1;
    }
}

/// Per-server source store: `<data>/logs.json` —
/// `[{"server_id":"s1","paths":["/var/log/custom.log"]}]` (array of objects:
/// std.json static parsing does not support StringHashMap fields).
pub const SourceStore = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    mutex: std.atomic.Mutex = .unlocked,

    pub const ServerSources = struct {
        server_id: []const u8,
        paths: [][]const u8,
    };

    pub const Loaded = struct {
        parsed: std.json.Parsed([]ServerSources),
        content: ?[]u8,

        pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
            self.parsed.deinit();
            if (self.content) |c| allocator.free(c);
        }
    };

    /// The persisted path list for a server (owned; caller frees the slice
    /// and each string).
    pub fn pathsFor(self: *SourceStore, io: std.Io, server_id: []const u8) ![][]const u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = try self.loadLocked(io);
        defer loaded.deinit(self.allocator);
        for (loaded.parsed.value) |s| {
            if (std.mem.eql(u8, s.server_id, server_id)) {
                const out = try self.allocator.alloc([]const u8, s.paths.len);
                for (s.paths, 0..) |p, i| out[i] = try self.allocator.dupe(u8, p);
                return out;
            }
        }
        return self.allocator.alloc([]const u8, 0);
    }

    /// Appends a validated path for a server (deduplicated).
    pub fn addSource(self: *SourceStore, io: std.Io, server_id: []const u8, path: []const u8) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = try self.loadLocked(io);
        defer loaded.deinit(self.allocator);
        for (loaded.parsed.value) |*s| {
            if (std.mem.eql(u8, s.server_id, server_id)) {
                for (s.paths) |p| {
                    if (std.mem.eql(u8, p, path)) return; // already added
                }
                const list = try self.allocator.alloc([]const u8, s.paths.len + 1);
                defer self.allocator.free(list);
                for (s.paths, 0..) |p, i| list[i] = p;
                list[s.paths.len] = path;
                s.paths = list;
                return self.saveLocked(io, loaded.parsed.value);
            }
        }
        const list = try self.allocator.alloc([]const u8, 1);
        defer self.allocator.free(list);
        list[0] = path;
        const entry = ServerSources{ .server_id = server_id, .paths = list };
        const all = try self.allocator.alloc(ServerSources, loaded.parsed.value.len + 1);
        defer self.allocator.free(all);
        @memcpy(all[0..loaded.parsed.value.len], loaded.parsed.value);
        all[loaded.parsed.value.len] = entry;
        try self.saveLocked(io, all);
    }

    fn loadLocked(self: *SourceStore, io: std.Io) !Loaded {
        const cwd = std.Io.Dir.cwd();
        const content = cwd.readFileAlloc(io, self.path, self.allocator, .limited(1024 * 1024)) catch {
            // No store yet: an empty load (its parse arena is released by
            // the caller's deinit).
            return .{
                .parsed = try std.json.parseFromSlice([]ServerSources, self.allocator, "[]", .{}),
                .content = null,
            };
        };
        const parsed = std.json.parseFromSlice([]ServerSources, self.allocator, content, .{}) catch {
            self.allocator.free(content);
            return .{
                .parsed = try std.json.parseFromSlice([]ServerSources, self.allocator, "[]", .{}),
                .content = null,
            };
        };
        return .{ .parsed = parsed, .content = content };
    }

    fn saveLocked(self: *SourceStore, io: std.Io, sources: []const ServerSources) !void {
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(self.path)) |dir| try cwd.createDirPath(io, dir);
        var buf: [256 * 1024]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buf);
        std.json.Stringify.value(sources, .{ .whitespace = .indent_2 }, &writer) catch return error.SerializeFailed;
        var file = try cwd.createFile(io, self.path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, writer.buffered());
        try file.sync(io);
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

/// Per-session scan cache (spec 04 §4: cached 60 s; auto-rescan on open).
pub const ScanCache = struct {
    mutex: std.atomic.Mutex = .unlocked,
    result: ?ScanResult = null,
    ts_ns: i128 = 0,

    pub fn lock(self: *ScanCache) void {
        lockSpin(&self.mutex);
    }

    pub fn unlock(self: *ScanCache) void {
        self.mutex.unlock();
    }

    pub fn get(self: *ScanCache) ?*const ScanResult {
        return if (self.result) |*r| r else null;
    }

    pub fn fresh(self: *ScanCache, now_ns: i128) bool {
        return self.ts_ns != 0 and now_ns - self.ts_ns < 60 * std.time.ns_per_s;
    }

    /// Drops the cached result (spec 04: adding a source must make the
    /// next scan pick it up; the 60 s freshness window is skipped).
    pub fn invalidate(self: *ScanCache, allocator: std.mem.Allocator) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.result) |*old| old.deinit(allocator);
        self.result = null;
        self.ts_ns = 0;
    }

    pub fn store(self: *ScanCache, allocator: std.mem.Allocator, result: ScanResult, now_ns: i128) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.result) |*old| old.deinit(allocator);
        self.result = result;
        self.ts_ns = now_ns;
    }

    pub fn deinit(self: *ScanCache, allocator: std.mem.Allocator) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.result) |*r| r.deinit(allocator);
        self.result = null;
    }
};

// --- tests ---------------------------------------------------------------

const fixtures = struct {
    const nul_records =
        "/var/log/nginx/access.log\x00" ++
        "472000\x00" ++
        "1754000000.123456\x00" ++
        "644\x00" ++
        "/var/log/auth.log\x00" ++
        "1200000\x00" ++
        "1754000034\x00" ++
        "640\x00";
};

test "grouping rules are stable" {
    try std.testing.expectEqualStrings("web", groupFor("/var/log/nginx/access.log"));
    try std.testing.expectEqualStrings("web", groupFor("/var/log/apache2/error.log"));
    try std.testing.expectEqualStrings("runtime", groupFor("/home/app/.pm2/logs/api-out.log"));
    try std.testing.expectEqualStrings("runtime", groupFor("/var/log/api-err.log"));
    try std.testing.expectEqualStrings("system", groupFor("/var/log/syslog"));
    try std.testing.expectEqualStrings("system", groupFor("/var/log/auth.log"));
    try std.testing.expectEqualStrings("system", groupFor("/var/log/kern.log"));
    try std.testing.expectEqualStrings("custom", groupFor("/var/log/whatever.log"));
}

test "display names follow the web convention" {
    const allocator = std.testing.allocator;
    const nginx = try displayName(allocator, "/var/log/nginx/access.log", "web");
    defer allocator.free(nginx);
    try std.testing.expectEqualStrings("Nginx · access", nginx);
    const plain = try displayName(allocator, "/var/log/auth.log", "system");
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("auth.log", plain);
}

test "path validation rejects relative, control, and directory paths" {
    try validatePath("/var/log/app.log");
    try std.testing.expectError(error.RelativePath, validatePath("var/log/app.log"));
    try std.testing.expectError(error.RelativePath, validatePath(""));
    try std.testing.expectError(error.TrailingSlash, validatePath("/var/log/"));
    try std.testing.expectError(error.InvalidChar, validatePath("/var/log/a\nb.log"));
    try std.testing.expectError(error.InvalidChar, validatePath("/var/log/\x00"));
}

test "nul-delimited scan records parse with grouping, age, and mode" {
    const allocator = std.testing.allocator;
    const text = "%BEGIN_DATE%\n1754000100\n%BEGIN_SCAN%\n" ++ fixtures.nul_records;
    var result = try parseScanOutput(allocator, text);
    defer result.deinit(allocator);

    try std.testing.expect(!result.partial);
    try std.testing.expectEqual(@as(usize, 2), result.entries.len);

    const nginx = result.entries[0];
    try std.testing.expectEqualStrings("/var/log/nginx/access.log", nginx.path);
    try std.testing.expectEqualStrings("web", nginx.group);
    try std.testing.expectEqualStrings("Nginx · access", nginx.name);
    try std.testing.expectEqual(@as(u64, 472000), nginx.size);
    try std.testing.expectEqual(@as(u64, 1754000000), nginx.mtime_epoch);
    try std.testing.expectEqual(@as(u64, 100), nginx.age_sec);
    try std.testing.expectEqual(@as(u32, 0o644), nginx.mode);

    const auth = result.entries[1];
    try std.testing.expectEqualStrings("system", auth.group);
    try std.testing.expectEqual(@as(u64, 66), auth.age_sec);
}

test "future mtimes clamp to zero age" {
    const allocator = std.testing.allocator;
    // mtime 10 s in the future: age must clamp to 0, never go negative.
    const text = "%BEGIN_DATE%\n1754000100\n%BEGIN_SCAN%\n" ++
        "/var/log/future.log\x00" ++ "10\x00" ++ "1754000110\x00" ++ "644\x00";
    var result = try parseScanOutput(allocator, text);
    defer result.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), result.entries[0].age_sec);
}

test "truncated nul records fail the scan rather than guess" {
    const allocator = std.testing.allocator;
    const text = "%BEGIN_DATE%\n1754000100\n%BEGIN_SCAN%\n" ++
        "/var/log/partial.log\x00" ++ "10\x00" ++ "1754000110\x00"; // no mode
    try std.testing.expectError(error.Invalid, parseScanOutput(allocator, text));
}

test "bare newline paths degrade to partial with a reason" {
    const allocator = std.testing.allocator;
    const text = "%BEGIN_DATE%\n1754000100\n%BEGIN_SCAN%\n/var/log/a.log\n/var/log/b.log\n";
    var result = try parseScanOutput(allocator, text);
    defer result.deinit(allocator);
    try std.testing.expect(result.partial);
    try std.testing.expect(result.reason.len > 0);
    try std.testing.expectEqual(@as(usize, 2), result.entries.len);
    try std.testing.expectEqual(@as(u64, 0), result.entries[0].size);
}

test "readability probe output maps to entries in order" {
    var entries = [_]ScanEntry{
        .{ .path = "a", .group = "custom", .name = "a" },
        .{ .path = "b", .group = "custom", .name = "b" },
        .{ .path = "c", .group = "custom", .name = "c" },
    };
    applyReadability(&entries, "1\n0\n1\n");
    try std.testing.expect(entries[0].readable);
    try std.testing.expect(!entries[1].readable);
    try std.testing.expect(entries[2].readable);
}

test "source store persists added paths per server" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [128]u8 = undefined;
    const dir_name = try std.fmt.bufPrint(&dir_buf, "oars-logs-test-{d}", .{now});
    var path_buf: [512]u8 = undefined;
    const store_path = try std.fmt.bufPrint(&path_buf, "/tmp/{s}/logs.json", .{dir_name});
    defer std.Io.Dir.cwd().deleteTree(io, dir_name) catch {};

    var store = SourceStore{ .allocator = allocator, .path = store_path };
    try store.addSource(io, "s1", "/var/log/custom.log");
    try store.addSource(io, "s1", "/var/log/other.log");
    try store.addSource(io, "s1", "/var/log/custom.log"); // dedupe
    try store.addSource(io, "s2", "/var/log/s2.log");

    const s1 = try store.pathsFor(io, "s1");
    defer {
        for (s1) |p| allocator.free(p);
        allocator.free(s1);
    }
    try std.testing.expectEqual(@as(usize, 2), s1.len);
    try std.testing.expectEqualStrings("/var/log/custom.log", s1[0]);

    const s2 = try store.pathsFor(io, "s2");
    defer {
        for (s2) |p| allocator.free(p);
        allocator.free(s2);
    }
    try std.testing.expectEqual(@as(usize, 1), s2.len);
}

test "scan cache stores once, serves fresh, expires, and invalidates" {
    const allocator = std.testing.allocator;
    var cache: ScanCache = .{};
    defer cache.deinit(allocator);

    const now: i128 = 1_000_000_000_000;
    try std.testing.expect(!cache.fresh(now));

    const text = "%BEGIN_DATE%\n1754000100\n%BEGIN_SCAN%\n" ++ fixtures.nul_records;
    const result = try parseScanOutput(allocator, text);
    cache.store(allocator, result, now); // the cache owns `result` from here

    try std.testing.expect(cache.fresh(now));
    try std.testing.expect(cache.fresh(now + 59 * std.time.ns_per_s));
    try std.testing.expect(!cache.fresh(now + 61 * std.time.ns_per_s));

    cache.lock();
    const cached = cache.get().?;
    try std.testing.expectEqual(@as(usize, 2), cached.entries.len);
    cache.unlock();

    cache.invalidate(allocator);
    try std.testing.expect(!cache.fresh(now));
    cache.lock();
    try std.testing.expect(cache.get() == null);
    cache.unlock();
}
