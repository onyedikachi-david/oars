//! Minimal append-only audit log for mutating product actions (spec 03:
//! clean-disk plans, drop-caches). Spec 15 owns the full history/audit
//! machinery; this matches its `audit.jsonl` shape — one JSON object per
//! line, fsync'd appends, so a recorded action survives a crash.

const std = @import("std");
const json = @import("json.zig");

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

pub const Entry = struct {
    ts: i64,
    action: []const u8,
    server_id: []const u8,
    detail: []const u8 = "",

    pub fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        if (self.action.len > 0) allocator.free(self.action);
        if (self.server_id.len > 0) allocator.free(self.server_id);
        if (self.detail.len > 0) allocator.free(self.detail);
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    /// Full path to audit.jsonl inside the app data directory.
    path: []const u8,
    /// Serializes appends: the bridge thread and session workers both write.
    mutex: std.atomic.Mutex = .unlocked,

    /// Appends one JSON line, creating the file (and its directory) on
    /// first use. O(1) positional append, then fsync.
    pub fn append(self: *Store, io: std.Io, entry: Entry) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(self.path)) |dir| try cwd.createDirPath(io, dir);
        var file = try cwd.createFile(io, self.path, .{ .truncate = false });
        defer file.close(io);
        const end = (try file.stat(io)).size;
        var buf: [2048]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try w.print("{{\"ts\":{d},\"action\":", .{entry.ts});
        try json.writeJsonString(&w, entry.action);
        try w.writeAll(",\"server_id\":");
        try json.writeJsonString(&w, entry.server_id);
        try w.writeAll(",\"detail\":");
        try json.writeJsonString(&w, entry.detail);
        try w.writeAll("}\n");
        try file.writePositionalAll(io, w.buffered(), end);
        try file.sync(io);
    }

    /// Owned entries for one server (optionally one action), newest
    /// first, capped at `limit`. Spec 15 owns the full history
    /// machinery; this is the minimal read the AI history needs.
    pub fn read(self: *Store, io: std.Io, server_id: []const u8, action: ?[]const u8, limit: usize) ![]Entry {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const content = std.Io.Dir.cwd().readFileAlloc(io, self.path, self.allocator, .limited(16 * 1024 * 1024)) catch return self.allocator.alloc(Entry, 0);
        defer self.allocator.free(content);
        var matches: std.ArrayList(Entry) = .empty;
        errdefer {
            for (matches.items) |*e| e.deinit(self.allocator);
            matches.deinit(self.allocator);
        }
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (line.len == 0 or line[0] != '{') continue;
            var parsed = std.json.parseFromSlice(Entry, self.allocator, line, .{ .allocate = .alloc_always }) catch continue;
            defer parsed.deinit();
            const e = parsed.value;
            if (!std.mem.eql(u8, e.server_id, server_id)) continue;
            if (action) |a| {
                if (!std.mem.eql(u8, e.action, a)) continue;
            }
            try matches.append(self.allocator, .{
                .ts = e.ts,
                .action = try self.allocator.dupe(u8, e.action),
                .server_id = try self.allocator.dupe(u8, e.server_id),
                .detail = try self.allocator.dupe(u8, e.detail),
            });
        }
        std.mem.reverse(Entry, matches.items); // append order → newest first
        if (matches.items.len > limit) {
            for (matches.items[limit..]) |*e| e.deinit(self.allocator);
            matches.items.len = limit;
        }
        return matches.toOwnedSlice(self.allocator);
    }
};

// --- tests ---------------------------------------------------------------

test "audit append creates the file, appends lines, and survives reopens" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [128]u8 = undefined;
    const dir_name = try std.fmt.bufPrint(&dir_buf, "oars-audit-test-{d}", .{now});
    var path_buf: [512]u8 = undefined;
    const audit_path = try std.fmt.bufPrint(&path_buf, "/tmp/{s}/audit.jsonl", .{dir_name});
    defer std.Io.Dir.cwd().deleteTree(io, dir_name) catch {};

    var store = Store{ .allocator = allocator, .path = audit_path };
    try store.append(io, .{ .ts = 1, .action = "monitor.clean_disk", .server_id = "s1", .detail = "plan=apt" });
    try store.append(io, .{ .ts = 2, .action = "monitor.drop_caches", .server_id = "s2", .detail = "level=3 before=123" });

    const content = try std.Io.Dir.cwd().readFileAlloc(io, audit_path, allocator, .limited(64 * 1024));
    defer allocator.free(content);
    try std.testing.expectEqualStrings(
        "{\"ts\":1,\"action\":\"monitor.clean_disk\",\"server_id\":\"s1\",\"detail\":\"plan=apt\"}\n" ++
            "{\"ts\":2,\"action\":\"monitor.drop_caches\",\"server_id\":\"s2\",\"detail\":\"level=3 before=123\"}\n",
        content,
    );

    // Each line parses back as a JSON object.
    var lines = std.mem.splitScalar(u8, content, '\n');
    const first = lines.next().?;
    const parsed = try std.json.parseFromSlice(Entry, allocator, first, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    try std.testing.expectEqualStrings("monitor.clean_disk", parsed.value.action);
    try std.testing.expectEqualStrings("s1", parsed.value.server_id);
}

test "audit read filters by server and action, newest first, capped" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [128]u8 = undefined;
    const dir_name = try std.fmt.bufPrint(&dir_buf, "oars-audit-read-test-{d}", .{now});
    var path_buf: [512]u8 = undefined;
    const audit_path = try std.fmt.bufPrint(&path_buf, "/tmp/{s}/audit.jsonl", .{dir_name});
    defer std.Io.Dir.cwd().deleteTree(io, dir_name) catch {};

    var store = Store{ .allocator = allocator, .path = audit_path };
    try store.append(io, .{ .ts = 1, .action = "ssh.exec", .server_id = "s1", .detail = "cmd=du" });
    try store.append(io, .{ .ts = 2, .action = "ssh.exec", .server_id = "s2", .detail = "cmd=whoami" });
    try store.append(io, .{ .ts = 3, .action = "ssh.exec", .server_id = "s1", .detail = "cmd=ls -la" });
    try store.append(io, .{ .ts = 4, .action = "ai.provider.set", .server_id = "s1", .detail = "adapter=openai_compatible" });

    // Filtered to one server's ssh.exec runs, newest first.
    const runs = try store.read(io, "s1", "ssh.exec", 10);
    defer {
        for (runs) |*e| e.deinit(allocator);
        allocator.free(runs);
    }
    try std.testing.expectEqual(@as(usize, 2), runs.len);
    try std.testing.expectEqual(@as(i64, 3), runs[0].ts);
    try std.testing.expectEqualStrings("cmd=ls -la", runs[0].detail);
    try std.testing.expectEqual(@as(i64, 1), runs[1].ts);

    // Other servers' entries are untouched by the filter; limit caps.
    const capped = try store.read(io, "s1", null, 1);
    defer {
        for (capped) |*e| e.deinit(allocator);
        allocator.free(capped);
    }
    try std.testing.expectEqual(@as(usize, 1), capped.len);
    try std.testing.expectEqual(@as(i64, 4), capped[0].ts); // ai.provider.set is newest

    // An empty store reads as an empty list.
    const none = try store.read(io, "nope", null, 10);
    defer allocator.free(none);
    try std.testing.expectEqual(@as(usize, 0), none.len);
}
