//! Server configuration model and JSON persistence.
//!
//! Configs live in the app data directory (`servers.json`). Secrets
//! (passwords, key passphrases) never live here — the frontend stores
//! them through the Keychain-backed credentials bridge.

const std = @import("std");
const builtin = @import("builtin");

pub const AuthMethod = enum {
    password,
    key,

    pub fn jsonName(self: AuthMethod) []const u8 {
        return switch (self) {
            .password => "password",
            .key => "key",
        };
    }

    pub fn fromJsonName(name: []const u8) ?AuthMethod {
        if (std.mem.eql(u8, name, "password")) return .password;
        if (std.mem.eql(u8, name, "key")) return .key;
        return null;
    }
};

pub const Server = struct {
    id: []const u8,
    name: []const u8,
    host: []const u8,
    port: u16 = 22,
    user: []const u8,
    auth_method: AuthMethod = .password,
    /// Path to the private key file when auth_method == .key. The public
    /// key is derived as `<path>.pub` by convention.
    key_path: []const u8 = "",
    /// True when the private key is passphrase-protected (the passphrase
    /// itself lives in the Keychain, keyed by server id).
    key_has_passphrase: bool = false,
    /// OpenSSH-style host key fingerprint (`SHA256:<base64-without-padding>`)
    /// once the user has trusted the server on first connect. Legacy
    /// 64-hex records are accepted on compare and migrated on verify.
    host_fingerprint: ?[]const u8 = null,
    group: []const u8 = "",
    /// Free-form labels, trimmed and deduplicated at save time.
    tags: [][]const u8 = &.{},
    /// Jump host (spec 18): connect via this server's session first.
    /// Chains are validated at save time (depth <= 3, acyclic, existing).
    via_server_id: ?[]const u8 = null,
    created_at: i64 = 0,
    updated_at: i64 = 0,

    pub fn copy(self: *const Server, allocator: std.mem.Allocator) !Server {
        var tags: [][]const u8 = &.{};
        errdefer {
            for (tags) |t| allocator.free(t);
            allocator.free(tags);
        }
        tags = try allocator.alloc([]const u8, self.tags.len);
        for (self.tags, 0..) |t, i| tags[i] = try allocator.dupe(u8, t);
        return .{
            .id = try allocator.dupe(u8, self.id),
            .name = try allocator.dupe(u8, self.name),
            .host = try allocator.dupe(u8, self.host),
            .port = self.port,
            .user = try allocator.dupe(u8, self.user),
            .auth_method = self.auth_method,
            .key_path = try allocator.dupe(u8, self.key_path),
            .key_has_passphrase = self.key_has_passphrase,
            .host_fingerprint = if (self.host_fingerprint) |fp| try allocator.dupe(u8, fp) else null,
            .group = try allocator.dupe(u8, self.group),
            .tags = tags,
            .via_server_id = if (self.via_server_id) |via| try allocator.dupe(u8, via) else null,
            .created_at = self.created_at,
            .updated_at = self.updated_at,
        };
    }

    pub fn deinit(self: *Server, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        allocator.free(self.host);
        allocator.free(self.user);
        allocator.free(self.key_path);
        if (self.host_fingerprint) |fp| allocator.free(fp);
        allocator.free(self.group);
        for (self.tags) |t| allocator.free(t);
        allocator.free(self.tags);
        if (self.via_server_id) |via| allocator.free(via);
    }
};

/// Validates a server's jump-host chain (spec 18) against the saved set:
/// no self-links, every referenced server must exist, chains are a DAG with
/// at most 3 hops, and cycles are rejected at save time.
pub fn validateViaChain(server: Server, all: []const Server) !void {
    const via = server.via_server_id orelse return;
    if (std.mem.eql(u8, via, server.id)) return error.SelfLink;

    var visited: [5][]const u8 = undefined;
    var visited_len: usize = 1;
    visited[0] = server.id;
    var current: []const u8 = via;
    // The edge server -> via is already one hop of the chain.
    var hops: usize = 1;

    while (true) {
        if (hops > 3) return error.ChainTooDeep;
        for (visited[0..visited_len]) |v| {
            if (std.mem.eql(u8, v, current)) return error.Cycle;
        }
        visited[visited_len] = current;
        visited_len += 1;

        const found = for (all) |s| {
            if (std.mem.eql(u8, s.id, current)) break s;
        } else return error.MissingVia;

        const next_via = found.via_server_id orelse return;
        if (next_via.len == 0) return;
        hops += 1;
        current = next_via;
    }
}

pub const Store = struct {
    allocator: std.mem.Allocator,
    /// Full path to servers.json inside the app data directory.
    path: []const u8,

    /// A parsed server list plus the file content it references.
    /// std.json parses strings with `.alloc_if_needed`, so string fields
    /// may point into the file buffer — it must outlive the Parsed value.
    pub const Loaded = struct {
        parsed: std.json.Parsed([]Server),
        content: ?[]u8,
        /// Path the corrupt file was moved to (allocated), when the file
        /// failed to parse and was quarantined instead of replaced.
        quarantined: ?[]const u8 = null,

        pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
            self.parsed.deinit();
            if (self.content) |c| allocator.free(c);
            if (self.quarantined) |q| allocator.free(q);
        }
    };

    /// Loads and parses all servers. Returns an empty list when the file
    /// does not exist or is malformed. A malformed file is never replaced
    /// in place: it is moved to `servers.json.corrupt-<timestamp>` so the
    /// damage is visible and recoverable, and the store continues with an
    /// empty list (spec 01 §10).
    pub fn loadParsed(self: *Store, io: std.Io) !Loaded {
        const cwd = std.Io.Dir.cwd();
        const content = cwd.readFileAlloc(io, self.path, self.allocator, .limited(4 * 1024 * 1024)) catch return emptyLoaded(self.allocator);
        const parsed = std.json.parseFromSlice([]Server, self.allocator, content, .{}) catch {
            self.allocator.free(content);
            var quarantined = try emptyLoaded(self.allocator);
            quarantined.quarantined = self.quarantine(io) catch null;
            return quarantined;
        };
        return .{ .parsed = parsed, .content = content };
    }

    /// An empty store view. Built lazily: constructing it eagerly in
    /// loadParsed would leak its parse arena on every successful load.
    fn emptyLoaded(allocator: std.mem.Allocator) !Loaded {
        return .{
            .parsed = try std.json.parseFromSlice([]Server, allocator, "[]", .{}),
            .content = null,
        };
    }

    /// Moves the corrupt store file aside under a timestamped name so a
    /// later save never overwrites the only copy of a damaged file.
    /// Returns the new path (allocated), or null when the file could not
    /// be moved (in which case the store still continues empty).
    fn quarantine(self: *Store, io: std.Io) !?[]const u8 {
        const now = std.Io.Timestamp.now(io, .real).nanoseconds;
        var buf: [512]u8 = undefined;
        const dir = std.fs.path.dirname(self.path) orelse return null;
        const base = std.fs.path.basename(self.path);
        const new_path = try std.fmt.bufPrint(&buf, "{s}/{s}.corrupt-{d}", .{ dir, base, now });
        std.Io.Dir.renameAbsolute(self.path, new_path, io) catch return null;
        return try self.allocator.dupe(u8, new_path);
    }

    /// Persists the whole list. Creates the data directory on demand, and
    /// writes with owner-only permissions (0600 on POSIX). An existing
    /// permissive file is tightened before the write (spec 01 §8).
    pub fn save(self: *Store, io: std.Io, servers: []const Server) !void {
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(self.path)) |dir| try cwd.createDirPath(io, dir);
        self.tightenPermissions(io);
        var buf: [512 * 1024]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buf);
        std.json.Stringify.value(servers, .{ .whitespace = .indent_2 }, &writer) catch return error.SerializeFailed;
        var file = try cwd.createFile(io, self.path, .{});
        defer file.close(io);
        if (file.stat(io)) |stat| {
            if (stat.permissions.toMode() & 0o077 != 0) file.setPermissions(io, .fromMode(0o600)) catch {};
        } else |_| {}
        try file.writeStreamingAll(io, writer.buffered());
        try file.sync(io);
    }

    /// Tightens a permissive existing store file to owner-only before the
    /// next write. The explicit warning is the frontend's job; the backend
    /// never leaves the file group/other-accessible after a mutation.
    fn tightenPermissions(self: *Store, io: std.Io) void {
        const cwd = std.Io.Dir.cwd();
        var file = cwd.openFile(io, self.path, .{ .mode = .read_write }) catch return;
        defer file.close(io);
        const stat = file.stat(io) catch return;
        if (stat.permissions.toMode() & 0o077 != 0) file.setPermissions(io, .fromMode(0o600)) catch {};
    }

    /// Convenience: returns a deep copy of the server with `id`, or null.
    pub fn find(self: *Store, io: std.Io, id: []const u8) !?Server {
        var loaded = try self.loadParsed(io);
        defer loaded.deinit(self.allocator);
        for (loaded.parsed.value) |s| {
            if (std.mem.eql(u8, s.id, id)) return try s.copy(self.allocator);
        }
        return null;
    }

    /// Inserts or replaces `server`, taking a deep copy of it. The
    /// caller keeps ownership of the argument. The copy is serialized and
    /// then released: the saved list only owns what the file buffer owns.
    pub fn upsert(self: *Store, io: std.Io, server: Server) !void {
        var loaded = try self.loadParsed(io);
        defer loaded.deinit(self.allocator);
        for (loaded.parsed.value) |*existing| {
            if (std.mem.eql(u8, existing.id, server.id)) {
                const copy = try server.copy(self.allocator);
                defer {
                    var c = copy;
                    c.deinit(self.allocator);
                }
                existing.* = copy;
                return self.save(io, loaded.parsed.value);
            }
        }
        const list = try self.allocator.alloc(Server, loaded.parsed.value.len + 1);
        defer self.allocator.free(list);
        @memcpy(list[0..loaded.parsed.value.len], loaded.parsed.value);
        const copy = try server.copy(self.allocator);
        defer {
            var c = copy;
            c.deinit(self.allocator);
        }
        list[loaded.parsed.value.len] = copy;
        try self.save(io, list);
    }

    pub fn delete(self: *Store, io: std.Io, id: []const u8) !void {
        var loaded = try self.loadParsed(io);
        defer loaded.deinit(self.allocator);
        var kept: std.ArrayList(Server) = .empty;
        defer kept.deinit(self.allocator);
        for (loaded.parsed.value) |s| {
            if (!std.mem.eql(u8, s.id, id)) try kept.append(self.allocator, s);
        }
        try self.save(io, kept.items);
    }
};

/// Expands a leading "~/" against `home` — tilde syntax is a shell
/// convention libssh2 knows nothing about, so a stored key path like
/// "~/.ssh/id_ed25519" would never resolve otherwise. Anything else is
/// returned as a plain copy. Caller owns the result.
pub fn expandHome(allocator: std.mem.Allocator, path: []const u8, home: ?[]const u8) ![]const u8 {
    if (path.len >= 2 and path[0] == '~' and path[1] == '/') {
        if (home) |h| return std.fmt.allocPrint(allocator, "{s}{s}", .{ h, path[1..] });
    }
    return allocator.dupe(u8, path);
}

pub fn makeId(allocator: std.mem.Allocator, now_ns: i128) ![]const u8 {
    const hex = "0123456789abcdef";
    var out: [16]u8 = undefined;
    var v: u64 = @intCast(now_ns);
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        out[15 - i] = hex[v & 0xf];
        v >>= 4;
    }
    return allocator.dupe(u8, &out);
}

// --- tests -----------------------------------------------------------------

fn testStorePath(io: std.Io, dir_buf: []u8, path_buf: []u8) []const u8 {
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    const dir_name = std.fmt.bufPrint(dir_buf, "oars-store-test-{d}", .{now}) catch unreachable;
    return std.fmt.bufPrint(path_buf, "/tmp/{s}/servers.json", .{dir_name}) catch unreachable;
}

test "server copy round-trips tags and via_server_id" {
    const allocator = std.testing.allocator;
    // All fields are allocated: Server.deinit frees them.
    const tags = try allocator.alloc([]const u8, 2);
    tags[0] = try allocator.dupe(u8, "customer-facing");
    tags[1] = try allocator.dupe(u8, "nodejs");
    var original = Server{
        .id = try allocator.dupe(u8, "s1"),
        .name = try allocator.dupe(u8, "prod"),
        .host = try allocator.dupe(u8, "10.0.0.1"),
        .user = try allocator.dupe(u8, "root"),
        .tags = tags,
        .via_server_id = try allocator.dupe(u8, "bastion"),
    };
    defer original.deinit(allocator);

    const copy = try original.copy(allocator);

    try std.testing.expectEqualStrings("10.0.0.1", copy.host);
    try std.testing.expectEqual(@as(usize, 2), copy.tags.len);
    try std.testing.expectEqualStrings("customer-facing", copy.tags[0]);
    try std.testing.expectEqualStrings("nodejs", copy.tags[1]);
    try std.testing.expectEqualStrings("bastion", copy.via_server_id.?);
    // Deep copy: replacing the copy's tag must not touch the original.
    allocator.free(copy.tags[0]);
    const replaced: []const u8 = allocator.dupe(u8, "renamed") catch unreachable;
    var mutable = copy;
    mutable.tags[0] = replaced;
    mutable.deinit(allocator);
    try std.testing.expectEqualStrings("customer-facing", original.tags[0]);
}

test "store saves servers.json with owner-only permissions" {
    if (builtin.os.tag == .windows) return;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [128]u8 = undefined;
    var path_buf: [512]u8 = undefined;
    const store_path = testStorePath(io, &dir_buf, &path_buf);
    defer std.Io.Dir.cwd().deleteTree(io, dir_buf[0..]) catch {};

    var store = Store{ .allocator = allocator, .path = store_path };
    var server = Server{
        .id = try allocator.dupe(u8, "s1"),
        .name = try allocator.dupe(u8, "prod"),
        .host = try allocator.dupe(u8, "10.0.0.1"),
        .user = try allocator.dupe(u8, "root"),
    };
    defer server.deinit(allocator);
    try store.upsert(io, server);

    var file = try std.Io.Dir.cwd().openFile(io, store_path, .{});
    defer file.close(io);
    const mode = (try file.stat(io)).permissions.toMode();
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), mode & 0o777);
}

test "permissive existing store file is tightened on save" {
    if (builtin.os.tag == .windows) return;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [128]u8 = undefined;
    var path_buf: [512]u8 = undefined;
    const store_path = testStorePath(io, &dir_buf, &path_buf);
    defer std.Io.Dir.cwd().deleteTree(io, dir_buf[0..]) catch {};
    // The seed file is written before any Store.save creates the directory.
    try std.Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(store_path).?);

    // Write a world-readable file the way a careless tool would.
    var seed = std.Io.Dir.cwd().createFile(io, store_path, .{ .permissions = .fromMode(0o644) }) catch unreachable;
    seed.writeStreamingAll(io, "[]") catch unreachable;
    seed.setPermissions(io, .fromMode(0o644)) catch unreachable;
    seed.close(io);

    var store = Store{ .allocator = allocator, .path = store_path };
    var server = Server{
        .id = try allocator.dupe(u8, "s1"),
        .name = try allocator.dupe(u8, "prod"),
        .host = try allocator.dupe(u8, "10.0.0.1"),
        .user = try allocator.dupe(u8, "root"),
    };
    defer server.deinit(allocator);
    try store.upsert(io, server);

    var file = try std.Io.Dir.cwd().openFile(io, store_path, .{});
    defer file.close(io);
    const mode = (try file.stat(io)).permissions.toMode();
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), mode & 0o777);
}

test "corrupt store file is quarantined, not replaced" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [128]u8 = undefined;
    var path_buf: [512]u8 = undefined;
    const store_path = testStorePath(io, &dir_buf, &path_buf);
    defer std.Io.Dir.cwd().deleteTree(io, dir_buf[0..]) catch {};
    try std.Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(store_path).?);

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = store_path, .data = "{not json at all" });

    var store = Store{ .allocator = allocator, .path = store_path };
    var loaded = try store.loadParsed(io);
    defer loaded.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), loaded.parsed.value.len);
    try std.testing.expect(loaded.quarantined != null);
    // The original path is gone (never overwritten in place) and the
    // damaged file survives under the timestamped quarantine name.
    std.Io.Dir.cwd().access(io, store_path, .{}) catch |err| {
        try std.testing.expectEqual(error.FileNotFound, err);
    };
    try std.Io.Dir.cwd().access(io, loaded.quarantined.?, .{});

    // A subsequent save starts a fresh store instead of failing.
    var server = Server{
        .id = try allocator.dupe(u8, "s1"),
        .name = try allocator.dupe(u8, "prod"),
        .host = try allocator.dupe(u8, "10.0.0.1"),
        .user = try allocator.dupe(u8, "root"),
    };
    defer server.deinit(allocator);
    try store.upsert(io, server);
    var reloaded = try store.loadParsed(io);
    defer reloaded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), reloaded.parsed.value.len);
    try std.testing.expect(reloaded.quarantined == null);
}

test "via chain validation rejects self, missing, deep, and cyclic chains" {
    const allocator = std.testing.allocator;
    const all = try allocator.alloc(Server, 5);
    defer {
        for (all) |*s| s.deinit(allocator);
        allocator.free(all);
    }
    // Every string field is allocated: Server.deinit frees them.
    for (0..5) |i| {
        const id = try std.fmt.allocPrint(allocator, "{c}", .{'a' + @as(u8, @intCast(i))});
        all[i] = .{
            .id = id,
            .name = try allocator.dupe(u8, "n"),
            .host = try allocator.dupe(u8, "h"),
            .user = try allocator.dupe(u8, "u"),
        };
    }

    // No via: valid.
    try validateViaChain(.{ .id = "x", .name = "", .host = "", .user = "" }, all);

    // Self-link.
    try std.testing.expectError(
        error.SelfLink,
        validateViaChain(.{ .id = "a", .name = "", .host = "", .user = "", .via_server_id = "a" }, all),
    );

    // Missing reference.
    try std.testing.expectError(
        error.MissingVia,
        validateViaChain(.{ .id = "x", .name = "", .host = "", .user = "", .via_server_id = "nope" }, all),
    );

    // Depth 3 is valid: x -> a -> b -> c.
    all[0].via_server_id = try allocator.dupe(u8, "b");
    all[1].via_server_id = try allocator.dupe(u8, "c");
    try validateViaChain(.{ .id = "x", .name = "", .host = "", .user = "", .via_server_id = "a" }, all);

    // Depth 4 is rejected: x -> a -> b -> c -> d.
    all[2].via_server_id = try allocator.dupe(u8, "d");
    try std.testing.expectError(
        error.ChainTooDeep,
        validateViaChain(.{ .id = "x", .name = "", .host = "", .user = "", .via_server_id = "a" }, all),
    );

    // Cycle: a -> b -> a.
    allocator.free(all[1].via_server_id.?);
    all[1].via_server_id = try allocator.dupe(u8, "a");
    try std.testing.expectError(
        error.Cycle,
        validateViaChain(.{ .id = "x", .name = "", .host = "", .user = "", .via_server_id = "a" }, all),
    );
}

test "expandHome expands only a leading tilde" {
    const allocator = std.testing.allocator;
    const expanded = try expandHome(allocator, "~/.ssh/id_ed25519", "/home/oars");
    defer allocator.free(expanded);
    try std.testing.expectEqualStrings("/home/oars/.ssh/id_ed25519", expanded);

    const plain = try expandHome(allocator, "/etc/ssh/key", "/home/oars");
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("/etc/ssh/key", plain);

    const bare = try expandHome(allocator, "~", "/home/oars");
    defer allocator.free(bare);
    try std.testing.expectEqualStrings("~", bare);
}
