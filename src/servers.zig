//! Server configuration model and JSON persistence.
//!
//! Configs live in the app data directory (`servers.json`). Secrets
//! (passwords, key passphrases) never live here — the frontend stores
//! them through the Keychain-backed credentials bridge.

const std = @import("std");

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
    /// SHA-256 host key fingerprint (hex) once the user has trusted the
    /// server on first connect.
    host_fingerprint: ?[]const u8 = null,
    group: []const u8 = "",
    created_at: i64 = 0,
    updated_at: i64 = 0,

    pub fn copy(self: *const Server, allocator: std.mem.Allocator) !Server {
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
    }
};

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

        pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
            self.parsed.deinit();
            if (self.content) |c| allocator.free(c);
        }
    };

    /// Loads and parses all servers. Returns an empty list when the file
    /// does not exist or is malformed (the store treats corruption as
    /// "start fresh" rather than refusing to launch).
    pub fn loadParsed(self: *Store, io: std.Io) !Loaded {
        const cwd = std.Io.Dir.cwd();
        const empty = Loaded{
            .parsed = try std.json.parseFromSlice([]Server, self.allocator, "[]", .{}),
            .content = null,
        };
        const content = cwd.readFileAlloc(io, self.path, self.allocator, .limited(4 * 1024 * 1024)) catch return empty;
        const parsed = std.json.parseFromSlice([]Server, self.allocator, content, .{}) catch {
            self.allocator.free(content);
            return empty;
        };
        return .{ .parsed = parsed, .content = content };
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

    /// Persists the whole list. Creates the data directory on demand.
    pub fn save(self: *Store, io: std.Io, servers: []const Server) !void {
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(self.path)) |dir| try cwd.createDirPath(io, dir);
        var buf: [512 * 1024]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buf);
        std.json.Stringify.value(servers, .{ .whitespace = .indent_2 }, &writer) catch return error.SerializeFailed;
        try cwd.writeFile(io, .{
            .sub_path = self.path,
            .data = writer.buffered(),
        });
    }

    /// Inserts or replaces `server`, taking a deep copy of it. The
    /// caller keeps ownership of the argument.
    pub fn upsert(self: *Store, io: std.Io, server: Server) !void {
        var loaded = try self.loadParsed(io);
        defer loaded.deinit(self.allocator);
        for (loaded.parsed.value) |*existing| {
            if (std.mem.eql(u8, existing.id, server.id)) {
                existing.* = try server.copy(self.allocator);
                return self.save(io, loaded.parsed.value);
            }
        }
        const list = try self.allocator.alloc(Server, loaded.parsed.value.len + 1);
        defer self.allocator.free(list);
        @memcpy(list[0..loaded.parsed.value.len], loaded.parsed.value);
        list[loaded.parsed.value.len] = try server.copy(self.allocator);
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
