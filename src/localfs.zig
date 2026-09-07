//! Bounded local-filesystem browsing for the spec 05 two-pane file manager.
//! A directory path enters this module only after the native directory picker
//! returns it. Listing never follows symlinks and never reads file contents.

const std = @import("std");

pub const max_entries: usize = 5000;
pub const max_path_bytes: usize = 16 * 1024;

pub const Kind = enum {
    file,
    dir,
    symlink,
    other,

    pub fn jsonName(self: Kind) []const u8 {
        return @tagName(self);
    }
};

pub const Entry = struct {
    name: []u8,
    path: []u8,
    kind: Kind,
    size: u64,
    mtime: i64,

    pub fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.path);
    }
};

pub const Listing = struct {
    entries: []Entry,
    truncated: bool,

    pub fn deinit(self: *Listing, allocator: std.mem.Allocator) void {
        for (self.entries) |*entry| entry.deinit(allocator);
        allocator.free(self.entries);
    }
};

pub fn validateAbsolutePath(path: []const u8) !void {
    if (path.len == 0 or path.len > max_path_bytes) return error.InvalidPath;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidPath;
    if (!std.fs.path.isAbsolute(path)) return error.InvalidPath;
}

fn kindFromFile(kind: std.Io.File.Kind) Kind {
    return switch (kind) {
        .file => .file,
        .directory => .dir,
        .sym_link => .symlink,
        else => .other,
    };
}

fn lessThan(_: void, a: Entry, b: Entry) bool {
    if (a.kind == .dir and b.kind != .dir) return true;
    if (a.kind != .dir and b.kind == .dir) return false;
    return std.ascii.lessThanIgnoreCase(a.name, b.name);
}

pub fn list(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Listing {
    try validateAbsolutePath(path);
    var dir = try std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true });
    defer dir.close(io);

    var entries: std.ArrayList(Entry) = .empty;
    errdefer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit(allocator);
    }
    var iterator = dir.iterateAssumeFirstIteration();
    var truncated = false;
    while (try iterator.next(io)) |raw| {
        if (entries.items.len == max_entries) {
            truncated = true;
            break;
        }
        const stat = dir.statFile(io, raw.name, .{ .follow_symlinks = false }) catch null;
        const kind = kindFromFile(if (stat) |value| value.kind else raw.kind);
        const name = try allocator.dupe(u8, raw.name);
        errdefer allocator.free(name);
        const full_path = try std.fs.path.join(allocator, &.{ path, raw.name });
        errdefer allocator.free(full_path);
        try entries.append(allocator, .{
            .name = name,
            .path = full_path,
            .kind = kind,
            .size = if (stat) |value| value.size else 0,
            .mtime = if (stat) |value| @intCast(@divFloor(value.mtime.nanoseconds, std.time.ns_per_s)) else 0,
        });
    }
    std.mem.sort(Entry, entries.items, {}, lessThan);
    return .{ .entries = try entries.toOwnedSlice(allocator), .truncated = truncated };
}

test "absolute local paths are required" {
    try std.testing.expectError(error.InvalidPath, validateAbsolutePath("relative/path"));
    try validateAbsolutePath(if (@import("builtin").os.tag == .windows) "C:\\Users" else "/Users");
}

test "listing keeps directories first and does not follow symlinks" {
    if (@import("builtin").os.tag == .windows) return;
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var name_buf: [128]u8 = undefined;
    const root = try std.fmt.bufPrint(&name_buf, "/tmp/oars-localfs-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    try std.Io.Dir.createDirAbsolute(io, root, .default_dir);
    defer std.Io.Dir.cwd().deleteTree(io, root) catch {};
    var dir = try std.Io.Dir.openDirAbsolute(io, root, .{});
    defer dir.close(io);
    try dir.createDir(io, "folder", .default_dir);
    var file = try dir.createFile(io, "z.txt", .{});
    try file.writeStreamingAll(io, "abc");
    file.close(io);
    try dir.symLink(io, "z.txt", "link", .{});

    var listing = try list(allocator, io, root);
    defer listing.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), listing.entries.len);
    try std.testing.expectEqual(Kind.dir, listing.entries[0].kind);
    try std.testing.expectEqual(Kind.symlink, listing.entries[1].kind);
    try std.testing.expectEqual(Kind.file, listing.entries[2].kind);
    try std.testing.expectEqual(@as(u64, 3), listing.entries[2].size);
}
