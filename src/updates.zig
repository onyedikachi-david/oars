//! Native updater boundary and the bounded Linux notification-feed parser.
const std = @import("std");
const json = @import("json.zig");
pub const c = @cImport({
    @cInclude("updates.h");
});
pub const version = @import("build_options").app_version;
pub const state_names = [_][]const u8{ "unavailable", "idle", "checking", "available", "downloading", "verifying", "ready", "blocked", "error" };

pub fn parseVersion(value: []const u8) ![3]u32 {
    if (value.len == 0 or value.len > 32) return error.InvalidVersion;
    var parts = std.mem.splitScalar(u8, value, '.');
    var result: [3]u32 = undefined;
    for (&result) |*part| {
        const text = parts.next() orelse return error.InvalidVersion;
        if (text.len == 0 or (text.len > 1 and text[0] == '0')) return error.InvalidVersion;
        for (text) |ch| if (ch < '0' or ch > '9') return error.InvalidVersion;
        part.* = std.fmt.parseInt(u32, text, 10) catch return error.InvalidVersion;
    }
    if (parts.next() != null) return error.InvalidVersion;
    return result;
}

pub fn newer(candidate: []const u8, current: []const u8) !bool {
    const a = try parseVersion(candidate);
    const b = try parseVersion(current);
    for (a, b) |left, right| {
        if (left != right) return left > right;
    }
    return false;
}

pub fn parseFeed(allocator: std.mem.Allocator, data: []const u8, current: []const u8, output: []u8) !bool {
    if (data.len > 128 * 1024) return error.FeedTooLarge;
    const Feed = struct { schema_version: u8, version: []const u8 };
    var parsed = try std.json.parseFromSlice(Feed, allocator, data, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    if (parsed.value.schema_version != 1) return error.InvalidFeed;
    const found = try newer(parsed.value.version, current);
    if (parsed.value.version.len >= output.len) return error.InvalidVersion;
    @memcpy(output[0..parsed.value.version.len], parsed.value.version);
    output[parsed.value.version.len] = 0;
    return found;
}

pub fn feedCallback(_: ?*anyopaque, data: [*c]const u8, len: usize, out: [*c]u8, capacity: usize) callconv(.c) c_int {
    if (data == null or out == null) return -1;
    const found = parseFeed(std.heap.page_allocator, data[0..len], version, out[0..capacity]) catch return -1;
    return if (found) 1 else 0;
}

pub fn writeStatus(output: []u8, busy: bool) ![]const u8 {
    var s: c.OarsUpdateStatus = std.mem.zeroes(c.OarsUpdateStatus);
    c.oars_updates_status(&s);
    var writer = std.Io.Writer.fixed(output);
    const mode: []const u8 = switch (s.mode) {
        1 => "sparkle",
        2 => "homebrew",
        3 => "manual",
        else => "unavailable",
    };
    const index: usize = if (s.state >= 0 and s.state < state_names.len) @intCast(s.state) else 0;
    try writer.writeAll("{\"mode\":");
    try json.writeJsonString(&writer, mode);
    try writer.writeAll(",\"state\":");
    try json.writeJsonString(&writer, state_names[index]);
    try writer.writeAll(",\"current_version\":");
    try json.writeJsonString(&writer, version);
    try writer.writeAll(",\"latest_version\":");
    try json.writeJsonString(&writer, std.mem.sliceTo(&s.latest_version, 0));
    try writer.writeAll(",\"error\":");
    const message = std.mem.sliceTo(&s.message, 0);
    try json.writeJsonString(&writer, if (std.unicode.utf8ValidateSlice(message)) message else "The update failed. Try again.");
    try writer.writeAll(",\"release_notes\":");
    const notes = std.mem.sliceTo(&s.release_notes, 0);
    try json.writeJsonString(&writer, if (std.unicode.utf8ValidateSlice(notes)) notes else "");
    try writer.print(",\"can_install\":{s},\"can_cancel\":{s},\"install_when_idle\":{s},\"downloaded_bytes\":{d},\"total_bytes\":{d}", .{
        boolText(s.can_install != 0), boolText(s.can_cancel != 0), boolText(s.install_when_idle != 0), s.downloaded_bytes, s.total_bytes,
    });
    try writer.print(",\"automatic_checks\":{s},\"automatic_downloads\":{s},\"can_check\":{s},\"can_resume\":{s},\"busy\":{s}}}", .{
        boolText(s.automatic_checks != 0), boolText(s.automatic_downloads != 0), boolText(s.can_check != 0), boolText(s.can_resume != 0), boolText(busy),
    });
    return writer.buffered();
}
fn boolText(v: bool) []const u8 {
    return if (v) "true" else "false";
}

test "notification feed rejects invalid versions, schemas, and unexpected payloads" {
    var out: [64]u8 = undefined;
    try std.testing.expect(try parseFeed(std.testing.allocator, "{\"schema_version\":1,\"version\":\"0.7.0\"}", "0.6.0", &out));
    try std.testing.expect(!try parseFeed(std.testing.allocator, "{\"schema_version\":1,\"version\":\"0.5.0\"}", "0.6.0", &out));
    for ([_][]const u8{ "1.0.0-beta", "01.0.0", "1.0", "1.0.0.1", "1.0.<script>", "4294967296.0.0" }) |bad| {
        try std.testing.expectError(error.InvalidVersion, parseVersion(bad));
    }
    try std.testing.expectError(error.InvalidFeed, parseFeed(std.testing.allocator, "{\"schema_version\":2,\"version\":\"1.0.0\"}", "0.6.0", &out));
    try std.testing.expectError(error.UnknownField, parseFeed(std.testing.allocator, "{\"schema_version\":1,\"version\":\"1.0.0\",\"url\":\"file:///tmp/run\"}", "0.6.0", &out));
}
