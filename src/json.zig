//! Shared JSON helpers. The SDK root does not re-export its json helper,
//! so small serialization primitives live here instead of being duplicated
//! per module.

const std = @import("std");

/// Minimal JSON string writer (escapes quotes, backslashes, and control
/// characters).
pub fn writeJsonString(w: *std.Io.Writer, value: []const u8) !void {
    try w.writeAll("\"");
    for (value) |ch| {
        switch (ch) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => if (ch < 0x20) try w.print("\\u{x:0>4}", .{ch}) else try w.writeByte(ch),
        }
    }
    try w.writeAll("\"");
}
