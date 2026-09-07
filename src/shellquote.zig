//! Shared POSIX-shell quoting (README cross-cutting convention: every value
//! from a user, profile, file path, domain, or model that goes into an SSH
//! exec string must pass through here — exec takes one shell string, not
//! argv).
//!
//! POSIX single-quote quoting (Bash §3.1.2.2): wrap in single quotes and
//! splice `'\''` for embedded quotes. The quoted form is a single word, so
//! it is safe against spaces, globs, metacharacters, and embedded quotes.

const std = @import("std");

/// Appends `value` to `out` in single-quoted form. Caller-provided buffer;
/// returns the bytes written (or the quoted length).
pub fn quoteAppend(out: []u8, value: []const u8) []const u8 {
    var i: usize = 0;
    out[i] = '\'';
    i += 1;
    for (value) |ch| {
        if (ch == '\'') {
            // Close the quote, splice the quote literally, reopen.
            const splice = "'\\''";
            @memcpy(out[i .. i + splice.len], splice);
            i += splice.len;
        } else {
            out[i] = ch;
            i += 1;
        }
    }
    out[i] = '\'';
    i += 1;
    return out[0..i];
}

/// Length of the single-quoted form, for sizing buffers.
pub fn quotedLen(value: []const u8) usize {
    var len: usize = 2;
    for (value) |ch| {
        len += if (ch == '\'') 4 else 1;
    }
    return len;
}

/// Allocated quoted form. Caller frees.
pub fn quote(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, quotedLen(value));
    const written = quoteAppend(out, value);
    return out[0..written.len];
}

// --- tests ---------------------------------------------------------------

test "single quotes wrap, and embedded quotes splice safely" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("'plain.log'", quoteAppend(&buf, "plain.log"));
    try std.testing.expectEqualStrings("'with space.log'", quoteAppend(&buf, "with space.log"));
    try std.testing.expectEqualStrings("'it'\\''s.log'", quoteAppend(&buf, "it's.log"));
    try std.testing.expectEqualStrings("''", quoteAppend(&buf, ""));
    try std.testing.expectEqualStrings("'$(rm -rf /); echo hi'", quoteAppend(&buf, "$(rm -rf /); echo hi"));
}

test "quoted form is a single shell word" {
    // Round-trip through a real shell: the quoted value must come back
    // whole, with no interpolation, globbing, or word-splitting.
    var buf: [256]u8 = undefined;
    const evil = "a b;$(touch /tmp/oars-quote-probe);'\"\\";
    const quoted = quoteAppend(&buf, evil);

    var fmt_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&fmt_buf, "printf %s {s}", .{quoted}) catch unreachable;
    const io = std.testing.io;
    const result = try std.process.run(std.testing.allocator, io, .{ .argv = &.{ "/bin/sh", "-c", cmd } });
    defer std.testing.allocator.free(result.stdout);
    defer std.testing.allocator.free(result.stderr);
    try std.testing.expectEqualStrings(evil, result.stdout);
    try std.testing.expect(std.mem.eql(u8, result.stderr, ""));
}
