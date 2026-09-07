const std = @import("std");
/// RFC 4180 text field, with spreadsheet formulas neutralized on export.
pub fn field(writer: *std.Io.Writer, value: []const u8) !void {
    const trimmed = std.mem.trimStart(u8, value, " \t\r\n");
    const formula = trimmed.len > 0 and std.mem.indexOfScalar(u8, "=+-@", trimmed[0]) != null;
    try writer.writeByte('"');
    if (formula) try writer.writeByte('\'');
    for (value) |byte| {
        if (byte == '"') try writer.writeByte('"');
        try writer.writeByte(byte);
    }
    try writer.writeByte('"');
}
test "CSV keeps commas quotes and newlines and neutralizes leading formulas" {
    var buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try field(&writer, "a,\"b\"\n");
    try writer.writeByte(',');
    try field(&writer, " =1+1");
    try std.testing.expectEqualStrings("\"a,\"\"b\"\"\n\",\"' =1+1\"", writer.buffered());
}
