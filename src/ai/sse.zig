//! Incremental, bounded Server-Sent Events parser for provider streams.

const std = @import("std");

pub const max_event_bytes: usize = 256 * 1024;
pub const max_event_name_bytes: usize = 128;

pub const Error = error{
    EventTooLarge,
    EventNameTooLarge,
    InvalidUtf8,
    Incomplete,
    OutOfMemory,
};

pub const Event = struct {
    name: []const u8,
    data: []const u8,
};

pub const Sink = struct {
    context: *anyopaque,
    event_fn: *const fn (context: *anyopaque, event: Event) anyerror!void,

    fn emit(self: Sink, event: Event) anyerror!void {
        return self.event_fn(self.context, event);
    }
};

pub const Parser = struct {
    allocator: std.mem.Allocator,
    line: std.ArrayList(u8) = .empty,
    data: std.ArrayList(u8) = .empty,
    event_name: std.ArrayList(u8) = .empty,
    saw_data: bool = false,

    pub fn init(allocator: std.mem.Allocator) Parser {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Parser) void {
        self.line.deinit(self.allocator);
        self.data.deinit(self.allocator);
        self.event_name.deinit(self.allocator);
    }

    pub fn feed(self: *Parser, bytes: []const u8, sink: Sink) anyerror!void {
        for (bytes) |byte| {
            if (byte == '\n') {
                const end = self.line.items.len - @intFromBool(self.line.items.len > 0 and self.line.items[self.line.items.len - 1] == '\r');
                try self.processLine(self.line.items[0..end], sink);
                self.line.clearRetainingCapacity();
                continue;
            }
            if (self.line.items.len >= max_event_bytes) return error.EventTooLarge;
            self.line.append(self.allocator, byte) catch return error.OutOfMemory;
        }
    }

    /// A provider stream must terminate through its adapter grammar. This
    /// method only validates that the byte stream did not end inside a line or
    /// an undispatched event.
    pub fn finish(self: *Parser) Error!void {
        if (self.line.items.len > 0 or self.saw_data or self.data.items.len > 0) return error.Incomplete;
    }

    fn processLine(self: *Parser, line: []const u8, sink: Sink) anyerror!void {
        if (line.len == 0) {
            if (!self.saw_data) {
                self.event_name.clearRetainingCapacity();
                return;
            }
            if (self.data.items.len > 0 and self.data.items[self.data.items.len - 1] == '\n') self.data.items.len -= 1;
            const name = if (self.event_name.items.len > 0) self.event_name.items else "message";
            if (!std.unicode.utf8ValidateSlice(name) or !std.unicode.utf8ValidateSlice(self.data.items)) return error.InvalidUtf8;
            try sink.emit(.{ .name = name, .data = self.data.items });
            self.data.clearRetainingCapacity();
            self.event_name.clearRetainingCapacity();
            self.saw_data = false;
            return;
        }
        if (line[0] == ':') return;
        const colon = std.mem.indexOfScalar(u8, line, ':');
        const field = if (colon) |index| line[0..index] else line;
        var value: []const u8 = if (colon) |index| line[index + 1 ..] else "";
        if (value.len > 0 and value[0] == ' ') value = value[1..];
        if (std.mem.eql(u8, field, "data")) {
            if (self.data.items.len + value.len + 1 > max_event_bytes) return error.EventTooLarge;
            self.data.appendSlice(self.allocator, value) catch return error.OutOfMemory;
            self.data.append(self.allocator, '\n') catch return error.OutOfMemory;
            self.saw_data = true;
        } else if (std.mem.eql(u8, field, "event")) {
            if (value.len > max_event_name_bytes) return error.EventNameTooLarge;
            self.event_name.clearRetainingCapacity();
            self.event_name.appendSlice(self.allocator, value) catch return error.OutOfMemory;
        }
        // `id`, `retry`, and extension fields are irrelevant to a one-request
        // provider stream and are deliberately ignored.
    }
};

const Capture = struct {
    allocator: std.mem.Allocator,
    names: std.ArrayList([]u8) = .empty,
    data: std.ArrayList([]u8) = .empty,

    fn deinit(self: *Capture) void {
        for (self.names.items) |value| self.allocator.free(value);
        for (self.data.items) |value| self.allocator.free(value);
        self.names.deinit(self.allocator);
        self.data.deinit(self.allocator);
    }

    fn event(context: *anyopaque, value: Event) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(context));
        const name = try self.allocator.dupe(u8, value.name);
        errdefer self.allocator.free(name);
        const data = try self.allocator.dupe(u8, value.data);
        errdefer self.allocator.free(data);
        try self.names.append(self.allocator, name);
        try self.data.append(self.allocator, data);
    }

    fn sink(self: *Capture) Sink {
        return .{ .context = self, .event_fn = event };
    }
};

test "SSE accepts LF CRLF comments multiline data and unknown fields" {
    const input = ": keepalive\r\nevent: response.output_text.delta\r\ndata: {\"delta\":\"hel\"}\r\ndata: {\"delta\":\"lo\"}\r\nid: ignored\r\n\r\ndata: [DONE]\n\n";
    var parser = Parser.init(std.testing.allocator);
    defer parser.deinit();
    var capture = Capture{ .allocator = std.testing.allocator };
    defer capture.deinit();
    try parser.feed(input, capture.sink());
    try parser.finish();
    try std.testing.expectEqual(@as(usize, 2), capture.data.items.len);
    try std.testing.expectEqualStrings("response.output_text.delta", capture.names.items[0]);
    try std.testing.expectEqualStrings("{\"delta\":\"hel\"}\n{\"delta\":\"lo\"}", capture.data.items[0]);
    try std.testing.expectEqualStrings("message", capture.names.items[1]);
    try std.testing.expectEqualStrings("[DONE]", capture.data.items[1]);
}

test "SSE produces the same events at every byte split" {
    const input = "event: progress\ndata: {\"text\":\"héllo\"}\n\ndata: [DONE]\n\n";
    var split: usize = 0;
    while (split <= input.len) : (split += 1) {
        var parser = Parser.init(std.testing.allocator);
        defer parser.deinit();
        var capture = Capture{ .allocator = std.testing.allocator };
        defer capture.deinit();
        try parser.feed(input[0..split], capture.sink());
        try parser.feed(input[split..], capture.sink());
        try parser.finish();
        try std.testing.expectEqual(@as(usize, 2), capture.data.items.len);
        try std.testing.expectEqualStrings("{\"text\":\"héllo\"}", capture.data.items[0]);
        try std.testing.expectEqualStrings("[DONE]", capture.data.items[1]);
    }
}

test "SSE rejects oversized invalid and unterminated events" {
    var parser = Parser.init(std.testing.allocator);
    defer parser.deinit();
    var capture = Capture{ .allocator = std.testing.allocator };
    defer capture.deinit();
    const oversized = try std.testing.allocator.alloc(u8, max_event_bytes + 1);
    defer std.testing.allocator.free(oversized);
    @memset(oversized, 'x');
    try std.testing.expectError(error.EventTooLarge, parser.feed(oversized, capture.sink()));

    var incomplete = Parser.init(std.testing.allocator);
    defer incomplete.deinit();
    try incomplete.feed("data: {\"x\":1}", capture.sink());
    try std.testing.expectError(error.Incomplete, incomplete.finish());

    var invalid = Parser.init(std.testing.allocator);
    defer invalid.deinit();
    try std.testing.expectError(error.InvalidUtf8, invalid.feed("data: \xff\n\n", capture.sink()));
}
