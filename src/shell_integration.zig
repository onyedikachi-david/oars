//! Bounded streaming OSC 633 parser. Only nonce-valid metadata changes history.
const std = @import("std");
pub const command_cap = 4096;
pub const frame_cap = command_cap * 4 + 128;
pub const Event = union(enum) { coverage: bool, command: []const u8, start, finish: i32 };
pub const Sink = struct {
    context: *anyopaque,
    output: *const fn (*anyopaque, []const u8) void,
    event: *const fn (*anyopaque, Event) void,
};
pub const Parser = struct {
    nonce: [32]u8,
    frame: [frame_cap]u8 = undefined,
    len: usize = 0,
    command: [command_cap]u8 = undefined,
    pub fn init(nonce: [32]u8) Parser {
        return .{ .nonce = nonce };
    }
    pub fn feed(self: *Parser, data: []const u8, sink: Sink) void {
        const prefix = "\x1b]633;";
        var offset: usize = 0;
        while (offset < data.len) {
            if (self.len == 0 and data[offset] != prefix[0]) {
                const next = if (std.mem.indexOfScalar(u8, data[offset..], prefix[0])) |index| offset + index else data.len;
                sink.output(sink.context, data[offset..next]);
                offset = next;
                continue;
            }
            const byte = data[offset];
            offset += 1;
            if (self.len < prefix.len and byte != prefix[self.len]) {
                sink.output(sink.context, self.frame[0..self.len]);
                self.len = 0;
                if (byte == prefix[0]) {
                    self.frame[0] = byte;
                    self.len = 1;
                } else sink.output(sink.context, &.{byte});
                continue;
            }
            if (self.len == self.frame.len) {
                sink.output(sink.context, self.frame[0..self.len]);
                self.len = 0;
                sink.event(sink.context, .{ .coverage = false });
                sink.output(sink.context, &.{byte});
                continue;
            }
            self.frame[self.len] = byte;
            self.len += 1;
            const bel = byte == 7;
            const st = self.len >= 2 and self.frame[self.len - 2] == 27 and byte == '\\';
            if (self.len >= prefix.len and (bel or st)) {
                const payload = self.frame[prefix.len .. self.len - @as(usize, if (bel) 1 else 2)];
                if (!self.parse(payload, sink)) sink.output(sink.context, self.frame[0..self.len]);
                self.len = 0;
            }
        }
    }
    pub fn flush(self: *Parser, sink: Sink) void {
        if (self.len > 0) sink.output(sink.context, self.frame[0..self.len]);
        self.len = 0;
    }
    fn parse(self: *Parser, payload: []const u8, sink: Sink) bool {
        const separator = std.mem.lastIndexOfScalar(u8, payload, ';') orelse return false;
        if (!std.mem.eql(u8, payload[separator + 1 ..], &self.nonce)) return false;
        const record = payload[0..separator];
        if (std.mem.eql(u8, record, "P;OarsHistory=1")) {
            sink.event(sink.context, .{ .coverage = true });
            return true;
        }
        if (std.mem.eql(u8, record, "P;OarsHistory=0")) {
            sink.event(sink.context, .{ .coverage = false });
            return true;
        }
        if (std.mem.eql(u8, record, "C")) {
            sink.event(sink.context, .start);
            return true;
        }
        if (std.mem.startsWith(u8, record, "D;")) {
            const code = std.fmt.parseInt(i32, record[2..], 10) catch return false;
            if (code < 0 or code > 255) return false;
            sink.event(sink.context, .{ .finish = code });
            return true;
        }
        if (std.mem.startsWith(u8, record, "E;")) {
            const decoded = decode(record[2..], &self.command) catch {
                sink.event(sink.context, .{ .coverage = false });
                return true;
            };
            if (decoded.len == 0) return true;
            sink.event(sink.context, .{ .command = decoded });
            return true;
        }
        return false;
    }
};
pub fn decode(encoded: []const u8, output: []u8) ![]const u8 {
    var i: usize = 0;
    var n: usize = 0;
    while (i < encoded.len) {
        if (n == output.len) return error.CommandTooLong;
        const value: u8 = if (encoded[i] == '\\') blk: {
            if (i + 1 < encoded.len and encoded[i + 1] == '\\') {
                i += 2;
                break :blk '\\';
            }
            if (i + 3 >= encoded.len or encoded[i + 1] != 'x') return error.InvalidEscape;
            const byte = std.fmt.parseInt(u8, encoded[i + 2 .. i + 4], 16) catch return error.InvalidEscape;
            i += 4;
            break :blk byte;
        } else blk: {
            const byte = encoded[i];
            i += 1;
            break :blk byte;
        };
        if (value == 0) return error.InvalidCommand;
        output[n] = value;
        n += 1;
    }
    if (!std.unicode.utf8ValidateSlice(output[0..n])) return error.InvalidCommand;
    return output[0..n];
}
pub fn resource(shell: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, shell, "bash")) return @embedFile("resources/shell-integration/v1/bash.sh");
    if (std.mem.eql(u8, shell, "zsh")) return @embedFile("resources/shell-integration/v1/zsh.sh");
    if (std.mem.eql(u8, shell, "fish")) return @embedFile("resources/shell-integration/v1/fish.fish");
    return null;
}

const TestSink = struct {
    output_bytes: std.ArrayList(u8) = .empty,
    commands: std.ArrayList(u8) = .empty,
    started: usize = 0,
    finished: usize = 0,
    full: bool = false,
    exit: i32 = -1,
    fn output(context: *anyopaque, bytes: []const u8) void {
        const self: *TestSink = @ptrCast(@alignCast(context));
        self.output_bytes.appendSlice(std.testing.allocator, bytes) catch unreachable;
    }
    fn event(context: *anyopaque, value: Event) void {
        const self: *TestSink = @ptrCast(@alignCast(context));
        switch (value) {
            .command => |command| self.commands.appendSlice(std.testing.allocator, command) catch unreachable,
            .start => self.started += 1,
            .finish => |code| {
                self.finished += 1;
                self.exit = code;
            },
            .coverage => |full| self.full = full,
        }
    }
    fn sink(self: *TestSink) Sink {
        return .{ .context = self, .output = output, .event = event };
    }
    fn deinit(self: *TestSink) void {
        self.output_bytes.deinit(std.testing.allocator);
        self.commands.deinit(std.testing.allocator);
    }
};
test "OSC command decoding preserves multiline and escaped punctuation" {
    var buffer: [128]u8 = undefined;
    try std.testing.expectEqualStrings("printf 'a;b'\nls \\tmp", try decode("printf\\x20'a\\x3bb'\\x0als\\x20\\\\tmp", &buffer));
    try std.testing.expectError(error.InvalidEscape, decode("bad\\xGG", &buffer));
    try std.testing.expectError(error.InvalidCommand, decode("bad\\x00", &buffer));
}
test "OSC streaming accepts only the shell nonce and strips valid metadata at every boundary" {
    const nonce = "0123456789abcdef0123456789abcdef";
    const stream = "hello\x1b]633;P;OarsHistory=1;" ++ nonce ++ "\x07\x1b]633;E;echo\\x20ok;" ++ nonce ++ "\x07\x1b]633;C;" ++ nonce ++ "\x1b\\ok\r\n\x1b]633;D;3;" ++ nonce ++ "\x07";
    for (0..stream.len) |boundary| {
        var parser = Parser.init(nonce.*);
        var target = TestSink{};
        defer target.deinit();
        parser.feed(stream[0..boundary], target.sink());
        parser.feed(stream[boundary..], target.sink());
        parser.flush(target.sink());
        try std.testing.expectEqualStrings("hellook\r\n", target.output_bytes.items);
        try std.testing.expectEqualStrings("echo ok", target.commands.items);
        try std.testing.expect(target.full);
        try std.testing.expectEqual(@as(usize, 1), target.started);
        try std.testing.expectEqual(@as(i32, 3), target.exit);
    }
    var parser = Parser.init(nonce.*);
    var target = TestSink{};
    defer target.deinit();
    const forged = "\x1b]633;E;rm\\x20-rf;wrong\x07\x1b[31mordinary\x1b[0m";
    parser.feed(forged, target.sink());
    parser.flush(target.sink());
    try std.testing.expectEqualStrings(forged, target.output_bytes.items);
    try std.testing.expectEqual(@as(usize, 0), target.commands.items.len);
}

/// Static, reviewed installer; all shell data is quoted as a single POSIX word.
pub fn installCommand(allocator: std.mem.Allocator, shell: []const u8) ![]u8 {
    const quote = @import("shellquote.zig").quote;
    const source = resource(shell) orelse return error.UnsupportedShell;
    const extension = if (std.mem.eql(u8, shell, "fish")) "fish" else "sh";
    const rc = if (std.mem.eql(u8, shell, "bash")) ".bashrc" else if (std.mem.eql(u8, shell, "zsh")) ".zshrc" else ".config/fish/config.fish";
    const quoted = try quote(allocator, source);
    defer allocator.free(quoted);
    const hook = if (std.mem.eql(u8, shell, "fish"))
        "if set -q OARS_HISTORY_NONCE; source \"$HOME/.config/oars/shell/v1/fish.fish\"; end # oars-shell-history-v1"
    else if (std.mem.eql(u8, shell, "bash"))
        "[ -z \"${OARS_HISTORY_NONCE:-}\" ] || . \"$HOME/.config/oars/shell/v1/bash.sh\" # oars-shell-history-v1"
    else
        "[ -z \"${OARS_HISTORY_NONCE:-}\" ] || . \"$HOME/.config/oars/shell/v1/zsh.sh\" # oars-shell-history-v1";
    const quoted_hook = try quote(allocator, hook);
    defer allocator.free(quoted_hook);
    const bootstrap = try quote(allocator, @embedFile("resources/shell-integration/v1/bash-start.sh"));
    defer allocator.free(bootstrap);
    const body = try std.fmt.allocPrint(allocator, "set -eu\numask 077\ncommand -v {s} >/dev/null || {{ printf 'Shell is not installed\\n' >&2; exit 1; }}\n" ++
        "dir=\"$HOME/.config/oars/shell/v1\"\nrc=\"$HOME/{s}\"\nmkdir -p \"$dir\" \"$(dirname \"$rc\")\"\n" ++
        "[ ! -L \"$dir/{s}.{s}\" ] && [ ! -L \"$rc\" ] || {{ printf 'Refusing a symbolic-link target\\n' >&2; exit 1; }}\n" ++
        "tmp=$(mktemp \"$dir/.install.XXXXXX\")\ntrap 'rm -f \"$tmp\"' EXIT\nprintf %s {s} >\"$tmp\"\nchmod 600 \"$tmp\"\nmv -f \"$tmp\" \"$dir/{s}.{s}\"\n" ++
        "printf %s {s} >\"$dir/bash-start.sh\"\n" ++
        "if [ ! -e \"$rc\" ]; then : >\"$rc\"; fi\nif ! grep -Fq '# oars-shell-history-v1' \"$rc\"; then printf '\\n%s\\n' {s} >>\"$rc\"; fi\n" ++
        "printf 'Shell history helper installed. Enable it for the next connection.\\n'\n", .{ shell, rc, shell, extension, quoted, shell, extension, bootstrap, quoted_hook });
    defer allocator.free(body);
    const body_quoted = try quote(allocator, body);
    defer allocator.free(body_quoted);
    return std.fmt.allocPrint(allocator, "sh -c {s}", .{body_quoted});
}
