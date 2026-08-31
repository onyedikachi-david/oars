//! Strict provider-output schema and local proposal validation.

const std = @import("std");
const types = @import("types.zig");

pub const schema_name = "oars_chat_result_v2";
pub const strict_schema_json =
    \\{"type":"object","additionalProperties":false,"properties":{"kind":{"type":"string","enum":["message","command","question"]},"message":{"type":["string","null"]},"command":{"type":["string","null"]},"question":{"type":["string","null"]},"explanation":{"type":"string"},"destructive":{"type":"boolean"},"needs_sudo":{"type":"boolean"}},"required":["kind","message","command","question","explanation","destructive","needs_sudo"]}
;

pub const Kind = enum { message, command, question };

const Raw = struct {
    kind: Kind,
    // The default keeps recovery compatible with Spec 11 journal records.
    message: ?[]const u8 = null,
    command: ?[]const u8,
    question: ?[]const u8,
    explanation: []const u8,
    destructive: bool,
    needs_sudo: bool,
};

pub const Error = error{
    InvalidJson,
    InvalidDiscriminator,
    InvalidText,
    LimitExceeded,
    OutOfMemory,
};

pub const Validated = struct {
    kind: Kind,
    message: ?[]u8,
    command: ?[]u8,
    question: ?[]u8,
    explanation: []u8,
    model_destructive: bool,
    local_destructive: bool,
    needs_sudo: bool,

    pub fn deinit(self: *Validated, allocator: std.mem.Allocator) void {
        if (self.message) |value| allocator.free(value);
        if (self.command) |value| allocator.free(value);
        if (self.question) |value| allocator.free(value);
        allocator.free(self.explanation);
    }
};

pub fn parse(allocator: std.mem.Allocator, json_bytes: []const u8) Error!Validated {
    if (json_bytes.len == 0 or json_bytes.len > types.max_structured_output_bytes or !std.unicode.utf8ValidateSlice(json_bytes)) return error.LimitExceeded;
    var parsed = std.json.parseFromSlice(Raw, allocator, json_bytes, .{ .allocate = .alloc_always }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidJson;
    defer parsed.deinit();
    const raw = parsed.value;
    if (!validText(raw.explanation, types.max_explanation_bytes, true)) return textError(raw.explanation.len, types.max_explanation_bytes);
    switch (raw.kind) {
        .message => {
            if (raw.command != null or raw.question != null or raw.message == null) return error.InvalidDiscriminator;
            if (!validText(raw.message.?, types.max_message_bytes, false)) return textError(raw.message.?.len, types.max_message_bytes);
        },
        .command => {
            if (raw.message != null or raw.question != null or raw.command == null) return error.InvalidDiscriminator;
            if (!validText(raw.command.?, types.max_command_bytes, false)) return textError(raw.command.?.len, types.max_command_bytes);
        },
        .question => {
            if (raw.message != null or raw.command != null or raw.question == null) return error.InvalidDiscriminator;
            if (!validText(raw.question.?, types.max_question_bytes, false)) return textError(raw.question.?.len, types.max_question_bytes);
        },
    }

    const message = if (raw.message) |value| allocator.dupe(u8, value) catch return error.OutOfMemory else null;
    errdefer if (message) |value| allocator.free(value);
    const command = if (raw.command) |value| allocator.dupe(u8, value) catch return error.OutOfMemory else null;
    errdefer if (command) |value| allocator.free(value);
    const question = if (raw.question) |value| allocator.dupe(u8, value) catch return error.OutOfMemory else null;
    errdefer if (question) |value| allocator.free(value);
    const explanation = allocator.dupe(u8, raw.explanation) catch return error.OutOfMemory;
    return .{
        .kind = raw.kind,
        .message = message,
        .command = command,
        .question = question,
        .explanation = explanation,
        .model_destructive = raw.destructive,
        .local_destructive = if (raw.command) |value| isDestructive(value) else false,
        .needs_sudo = raw.needs_sudo,
    };
}

fn textError(len: usize, max: usize) Error {
    return if (len > max) error.LimitExceeded else error.InvalidText;
}

fn validText(value: []const u8, max: usize, allow_empty: bool) bool {
    if ((!allow_empty and value.len == 0) or value.len > max) return false;
    return std.unicode.utf8ValidateSlice(value) and std.mem.indexOfScalar(u8, value, 0) == null;
}

fn isBoundary(ch: u8) bool {
    return !std.ascii.isAlphanumeric(ch) and ch != '_' and ch != '-';
}

fn containsWord(text: []const u8, word: []const u8) bool {
    var start: usize = 0;
    while (std.mem.indexOfPos(u8, text, start, word)) |index| {
        const before = index == 0 or isBoundary(text[index - 1]);
        const end = index + word.len;
        const after = end == text.len or isBoundary(text[end]);
        if (before and after) return true;
        start = index + 1;
    }
    return false;
}

pub fn isDestructive(command: []const u8) bool {
    if (command.len == 0 or !std.unicode.utf8ValidateSlice(command)) return true;
    var lower_buffer: [types.max_command_bytes]u8 = undefined;
    if (command.len > lower_buffer.len) return true;
    const lower = lower_buffer[0..command.len];
    for (command, 0..) |ch, index| lower[index] = std.ascii.toLower(ch);
    const direct = [_][]const u8{ "rm", "rmdir", "mkfs", "shutdown", "reboot", "poweroff", "halt", "kill", "pkill", "killall", "chown", "chmod", "truncate", "wipefs" };
    for (direct) |word| if (containsWord(lower, word)) return true;
    if (containsWord(lower, "dd") and std.mem.indexOf(u8, lower, "of=") != null) return true;
    const managers = [_][]const u8{ "apt", "apt-get", "dnf", "yum", "apk", "pacman", "zypper" };
    const removals = [_][]const u8{ "remove", "purge", "erase", "uninstall" };
    var has_manager = false;
    for (managers) |word| if (containsWord(lower, word)) {
        has_manager = true;
        break;
    };
    if (has_manager) for (removals) |word| if (containsWord(lower, word)) return true;
    return false;
}

test "strict proposal validator accepts one complete command or question" {
    var command = try parse(std.testing.allocator, "{\"kind\":\"command\",\"command\":\"uname -a\",\"question\":null,\"explanation\":\"Inspect the kernel.\",\"destructive\":false,\"needs_sudo\":false}");
    defer command.deinit(std.testing.allocator);
    try std.testing.expectEqual(Kind.command, command.kind);
    try std.testing.expectEqualStrings("uname -a", command.command.?);
    try std.testing.expect(!command.local_destructive);
    var question = try parse(std.testing.allocator, "{\"kind\":\"question\",\"command\":null,\"question\":\"Which service?\",\"explanation\":\"The target is ambiguous.\",\"destructive\":false,\"needs_sudo\":false}");
    defer question.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("Which service?", question.question.?);
}

test "strict chat validator accepts assistant prose and rejects mixed results" {
    var message = try parse(std.testing.allocator, "{\"kind\":\"message\",\"message\":\"The root filesystem is 56% used.\",\"command\":null,\"question\":null,\"explanation\":\"Summarized the reviewed output.\",\"destructive\":false,\"needs_sudo\":false}");
    defer message.deinit(std.testing.allocator);
    try std.testing.expectEqual(Kind.message, message.kind);
    try std.testing.expectEqualStrings("The root filesystem is 56% used.", message.message.?);
    try std.testing.expectError(error.InvalidDiscriminator, parse(std.testing.allocator, "{\"kind\":\"message\",\"message\":\"Done.\",\"command\":\"echo done\",\"question\":null,\"explanation\":\"x\",\"destructive\":false,\"needs_sudo\":false}"));
}

test "strict proposal validator rejects extra fields wrong nulls NUL and oversize" {
    try std.testing.expectError(error.InvalidJson, parse(std.testing.allocator, "{\"kind\":\"command\",\"command\":\"id\",\"question\":null,\"explanation\":\"x\",\"destructive\":false,\"needs_sudo\":false,\"extra\":true}"));
    try std.testing.expectError(error.InvalidDiscriminator, parse(std.testing.allocator, "{\"kind\":\"command\",\"command\":null,\"question\":\"x\",\"explanation\":\"x\",\"destructive\":false,\"needs_sudo\":false}"));
    try std.testing.expectError(error.InvalidDiscriminator, parse(std.testing.allocator, "{\"kind\":\"question\",\"command\":\"id\",\"question\":null,\"explanation\":\"x\",\"destructive\":false,\"needs_sudo\":false}"));
    try std.testing.expectError(error.InvalidText, parse(std.testing.allocator, "{\"kind\":\"command\",\"command\":\"id\\u0000whoami\",\"question\":null,\"explanation\":\"x\",\"destructive\":false,\"needs_sudo\":false}"));
    const long_command = try std.testing.allocator.alloc(u8, types.max_command_bytes + 1);
    defer std.testing.allocator.free(long_command);
    @memset(long_command, 'x');
    const document = try std.fmt.allocPrint(std.testing.allocator, "{{\"kind\":\"command\",\"command\":\"{s}\",\"question\":null,\"explanation\":\"x\",\"destructive\":false,\"needs_sudo\":false}}", .{long_command});
    defer std.testing.allocator.free(document);
    try std.testing.expectError(error.LimitExceeded, parse(std.testing.allocator, document));
}

test "shared destructive fixtures match local classifier" {
    const Fixture = struct { command: []const u8, destructive: bool };
    const fixture_bytes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "fixtures/ai/destructive.json", std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(fixture_bytes);
    var fixtures = try std.json.parseFromSlice([]Fixture, std.testing.allocator, fixture_bytes, .{});
    defer fixtures.deinit();
    for (fixtures.value) |fixture| try std.testing.expectEqual(fixture.destructive, isDestructive(fixture.command));
}
