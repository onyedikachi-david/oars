//! OpenAI-compatible Chat Completions request and SSE adapter.

const std = @import("std");
const types = @import("types.zig");
const provider = @import("provider.zig");
const proposal = @import("proposal.zig");
const sse = @import("sse.zig");

pub const endpoint_suffix = "/chat/completions";

pub const Error = error{
    InvalidInput,
    RequestTooLarge,
    InvalidJson,
    MalformedChunk,
    MultipleChoices,
    ToolCallRejected,
    DuplicateTerminal,
    MissingTerminal,
    Refused,
    Incomplete,
    OutputInvalid,
    OutputTooLarge,
    OutOfMemory,
};

pub fn buildRequest(
    allocator: std.mem.Allocator,
    model: []const u8,
    role: provider.InstructionRole,
    mode: provider.StructuredOutput,
    instructions: []const u8,
    user_text: []const u8,
) Error![]u8 {
    return buildRequestWithContinuation(allocator, model, role, mode, instructions, user_text, "[]");
}

pub fn buildRequestWithContinuation(
    allocator: std.mem.Allocator,
    model: []const u8,
    role: provider.InstructionRole,
    mode: provider.StructuredOutput,
    instructions: []const u8,
    user_text: []const u8,
    continuation_json: []const u8,
) Error![]u8 {
    if (!validText(model, 256) or !validText(instructions, types.max_message_bytes) or !validText(user_text, types.max_message_bytes)) return error.InvalidInput;
    if (continuation_json.len > types.max_continuation_bytes) return error.RequestTooLarge;
    var continuation = std.json.parseFromSlice(std.json.Value, allocator, continuation_json, .{}) catch return error.InvalidInput;
    defer continuation.deinit();
    if (continuation.value != .array) return error.InvalidInput;
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;
    writer.writeAll("{\"model\":") catch return error.OutOfMemory;
    std.json.Stringify.value(model, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll(",\"stream\":true,\"messages\":[{\"role\":") catch return error.OutOfMemory;
    std.json.Stringify.value(@tagName(role), .{}, writer) catch return error.OutOfMemory;
    writer.writeAll(",\"content\":") catch return error.OutOfMemory;
    std.json.Stringify.value(instructions, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll("}") catch return error.OutOfMemory;
    for (continuation.value.array.items) |message| {
        writer.writeAll(",") catch return error.OutOfMemory;
        std.json.Stringify.value(message, .{}, writer) catch return error.OutOfMemory;
    }
    writer.writeAll(",{\"role\":\"user\",\"content\":") catch return error.OutOfMemory;
    std.json.Stringify.value(user_text, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll("}],\"response_format\":") catch return error.OutOfMemory;
    switch (mode) {
        .json_schema => {
            writer.writeAll("{\"type\":\"json_schema\",\"json_schema\":{\"name\":") catch return error.OutOfMemory;
            std.json.Stringify.value(proposal.schema_name, .{}, writer) catch return error.OutOfMemory;
            writer.writeAll(",\"strict\":true,\"schema\":") catch return error.OutOfMemory;
            writer.writeAll(proposal.strict_schema_json) catch return error.OutOfMemory;
            writer.writeAll("}}") catch return error.OutOfMemory;
        },
        .json_object => writer.writeAll("{\"type\":\"json_object\"}") catch return error.OutOfMemory,
    }
    writer.writeAll("}") catch return error.OutOfMemory;
    if (writer.buffered().len > types.max_request_body_bytes) return error.RequestTooLarge;
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

fn validText(value: []const u8, max: usize) bool {
    return value.len > 0 and value.len <= max and std.unicode.utf8ValidateSlice(value) and std.mem.indexOfScalar(u8, value, 0) == null;
}

const Delta = struct {
    role: ?[]const u8 = null,
    content: ?[]const u8 = null,
    refusal: ?[]const u8 = null,
    tool_calls: ?std.json.Value = null,
    function_call: ?std.json.Value = null,
};

const Choice = struct {
    index: usize,
    delta: Delta,
    finish_reason: ?[]const u8 = null,
};

const Chunk = struct {
    id: []const u8,
    choices: []const Choice,
};

pub const State = struct {
    allocator: std.mem.Allocator,
    output: std.ArrayList(u8) = .empty,
    saw_chunk: bool = false,
    saw_stop: bool = false,
    saw_done: bool = false,
    saw_refusal: bool = false,
    incomplete: bool = false,
    result: ?proposal.Validated = null,

    pub fn init(allocator: std.mem.Allocator) State {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *State) void {
        self.output.deinit(self.allocator);
        if (self.result) |*value| value.deinit(self.allocator);
    }

    pub fn sink(self: *State) sse.Sink {
        return .{ .context = self, .event_fn = consumeFromSink };
    }

    fn consumeFromSink(context: *anyopaque, event: sse.Event) anyerror!void {
        const self: *State = @ptrCast(@alignCast(context));
        return self.consume(event);
    }

    pub fn consume(self: *State, event: sse.Event) Error!void {
        if (!std.mem.eql(u8, event.name, "message")) return error.MalformedChunk;
        if (std.mem.eql(u8, event.data, "[DONE]")) {
            if (self.saw_done) return error.DuplicateTerminal;
            self.saw_done = true;
            if (self.saw_refusal or self.incomplete or !self.saw_stop or !self.saw_chunk or self.output.items.len == 0) return;
            self.result = proposal.parse(self.allocator, self.output.items) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.LimitExceeded => error.OutputTooLarge,
                else => error.OutputInvalid,
            };
            return;
        }
        if (self.saw_done) return error.DuplicateTerminal;
        var parsed = std.json.parseFromSlice(Chunk, self.allocator, event.data, .{ .ignore_unknown_fields = true }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidJson;
        defer parsed.deinit();
        if (parsed.value.id.len == 0 or parsed.value.choices.len != 1 or parsed.value.choices[0].index != 0) return error.MultipleChoices;
        self.saw_chunk = true;
        const choice = parsed.value.choices[0];
        if (choice.delta.tool_calls != null or choice.delta.function_call != null) return error.ToolCallRejected;
        if (choice.delta.role) |role| {
            if (!std.mem.eql(u8, role, "assistant")) return error.MalformedChunk;
        }
        if (choice.delta.refusal) |refusal| {
            if (refusal.len > 0) self.saw_refusal = true;
        }
        if (choice.delta.content) |content| {
            if (!std.unicode.utf8ValidateSlice(content) or self.output.items.len + content.len > types.max_structured_output_bytes) return error.OutputTooLarge;
            self.output.appendSlice(self.allocator, content) catch return error.OutOfMemory;
        }
        if (choice.finish_reason) |reason| {
            if (self.saw_stop or self.incomplete) return error.DuplicateTerminal;
            if (std.mem.eql(u8, reason, "stop")) self.saw_stop = true else self.incomplete = true;
        }
    }

    pub fn finish(self: *State) Error!void {
        if (!self.saw_done) return error.MissingTerminal;
        if (self.saw_refusal) return error.Refused;
        if (self.incomplete or !self.saw_stop) return error.Incomplete;
        if (self.result == null) return error.OutputInvalid;
    }

    pub fn continuationJson(self: *State) Error![]u8 {
        if (self.result == null) return error.OutputInvalid;
        var output: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer output.deinit();
        output.writer.writeAll("[{\"role\":\"assistant\",\"content\":") catch return error.OutOfMemory;
        std.json.Stringify.value(self.output.items, .{}, &output.writer) catch return error.OutOfMemory;
        output.writer.writeAll("}]") catch return error.OutOfMemory;
        if (output.writer.buffered().len > types.max_continuation_bytes) return error.OutputTooLarge;
        return output.toOwnedSlice() catch return error.OutOfMemory;
    }
};

test "Chat request keeps compatibility choices explicit and declares no tools" {
    const strict = try buildRequest(std.testing.allocator, "qwen3", .system, .json_schema, "Return one proposal.", "Inspect the host.");
    defer std.testing.allocator.free(strict);
    try std.testing.expect(std.mem.indexOf(u8, strict, "\"role\":\"system\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, strict, "\"type\":\"json_schema\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, strict, "\"strict\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, strict, "\"message\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, strict, "\"tools\"") == null);
    const object = try buildRequest(std.testing.allocator, "local", .developer, .json_object, "Return JSON.", "Inspect.");
    defer std.testing.allocator.free(object);
    try std.testing.expect(std.mem.indexOf(u8, object, "\"role\":\"developer\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, object, "\"type\":\"json_object\"") != null);
}

test "Chat stream validates one result at every transport split" {
    const first = "{\"kind\":\"command\",\"command\":\"uname -a\",\"question\":null,";
    const second = "\"explanation\":\"Inspect the kernel.\",\"destructive\":false,\"needs_sudo\":false}";
    const stream = try std.fmt.allocPrint(std.testing.allocator, "data: {{\"id\":\"chat_1\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"content\":{f}}},\"finish_reason\":null}}]}}\n\n" ++
        "data: {{\"id\":\"chat_1\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{f}}},\"finish_reason\":\"stop\"}}]}}\n\n" ++
        "data: [DONE]\n\n", .{ std.json.fmt(first, .{}), std.json.fmt(second, .{}) });
    defer std.testing.allocator.free(stream);
    var split: usize = 0;
    while (split <= stream.len) : (split += 1) {
        var adapter = State.init(std.testing.allocator);
        defer adapter.deinit();
        var parser = sse.Parser.init(std.testing.allocator);
        defer parser.deinit();
        try parser.feed(stream[0..split], adapter.sink());
        try parser.feed(stream[split..], adapter.sink());
        try parser.finish();
        try adapter.finish();
        try std.testing.expectEqualStrings("uname -a", adapter.result.?.command.?);
    }
}

test "Chat stream rejects tools multiple choices and missing done" {
    var tools = State.init(std.testing.allocator);
    defer tools.deinit();
    try std.testing.expectError(error.ToolCallRejected, tools.consume(.{ .name = "message", .data = "{\"id\":\"chat_1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[]},\"finish_reason\":null}]}" }));
    var choices = State.init(std.testing.allocator);
    defer choices.deinit();
    try std.testing.expectError(error.MultipleChoices, choices.consume(.{ .name = "message", .data = "{\"id\":\"chat_1\",\"choices\":[]}" }));
    var missing = State.init(std.testing.allocator);
    defer missing.deinit();
    try missing.consume(.{ .name = "message", .data = "{\"id\":\"chat_1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"{}\"},\"finish_reason\":\"stop\"}]}" });
    try std.testing.expectError(error.MissingTerminal, missing.finish());
}
