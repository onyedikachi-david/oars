//! OpenAI-compatible Chat Completions request and SSE adapter.

const std = @import("std");
const types = @import("types.zig");
const provider = @import("provider.zig");
const proposal = @import("proposal.zig");
const tool_call = @import("tool_call.zig");
const sse = @import("sse.zig");

pub const endpoint_suffix = "/chat/completions";

pub const Error = error{
    InvalidInput,
    RequestTooLarge,
    InvalidJson,
    InvalidToolName,
    InconsistentItem,
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

const NativeToolChoice = enum { auto, force };

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
    return buildRequestWithMode(allocator, model, role, mode, instructions, user_text, continuation_json, .structured_result);
}

pub fn buildRequestWithMode(
    allocator: std.mem.Allocator,
    model: []const u8,
    role: ?provider.InstructionRole,
    mode: ?provider.StructuredOutput,
    instructions: []const u8,
    user_text: []const u8,
    continuation_json: []const u8,
    tool_mode: types.ToolMode,
) Error![]u8 {
    return buildRequestWithNativeChoice(allocator, model, role, mode, instructions, user_text, continuation_json, tool_mode, .auto);
}

pub fn buildCapabilityTestRequest(
    allocator: std.mem.Allocator,
    model: []const u8,
    role: ?provider.InstructionRole,
    instructions: []const u8,
    user_text: []const u8,
) Error![]u8 {
    return buildRequestWithNativeChoice(allocator, model, role, null, instructions, user_text, "[]", .native_function, .force);
}

fn buildRequestWithNativeChoice(
    allocator: std.mem.Allocator,
    model: []const u8,
    role: ?provider.InstructionRole,
    mode: ?provider.StructuredOutput,
    instructions: []const u8,
    user_text: []const u8,
    continuation_json: []const u8,
    tool_mode: types.ToolMode,
    native_choice: NativeToolChoice,
) Error![]u8 {
    if (!validText(model, 256) or !validText(instructions, types.max_message_bytes) or !validText(user_text, types.max_message_bytes)) return error.InvalidInput;
    if (continuation_json.len > types.max_continuation_bytes) return error.RequestTooLarge;
    var continuation = std.json.parseFromSlice(std.json.Value, allocator, continuation_json, .{}) catch return error.InvalidInput;
    defer continuation.deinit();
    if (continuation.value != .array) return error.InvalidInput;

    const actual_role = role orelse .system;

    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;

    writer.writeAll("{\"model\":") catch return error.OutOfMemory;
    std.json.Stringify.value(model, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll(",\"stream\":true,\"messages\":[{\"role\":") catch return error.OutOfMemory;
    std.json.Stringify.value(@tagName(actual_role), .{}, writer) catch return error.OutOfMemory;
    writer.writeAll(",\"content\":") catch return error.OutOfMemory;
    std.json.Stringify.value(instructions, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll("}") catch return error.OutOfMemory;

    for (continuation.value.array.items) |message| {
        writer.writeAll(",") catch return error.OutOfMemory;
        std.json.Stringify.value(message, .{}, writer) catch return error.OutOfMemory;
    }

    writer.writeAll(",{\"role\":\"user\",\"content\":") catch return error.OutOfMemory;
    std.json.Stringify.value(user_text, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll("}]") catch return error.OutOfMemory;

    switch (tool_mode) {
        .structured_result => {
            const actual_mode = mode orelse .json_schema;
            writer.writeAll(",\"response_format\":") catch return error.OutOfMemory;
            switch (actual_mode) {
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
        },
        .native_function => {
            writer.writeAll(",\"tools\":[") catch return error.OutOfMemory;
            writer.writeAll(tool_call.chat_tool_json) catch return error.OutOfMemory;
            writer.writeAll("],\"tool_choice\":") catch return error.OutOfMemory;
            switch (native_choice) {
                .auto => writer.writeAll("\"auto\"") catch return error.OutOfMemory,
                .force => writer.writeAll("{\"type\":\"function\",\"function\":{\"name\":\"run_server_command\"}}") catch return error.OutOfMemory,
            }
            writer.writeAll(",\"parallel_tool_calls\":false}") catch return error.OutOfMemory;
        },
    }

    if (writer.buffered().len > types.max_request_body_bytes) return error.RequestTooLarge;
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

pub fn buildContinuationRequest(
    allocator: std.mem.Allocator,
    model: []const u8,
    role: ?provider.InstructionRole,
    instructions: []const u8,
    continuation_json: []const u8,
    tool_call_id: []const u8,
    output: []const u8,
) Error![]u8 {
    if (!validText(model, 256) or !validText(instructions, types.max_message_bytes) or !validText(tool_call_id, 128)) return error.InvalidInput;
    if (continuation_json.len > types.max_continuation_bytes or output.len > types.max_structured_output_bytes) return error.RequestTooLarge;

    var continuation = std.json.parseFromSlice(std.json.Value, allocator, continuation_json, .{}) catch return error.InvalidInput;
    defer continuation.deinit();
    if (continuation.value != .array) return error.InvalidInput;

    const actual_role = role orelse .system;

    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;

    writer.writeAll("{\"model\":") catch return error.OutOfMemory;
    std.json.Stringify.value(model, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll(",\"stream\":true,\"messages\":[{\"role\":") catch return error.OutOfMemory;
    std.json.Stringify.value(@tagName(actual_role), .{}, writer) catch return error.OutOfMemory;
    writer.writeAll(",\"content\":") catch return error.OutOfMemory;
    std.json.Stringify.value(instructions, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll("}") catch return error.OutOfMemory;

    for (continuation.value.array.items) |message| {
        writer.writeAll(",") catch return error.OutOfMemory;
        std.json.Stringify.value(message, .{}, writer) catch return error.OutOfMemory;
    }

    writer.writeAll(",{\"role\":\"tool\",\"tool_call_id\":") catch return error.OutOfMemory;
    std.json.Stringify.value(tool_call_id, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll(",\"content\":") catch return error.OutOfMemory;
    std.json.Stringify.value(output, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll("}],\"tools\":[") catch return error.OutOfMemory;
    writer.writeAll(tool_call.chat_tool_json) catch return error.OutOfMemory;
    writer.writeAll("],\"tool_choice\":\"none\",\"parallel_tool_calls\":false}") catch return error.OutOfMemory;

    if (writer.buffered().len > types.max_request_body_bytes) return error.RequestTooLarge;
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

fn validText(value: []const u8, max: usize) bool {
    return value.len > 0 and value.len <= max and std.unicode.utf8ValidateSlice(value) and std.mem.indexOfScalar(u8, value, 0) == null;
}

const ToolCallFunction = struct {
    name: ?[]const u8 = null,
    arguments: ?[]const u8 = null,
};

const ToolCallDelta = struct {
    index: usize,
    id: ?[]const u8 = null,
    type: ?[]const u8 = null,
    function: ?ToolCallFunction = null,
};

const Delta = struct {
    role: ?[]const u8 = null,
    content: ?[]const u8 = null,
    refusal: ?[]const u8 = null,
    tool_calls: ?[]const ToolCallDelta = null,
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
    tool_mode: types.ToolMode = .structured_result,
    is_continuation: bool = false,
    output: std.ArrayList(u8) = .empty,
    saw_chunk: bool = false,
    saw_stop: bool = false,
    saw_tool_calls_finish: bool = false,
    saw_done: bool = false,
    saw_refusal: bool = false,
    incomplete: bool = false,
    result: ?proposal.Validated = null,

    tool_call_id: ?[]u8 = null,
    tool_call_name: ?[]u8 = null,
    tool_call_arguments: std.ArrayList(u8) = .empty,
    saw_tool_call: bool = false,
    saw_tool_call_type: bool = false,
    preamble: ?[]u8 = null,

    pub fn init(allocator: std.mem.Allocator) State {
        return .{ .allocator = allocator, .tool_mode = .structured_result, .is_continuation = false };
    }

    pub fn initWithMode(allocator: std.mem.Allocator, tool_mode: types.ToolMode, is_continuation: bool) State {
        return .{ .allocator = allocator, .tool_mode = tool_mode, .is_continuation = is_continuation };
    }

    pub fn deinit(self: *State) void {
        self.output.deinit(self.allocator);
        if (self.result) |*value| value.deinit(self.allocator);
        if (self.tool_call_id) |v| self.allocator.free(v);
        if (self.tool_call_name) |v| self.allocator.free(v);
        self.tool_call_arguments.deinit(self.allocator);
        if (self.preamble) |v| self.allocator.free(v);
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
            if (self.saw_refusal or self.incomplete or !self.saw_chunk) return;

            if (self.saw_tool_calls_finish or self.saw_tool_call) {
                if (!self.saw_tool_calls_finish or !self.saw_tool_call_type or self.tool_call_id == null or self.tool_call_name == null or self.tool_call_arguments.items.len == 0) return error.MalformedChunk;
                var parsed_args = tool_call.parseArguments(self.allocator, self.tool_call_arguments.items) catch |err| return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    error.LimitExceeded => error.OutputTooLarge,
                    else => error.OutputInvalid,
                };
                errdefer parsed_args.deinit(self.allocator);

                const call_id_owned = try self.allocator.dupe(u8, self.tool_call_id.?);
                errdefer self.allocator.free(call_id_owned);
                const tool_name_owned = try self.allocator.dupe(u8, self.tool_call_name.?);
                errdefer self.allocator.free(tool_name_owned);

                var preamble: ?[]u8 = null;
                if (self.output.items.len > 0 and self.preamble == null) {
                    preamble = try self.allocator.dupe(u8, self.output.items);
                } else if (self.preamble) |p| {
                    preamble = p;
                    self.preamble = null;
                }

                self.result = .{
                    .kind = .command,
                    .message = null,
                    .command = parsed_args.command,
                    .question = null,
                    .explanation = parsed_args.explanation,
                    .model_destructive = parsed_args.model_destructive,
                    .local_destructive = parsed_args.local_destructive,
                    .needs_sudo = parsed_args.needs_sudo,
                    .tool_mode = .native_function,
                    .provider_call_id = call_id_owned,
                    .tool_name = tool_name_owned,
                    .preamble = preamble,
                };
                return;
            }

            if (!self.saw_stop or self.output.items.len == 0) return;

            if (self.tool_mode == .structured_result) {
                self.result = proposal.parse(self.allocator, self.output.items) catch |err| return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    error.LimitExceeded => error.OutputTooLarge,
                    else => error.OutputInvalid,
                };
            } else {
                const msg = self.allocator.dupe(u8, self.output.items) catch return error.OutOfMemory;
                errdefer self.allocator.free(msg);
                const exp = self.allocator.dupe(u8, self.output.items) catch return error.OutOfMemory;
                self.result = .{
                    .kind = .message,
                    .message = msg,
                    .command = null,
                    .question = null,
                    .explanation = exp,
                    .model_destructive = false,
                    .local_destructive = false,
                    .needs_sudo = false,
                    .tool_mode = .native_function,
                };
            }
            return;
        }

        if (self.saw_done) return error.DuplicateTerminal;
        var parsed = std.json.parseFromSlice(Chunk, self.allocator, event.data, .{ .ignore_unknown_fields = true }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidJson;
        defer parsed.deinit();
        if (parsed.value.id.len == 0 or parsed.value.choices.len != 1 or parsed.value.choices[0].index != 0) return error.MultipleChoices;
        self.saw_chunk = true;
        const choice = parsed.value.choices[0];

        // Reject deprecated function_call
        if (choice.delta.function_call != null) return error.ToolCallRejected;

        if (choice.delta.tool_calls) |tool_calls_arr| {
            if (self.tool_mode == .structured_result or self.is_continuation) return error.ToolCallRejected;
            if (tool_calls_arr.len != 1) return error.ToolCallRejected;
            for (tool_calls_arr) |tc| {
                if (tc.index != 0) return error.ToolCallRejected;
                if (tc.type) |tool_type| {
                    if (!std.mem.eql(u8, tool_type, "function")) return error.ToolCallRejected;
                    self.saw_tool_call_type = true;
                }
                if (tc.id) |cid| {
                    if (!validText(cid, 128)) return error.MalformedChunk;
                    if (self.tool_call_id == null) {
                        self.tool_call_id = try self.allocator.dupe(u8, cid);
                    } else if (!std.mem.eql(u8, self.tool_call_id.?, cid)) {
                        return error.InconsistentItem;
                    }
                }
                if (tc.function) |func| {
                    if (func.name) |fname| {
                        if (!validText(fname, 64)) return error.InvalidToolName;
                        if (!std.mem.eql(u8, fname, tool_call.tool_name)) return error.InvalidToolName;
                        if (self.tool_call_name == null) {
                            self.tool_call_name = try self.allocator.dupe(u8, fname);
                        } else if (!std.mem.eql(u8, self.tool_call_name.?, fname)) {
                            return error.InconsistentItem;
                        }
                    }
                    if (func.arguments) |args| {
                        if (!std.unicode.utf8ValidateSlice(args) or std.mem.indexOfScalar(u8, args, 0) != null or self.tool_call_arguments.items.len + args.len > types.max_structured_output_bytes) return error.OutputTooLarge;
                        try self.tool_call_arguments.appendSlice(self.allocator, args);
                    }
                }
                self.saw_tool_call = true;
            }
        }

        if (choice.delta.role) |role| {
            if (!std.mem.eql(u8, role, "assistant")) return error.MalformedChunk;
        }
        if (choice.delta.refusal) |refusal| {
            if (refusal.len > 0) self.saw_refusal = true;
        }
        if (choice.delta.content) |content| {
            if (self.saw_tool_call) return error.MalformedChunk;
            if (!std.unicode.utf8ValidateSlice(content) or self.output.items.len + content.len > types.max_structured_output_bytes) return error.OutputTooLarge;
            self.output.appendSlice(self.allocator, content) catch return error.OutOfMemory;
        }
        if (choice.finish_reason) |reason| {
            if (self.saw_stop or self.saw_tool_calls_finish or self.incomplete) return error.DuplicateTerminal;
            if (std.mem.eql(u8, reason, "tool_calls")) {
                if (!self.saw_tool_call) return error.MalformedChunk;
                self.saw_tool_calls_finish = true;
            } else if (std.mem.eql(u8, reason, "stop")) {
                self.saw_stop = true;
            } else {
                self.incomplete = true;
            }
        }
    }

    pub fn finish(self: *State) Error!void {
        if (!self.saw_done) return error.MissingTerminal;
        if (self.saw_refusal) return error.Refused;
        if (self.incomplete or (!self.saw_stop and !self.saw_tool_calls_finish)) return error.Incomplete;
        if (self.result == null) return error.OutputInvalid;
    }

    pub fn continuationJson(self: *State) Error![]u8 {
        if (self.result == null) return error.OutputInvalid;
        var output: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer output.deinit();

        if (self.saw_tool_call) {
            output.writer.writeAll("[{\"role\":\"assistant\",\"content\":") catch return error.OutOfMemory;
            if (self.result.?.preamble) |p| {
                std.json.Stringify.value(p, .{}, &output.writer) catch return error.OutOfMemory;
            } else {
                output.writer.writeAll("null") catch return error.OutOfMemory;
            }
            output.writer.writeAll(",\"tool_calls\":[{\"id\":") catch return error.OutOfMemory;
            std.json.Stringify.value(self.result.?.provider_call_id orelse "", .{}, &output.writer) catch return error.OutOfMemory;
            output.writer.writeAll(",\"type\":\"function\",\"function\":{\"name\":\"run_server_command\",\"arguments\":") catch return error.OutOfMemory;
            std.json.Stringify.value(self.tool_call_arguments.items, .{}, &output.writer) catch return error.OutOfMemory;
            output.writer.writeAll("}}]}]") catch return error.OutOfMemory;
        } else {
            output.writer.writeAll("[{\"role\":\"assistant\",\"content\":") catch return error.OutOfMemory;
            std.json.Stringify.value(self.output.items, .{}, &output.writer) catch return error.OutOfMemory;
            output.writer.writeAll("}]") catch return error.OutOfMemory;
        }

        if (output.writer.buffered().len > types.max_continuation_bytes) return error.OutputTooLarge;
        return output.toOwnedSlice() catch return error.OutOfMemory;
    }
};

test "Chat request keeps compatibility choices explicit and declares no tools in structured_result" {
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

test "Chat request declares strict tool and parallel_tool_calls false in native_function" {
    const req = try buildRequestWithMode(std.testing.allocator, "qwen3", .system, null, "Propose command.", "Inspect disk.", "[]", .native_function);
    defer std.testing.allocator.free(req);
    try std.testing.expect(std.mem.indexOf(u8, req, "\"run_server_command\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "\"parallel_tool_calls\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "\"tool_choice\":\"auto\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "\"response_format\"") == null);
}

test "Chat rejects native tool calls without complete provider identity" {
    var missing_id = State.initWithMode(std.testing.allocator, .native_function, false);
    defer missing_id.deinit();
    try missing_id.consume(.{ .name = "message", .data = "{\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"type\":\"function\",\"function\":{\"name\":\"run_server_command\",\"arguments\":\"{\\\"command\\\":\\\"df -h\\\",\\\"explanation\\\":\\\"Inspect disk use.\\\",\\\"destructive\\\":false,\\\"needs_sudo\\\":false}\"}}]},\"finish_reason\":\"tool_calls\"}]}" });
    try std.testing.expectError(error.MalformedChunk, missing_id.consume(.{ .name = "message", .data = "[DONE]" }));

    var missing_type = State.initWithMode(std.testing.allocator, .native_function, false);
    defer missing_type.deinit();
    try missing_type.consume(.{ .name = "message", .data = "{\"id\":\"chatcmpl-2\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_2\",\"function\":{\"name\":\"run_server_command\",\"arguments\":\"{\\\"command\\\":\\\"df -h\\\",\\\"explanation\\\":\\\"Inspect disk use.\\\",\\\"destructive\\\":false,\\\"needs_sudo\\\":false}\"}}]},\"finish_reason\":\"tool_calls\"}]}" });
    try std.testing.expectError(error.MalformedChunk, missing_type.consume(.{ .name = "message", .data = "[DONE]" }));
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

test "Chat stream parses native tool call deltas across transport splits" {
    const arg1 = "{\"command\":\"df -h\",\"explanation\":\"Check disk capacity.\",";
    const arg2 = "\"destructive\":false,\"needs_sudo\":false}";
    const stream = try std.fmt.allocPrint(std.testing.allocator, "data: {{\"id\":\"chat_2\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"tool_calls\":[{{\"index\":0,\"id\":\"call_chat_1\",\"type\":\"function\",\"function\":{{\"name\":\"run_server_command\",\"arguments\":{f}}}}}]}},\"finish_reason\":null}}]}}\n\n" ++
        "data: {{\"id\":\"chat_2\",\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"arguments\":{f}}}}}]}},\"finish_reason\":null}}]}}\n\n" ++
        "data: {{\"id\":\"chat_2\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"tool_calls\"}}]}}\n\n" ++
        "data: [DONE]\n\n", .{ std.json.fmt(arg1, .{}), std.json.fmt(arg2, .{}) });
    defer std.testing.allocator.free(stream);

    var split: usize = 0;
    while (split <= stream.len) : (split += 1) {
        var adapter = State.initWithMode(std.testing.allocator, .native_function, false);
        defer adapter.deinit();
        var parser = sse.Parser.init(std.testing.allocator);
        defer parser.deinit();
        try parser.feed(stream[0..split], adapter.sink());
        try parser.feed(stream[split..], adapter.sink());
        try parser.finish();
        try adapter.finish();
        try std.testing.expectEqualStrings("df -h", adapter.result.?.command.?);
        try std.testing.expectEqualStrings("call_chat_1", adapter.result.?.provider_call_id.?);
        try std.testing.expectEqualStrings("run_server_command", adapter.result.?.tool_name.?);
    }
}

test "Chat stream parses preamble text before tool call" {
    const stream =
        "data: {\"id\":\"chat_pre\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Inspecting disk...\"},\"finish_reason\":null}]}\n\n" ++
        "data: {\"id\":\"chat_pre\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_pre\",\"type\":\"function\",\"function\":{\"name\":\"run_server_command\",\"arguments\":\"{\\\"command\\\":\\\"df -h\\\",\\\"explanation\\\":\\\"Disk\\\",\\\"destructive\\\":false,\\\"needs_sudo\\\":false}\"}}]},\"finish_reason\":null}]}\n\n" ++
        "data: {\"id\":\"chat_pre\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n" ++
        "data: [DONE]\n\n";

    var adapter = State.initWithMode(std.testing.allocator, .native_function, false);
    defer adapter.deinit();
    var parser = sse.Parser.init(std.testing.allocator);
    defer parser.deinit();
    try parser.feed(stream, adapter.sink());
    try parser.finish();
    try adapter.finish();

    try std.testing.expectEqualStrings("df -h", adapter.result.?.command.?);
    try std.testing.expectEqualStrings("Inspecting disk...", adapter.result.?.preamble.?);
}

test "Chat continuation request sends role tool message and rejects second tool call" {
    const continuation_items = "[{\"role\":\"assistant\",\"content\":null,\"tool_calls\":[{\"id\":\"call_chat_1\",\"type\":\"function\",\"function\":{\"name\":\"run_server_command\",\"arguments\":\"{}\"}}]}]";
    const req = try buildContinuationRequest(std.testing.allocator, "qwen3", .system, "Explain output.", continuation_items, "call_chat_1", "Filesystem 85% full");
    defer std.testing.allocator.free(req);

    try std.testing.expect(std.mem.indexOf(u8, req, "\"role\":\"tool\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "\"tool_call_id\":\"call_chat_1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "Filesystem 85% full") != null);

    var cont_state = State.initWithMode(std.testing.allocator, .native_function, true);
    defer cont_state.deinit();
    try std.testing.expectError(error.ToolCallRejected, cont_state.consume(.{
        .name = "message",
        .data = "{\"id\":\"chat_nest\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c2\",\"function\":{\"name\":\"run_server_command\",\"arguments\":\"{}\"}}]},\"finish_reason\":null}]}",
    }));
}

test "Chat stream rejects tools in structured mode, deprecated function_call, index > 0, and multiple choices" {
    var tools = State.init(std.testing.allocator);
    defer tools.deinit();
    try std.testing.expectError(error.ToolCallRejected, tools.consume(.{ .name = "message", .data = "{\"id\":\"chat_1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"run_server_command\",\"arguments\":\"{}\"}}]},\"finish_reason\":null}]}" }));

    var dep_fn = State.initWithMode(std.testing.allocator, .native_function, false);
    defer dep_fn.deinit();
    try std.testing.expectError(error.ToolCallRejected, dep_fn.consume(.{ .name = "message", .data = "{\"id\":\"chat_1\",\"choices\":[{\"index\":0,\"delta\":{\"function_call\":{}},\"finish_reason\":null}]}" }));

    var index_gt = State.initWithMode(std.testing.allocator, .native_function, false);
    defer index_gt.deinit();
    try std.testing.expectError(error.ToolCallRejected, index_gt.consume(.{ .name = "message", .data = "{\"id\":\"chat_1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"c2\",\"function\":{\"name\":\"run_server_command\",\"arguments\":\"{}\"}}]},\"finish_reason\":null}]}" }));

    var choices = State.init(std.testing.allocator);
    defer choices.deinit();
    try std.testing.expectError(error.MultipleChoices, choices.consume(.{ .name = "message", .data = "{\"id\":\"chat_1\",\"choices\":[]}" }));

    var missing = State.init(std.testing.allocator);
    defer missing.deinit();
    try missing.consume(.{ .name = "message", .data = "{\"id\":\"chat_1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"{}\"},\"finish_reason\":\"stop\"}]}" });
    try std.testing.expectError(error.MissingTerminal, missing.finish());
}
