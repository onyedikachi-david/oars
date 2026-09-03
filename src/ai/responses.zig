//! OpenAI Responses request builder and typed streaming adapter.

const std = @import("std");
const types = @import("types.zig");
const proposal = @import("proposal.zig");
const tool_call = @import("tool_call.zig");
const sse = @import("sse.zig");

pub const endpoint_suffix = "/responses";

pub const Error = error{
    InvalidInput,
    RequestTooLarge,
    InvalidJson,
    InvalidToolName,
    MalformedKnownEvent,
    InconsistentItem,
    ToolCallRejected,
    DuplicateTerminal,
    MissingTerminal,
    MissingStructuredOutput,
    MultipleStructuredOutputs,
    Refused,
    Incomplete,
    ProviderFailed,
    OutputInvalid,
    OutputTooLarge,
    OutOfMemory,
};

pub const Terminal = enum { none, completed, refused, incomplete, failed };
const NativeToolChoice = enum { auto, force };

pub fn buildRequest(allocator: std.mem.Allocator, model: []const u8, instructions: []const u8, user_text: []const u8) Error![]u8 {
    return buildRequestWithMode(allocator, model, instructions, user_text, "[]", .structured_result);
}

pub fn buildRequestWithContinuation(allocator: std.mem.Allocator, model: []const u8, instructions: []const u8, user_text: []const u8, continuation_json: []const u8) Error![]u8 {
    return buildRequestWithMode(allocator, model, instructions, user_text, continuation_json, .structured_result);
}

pub fn buildRequestWithMode(allocator: std.mem.Allocator, model: []const u8, instructions: []const u8, user_text: []const u8, continuation_json: []const u8, mode: types.ToolMode) Error![]u8 {
    return buildRequestWithNativeChoice(allocator, model, instructions, user_text, continuation_json, mode, .auto);
}

pub fn buildCapabilityTestRequest(allocator: std.mem.Allocator, model: []const u8, instructions: []const u8, user_text: []const u8) Error![]u8 {
    return buildRequestWithNativeChoice(allocator, model, instructions, user_text, "[]", .native_function, .force);
}

fn buildRequestWithNativeChoice(allocator: std.mem.Allocator, model: []const u8, instructions: []const u8, user_text: []const u8, continuation_json: []const u8, mode: types.ToolMode, native_choice: NativeToolChoice) Error![]u8 {
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
    writer.writeAll(",\"stream\":true,\"store\":false,\"background\":false,\"include\":[\"reasoning.encrypted_content\"],\"input\":[{\"role\":\"developer\",\"content\":[{\"type\":\"input_text\",\"text\":") catch return error.OutOfMemory;
    std.json.Stringify.value(instructions, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll("}]}") catch return error.OutOfMemory;

    for (continuation.value.array.items) |item| {
        writer.writeAll(",") catch return error.OutOfMemory;
        std.json.Stringify.value(item, .{}, writer) catch return error.OutOfMemory;
    }

    writer.writeAll(",{\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":") catch return error.OutOfMemory;
    std.json.Stringify.value(user_text, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll("}]}]") catch return error.OutOfMemory;

    switch (mode) {
        .structured_result => {
            writer.writeAll(",\"text\":{\"format\":{\"type\":\"json_schema\",\"name\":") catch return error.OutOfMemory;
            std.json.Stringify.value(proposal.schema_name, .{}, writer) catch return error.OutOfMemory;
            writer.writeAll(",\"strict\":true,\"schema\":") catch return error.OutOfMemory;
            writer.writeAll(proposal.strict_schema_json) catch return error.OutOfMemory;
            writer.writeAll("}}}") catch return error.OutOfMemory;
        },
        .native_function => {
            writer.writeAll(",\"tools\":[") catch return error.OutOfMemory;
            writer.writeAll(tool_call.responses_tool_json) catch return error.OutOfMemory;
            writer.writeAll("],\"tool_choice\":") catch return error.OutOfMemory;
            switch (native_choice) {
                .auto => writer.writeAll("\"auto\"") catch return error.OutOfMemory,
                .force => writer.writeAll("{\"type\":\"function\",\"name\":\"run_server_command\"}") catch return error.OutOfMemory,
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
    instructions: []const u8,
    continuation_json: []const u8,
    call_id: []const u8,
    output: []const u8,
) Error![]u8 {
    if (!validText(model, 256) or !validText(instructions, types.max_message_bytes) or !validText(call_id, 128)) return error.InvalidInput;
    if (continuation_json.len > types.max_continuation_bytes or output.len > types.max_structured_output_bytes) return error.RequestTooLarge;

    var continuation = std.json.parseFromSlice(std.json.Value, allocator, continuation_json, .{}) catch return error.InvalidInput;
    defer continuation.deinit();
    if (continuation.value != .array) return error.InvalidInput;

    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;

    writer.writeAll("{\"model\":") catch return error.OutOfMemory;
    std.json.Stringify.value(model, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll(",\"stream\":true,\"store\":false,\"background\":false,\"include\":[\"reasoning.encrypted_content\"],\"input\":[{\"role\":\"developer\",\"content\":[{\"type\":\"input_text\",\"text\":") catch return error.OutOfMemory;
    std.json.Stringify.value(instructions, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll("}]}") catch return error.OutOfMemory;

    for (continuation.value.array.items) |item| {
        writer.writeAll(",") catch return error.OutOfMemory;
        std.json.Stringify.value(item, .{}, writer) catch return error.OutOfMemory;
    }

    writer.writeAll(",{\"type\":\"function_call_output\",\"call_id\":") catch return error.OutOfMemory;
    std.json.Stringify.value(call_id, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll(",\"output\":") catch return error.OutOfMemory;
    std.json.Stringify.value(output, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll("}],\"tools\":[") catch return error.OutOfMemory;
    writer.writeAll(tool_call.responses_tool_json) catch return error.OutOfMemory;
    writer.writeAll("],\"tool_choice\":\"none\",\"parallel_tool_calls\":false}") catch return error.OutOfMemory;

    if (writer.buffered().len > types.max_request_body_bytes) return error.RequestTooLarge;
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

fn validText(value: []const u8, max: usize) bool {
    return value.len > 0 and value.len <= max and std.unicode.utf8ValidateSlice(value) and std.mem.indexOfScalar(u8, value, 0) == null;
}

const Item = struct {
    id: []const u8,
    type: []const u8,
    call_id: ?[]const u8 = null,
    name: ?[]const u8 = null,
    arguments: ?[]const u8 = null,
};

const ItemEvent = struct {
    type: []const u8,
    item: Item,
};

const TextDelta = struct {
    type: []const u8,
    delta: []const u8,
};

const TextDone = struct {
    type: []const u8,
    text: []const u8,
};

const FunctionArgsDelta = struct {
    type: []const u8,
    item_id: []const u8,
    delta: []const u8,
};

const FunctionArgsDone = struct {
    type: []const u8,
    item_id: []const u8,
    arguments: []const u8,
};

const Envelope = struct { type: []const u8 };

const ItemIdentity = struct {
    id: []u8,
    kind: []u8,
    done: bool = false,
};

pub const State = struct {
    allocator: std.mem.Allocator,
    tool_mode: types.ToolMode = .structured_result,
    is_continuation: bool = false,
    output: std.ArrayList(u8) = .empty,
    items: std.ArrayList(ItemIdentity) = .empty,
    continuation_items: std.ArrayList([]u8) = .empty,
    continuation_bytes: usize = 0,
    terminal: Terminal = .none,
    created: bool = false,
    text_done_count: usize = 0,
    message_count: usize = 0,
    saw_refusal: bool = false,
    result: ?proposal.Validated = null,

    function_call_count: usize = 0,
    active_function_call_id: ?[]u8 = null,
    active_function_call_name: ?[]u8 = null,
    active_function_call_call_id: ?[]u8 = null,
    function_call_arguments: std.ArrayList(u8) = .empty,
    function_call_arguments_done: bool = false,
    preamble: ?[]u8 = null,

    pub fn init(allocator: std.mem.Allocator) State {
        return .{ .allocator = allocator, .tool_mode = .structured_result, .is_continuation = false };
    }

    pub fn initWithMode(allocator: std.mem.Allocator, tool_mode: types.ToolMode, is_continuation: bool) State {
        return .{ .allocator = allocator, .tool_mode = tool_mode, .is_continuation = is_continuation };
    }

    pub fn deinit(self: *State) void {
        self.output.deinit(self.allocator);
        for (self.items.items) |item| {
            self.allocator.free(item.id);
            self.allocator.free(item.kind);
        }
        self.items.deinit(self.allocator);
        for (self.continuation_items.items) |item| self.allocator.free(item);
        self.continuation_items.deinit(self.allocator);
        if (self.result) |*value| value.deinit(self.allocator);
        if (self.active_function_call_id) |v| self.allocator.free(v);
        if (self.active_function_call_name) |v| self.allocator.free(v);
        if (self.active_function_call_call_id) |v| self.allocator.free(v);
        self.function_call_arguments.deinit(self.allocator);
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
        if (std.mem.eql(u8, event.data, "[DONE]")) return;
        var envelope = std.json.parseFromSlice(Envelope, self.allocator, event.data, .{ .ignore_unknown_fields = true }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidJson;
        defer envelope.deinit();
        const event_type = envelope.value.type;
        if (!std.mem.eql(u8, event.name, "message") and !std.mem.eql(u8, event.name, event_type)) return error.MalformedKnownEvent;

        if (std.mem.eql(u8, event_type, "response.created")) {
            if (self.created or self.terminal != .none) return error.MalformedKnownEvent;
            self.created = true;
        } else if (std.mem.eql(u8, event_type, "response.output_item.added")) {
            try self.addItem(event.data);
        } else if (std.mem.eql(u8, event_type, "response.output_item.done")) {
            try self.finishItem(event.data);
        } else if (std.mem.eql(u8, event_type, "response.function_call_arguments.delta")) {
            if (self.terminal != .none or self.saw_refusal) return error.MalformedKnownEvent;
            var parsed = std.json.parseFromSlice(FunctionArgsDelta, self.allocator, event.data, .{ .ignore_unknown_fields = true }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.MalformedKnownEvent;
            defer parsed.deinit();
            if (self.active_function_call_id == null or !std.mem.eql(u8, self.active_function_call_id.?, parsed.value.item_id)) return error.InconsistentItem;
            if (self.function_call_arguments_done) return error.InconsistentItem;
            if (!std.unicode.utf8ValidateSlice(parsed.value.delta) or std.mem.indexOfScalar(u8, parsed.value.delta, 0) != null or self.function_call_arguments.items.len + parsed.value.delta.len > types.max_structured_output_bytes) return error.OutputTooLarge;
            self.function_call_arguments.appendSlice(self.allocator, parsed.value.delta) catch return error.OutOfMemory;
        } else if (std.mem.eql(u8, event_type, "response.function_call_arguments.done")) {
            var parsed = std.json.parseFromSlice(FunctionArgsDone, self.allocator, event.data, .{ .ignore_unknown_fields = true }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.MalformedKnownEvent;
            defer parsed.deinit();
            if (self.active_function_call_id == null or !std.mem.eql(u8, self.active_function_call_id.?, parsed.value.item_id)) return error.InconsistentItem;
            if (self.function_call_arguments_done) return error.InconsistentItem;
            if (!std.mem.eql(u8, parsed.value.arguments, self.function_call_arguments.items)) return error.InconsistentItem;
            self.function_call_arguments_done = true;
        } else if (std.mem.eql(u8, event_type, "response.output_text.delta")) {
            if (self.terminal != .none or self.saw_refusal) return error.MalformedKnownEvent;
            var parsed = std.json.parseFromSlice(TextDelta, self.allocator, event.data, .{ .ignore_unknown_fields = true }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.MalformedKnownEvent;
            defer parsed.deinit();
            if (!std.unicode.utf8ValidateSlice(parsed.value.delta) or self.output.items.len + parsed.value.delta.len > types.max_structured_output_bytes) return error.OutputTooLarge;
            self.output.appendSlice(self.allocator, parsed.value.delta) catch return error.OutOfMemory;
        } else if (std.mem.eql(u8, event_type, "response.output_text.done")) {
            var parsed = std.json.parseFromSlice(TextDone, self.allocator, event.data, .{ .ignore_unknown_fields = true }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.MalformedKnownEvent;
            defer parsed.deinit();
            self.text_done_count += 1;
            if (self.text_done_count > 1 and self.tool_mode == .structured_result) return error.MultipleStructuredOutputs;
            if (!std.mem.eql(u8, parsed.value.text, self.output.items)) return error.InconsistentItem;
        } else if (std.mem.startsWith(u8, event_type, "response.refusal.")) {
            if (self.terminal != .none) return error.MalformedKnownEvent;
            self.saw_refusal = true;
        } else if (std.mem.eql(u8, event_type, "response.completed")) {
            try self.complete();
        } else if (std.mem.eql(u8, event_type, "response.incomplete")) {
            try self.setTerminal(.incomplete);
        } else if (std.mem.eql(u8, event_type, "response.failed") or std.mem.eql(u8, event_type, "error")) {
            try self.setTerminal(.failed);
        }
    }

    fn addItem(self: *State, bytes: []const u8) Error!void {
        var parsed = std.json.parseFromSlice(ItemEvent, self.allocator, bytes, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.MalformedKnownEvent;
        defer parsed.deinit();
        if (!validText(parsed.value.item.id, 128) or parsed.value.item.type.len == 0) return error.MalformedKnownEvent;
        for (self.items.items) |item| if (std.mem.eql(u8, item.id, parsed.value.item.id)) return error.InconsistentItem;

        if (std.mem.eql(u8, parsed.value.item.type, "function_call")) {
            if (self.tool_mode == .structured_result or self.is_continuation) return error.ToolCallRejected;
            if (self.function_call_count > 0) return error.MultipleStructuredOutputs;
            const item_name = parsed.value.item.name orelse return error.MalformedKnownEvent;
            if (!std.mem.eql(u8, item_name, tool_call.tool_name)) return error.InvalidToolName;
            const call_id = parsed.value.item.call_id orelse return error.MalformedKnownEvent;
            if (!validText(call_id, 128)) return error.MalformedKnownEvent;

            self.active_function_call_id = try self.allocator.dupe(u8, parsed.value.item.id);
            self.active_function_call_name = try self.allocator.dupe(u8, item_name);
            self.active_function_call_call_id = try self.allocator.dupe(u8, call_id);
            self.function_call_count += 1;
        } else if (isToolType(parsed.value.item.type)) {
            return error.ToolCallRejected;
        } else if (std.mem.eql(u8, parsed.value.item.type, "message")) {
            if (self.function_call_count > 0) return error.MultipleStructuredOutputs;
            self.message_count += 1;
            if (self.message_count > 1 and self.tool_mode == .structured_result) return error.MultipleStructuredOutputs;
        } else if (!std.mem.eql(u8, parsed.value.item.type, "reasoning")) {
            return error.MalformedKnownEvent;
        }

        const id = self.allocator.dupe(u8, parsed.value.item.id) catch return error.OutOfMemory;
        errdefer self.allocator.free(id);
        const kind = self.allocator.dupe(u8, parsed.value.item.type) catch return error.OutOfMemory;
        self.items.append(self.allocator, .{ .id = id, .kind = kind }) catch return error.OutOfMemory;
    }

    fn finishItem(self: *State, bytes: []const u8) Error!void {
        var parsed = std.json.parseFromSlice(ItemEvent, self.allocator, bytes, .{ .ignore_unknown_fields = true }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.MalformedKnownEvent;
        defer parsed.deinit();
        for (self.items.items) |*item| {
            if (!std.mem.eql(u8, item.id, parsed.value.item.id)) continue;
            if (!std.mem.eql(u8, item.kind, parsed.value.item.type)) return error.InconsistentItem;
            if (item.done) return error.InconsistentItem;

            if (std.mem.eql(u8, item.kind, "function_call")) {
                const final_call_id = parsed.value.item.call_id orelse return error.MalformedKnownEvent;
                const final_name = parsed.value.item.name orelse return error.MalformedKnownEvent;
                const final_arguments = parsed.value.item.arguments orelse return error.MalformedKnownEvent;
                if (!validText(final_call_id, 128) or
                    self.active_function_call_call_id == null or !std.mem.eql(u8, self.active_function_call_call_id.?, final_call_id) or
                    self.active_function_call_name == null or !std.mem.eql(u8, self.active_function_call_name.?, final_name) or
                    !self.function_call_arguments_done or !std.mem.eql(u8, self.function_call_arguments.items, final_arguments)) return error.InconsistentItem;
            }

            if (std.mem.eql(u8, item.kind, "message") and self.tool_mode == .native_function and self.function_call_count == 0) {
                if (self.output.items.len > 0 and self.preamble == null) {
                    self.preamble = self.allocator.dupe(u8, self.output.items) catch return error.OutOfMemory;
                }
            }

            var document = std.json.parseFromSlice(std.json.Value, self.allocator, bytes, .{}) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.MalformedKnownEvent;
            defer document.deinit();
            const object = if (document.value == .object) document.value.object else return error.MalformedKnownEvent;
            const raw_item = object.get("item") orelse return error.MalformedKnownEvent;
            var encoded: std.Io.Writer.Allocating = .init(self.allocator);
            errdefer encoded.deinit();
            std.json.Stringify.value(raw_item, .{}, &encoded.writer) catch return error.OutOfMemory;
            if (self.continuation_bytes + encoded.writer.buffered().len > types.max_continuation_bytes) return error.OutputTooLarge;
            const owned = encoded.toOwnedSlice() catch return error.OutOfMemory;
            errdefer self.allocator.free(owned);
            self.continuation_items.append(self.allocator, owned) catch return error.OutOfMemory;
            self.continuation_bytes += owned.len;
            item.done = true;
            return;
        }
        return error.InconsistentItem;
    }

    fn complete(self: *State) Error!void {
        if (self.saw_refusal) {
            try self.setTerminal(.refused);
            return;
        }

        if (self.function_call_count == 1) {
            if (!self.created or !self.function_call_arguments_done or self.function_call_arguments.items.len == 0) return error.MissingStructuredOutput;
            for (self.items.items) |item| if (!item.done) return error.MissingStructuredOutput;
            var parsed_args = tool_call.parseArguments(self.allocator, self.function_call_arguments.items) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.LimitExceeded => error.OutputTooLarge,
                else => error.OutputInvalid,
            };
            errdefer parsed_args.deinit(self.allocator);

            const provider_call_id = try self.allocator.dupe(u8, self.active_function_call_call_id orelse return error.MissingStructuredOutput);
            errdefer self.allocator.free(provider_call_id);

            const tool_name_owned = try self.allocator.dupe(u8, tool_call.tool_name);
            errdefer self.allocator.free(tool_name_owned);

            const preamble = self.preamble;
            self.preamble = null;

            try self.setTerminal(.completed);
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
                .provider_call_id = provider_call_id,
                .tool_name = tool_name_owned,
                .preamble = preamble,
            };
            return;
        }

        if (!self.created or self.message_count != 1 or self.text_done_count != 1 or self.output.items.len == 0) return error.MissingStructuredOutput;

        if (self.tool_mode == .structured_result) {
            var validated = proposal.parse(self.allocator, self.output.items) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.LimitExceeded => error.OutputTooLarge,
                else => error.OutputInvalid,
            };
            errdefer validated.deinit(self.allocator);
            try self.setTerminal(.completed);
            self.result = validated;
        } else {
            const msg = self.allocator.dupe(u8, self.output.items) catch return error.OutOfMemory;
            errdefer self.allocator.free(msg);
            const exp = self.allocator.dupe(u8, self.output.items) catch return error.OutOfMemory;
            try self.setTerminal(.completed);
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
    }

    fn setTerminal(self: *State, terminal: Terminal) Error!void {
        if (self.terminal != .none) return error.DuplicateTerminal;
        self.terminal = terminal;
    }

    pub fn finish(self: *State) Error!void {
        return switch (self.terminal) {
            .none => error.MissingTerminal,
            .completed => if (self.result == null) error.MissingStructuredOutput else {},
            .refused => error.Refused,
            .incomplete => error.Incomplete,
            .failed => error.ProviderFailed,
        };
    }

    pub fn continuationJson(self: *State) Error![]u8 {
        var output: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer output.deinit();
        output.writer.writeAll("[") catch return error.OutOfMemory;
        for (self.continuation_items.items, 0..) |item, index| {
            if (index > 0) output.writer.writeAll(",") catch return error.OutOfMemory;
            output.writer.writeAll(item) catch return error.OutOfMemory;
        }
        output.writer.writeAll("]") catch return error.OutOfMemory;
        return output.toOwnedSlice() catch return error.OutOfMemory;
    }
};

fn isToolType(kind: []const u8) bool {
    const tool_types = [_][]const u8{ "shell_call", "computer_call", "mcp_call", "custom_tool_call", "local_shell_call", "web_search_call", "file_search_call", "code_interpreter_call" };
    for (tool_types) |tool| if (std.mem.eql(u8, kind, tool)) return true;
    return false;
}

test "Responses request is stateless strict streamed and tool-free in structured_result mode" {
    const body = try buildRequest(std.testing.allocator, "gpt-5", "Return one safe proposal.", "Inspect the host.");
    defer std.testing.allocator.free(body);
    try std.testing.expect(body.len <= types.max_request_body_bytes);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"store\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"background\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"stream\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "reasoning.encrypted_content") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"strict\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"message\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"tools\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "previous_response_id") == null);
}

test "Responses request declares strict run_server_command in native_function mode" {
    const body = try buildRequestWithMode(std.testing.allocator, "gpt-5", "Return one safe command.", "Inspect disk space.", "[]", .native_function);
    defer std.testing.allocator.free(body);
    try std.testing.expect(body.len <= types.max_request_body_bytes);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"run_server_command\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"parallel_tool_calls\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"tool_choice\":\"auto\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"json_schema\"") == null);
}

test "Responses rejects incomplete or changed final function-call identity" {
    var missing_call_id = State.initWithMode(std.testing.allocator, .native_function, false);
    defer missing_call_id.deinit();
    try missing_call_id.consume(.{ .name = "response.created", .data = "{\"type\":\"response.created\"}" });
    try std.testing.expectError(error.MalformedKnownEvent, missing_call_id.consume(.{
        .name = "response.output_item.added",
        .data = "{\"type\":\"response.output_item.added\",\"item\":{\"id\":\"call_missing\",\"type\":\"function_call\",\"name\":\"run_server_command\"}}",
    }));

    const args = "{\"command\":\"df -h\",\"explanation\":\"Inspect disk use.\",\"destructive\":false,\"needs_sudo\":false}";
    var changed = State.initWithMode(std.testing.allocator, .native_function, false);
    defer changed.deinit();
    try changed.consume(.{ .name = "response.created", .data = "{\"type\":\"response.created\"}" });
    try changed.consume(.{ .name = "response.output_item.added", .data = "{\"type\":\"response.output_item.added\",\"item\":{\"id\":\"call_1\",\"type\":\"function_call\",\"call_id\":\"provider_call_1\",\"name\":\"run_server_command\"}}" });
    const delta = try std.fmt.allocPrint(std.testing.allocator, "{{\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"call_1\",\"delta\":{f}}}", .{std.json.fmt(args, .{})});
    defer std.testing.allocator.free(delta);
    try changed.consume(.{ .name = "response.function_call_arguments.delta", .data = delta });
    const done = try std.fmt.allocPrint(std.testing.allocator, "{{\"type\":\"response.function_call_arguments.done\",\"item_id\":\"call_1\",\"arguments\":{f}}}", .{std.json.fmt(args, .{})});
    defer std.testing.allocator.free(done);
    try changed.consume(.{ .name = "response.function_call_arguments.done", .data = done });
    try std.testing.expectError(error.InconsistentItem, changed.consume(.{
        .name = "response.output_item.done",
        .data = "{\"type\":\"response.output_item.done\",\"item\":{\"id\":\"call_1\",\"type\":\"function_call\",\"call_id\":\"provider_call_2\",\"name\":\"run_server_command\",\"arguments\":\"{}\"}}",
    }));
}

test "Responses rejects a duplicate output_item.done event" {
    var state = State.initWithMode(std.testing.allocator, .native_function, false);
    defer state.deinit();
    try state.consume(.{ .name = "response.created", .data = "{\"type\":\"response.created\"}" });
    try state.consume(.{ .name = "response.output_item.added", .data = "{\"type\":\"response.output_item.added\",\"item\":{\"id\":\"call_1\",\"type\":\"function_call\",\"call_id\":\"provider_call_1\",\"name\":\"run_server_command\"}}" });
    const arguments = "{\"command\":\"df -h\",\"explanation\":\"Inspect disk use.\",\"destructive\":false,\"needs_sudo\":false}";
    const delta = try std.fmt.allocPrint(std.testing.allocator, "{{\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"call_1\",\"delta\":{f}}}", .{std.json.fmt(arguments, .{})});
    defer std.testing.allocator.free(delta);
    try state.consume(.{ .name = "response.function_call_arguments.delta", .data = delta });
    const done = try std.fmt.allocPrint(std.testing.allocator, "{{\"type\":\"response.function_call_arguments.done\",\"item_id\":\"call_1\",\"arguments\":{f}}}", .{std.json.fmt(arguments, .{})});
    defer std.testing.allocator.free(done);
    try state.consume(.{ .name = "response.function_call_arguments.done", .data = done });
    const final_item = try std.fmt.allocPrint(std.testing.allocator, "{{\"type\":\"response.output_item.done\",\"item\":{{\"id\":\"call_1\",\"type\":\"function_call\",\"call_id\":\"provider_call_1\",\"name\":\"run_server_command\",\"arguments\":{f}}}}}", .{std.json.fmt(arguments, .{})});
    defer std.testing.allocator.free(final_item);
    try state.consume(.{ .name = "response.output_item.done", .data = final_item });
    try std.testing.expectError(error.InconsistentItem, state.consume(.{ .name = "response.output_item.done", .data = final_item }));
}

test "Responses typed stream yields one locally validated proposal at every transport split" {
    const document = "{\"kind\":\"command\",\"command\":\"uname -a\",\"question\":null,\"explanation\":\"Inspect the kernel.\",\"destructive\":false,\"needs_sudo\":false}";
    const stream = try std.fmt.allocPrint(std.testing.allocator, "event: response.created\ndata: {{\"type\":\"response.created\",\"response\":{{\"id\":\"resp_1\"}}}}\n\n" ++
        "event: response.output_item.added\ndata: {{\"type\":\"response.output_item.added\",\"item\":{{\"id\":\"msg_1\",\"type\":\"message\"}}}}\n\n" ++
        "event: response.unknown_future_event\ndata: {{\"type\":\"response.unknown_future_event\",\"value\":1}}\n\n" ++
        "event: response.output_text.delta\ndata: {{\"type\":\"response.output_text.delta\",\"delta\":{f}}}\n\n" ++
        "event: response.output_text.done\ndata: {{\"type\":\"response.output_text.done\",\"text\":{f}}}\n\n" ++
        "event: response.output_item.done\ndata: {{\"type\":\"response.output_item.done\",\"item\":{{\"id\":\"msg_1\",\"type\":\"message\"}}}}\n\n" ++
        "event: response.completed\ndata: {{\"type\":\"response.completed\",\"response\":{{\"status\":\"completed\"}}}}\n\n", .{ std.json.fmt(document, .{}), std.json.fmt(document, .{}) });
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

test "Responses native_function mode parses function call across transport splits" {
    const args_doc = "{\"command\":\"df -h\",\"explanation\":\"Check disk capacity.\",\"destructive\":false,\"needs_sudo\":false}";
    const stream = try std.fmt.allocPrint(std.testing.allocator, "event: response.created\ndata: {{\"type\":\"response.created\",\"response\":{{\"id\":\"resp_2\"}}}}\n\n" ++
        "event: response.output_item.added\ndata: {{\"type\":\"response.output_item.added\",\"item\":{{\"id\":\"call_1\",\"type\":\"function_call\",\"call_id\":\"call_xyz\",\"name\":\"run_server_command\"}}}}\n\n" ++
        "event: response.function_call_arguments.delta\ndata: {{\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"call_1\",\"delta\":{f}}}\n\n" ++
        "event: response.function_call_arguments.done\ndata: {{\"type\":\"response.function_call_arguments.done\",\"item_id\":\"call_1\",\"arguments\":{f}}}\n\n" ++
        "event: response.output_item.done\ndata: {{\"type\":\"response.output_item.done\",\"item\":{{\"id\":\"call_1\",\"type\":\"function_call\",\"call_id\":\"call_xyz\",\"name\":\"run_server_command\",\"arguments\":{f}}}}}\n\n" ++
        "event: response.completed\ndata: {{\"type\":\"response.completed\",\"response\":{{\"status\":\"completed\"}}}}\n\n", .{ std.json.fmt(args_doc, .{}), std.json.fmt(args_doc, .{}), std.json.fmt(args_doc, .{}) });
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
        try std.testing.expectEqualStrings("call_xyz", adapter.result.?.provider_call_id.?);
        try std.testing.expectEqualStrings("run_server_command", adapter.result.?.tool_name.?);
    }
}

test "Responses native_function mode parses preamble text before function call" {
    const args_doc = "{\"command\":\"free -m\",\"explanation\":\"Check free memory.\",\"destructive\":false,\"needs_sudo\":false}";
    const stream = try std.fmt.allocPrint(std.testing.allocator, "event: response.created\ndata: {{\"type\":\"response.created\"}}\n\n" ++
        "event: response.output_item.added\ndata: {{\"type\":\"response.output_item.added\",\"item\":{{\"id\":\"msg_pre\",\"type\":\"message\"}}}}\n\n" ++
        "event: response.output_text.delta\ndata: {{\"type\":\"response.output_text.delta\",\"delta\":\"Let me check the memory usage.\"}}\n\n" ++
        "event: response.output_text.done\ndata: {{\"type\":\"response.output_text.done\",\"text\":\"Let me check the memory usage.\"}}\n\n" ++
        "event: response.output_item.done\ndata: {{\"type\":\"response.output_item.done\",\"item\":{{\"id\":\"msg_pre\",\"type\":\"message\"}}}}\n\n" ++
        "event: response.output_item.added\ndata: {{\"type\":\"response.output_item.added\",\"item\":{{\"id\":\"call_2\",\"type\":\"function_call\",\"call_id\":\"call_abc\",\"name\":\"run_server_command\"}}}}\n\n" ++
        "event: response.function_call_arguments.delta\ndata: {{\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"call_2\",\"delta\":{f}}}\n\n" ++
        "event: response.function_call_arguments.done\ndata: {{\"type\":\"response.function_call_arguments.done\",\"item_id\":\"call_2\",\"arguments\":{f}}}\n\n" ++
        "event: response.output_item.done\ndata: {{\"type\":\"response.output_item.done\",\"item\":{{\"id\":\"call_2\",\"type\":\"function_call\",\"call_id\":\"call_abc\",\"name\":\"run_server_command\",\"arguments\":{f}}}}}\n\n" ++
        "event: response.completed\ndata: {{\"type\":\"response.completed\"}}\n\n", .{ std.json.fmt(args_doc, .{}), std.json.fmt(args_doc, .{}), std.json.fmt(args_doc, .{}) });
    defer std.testing.allocator.free(stream);

    var adapter = State.initWithMode(std.testing.allocator, .native_function, false);
    defer adapter.deinit();
    var parser = sse.Parser.init(std.testing.allocator);
    defer parser.deinit();
    try parser.feed(stream, adapter.sink());
    try parser.finish();
    try adapter.finish();

    try std.testing.expectEqualStrings("free -m", adapter.result.?.command.?);
    try std.testing.expectEqualStrings("Let me check the memory usage.", adapter.result.?.preamble.?);
}

test "Responses continuation request builds function_call_output and rejects second tool call" {
    const continuation_items = "[{\"id\":\"call_1\",\"type\":\"function_call\",\"call_id\":\"call_xyz\",\"name\":\"run_server_command\"}]";
    const req = try buildContinuationRequest(std.testing.allocator, "gpt-5", "Explain the output.", continuation_items, "call_xyz", "Filesystem 100% full");
    defer std.testing.allocator.free(req);

    try std.testing.expect(std.mem.indexOf(u8, req, "\"function_call_output\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "\"call_xyz\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "Filesystem 100% full") != null);

    // If provider tries to return a tool call during continuation, State rejects it
    var cont_state = State.initWithMode(std.testing.allocator, .native_function, true);
    defer cont_state.deinit();
    try std.testing.expectError(error.ToolCallRejected, cont_state.consume(.{
        .name = "response.output_item.added",
        .data = "{\"type\":\"response.output_item.added\",\"item\":{\"id\":\"call_nested\",\"type\":\"function_call\",\"call_id\":\"call_nested\",\"name\":\"run_server_command\"}}",
    }));
}

test "Responses rejects invalid tool names duplicate tool calls and mismatched arguments" {
    var state = State.initWithMode(std.testing.allocator, .native_function, false);
    defer state.deinit();
    try state.consume(.{ .name = "response.created", .data = "{\"type\":\"response.created\"}" });
    // Unknown tool name
    try std.testing.expectError(error.InvalidToolName, state.consume(.{
        .name = "response.output_item.added",
        .data = "{\"type\":\"response.output_item.added\",\"item\":{\"id\":\"call_bad\",\"type\":\"function_call\",\"name\":\"unauthorized_tool\"}}",
    }));

    var state2 = State.initWithMode(std.testing.allocator, .native_function, false);
    defer state2.deinit();
    try state2.consume(.{ .name = "response.created", .data = "{\"type\":\"response.created\"}" });
    try state2.consume(.{ .name = "response.output_item.added", .data = "{\"type\":\"response.output_item.added\",\"item\":{\"id\":\"call_1\",\"type\":\"function_call\",\"call_id\":\"provider_call_1\",\"name\":\"run_server_command\"}}" });
    // Duplicate tool call
    try std.testing.expectError(error.MultipleStructuredOutputs, state2.consume(.{
        .name = "response.output_item.added",
        .data = "{\"type\":\"response.output_item.added\",\"item\":{\"id\":\"call_2\",\"type\":\"function_call\",\"call_id\":\"provider_call_2\",\"name\":\"run_server_command\"}}",
    }));

    var state3 = State.initWithMode(std.testing.allocator, .native_function, false);
    defer state3.deinit();
    try state3.consume(.{ .name = "response.created", .data = "{\"type\":\"response.created\"}" });
    try state3.consume(.{ .name = "response.output_item.added", .data = "{\"type\":\"response.output_item.added\",\"item\":{\"id\":\"call_1\",\"type\":\"function_call\",\"call_id\":\"provider_call_1\",\"name\":\"run_server_command\"}}" });
    try state3.consume(.{ .name = "response.function_call_arguments.delta", .data = "{\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"call_1\",\"delta\":\"{\\\"command\\\":\\\"ls\\\"}\"}" });
    // Done arguments do not match accumulated delta
    try std.testing.expectError(error.InconsistentItem, state3.consume(.{
        .name = "response.function_call_arguments.done",
        .data = "{\"type\":\"response.function_call_arguments.done\",\"item_id\":\"call_1\",\"arguments\":\"{\\\"command\\\":\\\"other\\\"}\"}",
    }));
}

test "Responses rejects tools in structured_result mode and handles missing terminal" {
    var tools = State.init(std.testing.allocator);
    defer tools.deinit();
    try std.testing.expectError(error.ToolCallRejected, tools.consume(.{ .name = "response.output_item.added", .data = "{\"type\":\"response.output_item.added\",\"item\":{\"id\":\"call_1\",\"type\":\"function_call\",\"name\":\"run_server_command\"}}" }));

    var identity = State.init(std.testing.allocator);
    defer identity.deinit();
    try identity.consume(.{ .name = "response.output_item.added", .data = "{\"type\":\"response.output_item.added\",\"item\":{\"id\":\"msg_1\",\"type\":\"message\"}}" });
    try std.testing.expectError(error.InconsistentItem, identity.consume(.{ .name = "response.output_item.done", .data = "{\"type\":\"response.output_item.done\",\"item\":{\"id\":\"other\",\"type\":\"message\"}}" }));

    var terminal = State.init(std.testing.allocator);
    defer terminal.deinit();
    try terminal.consume(.{ .name = "response.failed", .data = "{\"type\":\"response.failed\"}" });
    try std.testing.expectError(error.DuplicateTerminal, terminal.consume(.{ .name = "response.incomplete", .data = "{\"type\":\"response.incomplete\"}" }));

    var missing = State.init(std.testing.allocator);
    defer missing.deinit();
    try missing.consume(.{ .name = "response.created", .data = "{\"type\":\"response.created\"}" });
    try std.testing.expectError(error.MissingTerminal, missing.finish());
}

test "Responses retains encrypted reasoning items for stateless continuation" {
    const document = "{\"kind\":\"question\",\"command\":null,\"question\":\"Which disk?\",\"explanation\":\"The target is ambiguous.\",\"destructive\":false,\"needs_sudo\":false}";
    var state = State.init(std.testing.allocator);
    defer state.deinit();
    try state.consume(.{ .name = "response.created", .data = "{\"type\":\"response.created\"}" });
    try state.consume(.{ .name = "response.output_item.added", .data = "{\"type\":\"response.output_item.added\",\"item\":{\"id\":\"reason_1\",\"type\":\"reasoning\"}}" });
    try state.consume(.{ .name = "response.output_item.done", .data = "{\"type\":\"response.output_item.done\",\"item\":{\"id\":\"reason_1\",\"type\":\"reasoning\",\"encrypted_content\":\"opaque-fixture\"}}" });
    try state.consume(.{ .name = "response.output_item.added", .data = "{\"type\":\"response.output_item.added\",\"item\":{\"id\":\"msg_1\",\"type\":\"message\"}}" });
    const delta = try std.fmt.allocPrint(std.testing.allocator, "{{\"type\":\"response.output_text.delta\",\"delta\":{f}}}", .{std.json.fmt(document, .{})});
    defer std.testing.allocator.free(delta);
    try state.consume(.{ .name = "response.output_text.delta", .data = delta });
    const done = try std.fmt.allocPrint(std.testing.allocator, "{{\"type\":\"response.output_text.done\",\"text\":{f}}}", .{std.json.fmt(document, .{})});
    defer std.testing.allocator.free(done);
    try state.consume(.{ .name = "response.output_text.done", .data = done });
    try state.consume(.{ .name = "response.output_item.done", .data = "{\"type\":\"response.output_item.done\",\"item\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[]}}" });
    try state.consume(.{ .name = "response.completed", .data = "{\"type\":\"response.completed\"}" });
    try state.finish();
    const continuation = try state.continuationJson();
    defer std.testing.allocator.free(continuation);
    try std.testing.expect(std.mem.indexOf(u8, continuation, "opaque-fixture") != null);
    const next = try buildRequestWithContinuation(std.testing.allocator, "gpt-5", "Return one proposal.", "Continue.", continuation);
    defer std.testing.allocator.free(next);
    try std.testing.expect(std.mem.indexOf(u8, next, "opaque-fixture") != null);
    try std.testing.expect(std.mem.indexOf(u8, next, "previous_response_id") == null);
}
