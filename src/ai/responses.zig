//! OpenAI Responses request builder and typed streaming adapter.

const std = @import("std");
const types = @import("types.zig");
const proposal = @import("proposal.zig");
const sse = @import("sse.zig");

pub const endpoint_suffix = "/responses";

pub const Error = error{
    InvalidInput,
    RequestTooLarge,
    InvalidJson,
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

pub fn buildRequest(allocator: std.mem.Allocator, model: []const u8, instructions: []const u8, user_text: []const u8) Error![]u8 {
    return buildRequestWithContinuation(allocator, model, instructions, user_text, "[]");
}

pub fn buildRequestWithContinuation(allocator: std.mem.Allocator, model: []const u8, instructions: []const u8, user_text: []const u8, continuation_json: []const u8) Error![]u8 {
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
    writer.writeAll("}]}],\"text\":{\"format\":{\"type\":\"json_schema\",\"name\":") catch return error.OutOfMemory;
    std.json.Stringify.value(proposal.schema_name, .{}, writer) catch return error.OutOfMemory;
    writer.writeAll(",\"strict\":true,\"schema\":") catch return error.OutOfMemory;
    writer.writeAll(proposal.strict_schema_json) catch return error.OutOfMemory;
    writer.writeAll("}}}") catch return error.OutOfMemory;
    if (writer.buffered().len > types.max_request_body_bytes) return error.RequestTooLarge;
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

fn validText(value: []const u8, max: usize) bool {
    return value.len > 0 and value.len <= max and std.unicode.utf8ValidateSlice(value) and std.mem.indexOfScalar(u8, value, 0) == null;
}

const Item = struct {
    id: []const u8,
    type: []const u8,
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

const Envelope = struct { type: []const u8 };

const ItemIdentity = struct {
    id: []u8,
    kind: []u8,
};

pub const State = struct {
    allocator: std.mem.Allocator,
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

    pub fn init(allocator: std.mem.Allocator) State {
        return .{ .allocator = allocator };
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
            if (self.text_done_count > 1) return error.MultipleStructuredOutputs;
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
        // Unknown bounded event types are ignored. The known terminal and
        // structured-output invariants are still required by finish().
    }

    fn addItem(self: *State, bytes: []const u8) Error!void {
        var parsed = std.json.parseFromSlice(ItemEvent, self.allocator, bytes, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.MalformedKnownEvent;
        defer parsed.deinit();
        if (parsed.value.item.id.len == 0 or parsed.value.item.type.len == 0) return error.MalformedKnownEvent;
        for (self.items.items) |item| if (std.mem.eql(u8, item.id, parsed.value.item.id)) return error.InconsistentItem;
        if (isToolType(parsed.value.item.type)) return error.ToolCallRejected;
        if (!std.mem.eql(u8, parsed.value.item.type, "message") and !std.mem.eql(u8, parsed.value.item.type, "reasoning")) return error.MalformedKnownEvent;
        if (std.mem.eql(u8, parsed.value.item.type, "message")) {
            self.message_count += 1;
            if (self.message_count > 1) return error.MultipleStructuredOutputs;
        }
        const id = self.allocator.dupe(u8, parsed.value.item.id) catch return error.OutOfMemory;
        errdefer self.allocator.free(id);
        const kind = self.allocator.dupe(u8, parsed.value.item.type) catch return error.OutOfMemory;
        self.items.append(self.allocator, .{ .id = id, .kind = kind }) catch return error.OutOfMemory;
    }

    fn finishItem(self: *State, bytes: []const u8) Error!void {
        var parsed = std.json.parseFromSlice(ItemEvent, self.allocator, bytes, .{ .ignore_unknown_fields = true }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.MalformedKnownEvent;
        defer parsed.deinit();
        for (self.items.items) |item| {
            if (!std.mem.eql(u8, item.id, parsed.value.item.id)) continue;
            if (!std.mem.eql(u8, item.kind, parsed.value.item.type)) return error.InconsistentItem;
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
            return;
        }
        return error.InconsistentItem;
    }

    fn complete(self: *State) Error!void {
        if (self.saw_refusal) {
            try self.setTerminal(.refused);
            return;
        }
        if (!self.created or self.message_count != 1 or self.text_done_count != 1 or self.output.items.len == 0) return error.MissingStructuredOutput;
        var validated = proposal.parse(self.allocator, self.output.items) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.LimitExceeded => error.OutputTooLarge,
            else => error.OutputInvalid,
        };
        errdefer validated.deinit(self.allocator);
        try self.setTerminal(.completed);
        self.result = validated;
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
    const tool_types = [_][]const u8{ "function_call", "shell_call", "computer_call", "mcp_call", "custom_tool_call", "local_shell_call", "web_search_call", "file_search_call", "code_interpreter_call" };
    for (tool_types) |tool| if (std.mem.eql(u8, kind, tool)) return true;
    return false;
}

test "Responses request is stateless strict streamed and tool-free" {
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

test "Responses rejects tools malformed identity duplicate terminals and missing terminal" {
    var tools = State.init(std.testing.allocator);
    defer tools.deinit();
    try std.testing.expectError(error.ToolCallRejected, tools.consume(.{ .name = "response.output_item.added", .data = "{\"type\":\"response.output_item.added\",\"item\":{\"id\":\"call_1\",\"type\":\"function_call\"}}" }));

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
