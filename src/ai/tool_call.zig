//! Strict provider-neutral tool call schema and argument parsing for Spec 19.
//!
//! The only tool declared to models is `run_server_command`. This module
//! defines the strict schema and validates function arguments under Oars bounds.

const std = @import("std");
const types = @import("types.zig");
const proposal = @import("proposal.zig");

pub const tool_name = "run_server_command";
pub const tool_description = "Propose one shell command to inspect or change the selected Linux server. The command is reviewed by the operator before execution.";

pub const strict_parameters_schema_json =
    \\{"type":"object","additionalProperties":false,"properties":{"command":{"type":"string","description":"The exact bash/sh command line to run on the target server."},"explanation":{"type":"string","description":"Human-readable explanation of why this command is proposed."},"destructive":{"type":"boolean","description":"True if this command mutates state, deletes data, restarts services, or could disrupt operations."},"needs_sudo":{"type":"boolean","description":"True if this command requires elevated root/sudo privileges."}},"required":["command","explanation","destructive","needs_sudo"]}
;

pub const responses_tool_json =
    \\{"type":"function","name":"run_server_command","description":"Propose one shell command to inspect or change the selected Linux server. The command is reviewed by the operator before execution.","strict":true,"parameters":
    ++ strict_parameters_schema_json ++ "}"
;

pub const chat_tool_json =
    \\{"type":"function","function":{"name":"run_server_command","description":"Propose one shell command to inspect or change the selected Linux server. The command is reviewed by the operator before execution.","strict":true,"parameters":
    ++ strict_parameters_schema_json ++ "}}"
;

pub const Error = error{
    InvalidJson,
    InvalidToolName,
    InvalidArguments,
    InvalidText,
    LimitExceeded,
    OutOfMemory,
};

pub const RawArguments = struct {
    command: []const u8,
    explanation: []const u8,
    destructive: bool,
    needs_sudo: bool,
};

pub const ParsedArguments = struct {
    command: []u8,
    explanation: []u8,
    model_destructive: bool,
    local_destructive: bool,
    needs_sudo: bool,

    pub fn deinit(self: *ParsedArguments, allocator: std.mem.Allocator) void {
        allocator.free(self.command);
        allocator.free(self.explanation);
    }
};

pub const ToolCall = struct {
    id: []const u8,
    provider_call_id: []const u8,
    name: []const u8,
    command: []u8,
    explanation: []u8,
    model_destructive: bool,
    local_destructive: bool,
    needs_sudo: bool,

    pub fn deinit(self: *ToolCall, allocator: std.mem.Allocator) void {
        allocator.free(self.command);
        allocator.free(self.explanation);
        if (self.id.len > 0) allocator.free(self.id);
        if (self.provider_call_id.len > 0) allocator.free(self.provider_call_id);
    }
};

pub const AssistantMessage = struct {
    message: []u8,
    explanation: []u8,

    pub fn deinit(self: *AssistantMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.message);
        allocator.free(self.explanation);
    }
};

pub const AssistantQuestion = struct {
    question: []u8,
    explanation: []u8,

    pub fn deinit(self: *AssistantQuestion, allocator: std.mem.Allocator) void {
        allocator.free(self.question);
        allocator.free(self.explanation);
    }
};

pub const ProviderResult = union(enum) {
    message: AssistantMessage,
    question: AssistantQuestion,
    tool_call: ToolCall,

    pub fn deinit(self: *ProviderResult, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .message => |*m| m.deinit(allocator),
            .question => |*q| q.deinit(allocator),
            .tool_call => |*t| t.deinit(allocator),
        }
    }
};

fn validText(value: []const u8, max: usize, allow_empty: bool) bool {
    if ((!allow_empty and value.len == 0) or value.len > max) return false;
    return std.unicode.utf8ValidateSlice(value) and std.mem.indexOfScalar(u8, value, 0) == null;
}

pub fn parseArguments(allocator: std.mem.Allocator, json_bytes: []const u8) Error!ParsedArguments {
    if (json_bytes.len == 0 or json_bytes.len > types.max_structured_output_bytes or !std.unicode.utf8ValidateSlice(json_bytes)) return error.LimitExceeded;
    var parsed = std.json.parseFromSlice(RawArguments, allocator, json_bytes, .{ .allocate = .alloc_always }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidJson;
    defer parsed.deinit();

    const raw = parsed.value;
    if (!validText(raw.command, types.max_command_bytes, false)) return if (raw.command.len > types.max_command_bytes) error.LimitExceeded else error.InvalidText;
    if (!validText(raw.explanation, types.max_explanation_bytes, true)) return if (raw.explanation.len > types.max_explanation_bytes) error.LimitExceeded else error.InvalidText;

    const command = allocator.dupe(u8, raw.command) catch return error.OutOfMemory;
    errdefer allocator.free(command);
    const explanation = allocator.dupe(u8, raw.explanation) catch return error.OutOfMemory;

    return .{
        .command = command,
        .explanation = explanation,
        .model_destructive = raw.destructive,
        .local_destructive = proposal.isDestructive(raw.command),
        .needs_sudo = raw.needs_sudo,
    };
}

pub fn parseToolCall(
    allocator: std.mem.Allocator,
    id: []const u8,
    provider_call_id: []const u8,
    name: []const u8,
    json_arguments: []const u8,
) Error!ToolCall {
    if (!std.mem.eql(u8, name, tool_name)) return error.InvalidToolName;
    var parsed = try parseArguments(allocator, json_arguments);
    errdefer parsed.deinit(allocator);

    const owned_id = allocator.dupe(u8, id) catch return error.OutOfMemory;
    errdefer allocator.free(owned_id);
    const owned_provider_call_id = allocator.dupe(u8, provider_call_id) catch return error.OutOfMemory;

    return .{
        .id = owned_id,
        .provider_call_id = owned_provider_call_id,
        .name = tool_name,
        .command = parsed.command,
        .explanation = parsed.explanation,
        .model_destructive = parsed.model_destructive,
        .local_destructive = parsed.local_destructive,
        .needs_sudo = parsed.needs_sudo,
    };
}

test "strict tool argument parser accepts valid arguments" {
    const allocator = std.testing.allocator;
    const json =
        \\{"command":"uname -a","explanation":"Check kernel version.","destructive":false,"needs_sudo":false}
    ;
    var parsed = try parseArguments(allocator, json);
    defer parsed.deinit(allocator);

    try std.testing.expectEqualStrings("uname -a", parsed.command);
    try std.testing.expectEqualStrings("Check kernel version.", parsed.explanation);
    try std.testing.expect(!parsed.model_destructive);
    try std.testing.expect(!parsed.local_destructive);
    try std.testing.expect(!parsed.needs_sudo);
}

test "local destructive classifier overrides false model assessment for rm" {
    const allocator = std.testing.allocator;
    const json =
        \\{"command":"rm -rf /var/log/test","explanation":"Clean test logs.","destructive":false,"needs_sudo":true}
    ;
    var parsed = try parseArguments(allocator, json);
    defer parsed.deinit(allocator);

    try std.testing.expect(!parsed.model_destructive);
    try std.testing.expect(parsed.local_destructive);
    try std.testing.expect(parsed.needs_sudo);
}

test "strict tool argument parser rejects extra fields, nulls, and NUL bytes" {
    const allocator = std.testing.allocator;
    // Extra field
    try std.testing.expectError(error.InvalidJson, parseArguments(allocator, "{\"command\":\"df -h\",\"explanation\":\"Disk check\",\"destructive\":false,\"needs_sudo\":false,\"extra\":1}"));
    // Missing required field
    try std.testing.expectError(error.InvalidJson, parseArguments(allocator, "{\"command\":\"df -h\",\"explanation\":\"Disk check\",\"destructive\":false}"));
    // NUL byte
    try std.testing.expectError(error.InvalidText, parseArguments(allocator, "{\"command\":\"df\\u0000-h\",\"explanation\":\"Disk check\",\"destructive\":false,\"needs_sudo\":false}"));
    // Empty command
    try std.testing.expectError(error.InvalidText, parseArguments(allocator, "{\"command\":\"\",\"explanation\":\"Disk check\",\"destructive\":false,\"needs_sudo\":false}"));
}

test "parseToolCall rejects unknown tool names" {
    const allocator = std.testing.allocator;
    const json = "{\"command\":\"ls\",\"explanation\":\"List\",\"destructive\":false,\"needs_sudo\":false}";
    try std.testing.expectError(error.InvalidToolName, parseToolCall(allocator, "aitool-1", "call_1", "execute_command", json));
    try std.testing.expectError(error.InvalidToolName, parseToolCall(allocator, "aitool-1", "call_1", "bash", json));
    var tool = try parseToolCall(allocator, "aitool-1", "call_1", "run_server_command", json);
    defer tool.deinit(allocator);
    try std.testing.expectEqualStrings("run_server_command", tool.name);
    try std.testing.expectEqualStrings("aitool-1", tool.id);
    try std.testing.expectEqualStrings("call_1", tool.provider_call_id);
}
