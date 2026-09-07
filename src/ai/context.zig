//! Asynchronous context-operation registry and cache for Spec 11.

const std = @import("std");
const sessions = @import("../sessions.zig");
const types = @import("types.zig");
const events = @import("events.zig");

pub const cache_ttl_ms: i64 = 5_000;
pub const max_operations: usize = 32;
pub const max_snapshots: usize = 16;

pub const State = enum {
    queued,
    running,
    cancel_requested,
    ready,
    failed,
    canceled,

    pub fn terminal(self: State) bool {
        return self == .ready or self == .failed or self == .canceled;
    }
};

pub const Snapshot = struct {
    server_id: []const u8,
    context_json: []const u8,
    partial: bool,
    updated_at_ms: i64,

    pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.server_id);
        allocator.free(self.context_json);
    }
};

pub const GetResult = struct {
    snapshot: Snapshot,
    stale: bool,
};

pub const Operation = struct {
    allocator: std.mem.Allocator,
    id: []const u8,
    server_id: []const u8,
    state: State,
    created_at_ms: i64,
    outcome: ?*sessions.AiContextOutcome,
    stream: events.Stream,

    fn deinit(self: *Operation) void {
        if (self.outcome) |outcome| {
            if (outcome.abandon()) destroyOutcome(self.allocator, outcome);
        }
        self.stream.deinit();
        self.allocator.free(self.id);
        self.allocator.free(self.server_id);
        self.allocator.destroy(self);
    }
};

pub const Admission = struct {
    operation: *Operation,
    admitted: bool,
    state: State,
};

pub const Error = error{
    InvalidOperationId,
    InvalidServerId,
    OperationConflict,
    Busy,
    LimitExceeded,
    NotFound,
    OutOfMemory,
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    operations: std.ArrayList(*Operation) = .empty,
    snapshots: std.ArrayList(Snapshot) = .empty,

    pub fn deinit(self: *Registry) void {
        lockSpin(&self.mutex);
        for (self.operations.items) |operation| operation.deinit();
        self.operations.deinit(self.allocator);
        for (self.snapshots.items) |*snapshot| snapshot.deinit(self.allocator);
        self.snapshots.deinit(self.allocator);
        self.mutex.unlock();
    }

    pub fn admit(self: *Registry, operation_id: []const u8, server_id: []const u8, outcome: *sessions.AiContextOutcome, now_ms: i64) Error!Admission {
        if (!types.validOperationId(operation_id)) return error.InvalidOperationId;
        if (server_id.len == 0 or server_id.len > 128) return error.InvalidServerId;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.operations.items) |operation| {
            if (std.mem.eql(u8, operation.id, operation_id)) {
                if (!std.mem.eql(u8, operation.server_id, server_id)) return error.OperationConflict;
                return .{ .operation = operation, .admitted = false, .state = operation.state };
            }
            if (!operation.state.terminal() and std.mem.eql(u8, operation.server_id, server_id)) return error.Busy;
        }
        try self.makeRoomLocked();
        const operation = self.allocator.create(Operation) catch return error.OutOfMemory;
        errdefer self.allocator.destroy(operation);
        const id = self.allocator.dupe(u8, operation_id) catch return error.OutOfMemory;
        errdefer self.allocator.free(id);
        const server = self.allocator.dupe(u8, server_id) catch return error.OutOfMemory;
        errdefer self.allocator.free(server);
        var stream = events.Stream.init(self.allocator, operation_id) catch return error.OutOfMemory;
        errdefer stream.deinit();
        var payload_buf: [96]u8 = undefined;
        const payload = std.fmt.bufPrint(&payload_buf, "{{\"state\":\"running\",\"started_at_ms\":{d}}}", .{now_ms}) catch return error.OutOfMemory;
        stream.append("context.refresh_started", payload) catch return error.OutOfMemory;
        operation.* = .{
            .allocator = self.allocator,
            .id = id,
            .server_id = server,
            .state = .running,
            .created_at_ms = now_ms,
            .outcome = outcome,
            .stream = stream,
        };
        self.operations.append(self.allocator, operation) catch return error.OutOfMemory;
        return .{ .operation = operation, .admitted = true, .state = operation.state };
    }

    fn makeRoomLocked(self: *Registry) Error!void {
        if (self.operations.items.len < max_operations) return;
        for (self.operations.items, 0..) |operation, index| {
            if (!operation.state.terminal()) continue;
            _ = self.operations.orderedRemove(index);
            operation.deinit();
            return;
        }
        return error.LimitExceeded;
    }

    pub fn failAdmission(self: *Registry, operation_id: []const u8, code: types.ErrorCode, message: []const u8, now_ms: i64) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const operation = self.findLocked(operation_id) orelse return;
        if (operation.state.terminal()) return;
        operation.state = .failed;
        if (operation.outcome) |outcome| {
            operation.outcome = null;
            destroyOutcome(self.allocator, outcome);
        }
        appendFailure(operation, code, message, now_ms);
    }

    pub fn requestCancel(self: *Registry, operation_id: []const u8, now_ms: i64) Error!struct { server_id: []u8, queue: bool, state: State } {
        if (!types.validOperationId(operation_id)) return error.InvalidOperationId;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const operation = self.findLocked(operation_id) orelse return error.NotFound;
        const server_id = self.allocator.dupe(u8, operation.server_id) catch return error.OutOfMemory;
        if (operation.state.terminal() or operation.state == .cancel_requested) return .{ .server_id = server_id, .queue = false, .state = operation.state };
        operation.state = .cancel_requested;
        var payload_buf: [96]u8 = undefined;
        const payload = std.fmt.bufPrint(&payload_buf, "{{\"state\":\"cancel_requested\",\"requested_at_ms\":{d}}}", .{now_ms}) catch "{\"state\":\"cancel_requested\"}";
        operation.stream.append("context.cancel_requested", payload) catch {};
        return .{ .server_id = server_id, .queue = true, .state = .cancel_requested };
    }

    /// Observes worker completion and publishes exactly one terminal event.
    /// Returns true when the operation changed state.
    pub fn finalize(self: *Registry, operation_id: []const u8, context_json: ?[]const u8, partial: bool, code: ?types.ErrorCode, message: []const u8, now_ms: i64) Error!bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const operation = self.findLocked(operation_id) orelse return error.NotFound;
        if (operation.state.terminal()) return false;
        const outcome = operation.outcome orelse return false;
        var worker = outcome.snapshot(self.allocator) catch return error.OutOfMemory;
        defer worker.deinit(self.allocator);
        if (!worker.done) return false;
        operation.outcome = null;
        if (outcome.abandon()) destroyOutcome(self.allocator, outcome);

        if (worker.canceled) {
            operation.state = .canceled;
            var payload_buf: [96]u8 = undefined;
            const payload = std.fmt.bufPrint(&payload_buf, "{{\"state\":\"canceled\",\"finished_at_ms\":{d}}}", .{now_ms}) catch "{\"state\":\"canceled\"}";
            operation.stream.append("context.canceled", payload) catch {};
            return true;
        }
        if (context_json) |json_value| {
            try self.putSnapshotLocked(operation.server_id, json_value, partial, now_ms);
            operation.state = .ready;
            var payload_buf: [128]u8 = undefined;
            const payload = std.fmt.bufPrint(&payload_buf, "{{\"state\":\"ready\",\"partial\":{s},\"updated_at_ms\":{d}}}", .{ if (partial) "true" else "false", now_ms }) catch "{\"state\":\"ready\"}";
            operation.stream.append("context.ready", payload) catch {};
            return true;
        }
        operation.state = .failed;
        appendFailure(operation, code orelse if (worker.disconnected) .not_connected else .conflict, if (message.len > 0) message else worker.message, now_ms);
        return true;
    }

    fn putSnapshotLocked(self: *Registry, server_id: []const u8, context_json: []const u8, partial: bool, now_ms: i64) Error!void {
        const server_copy = self.allocator.dupe(u8, server_id) catch return error.OutOfMemory;
        errdefer self.allocator.free(server_copy);
        const json_copy = self.allocator.dupe(u8, context_json) catch return error.OutOfMemory;
        errdefer self.allocator.free(json_copy);
        const snapshot = Snapshot{ .server_id = server_copy, .context_json = json_copy, .partial = partial, .updated_at_ms = now_ms };
        for (self.snapshots.items, 0..) |*current, index| {
            if (!std.mem.eql(u8, current.server_id, server_id)) continue;
            var old = self.snapshots.items[index];
            self.snapshots.items[index] = snapshot;
            old.deinit(self.allocator);
            return;
        }
        if (self.snapshots.items.len >= max_snapshots) {
            var oldest: usize = 0;
            for (self.snapshots.items, 0..) |current, index| if (current.updated_at_ms < self.snapshots.items[oldest].updated_at_ms) {
                oldest = index;
            };
            var removed = self.snapshots.orderedRemove(oldest);
            removed.deinit(self.allocator);
        }
        self.snapshots.append(self.allocator, snapshot) catch return error.OutOfMemory;
    }

    pub fn get(self: *Registry, server_id: []const u8, now_ms: i64) Error!?GetResult {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.snapshots.items) |snapshot| {
            if (!std.mem.eql(u8, snapshot.server_id, server_id)) continue;
            const server_copy = self.allocator.dupe(u8, snapshot.server_id) catch return error.OutOfMemory;
            errdefer self.allocator.free(server_copy);
            const json_copy = self.allocator.dupe(u8, snapshot.context_json) catch return error.OutOfMemory;
            return .{
                .snapshot = .{ .server_id = server_copy, .context_json = json_copy, .partial = snapshot.partial, .updated_at_ms = snapshot.updated_at_ms },
                .stale = now_ms - snapshot.updated_at_ms >= cache_ttl_ms,
            };
        }
        return null;
    }

    pub fn poll(self: *Registry, operation_id: []const u8, cursor: u64, rewind: bool) Error!struct { poll: events.Poll, state: State } {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const operation = self.findLocked(operation_id) orelse return error.NotFound;
        const poll_result = operation.stream.poll(self.allocator, cursor, rewind) catch return error.OutOfMemory;
        return .{ .poll = poll_result, .state = operation.state };
    }

    pub fn outcomeSnapshot(self: *Registry, operation_id: []const u8) Error!?sessions.AiContextOutcome.Snapshot {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const operation = self.findLocked(operation_id) orelse return error.NotFound;
        const outcome = operation.outcome orelse return null;
        return outcome.snapshot(self.allocator) catch return error.OutOfMemory;
    }

    pub fn serverId(self: *Registry, operation_id: []const u8) Error![]u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const operation = self.findLocked(operation_id) orelse return error.NotFound;
        return self.allocator.dupe(u8, operation.server_id) catch return error.OutOfMemory;
    }

    fn findLocked(self: *Registry, operation_id: []const u8) ?*Operation {
        for (self.operations.items) |operation| if (std.mem.eql(u8, operation.id, operation_id)) return operation;
        return null;
    }
};

fn appendFailure(operation: *Operation, code: types.ErrorCode, message: []const u8, now_ms: i64) void {
    var payload_buffer: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&payload_buffer);
    writer.writeAll("{\"code\":") catch return;
    writeJsonString(&writer, @tagName(code)) catch return;
    writer.writeAll(",\"error\":") catch return;
    const bounded = message[0..@min(message.len, 512)];
    writeJsonString(&writer, bounded) catch return;
    writer.print(",\"finished_at_ms\":{d}}}", .{now_ms}) catch return;
    operation.stream.append("context.failed", writer.buffered()) catch {};
}

fn writeJsonString(writer: *std.Io.Writer, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |ch| switch (ch) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        else => if (ch <= 0x1f)
            try writer.print("\\u00{x:0>2}", .{ch})
        else
            try writer.writeByte(ch),
    };
    try writer.writeByte('"');
}

fn destroyOutcome(allocator: std.mem.Allocator, outcome: *sessions.AiContextOutcome) void {
    outcome.data.deinit(allocator);
    allocator.destroy(outcome);
}

fn lockSpin(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.atomic.spinLoopHint();
}

test "context cache is cache-only and labels stale snapshots" {
    const allocator = std.testing.allocator;
    var registry = Registry{ .allocator = allocator };
    defer registry.deinit();
    try std.testing.expect((try registry.get("s1", 0)) == null);
    lockSpin(&registry.mutex);
    try registry.putSnapshotLocked("s1", "{\"server_id\":\"s1\"}", false, 100);
    registry.mutex.unlock();
    var fresh = (try registry.get("s1", 101)).?;
    defer fresh.snapshot.deinit(allocator);
    try std.testing.expect(!fresh.stale);
    var stale = (try registry.get("s1", 5_100)).?;
    defer stale.snapshot.deinit(allocator);
    try std.testing.expect(stale.stale);
}

test "context admission is idempotent and cursors do not consume events" {
    const allocator = std.testing.allocator;
    var registry = Registry{ .allocator = allocator };
    defer registry.deinit();
    const outcome = try allocator.create(sessions.AiContextOutcome);
    outcome.* = .{ .allocator = allocator };
    const admitted = try registry.admit("context-op-1", "s1", outcome, 10);
    try std.testing.expect(admitted.admitted);
    const unused = try allocator.create(sessions.AiContextOutcome);
    unused.* = .{ .allocator = allocator };
    const replay = try registry.admit("context-op-1", "s1", unused, 11);
    try std.testing.expect(!replay.admitted);
    allocator.destroy(unused);
    var first = try registry.poll("context-op-1", 0, false);
    defer first.poll.deinit(allocator);
    var second = try registry.poll("context-op-1", 0, false);
    defer second.poll.deinit(allocator);
    try std.testing.expectEqual(first.poll.cursor, second.poll.cursor);
    try std.testing.expectEqual(@as(usize, 1), first.poll.events.len);
    outcome.complete(0, "", "ok", false, false);
}
