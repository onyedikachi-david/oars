//! Bounded, non-destructive domain-event streams for Spec 11.

const std = @import("std");
const types = @import("types.zig");

pub const Event = struct {
    version: u8 = types.schema_version,
    sequence: u64,
    stream_id: []const u8,
    type: []const u8,
    payload_json: []const u8,

    pub fn deinit(self: *Event, allocator: std.mem.Allocator) void {
        allocator.free(self.stream_id);
        allocator.free(self.type);
        allocator.free(self.payload_json);
    }
};

pub const Poll = struct {
    stream_id: []const u8,
    cursor: u64,
    dropped: u64,
    events: []Event,

    pub fn deinit(self: *Poll, allocator: std.mem.Allocator) void {
        allocator.free(self.stream_id);
        for (self.events) |*event| event.deinit(allocator);
        allocator.free(self.events);
    }
};

pub const Error = error{ InvalidPayload, EventTooLarge, OutOfMemory };

pub const Stream = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    id: []const u8,
    events: std.ArrayList(Event) = .empty,
    next_sequence: u64 = 0,
    retained_bytes: usize = 0,
    max_events: usize = types.max_events,
    max_bytes: usize = types.max_event_bytes,

    pub fn init(allocator: std.mem.Allocator, stream_id: []const u8) !Stream {
        return .{ .allocator = allocator, .id = try allocator.dupe(u8, stream_id) };
    }

    pub fn deinit(self: *Stream) void {
        lockSpin(&self.mutex);
        for (self.events.items) |*event| event.deinit(self.allocator);
        self.events.deinit(self.allocator);
        self.allocator.free(self.id);
        self.mutex.unlock();
    }

    pub fn append(self: *Stream, event_type: []const u8, payload_json: []const u8) Error!void {
        if (event_type.len == 0 or event_type.len > 128 or payload_json.len > types.max_sse_event_bytes) return error.EventTooLarge;
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload_json, .{}) catch return error.InvalidPayload;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidPayload;
        const stream_id = self.allocator.dupe(u8, self.id) catch return error.OutOfMemory;
        errdefer self.allocator.free(stream_id);
        const type_copy = self.allocator.dupe(u8, event_type) catch return error.OutOfMemory;
        errdefer self.allocator.free(type_copy);
        const payload_copy = self.allocator.dupe(u8, payload_json) catch return error.OutOfMemory;
        errdefer self.allocator.free(payload_copy);
        const byte_size = stream_id.len + type_copy.len + payload_copy.len;
        if (byte_size > self.max_bytes) return error.EventTooLarge;

        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (std.mem.eql(u8, event_type, "provider.progress") and self.events.items.len > 0 and std.mem.eql(u8, self.events.items[self.events.items.len - 1].type, event_type)) {
            var removed = self.events.pop().?;
            self.retained_bytes -= eventBytes(removed);
            removed.deinit(self.allocator);
        }
        while (self.events.items.len >= self.max_events or (self.events.items.len > 0 and self.retained_bytes + byte_size > self.max_bytes)) {
            var removed = self.events.orderedRemove(0);
            self.retained_bytes -= eventBytes(removed);
            removed.deinit(self.allocator);
        }
        self.events.append(self.allocator, .{
            .sequence = self.next_sequence,
            .stream_id = stream_id,
            .type = type_copy,
            .payload_json = payload_copy,
        }) catch return error.OutOfMemory;
        self.next_sequence += 1;
        self.retained_bytes += byte_size;
    }

    pub fn poll(self: *Stream, allocator: std.mem.Allocator, cursor: u64, rewind: bool) !Poll {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const retained_start = if (self.events.items.len > 0) self.events.items[0].sequence else self.next_sequence;
        const requested = if (rewind) retained_start else cursor;
        const start = @max(requested, retained_start);
        var count: usize = 0;
        for (self.events.items) |event| if (event.sequence >= start) {
            count += 1;
        };
        const copied = try allocator.alloc(Event, count);
        errdefer allocator.free(copied);
        var completed: usize = 0;
        errdefer for (copied[0..completed]) |*event| event.deinit(allocator);
        for (self.events.items) |event| {
            if (event.sequence < start) continue;
            const stream_id = try allocator.dupe(u8, event.stream_id);
            errdefer allocator.free(stream_id);
            const type_copy = try allocator.dupe(u8, event.type);
            errdefer allocator.free(type_copy);
            const payload_copy = try allocator.dupe(u8, event.payload_json);
            copied[completed] = .{
                .sequence = event.sequence,
                .stream_id = stream_id,
                .type = type_copy,
                .payload_json = payload_copy,
            };
            completed += 1;
        }
        const id_copy = try allocator.dupe(u8, self.id);
        return .{
            .stream_id = id_copy,
            .cursor = if (count > 0) copied[count - 1].sequence + 1 else start,
            .dropped = start -| requested,
            .events = copied,
        };
    }
};

fn eventBytes(event: Event) usize {
    return event.stream_id.len + event.type.len + event.payload_json.len;
}

fn lockSpin(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.atomic.spinLoopHint();
}

test "event streams keep independent cursors and report dropped events" {
    const allocator = std.testing.allocator;
    var stream = try Stream.init(allocator, "context-1");
    defer stream.deinit();
    stream.max_events = 2;
    try stream.append("context.refresh_started", "{\"state\":\"running\"}");
    try stream.append("context.ready", "{\"state\":\"ready\"}");
    var first = try stream.poll(allocator, 0, false);
    defer first.deinit(allocator);
    var mirrored = try stream.poll(allocator, 0, false);
    defer mirrored.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), first.events.len);
    try std.testing.expectEqual(first.cursor, mirrored.cursor);
    try std.testing.expectEqual(@as(u64, 0), mirrored.dropped);

    try stream.append("context.failed", "{\"code\":\"provider_protocol\"}");
    var stale = try stream.poll(allocator, 0, false);
    defer stale.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), stale.dropped);
    try std.testing.expectEqual(@as(usize, 2), stale.events.len);
    try std.testing.expectEqualStrings("context.ready", stale.events[0].type);
    var rewind = try stream.poll(allocator, 99, true);
    defer rewind.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), rewind.events.len);
    try std.testing.expectEqual(@as(u64, 0), rewind.dropped);
}

test "event payloads must be bounded JSON objects" {
    const allocator = std.testing.allocator;
    var stream = try Stream.init(allocator, "turn-1");
    defer stream.deinit();
    try std.testing.expectError(error.InvalidPayload, stream.append("turn.started", "[]"));
    try std.testing.expectError(error.InvalidPayload, stream.append("turn.started", "broken"));
}

test "contiguous provider progress is coalesced without hiding the newest sequence" {
    const allocator = std.testing.allocator;
    var stream = try Stream.init(allocator, "turn-progress");
    defer stream.deinit();
    try stream.append("provider.progress", "{\"phase\":\"streaming\",\"received_bytes\":10}");
    try stream.append("provider.progress", "{\"phase\":\"streaming\",\"received_bytes\":20}");
    try std.testing.expectEqual(@as(usize, 1), stream.events.items.len);
    try std.testing.expectEqual(@as(u64, 1), stream.events.items[0].sequence);
    var poll = try stream.poll(allocator, 1, false);
    defer poll.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), poll.events.len);
    try std.testing.expect(std.mem.indexOf(u8, poll.events[0].payload_json, "20") != null);
}
