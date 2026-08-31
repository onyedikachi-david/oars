//! Durable append-only AI state journal (Spec 11).

const std = @import("std");
const types = @import("types.zig");

pub const max_journal_bytes: usize = 16 * 1024 * 1024;

pub const Kind = enum {
    thread_created,
    thread_deleted,
    turn_queued,
    context_collected,
    provider_request_started,
    provider_result,
    provider_interrupted,
    proposal_ready,
    proposal_edited,
    proposal_canceled,
    approval_recorded,
    execution_admitted,
    execution_finished,
    turn_terminal,
    recovery_marked,
};

pub const Error = error{
    InvalidRecord,
    InvalidPayload,
    StoreUnavailable,
    StoreAccess,
    StoreCorrupt,
    StoreQuarantineFailed,
    SerializeFailed,
    OutOfMemory,
};

pub const AppendInput = struct {
    kind: Kind,
    operation_id: ?[]const u8 = null,
    thread_id: ?[]const u8 = null,
    turn_id: ?[]const u8 = null,
    proposal_id: ?[]const u8 = null,
    execution_id: ?[]const u8 = null,
    payload_json: []const u8,
};

pub const Record = struct {
    version: u8 = types.schema_version,
    sequence: u64,
    timestamp_ms: i64,
    kind: Kind,
    operation_id: ?[]const u8 = null,
    thread_id: ?[]const u8 = null,
    turn_id: ?[]const u8 = null,
    proposal_id: ?[]const u8 = null,
    execution_id: ?[]const u8 = null,
    payload_json: []const u8,

    pub fn deinit(self: *Record, allocator: std.mem.Allocator) void {
        if (self.operation_id) |value| allocator.free(value);
        if (self.thread_id) |value| allocator.free(value);
        if (self.turn_id) |value| allocator.free(value);
        if (self.proposal_id) |value| allocator.free(value);
        if (self.execution_id) |value| allocator.free(value);
        allocator.free(self.payload_json);
    }
};

const Envelope = struct {
    version: u8,
    sequence: u64,
    timestamp_ms: i64,
    kind: Kind,
    operation_id: ?[]const u8 = null,
    thread_id: ?[]const u8 = null,
    turn_id: ?[]const u8 = null,
    proposal_id: ?[]const u8 = null,
    execution_id: ?[]const u8 = null,
    payload: std.json.Value,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    mutex: std.atomic.Mutex = .unlocked,
    loaded: bool = false,
    available: bool = true,
    recovered_tail: bool = false,
    quarantine_path: ?[]u8 = null,
    next_sequence: u64 = 1,
    records: std.ArrayList(Record) = .empty,

    pub fn deinit(self: *Store) void {
        for (self.records.items) |*record| record.deinit(self.allocator);
        self.records.deinit(self.allocator);
        if (self.quarantine_path) |path| self.allocator.free(path);
    }

    pub fn ensureLoaded(self: *Store, io: std.Io) Error!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.ensureLoadedLocked(io);
    }

    pub fn append(self: *Store, io: std.Io, timestamp_ms: i64, input: AppendInput) Error!u64 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.ensureLoadedLocked(io);
        if (!self.available) return error.StoreUnavailable;
        try validateInput(input);
        const sequence = self.next_sequence;
        var owned = try cloneInput(self.allocator, sequence, timestamp_ms, input);
        errdefer owned.deinit(self.allocator);
        self.records.ensureUnusedCapacity(self.allocator, 1) catch return error.OutOfMemory;
        const line = serializeRecord(self.allocator, &owned) catch |err| return err;
        defer self.allocator.free(line);
        appendLine(io, self.path, line) catch return error.StoreAccess;
        self.records.appendAssumeCapacity(owned);
        self.next_sequence += 1;
        return sequence;
    }

    /// Appends related transitions with one positional write and one sync.
    /// No record enters memory or disk unless every input validates, clones,
    /// and serializes first.
    pub fn appendBatch(self: *Store, io: std.Io, timestamp_ms: i64, inputs: []const AppendInput) Error!u64 {
        if (inputs.len == 0) return error.InvalidRecord;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.ensureLoadedLocked(io);
        if (!self.available) return error.StoreUnavailable;
        const owned = self.allocator.alloc(Record, inputs.len) catch return error.OutOfMemory;
        defer self.allocator.free(owned);
        var completed: usize = 0;
        errdefer for (owned[0..completed]) |*record| record.deinit(self.allocator);
        var bytes: std.Io.Writer.Allocating = .init(self.allocator);
        defer bytes.deinit();
        for (inputs, 0..) |input, index| {
            try validateInput(input);
            owned[index] = try cloneInput(self.allocator, self.next_sequence + index, timestamp_ms, input);
            completed += 1;
            const line = try serializeRecord(self.allocator, &owned[index]);
            defer self.allocator.free(line);
            bytes.writer.writeAll(line) catch return error.OutOfMemory;
        }
        self.records.ensureUnusedCapacity(self.allocator, inputs.len) catch return error.OutOfMemory;
        appendLine(io, self.path, bytes.writer.buffered()) catch return error.StoreAccess;
        for (owned) |record| self.records.appendAssumeCapacity(record);
        const first_sequence = self.next_sequence;
        self.next_sequence += inputs.len;
        return first_sequence;
    }

    pub fn snapshot(self: *Store, io: std.Io) Error![]Record {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.ensureLoadedLocked(io);
        const copy = self.allocator.alloc(Record, self.records.items.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(copy);
        var completed: usize = 0;
        errdefer for (copy[0..completed]) |*record| record.deinit(self.allocator);
        for (self.records.items, 0..) |record, index| {
            copy[index] = cloneRecord(self.allocator, record) catch return error.OutOfMemory;
            completed += 1;
        }
        return copy;
    }

    pub fn deinitSnapshot(allocator: std.mem.Allocator, records: []Record) void {
        for (records) |*record| record.deinit(allocator);
        allocator.free(records);
    }

    /// Rewrites the valid suffix selected by the state owner. The journal
    /// keeps original sequence numbers so cursors and operation identities do
    /// not change across compaction.
    pub fn compact(self: *Store, io: std.Io, retain_from_sequence: u64) Error!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.ensureLoadedLocked(io);
        if (!self.available) return error.StoreUnavailable;
        var output: std.Io.Writer.Allocating = .init(self.allocator);
        defer output.deinit();
        for (self.records.items) |*record| {
            if (record.sequence < retain_from_sequence) continue;
            const line = serializeRecord(self.allocator, record) catch return error.SerializeFailed;
            defer self.allocator.free(line);
            output.writer.writeAll(line) catch return error.OutOfMemory;
        }
        rewriteAtomically(self.allocator, io, self.path, output.writer.buffered(), ".compact") catch return error.StoreAccess;
        while (self.records.items.len > 0) {
            if (self.records.items[0].sequence >= retain_from_sequence) break;
            var removed = self.records.orderedRemove(0);
            removed.deinit(self.allocator);
        }
    }

    fn ensureLoadedLocked(self: *Store, io: std.Io) Error!void {
        if (self.loaded) return;
        self.loaded = true;
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, self.path, self.allocator, .limited(max_journal_bytes)) catch |err| {
            if (err == error.FileNotFound) return;
            self.available = false;
            return error.StoreAccess;
        };
        defer self.allocator.free(bytes);
        var start: usize = 0;
        var last_sequence: u64 = 0;
        while (start < bytes.len) {
            const relative_end = std.mem.indexOfScalar(u8, bytes[start..], '\n');
            if (relative_end == null) {
                try self.recoverTailLocked(io, bytes[0..start], bytes[start..]);
                break;
            }
            const end = start + relative_end.?;
            const line = bytes[start..end];
            if (line.len == 0) {
                try self.markCorruptLocked(io);
                return;
            }
            var record = parseRecord(self.allocator, line) catch {
                try self.markCorruptLocked(io);
                return;
            };
            if (record.sequence <= last_sequence) {
                record.deinit(self.allocator);
                try self.markCorruptLocked(io);
                return;
            }
            last_sequence = record.sequence;
            self.records.append(self.allocator, record) catch {
                record.deinit(self.allocator);
                return error.OutOfMemory;
            };
            start = end + 1;
        }
        self.next_sequence = last_sequence + 1;
    }

    fn recoverTailLocked(self: *Store, io: std.Io, prefix: []const u8, tail: []const u8) Error!void {
        if (tail.len == 0) return;
        const quarantine = try quarantineName(self.allocator, io, self.path, ".tail-");
        errdefer self.allocator.free(quarantine);
        writeOwned(io, quarantine, tail) catch return error.StoreQuarantineFailed;
        rewriteAtomically(self.allocator, io, self.path, prefix, ".recover") catch return error.StoreAccess;
        self.recovered_tail = true;
        self.quarantine_path = quarantine;
    }

    fn markCorruptLocked(self: *Store, io: std.Io) Error!void {
        const quarantine = try quarantineName(self.allocator, io, self.path, ".corrupt-");
        errdefer self.allocator.free(quarantine);
        std.Io.Dir.renameAbsolute(self.path, quarantine, io) catch return error.StoreQuarantineFailed;
        syncParent(io, self.path) catch return error.StoreQuarantineFailed;
        self.available = false;
        self.quarantine_path = quarantine;
    }
};

fn validateInput(input: AppendInput) Error!void {
    if (input.operation_id) |value| if (!types.validOperationId(value)) return error.InvalidRecord;
    for ([_]?[]const u8{ input.thread_id, input.turn_id, input.proposal_id, input.execution_id }) |maybe| if (maybe) |value| {
        if (!validOpaqueId(value)) return error.InvalidRecord;
    };
    var payload = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, input.payload_json, .{}) catch return error.InvalidPayload;
    defer payload.deinit();
    if (payload.value != .object) return error.InvalidPayload;
}

fn validOpaqueId(value: []const u8) bool {
    if (value.len == 0 or value.len > 128) return false;
    for (value) |ch| switch (ch) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', ':', '_', '-' => {},
        else => return false,
    };
    return true;
}

fn cloneOptional(allocator: std.mem.Allocator, value: ?[]const u8) !?[]const u8 {
    return if (value) |text| try allocator.dupe(u8, text) else null;
}

fn cloneInput(allocator: std.mem.Allocator, sequence: u64, timestamp_ms: i64, input: AppendInput) !Record {
    const operation_id = try cloneOptional(allocator, input.operation_id);
    errdefer if (operation_id) |value| allocator.free(value);
    const thread_id = try cloneOptional(allocator, input.thread_id);
    errdefer if (thread_id) |value| allocator.free(value);
    const turn_id = try cloneOptional(allocator, input.turn_id);
    errdefer if (turn_id) |value| allocator.free(value);
    const proposal_id = try cloneOptional(allocator, input.proposal_id);
    errdefer if (proposal_id) |value| allocator.free(value);
    const execution_id = try cloneOptional(allocator, input.execution_id);
    errdefer if (execution_id) |value| allocator.free(value);
    const payload = try allocator.dupe(u8, input.payload_json);
    return .{ .sequence = sequence, .timestamp_ms = timestamp_ms, .kind = input.kind, .operation_id = operation_id, .thread_id = thread_id, .turn_id = turn_id, .proposal_id = proposal_id, .execution_id = execution_id, .payload_json = payload };
}

fn cloneRecord(allocator: std.mem.Allocator, record: Record) !Record {
    return cloneInput(allocator, record.sequence, record.timestamp_ms, .{
        .kind = record.kind,
        .operation_id = record.operation_id,
        .thread_id = record.thread_id,
        .turn_id = record.turn_id,
        .proposal_id = record.proposal_id,
        .execution_id = record.execution_id,
        .payload_json = record.payload_json,
    });
}

fn parseRecord(allocator: std.mem.Allocator, line: []const u8) Error!Record {
    var parsed = std.json.parseFromSlice(Envelope, allocator, line, .{ .allocate = .alloc_always }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.StoreCorrupt;
    defer parsed.deinit();
    const value = parsed.value;
    if (value.version != types.schema_version or value.sequence == 0 or value.payload != .object) return error.StoreCorrupt;
    const input = AppendInput{ .kind = value.kind, .operation_id = value.operation_id, .thread_id = value.thread_id, .turn_id = value.turn_id, .proposal_id = value.proposal_id, .execution_id = value.execution_id, .payload_json = "{}" };
    validateInput(input) catch return error.StoreCorrupt;
    var payload: std.Io.Writer.Allocating = .init(allocator);
    defer payload.deinit();
    std.json.Stringify.value(value.payload, .{}, &payload.writer) catch return error.OutOfMemory;
    return cloneInput(allocator, value.sequence, value.timestamp_ms, .{
        .kind = value.kind,
        .operation_id = value.operation_id,
        .thread_id = value.thread_id,
        .turn_id = value.turn_id,
        .proposal_id = value.proposal_id,
        .execution_id = value.execution_id,
        .payload_json = payload.writer.buffered(),
    }) catch return error.OutOfMemory;
}

fn serializeRecord(allocator: std.mem.Allocator, record: *const Record) Error![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    const writer = &output.writer;
    writer.print("{{\"version\":{d},\"sequence\":{d},\"timestamp_ms\":{d},\"kind\":", .{ record.version, record.sequence, record.timestamp_ms }) catch return error.OutOfMemory;
    std.json.Stringify.value(@tagName(record.kind), .{}, writer) catch return error.OutOfMemory;
    inline for (.{ .{ "operation_id", record.operation_id }, .{ "thread_id", record.thread_id }, .{ "turn_id", record.turn_id }, .{ "proposal_id", record.proposal_id }, .{ "execution_id", record.execution_id } }) |field| {
        if (field[1]) |value| {
            writer.print(",\"{s}\":", .{field[0]}) catch return error.OutOfMemory;
            std.json.Stringify.value(value, .{}, writer) catch return error.OutOfMemory;
        }
    }
    writer.writeAll(",\"payload\":") catch return error.OutOfMemory;
    writer.writeAll(record.payload_json) catch return error.OutOfMemory;
    writer.writeAll("}\n") catch return error.OutOfMemory;
    return output.toOwnedSlice() catch return error.OutOfMemory;
}

fn appendLine(io: std.Io, path: []const u8, bytes: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |dir| try cwd.createDirPath(io, dir);
    var file = try cwd.createFile(io, path, .{ .truncate = false, .permissions = .fromMode(0o600) });
    defer file.close(io);
    const end = (try file.stat(io)).size;
    try file.writePositionalAll(io, bytes, end);
    try file.setPermissions(io, .fromMode(0o600));
    try file.sync(io);
}

fn writeOwned(io: std.Io, path: []const u8, bytes: []const u8) !void {
    var file = try std.Io.Dir.cwd().createFile(io, path, .{ .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    try file.sync(io);
}

fn rewriteAtomically(allocator: std.mem.Allocator, io: std.Io, path: []const u8, bytes: []const u8, suffix: []const u8) !void {
    const tmp = try std.fmt.allocPrint(allocator, "{s}{s}", .{ path, suffix });
    defer allocator.free(tmp);
    writeOwned(io, tmp, bytes) catch |err| return err;
    std.Io.Dir.renameAbsolute(tmp, path, io) catch return error.RenameFailed;
    try syncParent(io, path);
}

fn quarantineName(allocator: std.mem.Allocator, io: std.Io, path: []const u8, marker: []const u8) Error![]u8 {
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    return std.fmt.allocPrint(allocator, "{s}{s}{d}", .{ path, marker, now }) catch error.OutOfMemory;
}

fn syncParent(io: std.Io, path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse ".";
    var directory = try std.Io.Dir.cwd().openFile(io, parent, .{ .mode = .read_only, .allow_directory = true });
    defer directory.close(io);
    try directory.sync(io);
}

fn lockSpin(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.atomic.spinLoopHint();
}

fn testPath(io: std.Io, suffix: []const u8, dir_buffer: []u8, path_buffer: []u8) !struct { dir: []const u8, path: []const u8 } {
    const dir = try std.fmt.bufPrint(dir_buffer, "/tmp/oars-ai-journal-{s}-{d}", .{ suffix, std.Io.Timestamp.now(io, .real).nanoseconds });
    const path = try std.fmt.bufPrint(path_buffer, "{s}/ai_journal.jsonl", .{dir});
    return .{ .dir = dir, .path = path };
}

test "journal append replay compaction and owner-only mode" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buffer: [192]u8 = undefined;
    var path_buffer: [256]u8 = undefined;
    const temp = try testPath(io, "core", &dir_buffer, &path_buffer);
    defer std.Io.Dir.cwd().deleteTree(io, temp.dir) catch {};
    var store = Store{ .allocator = allocator, .path = temp.path };
    const admitted = [_]AppendInput{
        .{ .kind = .thread_created, .thread_id = "ait-1", .payload_json = "{\"server_id\":\"s1\"}" },
        .{ .kind = .turn_queued, .operation_id = "turn-op-1", .thread_id = "ait-1", .turn_id = "turn-1", .payload_json = "{\"message\":\"inspect\"}" },
    };
    try std.testing.expectEqual(@as(u64, 1), try store.appendBatch(io, 10, &admitted));
    var file = try std.Io.Dir.cwd().openFile(io, temp.path, .{ .mode = .read_only });
    const stat = try file.stat(io);
    file.close(io);
    try std.testing.expectEqual(@as(u32, 0), stat.permissions.toMode() & 0o077);
    store.deinit();

    var replay = Store{ .allocator = allocator, .path = temp.path };
    defer replay.deinit();
    const records = try replay.snapshot(io);
    defer Store.deinitSnapshot(allocator, records);
    try std.testing.expectEqual(@as(usize, 2), records.len);
    try std.testing.expectEqual(Kind.turn_queued, records[1].kind);
    try replay.compact(io, 2);
    try std.testing.expectEqual(@as(usize, 1), replay.records.items.len);
    try std.testing.expectEqual(@as(u64, 3), try replay.append(io, 12, .{ .kind = .turn_terminal, .turn_id = "turn-1", .payload_json = "{\"state\":\"interrupted\"}" }));
}

test "journal recovers a truncated final line and quarantines only the tail" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buffer: [192]u8 = undefined;
    var path_buffer: [256]u8 = undefined;
    const temp = try testPath(io, "tail", &dir_buffer, &path_buffer);
    defer std.Io.Dir.cwd().deleteTree(io, temp.dir) catch {};
    var first = Store{ .allocator = allocator, .path = temp.path };
    _ = try first.append(io, 10, .{ .kind = .thread_created, .thread_id = "ait-1", .payload_json = "{}" });
    first.deinit();
    try appendLine(io, temp.path, "{\"version\":1");
    var replay = Store{ .allocator = allocator, .path = temp.path };
    defer replay.deinit();
    try replay.ensureLoaded(io);
    try std.testing.expect(replay.available);
    try std.testing.expect(replay.recovered_tail);
    try std.testing.expectEqual(@as(usize, 1), replay.records.items.len);
    try std.testing.expect(replay.quarantine_path != null);
}

test "journal rejects a corrupt complete middle record and blocks mutation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buffer: [192]u8 = undefined;
    var path_buffer: [256]u8 = undefined;
    const temp = try testPath(io, "corrupt", &dir_buffer, &path_buffer);
    defer std.Io.Dir.cwd().deleteTree(io, temp.dir) catch {};
    var first = Store{ .allocator = allocator, .path = temp.path };
    _ = try first.append(io, 10, .{ .kind = .thread_created, .thread_id = "ait-1", .payload_json = "{}" });
    first.deinit();
    try appendLine(io, temp.path, "not-json\n");
    var replay = Store{ .allocator = allocator, .path = temp.path };
    defer replay.deinit();
    try replay.ensureLoaded(io);
    try std.testing.expect(!replay.available);
    try std.testing.expect(replay.quarantine_path != null);
    try std.testing.expectError(error.StoreUnavailable, replay.append(io, 11, .{ .kind = .turn_terminal, .turn_id = "turn-1", .payload_json = "{}" }));
}
