//! Bounded, cancellable provider capability tests for Spec 11.

const std = @import("std");
const types = @import("types.zig");
const provider = @import("provider.zig");
const credentials = @import("credentials.zig");
const transport = @import("transport.zig");
const responses = @import("responses.zig");
const chat = @import("chat.zig");
const events = @import("events.zig");
const request_slots = @import("request_slots.zig");

pub const max_operations: usize = 32;

pub const State = enum {
    queued,
    running,
    cancel_requested,
    passed,
    failed,
    canceled,

    pub fn terminal(self: State) bool {
        return self == .passed or self == .failed or self == .canceled;
    }
};

pub const Error = error{
    InvalidOperationId,
    InvalidProviderId,
    OperationConflict,
    StaleRevision,
    Busy,
    LimitExceeded,
    NotFound,
    OutOfMemory,
};

pub const Runner = struct {
    context: ?*anyopaque = null,
    run_fn: *const fn (
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        selected: *const provider.Public,
        secret: *const credentials.SecretBuffer,
        client_request_id: []const u8,
        cancellation: *transport.Cancellation,
    ) anyerror!transport.Meta,

    pub fn native() Runner {
        return .{ .run_fn = runNative };
    }
};

pub const Operation = struct {
    allocator: std.mem.Allocator,
    id: []const u8,
    selected: provider.Public,
    credential_generation: u64,
    secret: credentials.SecretBuffer,
    state: State = .queued,
    cancellation: transport.Cancellation = .{},
    stream: events.Stream,
    thread: ?std.Thread = null,

    fn deinit(self: *Operation) void {
        if (self.thread) |thread| thread.join();
        self.secret.clear();
        self.stream.deinit();
        self.selected.deinit(self.allocator);
        self.allocator.free(self.id);
        self.allocator.destroy(self);
    }
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    providers: *provider.Store,
    limiter: *request_slots.Limiter,
    runner: Runner,
    mutex: std.atomic.Mutex = .unlocked,
    operations: std.ArrayList(*Operation) = .empty,
    accepting: bool = true,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, providers: *provider.Store, limiter: *request_slots.Limiter) Registry {
        return .{ .allocator = allocator, .io = io, .providers = providers, .limiter = limiter, .runner = Runner.native() };
    }

    pub fn deinit(self: *Registry) void {
        lockSpin(&self.mutex);
        self.accepting = false;
        for (self.operations.items) |operation| operation.cancellation.cancel();
        self.mutex.unlock();
        for (self.operations.items) |operation| operation.deinit();
        self.operations.deinit(self.allocator);
    }

    /// Checks an operation replay before the runtime thread reads a secret.
    pub fn lookup(self: *Registry, operation_id: []const u8, provider_id: []const u8, expected_revision: u64) Error!?State {
        try validateIdentity(operation_id, provider_id);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.operations.items) |operation| {
            if (!std.mem.eql(u8, operation.id, operation_id)) continue;
            if (!std.mem.eql(u8, operation.selected.id, provider_id) or operation.selected.revision != expected_revision) return error.OperationConflict;
            return operation.state;
        }
        return null;
    }

    /// Fails before a credential read when the global two-request quota is
    /// already occupied. Admission repeats this check under the same mutex.
    pub fn checkCapacity(self: *Registry) Error!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (!self.accepting) return error.Busy;
        if (self.limiter.count() >= types.max_provider_requests) return error.Busy;
    }

    /// Takes ownership of `selected` and `secret` only when it returns.
    pub fn admitOwned(self: *Registry, operation_id: []const u8, selected: provider.Public, credential_generation: u64, secret: credentials.SecretBuffer) Error!State {
        try validateIdentity(operation_id, selected.id);
        if (credential_generation == 0 or selected.revision == 0) return error.StaleRevision;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (!self.accepting) return error.Busy;
        for (self.operations.items) |operation| {
            if (!std.mem.eql(u8, operation.id, operation_id)) continue;
            if (!std.mem.eql(u8, operation.selected.id, selected.id) or operation.selected.revision != selected.revision) return error.OperationConflict;
            return operation.state;
        }
        if (!self.limiter.tryAcquire()) return error.Busy;
        errdefer self.limiter.release();
        try self.makeRoomLocked();

        const operation = self.allocator.create(Operation) catch return error.OutOfMemory;
        errdefer self.allocator.destroy(operation);
        const id = self.allocator.dupe(u8, operation_id) catch return error.OutOfMemory;
        errdefer self.allocator.free(id);
        var stream = events.Stream.init(self.allocator, operation_id) catch return error.OutOfMemory;
        errdefer stream.deinit();
        operation.* = .{
            .allocator = self.allocator,
            .id = id,
            .selected = selected,
            .credential_generation = credential_generation,
            .secret = secret,
            .stream = stream,
        };
        self.operations.append(self.allocator, operation) catch return error.OutOfMemory;
        errdefer _ = self.operations.pop();
        operation.thread = std.Thread.spawn(.{}, workerMain, .{ self, operation }) catch return error.OutOfMemory;
        return .queued;
    }

    pub fn poll(self: *Registry, operation_id: []const u8, cursor: u64, rewind: bool) Error!struct { poll: events.Poll, state: State } {
        if (!types.validOperationId(operation_id)) return error.InvalidOperationId;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const operation = self.findLocked(operation_id) orelse return error.NotFound;
        const result = operation.stream.poll(self.allocator, cursor, rewind) catch return error.OutOfMemory;
        return .{ .poll = result, .state = operation.state };
    }

    pub fn cancel(self: *Registry, operation_id: []const u8) Error!State {
        if (!types.validOperationId(operation_id)) return error.InvalidOperationId;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const operation = self.findLocked(operation_id) orelse return error.NotFound;
        if (operation.state.terminal() or operation.state == .cancel_requested) return operation.state;
        operation.state = .cancel_requested;
        operation.cancellation.cancel();
        return operation.state;
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

    fn findLocked(self: *Registry, operation_id: []const u8) ?*Operation {
        for (self.operations.items) |operation| if (std.mem.eql(u8, operation.id, operation_id)) return operation;
        return null;
    }
};

fn validateIdentity(operation_id: []const u8, provider_id: []const u8) Error!void {
    if (!types.validOperationId(operation_id)) return error.InvalidOperationId;
    if (provider_id.len < 4 or provider_id.len > 64 or !std.mem.startsWith(u8, provider_id, "aip-")) return error.InvalidProviderId;
}

fn workerMain(registry: *Registry, operation: *Operation) void {
    defer registry.limiter.release();
    lockSpin(&registry.mutex);
    if (operation.cancellation.isCanceled()) {
        finishCanceled(operation);
        registry.mutex.unlock();
        operation.secret.clear();
        return;
    }
    operation.state = .running;
    operation.stream.append("provider.test_started", "{\"state\":\"running\"}") catch {};
    registry.mutex.unlock();

    const run_result = registry.runner.run_fn(registry.runner.context, registry.allocator, registry.io, &operation.selected, &operation.secret, operation.id, &operation.cancellation);
    operation.secret.clear();
    const canceled = operation.cancellation.isCanceled();
    if (canceled) {
        lockSpin(&registry.mutex);
        finishCanceled(operation);
        registry.mutex.unlock();
        return;
    }

    const passed = if (run_result) |_| true else |_| false;
    const tested_at_ms = nowMs(registry.io);
    var persisted = registry.providers.recordTestResult(
        registry.io,
        operation.selected.id,
        operation.selected.revision,
        operation.credential_generation,
        if (passed) .passed else .failed,
        tested_at_ms,
    ) catch |err| {
        lockSpin(&registry.mutex);
        operation.state = .failed;
        appendFailure(operation, if (err == error.StaleRevision) .stale_revision else .recovery_required, if (err == error.StaleRevision) "provider or credential changed during the test" else "provider test status could not be saved");
        registry.mutex.unlock();
        return;
    };
    persisted.deinit(registry.allocator);

    lockSpin(&registry.mutex);
    if (run_result) |meta| {
        operation.state = .passed;
        appendPassed(operation, meta.requestId(), tested_at_ms);
    } else |err| {
        operation.state = .failed;
        appendFailure(operation, errorCode(err), errorMessage(err));
    }
    registry.mutex.unlock();
}

fn finishCanceled(operation: *Operation) void {
    if (operation.state.terminal()) return;
    operation.state = .canceled;
    operation.stream.append("provider.test_canceled", "{\"state\":\"canceled\"}") catch {};
}

fn appendPassed(operation: *Operation, provider_request_id: []const u8, tested_at_ms: i64) void {
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    writer.writeAll("{\"state\":\"passed\",\"provider_request_id\":") catch return;
    std.json.Stringify.value(provider_request_id, .{}, &writer) catch return;
    writer.print(",\"tested_at_ms\":{d}}}", .{tested_at_ms}) catch return;
    operation.stream.append("provider.test_succeeded", writer.buffered()) catch {};
}

fn appendFailure(operation: *Operation, code: types.ErrorCode, message: []const u8) void {
    var buffer: [768]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    writer.writeAll("{\"state\":\"failed\",\"code\":") catch return;
    std.json.Stringify.value(@tagName(code), .{}, &writer) catch return;
    writer.writeAll(",\"error\":") catch return;
    std.json.Stringify.value(message, .{}, &writer) catch return;
    writer.writeAll("}") catch return;
    operation.stream.append("provider.test_failed", writer.buffered()) catch {};
}

fn errorCode(err: anyerror) types.ErrorCode {
    return switch (err) {
        error.AuthenticationFailed => .provider_auth,
        error.RateLimited => .provider_rate_limited,
        error.Timeout => .provider_timeout,
        error.OutOfMemory => .recovery_required,
        else => .provider_protocol,
    };
}

fn errorMessage(err: anyerror) []const u8 {
    return switch (errorCode(err)) {
        .provider_auth => "the provider rejected the credential",
        .provider_rate_limited => "the provider rate limited the capability test",
        .provider_timeout => "the provider capability test timed out",
        .recovery_required => "the provider test could not allocate required state",
        else => "the provider response did not satisfy the selected adapter contract",
    };
}

fn runNative(
    _: ?*anyopaque,
    allocator: std.mem.Allocator,
    io: std.Io,
    selected: *const provider.Public,
    secret: *const credentials.SecretBuffer,
    client_request_id: []const u8,
    cancellation: *transport.Cancellation,
) anyerror!transport.Meta {
    const instructions = "Return exactly one valid proposal object. Do not call tools. This is a provider capability test only.";
    const question = "Return a harmless command proposal that prints the operating-system kernel name.";
    var endpoint_buffer: [provider.max_base_url_bytes + 32]u8 = undefined;
    return switch (selected.adapter) {
        .openai_responses => blk: {
            const body = try responses.buildRequest(allocator, selected.model, instructions, question);
            defer allocator.free(body);
            const endpoint = try transport.composeEndpoint(&endpoint_buffer, selected.base_url, responses.endpoint_suffix);
            var state = responses.State.init(allocator);
            defer state.deinit();
            const meta = try transport.postSseTimed(allocator, io, endpoint, secret, client_request_id, body, cancellation, state.sink(), .{});
            try state.finish();
            break :blk meta;
        },
        .openai_chat_completions => blk: {
            const role = selected.instruction_role orelse return error.InvalidCompatibility;
            const mode = selected.structured_output orelse return error.InvalidCompatibility;
            const body = try chat.buildRequest(allocator, selected.model, role, mode, instructions, question);
            defer allocator.free(body);
            const endpoint = try transport.composeEndpoint(&endpoint_buffer, selected.base_url, chat.endpoint_suffix);
            var state = chat.State.init(allocator);
            defer state.deinit();
            const meta = try transport.postSseTimed(allocator, io, endpoint, secret, client_request_id, body, cancellation, state.sink(), .{});
            try state.finish();
            break :blk meta;
        },
    };
}

fn nowMs(io: std.Io) i64 {
    return @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_ms));
}

fn lockSpin(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.atomic.spinLoopHint();
}

const FakeRunner = struct {
    block: bool = false,
    fail: bool = false,
    active: std.atomic.Value(usize) = .init(0),

    fn run(context: ?*anyopaque, _: std.mem.Allocator, io: std.Io, _: *const provider.Public, secret: *const credentials.SecretBuffer, _: []const u8, cancellation: *transport.Cancellation) anyerror!transport.Meta {
        const self: *FakeRunner = @ptrCast(@alignCast(context.?));
        if (!std.mem.eql(u8, secret.slice(), "fixture-secret")) return error.AuthenticationFailed;
        _ = self.active.fetchAdd(1, .acq_rel);
        defer _ = self.active.fetchSub(1, .acq_rel);
        while (self.block and !cancellation.isCanceled()) std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake) catch {};
        if (cancellation.isCanceled()) return error.Canceled;
        if (self.fail) return error.AuthenticationFailed;
        var meta = transport.Meta{ .status = 200 };
        @memcpy(meta.provider_request_id[0.."fixture-request".len], "fixture-request");
        meta.provider_request_id_len = "fixture-request".len;
        return meta;
    }

    fn adapter(self: *FakeRunner) Runner {
        return .{ .context = self, .run_fn = run };
    }
};

fn fixtureSecret() credentials.SecretBuffer {
    var secret = credentials.SecretBuffer{};
    @memcpy(secret.bytes[0.."fixture-secret".len], "fixture-secret");
    secret.len = "fixture-secret".len;
    return secret;
}

fn waitTerminal(registry: *Registry, operation_id: []const u8) !State {
    var attempts: usize = 0;
    while (attempts < 1000) : (attempts += 1) {
        var result = try registry.poll(operation_id, 0, false);
        defer result.poll.deinit(registry.allocator);
        if (result.state.terminal()) return result.state;
        try std.Io.sleep(registry.io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    return error.TestUnexpectedResult;
}

test "provider tests persist an exact revision and credential generation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buffer: [192]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buffer, "/tmp/oars-ai-provider-test-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var path_buffer: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "{s}/ai.json", .{dir});
    var store = provider.Store{ .allocator = allocator, .path = path };
    const selected = try store.save(io, "save-provider", .{ .name = "Fixture", .adapter = .openai_responses, .base_url = "https://example.com/v1", .model = "model" }, null);
    try store.bindCredential(io, selected.id, selected.base_url);
    const generation = (try store.credentialGeneration(io, selected.id, selected.base_url)).?;
    var fake = FakeRunner{};
    var limiter = request_slots.Limiter{};
    var registry = Registry.init(allocator, io, &store, &limiter);
    registry.runner = fake.adapter();
    defer registry.deinit();
    try std.testing.expectEqual(.queued, try registry.admitOwned("provider-test-1", selected, generation, fixtureSecret()));
    try std.testing.expectEqual(.passed, try waitTerminal(&registry, "provider-test-1"));
    var persisted = try store.get(io, selected.id);
    defer persisted.deinit(allocator);
    try std.testing.expectEqual(.passed, persisted.test_status);
}

test "provider test quota is two and cancellation stops admitted work" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buffer: [192]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buffer, "/tmp/oars-ai-provider-quota-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var path_buffer: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "{s}/ai.json", .{dir});
    var store = provider.Store{ .allocator = allocator, .path = path };
    var base = try store.save(io, "save-provider", .{ .name = "Fixture", .adapter = .openai_responses, .base_url = "https://example.com/v1", .model = "model" }, null);
    defer base.deinit(allocator);
    try store.bindCredential(io, base.id, base.base_url);
    const generation = (try store.credentialGeneration(io, base.id, base.base_url)).?;
    var fake = FakeRunner{ .block = true };
    var limiter = request_slots.Limiter{};
    var registry = Registry.init(allocator, io, &store, &limiter);
    registry.runner = fake.adapter();
    defer registry.deinit();
    const first = try store.get(io, base.id);
    try std.testing.expectEqual(.queued, try registry.admitOwned("provider-test-1", first, generation, fixtureSecret()));
    const second = try store.get(io, base.id);
    try std.testing.expectEqual(.queued, try registry.admitOwned("provider-test-2", second, generation, fixtureSecret()));
    try std.testing.expectError(error.Busy, registry.checkCapacity());
    try std.testing.expectEqual(.cancel_requested, try registry.cancel("provider-test-1"));
    try std.testing.expectEqual(.cancel_requested, try registry.cancel("provider-test-2"));
    try std.testing.expectEqual(.canceled, try waitTerminal(&registry, "provider-test-1"));
    try std.testing.expectEqual(.canceled, try waitTerminal(&registry, "provider-test-2"));
}
