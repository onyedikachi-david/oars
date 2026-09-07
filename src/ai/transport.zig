//! Native HTTP transport for one authenticated provider POST.

const std = @import("std");
const types = @import("types.zig");
const provider = @import("provider.zig");
const credentials = @import("credentials.zig");
const sse = @import("sse.zig");

pub const connect_timeout_ns: i128 = 10 * std.time.ns_per_s;
pub const first_byte_timeout_ns: i128 = 30 * std.time.ns_per_s;
pub const idle_timeout_ns: i128 = 30 * std.time.ns_per_s;
pub const total_timeout_ns: i128 = 120 * std.time.ns_per_s;

pub const Error = error{
    InvalidUrl,
    InvalidRequestId,
    RequestTooLarge,
    ConnectFailed,
    WriteFailed,
    HeadersInvalid,
    HeadersTooLarge,
    RedirectRejected,
    AuthenticationFailed,
    RateLimited,
    ServerFailed,
    ProtocolFailed,
    BodyFailed,
    Timeout,
    Canceled,
    OutOfMemory,
};

pub const Cancellation = struct {
    requested: std.atomic.Value(bool) = .init(false),

    pub fn cancel(self: *Cancellation) void {
        self.requested.store(true, .release);
    }

    pub fn isCanceled(self: *const Cancellation) bool {
        return self.requested.load(.acquire);
    }
};

pub const Timeouts = struct {
    connect_ms: i64 = @intCast(connect_timeout_ns / std.time.ns_per_ms),
    first_byte_ms: i64 = @intCast(first_byte_timeout_ns / std.time.ns_per_ms),
    idle_ms: i64 = @intCast(idle_timeout_ns / std.time.ns_per_ms),
    total_ms: i64 = @intCast(total_timeout_ns / std.time.ns_per_ms),
    poll_ms: i64 = 25,
};

pub const Phase = enum(u8) { connecting, waiting_first_byte, streaming, done };

pub const Observer = struct {
    context: ?*anyopaque = null,
    response_fn: *const fn (?*anyopaque, []const u8) void = ignoreResponse,
    progress_fn: *const fn (?*anyopaque, Phase, usize) void = ignoreProgress,

    fn ignoreResponse(_: ?*anyopaque, _: []const u8) void {}
    fn ignoreProgress(_: ?*anyopaque, _: Phase, _: usize) void {}
};

pub const Progress = struct {
    phase: std.atomic.Value(u8) = .init(@intFromEnum(Phase.connecting)),
    started_ms: std.atomic.Value(i64) = .init(0),
    phase_started_ms: std.atomic.Value(i64) = .init(0),
    last_byte_ms: std.atomic.Value(i64) = .init(0),
    received_bytes: std.atomic.Value(usize) = .init(0),
    provider_request_id: [256]u8 = undefined,
    provider_request_id_len: std.atomic.Value(usize) = .init(0),

    fn start(self: *Progress, now_ms: i64) void {
        self.started_ms.store(now_ms, .release);
        self.received_bytes.store(0, .release);
        self.provider_request_id_len.store(0, .release);
        self.set(.connecting, now_ms);
    }

    fn set(self: *Progress, phase: Phase, now_ms: i64) void {
        self.phase_started_ms.store(now_ms, .release);
        self.last_byte_ms.store(now_ms, .release);
        self.phase.store(@intFromEnum(phase), .release);
    }

    fn touch(self: *Progress, now_ms: i64) void {
        self.last_byte_ms.store(now_ms, .release);
    }

    fn current(self: *const Progress) Phase {
        return @enumFromInt(self.phase.load(.acquire));
    }

    fn setRequestId(self: *Progress, request_id: []const u8) void {
        if (request_id.len > 0) @memcpy(self.provider_request_id[0..request_id.len], request_id);
        self.provider_request_id_len.store(request_id.len, .release);
    }

    fn requestId(self: *const Progress) []const u8 {
        return self.provider_request_id[0..self.provider_request_id_len.load(.acquire)];
    }
};

pub const Meta = struct {
    status: u16,
    provider_request_id: [256]u8 = undefined,
    provider_request_id_len: usize = 0,

    pub fn requestId(self: *const Meta) []const u8 {
        return self.provider_request_id[0..self.provider_request_id_len];
    }
};

pub fn composeEndpoint(output: []u8, base_url: []const u8, suffix: []const u8) Error![]const u8 {
    const normalized = provider.normalizeBaseUrl(base_url) catch return error.InvalidUrl;
    if (suffix.len < 2 or suffix[0] != '/' or std.mem.indexOfAny(u8, suffix, "?#\\") != null) return error.InvalidUrl;
    return std.fmt.bufPrint(output, "{s}{s}", .{ normalized, suffix }) catch error.InvalidUrl;
}

fn validRequestId(value: []const u8) bool {
    if (value.len == 0 or value.len > 128) return false;
    for (value) |ch| switch (ch) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', ':', '_', '-' => {},
        else => return false,
    };
    return true;
}

fn copyProviderRequestId(head: std.http.Client.Response.Head, meta: *Meta) Error!void {
    var headers = head.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "x-request-id")) continue;
        if (meta.provider_request_id_len != 0 or header.value.len == 0 or header.value.len > meta.provider_request_id.len) return error.HeadersInvalid;
        for (header.value) |ch| if (ch < 0x20 or ch == 0x7f) return error.HeadersInvalid;
        @memcpy(meta.provider_request_id[0..header.value.len], header.value);
        meta.provider_request_id_len = header.value.len;
    }
}

/// Executes exactly one POST. It never follows a redirect and never retries.
/// Cancellation of a blocked socket is owned by the coordinator through the
/// surrounding `std.Io.Future`; this token covers boundaries between I/O
/// operations and deterministic test fixtures.
pub fn postSse(
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: []const u8,
    secret: *const credentials.SecretBuffer,
    client_request_id: []const u8,
    body: []const u8,
    progress: ?*Progress,
    cancellation: *const Cancellation,
    sink: sse.Sink,
) anyerror!Meta {
    if (!validRequestId(client_request_id)) return error.InvalidRequestId;
    if (body.len == 0 or body.len > types.max_request_body_bytes) return error.RequestTooLarge;
    if (secret.len == 0 or secret.len > credentials.max_secret_bytes) return error.AuthenticationFailed;
    const uri = std.Uri.parse(endpoint) catch return error.InvalidUrl;
    if (progress) |value| value.start(nowMs(io));

    var authorization: ["Bearer ".len + credentials.max_secret_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &authorization);
    @memcpy(authorization[0.."Bearer ".len], "Bearer ");
    @memcpy(authorization["Bearer ".len .. "Bearer ".len + secret.len], secret.slice());
    const authorization_value = authorization[0 .. "Bearer ".len + secret.len];
    const extra_headers = [_]std.http.Header{
        .{ .name = "accept", .value = "text/event-stream" },
        .{ .name = "x-client-request-id", .value = client_request_id },
    };

    if (cancellation.isCanceled()) return error.Canceled;
    var client: std.http.Client = .{ .allocator = allocator, .io = io, .read_buffer_size = types.max_response_headers_bytes };
    defer client.deinit();
    var request = client.request(.POST, uri, .{
        .keep_alive = false,
        .redirect_behavior = .unhandled,
        .headers = .{
            .authorization = .{ .override = authorization_value },
            .content_type = .{ .override = "application/json" },
            .accept_encoding = .{ .override = "identity" },
        },
        .extra_headers = &extra_headers,
    }) catch return error.ConnectFailed;
    defer request.deinit();
    if (cancellation.isCanceled()) return error.Canceled;
    request.sendBodyComplete(@constCast(body)) catch return error.WriteFailed;
    if (progress) |value| value.set(.waiting_first_byte, nowMs(io));
    if (cancellation.isCanceled()) return error.Canceled;
    var response = request.receiveHead(&.{}) catch |err| return switch (err) {
        error.HttpHeadersOversize => error.HeadersTooLarge,
        error.TooManyHttpRedirects => error.RedirectRejected,
        else => error.HeadersInvalid,
    };
    var meta = Meta{ .status = @intFromEnum(response.head.status) };
    try copyProviderRequestId(response.head, &meta);
    if (progress) |value| {
        value.setRequestId(meta.requestId());
        value.set(.streaming, nowMs(io));
    }
    const status = meta.status;
    if (status >= 300 and status < 400) return error.RedirectRejected;
    if (status == 401 or status == 403) return error.AuthenticationFailed;
    if (status == 429) return error.RateLimited;
    if (status >= 500) return error.ServerFailed;
    if (status < 200 or status >= 300) return error.ProtocolFailed;
    const content_type = response.head.content_type orelse return error.ProtocolFailed;
    if (!std.ascii.startsWithIgnoreCase(content_type, "text/event-stream")) return error.ProtocolFailed;

    var transfer_buffer: [8192]u8 = undefined;
    const reader = response.reader(&transfer_buffer);
    var parser = sse.Parser.init(allocator);
    defer parser.deinit();
    while (true) {
        if (cancellation.isCanceled()) return error.Canceled;
        const byte = reader.takeByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return error.BodyFailed,
        };
        if (progress) |value| {
            _ = value.received_bytes.fetchAdd(1, .acq_rel);
            value.touch(nowMs(io));
        }
        try parser.feed(&.{byte}, sink);
    }
    try parser.finish();
    if (progress) |value| value.set(.done, nowMs(io));
    return meta;
}

fn nowMs(io: std.Io) i64 {
    return @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_ms));
}

const PostTaskResult = union(enum) { ok: Meta, failed: anyerror };

const PostTaskArgs = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: []const u8,
    secret: *const credentials.SecretBuffer,
    client_request_id: []const u8,
    body: []const u8,
    progress: *Progress,
    cancellation: *const Cancellation,
    sink: sse.Sink,
};

fn postTask(args: PostTaskArgs) PostTaskResult {
    const meta = postSse(args.allocator, args.io, args.endpoint, args.secret, args.client_request_id, args.body, args.progress, args.cancellation, args.sink) catch |err| return .{ .failed = err };
    return .{ .ok = meta };
}

fn timeoutTick(io: std.Io, milliseconds: i64) void {
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(@intCast(@max(milliseconds, 1))), .awake) catch {};
}

/// Runs one provider POST under cancellable I/O. The surrounding worker owns
/// this select and therefore cancels the blocked connect/read operation before
/// returning a timeout or user cancellation.
pub fn postSseTimed(
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: []const u8,
    secret: *const credentials.SecretBuffer,
    client_request_id: []const u8,
    body: []const u8,
    cancellation: *Cancellation,
    sink: sse.Sink,
    timeouts: Timeouts,
) anyerror!Meta {
    return postSseTimedObserved(allocator, io, endpoint, secret, client_request_id, body, cancellation, sink, timeouts, .{});
}

pub fn postSseTimedObserved(
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: []const u8,
    secret: *const credentials.SecretBuffer,
    client_request_id: []const u8,
    body: []const u8,
    cancellation: *Cancellation,
    sink: sse.Sink,
    timeouts: Timeouts,
    observer: Observer,
) anyerror!Meta {
    var progress = Progress{};
    const started_at = nowMs(io);
    progress.start(started_at);
    var last_progress_at = started_at;
    var response_reported = false;
    const Selected = union(enum) { request: PostTaskResult, tick: void };
    var selected_buffer: [2]Selected = undefined;
    var select = std.Io.Select(Selected).init(io, &selected_buffer);
    defer select.cancelDiscard();
    try select.concurrent(.request, postTask, .{PostTaskArgs{
        .allocator = allocator,
        .io = io,
        .endpoint = endpoint,
        .secret = secret,
        .client_request_id = client_request_id,
        .body = body,
        .progress = &progress,
        .cancellation = cancellation,
        .sink = sink,
    }});
    select.async(.tick, timeoutTick, .{ io, timeouts.poll_ms });
    while (true) switch (try select.await()) {
        .request => |result| return switch (result) {
            .ok => |meta| blk: {
                if (!response_reported) observer.response_fn(observer.context, meta.requestId());
                observer.progress_fn(observer.context, .done, progress.received_bytes.load(.acquire));
                break :blk meta;
            },
            .failed => |err| {
                const phase = progress.current();
                if (!response_reported and (phase == .streaming or phase == .done)) {
                    observer.response_fn(observer.context, progress.requestId());
                }
                return err;
            },
        },
        .tick => {
            const now = nowMs(io);
            const phase = progress.current();
            if (phase == .streaming and !response_reported) {
                observer.response_fn(observer.context, progress.requestId());
                response_reported = true;
            }
            if (phase != .done and now - last_progress_at >= 100) {
                observer.progress_fn(observer.context, phase, progress.received_bytes.load(.acquire));
                last_progress_at = now;
            }
            const total_elapsed = now - progress.started_ms.load(.acquire);
            const phase_elapsed = now - progress.phase_started_ms.load(.acquire);
            const idle_elapsed = now - progress.last_byte_ms.load(.acquire);
            if (cancellation.isCanceled()) return error.Canceled;
            const timed_out = total_elapsed >= timeouts.total_ms or switch (phase) {
                .connecting => phase_elapsed >= timeouts.connect_ms,
                .waiting_first_byte => phase_elapsed >= timeouts.first_byte_ms,
                .streaming => idle_elapsed >= timeouts.idle_ms,
                .done => false,
            };
            if (timed_out) {
                cancellation.cancel();
                return error.Timeout;
            }
            select.async(.tick, timeoutTick, .{ io, timeouts.poll_ms });
        },
    };
}

test "transport composes only reviewed fixed endpoints" {
    var buffer: [600]u8 = undefined;
    try std.testing.expectEqualStrings("https://api.openai.com/v1/responses", try composeEndpoint(&buffer, "https://api.openai.com/v1/", "/responses"));
    try std.testing.expectEqualStrings("http://localhost:11434/v1/chat/completions", try composeEndpoint(&buffer, "http://localhost:11434/v1", "/chat/completions"));
    try std.testing.expectError(error.InvalidUrl, composeEndpoint(&buffer, "https://api.openai.com/v1", "https://evil.example"));
    try std.testing.expectError(error.InvalidUrl, composeEndpoint(&buffer, "https://api.openai.com/v1", "/responses?redirect=1"));
}

test "transport cancellation and request IDs are bounded before network work" {
    var secret = credentials.SecretBuffer{};
    defer secret.clear();
    @memcpy(secret.bytes[0..4], "test");
    secret.len = 4;
    var cancellation = Cancellation{};
    cancellation.cancel();
    const Noop = struct {
        fn event(_: *anyopaque, _: sse.Event) anyerror!void {}
    };
    var byte: u8 = 0;
    const sink = sse.Sink{ .context = &byte, .event_fn = Noop.event };
    try std.testing.expectError(error.Canceled, postSse(std.testing.allocator, std.testing.io, "http://127.0.0.1:1/responses", &secret, "request-1", "{}", null, &cancellation, sink));
    var active = Cancellation{};
    try std.testing.expectError(error.InvalidRequestId, postSse(std.testing.allocator, std.testing.io, "http://127.0.0.1:1/responses", &secret, "bad id", "{}", null, &active, sink));
}

const FixtureMode = enum { success, unauthorized, rate_limited, server_error, redirect, dropped, delayed_headers, stalled_stream };

const Fixture = struct {
    io: std.Io,
    server: *std.Io.net.Server,
    mode: FixtureMode,
    saw_authorization: std.atomic.Value(bool) = .init(false),
    saw_request_id: std.atomic.Value(bool) = .init(false),
    failed: std.atomic.Value(bool) = .init(false),

    fn serve(self: *Fixture) void {
        self.serveFallible() catch self.failed.store(true, .release);
    }

    fn serveFallible(self: *Fixture) !void {
        var stream = try self.server.accept(self.io);
        defer stream.close(self.io);
        var send_buffer: [4096]u8 = undefined;
        var receive_buffer: [4096]u8 = undefined;
        var stream_reader = stream.reader(self.io, &receive_buffer);
        var stream_writer = stream.writer(self.io, &send_buffer);
        var server = std.http.Server.init(&stream_reader.interface, &stream_writer.interface);
        var request = try server.receiveHead();
        var headers = request.iterateHeaders();
        while (headers.next()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "authorization") and std.mem.eql(u8, header.value, "Bearer fixture-secret")) self.saw_authorization.store(true, .release);
            if (std.ascii.eqlIgnoreCase(header.name, "x-client-request-id") and std.mem.eql(u8, header.value, "fixture-request-1")) self.saw_request_id.store(true, .release);
        }
        if (self.mode == .delayed_headers) {
            try std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(200), .awake);
        }
        switch (self.mode) {
            .unauthorized => try request.respond("denied", .{ .status = .unauthorized, .keep_alive = false }),
            .rate_limited => try request.respond("slow down", .{ .status = .too_many_requests, .keep_alive = false }),
            .server_error => try request.respond("failed", .{ .status = .internal_server_error, .keep_alive = false }),
            .redirect => try request.respond("move", .{ .status = .temporary_redirect, .keep_alive = false, .extra_headers = &.{.{ .name = "location", .value = "http://127.0.0.1:1/stolen" }} }),
            .success, .dropped, .delayed_headers, .stalled_stream => {
                const payload = "event: fixture.event\r\ndata: {\"type\":\"fixture.event\",\"ok\":true}\r\n\r\n";
                var body_buffer: [128]u8 = undefined;
                var body = try request.respondStreaming(&body_buffer, .{ .respond_options = .{ .keep_alive = false, .extra_headers = &.{
                    .{ .name = "content-type", .value = "text/event-stream" },
                    .{ .name = "x-request-id", .value = "provider-request-1" },
                } } });
                const limit = if (self.mode == .dropped or self.mode == .stalled_stream) payload.len / 2 else payload.len;
                for (payload[0..limit]) |byte| {
                    try body.writer.writeByte(byte);
                    try body.writer.flush();
                }
                // The incomplete-response fixtures deliberately skip
                // `body.end()`. Flush the server socket buffer first so the
                // client always observes valid headers and a partial body.
                if (self.mode == .dropped or self.mode == .stalled_stream) try stream_writer.interface.flush();
                if (self.mode == .stalled_stream) try std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(200), .awake);
                if (self.mode == .success or self.mode == .delayed_headers) try body.end();
            },
        }
    }
};

const EventCapture = struct {
    count: usize = 0,
    valid: bool = false,

    fn event(context: *anyopaque, value: sse.Event) anyerror!void {
        const self: *EventCapture = @ptrCast(@alignCast(context));
        self.count += 1;
        self.valid = std.mem.eql(u8, value.name, "fixture.event") and std.mem.indexOf(u8, value.data, "\"ok\":true") != null;
    }
};

const ObserverCapture = struct {
    io: std.Io,
    response_count: usize = 0,
    request_id: [256]u8 = undefined,
    request_id_len: usize = 0,
    progress_count: usize = 0,
    progress_times_ms: [16]i64 = @splat(0),

    fn response(context: ?*anyopaque, request_id: []const u8) void {
        const self: *ObserverCapture = @ptrCast(@alignCast(context.?));
        self.response_count += 1;
        self.request_id_len = @min(request_id.len, self.request_id.len);
        @memcpy(self.request_id[0..self.request_id_len], request_id[0..self.request_id_len]);
    }

    fn progress(context: ?*anyopaque, phase: Phase, _: usize) void {
        if (phase == .done) return;
        const self: *ObserverCapture = @ptrCast(@alignCast(context.?));
        if (self.progress_count < self.progress_times_ms.len) {
            self.progress_times_ms[self.progress_count] = nowMs(self.io);
            self.progress_count += 1;
        }
    }
};

fn fixtureEndpoint(server: *const std.Io.net.Server, output: []u8) ![]const u8 {
    return std.fmt.bufPrint(output, "http://127.0.0.1:{d}/v1/responses", .{server.socket.address.getPort()});
}

test "local provider fixture fragments SSE and verifies authorization without logging it" {
    const io = std.testing.io;
    const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    var fixture = Fixture{ .io = io, .server = &server, .mode = .success };
    const thread = try std.Thread.spawn(.{}, Fixture.serve, .{&fixture});
    var endpoint_buffer: [128]u8 = undefined;
    const endpoint = try fixtureEndpoint(&server, &endpoint_buffer);
    var secret = credentials.SecretBuffer{};
    defer secret.clear();
    @memcpy(secret.bytes[0.."fixture-secret".len], "fixture-secret");
    secret.len = "fixture-secret".len;
    var cancellation = Cancellation{};
    var capture = EventCapture{};
    const meta = try postSseTimed(std.testing.allocator, io, endpoint, &secret, "fixture-request-1", "{}", &cancellation, .{ .context = &capture, .event_fn = EventCapture.event }, .{});
    thread.join();
    try std.testing.expect(!fixture.failed.load(.acquire));
    try std.testing.expect(fixture.saw_authorization.load(.acquire));
    try std.testing.expect(fixture.saw_request_id.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    try std.testing.expect(capture.valid);
    try std.testing.expectEqualStrings("provider-request-1", meta.requestId());
}

test "provider observer reports accepted response once and rate limits live progress" {
    const io = std.testing.io;
    const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    var fixture = Fixture{ .io = io, .server = &server, .mode = .stalled_stream };
    const thread = try std.Thread.spawn(.{}, Fixture.serve, .{&fixture});
    var endpoint_buffer: [128]u8 = undefined;
    const endpoint = try fixtureEndpoint(&server, &endpoint_buffer);
    var secret = credentials.SecretBuffer{};
    defer secret.clear();
    @memcpy(secret.bytes[0.."fixture-secret".len], "fixture-secret");
    secret.len = "fixture-secret".len;
    var cancellation = Cancellation{};
    var events_capture = EventCapture{};
    var observer_capture = ObserverCapture{ .io = io };
    const result = postSseTimedObserved(
        std.testing.allocator,
        io,
        endpoint,
        &secret,
        "fixture-observer-1",
        "{}",
        &cancellation,
        .{ .context = &events_capture, .event_fn = EventCapture.event },
        .{ .connect_ms = 1000, .first_byte_ms = 1000, .idle_ms = 1000, .total_ms = 1000, .poll_ms = 5 },
        .{ .context = &observer_capture, .response_fn = ObserverCapture.response, .progress_fn = ObserverCapture.progress },
    );
    thread.join();
    try std.testing.expectError(error.BodyFailed, result);
    try std.testing.expectEqual(@as(usize, 1), observer_capture.response_count);
    try std.testing.expectEqualStrings("provider-request-1", observer_capture.request_id[0..observer_capture.request_id_len]);
    try std.testing.expect(observer_capture.progress_count >= 1);
    for (observer_capture.progress_times_ms[1..observer_capture.progress_count], observer_capture.progress_times_ms[0 .. observer_capture.progress_count - 1]) |current, previous| {
        try std.testing.expect(current - previous >= 95);
    }
}

fn expectFixtureError(mode: FixtureMode, expected: anyerror) !void {
    const io = std.testing.io;
    const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    var fixture = Fixture{ .io = io, .server = &server, .mode = mode };
    const thread = try std.Thread.spawn(.{}, Fixture.serve, .{&fixture});
    var endpoint_buffer: [128]u8 = undefined;
    const endpoint = try fixtureEndpoint(&server, &endpoint_buffer);
    var secret = credentials.SecretBuffer{};
    defer secret.clear();
    @memcpy(secret.bytes[0.."fixture-secret".len], "fixture-secret");
    secret.len = "fixture-secret".len;
    var cancellation = Cancellation{};
    var capture = EventCapture{};
    const result = postSseTimed(std.testing.allocator, io, endpoint, &secret, "fixture-request-1", "{}", &cancellation, .{ .context = &capture, .event_fn = EventCapture.event }, .{});
    if (result) |_| {
        thread.join();
        return error.TestUnexpectedResult;
    } else |err| {
        thread.join();
        // A peer that closes during a fragmented body can surface either at
        // response-head completion or at the body reader boundary. Both are
        // protocol failures and neither path retries the authenticated POST.
        try std.testing.expectEqual(expected, err);
    }
    try std.testing.expect(!fixture.failed.load(.acquire));
    try std.testing.expect(fixture.saw_authorization.load(.acquire));
}

test "local provider fixture classifies status redirect and dropped stream without retry" {
    try expectFixtureError(.unauthorized, error.AuthenticationFailed);
    try expectFixtureError(.rate_limited, error.RateLimited);
    try expectFixtureError(.server_error, error.ServerFailed);
    try expectFixtureError(.redirect, error.RedirectRejected);
    try expectFixtureError(.dropped, error.BodyFailed);
}

fn runTimedFixture(mode: FixtureMode, cancellation: *Cancellation, timeouts: Timeouts) anyerror!void {
    const io = std.testing.io;
    const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    var fixture = Fixture{ .io = io, .server = &server, .mode = mode };
    const thread = try std.Thread.spawn(.{}, Fixture.serve, .{&fixture});
    var endpoint_buffer: [128]u8 = undefined;
    const endpoint = try fixtureEndpoint(&server, &endpoint_buffer);
    var secret = credentials.SecretBuffer{};
    defer secret.clear();
    @memcpy(secret.bytes[0.."fixture-secret".len], "fixture-secret");
    secret.len = "fixture-secret".len;
    var capture = EventCapture{};
    _ = postSseTimed(std.testing.allocator, io, endpoint, &secret, "fixture-request-1", "{}", cancellation, .{ .context = &capture, .event_fn = EventCapture.event }, timeouts) catch |err| {
        thread.join();
        return err;
    };
    thread.join();
    return error.TestUnexpectedResult;
}

const CancelArgs = struct { io: std.Io, cancellation: *Cancellation };

fn cancelSoon(args: CancelArgs) void {
    std.Io.sleep(args.io, std.Io.Duration.fromMilliseconds(25), .awake) catch {};
    args.cancellation.cancel();
}

test "local provider fixture enforces first-byte idle and user cancellation" {
    const short = Timeouts{ .connect_ms = 1000, .first_byte_ms = 40, .idle_ms = 40, .total_ms = 1000, .poll_ms = 5 };
    var first = Cancellation{};
    try std.testing.expectError(error.Timeout, runTimedFixture(.delayed_headers, &first, short));
    var idle = Cancellation{};
    try std.testing.expectError(error.Timeout, runTimedFixture(.stalled_stream, &idle, short));
    var canceled = Cancellation{};
    const cancel_thread = try std.Thread.spawn(.{}, cancelSoon, .{CancelArgs{ .io = std.testing.io, .cancellation = &canceled }});
    const canceled_result = runTimedFixture(.delayed_headers, &canceled, .{ .connect_ms = 1000, .first_byte_ms = 1000, .idle_ms = 1000, .total_ms = 1000, .poll_ms = 5 });
    cancel_thread.join();
    try std.testing.expectError(error.Canceled, canceled_result);
}
