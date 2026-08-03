//! Bridge command handlers for Oars.
//!
//! All `oars.*` commands are policy-gated by origin (`zero://app` in
//! production, the Vite dev server origin in development). Handlers run
//! on the runtime's main thread and never block on the network; the
//! session manager owns all SSH worker threads.

const std = @import("std");
const native_sdk = @import("native_sdk");
const servers = @import("servers.zig");
const sessions = @import("sessions.zig");
const monitor = @import("monitor.zig");
const audit = @import("audit.zig");
const json = @import("json.zig");
const logs = @import("logs.zig");
const shellquote = @import("shellquote.zig");

pub const allowed_origins = [_][]const u8{ "zero://app", "http://127.0.0.1:5173" };

const handler_count = 21;

pub const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    store: *servers.Store,
    manager: *sessions.Manager,
    audit: *audit.Store,
    logs: *logs.SourceStore,
    handlers: [handler_count]native_sdk.BridgeHandler = undefined,
    policies: [handler_count]native_sdk.BridgeCommandPolicy = undefined,

    pub fn dispatcher(self: *Context) native_sdk.BridgeDispatcher {
        self.handlers = .{
            .{ .name = "oars.servers.list", .context = self, .invoke_fn = handleServersList },
            .{ .name = "oars.servers.save", .context = self, .invoke_fn = handleServersSave },
            .{ .name = "oars.servers.delete", .context = self, .invoke_fn = handleServersDelete },
            .{ .name = "oars.ssh.connect", .context = self, .invoke_fn = handleSshConnect },
            .{ .name = "oars.ssh.disconnect", .context = self, .invoke_fn = handleSshDisconnect },
            .{ .name = "oars.ssh.input", .context = self, .invoke_fn = handleSshInput },
            .{ .name = "oars.ssh.exec", .context = self, .invoke_fn = handleSshExec },
            .{ .name = "oars.ssh.closeChannel", .context = self, .invoke_fn = handleSshCloseChannel },
            .{ .name = "oars.ssh.resize", .context = self, .invoke_fn = handleSshResize },
            .{ .name = "oars.ssh.trust", .context = self, .invoke_fn = handleSshTrust },
            .{ .name = "oars.ssh.poll", .context = self, .invoke_fn = handleSshPoll },
            .{ .name = "oars.monitor.poll", .context = self, .invoke_fn = handleMonitorPoll },
            .{ .name = "oars.monitor.probe", .context = self, .invoke_fn = handleMonitorProbe },
            .{ .name = "oars.monitor.cleanDiskEstimate", .context = self, .invoke_fn = handleMonitorCleanDiskEstimate },
            .{ .name = "oars.monitor.cleanDisk", .context = self, .invoke_fn = handleMonitorCleanDisk },
            .{ .name = "oars.monitor.dropCaches", .context = self, .invoke_fn = handleMonitorDropCaches },
            .{ .name = "oars.logs.scan", .context = self, .invoke_fn = handleLogsScan },
            .{ .name = "oars.logs.read", .context = self, .invoke_fn = handleLogsRead },
            .{ .name = "oars.logs.follow", .context = self, .invoke_fn = handleLogsFollow },
            .{ .name = "oars.logs.clear", .context = self, .invoke_fn = handleLogsClear },
            .{ .name = "oars.logs.addSource", .context = self, .invoke_fn = handleLogsAddSource },
        };
        self.policies = .{
            .{ .name = "oars.servers.list", .origins = &allowed_origins },
            .{ .name = "oars.servers.save", .origins = &allowed_origins },
            .{ .name = "oars.servers.delete", .origins = &allowed_origins },
            .{ .name = "oars.ssh.connect", .origins = &allowed_origins },
            .{ .name = "oars.ssh.disconnect", .origins = &allowed_origins },
            .{ .name = "oars.ssh.input", .origins = &allowed_origins },
            .{ .name = "oars.ssh.exec", .origins = &allowed_origins },
            .{ .name = "oars.ssh.closeChannel", .origins = &allowed_origins },
            .{ .name = "oars.ssh.resize", .origins = &allowed_origins },
            .{ .name = "oars.ssh.trust", .origins = &allowed_origins },
            .{ .name = "oars.ssh.poll", .origins = &allowed_origins },
            .{ .name = "oars.monitor.poll", .origins = &allowed_origins },
            .{ .name = "oars.monitor.probe", .origins = &allowed_origins },
            .{ .name = "oars.monitor.cleanDiskEstimate", .origins = &allowed_origins },
            .{ .name = "oars.monitor.cleanDisk", .origins = &allowed_origins },
            .{ .name = "oars.monitor.dropCaches", .origins = &allowed_origins },
            .{ .name = "oars.logs.scan", .origins = &allowed_origins },
            .{ .name = "oars.logs.read", .origins = &allowed_origins },
            .{ .name = "oars.logs.follow", .origins = &allowed_origins },
            .{ .name = "oars.logs.clear", .origins = &allowed_origins },
            .{ .name = "oars.logs.addSource", .origins = &allowed_origins },
        };
        return .{
            .policy = .{ .enabled = true, .commands = &self.policies },
            .registry = .{ .handlers = &self.handlers },
        };
    }
};

fn contextOf(context: *anyopaque) *Context {
    return @ptrCast(@alignCast(context));
}

const HandlerFn = *const fn (context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8;

/// User-facing error result: resolves the invoke with ok:false so the
/// frontend can show a message without a framework-level rejection.
fn respondError(output: []u8, message: []const u8) []const u8 {
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":false,\"error\":") catch return output[0..0];
    json.writeJsonString(&writer, message) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

const ok_json = "{\"ok\":true}";

// --- payload parsing ------------------------------------------------------

fn parsePayload(comptime T: type, allocator: std.mem.Allocator, payload: []const u8) !std.json.Parsed(T) {
    return std.json.parseFromSlice(T, allocator, payload, .{});
}

// --- servers --------------------------------------------------------------

fn handleServersList(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    _ = invocation;
    const self = contextOf(context);
    var loaded = self.store.loadParsed(self.io) catch {
        return "{\"ok\":false,\"error\":\"failed to load servers\"}";
    };
    defer loaded.deinit(self.allocator);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"servers\":") catch return output[0..0];
    std.json.Stringify.value(loaded.parsed.value, .{}, &writer) catch return output[0..0];
    if (loaded.quarantined) |q| {
        var msg_buf: [640]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "servers.json was unreadable and was moved to {s}; the server list starts fresh", .{q}) catch "servers.json was unreadable and was moved aside";
        writer.writeAll(",\"recovery_error\":") catch return output[0..0];
        json.writeJsonString(&writer, msg) catch return output[0..0];
    }
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

const SavePayload = struct {
    id: ?[]const u8 = null,
    name: []const u8,
    host: []const u8,
    port: u16 = 22,
    user: []const u8,
    auth_method: []const u8,
    key_path: ?[]const u8 = null,
    key_has_passphrase: bool = false,
    group: ?[]const u8 = null,
    tags: ?[][]const u8 = null,
    via_server_id: ?[]const u8 = null,
};

fn handleServersSave(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SavePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    const auth_method = servers.AuthMethod.fromJsonName(payload.auth_method) orelse {
        return respondError(output, "unknown auth method");
    };

    // Host names are trimmed; a trailing slash is not part of an SSH host
    // and is rejected rather than silently stripped (spec 01 §10).
    const host = std.mem.trim(u8, payload.host, " \t\r\n");
    if (host.len == 0) return respondError(output, "host is required");
    if (host[host.len - 1] == '/') return respondError(output, "host must not end with '/'");
    if (payload.port == 0) return respondError(output, "port must be between 1 and 65535");

    const key_path = std.mem.trim(u8, payload.key_path orelse "", " \t\r\n");
    if (auth_method == .key) {
        if (key_path.len == 0) {
            return respondError(output, "choose a private key file");
        }
        // Refuse to persist a key path we cannot read (a paste of the
        // whole "ssh -i key host" command line is the classic mistake).
        const expanded = servers.expandHome(self.allocator, key_path, self.manager.home) catch {
            return respondError(output, "out of memory");
        };
        defer self.allocator.free(expanded);
        std.Io.Dir.cwd().access(self.io, expanded, .{}) catch {
            var msg_buf: [512]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "private key file not readable: {s}", .{expanded}) catch "private key file not readable";
            return respondError(output, msg);
        };
    }

    // Tags are normalized: trimmed, empties dropped, duplicates removed.
    var tags: std.ArrayList([]const u8) = .empty;
    defer {
        for (tags.items) |t| self.allocator.free(t);
        tags.deinit(self.allocator);
    }
    if (payload.tags) |incoming| {
        for (incoming) |raw| {
            const tag = std.mem.trim(u8, raw, " \t\r\n");
            if (tag.len == 0) continue;
            var dup = false;
            for (tags.items) |existing| {
                if (std.mem.eql(u8, existing, tag)) {
                    dup = true;
                    break;
                }
            }
            if (dup) continue;
            tags.append(self.allocator, self.allocator.dupe(u8, tag) catch return respondError(output, "out of memory")) catch return respondError(output, "out of memory");
        }
    }

    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    var owned_id: ?[]const u8 = null;
    defer if (owned_id) |o| self.allocator.free(o);
    const id = payload.id orelse blk: {
        owned_id = servers.makeId(self.allocator, now) catch {
            return respondError(output, "out of memory");
        };
        break :blk owned_id.?;
    };

    // Edits preserve created_at, and keep the trusted host fingerprint
    // only while the endpoint (host+port) is unchanged (spec 01 §5).
    var loaded = self.store.loadParsed(self.io) catch {
        return respondError(output, "failed to load servers");
    };
    defer loaded.deinit(self.allocator);
    var created_at: i64 = @intCast(now);
    var host_fingerprint: ?[]const u8 = null;
    if (payload.id) |pid| {
        for (loaded.parsed.value) |existing| {
            if (std.mem.eql(u8, existing.id, pid)) {
                created_at = existing.created_at;
                if (std.mem.eql(u8, existing.host, host) and existing.port == payload.port) {
                    host_fingerprint = existing.host_fingerprint;
                }
                break;
            }
        }
    }

    const server = servers.Server{
        .id = id,
        .name = payload.name,
        .host = host,
        .port = payload.port,
        .user = payload.user,
        .auth_method = auth_method,
        .key_path = key_path,
        .key_has_passphrase = payload.key_has_passphrase,
        .host_fingerprint = host_fingerprint,
        .group = payload.group orelse "",
        .tags = tags.items,
        .via_server_id = payload.via_server_id,
        .created_at = created_at,
        .updated_at = @intCast(now),
    };

    // Jump chains are validated against the saved set at save time:
    // existing references, no self-links, depth <= 3, no cycles (spec 18).
    servers.validateViaChain(server, loaded.parsed.value) catch |err| {
        return respondError(output, switch (err) {
            error.SelfLink => "a server cannot connect via itself",
            error.MissingVia => "the configured jump host does not exist",
            error.ChainTooDeep => "jump chains are limited to 3 hops",
            error.Cycle => "jump chain contains a cycle",
        });
    };

    self.store.upsert(self.io, server) catch {
        return respondError(output, "failed to save server");
    };

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"server\":") catch return output[0..0];
    writeServer(&writer, server) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn writeServer(writer: anytype, server: servers.Server) !void {
    try writer.writeAll("{\"id\":");
    try json.writeJsonString(writer, server.id);
    try writer.writeAll(",\"name\":");
    try json.writeJsonString(writer, server.name);
    try writer.writeAll(",\"host\":");
    try json.writeJsonString(writer, server.host);
    try writer.print(",\"port\":{d}", .{server.port});
    try writer.writeAll(",\"user\":");
    try json.writeJsonString(writer, server.user);
    try writer.writeAll(",\"auth_method\":");
    try json.writeJsonString(writer, server.auth_method.jsonName());
    try writer.writeAll(",\"key_path\":");
    try json.writeJsonString(writer, server.key_path);
    try writer.print(",\"key_has_passphrase\":{s}", .{if (server.key_has_passphrase) "true" else "false"});
    try writer.writeAll(",\"host_fingerprint\":");
    if (server.host_fingerprint) |fp| {
        try json.writeJsonString(writer, fp);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"group\":");
    try json.writeJsonString(writer, server.group);
    try writer.writeAll(",\"tags\":[");
    for (server.tags, 0..) |tag, i| {
        if (i > 0) try writer.writeByte(',');
        try json.writeJsonString(writer, tag);
    }
    try writer.writeAll("],\"via_server_id\":");
    if (server.via_server_id) |via| {
        try json.writeJsonString(writer, via);
    } else {
        try writer.writeAll("null");
    }
    try writer.print(",\"created_at\":{d},\"updated_at\":{d}}}", .{ server.created_at, server.updated_at });
}

const DeletePayload = struct {
    id: []const u8,
};

fn handleServersDelete(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeletePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.disconnect(parsed.value.id);
    self.store.delete(self.io, parsed.value.id) catch {
        return respondError(output, "failed to delete server");
    };
    return ok_json;
}

// --- ssh ------------------------------------------------------------------

const ConnectPayload = struct {
    server_id: []const u8,
    password: ?[]const u8 = null,
    passphrase: ?[]const u8 = null,
};

fn handleSshConnect(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ConnectPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    const server = self.store.find(self.io, payload.server_id) catch {
        return respondError(output, "failed to load server");
    } orelse {
        return respondError(output, "server not found");
    };
    defer {
        var s = server;
        s.deinit(self.allocator);
    }

    _ = self.manager.connect(server, payload.password, payload.passphrase) catch |err| {
        if (err == error.AlreadyConnected) {
            // Idempotent connect (spec 02 §5): success carrying the live
            // session status, never a text-coupled error.
            if (self.manager.get(server.id)) |existing| {
                var writer = std.Io.Writer.fixed(output);
                writer.print("{{\"ok\":true,\"status\":\"{s}\"}}", .{existing.status.load(.acquire).jsonName()}) catch return output[0..0];
                return writer.buffered();
            }
            return ok_json;
        }
        return respondError(output, "failed to start connection");
    };
    return ok_json;
}

const IdPayload = struct {
    server_id: []const u8,
};

fn handleSshDisconnect(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(IdPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.disconnect(parsed.value.server_id);
    return ok_json;
}

const InputPayload = struct {
    server_id: []const u8,
    data: []const u8,
};

fn handleSshInput(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(InputPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.input(parsed.value.server_id, parsed.value.data) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "input failed",
        });
    };
    return ok_json;
}

const ExecPayload = struct {
    server_id: []const u8,
    command: []const u8,
};

fn handleSshExec(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ExecPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const channel_id = self.manager.exec(parsed.value.server_id, parsed.value.command) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "exec failed",
        });
    };
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel_id}) catch return output[0..0];
    return writer.buffered();
}

const CloseChannelPayload = struct {
    server_id: []const u8,
    channel: u32,
};

/// Explicit channel close (spec 04 follow channels; spec 02 §5): the worker
/// sends EOF, closes the raw channel, and frees the entry.
fn handleSshCloseChannel(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(CloseChannelPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.closeChannel(parsed.value.server_id, parsed.value.channel) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.InvalidChannel => "cannot close the shell channel",
            else => "close failed",
        });
    };
    return ok_json;
}

const ResizePayload = struct {
    server_id: []const u8,
    cols: u16,
    rows: u16,
};

fn handleSshResize(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ResizePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.resize(parsed.value.server_id, parsed.value.cols, parsed.value.rows) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            else => "resize failed",
        });
    };
    return ok_json;
}

const TrustPayload = struct {
    server_id: []const u8,
    accept: bool,
};

fn handleSshTrust(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(TrustPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.trust(parsed.value.server_id, parsed.value.accept) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotPending => "no trust decision pending",
            else => "trust failed",
        });
    };
    return ok_json;
}

const PollPayload = struct {
    server_id: []const u8,
    /// Per-channel absolute cursors for the requesting tab (spec 02 §5),
    /// e.g. [{"channel":0,"cursor":1200}].
    cursors: ?[]const PollCursor = null,
    rewind: bool = false,
};

const PollCursor = struct {
    channel: u32,
    cursor: u64,
};

const poll_data_budget: usize = 384 * 1024;
const poll_channel_budget: usize = 256 * 1024;

fn handleSshPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(PollPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();

    const info = self.manager.sessionSnapshot(parsed.value.server_id) catch {
        return "{\"ok\":true,\"status\":\"closed\",\"error\":\"\",\"trust\":{\"pending\":false},\"channels\":[]}";
    };

    // The requesting tab's cursors: channel id -> absolute position.
    var cursors: std.ArrayList(sessions.Cursor) = .empty;
    defer cursors.deinit(self.allocator);
    if (parsed.value.cursors) |incoming| {
        for (incoming) |c| {
            cursors.append(self.allocator, .{ .id = c.channel, .pos = c.cursor }) catch continue;
        }
    }

    const polls = self.manager.pollChannels(
        parsed.value.server_id,
        cursors.items,
        parsed.value.rewind,
        poll_data_budget,
        poll_channel_budget,
    ) catch {
        return "{\"ok\":true,\"status\":\"closed\",\"error\":\"\",\"trust\":{\"pending\":false},\"channels\":[]}";
    };
    defer {
        for (polls) |*p| p.deinit(self.allocator);
        self.allocator.free(polls);
    }

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"status\":") catch return output[0..0];
    json.writeJsonString(&writer, info.status.jsonName()) catch return output[0..0];
    writer.writeAll(",\"error\":") catch return output[0..0];
    json.writeJsonString(&writer, info.@"error") catch return output[0..0];
    writer.writeAll(",\"trust\":{") catch return output[0..0];
    if (info.trust_pending) {
        writer.writeAll("\"pending\":true,\"fingerprint\":") catch return output[0..0];
        json.writeJsonString(&writer, info.trust_fingerprint) catch return output[0..0];
    } else {
        writer.writeAll("\"pending\":false") catch return output[0..0];
    }
    writer.writeAll("},\"channels\":[") catch return output[0..0];

    var first = true;
    for (polls) |ch| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.print("{{\"id\":{d},\"kind\":", .{ch.id}) catch return output[0..0];
        json.writeJsonString(&writer, ch.kind.jsonName()) catch return output[0..0];
        writer.writeAll(",\"command\":") catch return output[0..0];
        json.writeJsonString(&writer, ch.command) catch return output[0..0];
        writer.print(",\"cursor\":{d},\"dropped\":{d},\"pending\":{d},\"eof\":{s},\"exit\":", .{
            ch.cursor, ch.gap, ch.pending, if (ch.eof) "true" else "false",
        }) catch return output[0..0];
        if (ch.exit_status) |status| {
            writer.print("{d}", .{status}) catch return output[0..0];
        } else {
            writer.writeAll("null") catch return output[0..0];
        }
        writer.writeAll(",\"data\":") catch return output[0..0];
        json.writeJsonString(&writer, ch.data) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

// --- monitor (spec 03) ----------------------------------------------------

/// Not-ready envelope: the monitor contract has exactly two statuses
/// (spec 03 §10) and the UI shows "waiting for connection".
const monitor_not_ready = "{\"ok\":true,\"status\":\"not_ready\"}";

/// Cached snapshot, refreshed on demand: marks poll activity (the probe
/// liveness heartbeat) and enqueues one probe when the cache is stale and
/// none is running. Never blocks on the network.
fn handleMonitorPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(IdPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();

    const session = self.manager.get(parsed.value.server_id) orelse return monitor_not_ready;
    if (session.status.load(.acquire) != .ready) return monitor_not_ready;

    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    session.monitor_last_poll_ns.store(now, .release);
    // Refresh-if-stale: enqueue one probe when the cache is stale and no
    // probe is already running (spec 03 §6).
    if (now - session.monitor_last_probe_ns.load(.acquire) >= session.monitor_interval_ns and
        !session.monitor_probe_active.load(.acquire))
    {
        session.monitor_force.store(true, .release);
    }

    session.monitor_cache.lock();
    defer session.monitor_cache.unlock();
    const snap = session.monitor_cache.current() orelse &monitor_empty_snapshot;
    var writer = std.Io.Writer.fixed(output);
    // Spec 03 §5: the snapshot fields are the payload, flat with `ok`.
    const payload = .{
        .ok = true,
        .ts = snap.ts,
        .cpu = snap.cpu,
        .mem = snap.mem,
        .disk = snap.disk,
        .processes = snap.processes,
        .probe_error = snap.probe_error,
    };
    std.json.Stringify.value(payload, .{}, &writer) catch return output[0..0];
    return writer.buffered();
}

/// Honest "no sample yet" state: real zeros and an explicit reason, never
/// fabricated gauge values.
const monitor_empty_snapshot = monitor.Snapshot{ .probe_error = "no sample yet" };

/// Manual refresh: enqueues a probe immediately.
fn handleMonitorProbe(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(IdPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    self.manager.monitorForce(parsed.value.server_id, now) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
        });
    };
    return ok_json;
}

/// Read-only preview for a disk plan (spec 03 §6: each plan has its own
/// preview before any cleanup runs). Output streams on the channel.
fn handleMonitorCleanDiskEstimate(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(CleanDiskPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const plan = monitor.DiskPlan.fromJsonName(parsed.value.plan) orelse {
        return respondError(output, "unknown disk plan");
    };
    const channel_id = self.manager.exec(parsed.value.server_id, plan.estimateCommand()) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "estimate failed",
        });
    };
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel_id}) catch return output[0..0];
    return writer.buffered();
}

const CleanDiskPayload = struct {
    server_id: []const u8,
    plan: []const u8,
};

/// Mutating disk cleanup for one fixed plan (spec 03 §6). Approval is the
/// frontend's confirmation; every execution is audited.
fn handleMonitorCleanDisk(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(CleanDiskPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const plan = monitor.DiskPlan.fromJsonName(parsed.value.plan) orelse {
        return respondError(output, "unknown disk plan");
    };
    const channel_id = self.manager.exec(parsed.value.server_id, plan.command()) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "cleanup failed",
        });
    };
    var detail_buf: [64]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "plan={s}", .{plan.jsonName()}) catch "plan";
    self.audit.append(self.io, .{
        .ts = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds),
        .action = "monitor.clean_disk",
        .server_id = parsed.value.server_id,
        .detail = detail,
    }) catch {
        return respondError(output, "cleanup ran but the audit entry could not be written");
    };
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel_id}) catch return output[0..0];
    return writer.buffered();
}

const DropCachesPayload = struct {
    server_id: []const u8,
    level: u8 = monitor.drop_cache_default,
};

/// Advanced diagnostics: `sync` then write the selected kernel-documented
/// value to /proc/sys/vm/drop_caches (spec 03 §6). The exact choice and the
/// before snapshot are audited at issue time; the worker records the after
/// snapshot when the forced probe completes.
fn handleMonitorDropCaches(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DropCachesPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const level = parsed.value.level;
    if (level < 1 or level > 3) return respondError(output, "drop-caches level must be 1, 2, or 3");

    const session = self.manager.get(parsed.value.server_id) orelse {
        return respondError(output, "not connected");
    };
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");

    // Before snapshot for the audit record.
    session.monitor_cache.lock();
    const before = if (session.monitor_cache.current()) |s| s.* else monitor.Snapshot{};
    session.monitor_cache.unlock();

    var cmd_buf: [64]u8 = undefined;
    const command = std.fmt.bufPrint(&cmd_buf, monitor.drop_cache_command, .{level}) catch {
        return respondError(output, "invalid drop-caches level");
    };
    const channel_id = self.manager.exec(parsed.value.server_id, command) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "drop-caches failed",
        });
    };

    var detail_buf: [512]u8 = undefined;
    const detail = std.fmt.bufPrint(
        &detail_buf,
        "level={d} before_mem_used_bytes={d} before_mem_available_bytes={d}",
        .{ level, before.mem.used_bytes, before.mem.available_bytes },
    ) catch "drop_caches";
    self.audit.append(self.io, .{
        .ts = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds),
        .action = "monitor.drop_caches",
        .server_id = parsed.value.server_id,
        .detail = detail,
    }) catch {
        return respondError(output, "drop-caches ran but the audit entry could not be written");
    };
    session.monitor_drop_pending.store(true, .release);
    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    self.manager.monitorForce(parsed.value.server_id, now) catch {};

    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel_id}) catch return output[0..0];
    return writer.buffered();
}

// --- logs (spec 04) --------------------------------------------------------

const LogsIdPayload = struct {
    server_id: []const u8,
};

const LogsPathPayload = struct {
    server_id: []const u8,
    path: []const u8,
};

const logs_scan_timeout_ns = 15 * std.time.ns_per_s;
const logs_read_timeout_ns = 10 * std.time.ns_per_s;
const logs_clear_wait_ns = 20 * std.time.ns_per_s;
/// Read byte cap: the SDK result buffer is 1 MB and escaped JSON needs
/// headroom, so a full 5,000-line response cannot exceed this (spec 04 §5).
const logs_read_byte_cap: usize = 160 * 1024;
const logs_scan_cmd_cap: usize = 256 * 1024;
const logs_readability_cmd_cap: usize = 128 * 1024;

/// The scan is ONE exec, marker-delimited like the monitor probe:
/// `%BEGIN_DATE%` carries the remote clock (ages are computed against it,
/// never the local workstation clock) and `%BEGIN_SCAN%` carries NUL-
/// delimited records (`path\0size\0mtime\0mode\0`). Markers are emitted
/// with `%%` escapes — busybox printf errors on `%B`-style directives, so
/// a bare `%BEGIN_X%` format prints nothing (verified live); `%%` works on
/// both busybox and GNU. The GNU `find -printf` form and the busybox
/// `-print0` + `stat` fallback are joined with `||` (not `;`): a find
/// without `-printf` fails over instead of emitting two streams. The
/// trailing `printf '\0'` makes an empty tree parse as zero records
/// instead of degrading to the bare-path fallback.
const logs_scan_prefix = "printf '%%BEGIN_DATE%%\\n'; date +%s; printf '%%BEGIN_SCAN%%\\n'; find ";
const logs_scan_middle = " -maxdepth 3 -type f -printf '%p\\0%s\\0%T@\\0%m\\0' 2>/dev/null || find ";
const logs_scan_suffix = " -maxdepth 3 -type f -print0 2>/dev/null | while IFS= read -r -d '' p; do printf '%s\\0' \"$p\"; (stat -c '%s %Y %a' \"$p\" 2>/dev/null || printf '0 0 0\\n') | tr ' \\n' '\\000\\000'; done; printf '\\0'";

const logs_empty_result = logs.ScanResult{};

/// Serializes a scan result. The caller must own `result` (or hold the
/// cache lock) for the duration. Returns an empty slice only on a
/// response-budget failure (the caller turns that into an explicit error).
fn writeScanResult(output: []u8, result: *const logs.ScanResult) []const u8 {
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"sources\":[") catch return output[0..0];
    for (result.entries, 0..) |entry, i| {
        if (i > 0) writer.writeAll(",") catch return output[0..0];
        writer.writeAll("{\"path\":") catch return output[0..0];
        json.writeJsonString(&writer, entry.path) catch return output[0..0];
        writer.writeAll(",\"group\":") catch return output[0..0];
        json.writeJsonString(&writer, entry.group) catch return output[0..0];
        writer.writeAll(",\"name\":") catch return output[0..0];
        json.writeJsonString(&writer, entry.name) catch return output[0..0];
        writer.print(",\"size\":{d},\"mtime_epoch\":{d},\"age_sec\":{d},\"mode\":{d},\"readable\":{s}", .{
            entry.size,                              entry.mtime_epoch, entry.age_sec, entry.mode,
            if (entry.readable) "true" else "false",
        }) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.print("],\"partial\":{s},\"reason\":", .{if (result.partial) "true" else "false"}) catch return output[0..0];
    json.writeJsonString(&writer, result.reason) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

/// Scans documented log locations (spec 04 §5): one exec, cached per
/// session for 60 s; the cache serves repeats without network traffic.
fn handleLogsScan(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(LogsIdPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const server_id = parsed.value.server_id;

    const session = self.manager.get(server_id) orelse {
        return respondError(output, "not connected");
    };
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");

    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;

    // Serve the 60 s cache when fresh (spec 04 §4). The result strings are
    // owned by the cache, so serialization happens under its lock.
    session.logs_cache.lock();
    if (session.logs_cache.fresh(now)) {
        const cached = session.logs_cache.get() orelse &logs_empty_result;
        const written = writeScanResult(output, cached);
        session.logs_cache.unlock();
        return written;
    }
    session.logs_cache.unlock();

    // Fresh scan. Roots = the documented /var/log tree + user-added paths
    // (spec 04 §5: the scan includes user-added sources).
    const added = self.logs.pathsFor(self.io, server_id) catch {
        return respondError(output, "failed to load log sources");
    };
    defer {
        for (added) |p| self.allocator.free(p);
        self.allocator.free(added);
    }

    var roots: std.ArrayList(u8) = .empty;
    defer roots.deinit(self.allocator);
    roots.appendSlice(self.allocator, "'/var/log'") catch {
        return respondError(output, "out of memory");
    };
    for (added) |p| {
        const qlen = shellquote.quotedLen(p);
        if (roots.items.len + qlen + 1 > logs_scan_cmd_cap) break;
        roots.append(self.allocator, ' ') catch {
            return respondError(output, "out of memory");
        };
        var scratch: [64 * 1024]u8 = undefined;
        if (qlen > scratch.len) break;
        roots.appendSlice(self.allocator, shellquote.quoteAppend(&scratch, p)) catch {
            return respondError(output, "out of memory");
        };
    }

    var cmd_buf: [logs_scan_cmd_cap]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "{s}{s}{s}{s}{s}", .{
        logs_scan_prefix, roots.items, logs_scan_middle, roots.items, logs_scan_suffix,
    }) catch {
        return respondError(output, "scan roots too large");
    };

    var outcome = self.manager.execWait(server_id, cmd, logs.max_scan_bytes, logs_scan_timeout_ns) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "scan failed",
        });
    };
    defer outcome.output.deinit(self.allocator);
    if (outcome.limited) return respondError(output, "scan output exceeded the capture cap");
    if (outcome.exit != 0) return respondError(output, "scan command failed");
    if (outcome.output.items.len == 0) return respondError(output, "scan returned no output");

    var result_owned = false;
    var result = logs.parseScanOutput(self.allocator, outcome.output.items) catch {
        return respondError(output, "scan output could not be parsed");
    };
    defer if (!result_owned) result.deinit(self.allocator);

    // Batched readability probe (spec 04 §5: `test -r` per source; only
    // the first max_probe_paths entries, paths that fit the command
    // budget). Unprobed entries stay readable:false — honest, never a lie.
    var probe_buf: [logs_readability_cmd_cap]u8 = undefined;
    var probe_len: usize = 0;
    var probed: usize = 0;
    for (result.entries, 0..) |entry, i| {
        if (i >= logs.max_probe_paths) break;
        const qlen = shellquote.quotedLen(entry.path);
        if (qlen > probe_buf.len or probe_len + qlen + 40 > probe_buf.len) break;
        const head = std.fmt.bufPrint(probe_buf[probe_len..], "test -r ", .{}) catch break;
        probe_len += head.len;
        const q = shellquote.quoteAppend(probe_buf[probe_len..], entry.path);
        probe_len += q.len;
        const tail = std.fmt.bufPrint(probe_buf[probe_len..], " && echo 1 || echo 0; ", .{}) catch break;
        probe_len += tail.len;
        probed += 1;
    }
    if (probed > 0) {
        var probe_outcome = self.manager.execWait(server_id, probe_buf[0..probe_len], 64 * 1024, logs_read_timeout_ns) catch |err| {
            return respondError(output, switch (err) {
                error.NoSession => "not connected",
                error.NotReady => "session not ready",
                else => "readability probe failed",
            });
        };
        defer probe_outcome.output.deinit(self.allocator);
        logs.applyReadability(result.entries[0..probed], probe_outcome.output.items);
    }

    const written = writeScanResult(output, &result);
    if (written.len == 0) return respondError(output, "scan results too large");
    // The cache takes ownership of `result` from here on.
    session.logs_cache.store(self.allocator, result, now);
    result_owned = true;
    return written;
}

const LogsReadPayload = struct {
    server_id: []const u8,
    path: []const u8,
    lines: u32 = 200,
};

const allowed_log_read_lines = [_]u32{ 200, 500, 1000, 5000 };

/// Validates a log path for the path-taking handlers; returns the error
/// response on failure, null on success.
fn validateLogPath(payload_path: []const u8, output: []u8) ?[]const u8 {
    logs.validatePath(payload_path) catch |err| {
        return respondError(output, switch (err) {
            error.RelativePath => "path must be absolute",
            error.InvalidChar => "path contains control characters",
            error.TrailingSlash => "path must not end with '/'",
        });
    };
    return null;
}

/// Reads the last N lines of a log (spec 04 §5: `tail -n <lines>`, lines ∈
/// {200, 500, 1000, 5000}); the byte cap sets `limited` honestly.
fn handleLogsRead(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(LogsReadPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    if (validateLogPath(payload.path, output)) |err_response| return err_response;
    var allowed = false;
    for (allowed_log_read_lines) |l| {
        if (payload.lines == l) {
            allowed = true;
            break;
        }
    }
    if (!allowed) return respondError(output, "line count must be 200, 500, 1000, or 5000");

    var cmd_buf: [64 * 1024]u8 = undefined;
    const qlen = shellquote.quotedLen(payload.path);
    if (qlen > cmd_buf.len or qlen + 32 > cmd_buf.len) return respondError(output, "path too long");
    const head = std.fmt.bufPrint(&cmd_buf, "tail -n {d} ", .{payload.lines}) catch unreachable;
    const q = shellquote.quoteAppend(cmd_buf[head.len..], payload.path);

    var outcome = self.manager.execWait(payload.server_id, cmd_buf[0 .. head.len + q.len], logs_read_byte_cap, logs_read_timeout_ns) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "read failed",
        });
    };
    defer outcome.output.deinit(self.allocator);
    if (outcome.exit != 0) return respondError(output, "file is missing or unreadable");

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"path\":") catch return output[0..0];
    json.writeJsonString(&writer, payload.path) catch return output[0..0];
    writer.writeAll(",\"lines\":[") catch return output[0..0];
    // Split on newlines; a trailing newline's empty remainder is not a line,
    // but empty lines in the middle of the file are preserved.
    const text = outcome.output.items;
    var start: usize = 0;
    var first = true;
    while (std.mem.indexOfScalarPos(u8, text, start, '\n')) |nl| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        json.writeJsonString(&writer, text[start..nl]) catch return output[0..0];
        start = nl + 1;
    }
    if (start < text.len) {
        if (!first) writer.writeAll(",") catch return output[0..0];
        json.writeJsonString(&writer, text[start..]) catch return output[0..0];
    }
    writer.writeAll("],\"limited\":") catch return output[0..0];
    writer.writeAll(if (outcome.limited) "true" else "false") catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

/// Starts a follow channel (spec 04 §5: `tail -n 100 -F` — name-follow with
/// retry, so normal rotation reopens the new file; verified on both GNU and
/// busybox). Output streams via oars.ssh.poll with kind `log`.
fn handleLogsFollow(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(LogsPathPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    if (validateLogPath(payload.path, output)) |err_response| return err_response;

    var cmd_buf: [64 * 1024]u8 = undefined;
    const qlen = shellquote.quotedLen(payload.path);
    if (qlen > cmd_buf.len or qlen + 32 > cmd_buf.len) return respondError(output, "path too long");
    const head = std.fmt.bufPrint(&cmd_buf, "tail -n 100 -F ", .{}) catch unreachable;
    const q = shellquote.quoteAppend(cmd_buf[head.len..], payload.path);
    const channel_id = self.manager.follow(payload.server_id, cmd_buf[0 .. head.len + q.len]) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "follow failed",
        });
    };
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel_id}) catch return output[0..0];
    return writer.buffered();
}

const LogsClearPayload = struct {
    server_id: []const u8,
    path: []const u8,
    expected: struct {
        size: u64,
        mtime: u64,
        mode: u32,
    },
};

/// Identity-bound truncate (spec 04 §5): the worker SFTP-lstats the path,
/// rejects symlinks/non-regular files, opens WITHOUT truncation, fstats the
/// handle, compares size/mtime/mode against the preview (a mismatch stops
/// with a conflict), and only then sets the size to zero. The audit entry
/// is written by the worker. The handler waits on the outcome with a
/// deadline — the op may not run if the session dies first.
fn handleLogsClear(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(LogsClearPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    if (validateLogPath(payload.path, output)) |err_response| return err_response;

    var outcome: sessions.ClearOutcome = .{};
    self.manager.clearLog(payload.server_id, payload.path, .{
        .size = payload.expected.size,
        .mtime = payload.expected.mtime,
        .mode = payload.expected.mode,
    }, &outcome) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "clear failed",
        });
    };
    const deadline = std.Io.Timestamp.now(self.io, .real).nanoseconds + logs_clear_wait_ns;
    outcome.wait(self.io, deadline);
    if (!outcome.isDone()) return respondError(output, "timed out waiting for the server");
    if (!outcome.ok) return respondError(output, outcome.message());

    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"before_size\":{d},\"after_size\":{d}}}", .{ outcome.before_size, outcome.after_size }) catch return output[0..0];
    return writer.buffered();
}

/// Persists a user-added log path per server (spec 04 §5). Adding a source
/// invalidates the scan cache so the next scan picks it up.
fn handleLogsAddSource(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(LogsPathPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    const path = std.mem.trim(u8, payload.path, " \t\r\n");
    if (validateLogPath(path, output)) |err_response| return err_response;

    self.logs.addSource(self.io, payload.server_id, path) catch {
        return respondError(output, "failed to save log source");
    };
    if (self.manager.get(payload.server_id)) |session| {
        session.logs_cache.invalidate(self.allocator);
    }
    return ok_json;
}

// --- tests -----------------------------------------------------------------

test "logs scan command is marker-escaped for busybox and GNU printf" {
    // busybox printf errors on bare %B-style directives and prints nothing
    // (verified live); `%%` escapes work on both busybox and GNU. The find
    // `-printf` directives are a separate format and keep single %.
    try std.testing.expect(std.mem.indexOf(u8, logs_scan_prefix, "%%BEGIN_DATE%%") != null);
    try std.testing.expect(std.mem.indexOf(u8, logs_scan_prefix, "%%BEGIN_SCAN%%") != null);
    // The busybox fallback exists and is joined with `||` (not `;`): a find
    // without -printf fails over instead of emitting two streams.
    try std.testing.expect(std.mem.indexOf(u8, logs_scan_middle, "|| find") != null);
    try std.testing.expect(std.mem.indexOf(u8, logs_scan_middle, "; find") == null);
    try std.testing.expect(std.mem.indexOf(u8, logs_scan_suffix, "-print0") != null);
    try std.testing.expect(std.mem.indexOf(u8, logs_scan_suffix, "stat -c") != null);
    try std.testing.expect(std.mem.indexOf(u8, logs_scan_suffix, "|| printf '0 0 0") != null);
}
