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
const sftpmod = @import("sftp.zig");
const scripts = @import("scripts.zig");
const broadcast = @import("broadcast.zig");

pub const allowed_origins = [_][]const u8{ "zero://app", "http://127.0.0.1:5173" };

const handler_count = 43;

pub const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    store: *servers.Store,
    manager: *sessions.Manager,
    audit: *audit.Store,
    logs: *logs.SourceStore,
    scripts: *scripts.Store,
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
            .{ .name = "oars.sftp.ls", .context = self, .invoke_fn = handleSftpLs },
            .{ .name = "oars.sftp.stat", .context = self, .invoke_fn = handleSftpStat },
            .{ .name = "oars.sftp.read", .context = self, .invoke_fn = handleSftpRead },
            .{ .name = "oars.sftp.write", .context = self, .invoke_fn = handleSftpWrite },
            .{ .name = "oars.sftp.save", .context = self, .invoke_fn = handleSftpSave },
            .{ .name = "oars.sftp.download", .context = self, .invoke_fn = handleSftpDownload },
            .{ .name = "oars.sftp.mkdir", .context = self, .invoke_fn = handleSftpMkdir },
            .{ .name = "oars.sftp.rm", .context = self, .invoke_fn = handleSftpRm },
            .{ .name = "oars.sftp.rename", .context = self, .invoke_fn = handleSftpRename },
            .{ .name = "oars.sftp.chmod", .context = self, .invoke_fn = handleSftpChmod },
            .{ .name = "oars.sftp.unzip", .context = self, .invoke_fn = handleSftpUnzip },
            .{ .name = "oars.sftp.zipDownload", .context = self, .invoke_fn = handleSftpZipDownload },
            .{ .name = "oars.sftp.folderSize", .context = self, .invoke_fn = handleSftpFolderSize },
            .{ .name = "oars.sftp.poll", .context = self, .invoke_fn = handleSftpPoll },
            .{ .name = "oars.sftp.cancel", .context = self, .invoke_fn = handleSftpCancel },
            .{ .name = "oars.scripts.list", .context = self, .invoke_fn = handleScriptsList },
            .{ .name = "oars.scripts.save", .context = self, .invoke_fn = handleScriptsSave },
            .{ .name = "oars.scripts.delete", .context = self, .invoke_fn = handleScriptsDelete },
            .{ .name = "oars.scripts.run", .context = self, .invoke_fn = handleScriptsRun },
            .{ .name = "oars.scripts.broadcast", .context = self, .invoke_fn = handleScriptsBroadcast },
            .{ .name = "oars.scripts.broadcastPoll", .context = self, .invoke_fn = handleScriptsBroadcastPoll },
            .{ .name = "oars.scripts.broadcastCancel", .context = self, .invoke_fn = handleScriptsBroadcastCancel },
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
            .{ .name = "oars.sftp.ls", .origins = &allowed_origins },
            .{ .name = "oars.sftp.stat", .origins = &allowed_origins },
            .{ .name = "oars.sftp.read", .origins = &allowed_origins },
            .{ .name = "oars.sftp.write", .origins = &allowed_origins },
            .{ .name = "oars.sftp.save", .origins = &allowed_origins },
            .{ .name = "oars.sftp.download", .origins = &allowed_origins },
            .{ .name = "oars.sftp.mkdir", .origins = &allowed_origins },
            .{ .name = "oars.sftp.rm", .origins = &allowed_origins },
            .{ .name = "oars.sftp.rename", .origins = &allowed_origins },
            .{ .name = "oars.sftp.chmod", .origins = &allowed_origins },
            .{ .name = "oars.sftp.unzip", .origins = &allowed_origins },
            .{ .name = "oars.sftp.zipDownload", .origins = &allowed_origins },
            .{ .name = "oars.sftp.folderSize", .origins = &allowed_origins },
            .{ .name = "oars.sftp.poll", .origins = &allowed_origins },
            .{ .name = "oars.sftp.cancel", .origins = &allowed_origins },
            .{ .name = "oars.scripts.list", .origins = &allowed_origins },
            .{ .name = "oars.scripts.save", .origins = &allowed_origins },
            .{ .name = "oars.scripts.delete", .origins = &allowed_origins },
            .{ .name = "oars.scripts.run", .origins = &allowed_origins },
            .{ .name = "oars.scripts.broadcast", .origins = &allowed_origins },
            .{ .name = "oars.scripts.broadcastPoll", .origins = &allowed_origins },
            .{ .name = "oars.scripts.broadcastCancel", .origins = &allowed_origins },
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

// --- SFTP (spec 05) ----------------------------------------------------------

const sftp_wait_ns = 20 * std.time.ns_per_s;
const sftp_folder_size_timeout_ns = 60 * std.time.ns_per_s;
const sftp_folder_size_cache_ns = 5 * std.time.ns_per_min;
const sftp_folder_size_cmd_cap: usize = 4 * 1024;

const SftpPathPayload = struct {
    server_id: []const u8,
    path: sftpmod.RemotePathJson,
};

const SftpReadPayload = struct {
    server_id: []const u8,
    path: sftpmod.RemotePathJson,
    offset: u64 = 0,
    max: usize = sftpmod.chunk_size,
};

const SftpWritePayload = struct {
    server_id: []const u8,
    path: sftpmod.RemotePathJson,
    offset: u64 = 0,
    base64: []const u8,
    transfer_id: u32,
    total: ?u64 = null,
};

const SftpSavePayload = struct {
    server_id: []const u8,
    path: sftpmod.RemotePathJson,
    base64: []const u8,
};

const SftpDownloadPayload = struct {
    server_id: []const u8,
    remote_path: sftpmod.RemotePathJson,
    local_path: []const u8,
};

const SftpRmPayload = struct {
    server_id: []const u8,
    path: sftpmod.RemotePathJson,
    recursive: bool = false,
};

const SftpRenamePayload = struct {
    server_id: []const u8,
    from: sftpmod.RemotePathJson,
    to: sftpmod.RemotePathJson,
};

const SftpChmodPayload = struct {
    server_id: []const u8,
    path: sftpmod.RemotePathJson,
    mode: u32,
};

const SftpUnzipPayload = struct {
    server_id: []const u8,
    zip_path: sftpmod.RemotePathJson,
    dest_dir: ?sftpmod.RemotePathJson = null,
    overwrite: bool = false,
};

const SftpZipDownloadPayload = struct {
    server_id: []const u8,
    paths: []const sftpmod.RemotePathJson,
    local_path: []const u8,
};

const SftpTransferIdPayload = struct {
    server_id: []const u8,
    transfer_id: u32,
};

/// Decodes + validates a RemotePath (spec 05 §5). On failure writes the
/// error response and returns it; on success stores the owned raw bytes in
/// `out_path` and returns null.
fn decodeSftpPathArg(self: *Context, output: []u8, path: sftpmod.RemotePathJson, out_path: *?[]u8) ?[]const u8 {
    const raw = sftpmod.decodeRemotePath(self.allocator, path) catch |err| {
        return respondError(output, switch (err) {
            error.NoPath => "path is required",
            error.InvalidBase64 => "invalid base64 path",
            error.InvalidPath => "path contains control characters",
            error.OutOfMemory => "out of memory",
        });
    };
    sftpmod.validatePath(raw) catch |err| {
        self.allocator.free(raw);
        return respondError(output, switch (err) {
            error.NoPath => "path is required",
            error.InvalidPath => "path contains control characters",
            else => "invalid path",
        });
    };
    out_path.* = raw;
    return null;
}

/// Validates a LOCAL path (the native save dialog result). Returns the
/// error response on failure, null on success.
fn validateSftpLocalPathArg(output: []u8, path: []const u8) ?[]const u8 {
    sftpmod.validateLocalPath(path) catch |err| {
        return respondError(output, switch (err) {
            error.NoPath => "local path is required",
            error.InvalidPath => "local path must be absolute and free of control characters",
            else => "invalid local path",
        });
    };
    return null;
}

/// Decodes a base64 payload (chunk or editor save). On failure writes the
/// error response and returns it; on success stores the owned bytes in
/// `out_data` and returns null.
fn decodeSftpBase64Arg(self: *Context, output: []u8, b64: []const u8, max: usize, out_data: *?[]u8) ?[]const u8 {
    const size = std.base64.standard.Decoder.calcSizeForSlice(b64) catch {
        return respondError(output, "invalid base64");
    };
    if (size > max) return respondError(output, "chunk too large");
    const buf = self.allocator.alloc(u8, size) catch {
        return respondError(output, "out of memory");
    };
    std.base64.standard.Decoder.decode(buf, b64) catch {
        self.allocator.free(buf);
        return respondError(output, "invalid base64");
    };
    out_data.* = buf;
    return null;
}

/// Waits for a synchronous SFTP outcome (bounded), then copies the
/// worker-built JSON into the output buffer and frees it.
fn sftpSyncOutcome(self: *Context, output: []u8, outcome: *sessions.SftpOutcome) []const u8 {
    const deadline = std.Io.Timestamp.now(self.io, .real).nanoseconds + sftp_wait_ns;
    outcome.wait(self.io, deadline);
    if (!outcome.isDone()) return respondError(output, "timed out waiting for the server");
    if (!outcome.ok) return respondError(output, outcome.message());
    const payload_json = outcome.json orelse return respondError(output, "no response payload");
    defer self.allocator.free(payload_json);
    if (payload_json.len > output.len) return respondError(output, "response too large");
    @memcpy(output[0..payload_json.len], payload_json);
    return output[0..payload_json.len];
}

/// Maps queueing errors to user-facing messages.
fn sftpQueueError(output: []u8, err: anyerror) []const u8 {
    return respondError(output, switch (err) {
        error.NoSession => "not connected",
        error.NotReady => "session not ready",
        else => "sftp failed",
    });
}

/// Marks a transfer record failed (queue failure after the record was
/// created, so poll never shows it stuck as queued).
fn sftpFailTransfer(session: *sessions.Session, op_id: u32, msg: []const u8) void {
    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(op_id)) |t| {
        t.status = .failed;
        t.err = msg;
    }
    session.sftp_transfers.unlock();
}

/// `{ok, op_id}` response for async ops.
fn sftpOpIdResponse(output: []u8, op_id: u32) []const u8 {
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"op_id\":{d}}}", .{op_id}) catch return output[0..0];
    return writer.buffered();
}

/// `<dir>/<zip stem>` for Expand-in-place (spec 05 §5: a folder named after
/// the archive appears next to it).
fn sftpDefaultDest(allocator: std.mem.Allocator, zip_path: []const u8) ![]u8 {
    const base = std.fs.path.basename(zip_path);
    var stem = base;
    if (std.mem.lastIndexOfScalar(u8, base, '.')) |dot| {
        if (dot > 0) stem = base[0..dot];
    }
    if (std.fs.path.dirname(zip_path)) |dir| {
        if (dir.len == 0) return allocator.dupe(u8, stem);
        if (std.mem.eql(u8, dir, "/")) return std.fmt.allocPrint(allocator, "/{s}", .{stem});
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, stem });
    }
    return allocator.dupe(u8, stem);
}

fn handleSftpLs(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpPathPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    var outcome: sessions.SftpOutcome = .{};
    self.manager.sftpLs(parsed.value.server_id, path.?, &outcome) catch |err| return sftpQueueError(output, err);
    return sftpSyncOutcome(self, output, &outcome);
}

fn handleSftpStat(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpPathPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    var outcome: sessions.SftpOutcome = .{};
    self.manager.sftpStat(parsed.value.server_id, path.?, &outcome) catch |err| return sftpQueueError(output, err);
    return sftpSyncOutcome(self, output, &outcome);
}

/// Explicit-offset 64 KB read (spec 05 §5); the worker answers with
/// `{ok, base64, eof}`.
fn handleSftpRead(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpReadPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    if (parsed.value.max == 0 or parsed.value.max > sftpmod.chunk_size) {
        return respondError(output, "max must be between 1 and 65536 bytes");
    }
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    var outcome: sessions.SftpOutcome = .{};
    self.manager.sftpRead(parsed.value.server_id, path.?, parsed.value.offset, parsed.value.max, &outcome) catch |err| return sftpQueueError(output, err);
    return sftpSyncOutcome(self, output, &outcome);
}

/// Upload chunk under the frontend's unguessable transfer_id (spec 05 §5):
/// the first chunk registers the transfer, the last chunk no-clobber
/// renames `<path>.partial` into place.
fn handleSftpWrite(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpWritePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.transfer_id == 0) return respondError(output, "invalid transfer id");
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, payload.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    var data: ?[]u8 = null;
    if (decodeSftpBase64Arg(self, output, payload.base64, sftpmod.chunk_size, &data)) |err_response| return err_response;
    defer self.allocator.free(data.?);

    const session = self.manager.get(payload.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    self.manager.sftpStartUpload(session, payload.transfer_id, path.?) catch return respondError(output, "out of memory");
    const total = payload.total orelse (payload.offset +| data.?.len);
    var outcome: sessions.SftpOutcome = .{};
    self.manager.sftpWriteChunk(payload.server_id, path.?, payload.offset, data.?, total, payload.transfer_id, &outcome) catch |err| return sftpQueueError(output, err);
    return sftpSyncOutcome(self, output, &outcome);
}

/// Editor save (spec 05 §4.2): temp file + atomic posix-rename on the
/// worker; refusal when the server lacks the extension.
fn handleSftpSave(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpSavePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    var data: ?[]u8 = null;
    if (decodeSftpBase64Arg(self, output, parsed.value.base64, sftpmod.max_inline_bytes, &data)) |err_response| return err_response;
    defer self.allocator.free(data.?);
    var outcome: sessions.SftpOutcome = .{};
    self.manager.sftpSave(parsed.value.server_id, path.?, data.?, &outcome) catch |err| return sftpQueueError(output, err);
    return sftpSyncOutcome(self, output, &outcome);
}

/// Remote→local download through the native writer: the core owns the
/// `<local>.partial` file and no-clobber renames it only after success
/// (spec 05 §5). Async — progress rides the transfer record.
fn handleSftpDownload(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpDownloadPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (validateSftpLocalPathArg(output, payload.local_path)) |err_response| return err_response;
    var remote: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, payload.remote_path, &remote)) |err_response| return err_response;
    defer self.allocator.free(remote.?);
    const partial = std.fmt.allocPrint(self.allocator, "{s}.partial", .{payload.local_path}) catch return respondError(output, "out of memory");
    defer self.allocator.free(partial);

    const session = self.manager.get(payload.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    const op_id = self.manager.sftpStartTransfer(session, "download", remote.?) catch return respondError(output, "out of memory");
    self.manager.sftpDownload(payload.server_id, remote.?, partial, payload.local_path, op_id, null) catch |err| {
        sftpFailTransfer(session, op_id, "failed to queue");
        return sftpQueueError(output, err);
    };
    return sftpOpIdResponse(output, op_id);
}

fn handleSftpMkdir(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpPathPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    var outcome: sessions.SftpOutcome = .{};
    self.manager.sftpMkdir(parsed.value.server_id, path.?, &outcome) catch |err| return sftpQueueError(output, err);
    return sftpSyncOutcome(self, output, &outcome);
}

/// Plain delete is synchronous; recursive deletes run as an async transfer
/// with per-entry progress and cancel (spec 05 §5).
fn handleSftpRm(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpRmPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, payload.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);

    if (!payload.recursive) {
        var outcome: sessions.SftpOutcome = .{};
        self.manager.sftpRm(payload.server_id, path.?, false, 0, &outcome) catch |err| return sftpQueueError(output, err);
        return sftpSyncOutcome(self, output, &outcome);
    }
    const session = self.manager.get(payload.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    const op_id = self.manager.sftpStartTransfer(session, "rm", path.?) catch return respondError(output, "out of memory");
    // The worker's recursive path never writes the outcome; it signals
    // through the transfer record instead.
    var dummy: sessions.SftpOutcome = .{};
    self.manager.sftpRm(payload.server_id, path.?, true, op_id, &dummy) catch |err| {
        sftpFailTransfer(session, op_id, "failed to queue");
        return sftpQueueError(output, err);
    };
    return sftpOpIdResponse(output, op_id);
}

fn handleSftpRename(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpRenamePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var from: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.from, &from)) |err_response| return err_response;
    defer self.allocator.free(from.?);
    var to: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.to, &to)) |err_response| return err_response;
    defer self.allocator.free(to.?);
    var outcome: sessions.SftpOutcome = .{};
    self.manager.sftpRename(parsed.value.server_id, from.?, to.?, &outcome) catch |err| return sftpQueueError(output, err);
    return sftpSyncOutcome(self, output, &outcome);
}

fn handleSftpChmod(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpChmodPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.mode & ~@as(u32, 0o7777) != 0) return respondError(output, "invalid mode");
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, payload.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    var outcome: sessions.SftpOutcome = .{};
    self.manager.sftpChmod(payload.server_id, path.?, payload.mode, &outcome) catch |err| return sftpQueueError(output, err);
    return sftpSyncOutcome(self, output, &outcome);
}

/// Expand in place (spec 05 §5): central-directory preflight on the worker,
/// overwrite disabled, extraction into `dest_dir` (defaults to a folder
/// named after the archive next to it). Async.
fn handleSftpUnzip(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpUnzipPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.overwrite) return respondError(output, "overwrite is not supported; choose an empty destination");
    var zip_path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, payload.zip_path, &zip_path)) |err_response| return err_response;
    defer self.allocator.free(zip_path.?);
    var dest: ?[]u8 = null;
    if (payload.dest_dir) |d| {
        if (decodeSftpPathArg(self, output, d, &dest)) |err_response| return err_response;
    } else {
        dest = sftpDefaultDest(self.allocator, zip_path.?) catch return respondError(output, "out of memory");
    }
    defer self.allocator.free(dest.?);

    const session = self.manager.get(payload.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    const op_id = self.manager.sftpStartTransfer(session, "unzip", zip_path.?) catch return respondError(output, "out of memory");
    self.manager.sftpUnzip(payload.server_id, zip_path.?, dest.?, op_id, null) catch |err| {
        sftpFailTransfer(session, op_id, "failed to queue");
        return sftpQueueError(output, err);
    };
    return sftpOpIdResponse(output, op_id);
}

/// Remote `zip -r` of the selected paths into a uniquely named staging
/// archive, downloaded through the native writer; the staging archive is
/// removed in success and failure (spec 05 §5). Async.
fn handleSftpZipDownload(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpZipDownloadPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.paths.len == 0) return respondError(output, "no paths");
    if (validateSftpLocalPathArg(output, payload.local_path)) |err_response| return err_response;

    var paths: std.ArrayList([]u8) = .empty;
    defer {
        for (paths.items) |p| self.allocator.free(p);
        paths.deinit(self.allocator);
    }
    for (payload.paths) |rp| {
        var p: ?[]u8 = null;
        if (decodeSftpPathArg(self, output, rp, &p)) |err_response| return err_response;
        paths.append(self.allocator, p.?) catch {
            self.allocator.free(p.?);
            return respondError(output, "out of memory");
        };
    }
    const partial = std.fmt.allocPrint(self.allocator, "{s}.partial", .{payload.local_path}) catch return respondError(output, "out of memory");
    defer self.allocator.free(partial);

    const session = self.manager.get(payload.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    const op_id = self.manager.sftpStartTransfer(session, "zip_download", paths.items[0]) catch return respondError(output, "out of memory");
    self.manager.sftpZipDownload(payload.server_id, paths.items, partial, payload.local_path, op_id, null) catch |err| {
        sftpFailTransfer(session, op_id, "failed to queue");
        return sftpQueueError(output, err);
    };
    return sftpOpIdResponse(output, op_id);
}

/// `du -sb <path>` parsed, cached 5 minutes per path (spec 05 §5).
fn handleSftpFolderSize(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpPathPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    const session = self.manager.get(parsed.value.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    if (self.manager.sftpFolderSizeCached(session, path.?, now)) |size| {
        var writer = std.Io.Writer.fixed(output);
        writer.print("{{\"ok\":true,\"size\":{d}}}", .{size}) catch return output[0..0];
        return writer.buffered();
    }

    var cmd_buf: [64 * 1024]u8 = undefined;
    const qlen = shellquote.quotedLen(path.?);
    if (qlen + 16 > cmd_buf.len) return respondError(output, "path too long");
    const head = std.fmt.bufPrint(&cmd_buf, "du -sb ", .{}) catch unreachable;
    const q = shellquote.quoteAppend(cmd_buf[head.len..], path.?);
    var outcome = self.manager.execWait(parsed.value.server_id, cmd_buf[0 .. head.len + q.len], sftp_folder_size_cmd_cap, sftp_folder_size_timeout_ns) catch |err| return sftpQueueError(output, err);
    defer outcome.output.deinit(self.allocator);
    if (outcome.exit != 0 or outcome.output.items.len == 0) return respondError(output, "cannot measure folder size");
    const text = std.mem.trim(u8, outcome.output.items, " \t\r\n");
    const end = std.mem.indexOfAny(u8, text, " \t") orelse text.len;
    const size = std.fmt.parseInt(u64, text[0..end], 10) catch {
        return respondError(output, "cannot parse folder size");
    };
    self.manager.sftpFolderSizeCacheSet(session, path.?, size, now);
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"size\":{d}}}", .{size}) catch return output[0..0];
    return writer.buffered();
}

/// Non-destructive snapshot of active + recent transfers (spec 05 §5): two
/// views can poll without consuming each other's progress.
fn handleSftpPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(IdPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const session = self.manager.get(parsed.value.server_id) orelse {
        return respondError(output, "not connected");
    };
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"transfers\":[") catch return output[0..0];
    session.sftp_transfers.lock();
    defer session.sftp_transfers.unlock();
    var first = true;
    for (session.sftp_transfers.list.items) |t| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.print("{{\"id\":{d},\"kind\":", .{t.id}) catch return output[0..0];
        json.writeJsonString(&writer, t.kind) catch return output[0..0];
        writer.writeAll(",\"path\":") catch return output[0..0];
        json.writeJsonString(&writer, t.path) catch return output[0..0];
        writer.print(",\"bytes\":{d},\"total\":{d},\"status\":", .{ t.bytes_done, t.bytes_total }) catch return output[0..0];
        json.writeJsonString(&writer, t.status.jsonName()) catch return output[0..0];
        writer.writeAll(",\"error\":") catch return output[0..0];
        json.writeJsonString(&writer, t.err) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

/// Cancels an async transfer: the worker cleanup op deletes the upload
/// partial; long-running ops check the flag between entries.
fn handleSftpCancel(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpTransferIdPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.sftpCancel(parsed.value.server_id, parsed.value.transfer_id) catch |err| return sftpQueueError(output, err);
    return ok_json;
}

// --- scripts (spec 06) ---------------------------------------------------------

const scripts_run_check_timeout_ns = 30 * std.time.ns_per_s;
const scripts_check_cap: usize = 16 * 1024;
const scripts_poll_data_budget: usize = 256 * 1024;

const ScriptsSavePayload = struct {
    script: scripts.ScriptInput,
};

const ScriptsIdPayload = struct {
    id: []const u8,
};

const ScriptsRunPayload = struct {
    server_id: []const u8,
    script_id: []const u8,
    vars: std.json.Value = .null,
};

const ScriptsBroadcastPayload = struct {
    script_id: []const u8,
    server_ids: []const []const u8,
    vars: std.json.Value = .null,
};

const ScriptsBroadcastPollPayload = struct {
    run_id: u32,
    cursors: std.json.Value = .null,
};

const ScriptsBroadcastCancelPayload = struct {
    run_id: u32,
};

/// Extracts `{name: {value, secret}}` from the payload. The returned
/// RunVars reference the parsed tree (valid until the parse is freed —
/// expansion happens before that). Returns the error response on failure.
fn scriptsVars(self: *Context, output: []u8, value: std.json.Value, out: *std.ArrayList(scripts.RunVar)) ?[]const u8 {
    if (value == .null) return null; // no variables
    if (value != .object) return respondError(output, "invalid vars payload");
    var it = value.object.iterator();
    while (it.next()) |entry| {
        const v: std.json.Value = entry.value_ptr.*;
        if (v != .object) return respondError(output, "invalid variable value");
        const value_field = v.object.get("value") orelse return respondError(output, "missing variable value");
        if (value_field != .string) return respondError(output, "invalid variable value");
        const secret = if (v.object.get("secret")) |s| s == .bool and s.bool else false;
        out.append(self.allocator, .{ .name = entry.key_ptr.*, .value = value_field.string, .secret = secret }) catch return respondError(output, "out of memory");
    }
    return null;
}

/// Appends one audit entry: script id/name, variable names, and the
/// redacted command (spec 06 §8 — secret values never written). Returns
/// the error response on failure.
fn scriptsAudit(self: *Context, output: []u8, action: []const u8, server_id: []const u8, script: *const scripts.Script, expansion: *const scripts.Expansion) ?[]const u8 {
    var names_buf: std.ArrayList(u8) = .empty;
    defer names_buf.deinit(self.allocator);
    for (expansion.names, 0..) |n, i| {
        if (names_buf.items.len >= 256) break;
        if (i > 0) names_buf.append(self.allocator, ',') catch return respondError(output, "out of memory");
        names_buf.appendSlice(self.allocator, n.name) catch return respondError(output, "out of memory");
    }
    const redacted = if (expansion.redacted.len > 1000) expansion.redacted[0..1000] else expansion.redacted;
    var detail_buf: [1800]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "script={s} name={s} vars={s} command={s}", .{ script.id, script.name, names_buf.items, redacted }) catch "scripts.run";
    self.audit.append(self.io, .{
        .ts = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds),
        .action = action,
        .server_id = server_id,
        .detail = detail,
    }) catch return respondError(output, "audit failed");
    return null;
}

/// Loads the script, expands the template with the payload vars, and
/// writes one audit entry per server (redacted command + variable names).
/// On failure writes an error response and returns null.
fn scriptsPrepare(
    self: *Context,
    output: []u8,
    err_response: *[]const u8,
    action: []const u8,
    server_ids: []const []const u8,
    script_id: []const u8,
    vars: std.json.Value,
) ?scripts.Expansion {
    err_response.* = "";
    var owned_script = self.scripts.find(self.io, script_id) catch {
        err_response.* = respondError(output, "script library is unreadable");
        return null;
    } orelse {
        err_response.* = respondError(output, "script not found");
        return null;
    };
    defer scripts.deinit(self.allocator, &owned_script);

    var var_list: std.ArrayList(scripts.RunVar) = .empty;
    defer var_list.deinit(self.allocator);
    if (scriptsVars(self, output, vars, &var_list)) |resp| {
        err_response.* = resp;
        return null;
    }

    var missing: []const u8 = undefined;
    var expansion = scripts.expandTemplate(self.allocator, owned_script.body, var_list.items, &missing) catch |err| {
        err_response.* = respondError(output, switch (err) {
            error.MissingVariable => blk: {
                var buf: [256]u8 = undefined;
                break :blk std.fmt.bufPrint(&buf, "missing variable: {s}", .{missing}) catch "missing variable";
            },
            error.MultilineValue => "multiline variable values are not supported",
            error.UnterminatedPlaceholder => "script contains an unterminated placeholder",
            error.InvalidPlaceholderName => "script contains an invalid placeholder name",
            error.AmbiguousPlaceholder => "a placeholder appears in an ambiguous shell context (quotes, redirection, assignment, or command name)",
            error.TooManyVariables => "script references too many variables",
            error.OutOfMemory => "out of memory",
        });
        return null;
    };
    errdefer expansion.deinit(self.allocator);

    for (server_ids) |sid| {
        if (scriptsAudit(self, output, action, sid, &owned_script, &expansion)) |resp| {
            err_response.* = resp;
            return null;
        }
    }
    return expansion;
}

fn handleScriptsList(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    _ = invocation;
    var loaded = self.scripts.loadParsed(self.io) catch {
        return "{\"ok\":false,\"error\":\"failed to load scripts\"}";
    };
    defer loaded.deinit(self.allocator);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"scripts\":") catch return output[0..0];
    std.json.Stringify.value(loaded.parsed.value, .{}, &writer) catch return output[0..0];
    if (loaded.quarantined) |q| {
        var msg_buf: [640]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "scripts.json was unreadable and was moved to {s}; the script library starts fresh", .{q}) catch "scripts.json was unreadable and was moved aside";
        writer.writeAll(",\"recovery_error\":") catch return output[0..0];
        json.writeJsonString(&writer, msg) catch return output[0..0];
    }
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

/// Upserts a script (spec 06 §7); ids are generated for creates. The body
/// is capped at 64 KB; variables must match the placeholder name charset.
fn handleScriptsSave(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsSavePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const input = parsed.value.script;
    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    var owned_id: ?[]const u8 = null;
    defer if (owned_id) |o| self.allocator.free(o);
    const id = input.id orelse blk: {
        owned_id = servers.makeId(self.allocator, now) catch return respondError(output, "out of memory");
        break :blk owned_id.?;
    };

    var saved = self.scripts.saveScript(self.io, .{
        .id = id,
        .name = input.name,
        .description = input.description,
        .tags = input.tags,
        .color = input.color,
        .body = input.body,
        .variables = input.variables,
    }, now) catch |err| {
        return respondError(output, switch (err) {
            error.MissingName => "script name is required",
            error.NameTooLong => "script name is too long",
            error.EmptyBody => "script body is required",
            error.BodyTooLarge => "script body must be under 64 KB",
            error.InvalidName => "invalid name or description",
            error.InvalidTag => "invalid tag",
            error.TooManyTags => "too many tags",
            error.InvalidColor => "invalid color",
            error.InvalidVariable => "invalid variable definition",
            error.DuplicateVariable => "duplicate variable",
            error.TooManyVariables => "too many variables",
            error.TooManyScripts => "script library is full",
            error.StoreCorrupt => "script library is unreadable",
            error.SerializeFailed => "failed to save scripts",
            error.OutOfMemory => "out of memory",
            error.MissingId => "missing script id",
        });
    };
    defer scripts.deinit(self.allocator, &saved);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"script\":") catch return output[0..0];
    std.json.Stringify.value(saved, .{}, &writer) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleScriptsDelete(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsIdPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    _ = self.scripts.delete(self.io, parsed.value.id) catch {
        return respondError(output, "failed to delete script");
    };
    return ok_json;
}

/// Runs a script on one server: expand, `bash -n` syntax check on the
/// server, then exec (spec 06 §5). The channel id carries the output.
fn handleScriptsRun(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsRunPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    var err_response: []const u8 = "";
    var expansion = scriptsPrepare(self, output, &err_response, "scripts.run", &.{payload.server_id}, payload.script_id, payload.vars) orelse return err_response;
    defer expansion.deinit(self.allocator);

    const quoted = shellquote.quote(self.allocator, expansion.command) catch return respondError(output, "out of memory");
    defer self.allocator.free(quoted);
    const check_cmd = std.fmt.allocPrint(self.allocator, "bash -n -c {s}", .{quoted}) catch return respondError(output, "out of memory");
    defer self.allocator.free(check_cmd);
    var check = self.manager.execWait(payload.server_id, check_cmd, scripts_check_cap, scripts_run_check_timeout_ns) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "syntax check failed",
        });
    };
    defer check.output.deinit(self.allocator);
    if (check.exit != 0) {
        if (check.exit == 127) return respondError(output, "bash is not available on this server");
        const tail = if (check.output.items.len > 200) check.output.items[check.output.items.len - 200 ..] else check.output.items;
        var msg_buf: [512]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "syntax check failed (exit {d}): {s}", .{ check.exit, tail }) catch "syntax check failed";
        return respondError(output, msg);
    }
    const channel = self.manager.exec(payload.server_id, expansion.command) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "run failed",
        });
    };
    self.scripts.touchRun(self.io, payload.script_id, std.Io.Timestamp.now(self.io, .real).nanoseconds);
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel}) catch return output[0..0];
    return writer.buffered();
}

/// `bash -n` syntax check on one broadcast server (spec 06 §5). On failure
/// the server state carries the reason; returns whether it may run.
fn scriptsCheckSyntax(self: *Context, server: *broadcast.ServerState, command: []const u8) bool {
    const quoted = shellquote.quote(self.allocator, command) catch {
        server.status = .failed;
        server.err = "out of memory";
        return false;
    };
    defer self.allocator.free(quoted);
    const check_cmd = std.fmt.allocPrint(self.allocator, "bash -n -c {s}", .{quoted}) catch {
        server.status = .failed;
        server.err = "out of memory";
        return false;
    };
    defer self.allocator.free(check_cmd);
    var check = self.manager.execWait(server.server_id, check_cmd, scripts_check_cap, scripts_run_check_timeout_ns) catch {
        server.status = .skipped;
        server.err = "unreachable";
        return false;
    };
    defer check.output.deinit(self.allocator);
    if (check.exit != 0) {
        server.status = .failed;
        server.err = if (check.exit == 127) "bash unavailable" else "syntax check failed";
        return false;
    }
    return true;
}

/// Safe broadcast (spec 06 §4.2/§6): expands once, audits per server, and
/// registers the run. Queued servers start as slots free during polling.
fn handleScriptsBroadcast(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsBroadcastPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.server_ids.len == 0) return respondError(output, "no servers selected");

    var err_response: []const u8 = "";
    var expansion = scriptsPrepare(self, output, &err_response, "scripts.broadcast", payload.server_ids, payload.script_id, payload.vars) orelse return err_response;
    defer expansion.deinit(self.allocator);

    const run_id = self.manager.broadcasts.start(payload.script_id, "", expansion.command, payload.server_ids) catch |err| {
        return respondError(output, switch (err) {
            error.NoServers => "no servers selected",
            else => "out of memory",
        });
    };
    self.scripts.touchRun(self.io, payload.script_id, std.Io.Timestamp.now(self.io, .real).nanoseconds);
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"run_id\":{d}}}", .{run_id}) catch return output[0..0];
    return writer.buffered();
}

/// The broadcast cursor map value for one server (absolute stream cursor;
/// spec 02 protocol — each view polls with its own cursors).
fn scriptsCursor(cursors: std.json.Value, server_id: []const u8) u64 {
    if (cursors != .object) return 0;
    const v = cursors.object.get(server_id) orelse return 0;
    return switch (v) {
        .integer => |i| if (i < 0) 0 else @intCast(i),
        .float => |f| if (f < 0) 0 else @intFromFloat(f),
        else => 0,
    };
}

/// Starts queued servers as slots free, polls running channels with the
/// caller's cursors, and returns the per-server status/output snapshot
/// (spec 06 §5 — non-destructive: nothing is consumed).
fn handleScriptsBroadcastPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsBroadcastPollPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    self.manager.broadcasts.lock();
    const run = self.manager.broadcasts.get(payload.run_id) orelse {
        self.manager.broadcasts.unlock();
        return respondError(output, "unknown run");
    };
    self.manager.broadcasts.unlock();
    // The bridge is single-threaded: no other handler can mutate or evict
    // the run while this one runs, so the pointer stays valid.

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"run_id\":") catch return output[0..0];
    writer.print("{d}", .{run.id}) catch return output[0..0];
    writer.writeAll(",\"script_name\":") catch return output[0..0];
    json.writeJsonString(&writer, run.script_name) catch return output[0..0];
    writer.print(",\"canceled\":{s}", .{if (run.canceled) "true" else "false"}) catch return output[0..0];

    // Start queued servers as slots free (spec 06 §6: at most four at a
    // time; polling drives the queue).
    while (run.running < broadcast.max_concurrent and run.next_to_start < run.servers.items.len and !run.canceled) {
        const idx = run.next_to_start;
        run.next_to_start += 1;
        const server = &run.servers.items[idx];
        if (!scriptsCheckSyntax(self, server, run.command)) continue;
        const channel = self.manager.exec(server.server_id, run.command) catch {
            server.status = .skipped;
            server.err = "unreachable";
            continue;
        };
        server.status = .running;
        server.channel = channel;
        run.running += 1;
    }

    writer.writeAll(",\"servers\":[") catch return output[0..0];
    var first = true;
    var budget = scripts_poll_data_budget;
    for (run.servers.items) |*server| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.writeAll("{\"server_id\":") catch return output[0..0];
        json.writeJsonString(&writer, server.server_id) catch return output[0..0];
        writer.writeAll(",\"status\":") catch return output[0..0];
        json.writeJsonString(&writer, server.status.jsonName()) catch return output[0..0];
        writer.writeAll(",\"exit\":") catch return output[0..0];
        if (server.exit) |exit| {
            writer.print("{d}", .{exit}) catch return output[0..0];
        } else {
            writer.writeAll("null") catch return output[0..0];
        }
        writer.writeAll(",\"error\":") catch return output[0..0];
        json.writeJsonString(&writer, server.err) catch return output[0..0];

        if (server.status == .running or server.status == .done) {
            const channel = server.channel orelse continue;
            const cursor = scriptsCursor(payload.cursors, server.server_id);
            const polls = self.manager.pollChannels(server.server_id, &.{.{ .id = channel, .pos = cursor }}, false, budget, 128 * 1024) catch {
                server.status = .failed;
                server.err = "session lost";
                run.running -= 1;
                continue;
            };
            var data: []u8 = &.{};
            var new_cursor = cursor;
            var eof = false;
            var exit: ?i32 = null;
            var gap: u64 = 0;
            for (polls) |*poll| {
                if (poll.id != channel) continue;
                data = poll.data;
                new_cursor = poll.cursor;
                eof = poll.eof;
                exit = poll.exit_status;
                gap = poll.gap;
            }
            budget = budget -| data.len;
            writer.print(",\"cursor\":{d},\"gap\":{d},\"eof\":{s},\"data\":", .{ new_cursor, gap, if (eof) "true" else "false" }) catch return output[0..0];
            json.writeJsonString(&writer, data) catch return output[0..0];
            // The serialized data must be written BEFORE the polls are
            // freed (poll.deinit owns the data buffer).
            for (polls) |*poll| poll.deinit(self.allocator);
            self.allocator.free(polls);
            // Done servers keep being polled (late cursors still get their
            // retained data), so the transition happens exactly once.
            if (eof and server.status == .running) {
                server.status = .done;
                server.exit = exit;
                run.running -= 1;
            }
        }
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]") catch return output[0..0];

    if (run.allTerminal()) run.finished = true;
    // The done flag must be serialized before eviction can free the run.
    writer.print(",\"done\":{s}}}", .{if (run.finished) "true" else "false"}) catch return output[0..0];
    self.manager.broadcasts.evictFinished();
    return writer.buffered();
}

/// Cancels a broadcast: queued servers never start; running channels are
/// closed and reported `canceled` ("cancel requested" — closing a channel
/// does not prove the remote process died; spec 06 §10).
fn handleScriptsBroadcastCancel(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsBroadcastCancelPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.broadcasts.lock();
    const run = self.manager.broadcasts.get(parsed.value.run_id) orelse {
        self.manager.broadcasts.unlock();
        return respondError(output, "unknown run");
    };
    run.canceled = true;
    for (run.servers.items) |*server| {
        switch (server.status) {
            .queued => server.status = .canceled,
            .running => {
                if (server.channel) |ch| self.manager.closeChannel(server.server_id, ch) catch {};
                server.status = .canceled;
                server.err = "cancel requested";
                run.running -= 1;
            },
            else => {},
        }
    }
    self.manager.broadcasts.unlock();
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
