const std = @import("std");
const runner = @import("runner");
const native_sdk = @import("native_sdk");
const servers = @import("servers.zig");
const sessions = @import("sessions.zig");
const ssh = @import("ssh.zig");
const bridge = @import("bridge.zig");
const audit = @import("audit.zig");
const logs = @import("logs.zig");
const scripts = @import("scripts.zig");
const integration = @import("integration.zig");

// Zig 0.16 only collects test blocks from files that are actually
// analyzed, and an unused import is never analyzed — so the env-gated
// container tests would silently drop out of `zig build test` without
// this reference.
comptime {
    _ = integration;
}

pub const panic = std.debug.FullPanic(native_sdk.debug.capturePanic);

const dev_origins = [_][]const u8{ "zero://app", "zero://inline", "http://127.0.0.1:5173" };

const dialog_permission = [_][]const u8{native_sdk.security.permission_dialog};
const credential_permission = [_][]const u8{native_sdk.security.permission_credentials};
const app_permissions = [_][]const u8{
    native_sdk.security.permission_dialog,
    native_sdk.security.permission_credentials,
};
const builtin_policies = [_]native_sdk.BridgeCommandPolicy{
    .{ .name = "native-sdk.credentials.set", .permissions = &credential_permission, .origins = &bridge.allowed_origins },
    .{ .name = "native-sdk.credentials.get", .permissions = &credential_permission, .origins = &bridge.allowed_origins },
    .{ .name = "native-sdk.credentials.delete", .permissions = &credential_permission, .origins = &bridge.allowed_origins },
    .{ .name = "native-sdk.dialog.openFile", .permissions = &dialog_permission, .origins = &bridge.allowed_origins },
    .{ .name = "native-sdk.dialog.saveFile", .permissions = &dialog_permission, .origins = &bridge.allowed_origins },
};

const App = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    env_map: *std.process.Environ.Map,
    store: servers.Store,
    audit_store: audit.Store,
    logs_store: logs.SourceStore,
    scripts_store: scripts.Store,
    manager: sessions.Manager,
    bridge_ctx: bridge.Context,
    store_path_buf: [2048]u8 = undefined,
    audit_path_buf: [2048]u8 = undefined,
    logs_path_buf: [2048]u8 = undefined,
    scripts_path_buf: [2048]u8 = undefined,
    data_dir_buf: [1024]u8 = undefined,
    fallback_dir_buf: [1024]u8 = undefined,

    fn init(self: *App, process: std.process.Init) !void {
        self.allocator = process.gpa;
        self.io = process.io;
        self.env_map = process.environ_map;

        // libssh2's own init counter is not thread-safe; run it once before
        // any session worker can touch the library (spec 02 §6).
        ssh.initGlobal();

        const data_dir = native_sdk.app_dirs.resolveOne(
            .{ .name = "Oars" },
            native_sdk.app_dirs.currentPlatform(),
            .{ .home = self.env_map.get("HOME") },
            .data,
            &self.data_dir_buf,
        ) catch null;
        const base: []const u8 = if (data_dir) |dir| dir else blk: {
            // Last-resort fallback when the OS has no home directory:
            // keep state somewhere writable rather than refusing to run.
            const tmp = process.environ_map.get("TMPDIR") orelse "/tmp";
            break :blk std.fmt.bufPrint(&self.fallback_dir_buf, "{s}/oars-data", .{tmp}) catch unreachable;
        };
        const store_path = native_sdk.app_dirs.join(
            native_sdk.app_dirs.currentPlatform(),
            &self.store_path_buf,
            &.{ base, "servers.json" },
        ) catch unreachable;
        const audit_path = native_sdk.app_dirs.join(
            native_sdk.app_dirs.currentPlatform(),
            &self.audit_path_buf,
            &.{ base, "audit.jsonl" },
        ) catch unreachable;
        const logs_path = native_sdk.app_dirs.join(
            native_sdk.app_dirs.currentPlatform(),
            &self.logs_path_buf,
            &.{ base, "logs.json" },
        ) catch unreachable;
        const scripts_path = native_sdk.app_dirs.join(
            native_sdk.app_dirs.currentPlatform(),
            &self.scripts_path_buf,
            &.{ base, "scripts.json" },
        ) catch unreachable;
        self.store = .{ .allocator = self.allocator, .path = store_path };
        self.audit_store = .{ .allocator = self.allocator, .path = audit_path };
        self.logs_store = .{ .allocator = self.allocator, .path = logs_path };
        self.scripts_store = .{ .allocator = self.allocator, .path = scripts_path };

        self.manager = sessions.Manager.init(self.allocator, self.io, &self.store, &self.audit_store, self.env_map.get("HOME"));
        self.bridge_ctx = .{
            .allocator = self.allocator,
            .io = self.io,
            .store = &self.store,
            .manager = &self.manager,
            .audit = &self.audit_store,
            .logs = &self.logs_store,
            .scripts = &self.scripts_store,
        };
    }

    fn deinit(self: *App) void {
        self.manager.deinit();
        ssh.Session.deinitGlobal();
    }

    fn app(self: *App) native_sdk.App {
        return .{
            .context = self,
            .name = "oars",
            .source = native_sdk.frontend.productionSource(.{ .dist = "frontend/dist" }),
            .source_fn = source,
        };
    }

    fn source(context: *anyopaque) anyerror!native_sdk.WebViewSource {
        const self: *App = @ptrCast(@alignCast(context));
        return native_sdk.frontend.sourceFromEnv(self.env_map, .{
            .dist = "frontend/dist",
            .entry = "index.html",
        });
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const app = try gpa.create(App);
    defer {
        app.deinit();
        gpa.destroy(app);
    }
    try app.init(init);

    try runner.runWithOptions(app.app(), .{
        .app_name = "Oars",
        .window_title = "Oars",
        .bundle_id = "dev.native_sdk.oars",
        .icon_path = "assets/icon.png",
        .bridge = app.bridge_ctx.dispatcher(),
        .builtin_bridge = .{ .enabled = true, .commands = &builtin_policies },
        .security = .{
            .permissions = &app_permissions,
            .navigation = .{ .allowed_origins = &dev_origins },
        },
    }, init);
}

test "servers.save round trips through the bridge dispatcher" {
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [128]u8 = undefined;
    const dir_name = std.fmt.bufPrint(&dir_buf, "oars-test-{d}", .{now}) catch unreachable;
    var path_buf: [512]u8 = undefined;
    const store_path = std.fmt.bufPrint(&path_buf, "/tmp/{s}/servers.json", .{dir_name}) catch unreachable;
    defer std.Io.Dir.cwd().deleteTree(io, dir_name) catch {};

    // The persistent store legitimately owns its strings for the app's
    // lifetime, so tests give it an arena and free everything at once.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const store_alloc = arena_state.allocator();

    var store = servers.Store{ .allocator = store_alloc, .path = store_path };
    var audit_buf: [512]u8 = undefined;
    const audit_path = std.fmt.bufPrint(&audit_buf, "/tmp/{s}/audit.jsonl", .{dir_name}) catch unreachable;
    var audit_store = audit.Store{ .allocator = store_alloc, .path = audit_path };
    var logs_buf: [512]u8 = undefined;
    const logs_path = std.fmt.bufPrint(&logs_buf, "/tmp/{s}/logs.json", .{dir_name}) catch unreachable;
    var logs_store = logs.SourceStore{ .allocator = store_alloc, .path = logs_path };
    var scripts_buf: [512]u8 = undefined;
    const scripts_path = std.fmt.bufPrint(&scripts_buf, "/tmp/{s}/scripts.json", .{dir_name}) catch unreachable;
    var scripts_store = scripts.Store{ .allocator = store_alloc, .path = scripts_path };
    var manager = sessions.Manager.init(store_alloc, io, &store, &audit_store, null);
    defer manager.deinit();
    var ctx = bridge.Context{ .allocator = store_alloc, .io = io, .store = &store, .manager = &manager, .audit = &audit_store, .logs = &logs_store, .scripts = &scripts_store };
    var dispatcher = ctx.dispatcher();
    var output: [64 * 1024]u8 = undefined;

    const save_response = dispatcher.dispatch(
        \\{"id":"1","command":"oars.servers.save","payload":{"name":"prod","host":"192.168.1.10","port":22,"user":"root","auth_method":"password"}}
    , .{ .origin = "zero://app" }, &output);
    try std.testing.expect(std.mem.indexOf(u8, save_response, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, save_response, "\"id\"") != null);

    const list_response = dispatcher.dispatch(
        \\{"id":"2","command":"oars.servers.list","payload":{}}
    , .{ .origin = "zero://app" }, &output);
    try std.testing.expect(std.mem.indexOf(u8, list_response, "192.168.1.10") != null);

    // The dev-server origin is allowed...
    _ = dispatcher.dispatch(
        \\{"id":"3","command":"oars.servers.list","payload":{}}
    , .{ .origin = "http://127.0.0.1:5173" }, &output);

    // ...but strangers are not.
    const denied = dispatcher.dispatch(
        \\{"id":"4","command":"oars.servers.list","payload":{}}
    , .{ .origin = "https://evil.example" }, &output);
    try std.testing.expect(std.mem.indexOf(u8, denied, "permission_denied") != null);
}

test "app name is configured" {
    try std.testing.expectEqualStrings("oars", "oars");
}

// --- spec 01 bridge tests --------------------------------------------------

const SaveResponse = struct {
    // The dispatcher wraps handler output under "result".
    result: struct {
        ok: bool,
        server: struct {
            id: []const u8,
            created_at: i64,
            host_fingerprint: ?[]const u8 = null,
            tags: [][]const u8 = &.{},
            via_server_id: ?[]const u8 = null,
        },
    },
};

fn parseSaveResponse(allocator: std.mem.Allocator, response: []const u8) !std.json.Parsed(SaveResponse) {
    // alloc_always so parsed strings never alias the dispatcher's output
    // buffer, which the next dispatch overwrites.
    return std.json.parseFromSlice(SaveResponse, allocator, response, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

/// A disposable app: arena-backed store (store strings live for the app
/// lifetime), a session manager with no live sessions, and a dispatcher.
/// init() must run in place (not return a copy): ArenaAllocator.allocator()
/// captures the arena's address, and the context holds it.
const TestApp = struct {
    arena: std.heap.ArenaAllocator,
    store: servers.Store,
    audit_store: audit.Store,
    logs_store: logs.SourceStore,
    scripts_store: scripts.Store,
    manager: sessions.Manager,
    ctx: bridge.Context,
    dispatcher: native_sdk.BridgeDispatcher,
    output: [64 * 1024]u8 = undefined,
    dir_buf: [128]u8 = undefined,
    path_buf: [512]u8 = undefined,
    audit_path_buf: [512]u8 = undefined,
    logs_path_buf: [512]u8 = undefined,
    scripts_path_buf: [512]u8 = undefined,
    dir_name: []const u8,

    fn init(self: *TestApp) !void {
        self.arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        errdefer self.arena.deinit();
        const io = std.testing.io;
        const now = std.Io.Timestamp.now(io, .real).nanoseconds;
        self.dir_name = try std.fmt.bufPrint(&self.dir_buf, "oars-test-{d}", .{now});
        const store_path = try std.fmt.bufPrint(&self.path_buf, "/tmp/{s}/servers.json", .{self.dir_name});
        const audit_path = try std.fmt.bufPrint(&self.audit_path_buf, "/tmp/{s}/audit.jsonl", .{self.dir_name});
        const logs_path = try std.fmt.bufPrint(&self.logs_path_buf, "/tmp/{s}/logs.json", .{self.dir_name});
        const scripts_path = try std.fmt.bufPrint(&self.scripts_path_buf, "/tmp/{s}/scripts.json", .{self.dir_name});
        const store_alloc = self.arena.allocator();
        self.store = .{ .allocator = store_alloc, .path = store_path };
        self.audit_store = .{ .allocator = store_alloc, .path = audit_path };
        self.logs_store = .{ .allocator = store_alloc, .path = logs_path };
        self.scripts_store = .{ .allocator = store_alloc, .path = scripts_path };
        self.manager = sessions.Manager.init(store_alloc, io, &self.store, &self.audit_store, null);
        self.ctx = .{ .allocator = store_alloc, .io = io, .store = &self.store, .manager = &self.manager, .audit = &self.audit_store, .logs = &self.logs_store, .scripts = &self.scripts_store };
        self.dispatcher = self.ctx.dispatcher();
    }

    fn deinit(self: *TestApp) void {
        self.manager.deinit();
        self.arena.deinit();
        std.Io.Dir.cwd().deleteTree(std.testing.io, self.dir_name) catch {};
    }

    /// Returns a slice into `self.output`; the caller must read or parse
    /// it before the next dispatch call.
    fn dispatch(self: *TestApp, request: []const u8) []const u8 {
        return self.dispatcher.dispatch(request, .{ .origin = "zero://app" }, &self.output);
    }
};

test "servers.save preserves created_at and fingerprint by endpoint rule" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();
    const store_alloc = app.arena.allocator();

    const first = app.dispatch(
        \\{"id":"1","command":"oars.servers.save","payload":{"id":"fp1","name":"prod","host":"1.2.3.4","port":22,"user":"root","auth_method":"password"}}
    );
    var first_parsed = try parseSaveResponse(store_alloc, first);
    defer first_parsed.deinit();
    const created_at = first_parsed.value.result.server.created_at;

    // A successful trust stores the fingerprint in the config; editing the
    // profile afterwards must not silently clear it while the endpoint is
    // unchanged.
    const existing = servers.Server{
        .id = "fp1",
        .name = "prod",
        .host = "1.2.3.4",
        .port = 22,
        .user = "root",
        .host_fingerprint = "SHA256:deadbeef",
        .created_at = created_at,
    };
    try app.store.upsert(std.testing.io, existing);

    const edit_same_endpoint = app.dispatch(
        \\{"id":"2","command":"oars.servers.save","payload":{"id":"fp1","name":"renamed","host":"1.2.3.4","port":22,"user":"root","auth_method":"password"}}
    );
    var same_parsed = try parseSaveResponse(store_alloc, edit_same_endpoint);
    defer same_parsed.deinit();
    try std.testing.expectEqual(created_at, same_parsed.value.result.server.created_at);
    try std.testing.expectEqualStrings("SHA256:deadbeef", same_parsed.value.result.server.host_fingerprint.?);

    // Changing the endpoint clears the fingerprint but still preserves
    // created_at.
    const edit_new_port = app.dispatch(
        \\{"id":"3","command":"oars.servers.save","payload":{"id":"fp1","name":"renamed","host":"1.2.3.4","port":2222,"user":"root","auth_method":"password"}}
    );
    var port_parsed = try parseSaveResponse(store_alloc, edit_new_port);
    defer port_parsed.deinit();
    try std.testing.expectEqual(created_at, port_parsed.value.result.server.created_at);
    try std.testing.expect(port_parsed.value.result.server.host_fingerprint == null);
}

test "servers.save normalizes tags and validates host, port, and via chains" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();
    const store_alloc = app.arena.allocator();

    const tagged = app.dispatch(
        \\{"id":"1","command":"oars.servers.save","payload":{"id":"t1","name":"prod","host":"1.2.3.4","user":"root","auth_method":"password","tags":[" web ","api","web",""]}}
    );
    var tagged_parsed = try parseSaveResponse(store_alloc, tagged);
    defer tagged_parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), tagged_parsed.value.result.server.tags.len);
    try std.testing.expectEqualStrings("web", tagged_parsed.value.result.server.tags[0]);
    try std.testing.expectEqualStrings("api", tagged_parsed.value.result.server.tags[1]);

    // Trailing slash in a host is rejected, not stripped.
    const bad_host = app.dispatch(
        \\{"id":"2","command":"oars.servers.save","payload":{"id":"t2","name":"x","host":"1.2.3.4/","user":"root","auth_method":"password"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_host, "must not end with '/'") != null);

    // Port 0 is rejected, never clamped.
    const bad_port = app.dispatch(
        \\{"id":"3","command":"oars.servers.save","payload":{"id":"t3","name":"x","host":"1.2.3.4","port":0,"user":"root","auth_method":"password"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_port, "port must be between 1 and 65535") != null);

    // Jump host must exist.
    const missing_via = app.dispatch(
        \\{"id":"4","command":"oars.servers.save","payload":{"id":"a","name":"a","host":"1.1.1.1","user":"root","auth_method":"password","via_server_id":"nope"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, missing_via, "jump host does not exist") != null);

    // A valid chain saves; then a cycle is rejected.
    const save_b = app.dispatch(
        \\{"id":"5","command":"oars.servers.save","payload":{"id":"b","name":"b","host":"2.2.2.2","user":"root","auth_method":"password"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, save_b, "\"ok\":true") != null);
    const save_a_via_b = app.dispatch(
        \\{"id":"6","command":"oars.servers.save","payload":{"id":"a","name":"a","host":"1.1.1.1","user":"root","auth_method":"password","via_server_id":"b"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, save_a_via_b, "\"ok\":true") != null);
    const cycle = app.dispatch(
        \\{"id":"7","command":"oars.servers.save","payload":{"id":"b","name":"b","host":"2.2.2.2","user":"root","auth_method":"password","via_server_id":"a"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, cycle, "contains a cycle") != null);

    const self_link = app.dispatch(
        \\{"id":"8","command":"oars.servers.save","payload":{"id":"c","name":"c","host":"3.3.3.3","user":"root","auth_method":"password","via_server_id":"c"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, self_link, "cannot connect via itself") != null);
}

test "servers.list reports quarantine recovery when the store is corrupt" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    // Build a healthy store first, then corrupt the file behind the
    // store's back — quarantine only applies to an existing store.
    _ = app.dispatch(
        \\{"id":"1","command":"oars.servers.save","payload":{"id":"s1","name":"prod","host":"1.2.3.4","user":"root","auth_method":"password"}}
    );
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = app.store.path, .data = "{corrupt" });

    const list_response = app.dispatch(
        \\{"id":"2","command":"oars.servers.list","payload":{}}
    );
    try std.testing.expect(std.mem.indexOf(u8, list_response, "\"recovery_error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, list_response, "corrupt-") != null);
    try std.testing.expect(std.mem.indexOf(u8, list_response, "\"servers\":[]") != null);

    // A save afterwards starts a fresh store and clears the recovery state.
    _ = app.dispatch(
        \\{"id":"3","command":"oars.servers.save","payload":{"id":"s2","name":"prod","host":"1.2.3.4","user":"root","auth_method":"password"}}
    );
    const list_again = app.dispatch(
        \\{"id":"4","command":"oars.servers.list","payload":{}}
    );
    try std.testing.expect(std.mem.indexOf(u8, list_again, "\"recovery_error\"") == null);
}

// --- spec 04 bridge tests --------------------------------------------------

test "logs.addSource validates, persists, and dedupes through the dispatcher" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    const ok = app.dispatch(
        \\{"id":"1","command":"oars.logs.addSource","payload":{"server_id":"s1","path":"/var/log/custom.log"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, ok, "\"ok\":true") != null);

    // Whitespace is trimmed before validation and persistence.
    const trimmed = app.dispatch(
        \\{"id":"2","command":"oars.logs.addSource","payload":{"server_id":"s1","path":"  /var/log/trimmed.log  "}}
    );
    try std.testing.expect(std.mem.indexOf(u8, trimmed, "\"ok\":true") != null);

    // Duplicates are dropped, not appended twice.
    const dup = app.dispatch(
        \\{"id":"3","command":"oars.logs.addSource","payload":{"server_id":"s1","path":"/var/log/custom.log"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, dup, "\"ok\":true") != null);

    const relative = app.dispatch(
        \\{"id":"4","command":"oars.logs.addSource","payload":{"server_id":"s1","path":"var/log/x.log"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, relative, "path must be absolute") != null);

    const trailing = app.dispatch(
        \\{"id":"5","command":"oars.logs.addSource","payload":{"server_id":"s1","path":"/var/log/"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, trailing, "must not end with '/'") != null);

    const control = app.dispatch(
        \\{"id":"6","command":"oars.logs.addSource","payload":{"server_id":"s1","path":"/var/log/a\nb.log"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, control, "control characters") != null);

    // Persisted per server, deduped, trimmed.
    const alloc = app.arena.allocator();
    const paths = try app.logs_store.pathsFor(std.testing.io, "s1");
    defer {
        for (paths) |p| alloc.free(p);
        alloc.free(paths);
    }
    try std.testing.expectEqual(@as(usize, 2), paths.len);
    try std.testing.expectEqualStrings("/var/log/custom.log", paths[0]);
    try std.testing.expectEqualStrings("/var/log/trimmed.log", paths[1]);

    const s2 = try app.logs_store.pathsFor(std.testing.io, "s2");
    defer {
        for (s2) |p| alloc.free(p);
        alloc.free(s2);
    }
    try std.testing.expectEqual(@as(usize, 0), s2.len);
}

test "logs scan/read/follow/clear require a session and validate payloads" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    // No live session: every network handler says so explicitly.
    const scan = app.dispatch(
        \\{"id":"1","command":"oars.logs.scan","payload":{"server_id":"ghost"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, scan, "not connected") != null);

    const read = app.dispatch(
        \\{"id":"2","command":"oars.logs.read","payload":{"server_id":"ghost","path":"/var/log/app.log","lines":200}}
    );
    try std.testing.expect(std.mem.indexOf(u8, read, "not connected") != null);

    const follow = app.dispatch(
        \\{"id":"3","command":"oars.logs.follow","payload":{"server_id":"ghost","path":"/var/log/app.log"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, follow, "not connected") != null);

    const clear = app.dispatch(
        \\{"id":"4","command":"oars.logs.clear","payload":{"server_id":"ghost","path":"/var/log/app.log","expected":{"size":10,"mtime":100,"mode":420}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, clear, "not connected") != null);

    // Payload validation happens before the session lookup.
    const bad_lines = app.dispatch(
        \\{"id":"5","command":"oars.logs.read","payload":{"server_id":"ghost","path":"/var/log/app.log","lines":300}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_lines, "line count must be 200, 500, 1000, or 5000") != null);

    const bad_path = app.dispatch(
        \\{"id":"6","command":"oars.logs.follow","payload":{"server_id":"ghost","path":"relative.log"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_path, "path must be absolute") != null);

    const clear_bad_path = app.dispatch(
        \\{"id":"7","command":"oars.logs.clear","payload":{"server_id":"ghost","path":"/var/log/","expected":{"size":1,"mtime":2,"mode":420}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, clear_bad_path, "must not end with '/'") != null);

    const scan_bad_payload = app.dispatch(
        \\{"id":"8","command":"oars.logs.scan","payload":{}}
    );
    try std.testing.expect(std.mem.indexOf(u8, scan_bad_payload, "invalid payload") != null);
}

test "sftp handlers require a session and validate payloads" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    // No live session: every sftp handler says so explicitly.
    const ls = app.dispatch(
        \\{"id":"1","command":"oars.sftp.ls","payload":{"server_id":"ghost","path":{"utf8":"/etc"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, ls, "not connected") != null);

    const stat = app.dispatch(
        \\{"id":"2","command":"oars.sftp.stat","payload":{"server_id":"ghost","path":{"utf8":"/etc/hosts"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, stat, "not connected") != null);

    const read = app.dispatch(
        \\{"id":"3","command":"oars.sftp.read","payload":{"server_id":"ghost","path":{"utf8":"/etc/hosts"},"offset":0,"max":4096}}
    );
    try std.testing.expect(std.mem.indexOf(u8, read, "not connected") != null);

    const write = app.dispatch(
        \\{"id":"4","command":"oars.sftp.write","payload":{"server_id":"ghost","path":{"utf8":"/tmp/x"},"offset":0,"base64":"aGk=","transfer_id":42}}
    );
    try std.testing.expect(std.mem.indexOf(u8, write, "not connected") != null);

    const save = app.dispatch(
        \\{"id":"5","command":"oars.sftp.save","payload":{"server_id":"ghost","path":{"utf8":"/tmp/x"},"base64":"aGk="}}
    );
    try std.testing.expect(std.mem.indexOf(u8, save, "not connected") != null);

    const download = app.dispatch(
        \\{"id":"6","command":"oars.sftp.download","payload":{"server_id":"ghost","remote_path":{"utf8":"/etc/hosts"},"local_path":"/tmp/hosts"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, download, "not connected") != null);

    const mkdir = app.dispatch(
        \\{"id":"7","command":"oars.sftp.mkdir","payload":{"server_id":"ghost","path":{"utf8":"/tmp/d"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, mkdir, "not connected") != null);

    const rm = app.dispatch(
        \\{"id":"8","command":"oars.sftp.rm","payload":{"server_id":"ghost","path":{"utf8":"/tmp/x"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, rm, "not connected") != null);

    const rm_recursive = app.dispatch(
        \\{"id":"9","command":"oars.sftp.rm","payload":{"server_id":"ghost","path":{"utf8":"/tmp/d"},"recursive":true}}
    );
    try std.testing.expect(std.mem.indexOf(u8, rm_recursive, "not connected") != null);

    const rename = app.dispatch(
        \\{"id":"10","command":"oars.sftp.rename","payload":{"server_id":"ghost","from":{"utf8":"/tmp/a"},"to":{"utf8":"/tmp/b"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, rename, "not connected") != null);

    const chmod = app.dispatch(
        \\{"id":"11","command":"oars.sftp.chmod","payload":{"server_id":"ghost","path":{"utf8":"/tmp/x"},"mode":420}}
    );
    try std.testing.expect(std.mem.indexOf(u8, chmod, "not connected") != null);

    const unzip = app.dispatch(
        \\{"id":"12","command":"oars.sftp.unzip","payload":{"server_id":"ghost","zip_path":{"utf8":"/tmp/a.zip"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, unzip, "not connected") != null);

    const zip_download = app.dispatch(
        \\{"id":"13","command":"oars.sftp.zipDownload","payload":{"server_id":"ghost","paths":[{"utf8":"/tmp/a"}],"local_path":"/tmp/a.zip"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, zip_download, "not connected") != null);

    const folder_size = app.dispatch(
        \\{"id":"14","command":"oars.sftp.folderSize","payload":{"server_id":"ghost","path":{"utf8":"/tmp"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, folder_size, "not connected") != null);

    const poll = app.dispatch(
        \\{"id":"15","command":"oars.sftp.poll","payload":{"server_id":"ghost"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, poll, "not connected") != null);

    const cancel = app.dispatch(
        \\{"id":"16","command":"oars.sftp.cancel","payload":{"server_id":"ghost","transfer_id":7}}
    );
    try std.testing.expect(std.mem.indexOf(u8, cancel, "not connected") != null);

    // Payload validation happens before the session lookup.
    const bad_b64 = app.dispatch(
        \\{"id":"17","command":"oars.sftp.ls","payload":{"server_id":"ghost","path":{"base64":"%%%"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_b64, "invalid base64") != null);

    const no_path = app.dispatch(
        \\{"id":"18","command":"oars.sftp.stat","payload":{"server_id":"ghost","path":{}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, no_path, "path is required") != null);

    const bad_max = app.dispatch(
        \\{"id":"19","command":"oars.sftp.read","payload":{"server_id":"ghost","path":{"utf8":"/etc/hosts"},"max":999999}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_max, "max must be between 1 and 65536") != null);

    const bad_local = app.dispatch(
        \\{"id":"20","command":"oars.sftp.download","payload":{"server_id":"ghost","remote_path":{"utf8":"/etc/hosts"},"local_path":"relative.bin"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_local, "local path must be absolute") != null);

    const bad_mode = app.dispatch(
        \\{"id":"21","command":"oars.sftp.chmod","payload":{"server_id":"ghost","path":{"utf8":"/tmp/x"},"mode":32768}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_mode, "invalid mode") != null);

    const overwrite = app.dispatch(
        \\{"id":"22","command":"oars.sftp.unzip","payload":{"server_id":"ghost","zip_path":{"utf8":"/tmp/a.zip"},"overwrite":true}}
    );
    try std.testing.expect(std.mem.indexOf(u8, overwrite, "overwrite is not supported") != null);

    const zero_tid = app.dispatch(
        \\{"id":"23","command":"oars.sftp.write","payload":{"server_id":"ghost","path":{"utf8":"/tmp/x"},"base64":"aGk=","transfer_id":0}}
    );
    try std.testing.expect(std.mem.indexOf(u8, zero_tid, "invalid transfer id") != null);

    const bad_payload = app.dispatch(
        \\{"id":"24","command":"oars.sftp.poll","payload":{}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_payload, "invalid payload") != null);
}

test "scripts save/list/delete round trip through the dispatcher" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    // Create.
    const created = app.dispatch(
        \\{"id":"1","command":"oars.scripts.save","payload":{"script":{"name":"tail errors","body":"tail -f /var/log/{{service}}/error.log","tags":["logs"],"color":"#ff6b6b","variables":[{"name":"service","label":"Service"}]}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, created, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, created, "\"created_at\"") != null);
    // Pull the generated id out NOW — the output buffer is reused by the
    // next dispatch, so the slice must not outlive this response.
    var id_buf: [128]u8 = undefined;
    const id_pos = std.mem.indexOf(u8, created, "\"script\":{\"id\":\"") orelse return error.TestUnexpectedResult;
    const id_start = id_pos + "\"script\":{\"id\":\"".len;
    const id_end = std.mem.indexOfScalarPos(u8, created, id_start, '"') orelse return error.TestUnexpectedResult;
    const id = try std.fmt.bufPrint(&id_buf, "{s}", .{created[id_start..id_end]});

    const script_id = app.dispatch(
        \\{"id":"2","command":"oars.scripts.list","payload":{}}
    );
    try std.testing.expect(std.mem.indexOf(u8, script_id, "tail errors") != null);
    try std.testing.expect(std.mem.indexOf(u8, script_id, "\"service\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, script_id, "\"run_count\":0") != null);

    // Delete, then the list is empty again.
    var delete_buf: [256]u8 = undefined;
    const delete_req = try std.fmt.bufPrint(&delete_buf, "{{\"id\":\"3\",\"command\":\"oars.scripts.delete\",\"payload\":{{\"id\":\"{s}\"}}}}", .{id});
    const deleted = app.dispatch(delete_req);
    try std.testing.expect(std.mem.indexOf(u8, deleted, "\"ok\":true") != null);
    const after = app.dispatch(
        \\{"id":"4","command":"oars.scripts.list","payload":{}}
    );
    try std.testing.expect(std.mem.indexOf(u8, after, "tail errors") == null);
}

test "scripts.save validates payloads through the dispatcher" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    const no_name = app.dispatch(
        \\{"id":"1","command":"oars.scripts.save","payload":{"script":{"name":"","body":"echo hi"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, no_name, "script name is required") != null);

    const no_body = app.dispatch(
        \\{"id":"2","command":"oars.scripts.save","payload":{"script":{"name":"x","body":""}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, no_body, "script body is required") != null);

    const bad_var = app.dispatch(
        \\{"id":"3","command":"oars.scripts.save","payload":{"script":{"name":"x","body":"echo hi","variables":[{"name":"bad-name"}]}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_var, "invalid variable definition") != null);

    const dup_var = app.dispatch(
        \\{"id":"4","command":"oars.scripts.save","payload":{"script":{"name":"x","body":"echo hi","variables":[{"name":"a"},{"name":"a"}]}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, dup_var, "duplicate variable") != null);

    // A body over 64 KB is rejected at save (spec 06 §10).
    var big_buf: [64 * 1024 + 32]u8 = undefined;
    @memset(&big_buf, 'a');
    var save_buf: [70 * 1024]u8 = undefined;
    const payload_head = "{\"id\":\"5\",\"command\":\"oars.scripts.save\",\"payload\":{\"script\":{\"name\":\"big\",\"body\":\"";
    @memcpy(save_buf[0..payload_head.len], payload_head);
    const body_start = payload_head.len;
    @memcpy(save_buf[body_start .. body_start + big_buf.len], &big_buf);
    const tail = "\"}}}";
    @memcpy(save_buf[body_start + big_buf.len .. body_start + big_buf.len + tail.len], tail);
    const big = app.dispatch(save_buf[0 .. body_start + big_buf.len + tail.len]);
    try std.testing.expect(std.mem.indexOf(u8, big, "script body must be under 64 KB") != null);
}

test "scripts.run and broadcast require a session and validate inputs" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    // Save a script for the run paths.
    _ = app.dispatch(
        \\{"id":"1","command":"oars.scripts.save","payload":{"script":{"id":"sc-run","name":"hello","body":"echo {{who}}"}}}
    );

    // No session.
    const run = app.dispatch(
        \\{"id":"2","command":"oars.scripts.run","payload":{"server_id":"ghost","script_id":"sc-run","vars":{"who":{"value":"world"}}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, run, "not connected") != null);

    // Missing script.
    const missing_script = app.dispatch(
        \\{"id":"3","command":"oars.scripts.run","payload":{"server_id":"ghost","script_id":"nope","vars":{}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, missing_script, "script not found") != null);

    // Missing variable blocks the run (no partial substitution).
    const missing_var = app.dispatch(
        \\{"id":"4","command":"oars.scripts.run","payload":{"server_id":"ghost","script_id":"sc-run","vars":{}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, missing_var, "missing variable: who") != null);

    // Multiline values are refused.
    const multiline = app.dispatch(
        \\{"id":"5","command":"oars.scripts.run","payload":{"server_id":"ghost","script_id":"sc-run","vars":{"who":{"value":"a\nb"}}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, multiline, "multiline variable values are not supported") != null);

    // Ambiguous placeholder context is rejected before execution.
    _ = app.dispatch(
        \\{"id":"6","command":"oars.scripts.save","payload":{"script":{"id":"sc-bad","name":"bad","body":"x={{y}}"}}}
    );
    const ambiguous = app.dispatch(
        \\{"id":"7","command":"oars.scripts.run","payload":{"server_id":"ghost","script_id":"sc-bad","vars":{"y":{"value":"v"}}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, ambiguous, "ambiguous shell context") != null);

    // Broadcast requires servers.
    const no_servers = app.dispatch(
        \\{"id":"8","command":"oars.scripts.broadcast","payload":{"script_id":"sc-run","server_ids":[],"vars":{"who":{"value":"world"}}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, no_servers, "no servers selected") != null);

    // Broadcasting to a ghost server still registers the run (the run
    // reports it skipped/unreachable when polled).
    const broadcast = app.dispatch(
        \\{"id":"9","command":"oars.scripts.broadcast","payload":{"script_id":"sc-run","server_ids":["ghost"],"vars":{"who":{"value":"world"}}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, broadcast, "\"run_id\"") != null);
    const run_id_pos = std.mem.indexOf(u8, broadcast, "\"run_id\":") orelse return error.TestUnexpectedResult;
    var run_id_end: usize = run_id_pos + "\"run_id\":".len;
    while (run_id_end < broadcast.len and broadcast[run_id_end] >= '0' and broadcast[run_id_end] <= '9') run_id_end += 1;
    const run_id = broadcast[run_id_pos + "\"run_id\":".len .. run_id_end];
    var poll_buf: [256]u8 = undefined;
    const poll_req = try std.fmt.bufPrint(&poll_buf, "{{\"id\":\"10\",\"command\":\"oars.scripts.broadcastPoll\",\"payload\":{{\"run_id\":{s}}}}}", .{run_id});
    const poll = app.dispatch(poll_req);
    // The ghost server is marked skipped (unreachable), never dropped.
    try std.testing.expect(std.mem.indexOf(u8, poll, "\"status\":\"skipped\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, poll, "unreachable") != null);

    // Unknown run ids are explicit errors.
    const unknown = app.dispatch(
        \\{"id":"11","command":"oars.scripts.broadcastPoll","payload":{"run_id":9999}}
    );
    try std.testing.expect(std.mem.indexOf(u8, unknown, "unknown run") != null);
    const cancel_unknown = app.dispatch(
        \\{"id":"12","command":"oars.scripts.broadcastCancel","payload":{"run_id":9999}}
    );
    try std.testing.expect(std.mem.indexOf(u8, cancel_unknown, "unknown run") != null);
}
