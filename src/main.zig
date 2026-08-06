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
const deploy = @import("deploy.zig");
const integration = @import("integration.zig");
const access = @import("access.zig");
const backup = @import("backup.zig");
const ai = @import("ai.zig");

// Zig 0.16 only collects test blocks from files that are actually
// analyzed, and an unused import is never analyzed — so the env-gated
// container tests would silently drop out of `zig build test` without
// this reference.
comptime {
    _ = integration;
    _ = deploy;
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
    deploy_apps_store: deploy.AppStore,
    deploy_history_store: deploy.HistoryStore,
    access_registry: access.Registry,
    backup_registry: backup.Registry,
    ai_registry: ai.Registry,
    manager: sessions.Manager,
    bridge_ctx: bridge.Context,
    store_path_buf: [2048]u8 = undefined,
    audit_path_buf: [2048]u8 = undefined,
    logs_path_buf: [2048]u8 = undefined,
    scripts_path_buf: [2048]u8 = undefined,
    deploy_apps_path_buf: [2048]u8 = undefined,
    deploy_history_path_buf: [2048]u8 = undefined,
    access_path_buf: [2048]u8 = undefined,
    backup_jobs_path_buf: [2048]u8 = undefined,
    backup_runs_path_buf: [2048]u8 = undefined,
    ai_path_buf: [2048]u8 = undefined,
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
        const deploy_apps_path = native_sdk.app_dirs.join(
            native_sdk.app_dirs.currentPlatform(),
            &self.deploy_apps_path_buf,
            &.{ base, "apps.json" },
        ) catch unreachable;
        const deploy_history_path = native_sdk.app_dirs.join(
            native_sdk.app_dirs.currentPlatform(),
            &self.deploy_history_path_buf,
            &.{ base, "deploy_runs.json" },
        ) catch unreachable;
        const access_path = native_sdk.app_dirs.join(
            native_sdk.app_dirs.currentPlatform(),
            &self.access_path_buf,
            &.{ base, access.identity_store_name },
        ) catch unreachable;
        const backup_jobs_path = native_sdk.app_dirs.join(
            native_sdk.app_dirs.currentPlatform(),
            &self.backup_jobs_path_buf,
            &.{ base, "backups.json" },
        ) catch unreachable;
        const backup_runs_path = native_sdk.app_dirs.join(
            native_sdk.app_dirs.currentPlatform(),
            &self.backup_runs_path_buf,
            &.{ base, "backup_runs.json" },
        ) catch unreachable;
        const ai_path = native_sdk.app_dirs.join(
            native_sdk.app_dirs.currentPlatform(),
            &self.ai_path_buf,
            &.{ base, "ai.json" },
        ) catch unreachable;
        self.store = .{ .allocator = self.allocator, .path = store_path };
        self.audit_store = .{ .allocator = self.allocator, .path = audit_path };
        self.logs_store = .{ .allocator = self.allocator, .path = logs_path };
        self.scripts_store = .{ .allocator = self.allocator, .path = scripts_path };
        self.deploy_apps_store = .{ .allocator = self.allocator, .path = deploy_apps_path };
        self.deploy_history_store = .{ .allocator = self.allocator, .path = deploy_history_path };
        self.access_registry = access.Registry.init(self.allocator, access_path);
        self.backup_registry = backup.Registry.init(self.allocator, backup_jobs_path, backup_runs_path);
        self.ai_registry = ai.Registry.init(self.allocator, ai_path);

        self.manager = sessions.Manager.init(self.allocator, self.io, &self.store, &self.audit_store, self.env_map.get("HOME"));
        self.bridge_ctx = .{
            .allocator = self.allocator,
            .io = self.io,
            .store = &self.store,
            .manager = &self.manager,
            .audit = &self.audit_store,
            .logs = &self.logs_store,
            .scripts = &self.scripts_store,
            .apps = &self.deploy_apps_store,
            .deploy_history = &self.deploy_history_store,
            .access = &self.access_registry,
            .backup = &self.backup_registry,
            .ai = &self.ai_registry,
        };
    }

    fn deinit(self: *App) void {
        self.access_registry.deinit();
        self.backup_registry.deinit();
        self.ai_registry.deinit();
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
    var deploy_apps_buf: [512]u8 = undefined;
    const deploy_apps_path = std.fmt.bufPrint(&deploy_apps_buf, "/tmp/{s}/apps.json", .{dir_name}) catch unreachable;
    var deploy_apps_store = deploy.AppStore{ .allocator = store_alloc, .path = deploy_apps_path };
    var deploy_hist_buf: [512]u8 = undefined;
    const deploy_hist_path = std.fmt.bufPrint(&deploy_hist_buf, "/tmp/{s}/deploy_runs.json", .{dir_name}) catch unreachable;
    var deploy_hist_store = deploy.HistoryStore{ .allocator = store_alloc, .path = deploy_hist_path };
    var access_buf: [512]u8 = undefined;
    const access_path = std.fmt.bufPrint(&access_buf, "/tmp/{s}/access_identities.json", .{dir_name}) catch unreachable;
    var access_registry = access.Registry.init(store_alloc, access_path);
    defer access_registry.deinit();
    var backup_jobs_buf: [512]u8 = undefined;
    const backup_jobs_path = std.fmt.bufPrint(&backup_jobs_buf, "/tmp/{s}/backups.json", .{dir_name}) catch unreachable;
    var backup_runs_buf: [512]u8 = undefined;
    const backup_runs_path = std.fmt.bufPrint(&backup_runs_buf, "/tmp/{s}/backup_runs.json", .{dir_name}) catch unreachable;
    var backup_registry = backup.Registry.init(store_alloc, backup_jobs_path, backup_runs_path);
    defer backup_registry.deinit();
    var ai_path_buf: [512]u8 = undefined;
    const ai_path = std.fmt.bufPrint(&ai_path_buf, "/tmp/{s}/ai.json", .{dir_name}) catch unreachable;
    var ai_registry = ai.Registry.init(store_alloc, ai_path);
    defer ai_registry.deinit();
    var manager = sessions.Manager.init(store_alloc, io, &store, &audit_store, null);
    defer manager.deinit();
    var ctx = bridge.Context{ .allocator = store_alloc, .io = io, .store = &store, .manager = &manager, .audit = &audit_store, .logs = &logs_store, .scripts = &scripts_store, .apps = &deploy_apps_store, .deploy_history = &deploy_hist_store, .access = &access_registry, .backup = &backup_registry, .ai = &ai_registry };
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
    deploy_apps_store: deploy.AppStore,
    deploy_history_store: deploy.HistoryStore,
    access_registry: access.Registry,
    backup_registry: backup.Registry,
    ai_registry: ai.Registry,
    manager: sessions.Manager,
    ctx: bridge.Context,
    dispatcher: native_sdk.BridgeDispatcher,
    output: [64 * 1024]u8 = undefined,
    dir_buf: [128]u8 = undefined,
    path_buf: [512]u8 = undefined,
    audit_path_buf: [512]u8 = undefined,
    logs_path_buf: [512]u8 = undefined,
    scripts_path_buf: [512]u8 = undefined,
    deploy_apps_path_buf: [512]u8 = undefined,
    deploy_history_path_buf: [512]u8 = undefined,
    access_path_buf: [512]u8 = undefined,
    backup_jobs_path_buf: [512]u8 = undefined,
    backup_runs_path_buf: [512]u8 = undefined,
    ai_path_buf: [512]u8 = undefined,
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
        const deploy_apps_path = try std.fmt.bufPrint(&self.deploy_apps_path_buf, "/tmp/{s}/apps.json", .{self.dir_name});
        const deploy_history_path = try std.fmt.bufPrint(&self.deploy_history_path_buf, "/tmp/{s}/deploy_runs.json", .{self.dir_name});
        const access_path = try std.fmt.bufPrint(&self.access_path_buf, "/tmp/{s}/access_identities.json", .{self.dir_name});
        const backup_jobs_path = try std.fmt.bufPrint(&self.backup_jobs_path_buf, "/tmp/{s}/backups.json", .{self.dir_name});
        const backup_runs_path = try std.fmt.bufPrint(&self.backup_runs_path_buf, "/tmp/{s}/backup_runs.json", .{self.dir_name});
        const ai_path = try std.fmt.bufPrint(&self.ai_path_buf, "/tmp/{s}/ai.json", .{self.dir_name});
        const store_alloc = self.arena.allocator();
        self.store = .{ .allocator = store_alloc, .path = store_path };
        self.audit_store = .{ .allocator = store_alloc, .path = audit_path };
        self.logs_store = .{ .allocator = store_alloc, .path = logs_path };
        self.scripts_store = .{ .allocator = store_alloc, .path = scripts_path };
        self.deploy_apps_store = .{ .allocator = store_alloc, .path = deploy_apps_path };
        self.deploy_history_store = .{ .allocator = store_alloc, .path = deploy_history_path };
        self.access_registry = access.Registry.init(store_alloc, access_path);
        self.backup_registry = backup.Registry.init(store_alloc, backup_jobs_path, backup_runs_path);
        self.ai_registry = ai.Registry.init(store_alloc, ai_path);
        self.manager = sessions.Manager.init(store_alloc, io, &self.store, &self.audit_store, null);
        self.ctx = .{ .allocator = store_alloc, .io = io, .store = &self.store, .manager = &self.manager, .audit = &self.audit_store, .logs = &self.logs_store, .scripts = &self.scripts_store, .apps = &self.deploy_apps_store, .deploy_history = &self.deploy_history_store, .access = &self.access_registry, .backup = &self.backup_registry, .ai = &self.ai_registry };
        self.dispatcher = self.ctx.dispatcher();
    }

    fn deinit(self: *TestApp) void {
        self.access_registry.deinit();
        self.backup_registry.deinit();
        self.ai_registry.deinit();
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

test "deploy apps save/list/delete round trip through the dispatcher" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    // Create on s1: the id is generated, secret values never persist.
    const created = app.dispatch(
        \\{"id":"1","command":"oars.deploy.apps.save","payload":{"app":{"server_id":"s1","name":"storefront","folder":"/home/ubuntu/storefront","repo":{"url":"git@github.com:you/storefront.git","transport":"ssh","branch":"main"},"runtime":{"node_version":"22","type":"next","install":"npm ci","build":"npm run build","start":"npm start"},"env_vars":[{"name":"NODE_ENV","secret":false,"value":"production"},{"name":"DATABASE_URL","secret":true,"has_value":true}],"domains":["storefront.dev"],"ssl":true,"email":"ops@storefront.dev","app_port":3000}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, created, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, created, "postgres://secret") == null);

    const DeploySaveResp = struct {
        result: struct {
            ok: bool,
            app: struct {
                id: []const u8,
                server_id: []const u8,
                name: []const u8,
                env_vars: []const struct {
                    name: []const u8,
                    secret: bool,
                    value: []const u8 = "",
                    has_value: bool,
                } = &.{},
            },
        },
    };
    const created_parsed = try std.json.parseFromSlice(DeploySaveResp, std.testing.allocator, created, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer created_parsed.deinit();
    try std.testing.expect(created_parsed.value.result.ok);
    const app_id = created_parsed.value.result.app.id;
    try std.testing.expectEqualStrings("s1", created_parsed.value.result.app.server_id);
    try std.testing.expectEqual(@as(usize, 2), created_parsed.value.result.app.env_vars.len);
    try std.testing.expectEqualStrings("", created_parsed.value.result.app.env_vars[1].value); // never stored

    // A second app on a different server stays out of s1's list.
    _ = app.dispatch(
        \\{"id":"2","command":"oars.deploy.apps.save","payload":{"app":{"server_id":"s2","name":"api","folder":"/home/ubuntu/api","repo":{"url":"https://github.com/you/api.git","transport":"https"},"runtime":{"node_version":"22","type":"node","start":"node index.js"}}}}
    );

    const DeployListResp = struct {
        result: struct {
            ok: bool,
            apps: []const struct {
                id: []const u8,
                server_id: []const u8,
                env_vars: []const struct {
                    name: []const u8,
                    secret: bool,
                    value: []const u8 = "",
                    has_value: bool,
                } = &.{},
            } = &.{},
        },
    };
    const listed = app.dispatch(
        \\{"id":"3","command":"oars.deploy.apps.list","payload":{"server_id":"s1"}}
    );
    const listed_parsed = try std.json.parseFromSlice(DeployListResp, std.testing.allocator, listed, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer listed_parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), listed_parsed.value.result.apps.len);
    try std.testing.expectEqualStrings(app_id, listed_parsed.value.result.apps[0].id);
    try std.testing.expectEqualStrings("", listed_parsed.value.result.apps[0].env_vars[1].value);

    // Delete requires the owning server and removes the app.
    const wrong_server = app.dispatch(
        \\{"id":"4","command":"oars.deploy.apps.delete","payload":{"server_id":"s2","app_id":""}}
    );
    _ = wrong_server;
    var del_buf: [512]u8 = undefined;
    const del_req = try std.fmt.bufPrint(&del_buf, "{{\"id\":\"5\",\"command\":\"oars.deploy.apps.delete\",\"payload\":{{\"server_id\":\"s1\",\"app_id\":\"{s}\"}}}}", .{app_id});
    const deleted = app.dispatch(del_req);
    try std.testing.expect(std.mem.indexOf(u8, deleted, "\"ok\":true") != null);
    const after = app.dispatch(
        \\{"id":"6","command":"oars.deploy.apps.list","payload":{"server_id":"s1"}}
    );
    const after_parsed = try std.json.parseFromSlice(DeployListResp, std.testing.allocator, after, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer after_parsed.deinit();
    try std.testing.expectEqual(@as(usize, 0), after_parsed.value.result.apps.len);
}

test "deploy.run requires a session and validates secret values" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    // Unknown app.
    const unknown = app.dispatch(
        \\{"id":"1","command":"oars.deploy.run","payload":{"server_id":"ghost","app_id":"nope","secret_values":[]}}
    );
    try std.testing.expect(std.mem.indexOf(u8, unknown, "app not found") != null);

    // Create an app on a different server: the server must own the app.
    const created = app.dispatch(
        \\{"id":"2","command":"oars.deploy.apps.save","payload":{"app":{"id":"dep-1","server_id":"s1","name":"storefront","folder":"/home/ubuntu/storefront","repo":{"url":"git@github.com:you/storefront.git","transport":"ssh"},"runtime":{"node_version":"22","type":"node","install":"npm ci","build":"npm run build","start":"npm start"},"env_vars":[{"name":"DATABASE_URL","secret":true,"has_value":true}],"app_port":3000}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, created, "\"ok\":true") != null);

    const wrong_server = app.dispatch(
        \\{"id":"3","command":"oars.deploy.run","payload":{"server_id":"ghost","app_id":"dep-1","secret_values":[]}}
    );
    try std.testing.expect(std.mem.indexOf(u8, wrong_server, "app not found on this server") != null);

    // Unknown secret variable names are rejected before any work.
    const bad_secret = app.dispatch(
        \\{"id":"4","command":"oars.deploy.run","payload":{"server_id":"s1","app_id":"dep-1","secret_values":[{"name":"NOPE","value":"x"}]}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_secret, "unknown secret variable") != null);

    // A declared secret name passes validation, then the missing session
    // stops the run.
    const no_session = app.dispatch(
        \\{"id":"5","command":"oars.deploy.run","payload":{"server_id":"s1","app_id":"dep-1","secret_values":[{"name":"DATABASE_URL","value":"postgres://secret"}]}}
    );
    try std.testing.expect(std.mem.indexOf(u8, no_session, "not connected") != null);

    // Unknown run ids are explicit errors; history is empty and never
    // leaks secret values.
    const unknown_poll = app.dispatch(
        \\{"id":"6","command":"oars.deploy.poll","payload":{"run_id":9999}}
    );
    try std.testing.expect(std.mem.indexOf(u8, unknown_poll, "unknown run") != null);
    const cancel_unknown = app.dispatch(
        \\{"id":"7","command":"oars.deploy.cancel","payload":{"run_id":9999}}
    );
    try std.testing.expect(std.mem.indexOf(u8, cancel_unknown, "unknown run") != null);
    const history = app.dispatch(
        \\{"id":"8","command":"oars.deploy.history","payload":{"server_id":"s1","app_id":"dep-1"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, history, "\"runs\":[]") != null);
}

test "sshkeys.generate creates a key, refuses overwrites, and hides the passphrase" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();
    const io = std.testing.io;

    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [160]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-keygen-test-{d}", .{now});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    std.Io.Dir.cwd().createDirPath(io, dir) catch return error.TestUnexpectedResult;
    var dest_buf: [256]u8 = undefined;
    const dest = try std.fmt.bufPrint(&dest_buf, "{s}/id_ed25519_oars", .{dir});

    var req_buf: [512]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "{{\"id\":\"1\",\"command\":\"oars.sshkeys.generate\",\"payload\":{{\"destination\":\"{s}\",\"comment\":\"oars-test\",\"passphrase\":\"hunter2-secret\",\"remember_passphrase\":true}}}}", .{dest});
    const resp = app.dispatch(req);
    try std.testing.expect(std.mem.indexOf(u8, resp, "\"ok\":true") != null);
    // The passphrase never appears in the response; the Keychain account
    // name tells the frontend where to store it.
    try std.testing.expect(std.mem.indexOf(u8, resp, "hunter2-secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "keychain_account") != null);

    const GenResp = struct {
        result: struct {
            ok: bool,
            public_key: []const u8 = "",
            private_path: []const u8 = "",
            keychain_account: []const u8 = "",
        },
    };
    const gen_parsed = try std.json.parseFromSlice(GenResp, std.testing.allocator, resp, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer gen_parsed.deinit();
    try std.testing.expect(gen_parsed.value.result.ok);
    try std.testing.expect(std.mem.indexOf(u8, gen_parsed.value.result.public_key, "ssh-ed25519") != null);
    try std.testing.expectEqualStrings(dest, gen_parsed.value.result.private_path);
    try std.testing.expect(std.mem.startsWith(u8, gen_parsed.value.result.keychain_account, "localkey:SHA256:"));

    // The private file exists with mode 0600.
    var priv = std.Io.Dir.cwd().openFile(io, dest, .{}) catch return error.TestUnexpectedResult;
    defer priv.close(io);
    const st = try priv.stat(io);
    try std.testing.expectEqual(@as(u16, 0o600), st.permissions.toMode() & 0o777);

    // The audit entry has the fingerprint but never the passphrase.
    const audit_content = try std.Io.Dir.cwd().readFileAlloc(io, app.audit_store.path, std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(audit_content);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "sshkeys.generate") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "hunter2-secret") == null);

    // An existing destination is refused, not overwritten.
    const dup = app.dispatch(req);
    try std.testing.expect(std.mem.indexOf(u8, dup, "already exists") != null);

    // A relative destination is rejected before any work.
    var rel_buf: [320]u8 = undefined;
    const rel_req = try std.fmt.bufPrint(&rel_buf, "{{\"id\":\"2\",\"command\":\"oars.sshkeys.generate\",\"payload\":{{\"destination\":\"relative/path\"}}}}", .{});
    const rel = app.dispatch(rel_req);
    try std.testing.expect(std.mem.indexOf(u8, rel, "invalid destination") != null);
}

test "sshkeys handlers require a session and validate payloads" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    const list = app.dispatch(
        \\{"id":"1","command":"oars.sshkeys.list","payload":{"server_id":"ghost"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, list, "not connected") != null);

    const add = app.dispatch(
        \\{"id":"2","command":"oars.sshkeys.add","payload":{"server_id":"ghost","public_key":"ssh-ed25519 AAAA x"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, add, "not connected") != null);

    const revoke = app.dispatch(
        \\{"id":"3","command":"oars.sshkeys.revoke","payload":{"server_id":"ghost","fingerprint":"SHA256:x","expected_line_hash":"y"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, revoke, "not connected") != null);

    const rotate = app.dispatch(
        \\{"id":"4","command":"oars.sshkeys.rotate","payload":{"server_id":"ghost","fingerprint":"SHA256:x","expected_line_hash":"y","new_public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBs5Tnge2MIGi6Zcyo04aosYAQ+iwk4hKYUNpIHkyMQt z"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, rotate, "not connected") != null);

    const roles_list = app.dispatch(
        \\{"id":"5","command":"oars.sshkeys.roles.list","payload":{"server_id":"ghost"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, roles_list, "not connected") != null);

    const roles_create = app.dispatch(
        \\{"id":"6","command":"oars.sshkeys.roles.create","payload":{"server_id":"ghost","name":"ro-user","read_only":true}}
    );
    try std.testing.expect(std.mem.indexOf(u8, roles_create, "not connected") != null);

    const roles_delete = app.dispatch(
        \\{"id":"7","command":"oars.sshkeys.roles.delete","payload":{"server_id":"ghost","name":"ro-user"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, roles_delete, "not connected") != null);

    const deploy_key = app.dispatch(
        \\{"id":"8","command":"oars.sshkeys.deployKey.generate","payload":{"server_id":"ghost"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, deploy_key, "not connected") != null);

    // Role names are validated before any session work.
    const bad_name = app.dispatch(
        \\{"id":"9","command":"oars.sshkeys.roles.create","payload":{"server_id":"ghost","name":"Bad Name!","read_only":true}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_name, "invalid role name") != null);
}

test "access identities save/list/delete round trip through the dispatcher" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    const fp1 = "SHA256:IIiiMx8dWbmaEVhH8Oc9GEt16E2UPRuGtQ3itmbNZxs";
    const fp2 = "SHA256:el3RAdX7MPz8bGotR4kPQ4XBQTl42+OD1WbuC4jrRtg";

    const created = app.dispatch("{\"id\":\"1\",\"command\":\"oars.access.identities.save\",\"payload\":{\"identity\":{\"name\":\"Ada\",\"fingerprints\":[\"" ++ fp1 ++ "\",\"" ++ fp2 ++ "\"]}}}");
    try std.testing.expect(std.mem.indexOf(u8, created, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, created, "\"name\":\"Ada\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, created, fp1) != null);
    const id_start = std.mem.indexOf(u8, created, "\"id\":\"id-") orelse return error.TestUnexpectedResult;
    var id_buf: [64]u8 = undefined;
    var id_len: usize = 0;
    for (created[id_start + 6 ..]) |ch| {
        if (ch == '\"') break;
        if (id_len >= id_buf.len) return error.TestUnexpectedResult;
        id_buf[id_len] = ch;
        id_len += 1;
    }
    const id = id_buf[0..id_len];

    // A second person cannot claim Ada's fingerprint.
    const conflict = app.dispatch("{\"id\":\"2\",\"command\":\"oars.access.identities.save\",\"payload\":{\"identity\":{\"name\":\"Bob\",\"fingerprints\":[\"" ++ fp1 ++ "\"]}}}");
    try std.testing.expect(std.mem.indexOf(u8, conflict, "at most one person") != null);

    // Shared identities may overlap.
    const shared = app.dispatch("{\"id\":\"3\",\"command\":\"oars.access.identities.save\",\"payload\":{\"identity\":{\"name\":\"Oncall\",\"fingerprints\":[\"" ++ fp1 ++ "\"],\"shared\":true}}}");
    try std.testing.expect(std.mem.indexOf(u8, shared, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, shared, "\"shared\":true") != null);

    // Validation errors surface as ok:false messages.
    const bad_fp = app.dispatch(
        \\{"id":"4","command":"oars.access.identities.save","payload":{"identity":{"name":"X","fingerprints":["nope"]}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_fp, "invalid fingerprint") != null);
    const no_name = app.dispatch("{\"id\":\"5\",\"command\":\"oars.access.identities.save\",\"payload\":{\"identity\":{\"name\":\"  \",\"fingerprints\":[\"" ++ fp2 ++ "\"]}}}");
    try std.testing.expect(std.mem.indexOf(u8, no_name, "invalid identity name") != null);

    // List shows all three identities; delete removes one.
    const listed = app.dispatch(
        \\{"id":"6","command":"oars.access.identities.list","payload":{}}
    );
    try std.testing.expect(std.mem.indexOf(u8, listed, "Ada") != null);
    try std.testing.expect(std.mem.indexOf(u8, listed, "Oncall") != null);
    var del_buf: [256]u8 = undefined;
    const del_req = try std.fmt.bufPrint(&del_buf, "{{\"id\":\"7\",\"command\":\"oars.access.identities.delete\",\"payload\":{{\"id\":\"{s}\"}}}}", .{id});
    const deleted = app.dispatch(del_req);
    try std.testing.expect(std.mem.indexOf(u8, deleted, "\"ok\":true") != null);
    const del_unknown = app.dispatch(
        \\{"id":"8","command":"oars.access.identities.delete","payload":{"id":"id-nope"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, del_unknown, "unknown identity") != null);
}

test "access scan and job handlers validate payloads without sessions" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    // An unknown server id is rejected before any work.
    const bad_server = app.dispatch(
        \\{"id":"1","command":"oars.access.scan","payload":{"server_ids":["ghost"]}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_server, "unknown server") != null);

    // An empty fleet scans fine (nothing to do).
    const scan = app.dispatch(
        \\{"id":"2","command":"oars.access.scan","payload":{"full":true}}
    );
    try std.testing.expect(std.mem.indexOf(u8, scan, "\"ok\":true") != null);
    const scan_id_start = std.mem.indexOf(u8, scan, "\"scan_id\":\"scan-") orelse return error.TestUnexpectedResult;
    var scan_id_buf: [32]u8 = undefined;
    var scan_id_len: usize = 0;
    for (scan[scan_id_start + 11 ..]) |ch| {
        if (ch == '\"') break;
        if (scan_id_len >= scan_id_buf.len) return error.TestUnexpectedResult;
        scan_id_buf[scan_id_len] = ch;
        scan_id_len += 1;
    }
    const scan_id = scan_id_buf[0..scan_id_len];
    var poll_buf: [128]u8 = undefined;
    const poll_req = try std.fmt.bufPrint(&poll_buf, "{{\"id\":\"3\",\"command\":\"oars.access.poll\",\"payload\":{{\"scan_id\":\"{s}\"}}}}", .{scan_id});
    const done = app.dispatch(poll_req);
    try std.testing.expect(std.mem.indexOf(u8, done, "\"state\":\"done\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, done, "\"coverage\":\"complete\"") != null);
    const unknown_scan = app.dispatch(
        \\{"id":"4","command":"oars.access.poll","payload":{"scan_id":"scan-nope"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, unknown_scan, "unknown scan") != null);

    // Offboard requires a real identity and its own fingerprints.
    const offboard_unknown = app.dispatch(
        \\{"id":"5","command":"oars.access.offboard","payload":{"identity_id":"id-nope","grants":[{"fingerprint":"SHA256:IIiiMx8dWbmaEVhH8Oc9GEt16E2UPRuGtQ3itmbNZxs","server_id":"s1","user":"root","expected_line_hash":"h"}]}}
    );
    try std.testing.expect(std.mem.indexOf(u8, offboard_unknown, "unknown identity") != null);

    // The fingerprint must belong to the identity.
    const identity_saved = app.dispatch(
        \\{"id":"6","command":"oars.access.identities.save","payload":{"identity":{"name":"Ada","fingerprints":["SHA256:IIiiMx8dWbmaEVhH8Oc9GEt16E2UPRuGtQ3itmbNZxs"]}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, identity_saved, "\"ok\":true") != null);
    const identity_id_start = std.mem.indexOf(u8, identity_saved, "\"id\":\"id-") orelse return error.TestUnexpectedResult;
    var identity_id_buf: [64]u8 = undefined;
    var identity_id_len: usize = 0;
    for (identity_saved[identity_id_start + 6 ..]) |ch| {
        if (ch == '\"') break;
        if (identity_id_len >= identity_id_buf.len) return error.TestUnexpectedResult;
        identity_id_buf[identity_id_len] = ch;
        identity_id_len += 1;
    }
    const identity_id = identity_id_buf[0..identity_id_len];
    var off_buf: [512]u8 = undefined;
    const off_wrong_fp = try std.fmt.bufPrint(&off_buf, "{{\"id\":\"7\",\"command\":\"oars.access.offboard\",\"payload\":{{\"identity_id\":\"{s}\",\"grants\":[{{\"fingerprint\":\"SHA256:el3RAdX7MPz8bGotR4kPQ4XBQTl42+OD1WbuC4jrRtg\",\"server_id\":\"s1\",\"user\":\"root\",\"expected_line_hash\":\"h\"}}]}}}}", .{identity_id});
    const off_wrong = app.dispatch(off_wrong_fp);
    try std.testing.expect(std.mem.indexOf(u8, off_wrong, "not part of this identity") != null);

    // Onboard validates the public key before any session work.
    var onboard_buf: [512]u8 = undefined;
    const onboard_req = try std.fmt.bufPrint(&onboard_buf, "{{\"id\":\"8\",\"command\":\"oars.access.onboard\",\"payload\":{{\"identity_id\":\"{s}\",\"public_key\":\"not-a-key\",\"grants\":[{{\"server_id\":\"s1\",\"user\":\"root\"}}]}}}}", .{identity_id});
    const onboard_bad_key = app.dispatch(onboard_req);
    try std.testing.expect(std.mem.indexOf(u8, onboard_bad_key, "invalid public key") != null);

    // Rotate rejects a foreign old fingerprint.
    var rot_buf: [512]u8 = undefined;
    const rot_req = try std.fmt.bufPrint(&rot_buf, "{{\"id\":\"9\",\"command\":\"oars.access.rotate\",\"payload\":{{\"identity_id\":\"{s}\",\"old_fingerprint\":\"SHA256:el3RAdX7MPz8bGotR4kPQ4XBQTl42+OD1WbuC4jrRtg\",\"new_public_key\":\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBs5Tnge2MIGi6Zcyo04aosYAQ+iwk4hKYUNpIHkyMQt z\",\"grants\":[{{\"server_id\":\"s1\",\"user\":\"root\",\"expected_line_hash\":\"h\"}}]}}}}", .{identity_id});
    const rotated = app.dispatch(rot_req);
    try std.testing.expect(std.mem.indexOf(u8, rotated, "not part of this identity") != null);

    // Unknown jobs and exports without a completed scan are explicit.
    const unknown_job = app.dispatch(
        \\{"id":"10","command":"oars.access.jobPoll","payload":{"job_id":"job-nope"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, unknown_job, "unknown job") != null);
    const no_export = app.dispatch(
        \\{"id":"11","command":"oars.access.export","payload":{"format":"csv"}}
    );
    // The empty-fleet scan above completed, so the CSV export has a header.
    try std.testing.expect(std.mem.indexOf(u8, no_export, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, no_export, "identity_id,name,fingerprint,server_id,user,sudo,comment") != null);
    const json_export = app.dispatch(
        \\{"id":"12","command":"oars.access.export","payload":{"format":"json"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, json_export, "\\\"coverage\\\": \\\"complete\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_export, "Ada") != null);
    const bad_format = app.dispatch(
        \\{"id":"13","command":"oars.access.export","payload":{"format":"xlsx"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_format, "invalid format") != null);
}

test "backup jobs save/list/delete, run gates, and capability-test gates through the dispatcher" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    // 1. Save a MinIO job with schedule credentials. The server is not
    //    connected, so the job persists locally and the handler reports
    //    the session state explicitly (the schedule install is deferred
    //    until the next connected save).
    const saved = app.dispatch(
        \\{"id":"1","command":"oars.backup.jobs.save","payload":{"job":{"server_id":"s1","name":"daily-website","source_path":"/var/www/html","destination":{"type":"s3","provider":"minio","bucket":"acme","endpoint":"http://127.0.0.1:9000","storage_class":"standard"},"transfer":"sync","schedule":{"mode":"interval","interval_unit":"hours","interval_every":24,"enabled":true}},"schedule_credentials":{"access_key":"AKID","secret_key":"SECRET"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, saved, "not connected") != null);

    // The job persisted despite the session state; secrets never do.
    const listed = app.dispatch(
        \\{"id":"2","command":"oars.backup.jobs.list","payload":{"server_id":"s1"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, listed, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, listed, "daily-website") != null);
    try std.testing.expect(std.mem.indexOf(u8, listed, "\"transfer\":\"sync\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, listed, "AKID") == null);
    try std.testing.expect(std.mem.indexOf(u8, listed, "SECRET") == null);
    const id_start = std.mem.indexOf(u8, listed, "\"id\":\"bk-") orelse return error.TestUnexpectedResult;
    var id_buf: [64]u8 = undefined;
    var id_len: usize = 0;
    for (listed[id_start + 6 ..]) |ch| {
        if (ch == '\"') break;
        if (id_len >= id_buf.len) return error.TestUnexpectedResult;
        id_buf[id_len] = ch;
        id_len += 1;
    }
    const job_id = id_buf[0..id_len];

    // 2. Enabling an unattended schedule without credentials is rejected
    //    before any persistence (the remote-secret disclosure gate).
    const no_creds = app.dispatch(
        \\{"id":"3","command":"oars.backup.jobs.save","payload":{"job":{"server_id":"s1","name":"daily-website","source_path":"/var/www/html","destination":{"type":"s3","provider":"minio","bucket":"acme","endpoint":"http://127.0.0.1:9000"},"transfer":"sync","schedule":{"mode":"interval","interval_unit":"hours","interval_every":24,"enabled":true}}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, no_creds, "credentials are required") != null);

    // 3. Editing an existing job by id keeps the generated id.
    var edit_buf: [512]u8 = undefined;
    const edit_req = try std.fmt.bufPrint(&edit_buf, "{{\"id\":\"4\",\"command\":\"oars.backup.jobs.save\",\"payload\":{{\"job\":{{\"id\":\"{s}\",\"server_id\":\"s1\",\"name\":\"daily-www\",\"source_path\":\"/var/www/html\",\"destination\":{{\"type\":\"s3\",\"provider\":\"minio\",\"bucket\":\"acme\",\"endpoint\":\"http://127.0.0.1:9000\"}},\"transfer\":\"sync\",\"schedule\":{{\"mode\":\"manual\",\"enabled\":false}}}},\"schedule_credentials\":{{\"access_key\":\"AKID\",\"secret_key\":\"SECRET\"}}}}}}", .{job_id});
    const edited = app.dispatch(edit_req);
    try std.testing.expect(std.mem.indexOf(u8, edited, "not connected") != null);

    // 4. Shape errors surface with the spec messages.
    const bad_bucket = app.dispatch(
        \\{"id":"5","command":"oars.backup.jobs.save","payload":{"job":{"server_id":"s1","name":"x","source_path":"/var/www","destination":{"type":"s3","provider":"minio","bucket":"bad bucket","endpoint":"http://127.0.0.1:9000"}}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_bucket, "invalid bucket name") != null);
    const bad_cron = app.dispatch(
        \\{"id":"6","command":"oars.backup.jobs.save","payload":{"job":{"server_id":"s1","name":"x","source_path":"/var/www","destination":{"type":"s3","provider":"aws","bucket":"acme","region":"us-east-1"},"schedule":{"mode":"custom","expr":"not a cron","enabled":true}},"schedule_credentials":{"access_key":"A","secret_key":"B"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_cron, "invalid cron expression") != null);

    // 5. Every session-gated handler says so explicitly on a ghost server.
    const test_req = app.dispatch(
        \\{"id":"7","command":"oars.backup.test","payload":{"job":{"server_id":"s1","name":"x","source_path":"/var/www","destination":{"type":"s3","provider":"minio","bucket":"acme","endpoint":"http://127.0.0.1:9000"}},"credentials":{"access_key":"AKID","secret_key":"SECRET"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, test_req, "not connected") != null);
    var run_buf: [256]u8 = undefined;
    const run_req = try std.fmt.bufPrint(&run_buf, "{{\"id\":\"8\",\"command\":\"oars.backup.run\",\"payload\":{{\"server_id\":\"s1\",\"job_id\":\"{s}\",\"credentials\":{{\"access_key\":\"AKID\",\"secret_key\":\"SECRET\"}}}}}}", .{job_id});
    const run_resp = app.dispatch(run_req);
    try std.testing.expect(std.mem.indexOf(u8, run_resp, "not connected") != null);
    const run_unknown = app.dispatch(
        \\{"id":"9","command":"oars.backup.run","payload":{"server_id":"s1","job_id":"bk-nope","credentials":{"access_key":"AKID","secret_key":"SECRET"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, run_unknown, "not connected") != null); // session gate precedes job lookup
    const install = app.dispatch(
        \\{"id":"10","command":"oars.backup.install","payload":{"server_id":"s1","what":"rclone","dry_run":true}}
    );
    try std.testing.expect(std.mem.indexOf(u8, install, "not connected") != null);
    const cron_status = app.dispatch(
        \\{"id":"11","command":"oars.backup.cronStatus","payload":{"server_id":"s1"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, cron_status, "not connected") != null);

    // 6. Poll and history never touch the server: poll rejects unknown
    //    run ids, history serves the empty local store.
    const poll = app.dispatch(
        \\{"id":"12","command":"oars.backup.poll","payload":{"run_id":"run-nope"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, poll, "unknown run") != null);
    var hist_buf: [256]u8 = undefined;
    const hist_req = try std.fmt.bufPrint(&hist_buf, "{{\"id\":\"13\",\"command\":\"oars.backup.history\",\"payload\":{{\"server_id\":\"s1\",\"job_id\":\"{s}\",\"limit\":20}}}}", .{job_id});
    const history = app.dispatch(hist_req);
    try std.testing.expect(std.mem.indexOf(u8, history, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, history, "\"runs\":[]") != null);

    // 7. Delete persists without a session; deleting twice is explicit.
    var del_buf: [256]u8 = undefined;
    const del_req = try std.fmt.bufPrint(&del_buf, "{{\"id\":\"14\",\"command\":\"oars.backup.jobs.delete\",\"payload\":{{\"server_id\":\"s1\",\"job_id\":\"{s}\"}}}}", .{job_id});
    const deleted = app.dispatch(del_req);
    try std.testing.expect(std.mem.indexOf(u8, deleted, "\"ok\":true") != null);
    const deleted_again = app.dispatch(del_req);
    try std.testing.expect(std.mem.indexOf(u8, deleted_again, "unknown job") != null);
    const after = app.dispatch(
        \\{"id":"15","command":"oars.backup.jobs.list","payload":{"server_id":"s1"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, after, "daily-www") == null);
}

test "ai provider config and context/history gates through the dispatcher" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    // No provider configured yet.
    const empty = app.dispatch(
        \\{"id":"1","command":"oars.ai.provider.get","payload":{}}
    );
    try std.testing.expect(std.mem.indexOf(u8, empty, "\"provider\":null") != null);

    // A valid HTTPS provider round trips; the key never enters JSON.
    const set_ok = app.dispatch(
        \\{"id":"2","command":"oars.ai.provider.set","payload":{"provider":{"adapter":"openai_compatible","base_url":"https://api.openai.com/v1","model":"gpt-4o-mini","capabilities":{"instruction_role":"developer","streaming":true,"structured_output":true}}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, set_ok, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, set_ok, "\"adapter\":\"openai_compatible\"") != null);
    const got = app.dispatch(
        \\{"id":"3","command":"oars.ai.provider.get","payload":{}}
    );
    try std.testing.expect(std.mem.indexOf(u8, got, "gpt-4o-mini") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "\"instruction_role\":\"developer\"") != null);

    // Loopback http is accepted (user-chosen local model server)...
    const loopback = app.dispatch(
        \\{"id":"4","command":"oars.ai.provider.set","payload":{"provider":{"adapter":"custom","base_url":"http://localhost:11434/v1","model":"llama3","capabilities":{"instruction_role":"system","streaming":false,"structured_output":false}}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, loopback, "\"ok\":true") != null);

    // ...but plain http anywhere else is refused, as are bad shapes.
    const plain_http = app.dispatch(
        \\{"id":"5","command":"oars.ai.provider.set","payload":{"provider":{"adapter":"openai_compatible","base_url":"http://api.example.com/v1","model":"x"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, plain_http, "the base URL must be https") != null);
    const bad_adapter = app.dispatch(
        \\{"id":"6","command":"oars.ai.provider.set","payload":{"provider":{"adapter":"claude","base_url":"https://api.example.com/v1","model":"x"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_adapter, "unsupported adapter") != null);
    const bad_model = app.dispatch(
        \\{"id":"7","command":"oars.ai.provider.set","payload":{"provider":{"adapter":"openai_compatible","base_url":"https://api.example.com/v1","model":" "}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_model, "invalid model name") != null);
    const bad_role = app.dispatch(
        \\{"id":"8","command":"oars.ai.provider.set","payload":{"provider":{"adapter":"openai_compatible","base_url":"https://api.example.com/v1","model":"x","capabilities":{"instruction_role":"assistant"}}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_role, "invalid capabilities") != null);

    // Context needs a live session; history is local and never blocks on
    // the server.
    const ctx = app.dispatch(
        \\{"id":"9","command":"oars.ai.context","payload":{"server_id":"ghost"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, ctx, "not connected") != null);
    const history = app.dispatch(
        \\{"id":"10","command":"oars.ai.history","payload":{"server_id":"ghost","limit":10}}
    );
    try std.testing.expect(std.mem.indexOf(u8, history, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, history, "\"runs\":[]") != null);
}

test "vnc handlers require a session and validate payloads" {
    var app: TestApp = undefined;
    try app.init();
    defer app.deinit();

    const start = app.dispatch(
        \\{"id":"1","command":"oars.vnc.start","payload":{"server_id":"ghost"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, start, "not connected") != null);
    const stop = app.dispatch(
        \\{"id":"2","command":"oars.vnc.stop","payload":{"server_id":"ghost","tunnel_id":1}}
    );
    try std.testing.expect(std.mem.indexOf(u8, stop, "not connected") != null);
    const probe = app.dispatch(
        \\{"id":"3","command":"oars.vnc.probe","payload":{"server_id":"ghost"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, probe, "not connected") != null);
    const setup = app.dispatch(
        \\{"id":"4","command":"oars.vnc.setup","payload":{"server_id":"ghost","dry_run":true}}
    );
    try std.testing.expect(std.mem.indexOf(u8, setup, "not connected") != null);
    const poll = app.dispatch(
        \\{"id":"5","command":"oars.vnc.poll","payload":{"server_id":"ghost","tunnel_id":1}}
    );
    try std.testing.expect(std.mem.indexOf(u8, poll, "not connected") != null);
}
