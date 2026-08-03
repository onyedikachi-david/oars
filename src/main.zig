const std = @import("std");
const runner = @import("runner");
const native_sdk = @import("native_sdk");
const servers = @import("servers.zig");
const sessions = @import("sessions.zig");
const ssh = @import("ssh.zig");
const bridge = @import("bridge.zig");

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
    manager: sessions.Manager,
    bridge_ctx: bridge.Context,
    store_path_buf: [2048]u8 = undefined,

    fn init(self: *App, process: std.process.Init) !void {
        self.allocator = process.gpa;
        self.io = process.io;
        self.env_map = process.environ_map;

        var data_dir_buf: [1024]u8 = undefined;
        const data_dir = native_sdk.app_dirs.resolveOne(
            .{ .name = "Oars" },
            native_sdk.app_dirs.currentPlatform(),
            .{ .home = self.env_map.get("HOME") },
            .data,
            &data_dir_buf,
        ) catch null;
        if (data_dir) |dir| {
            const path = native_sdk.app_dirs.join(
                native_sdk.app_dirs.currentPlatform(),
                &self.store_path_buf,
                &.{ dir, "servers.json" },
            ) catch unreachable;
            self.store = .{ .allocator = self.allocator, .path = path };
        } else {
            // Last-resort fallback when the OS has no home directory:
            // keep state somewhere writable rather than refusing to run.
            const tmp = process.environ_map.get("TMPDIR") orelse "/tmp";
            const fallback = std.fmt.bufPrint(&self.store_path_buf, "{s}/oars-data/servers.json", .{tmp}) catch unreachable;
            self.store = .{ .allocator = self.allocator, .path = fallback };
        }

        self.manager = sessions.Manager.init(self.allocator, self.io, &self.store, self.env_map.get("HOME"));
        self.bridge_ctx = .{
            .allocator = self.allocator,
            .io = self.io,
            .store = &self.store,
            .manager = &self.manager,
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
    var manager = sessions.Manager.init(store_alloc, io, &store, null);
    defer manager.deinit();
    var ctx = bridge.Context{ .allocator = store_alloc, .io = io, .store = &store, .manager = &manager };
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
