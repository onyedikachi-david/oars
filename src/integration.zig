//! Env-gated integration tests against a live sshd.
//!
//! These tests exercise the full session stack (DNS, handshake, trust,
//! auth, shell, exec, resize, disconnect) against a real server. They are
//! skipped unless `OARS_TEST_SSH_*` is set — `scripts/dev-sshd.sh up` +
//! `scripts/integration-test.sh` provide the container and variables
//! (spec 02 §11).
//!
//! Runs are parallel and independent: every test uses its own temp store
//! and server id.

const std = @import("std");
const builtin = @import("builtin");
const ssh = @import("ssh.zig");
const servers = @import("servers.zig");
const sessions = @import("sessions.zig");

/// Reads an environment variable from the process environment. The raw
/// environ pointer is the only env source in 0.16 outside `main(init)`.
fn getEnv(name: []const u8) ?[]const u8 {
    if (builtin.os.tag == .windows) return null;
    const environ = std.c.environ;
    var i: usize = 0;
    while (environ[i]) |entry| : (i += 1) {
        const raw: []const u8 = std.mem.span(entry);
        const eq = std.mem.indexOfScalar(u8, raw, '=') orelse continue;
        if (std.mem.eql(u8, raw[0..eq], name)) return raw[eq + 1 ..];
    }
    return null;
}

const TestEnv = struct {
    active: bool = false,
    host: []const u8 = "",
    port: u16 = 22,
    user: []const u8 = "root",
    password: []const u8 = "",
    key_path: []const u8 = "",
    passphrase: []const u8 = "",

    fn load() TestEnv {
        const host = getEnv("OARS_TEST_SSH_HOST") orelse return .{};
        return .{
            .active = true,
            .host = host,
            .port = std.fmt.parseInt(u16, getEnv("OARS_TEST_SSH_PORT") orelse "22", 10) catch 22,
            .user = getEnv("OARS_TEST_SSH_USER") orelse "root",
            .password = getEnv("OARS_TEST_SSH_PASSWORD") orelse "",
            .key_path = getEnv("OARS_TEST_SSH_KEY_PATH") orelse "",
            .passphrase = getEnv("OARS_TEST_SSH_PASSPHRASE") orelse "",
        };
    }
};

/// A temp store + manager pair backed by std.testing.allocator, so every
/// allocation the session stack makes is leak-checked. init() runs in
/// place: the manager holds a pointer to the store inside the rig.
const TestRig = struct {
    dir_buf: [128]u8 = undefined,
    path_buf: [512]u8 = undefined,
    dir_name: []const u8,
    store: servers.Store,
    manager: sessions.Manager,

    fn init(self: *TestRig, tag: []const u8) !void {
        const io = std.testing.io;
        const now = std.Io.Timestamp.now(io, .real).nanoseconds;
        self.dir_name = try std.fmt.bufPrint(&self.dir_buf, "oars-itest-{s}-{d}", .{ tag, now });
        const store_path = try std.fmt.bufPrint(&self.path_buf, "/tmp/{s}/servers.json", .{self.dir_name});
        self.store = .{ .allocator = std.testing.allocator, .path = store_path };
        self.manager = sessions.Manager.init(std.testing.allocator, io, &self.store, null);
    }

    fn deinit(self: *TestRig) void {
        self.manager.deinit();
        std.Io.Dir.cwd().deleteTree(std.testing.io, self.dir_name) catch {};
    }
};

/// Waits for a session status, failing explicitly on error status or
/// timeout. `want_error_text` (optional) is asserted when the session
/// lands in the error state.
fn waitForStatus(
    manager: *sessions.Manager,
    server_id: []const u8,
    want: sessions.Status,
    timeout_ns: i128,
) !void {
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + timeout_ns;
    while (true) {
        const info = try manager.sessionSnapshot(server_id);
        if (info.status == want) return;
        if (info.status == .@"error") return error.TestUnexpectedResult;
        if (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds >= deadline) return error.TestUnexpectedResult;
        std.Thread.sleep(50 * std.time.ns_per_ms);
    }
}

/// Sends a marker line to the shell and waits for it to come back.
fn shellEchoRoundTrip(manager: *sessions.Manager, server_id: []const u8, marker: []const u8) !void {
    var payload_buf: [128]u8 = undefined;
    const payload = try std.fmt.bufPrint(&payload_buf, "echo {s}\n", .{marker});
    try manager.input(server_id, payload);
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 10 * std.time.ns_per_s;
    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(std.testing.allocator);
    // Channel 0 is the shell; track our own cursor (non-destructive reads).
    var cursor: u64 = 0;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        const polls = try manager.pollChannels(server_id, &.{.{ .id = 0, .pos = cursor }}, false, 64 * 1024, 64 * 1024);
        for (polls) |*poll| {
            if (poll.id != 0) continue;
            try acc.appendSlice(std.testing.allocator, poll.data);
            cursor = poll.cursor;
        }
        for (polls) |*poll| poll.deinit(std.testing.allocator);
        std.testing.allocator.free(polls);
        if (std.mem.indexOf(u8, acc.items, marker) != null) return;
        std.Thread.sleep(50 * std.time.ns_per_ms);
    }
    return error.TestUnexpectedResult;
}

/// Sends a command line to the shell and waits for its output to contain
/// `want` (used for PTY state checks like `stty size`).
fn shellReadUntil(manager: *sessions.Manager, server_id: []const u8, command: []const u8, want: []const u8) !void {
    try manager.input(server_id, command);
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 10 * std.time.ns_per_s;
    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(std.testing.allocator);
    var cursor: u64 = 0;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        const polls = try manager.pollChannels(server_id, &.{.{ .id = 0, .pos = cursor }}, false, 64 * 1024, 64 * 1024);
        for (polls) |*poll| {
            if (poll.id != 0) continue;
            try acc.appendSlice(std.testing.allocator, poll.data);
            cursor = poll.cursor;
        }
        for (polls) |*poll| poll.deinit(std.testing.allocator);
        std.testing.allocator.free(polls);
        if (std.mem.indexOf(u8, acc.items, want) != null) return;
        std.Thread.sleep(50 * std.time.ns_per_ms);
    }
    return error.TestUnexpectedResult;
}

/// Runs an exec and waits for its channel to complete with the expected
/// exit code and output marker (the channel stays readable after EOF).
fn execWait(manager: *sessions.Manager, server_id: []const u8, command: []const u8, want_exit: i32, want_out: []const u8) !void {
    const channel = try manager.exec(server_id, command);
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 15 * std.time.ns_per_s;
    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(std.testing.allocator);
    var saw_eof = false;
    var exit: ?i32 = null;
    var cursor: u64 = 0;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        const polls = try manager.pollChannels(server_id, &.{.{ .id = channel, .pos = cursor }}, false, 64 * 1024, 64 * 1024);
        for (polls) |*poll| {
            if (poll.id != channel) continue;
            try acc.appendSlice(std.testing.allocator, poll.data);
            cursor = poll.cursor;
            saw_eof = poll.eof;
            exit = poll.exit_status;
        }
        for (polls) |*poll| poll.deinit(std.testing.allocator);
        std.testing.allocator.free(polls);
        if (saw_eof and exit != null) {
            try std.testing.expectEqual(want_exit, exit.?);
            if (want_out.len > 0) {
                try std.testing.expect(std.mem.indexOf(u8, acc.items, want_out) != null);
            }
            return;
        }
        std.Thread.sleep(50 * std.time.ns_per_ms);
    }
    return error.TestUnexpectedResult;
}

test "integration: password auth, trust, shell, exec, resize, disconnect" {
    const env = TestEnv.load();
    if (!env.active) return; // skipped: run scripts/integration-test.sh

    // libssh2's global init must happen before any worker touches it.
    ssh.initGlobal();

    var rig: TestRig = undefined;
    try rig.init("password");
    defer rig.deinit();
    const io = std.testing.io;

    var server = servers.Server{
        .id = "itest-password",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
    };
    defer server.deinit(std.testing.allocator);
    try rig.store.upsert(io, server);

    _ = try rig.manager.connect(server, env.password, null);

    // Trust flow: no stored fingerprint -> needs_trust -> accept.
    try waitForStatus(&rig.manager, "itest-password", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-password", true);
    try waitForStatus(&rig.manager, "itest-password", .ready, 20 * std.time.ns_per_s);

    // The accepted fingerprint was persisted in canonical form.
    const saved = (try rig.store.find(io, "itest-password")).?;
    defer {
        var s = saved;
        s.deinit(std.testing.allocator);
    }
    try std.testing.expect(std.mem.startsWith(u8, saved.host_fingerprint.?, "SHA256:"));

    // Shell echo round-trip through the PTY.
    try shellEchoRoundTrip(&rig.manager, "itest-password", "oars-roundtrip-42");

    // Exec exit codes and output streaming.
    try execWait(&rig.manager, "itest-password", "echo hi", 0, "hi");
    try execWait(&rig.manager, "itest-password", "exit 3", 3, "");

    // Resize must take effect on the shell PTY: verify with `stty size`
    // running inside the shell (spec 02 §12).
    try rig.manager.resize("itest-password", 100, 40);
    try shellEchoRoundTrip(&rig.manager, "itest-password", "oars-resize-7");
    try shellReadUntil(&rig.manager, "itest-password", "stty size\n", "100 40");
    try waitForStatus(&rig.manager, "itest-password", .ready, 5 * std.time.ns_per_s);

    // Duplicate connect is an idempotent no-op failure at the manager level
    // (the bridge turns it into an ok + live status response).
    try std.testing.expectError(error.AlreadyConnected, rig.manager.connect(server, env.password, null));

    rig.manager.disconnect("itest-password");
    try std.testing.expectError(error.NoSession, rig.manager.sessionSnapshot("itest-password"));
}

test "integration: ed25519 key auth with passphrase" {
    const env = TestEnv.load();
    if (!env.active) return;
    if (env.key_path.len == 0) return;

    ssh.initGlobal();

    var rig: TestRig = undefined;
    try rig.init("key");
    defer rig.deinit();
    const io = std.testing.io;

    var server = servers.Server{
        .id = "itest-key",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .key,
        .key_path = env.key_path,
        .key_has_passphrase = true,
    };
    defer server.deinit(std.testing.allocator);
    try rig.store.upsert(io, server);

    _ = try rig.manager.connect(server, null, env.passphrase);
    try waitForStatus(&rig.manager, "itest-key", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-key", true);
    try waitForStatus(&rig.manager, "itest-key", .ready, 20 * std.time.ns_per_s);

    try execWait(&rig.manager, "itest-key", "printf key-auth-ok", 0, "key-auth-ok");

    rig.manager.disconnect("itest-key");
}

test "integration: changed host key is rejected with both fingerprints" {
    const env = TestEnv.load();
    if (!env.active) return;

    ssh.initGlobal();

    var rig: TestRig = undefined;
    try rig.init("changed-key");
    defer rig.deinit();
    const io = std.testing.io;

    // A deliberately wrong canonical fingerprint: the worker must hard-fail
    // before auth with an explicit message carrying both values.
    var server = servers.Server{
        .id = "itest-changed",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
        .host_fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    };
    defer server.deinit(std.testing.allocator);
    try rig.store.upsert(io, server);

    _ = try rig.manager.connect(server, env.password, null);
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 20 * std.time.ns_per_s;
    while (true) {
        const info = try rig.manager.sessionSnapshot("itest-changed");
        if (info.status == .@"error") {
            try std.testing.expect(std.mem.indexOf(u8, info.@"error", "host key changed") != null);
            try std.testing.expect(std.mem.indexOf(u8, info.@"error", "SHA256:") != null);
            break;
        }
        if (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds >= deadline) return error.TestUnexpectedResult;
        std.Thread.sleep(50 * std.time.ns_per_ms);
    }
    rig.manager.disconnect("itest-changed");
}

test "integration: disconnect during needs_trust returns promptly" {
    const env = TestEnv.load();
    if (!env.active) return;

    ssh.initGlobal();

    var rig: TestRig = undefined;
    try rig.init("disconnect-trust");
    defer rig.deinit();
    const io = std.testing.io;

    var server = servers.Server{
        .id = "itest-disc",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
    };
    defer server.deinit(std.testing.allocator);
    try rig.store.upsert(io, server);

    _ = try rig.manager.connect(server, env.password, null);
    try waitForStatus(&rig.manager, "itest-disc", .needs_trust, 20 * std.time.ns_per_s);

    // The trust wait is stop-aware: disconnect must return well inside the
    // trust poll interval and tear the session down.
    const started = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds;
    rig.manager.disconnect("itest-disc");
    const elapsed = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds - started;
    try std.testing.expect(elapsed < 2 * std.time.ns_per_s);
    try std.testing.expectError(error.NoSession, rig.manager.sessionSnapshot("itest-disc"));
}
