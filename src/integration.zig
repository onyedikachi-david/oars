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
const native_sdk = @import("native_sdk");
const ssh = @import("ssh.zig");
const servers = @import("servers.zig");
const sessions = @import("sessions.zig");
const audit = @import("audit.zig");
const logs = @import("logs.zig");
const bridge = @import("bridge.zig");
const sftpmod = @import("sftp.zig");
const scripts = @import("scripts.zig");

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

/// Test sleep: std.Thread.sleep does not exist in 0.16 — sleeps go
/// through the Io clock.
fn testSleep(ms: i64) void {
    std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(ms), .awake) catch {};
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
    audit_path_buf: [512]u8 = undefined,
    logs_path_buf: [512]u8 = undefined,
    scripts_path_buf: [512]u8 = undefined,
    dir_name: []const u8,
    store: servers.Store,
    audit_store: audit.Store,
    logs_store: logs.SourceStore,
    scripts_store: scripts.Store,
    manager: sessions.Manager,
    ctx: bridge.Context,
    dispatcher: native_sdk.BridgeDispatcher,
    output: [64 * 1024]u8 = undefined,

    fn init(self: *TestRig, tag: []const u8) !void {
        const io = std.testing.io;
        const now = std.Io.Timestamp.now(io, .real).nanoseconds;
        self.dir_name = try std.fmt.bufPrint(&self.dir_buf, "oars-itest-{s}-{d}", .{ tag, now });
        const store_path = try std.fmt.bufPrint(&self.path_buf, "/tmp/{s}/servers.json", .{self.dir_name});
        const audit_path = try std.fmt.bufPrint(&self.audit_path_buf, "/tmp/{s}/audit.jsonl", .{self.dir_name});
        const logs_path = try std.fmt.bufPrint(&self.logs_path_buf, "/tmp/{s}/logs.json", .{self.dir_name});
        const scripts_path = try std.fmt.bufPrint(&self.scripts_path_buf, "/tmp/{s}/scripts.json", .{self.dir_name});
        self.store = .{ .allocator = std.testing.allocator, .path = store_path };
        self.audit_store = .{ .allocator = std.testing.allocator, .path = audit_path };
        self.logs_store = .{ .allocator = std.testing.allocator, .path = logs_path };
        self.scripts_store = .{ .allocator = std.testing.allocator, .path = scripts_path };
        self.manager = sessions.Manager.init(std.testing.allocator, io, &self.store, &self.audit_store, null);
        self.ctx = .{ .allocator = std.testing.allocator, .io = io, .store = &self.store, .manager = &self.manager, .audit = &self.audit_store, .logs = &self.logs_store, .scripts = &self.scripts_store };
        self.dispatcher = self.ctx.dispatcher();
    }

    fn deinit(self: *TestRig) void {
        self.manager.deinit();
        std.Io.Dir.cwd().deleteTree(std.testing.io, self.dir_name) catch {};
    }

    /// Returns a slice into `self.output`; the caller must read or parse
    /// it before the next dispatch call.
    fn dispatch(self: *TestRig, request: []const u8) []const u8 {
        return self.dispatcher.dispatch(request, .{ .origin = "zero://app" }, &self.output);
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
        if (info.status == .@"error") {
            std.debug.print("TEST session error: {s}\n", .{info.@"error"});
            return error.TestUnexpectedResult;
        }
        if (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds >= deadline) return error.TestUnexpectedResult;
        testSleep(50);
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
        testSleep(50);
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
        testSleep(50);
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
        testSleep(50);
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

    const server = servers.Server{
        .id = "itest-password",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
    };
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
    // running inside the shell (spec 02 §12). `stty size` prints
    // "rows cols" — resize(cols=100, rows=40) must read "40 100".
    try rig.manager.resize("itest-password", 100, 40);
    try shellEchoRoundTrip(&rig.manager, "itest-password", "oars-resize-7");
    try shellReadUntil(&rig.manager, "itest-password", "stty size\n", "40 100");
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

    const server = servers.Server{
        .id = "itest-key",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .key,
        .key_path = env.key_path,
        .key_has_passphrase = true,
    };
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
    const server = servers.Server{
        .id = "itest-changed",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
        .host_fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    };
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
        testSleep(50);
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

    const server = servers.Server{
        .id = "itest-disc",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
    };
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

test "integration: monitor probes, cleanup plans, and drop-caches audits" {
    const env = TestEnv.load();
    if (!env.active) return;

    ssh.initGlobal();

    var rig: TestRig = undefined;
    try rig.init("monitor");
    defer rig.deinit();
    const io = std.testing.io;

    // Fast cadence so probe behavior is observable in seconds.
    rig.manager.monitor_interval_ns = 200 * std.time.ns_per_ms;
    rig.manager.monitor_liveness_ns = 150 * std.time.ns_per_ms;

    const server = servers.Server{
        .id = "itest-mon",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
    };
    try rig.store.upsert(io, server);
    _ = try rig.manager.connect(server, env.password, null);
    try waitForStatus(&rig.manager, "itest-mon", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-mon", true);
    try waitForStatus(&rig.manager, "itest-mon", .ready, 20 * std.time.ns_per_s);

    // Before any monitor activity the cache must be empty: no poll -> no
    // probe traffic (spec 03 acceptance).
    testSleep(500);
    const session = rig.manager.get("itest-mon").?;
    session.monitor_cache.lock();
    const idle_empty = session.monitor_cache.current() == null;
    session.monitor_cache.unlock();
    try std.testing.expect(idle_empty);

    // Polling enqueues probes; wait for the first real snapshot. The
    // dispatcher wraps handler output under "result".
    const PollResp = struct {
        result: struct {
            ok: bool,
            ts: i64 = 0,
            probe_error: ?[]const u8 = null,
            cpu: struct {
                utilization_pct: ?f32 = null,
                cpu_warming: bool = false,
                load_1: f32 = 0,
                uptime_sec: u64 = 0,
                cores: u32 = 0,
            } = .{},
            mem: struct {
                used_bytes: u64 = 0,
                total_bytes: u64 = 0,
                available_bytes: u64 = 0,
            } = .{},
            disk: struct {
                used_bytes: u64 = 0,
                total_bytes: u64 = 0,
                available_bytes: u64 = 0,
            } = .{},
            processes: []const struct { pid: u32 } = &.{},
        },
    };

    var first_ts: i64 = 0;
    var warming_seen = false;
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 15 * std.time.ns_per_s;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        const response = rig.dispatch(
            \\{"id":"1","command":"oars.monitor.poll","payload":{"server_id":"itest-mon"}}
        );
        const parsed = try std.json.parseFromSlice(PollResp, std.testing.allocator, response, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        });
        defer parsed.deinit();
        const snap = parsed.value.result;
        if (snap.ts > 0) {
            // The busybox ps fallback yields null cpu/mem per row, but the
            // probe itself must not have failed.
            try std.testing.expect(snap.probe_error == null);
            try std.testing.expect(snap.cpu.cores >= 1);
            try std.testing.expect(snap.cpu.uptime_sec > 0);
            try std.testing.expect(snap.mem.total_bytes > 0);
            try std.testing.expect(snap.mem.available_bytes > 0);
            try std.testing.expect(snap.disk.total_bytes > 0);
            try std.testing.expect(snap.processes.len >= 1);
            first_ts = snap.ts;
            warming_seen = snap.cpu.cpu_warming;
            break;
        }
        testSleep(100);
    }
    try std.testing.expect(first_ts > 0);

    // The first probe warms up (no previous sample): no invented percent.
    try std.testing.expect(warming_seen);
    try std.testing.expect(std.mem.indexOf(u8, rig.output[0..], "\"cpu_warming\":true") != null);

    // Keep polling past the interval: the second probe must produce a real
    // utilization delta.
    const util_deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 15 * std.time.ns_per_s;
    var util_seen = false;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < util_deadline) {
        const response = rig.dispatch(
            \\{"id":"2","command":"oars.monitor.poll","payload":{"server_id":"itest-mon"}}
        );
        const parsed = try std.json.parseFromSlice(PollResp, std.testing.allocator, response, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        });
        defer parsed.deinit();
        if (parsed.value.result.ts > first_ts and parsed.value.result.cpu.utilization_pct != null) {
            util_seen = true;
            break;
        }
        testSleep(100);
    }
    try std.testing.expect(util_seen);

    // Stop polling: once the liveness window elapses the worker must not
    // start new probes (spec 03 §6: a session with no monitor view
    // generates no probe traffic). The probe clock is the honest signal —
    // a stale-cache poll enqueues a probe itself, so snapshot-ts
    // comparisons would race the refresh the poll just triggered.
    testSleep(400); // outlive the 150 ms liveness window + one probe RTT
    const probe_clock = session.monitor_last_probe_ns.load(.acquire);
    testSleep(400);
    try std.testing.expectEqual(probe_clock, session.monitor_last_probe_ns.load(.acquire));

    // Manual refresh forces a probe even without a poll cadence.
    _ = rig.dispatch(
        \\{"id":"5","command":"oars.monitor.probe","payload":{"server_id":"itest-mon"}}
    );
    const force_deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 10 * std.time.ns_per_s;
    var forced = false;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < force_deadline) {
        if (session.monitor_last_probe_ns.load(.acquire) > probe_clock) {
            forced = true;
            break;
        }
        testSleep(100);
    }
    try std.testing.expect(forced);

    // Cleanup plans: the estimate streams on a channel; the apt plan runs
    // and is audited.
    const estimate = rig.dispatch(
        \\{"id":"7","command":"oars.monitor.cleanDiskEstimate","payload":{"server_id":"itest-mon","plan":"apt"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, estimate, "\"ok\":true") != null);
    const cleaned = rig.dispatch(
        \\{"id":"8","command":"oars.monitor.cleanDisk","payload":{"server_id":"itest-mon","plan":"apt"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, cleaned, "\"ok\":true") != null);
    const bad_plan = rig.dispatch(
        \\{"id":"9","command":"oars.monitor.cleanDisk","payload":{"server_id":"itest-mon","plan":"nope"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_plan, "unknown disk plan") != null);

    // Drop caches: exact level chosen, audited before; the forced probe
    // writes the after snapshot (the container's /proc may be read-only, so
    // the exec's own exit code is not asserted — the audit trail is).
    const dropped = rig.dispatch(
        \\{"id":"10","command":"oars.monitor.dropCaches","payload":{"server_id":"itest-mon","level":3}}
    );
    try std.testing.expect(std.mem.indexOf(u8, dropped, "\"ok\":true") != null);
    const bad_level = rig.dispatch(
        \\{"id":"11","command":"oars.monitor.dropCaches","payload":{"server_id":"itest-mon","level":9}}
    );
    try std.testing.expect(std.mem.indexOf(u8, bad_level, "must be 1, 2, or 3") != null);

    const audit_deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 10 * std.time.ns_per_s;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < audit_deadline) {
        const content = std.Io.Dir.cwd().readFileAlloc(io, rig.audit_store.path, std.testing.allocator, .limited(256 * 1024)) catch null;
        if (content) |c| {
            defer std.testing.allocator.free(c);
            if (std.mem.indexOf(u8, c, "monitor.clean_disk") != null and
                std.mem.indexOf(u8, c, "monitor.drop_caches") != null and
                std.mem.indexOf(u8, c, "monitor.drop_caches.after") != null)
            {
                break;
            }
        }
        testSleep(100);
    }
    const final_audit = try std.Io.Dir.cwd().readFileAlloc(io, rig.audit_store.path, std.testing.allocator, .limited(256 * 1024));
    defer std.testing.allocator.free(final_audit);
    try std.testing.expect(std.mem.indexOf(u8, final_audit, "monitor.clean_disk") != null);
    try std.testing.expect(std.mem.indexOf(u8, final_audit, "\"plan=apt\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, final_audit, "monitor.drop_caches") != null);
    try std.testing.expect(std.mem.indexOf(u8, final_audit, "level=3 before_mem_used_bytes=") != null);
    try std.testing.expect(std.mem.indexOf(u8, final_audit, "monitor.drop_caches.after") != null);

    rig.manager.disconnect("itest-mon");
}

test "integration: logs scan, read, follow, clear, and addSource" {
    const env = TestEnv.load();
    if (!env.active) return;

    ssh.initGlobal();

    var rig: TestRig = undefined;
    try rig.init("logs");
    defer rig.deinit();
    const io = std.testing.io;

    const server = servers.Server{
        .id = "itest-logs",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
    };
    try rig.store.upsert(io, server);
    _ = try rig.manager.connect(server, env.password, null);
    try waitForStatus(&rig.manager, "itest-logs", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-logs", true);
    try waitForStatus(&rig.manager, "itest-logs", .ready, 20 * std.time.ns_per_s);

    // A small log tree the scan picks up through a user-added root.
    try execWait(&rig.manager, "itest-logs", "mkdir -p /tmp/oars-logs/nginx /tmp/oars-logs/pm2; " ++
        "seq 1 5 > /tmp/oars-logs/nginx/access.log; " ++
        "printf 'api started\\n' > /tmp/oars-logs/pm2/api-out.log", 0, "");

    // addSource persists the path and feeds the scan roots.
    const added = rig.dispatch(
        \\{"id":"1","command":"oars.logs.addSource","payload":{"server_id":"itest-logs","path":"/tmp/oars-logs"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, added, "\"ok\":true") != null);

    // Scan: grouping, size/mtime/mode stamps, readability probe.
    const ScanSource = struct {
        path: []const u8,
        group: []const u8,
        name: []const u8,
        size: u64,
        mtime_epoch: u64,
        age_sec: u64,
        mode: u32,
        readable: bool,
    };
    // The dispatcher wraps handler output under "result".
    const ScanResp = struct {
        result: struct {
            ok: bool,
            sources: []const ScanSource = &.{},
            partial: bool = false,
            reason: []const u8 = "",
        },
    };
    const scan_response = rig.dispatch(
        \\{"id":"2","command":"oars.logs.scan","payload":{"server_id":"itest-logs"}}
    );
    const scan_parsed = try std.json.parseFromSlice(ScanResp, std.testing.allocator, scan_response, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer scan_parsed.deinit();
    try std.testing.expect(scan_parsed.value.result.ok);
    try std.testing.expect(!scan_parsed.value.result.partial);

    var nginx_index: ?usize = null;
    var pm2_index: ?usize = null;
    for (scan_parsed.value.result.sources, 0..) |s, i| {
        if (std.mem.eql(u8, s.path, "/tmp/oars-logs/nginx/access.log")) nginx_index = i;
        if (std.mem.eql(u8, s.path, "/tmp/oars-logs/pm2/api-out.log")) pm2_index = i;
    }
    try std.testing.expect(nginx_index != null);
    try std.testing.expect(pm2_index != null);
    const nginx = scan_parsed.value.result.sources[nginx_index.?];
    try std.testing.expectEqualStrings("web", nginx.group);
    try std.testing.expectEqualStrings("Nginx · access", nginx.name);
    try std.testing.expectEqual(@as(u64, 10), nginx.size);
    try std.testing.expectEqual(@as(u32, 0o644), nginx.mode);
    try std.testing.expect(nginx.readable);
    try std.testing.expect(nginx.mtime_epoch > 0);
    const pm2 = scan_parsed.value.result.sources[pm2_index.?];
    try std.testing.expectEqualStrings("runtime", pm2.group);
    try std.testing.expectEqual(@as(u64, 12), pm2.size);

    // Read: last lines with the exact contract.
    const ReadResp = struct {
        result: struct {
            ok: bool,
            path: []const u8,
            lines: []const []const u8 = &.{},
            limited: bool = false,
        },
    };
    const read_response = rig.dispatch(
        \\{"id":"3","command":"oars.logs.read","payload":{"server_id":"itest-logs","path":"/tmp/oars-logs/nginx/access.log","lines":200}}
    );
    const read_parsed = try std.json.parseFromSlice(ReadResp, std.testing.allocator, read_response, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer read_parsed.deinit();
    try std.testing.expect(read_parsed.value.result.ok);
    try std.testing.expectEqualStrings("/tmp/oars-logs/nginx/access.log", read_parsed.value.result.path);
    try std.testing.expectEqual(@as(usize, 5), read_parsed.value.result.lines.len);
    try std.testing.expectEqualStrings("1", read_parsed.value.result.lines[0]);
    try std.testing.expectEqualStrings("5", read_parsed.value.result.lines[4]);
    try std.testing.expect(!read_parsed.value.result.limited);

    // Missing file: explicit failure surface, never a hang or fake success.
    const missing = rig.dispatch(
        \\{"id":"4","command":"oars.logs.read","payload":{"server_id":"itest-logs","path":"/tmp/oars-logs/nope.log","lines":200}}
    );
    try std.testing.expect(std.mem.indexOf(u8, missing, "file is missing or unreadable") != null);

    // Follow: a long-lived log channel; appended lines stream through it.
    const follow_response = rig.dispatch(
        \\{"id":"5","command":"oars.logs.follow","payload":{"server_id":"itest-logs","path":"/tmp/oars-logs/nginx/access.log"}}
    );
    const FollowResp = struct { result: struct { ok: bool, channel: u32 } };
    const follow_parsed = try std.json.parseFromSlice(FollowResp, std.testing.allocator, follow_response, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer follow_parsed.deinit();
    try std.testing.expect(follow_parsed.value.result.ok);
    const follow_channel = follow_parsed.value.result.channel;

    try execWait(&rig.manager, "itest-logs", "echo 6 >> /tmp/oars-logs/nginx/access.log", 0, "");

    const PollResp = struct {
        result: struct {
            ok: bool,
            channels: []const struct {
                id: u32,
                kind: []const u8,
                data: []const u8 = "",
            } = &.{},
        },
    };
    const poll_deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 15 * std.time.ns_per_s;
    var follow_seen = false;
    var kind_is_log = false;
    while (std.Io.Timestamp.now(io, .real).nanoseconds < poll_deadline) {
        var poll_buf: [512]u8 = undefined;
        var poll_writer = std.Io.Writer.fixed(&poll_buf);
        std.json.Stringify.value(.{
            .id = "6",
            .command = "oars.ssh.poll",
            .payload = .{
                .server_id = "itest-logs",
                .cursors = .{.{ .channel = follow_channel, .cursor = 0 }},
            },
        }, .{}, &poll_writer) catch unreachable;
        const poll_response = rig.dispatch(poll_writer.buffered());
        const poll_parsed = try std.json.parseFromSlice(PollResp, std.testing.allocator, poll_response, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        });
        defer poll_parsed.deinit();
        for (poll_parsed.value.result.channels) |ch| {
            if (ch.id == follow_channel) {
                kind_is_log = std.mem.eql(u8, ch.kind, "log");
                if (std.mem.indexOf(u8, ch.data, "6\n") != null) follow_seen = true;
            }
        }
        if (follow_seen and kind_is_log) break;
        testSleep(200);
    }
    try std.testing.expect(follow_seen);
    try std.testing.expect(kind_is_log);

    // Clear with the STALE preview: the file changed since the scan (the
    // follow appended a line), so the identity check must refuse.
    var clear_buf: [1024]u8 = undefined;
    var clear_writer = std.Io.Writer.fixed(&clear_buf);
    std.json.Stringify.value(.{
        .id = "7",
        .command = "oars.logs.clear",
        .payload = .{
            .server_id = "itest-logs",
            .path = "/tmp/oars-logs/nginx/access.log",
            .expected = .{ .size = @as(u64, 10), .mtime = nginx.mtime_epoch, .mode = nginx.mode },
        },
    }, .{}, &clear_writer) catch unreachable;
    const conflict = rig.dispatch(clear_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, conflict, "file changed since preview") != null);

    // Re-scan after the change: addSource (even a duplicate) invalidates
    // the 60 s cache so the fresh preview carries the new size.
    _ = rig.dispatch(
        \\{"id":"8","command":"oars.logs.addSource","payload":{"server_id":"itest-logs","path":"/tmp/oars-logs"}}
    );
    const rescan_response = rig.dispatch(
        \\{"id":"9","command":"oars.logs.scan","payload":{"server_id":"itest-logs"}}
    );
    const rescan_parsed = try std.json.parseFromSlice(ScanResp, std.testing.allocator, rescan_response, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer rescan_parsed.deinit();
    var fresh: ?ScanSource = null;
    for (rescan_parsed.value.result.sources) |s| {
        if (std.mem.eql(u8, s.path, "/tmp/oars-logs/nginx/access.log")) fresh = s;
    }
    try std.testing.expect(fresh != null);
    try std.testing.expectEqual(@as(u64, 12), fresh.?.size);

    // Clear with the fresh preview: identity matches, the file is truncated
    // to zero and the before/after sizes are audited.
    var clear2_buf: [1024]u8 = undefined;
    var clear2_writer = std.Io.Writer.fixed(&clear2_buf);
    std.json.Stringify.value(.{
        .id = "10",
        .command = "oars.logs.clear",
        .payload = .{
            .server_id = "itest-logs",
            .path = "/tmp/oars-logs/nginx/access.log",
            .expected = .{ .size = fresh.?.size, .mtime = fresh.?.mtime_epoch, .mode = fresh.?.mode },
        },
    }, .{}, &clear2_writer) catch unreachable;
    const cleared = rig.dispatch(clear2_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, cleared, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, cleared, "\"before_size\":12") != null);
    try std.testing.expect(std.mem.indexOf(u8, cleared, "\"after_size\":0") != null);

    // The file is now empty: a read returns zero lines, not an error.
    const empty_response = rig.dispatch(
        \\{"id":"11","command":"oars.logs.read","payload":{"server_id":"itest-logs","path":"/tmp/oars-logs/nginx/access.log","lines":200}}
    );
    const empty_parsed = try std.json.parseFromSlice(ReadResp, std.testing.allocator, empty_response, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer empty_parsed.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty_parsed.value.result.lines.len);

    // The clear was audited with the exact before/after sizes.
    const audit_content = try std.Io.Dir.cwd().readFileAlloc(io, rig.audit_store.path, std.testing.allocator, .limited(256 * 1024));
    defer std.testing.allocator.free(audit_content);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "logs.clear") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "before_size=12 after_size=0") != null);

    // closeChannel ends the follow stream and removes the channel.
    var close_buf: [512]u8 = undefined;
    var close_writer = std.Io.Writer.fixed(&close_buf);
    std.json.Stringify.value(.{
        .id = "12",
        .command = "oars.ssh.closeChannel",
        .payload = .{ .server_id = "itest-logs", .channel = follow_channel },
    }, .{}, &close_writer) catch unreachable;
    const closed = rig.dispatch(close_writer.buffered());
    try std.testing.expect(std.mem.indexOf(u8, closed, "\"ok\":true") != null);

    // The close is queued for the worker (10 ms loop): the channel must
    // disappear from polls shortly after.
    const gone_deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 5 * std.time.ns_per_s;
    var channel_gone = false;
    while (std.Io.Timestamp.now(io, .real).nanoseconds < gone_deadline) {
        const after_close = rig.dispatch(
            \\{"id":"13","command":"oars.ssh.poll","payload":{"server_id":"itest-logs"}}
        );
        const close_parsed = try std.json.parseFromSlice(PollResp, std.testing.allocator, after_close, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        });
        defer close_parsed.deinit();
        channel_gone = true;
        for (close_parsed.value.result.channels) |ch| {
            if (ch.id == follow_channel) channel_gone = false;
        }
        if (channel_gone) break;
        testSleep(50);
    }
    try std.testing.expect(channel_gone);

    rig.manager.disconnect("itest-logs");
}

// --- SFTP helpers (spec 05) ---------------------------------------------------

/// Parses `"op_id":N` out of an async-op response.
fn sftpOpId(resp: []const u8) ?u32 {
    const pos = std.mem.indexOf(u8, resp, "\"op_id\":") orelse return null;
    const rest = resp[pos + 8 ..];
    var end: usize = 0;
    while (end < rest.len and rest[end] >= '0' and rest[end] <= '9') end += 1;
    if (end == 0) return null;
    return std.fmt.parseInt(u32, rest[0..end], 10) catch null;
}

/// The status string of transfer `op_id` in a poll response (null when the
/// transfer is not present). The needle includes the kind delimiter so
/// `"id":1` never matches `"id":1001`.
fn sftpTransferStatus(resp: []const u8, op_id: u32) ?[]const u8 {
    var needle_buf: [48]u8 = undefined;
    const needle = std.fmt.bufPrint(&needle_buf, "\"id\":{d},\"kind\":\"", .{op_id}) catch return null;
    const start = std.mem.indexOf(u8, resp, needle) orelse return null;
    const tail = resp[start..];
    const marker = "\"status\":\"";
    const status_pos = std.mem.indexOf(u8, tail, marker) orelse return null;
    const value = tail[status_pos + marker.len ..];
    const end = std.mem.indexOfScalar(u8, value, '"') orelse return null;
    return value[0..end];
}

/// Polls `oars.sftp.poll` until transfer `op_id` reaches `want`.
fn sftpWaitTransfer(rig: *TestRig, op_id: u32, want: []const u8) !void {
    var req_buf: [256]u8 = undefined;
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 20 * std.time.ns_per_s;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        const req = std.fmt.bufPrint(&req_buf, "{{\"id\":\"p\",\"command\":\"oars.sftp.poll\",\"payload\":{{\"server_id\":\"itest-sftp\"}}}}", .{}) catch unreachable;
        const resp = rig.dispatch(req);
        if (sftpTransferStatus(resp, op_id)) |status| {
            if (std.mem.eql(u8, status, want)) return;
        }
        testSleep(50);
    }
    const dbg_req = std.fmt.bufPrint(&req_buf, "{{\"id\":\"p\",\"command\":\"oars.sftp.poll\",\"payload\":{{\"server_id\":\"itest-sftp\"}}}}", .{}) catch unreachable;
    std.debug.print("sftpWaitTransfer timeout: op_id={d} want={s} last_poll={s}\n", .{ op_id, want, rig.dispatch(dbg_req) });
    return error.TestUnexpectedResult;
}

/// Parses `"size":N` out of a folderSize response.
fn sftpSize(resp: []const u8) ?u64 {
    const pos = std.mem.indexOf(u8, resp, "\"size\":") orelse return null;
    const rest = resp[pos + 7 ..];
    var end: usize = 0;
    while (end < rest.len and rest[end] >= '0' and rest[end] <= '9') end += 1;
    if (end == 0) return null;
    return std.fmt.parseInt(u64, rest[0..end], 10) catch null;
}

test "integration: sftp crud, editor save, transfers, cancel, and zip paths" {
    const env = TestEnv.load();
    if (!env.active) return; // skipped: run scripts/integration-test.sh

    ssh.initGlobal();

    var rig: TestRig = undefined;
    try rig.init("sftp");
    defer rig.deinit();
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    const server = servers.Server{
        .id = "itest-sftp",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
    };
    try rig.store.upsert(io, server);
    _ = try rig.manager.connect(server, env.password, null);
    try waitForStatus(&rig.manager, "itest-sftp", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-sftp", true);
    try waitForStatus(&rig.manager, "itest-sftp", .ready, 20 * std.time.ns_per_s);

    // Fresh scratch space on the server.
    try execWait(&rig.manager, "itest-sftp", "rm -rf /tmp/oars-sftp-itest && mkdir -p /tmp/oars-sftp-itest/dir", 0, "");

    // --- mkdir ---
    const mkdir = rig.dispatch(
        \\{"id":"1","command":"oars.sftp.mkdir","payload":{"server_id":"itest-sftp","path":{"utf8":"/tmp/oars-sftp-itest/dir/sub"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, mkdir, "\"ok\":true") != null);

    // --- write two chunks under a frontend-chosen transfer id ---
    var b64_1_buf: [64]u8 = undefined;
    const b64_1 = std.base64.standard.Encoder.encode(&b64_1_buf, "hello ");
    var b64_2_buf: [64]u8 = undefined;
    const b64_2 = std.base64.standard.Encoder.encode(&b64_2_buf, "world");
    var write1_buf: [768]u8 = undefined;
    const write1 = std.fmt.bufPrint(&write1_buf, "{{\"id\":\"2\",\"command\":\"oars.sftp.write\",\"payload\":{{\"server_id\":\"itest-sftp\",\"path\":{{\"utf8\":\"/tmp/oars-sftp-itest/dir/file.txt\"}},\"offset\":0,\"base64\":\"{s}\",\"transfer_id\":1001,\"total\":11}}}}", .{b64_1}) catch unreachable;
    const w1 = rig.dispatch(write1);
    try std.testing.expect(std.mem.indexOf(u8, w1, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, w1, "\"written\":6") != null);
    var write2_buf: [768]u8 = undefined;
    const write2 = std.fmt.bufPrint(&write2_buf, "{{\"id\":\"3\",\"command\":\"oars.sftp.write\",\"payload\":{{\"server_id\":\"itest-sftp\",\"path\":{{\"utf8\":\"/tmp/oars-sftp-itest/dir/file.txt\"}},\"offset\":6,\"base64\":\"{s}\",\"transfer_id\":1001,\"total\":11}}}}", .{b64_2}) catch unreachable;
    const w2 = rig.dispatch(write2);
    try std.testing.expect(std.mem.indexOf(u8, w2, "\"done\":true") != null);

    // --- read back ---
    const read = rig.dispatch(
        \\{"id":"4","command":"oars.sftp.read","payload":{"server_id":"itest-sftp","path":{"utf8":"/tmp/oars-sftp-itest/dir/file.txt"},"offset":0,"max":65536}}
    );
    try std.testing.expect(std.mem.indexOf(u8, read, "aGVsbG8gd29ybGQ=") != null); // "hello world"
    try std.testing.expect(std.mem.indexOf(u8, read, "\"eof\":true") != null);

    // --- ls and stat ---
    const ls = rig.dispatch(
        \\{"id":"5","command":"oars.sftp.ls","payload":{"server_id":"itest-sftp","path":{"utf8":"/tmp/oars-sftp-itest/dir"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, ls, "\"utf8\":\"file.txt\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, ls, "\"kind\":\"file\"") != null);

    const stat = rig.dispatch(
        \\{"id":"6","command":"oars.sftp.stat","payload":{"server_id":"itest-sftp","path":{"utf8":"/tmp/oars-sftp-itest/dir/file.txt"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, stat, "\"size\":11") != null);

    // --- rename + chmod (verified through the shell) ---
    const rename = rig.dispatch(
        \\{"id":"7","command":"oars.sftp.rename","payload":{"server_id":"itest-sftp","from":{"utf8":"/tmp/oars-sftp-itest/dir/file.txt"},"to":{"utf8":"/tmp/oars-sftp-itest/dir/renamed.txt"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, rename, "\"ok\":true") != null);

    const chmod = rig.dispatch(
        \\{"id":"8","command":"oars.sftp.chmod","payload":{"server_id":"itest-sftp","path":{"utf8":"/tmp/oars-sftp-itest/dir/renamed.txt"},"mode":384}}
    );
    try std.testing.expect(std.mem.indexOf(u8, chmod, "\"ok\":true") != null);
    try execWait(&rig.manager, "itest-sftp", "stat -c %a /tmp/oars-sftp-itest/dir/renamed.txt", 0, "600");

    // --- editor save (atomic posix-rename path) ---
    var b64_save_buf: [128]u8 = undefined;
    const save_content = "edited content\n";
    const b64_save = std.base64.standard.Encoder.encode(&b64_save_buf, save_content);
    var save_buf: [1024]u8 = undefined;
    const save_req = std.fmt.bufPrint(&save_buf, "{{\"id\":\"9\",\"command\":\"oars.sftp.save\",\"payload\":{{\"server_id\":\"itest-sftp\",\"path\":{{\"utf8\":\"/tmp/oars-sftp-itest/dir/renamed.txt\"}},\"base64\":\"{s}\"}}}}", .{b64_save}) catch unreachable;
    const saved = rig.dispatch(save_req);
    try std.testing.expect(std.mem.indexOf(u8, saved, "\"ok\":true") != null);
    const read_back = rig.dispatch(
        \\{"id":"10","command":"oars.sftp.read","payload":{"server_id":"itest-sftp","path":{"utf8":"/tmp/oars-sftp-itest/dir/renamed.txt"},"offset":0,"max":65536}}
    );
    try std.testing.expect(std.mem.indexOf(u8, read_back, "ZWRpdGVkIGNvbnRlbnQK") != null);

    // --- folderSize (du -sb, cached) ---
    const folder_size = rig.dispatch(
        \\{"id":"11","command":"oars.sftp.folderSize","payload":{"server_id":"itest-sftp","path":{"utf8":"/tmp/oars-sftp-itest/dir"}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, folder_size, "\"ok\":true") != null);
    const size = sftpSize(folder_size) orelse return error.TestUnexpectedResult;
    try std.testing.expect(size > 0);

    // --- download through the native writer, poll to done, verify bytes ---
    const local_dir = try std.fmt.allocPrint(allocator, "/tmp/{s}", .{rig.dir_name});
    defer allocator.free(local_dir);
    const down_path = try std.fmt.allocPrint(allocator, "{s}/down.txt", .{local_dir});
    defer allocator.free(down_path);
    var download_buf: [1024]u8 = undefined;
    const download_req = std.fmt.bufPrint(&download_buf, "{{\"id\":\"12\",\"command\":\"oars.sftp.download\",\"payload\":{{\"server_id\":\"itest-sftp\",\"remote_path\":{{\"utf8\":\"/tmp/oars-sftp-itest/dir/renamed.txt\"}},\"local_path\":\"{s}\"}}}}", .{down_path}) catch unreachable;
    const download = rig.dispatch(download_req);
    const dl_op_id = sftpOpId(download) orelse return error.TestUnexpectedResult;
    try sftpWaitTransfer(&rig, dl_op_id, "done");
    const downloaded = std.Io.Dir.cwd().readFileAlloc(io, down_path, allocator, .limited(1024 * 1024)) catch return error.TestUnexpectedResult;
    defer allocator.free(downloaded);
    try std.testing.expect(std.mem.eql(u8, downloaded, save_content));

    // --- cancel: chunk 1 ok, cancel, chunk 2 refuses ---
    var b64_c1_buf: [64]u8 = undefined;
    const b64_c1 = std.base64.standard.Encoder.encode(&b64_c1_buf, "abc");
    var cancel1_buf: [768]u8 = undefined;
    const cancel1_req = std.fmt.bufPrint(&cancel1_buf, "{{\"id\":\"13\",\"command\":\"oars.sftp.write\",\"payload\":{{\"server_id\":\"itest-sftp\",\"path\":{{\"utf8\":\"/tmp/oars-sftp-itest/dir/cancel.txt\"}},\"offset\":0,\"base64\":\"{s}\",\"transfer_id\":2002,\"total\":9}}}}", .{b64_c1}) catch unreachable;
    const c1 = rig.dispatch(cancel1_req);
    try std.testing.expect(std.mem.indexOf(u8, c1, "\"ok\":true") != null);
    const cancel = rig.dispatch(
        \\{"id":"14","command":"oars.sftp.cancel","payload":{"server_id":"itest-sftp","transfer_id":2002}}
    );
    try std.testing.expect(std.mem.indexOf(u8, cancel, "\"ok\":true") != null);
    var b64_c2_buf: [64]u8 = undefined;
    const b64_c2 = std.base64.standard.Encoder.encode(&b64_c2_buf, "defghij");
    var cancel2_buf: [768]u8 = undefined;
    const cancel2_req = std.fmt.bufPrint(&cancel2_buf, "{{\"id\":\"15\",\"command\":\"oars.sftp.write\",\"payload\":{{\"server_id\":\"itest-sftp\",\"path\":{{\"utf8\":\"/tmp/oars-sftp-itest/dir/cancel.txt\"}},\"offset\":3,\"base64\":\"{s}\",\"transfer_id\":2002,\"total\":9}}}}", .{b64_c2}) catch unreachable;
    const c2 = rig.dispatch(cancel2_req);
    try std.testing.expect(std.mem.indexOf(u8, c2, "canceled") != null);
    // The partial file must be gone.
    try execWait(&rig.manager, "itest-sftp", "test ! -e /tmp/oars-sftp-itest/dir/cancel.txt.partial", 0, "");

    // --- unzip: host-built stored fixture, default dest, conflict refusal ---
    const archive = try sftpmod.buildStoredZip(allocator, &.{"sub/inner.txt"}, &.{"zipped content\n"});
    defer allocator.free(archive);
    var b64_zip_buf: [1024]u8 = undefined;
    const b64_zip = std.base64.standard.Encoder.encode(&b64_zip_buf, archive);
    var zip_upload_buf: [2048]u8 = undefined;
    const zip_upload_req = std.fmt.bufPrint(&zip_upload_buf, "{{\"id\":\"16\",\"command\":\"oars.sftp.write\",\"payload\":{{\"server_id\":\"itest-sftp\",\"path\":{{\"utf8\":\"/tmp/oars-sftp-itest/archive.zip\"}},\"offset\":0,\"base64\":\"{s}\",\"transfer_id\":3003,\"total\":{d}}}}}", .{ b64_zip, archive.len }) catch unreachable;
    const zip_uploaded = rig.dispatch(zip_upload_req);
    try std.testing.expect(std.mem.indexOf(u8, zip_uploaded, "\"done\":true") != null);

    const unzip = rig.dispatch(
        \\{"id":"17","command":"oars.sftp.unzip","payload":{"server_id":"itest-sftp","zip_path":{"utf8":"/tmp/oars-sftp-itest/archive.zip"}}}
    );
    const unzip_op_id = sftpOpId(unzip) orelse return error.TestUnexpectedResult;
    try sftpWaitTransfer(&rig, unzip_op_id, "done");
    const unzipped = rig.dispatch(
        \\{"id":"18","command":"oars.sftp.read","payload":{"server_id":"itest-sftp","path":{"utf8":"/tmp/oars-sftp-itest/archive/sub/inner.txt"},"offset":0,"max":65536}}
    );
    try std.testing.expect(std.mem.indexOf(u8, unzipped, "emlwcGVkIGNvbnRlbnQK") != null);

    // Overwrite is disabled: extracting again must fail on the conflict.
    const unzip_again = rig.dispatch(
        \\{"id":"19","command":"oars.sftp.unzip","payload":{"server_id":"itest-sftp","zip_path":{"utf8":"/tmp/oars-sftp-itest/archive.zip"}}}
    );
    const again_op_id = sftpOpId(unzip_again) orelse return error.TestUnexpectedResult;
    try sftpWaitTransfer(&rig, again_op_id, "failed");

    // --- zipDownload: remote zip -r, staged, downloaded, staging removed ---
    const bundle_path = try std.fmt.allocPrint(allocator, "{s}/bundle.zip", .{local_dir});
    defer allocator.free(bundle_path);
    var zip_dl_buf: [2048]u8 = undefined;
    const zip_dl_req = std.fmt.bufPrint(&zip_dl_buf, "{{\"id\":\"20\",\"command\":\"oars.sftp.zipDownload\",\"payload\":{{\"server_id\":\"itest-sftp\",\"paths\":[{{\"utf8\":\"/tmp/oars-sftp-itest/dir/renamed.txt\"}}],\"local_path\":\"{s}\"}}}}", .{bundle_path}) catch unreachable;
    const zip_dl = rig.dispatch(zip_dl_req);
    const zip_dl_op_id = sftpOpId(zip_dl) orelse return error.TestUnexpectedResult;
    try sftpWaitTransfer(&rig, zip_dl_op_id, "done");
    const bundle = std.Io.Dir.cwd().readFileAlloc(io, bundle_path, allocator, .limited(1024 * 1024)) catch return error.TestUnexpectedResult;
    defer allocator.free(bundle);
    try std.testing.expect(bundle.len >= 4 and bundle[0] == 'P' and bundle[1] == 'K');
    // The staging archive on the server must be cleaned up.
    try execWait(&rig.manager, "itest-sftp", "ls /tmp/oars-sftp-itest/.oars-zip-*.zip", 1, "");

    // --- recursive rm with per-entry progress ---
    const rm = rig.dispatch(
        \\{"id":"21","command":"oars.sftp.rm","payload":{"server_id":"itest-sftp","path":{"utf8":"/tmp/oars-sftp-itest"},"recursive":true}}
    );
    const rm_op_id = sftpOpId(rm) orelse return error.TestUnexpectedResult;
    try sftpWaitTransfer(&rig, rm_op_id, "done");
    // busybox ls exits 1 (not GNU's 2) on a missing path.
    try execWait(&rig.manager, "itest-sftp", "ls /tmp/oars-sftp-itest", 1, "");

    rig.manager.disconnect("itest-sftp");
}

// --- scripts helpers (spec 06) --------------------------------------------------

/// Polls an existing exec channel by id until EOF; asserts the exit code
/// and an output marker.
fn execChannelWait(manager: *sessions.Manager, server_id: []const u8, channel: u32, want_exit: i32, want_out: []const u8) !void {
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 15 * std.time.ns_per_s;
    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(std.testing.allocator);
    var cursor: u64 = 0;
    var saw_eof = false;
    var exit: ?i32 = null;
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
        testSleep(50);
    }
    return error.TestUnexpectedResult;
}

/// Parses `"channel":N` out of a run response.
fn scriptsChannel(resp: []const u8) ?u32 {
    const pos = std.mem.indexOf(u8, resp, "\"channel\":") orelse return null;
    const rest = resp[pos + 10 ..];
    var end: usize = 0;
    while (end < rest.len and rest[end] >= '0' and rest[end] <= '9') end += 1;
    if (end == 0) return null;
    return std.fmt.parseInt(u32, rest[0..end], 10) catch null;
}

/// Parses `"run_id":N` out of a broadcast response.
fn scriptsRunId(resp: []const u8) ?u32 {
    const pos = std.mem.indexOf(u8, resp, "\"run_id\":") orelse return null;
    const rest = resp[pos + 9 ..];
    var end: usize = 0;
    while (end < rest.len and rest[end] >= '0' and rest[end] <= '9') end += 1;
    if (end == 0) return null;
    return std.fmt.parseInt(u32, rest[0..end], 10) catch null;
}

const BroadcastServer = struct {
    server_id: []const u8,
    status: []const u8,
    exit: ?i32 = null,
    cursor: u64 = 0,
    eof: bool = false,
    data: []const u8 = "",
    @"error": []const u8 = "",
    gap: u64 = 0,
};

const BroadcastResp = struct {
    result: struct {
        ok: bool,
        run_id: u32,
        servers: []BroadcastServer = &.{},
        done: bool = false,
        canceled: bool = false,
    },
};

/// Polls a broadcast until every server is terminal; returns the last
/// response (alloc_always — the caller must deinit). Cursors stay empty,
/// so the final response carries each server's full retained output.
fn broadcastWaitFor(rig: *TestRig, run_id: u32) !std.json.Parsed(BroadcastResp) {
    var req_buf: [256]u8 = undefined;
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 25 * std.time.ns_per_s;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        const req = std.fmt.bufPrint(&req_buf, "{{\"id\":\"p\",\"command\":\"oars.scripts.broadcastPoll\",\"payload\":{{\"run_id\":{d},\"cursors\":{{}}}}}}", .{run_id}) catch unreachable;
        const resp = rig.dispatch(req);
        var parsed = std.json.parseFromSlice(BroadcastResp, std.testing.allocator, resp, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch return error.TestUnexpectedResult;
        var all_terminal = true;
        for (parsed.value.result.servers) |s| {
            if (std.mem.eql(u8, s.status, "queued") or std.mem.eql(u8, s.status, "running")) all_terminal = false;
        }
        if (all_terminal) return parsed;
        parsed.deinit();
        testSleep(100);
    }
    return error.TestUnexpectedResult;
}

test "integration: scripts run with variables, injection neutralization, broadcast, and cancel" {
    const env = TestEnv.load();
    if (!env.active) return; // skipped: run scripts/integration-test.sh

    ssh.initGlobal();

    var rig: TestRig = undefined;
    try rig.init("scripts");
    defer rig.deinit();
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    // Two sessions to the same container: the broadcast fan-out needs two
    // servers (spec 06 §11).
    const s1 = servers.Server{
        .id = "itest-scr-a",
        .name = "dev-sshd-a",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
    };
    const s2 = servers.Server{
        .id = "itest-scr-b",
        .name = "dev-sshd-b",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
    };
    try rig.store.upsert(io, s1);
    try rig.store.upsert(io, s2);
    _ = try rig.manager.connect(s1, env.password, null);
    try waitForStatus(&rig.manager, "itest-scr-a", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-scr-a", true);
    try waitForStatus(&rig.manager, "itest-scr-a", .ready, 20 * std.time.ns_per_s);
    _ = try rig.manager.connect(s2, env.password, null);
    try waitForStatus(&rig.manager, "itest-scr-b", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-scr-b", true);
    try waitForStatus(&rig.manager, "itest-scr-b", .ready, 20 * std.time.ns_per_s);

    // Save the scripts.
    const saved = rig.dispatch(
        \\{"id":"1","command":"oars.scripts.save","payload":{"script":{"id":"sc-hello","name":"hello","body":"echo hello {{who}}","variables":[{"name":"who","label":"Who"}]}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, saved, "\"ok\":true") != null);
    _ = rig.dispatch(
        \\{"id":"2","command":"oars.scripts.save","payload":{"script":{"id":"sc-echo","name":"echo","body":"echo {{x}}"}}}
    );
    _ = rig.dispatch(
        \\{"id":"3","command":"oars.scripts.save","payload":{"script":{"id":"sc-secret","name":"secret","body":"echo {{pw}}"}}}
    );
    _ = rig.dispatch(
        \\{"id":"4","command":"oars.scripts.save","payload":{"script":{"id":"sc-sleep","name":"sleep","body":"sleep 30"}}}
    );

    // --- run with a variable ---
    const run = rig.dispatch(
        \\{"id":"5","command":"oars.scripts.run","payload":{"server_id":"itest-scr-a","script_id":"sc-hello","vars":{"who":{"value":"world"}}}}
    );
    const channel = scriptsChannel(run) orelse return error.TestUnexpectedResult;
    try execChannelWait(&rig.manager, "itest-scr-a", channel, 0, "hello world");

    // --- injection value stays a literal argument ---
    const inj = rig.dispatch(
        \\{"id":"6","command":"oars.scripts.run","payload":{"server_id":"itest-scr-a","script_id":"sc-echo","vars":{"x":{"value":"'; touch /tmp/oars-pwned"}}}}
    );
    const inj_channel = scriptsChannel(inj) orelse return error.TestUnexpectedResult;
    try execChannelWait(&rig.manager, "itest-scr-a", inj_channel, 0, "'; touch /tmp/oars-pwned");
    // The injected command never ran.
    try execWait(&rig.manager, "itest-scr-a", "ls /tmp/oars-pwned", 1, "");

    // --- missing variable blocks the run ---
    const missing = rig.dispatch(
        \\{"id":"7","command":"oars.scripts.run","payload":{"server_id":"itest-scr-a","script_id":"sc-hello","vars":{}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, missing, "missing variable: who") != null);

    // --- a bad-syntax body is refused by the bash -n check ---
    _ = rig.dispatch(
        \\{"id":"8","command":"oars.scripts.save","payload":{"script":{"id":"sc-broken","name":"broken","body":"if then fi"}}}
    );
    const broken = rig.dispatch(
        \\{"id":"9","command":"oars.scripts.run","payload":{"server_id":"itest-scr-a","script_id":"sc-broken","vars":{}}}
    );
    try std.testing.expect(std.mem.indexOf(u8, broken, "syntax check failed") != null);

    // --- broadcast to both servers ---
    const broadcast = rig.dispatch(
        \\{"id":"10","command":"oars.scripts.broadcast","payload":{"script_id":"sc-hello","server_ids":["itest-scr-a","itest-scr-b"],"vars":{"who":{"value":"alice"}}}}
    );
    const run_id = scriptsRunId(broadcast) orelse return error.TestUnexpectedResult;
    var final_poll = try broadcastWaitFor(&rig, run_id);
    defer final_poll.deinit();
    try std.testing.expect(final_poll.value.result.done);
    var saw_a = false;
    var saw_b = false;
    for (final_poll.value.result.servers) |s| {
        try std.testing.expectEqualStrings("done", s.status);
        try std.testing.expectEqual(@as(i32, 0), s.exit orelse -1);
        try std.testing.expect(std.mem.indexOf(u8, s.data, "hello alice") != null);
        if (std.mem.eql(u8, s.server_id, "itest-scr-a")) saw_a = true;
        if (std.mem.eql(u8, s.server_id, "itest-scr-b")) saw_b = true;
    }
    try std.testing.expect(saw_a and saw_b);

    // --- secret values never reach the audit file ---
    const secret_run = rig.dispatch(
        \\{"id":"11","command":"oars.scripts.run","payload":{"server_id":"itest-scr-b","script_id":"sc-secret","vars":{"pw":{"value":"s3cret-value","secret":true}}}}
    );
    const secret_channel = scriptsChannel(secret_run) orelse return error.TestUnexpectedResult;
    try execChannelWait(&rig.manager, "itest-scr-b", secret_channel, 0, "s3cret-value");
    const audit_content = std.Io.Dir.cwd().readFileAlloc(io, rig.audit_store.path, allocator, .limited(256 * 1024)) catch return error.TestUnexpectedResult;
    defer allocator.free(audit_content);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "scripts.run") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "scripts.broadcast") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "s3cret-value") == null);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "***") != null);

    // --- run counts and last-run stamps persist ---
    const list = rig.dispatch(
        \\{"id":"12","command":"oars.scripts.list","payload":{}}
    );
    try std.testing.expect(std.mem.indexOf(u8, list, "\"run_count\":2") != null); // sc-hello: run + broadcast
    try std.testing.expect(std.mem.indexOf(u8, list, "\"run_count\":1") != null); // sc-echo / sc-secret
    try std.testing.expect(std.mem.indexOf(u8, list, "\"last_run_at\":") != null);

    // --- cancel a running broadcast ---
    const cancel_broadcast = rig.dispatch(
        \\{"id":"13","command":"oars.scripts.broadcast","payload":{"script_id":"sc-sleep","server_ids":["itest-scr-a","itest-scr-b"],"vars":{}}}
    );
    const cancel_run = scriptsRunId(cancel_broadcast) orelse return error.TestUnexpectedResult;
    // Give the runner a moment to start both, then cancel.
    var saw_running = false;
    var req_buf: [256]u8 = undefined;
    const start_deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 10 * std.time.ns_per_s;
    while (std.Io.Timestamp.now(io, .real).nanoseconds < start_deadline) {
        const req = std.fmt.bufPrint(&req_buf, "{{\"id\":\"14\",\"command\":\"oars.scripts.broadcastPoll\",\"payload\":{{\"run_id\":{d},\"cursors\":{{}}}}}}", .{cancel_run}) catch unreachable;
        const resp = rig.dispatch(req);
        var parsed = std.json.parseFromSlice(BroadcastResp, allocator, resp, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch return error.TestUnexpectedResult;
        defer parsed.deinit();
        for (parsed.value.result.servers) |s| {
            if (std.mem.eql(u8, s.status, "running")) saw_running = true;
        }
        if (saw_running) break;
        testSleep(100);
    }
    try std.testing.expect(saw_running);
    var cancel_buf: [128]u8 = undefined;
    const cancel_req = std.fmt.bufPrint(&cancel_buf, "{{\"id\":\"15\",\"command\":\"oars.scripts.broadcastCancel\",\"payload\":{{\"run_id\":{d}}}}}", .{cancel_run}) catch unreachable;
    const canceled_resp = rig.dispatch(cancel_req);
    try std.testing.expect(std.mem.indexOf(u8, canceled_resp, "\"ok\":true") != null);

    var canceled_poll = try broadcastWaitFor(&rig, cancel_run);
    defer canceled_poll.deinit();
    try std.testing.expect(canceled_poll.value.result.canceled);
    for (canceled_poll.value.result.servers) |s| {
        try std.testing.expectEqualStrings("canceled", s.status);
        try std.testing.expect(std.mem.indexOf(u8, s.@"error", "cancel requested") != null);
    }

    rig.manager.disconnect("itest-scr-a");
    rig.manager.disconnect("itest-scr-b");
}
