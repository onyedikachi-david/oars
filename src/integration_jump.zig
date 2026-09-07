//! Env-gated integration tests for spec 18 jump hosts against a live
//! sshd. The target session tunnels through the via session's
//! direct-tcpip channel to the container's own loopback sshd
//! (127.0.0.1:22 as the server sees it; the host maps 2222:22).

const std = @import("std");
const servers = @import("servers.zig");
const sessions = @import("sessions.zig");
const integration = @import("integration.zig");

const TestEnv = integration.TestEnv;
const TestRig = integration.TestRig;
const waitForStatus = integration.waitForStatus;

test "disconnecting a jump host cascade-closes the target without deadlock" {
    const env = TestEnv.load();
    if (!env.active) return;
    const io = std.testing.io;
    var rig: TestRig = undefined;
    try rig.init("jump");
    defer rig.deinit();

    // The via hop: password auth straight at the container.
    const via_server = servers.Server{
        .id = "itest-jump-via",
        .name = "jump-box",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
    };
    try rig.store.upsert(io, via_server);
    _ = try rig.manager.connect(via_server, env.password, null);
    try waitForStatus(&rig.manager, "itest-jump-via", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-jump-via", true);
    try waitForStatus(&rig.manager, "itest-jump-via", .ready, 20 * std.time.ns_per_s);

    // The target: the same container's sshd, reached THROUGH the via
    // session (direct-tcpip to 127.0.0.1:22 as the container sees it).
    const target_server = servers.Server{
        .id = "itest-jump-target",
        .name = "behind-jump",
        .host = "127.0.0.1",
        .port = 22,
        .user = env.user,
        .auth_method = .password,
        .via_server_id = "itest-jump-via",
    };
    try rig.store.upsert(io, target_server);
    _ = try rig.manager.connect(target_server, env.password, null);
    try waitForStatus(&rig.manager, "itest-jump-target", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-jump-target", true);
    try waitForStatus(&rig.manager, "itest-jump-target", .ready, 20 * std.time.ns_per_s);

    // The regression: disconnecting the via while the target's jump
    // tunnel is live used to deadlock — disconnect held the manager
    // mutex across the worker join while the via worker's sessionDone
    // cascade spun on the same mutex resolving this very target.
    rig.manager.disconnect("itest-jump-via");

    // The dependant must leave .ready (cascade error or its own
    // transport failure), bounded — never a hang.
    const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 20 * std.time.ns_per_s;
    while (true) {
        const info = rig.manager.sessionSnapshot("itest-jump-target") catch break;
        if (info.status != .ready and info.status != .connecting) break;
        if (std.Io.Timestamp.now(io, .real).nanoseconds >= deadline) return error.TestUnexpectedResult;
        integration.testSleep(50);
    }
    rig.manager.disconnect("itest-jump-target");
}

fn toggleForwarding(rig: *TestRig, id: []const u8, enabled: bool) !void {
    const allocator = std.testing.allocator;
    const outcome = try allocator.create(sessions.ForwardSetOutcome);
    outcome.* = .{ .allocator = allocator };
    rig.manager.setForwarding(id, enabled, outcome) catch |err| {
        allocator.destroy(outcome);
        return err;
    };
    outcome.wait(std.testing.io, std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 20 * std.time.ns_per_s);
    if (!outcome.isDone() and !outcome.abandon()) return error.Timeout;
    defer allocator.destroy(outcome);
    if (!outcome.ok) {
        std.debug.print("forwarding failed: {s}\n", .{outcome.message()});
        return error.TestUnexpectedResult;
    }
}

test "integration: isolated agent forwarding replaces shell cursors and closes proxy access on disable" {
    const env = TestEnv.load();
    if (!env.active or integration.getEnv("OARS_TEST_AGENT") == null) return;
    const io = std.testing.io;
    var rig: TestRig = undefined;
    try rig.init("forwarding");
    defer rig.deinit();
    const id = "forwarding-fixture";
    const server = servers.Server{ .id = id, .name = "Forwarding fixture", .host = env.host, .port = env.port, .user = env.user, .auth_method = .password };
    try rig.store.upsert(io, server);
    _ = try rig.manager.connect(server, env.password, null);
    try waitForStatus(&rig.manager, id, .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust(id, true);
    try waitForStatus(&rig.manager, id, .ready, 20 * std.time.ns_per_s);
    const original = rig.manager.get(id).?.shell_channel_id;
    try toggleForwarding(&rig, id, false);
    try std.testing.expectEqual(original, rig.manager.get(id).?.shell_channel_id);
    try toggleForwarding(&rig, id, true);
    try std.testing.expect((try rig.manager.sessionSnapshot(id)).forwarding);
    const forwarded = rig.manager.get(id).?.shell_channel_id;
    try std.testing.expect(forwarded != original);
    try integration.shellReadUntil(&rig.manager, id, "ssh-add -L\n", "oars-forward-test");
    try std.testing.expectError(error.InvalidChannel, rig.manager.closeChannel(id, forwarded));
    try toggleForwarding(&rig, id, false);
    try std.testing.expect(!(try rig.manager.sessionSnapshot(id)).forwarding);
    try std.testing.expect(rig.manager.get(id).?.shell_channel_id != forwarded);
    try integration.shellReadUntil(&rig.manager, id, "ssh-add -L >/dev/null 2>&1 || echo forwar\"ding-disabled\"\n", "forwarding-disabled");
}
