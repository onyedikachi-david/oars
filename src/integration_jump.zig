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
