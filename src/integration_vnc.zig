//! Spec 12 integration coverage (container): the full VNC-over-SSH
//! tunnel. The setup helper installs x11vnc + Xvfb (approval-gated and
//! audited), the test starts a real VNC server on display :1 (port
//! 5901), `oars.vnc.start` opens a loopback WebSocket → SSH direct-tcpip
//! tunnel, a Zig WebSocket client performs the RFC 6455 handshake
//! (Origin `zero://app`, `binary` subprotocol) and observes the VNC
//! server's RFB greeting flowing through the tunnel, and `oars.vnc.poll`
//! reports connected with real byte counters before `stop` tears it
//! down.
//!
//! Imported from integration.zig so `zig build test` picks it up.
//! Skipped unless OARS_TEST_SSH_* is set. Idempotent: the container
//! persists, so a previous run's install is detected (already_installed)
//! and the VNC server processes are restarted fresh each run.

const std = @import("std");
const servers = @import("servers.zig");
const wsmod = @import("ws.zig");
const rig_mod = @import("integration.zig");

const TestRig = rig_mod.TestRig;
const testSleep = rig_mod.testSleep;
const execWait = rig_mod.execWait;
const waitForStatus = rig_mod.waitForStatus;

const server_id = "itest-vnc-1";
const vnc_port: u16 = 5901;

const VncSetupResp = struct {
    result: struct {
        ok: bool = false,
        action: []const u8 = "",
        executed: bool = false,
        plan: []const u8 = "",
        hint: []const u8 = "",
    },
};

const VncProbeResp = struct {
    result: struct {
        ok: bool = false,
        x11vnc: bool = false,
        tigervnc: bool = false,
        listening: []const struct {
            port: u16 = 0,
            process: []const u8 = "",
        } = &.{},
    },
};

const VncStartResp = struct {
    result: struct {
        ok: bool = false,
        tunnel_id: u32 = 0,
        ws_port: u16 = 0,
        token: []const u8 = "",
    },
};

const VncPollResp = struct {
    result: struct {
        ok: bool = false,
        state: []const u8 = "",
        bytes_up: u64 = 0,
        bytes_down: u64 = 0,
        @"error": []const u8 = "",
    },
};

fn dispatchParsed(rig: *TestRig, comptime T: type, req: []const u8) !std.json.Parsed(T) {
    const resp = rig.dispatch(req);
    return std.json.parseFromSlice(T, std.testing.allocator, resp, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

/// Blocking read with a 1 s poll gate (the test thread may block).
fn wsReadAvailable(stream: std.Io.net.Stream, buf: []u8) usize {
    var fds = [_]std.posix.pollfd{.{ .fd = stream.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
    const ready = std.posix.poll(&fds, 1000) catch return 0;
    if (ready == 0 or fds[0].revents & std.posix.POLL.IN == 0) return 0;
    const n = std.posix.read(fds[0].fd, buf) catch return 0;
    return n;
}

/// Performs the RFC 6455 handshake against the tunnel and waits for the
/// first binary frame whose payload starts with `prefix` (the VNC server
/// greeting). Returns the payload (owned).
fn wsExpectFrame(stream: std.Io.net.Stream, token: []const u8, prefix: []const u8, timeout_ns: i128) ![]u8 {
    const io = std.testing.io;
    var req_buf: [512]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "GET /vnc/{s} HTTP/1.1\r\n" ++
        "Host: 127.0.0.1\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Origin: zero://app\r\n" ++
        "Sec-WebSocket-Protocol: binary\r\n\r\n", .{token});
    _ = std.c.write(stream.socket.handle, req.ptr, req.len);

    var acc: [4096]u8 = undefined;
    var acc_len: usize = 0;
    var handshaken = false;
    const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + timeout_ns;
    while (std.Io.Timestamp.now(io, .real).nanoseconds < deadline) {
        if (acc_len < acc.len) {
            const n = wsReadAvailable(stream, acc[acc_len..]);
            if (n > 0) acc_len += n;
        }
        if (!handshaken) {
            const header_end = std.mem.indexOf(u8, acc[0..acc_len], "\r\n\r\n") orelse {
                testSleep(25);
                continue;
            };
            if (std.mem.indexOf(u8, acc[0..header_end], "101 Switching Protocols") == null) {
                return error.TestUnexpectedResult;
            }
            handshaken = true;
            std.mem.copyForwards(u8, acc[0 .. acc_len - (header_end + 4)], acc[header_end + 4 .. acc_len]);
            acc_len -= header_end + 4;
        }
        if (acc_len > 0) {
            const parsed = wsmod.parseFrame(acc[0..acc_len], false) catch {
                testSleep(25);
                continue;
            };
            switch (parsed) {
                .need_more => testSleep(25),
                .frame => |f| {
                    if (f.opcode == .binary and f.payload.len >= prefix.len and
                        std.mem.eql(u8, f.payload[0..prefix.len], prefix))
                    {
                        return std.testing.allocator.dupe(u8, f.payload);
                    }
                    std.mem.copyForwards(u8, acc[0 .. acc_len - f.payload.len], acc[f.payload.len..]);
                    acc_len -= f.payload.len;
                },
            }
        } else {
            testSleep(25);
        }
    }
    return error.TestUnexpectedResult;
}

test "integration: vnc setup, probe, tunnel, ws handshake, RFB bytes, poll, stop" {
    const env = rig_mod.TestEnv.load();
    if (!env.active) return; // env-gated

    var rig: TestRig = undefined;
    try rig.init("vnc");
    defer rig.deinit();
    const io = std.testing.io;

    const server = servers.Server{
        .id = server_id,
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
    };
    try rig.store.upsert(io, server);
    _ = try rig.manager.connect(server, env.password, null);
    try waitForStatus(&rig.manager, server_id, .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust(server_id, true);
    try waitForStatus(&rig.manager, server_id, .ready, 20 * std.time.ns_per_s);

    // --- setup helper: plan first (approval), then execute + audit --------
    var dry = try dispatchParsed(&rig, VncSetupResp, "{\"id\":\"s1\",\"command\":\"oars.vnc.setup\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"dry_run\":true}}");
    defer dry.deinit();
    try std.testing.expect(dry.value.result.ok);
    try std.testing.expect(!dry.value.result.executed);
    const action = dry.value.result.action;

    if (std.mem.eql(u8, action, "install")) {
        var install = try dispatchParsed(&rig, VncSetupResp, "{\"id\":\"s2\",\"command\":\"oars.vnc.setup\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\"}}");
        defer install.deinit();
        try std.testing.expect(install.value.result.ok);
        try std.testing.expect(install.value.result.executed);
        try std.testing.expect(std.mem.indexOf(u8, install.value.result.plan, "apk add") != null);
        // The hint always configures a password, never -nopw (spec 12 §8).
        try std.testing.expect(std.mem.indexOf(u8, install.value.result.hint, "-passwd") != null);
        try std.testing.expect(std.mem.indexOf(u8, install.value.result.hint, "-nopw") == null);
        // Audited.
        const entries = try rig.audit_store.read(io, server_id, "vnc.setup", 10);
        defer {
            for (entries) |*e| e.deinit(std.testing.allocator);
            std.testing.allocator.free(entries);
        }
        try std.testing.expect(entries.len > 0);
    } else if (std.mem.eql(u8, action, "manual")) {
        return error.TestUnexpectedResult; // the container is Alpine
    }
    // already_installed: nothing more to do.

    // --- start a real VNC server (idempotent restart) ----------------------
    // The daemons must outlive the exec channel: `pkill -x` (never -f —
    // the pattern would match this very shell's command line and kill
    // it), a fresh :1 lock, and setsid so sshd's channel teardown cannot
    // reach their process group. All fds are redirected so the exec
    // channel EOFs as soon as the shell exits.
    try execWait(&rig.manager, server_id, "pkill -x x11vnc 2>/dev/null; pkill -x Xvfb 2>/dev/null; sleep 1; " ++
        "rm -f /tmp/.X1-lock /tmp/.X11-unix/X1; " ++
        "setsid Xvfb :1 -screen 0 1280x800x24 </dev/null >/dev/null 2>&1 & sleep 1; " ++
        "setsid x11vnc -display :1 -rfbport 5901 -forever -shared -passwd oars-test-password </dev/null >/dev/null 2>&1 & sleep 2; true", 0, "");

    // --- probe: x11vnc installed and listening on 5901 ----------------------
    // The daemons bind asynchronously; poll the probe until the listener
    // shows up (with a bounded deadline) instead of trusting fixed sleeps.
    var probe = try dispatchParsed(&rig, VncProbeResp, "{\"id\":\"p1\",\"command\":\"oars.vnc.probe\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\"}}");
    defer probe.deinit();
    const probe_deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 15 * std.time.ns_per_s;
    while (true) {
        try std.testing.expect(probe.value.result.ok);
        try std.testing.expect(probe.value.result.x11vnc);
        var found_5901 = false;
        for (probe.value.result.listening) |l| {
            if (l.port == vnc_port) {
                found_5901 = true;
                try std.testing.expectEqualStrings("x11vnc", l.process);
            }
        }
        if (found_5901) break;
        if (std.Io.Timestamp.now(io, .real).nanoseconds >= probe_deadline) {
            return error.TestUnexpectedResult;
        }
        probe.deinit();
        testSleep(500);
        probe = try dispatchParsed(&rig, VncProbeResp, "{\"id\":\"p1\",\"command\":\"oars.vnc.probe\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\"}}");
    }

    // --- start the tunnel ----------------------------------------------------
    var start_buf: [256]u8 = undefined;
    const start_req = try std.fmt.bufPrint(&start_buf, "{{\"id\":\"t1\",\"command\":\"oars.vnc.start\",\"payload\":{{\"server_id\":\"{s}\",\"port\":{d}}}}}", .{ server_id, vnc_port });
    var start = try dispatchParsed(&rig, VncStartResp, start_req);
    defer start.deinit();
    try std.testing.expect(start.value.result.ok);
    try std.testing.expect(start.value.result.token.len == 32);
    try std.testing.expect(start.value.result.ws_port > 0);
    const tunnel_id = start.value.result.tunnel_id;
    const token = start.value.result.token;

    // --- WebSocket client: handshake + RFB greeting through the tunnel ------
    var addr = try std.Io.net.IpAddress.parse("127.0.0.1", start.value.result.ws_port);
    var stream = try std.Io.net.IpAddress.connect(&addr, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);
    const greeting = try wsExpectFrame(stream, token, "RFB ", 15 * std.time.ns_per_s);
    defer std.testing.allocator.free(greeting);
    try std.testing.expectEqualStrings("RFB 003.008", greeting[0..11]);

    // --- poll: connected with real byte counters -----------------------------
    var poll_buf: [256]u8 = undefined;
    const poll_req = try std.fmt.bufPrint(&poll_buf, "{{\"id\":\"v1\",\"command\":\"oars.vnc.poll\",\"payload\":{{\"server_id\":\"{s}\",\"tunnel_id\":{d}}}}}", .{ server_id, tunnel_id });
    var poll = try dispatchParsed(&rig, VncPollResp, poll_req);
    defer poll.deinit();
    try std.testing.expect(poll.value.result.ok);
    try std.testing.expectEqualStrings("connected", poll.value.result.state);
    try std.testing.expect(poll.value.result.bytes_down >= greeting.len);

    // --- stop: teardown, poll reports closed ---------------------------------
    var stop_buf: [256]u8 = undefined;
    const stop_req = try std.fmt.bufPrint(&stop_buf, "{{\"id\":\"v2\",\"command\":\"oars.vnc.stop\",\"payload\":{{\"server_id\":\"{s}\",\"tunnel_id\":{d}}}}}", .{ server_id, tunnel_id });
    const stop_resp = rig.dispatch(stop_req);
    try std.testing.expect(std.mem.indexOf(u8, stop_resp, "\"ok\":true") != null);
    testSleep(300);
    var poll2 = try dispatchParsed(&rig, VncPollResp, poll_req);
    defer poll2.deinit();
    try std.testing.expect(poll2.value.result.ok);
    try std.testing.expectEqualStrings("closed", poll2.value.result.state);

    // --- cleanup ---------------------------------------------------------------
    try execWait(&rig.manager, server_id, "pkill -x x11vnc 2>/dev/null; pkill -x Xvfb 2>/dev/null; true", 0, "");
}
