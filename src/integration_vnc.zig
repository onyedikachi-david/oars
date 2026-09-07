//! Spec 12 integration coverage (container): the full VNC-over-SSH
//! tunnel. The fixture includes x11vnc, Xvfb, and XFCE; the approval-gated
//! setup helper configures and starts them on display :1 (port
//! 5901), `oars.vnc.start` opens a loopback WebSocket → SSH direct-tcpip
//! tunnel, and a Zig WebSocket/RFB client performs VNC authentication,
//! receives live raw framebuffer pixels, moves the X pointer, and types into
//! a real xterm. `oars.vnc.poll` then reports connected with real byte
//! counters before `stop` tears the tunnel down.
//!
//! Imported from integration.zig so `zig build test` picks it up.
//! Skipped unless OARS_TEST_SSH_* is set. Idempotent: the container
//! persists, so a previous run configures the installed package and the VNC
//! server processes are restarted fresh each run.

const std = @import("std");
const servers = @import("servers.zig");
const wsmod = @import("ws.zig");
const vncmod = @import("vnc.zig");
const rig_mod = @import("integration.zig");
const mbedtls = @cImport({
    @cInclude("mbedtls/des.h");
});

const TestRig = rig_mod.TestRig;
const testSleep = rig_mod.testSleep;
const execWait = rig_mod.execWait;
const waitForStatus = rig_mod.waitForStatus;

const server_id = "itest-vnc-1";
const vnc_port: u16 = 5901;

const VncSetupResp = struct {
    result: struct {
        ok: bool = false,
        @"error": []const u8 = "",
        action: []const u8 = "",
        executed: bool = false,
        plan: []const u8 = "",
        hint: []const u8 = "",
        desktop_action: []const u8 = "",
        desktop_name: []const u8 = "",
    },
};

const VncProbeResp = struct {
    result: struct {
        ok: bool = false,
        display_present: bool = false,
        display_accessible: bool = false,
        display_managed: bool = false,
        x11vnc: bool = false,
        tigervnc: bool = false,
        desktop_installed: bool = false,
        window_manager_running: bool = false,
        desktop_surface_running: bool = false,
        desktop_panel_running: bool = false,
        desktop_running: bool = false,
        desktop_name: []const u8 = "",
        setup_state: []const u8 = "idle",
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

fn consumePrefix(list: *std.ArrayList(u8), len: usize) void {
    std.debug.assert(len <= list.items.len);
    std.mem.copyForwards(u8, list.items[0 .. list.items.len - len], list.items[len..]);
    list.items.len -= len;
}

fn socketWriteAll(stream: std.Io.net.Stream, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = std.c.write(stream.socket.handle, bytes[written..].ptr, bytes.len - written);
        if (n <= 0) return error.WriteFailed;
        written += @intCast(n);
    }
}

const RfbReader = struct {
    stream: std.Io.net.Stream,
    wire: std.ArrayList(u8) = .empty,
    rfb: std.ArrayList(u8) = .empty,
    total_rfb_bytes: usize = 0,

    fn deinit(self: *RfbReader) void {
        self.wire.deinit(std.testing.allocator);
        self.rfb.deinit(std.testing.allocator);
    }

    fn pump(self: *RfbReader, deadline: i128) !void {
        const initial_rfb_len = self.rfb.items.len;
        while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
            while (self.wire.items.len > 0) {
                const parsed = wsmod.parseFrame(self.wire.items, false) catch return error.BadWebSocketFrame;
                switch (parsed) {
                    .need_more => break,
                    .frame => |frame| {
                        const consumed = frame.payload_offset + frame.payload.len;
                        switch (frame.opcode) {
                            .binary => {
                                try self.rfb.appendSlice(std.testing.allocator, frame.payload);
                                self.total_rfb_bytes += frame.payload.len;
                            },
                            .ping, .pong => {},
                            .close => return error.WebSocketClosed,
                            else => return error.BadWebSocketFrame,
                        }
                        consumePrefix(&self.wire, consumed);
                    },
                }
            }
            if (self.rfb.items.len > initial_rfb_len) return;

            var chunk: [64 * 1024]u8 = undefined;
            const n = wsReadAvailable(self.stream, &chunk);
            if (n > 0) {
                try self.wire.appendSlice(std.testing.allocator, chunk[0..n]);
                continue;
            }
            testSleep(10);
        }
        std.debug.print("RFB read timed out: total={d} buffered={d} wire={d}\n", .{
            self.total_rfb_bytes,
            self.rfb.items.len,
            self.wire.items.len,
        });
        return error.TestUnexpectedResult;
    }

    fn readExact(self: *RfbReader, out: []u8, timeout_ns: i128) !void {
        const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + timeout_ns;
        while (self.rfb.items.len < out.len) try self.pump(deadline);
        @memcpy(out, self.rfb.items[0..out.len]);
        consumePrefix(&self.rfb, out.len);
    }
};

fn wsHandshake(client: *RfbReader, token: []const u8) !void {
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
    try socketWriteAll(client.stream, req);

    const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 10 * std.time.ns_per_s;
    while (std.Io.Timestamp.now(io, .real).nanoseconds < deadline) {
        if (std.mem.indexOf(u8, client.wire.items, "\r\n\r\n")) |header_end| {
            if (std.mem.indexOf(u8, client.wire.items[0..header_end], "101 Switching Protocols") == null or
                std.mem.indexOf(u8, client.wire.items[0..header_end], "Sec-WebSocket-Protocol: binary") == null)
            {
                return error.TestUnexpectedResult;
            }
            consumePrefix(&client.wire, header_end + 4);
            return;
        }
        var chunk: [4096]u8 = undefined;
        const n = wsReadAvailable(client.stream, &chunk);
        if (n > 0) try client.wire.appendSlice(std.testing.allocator, chunk[0..n]);
        testSleep(10);
    }
    return error.TestUnexpectedResult;
}

fn sendRfb(stream: std.Io.net.Stream, payload: []const u8) !void {
    var frame: [1024]u8 = undefined;
    if (payload.len + 14 > frame.len) return error.MessageTooLarge;
    var mask: [4]u8 = undefined;
    std.Io.random(std.testing.io, &mask);
    const len = wsmod.encodeClientFrame(&frame, .binary, payload, mask);
    try socketWriteAll(stream, frame[0..len]);
}

fn reverseByteBits(value: u8) u8 {
    var out = ((value & 0xf0) >> 4) | ((value & 0x0f) << 4);
    out = ((out & 0xcc) >> 2) | ((out & 0x33) << 2);
    return ((out & 0xaa) >> 1) | ((out & 0x55) << 1);
}

fn vncAuthResponse(challenge: *const [16]u8, password: []const u8) ![16]u8 {
    var key = [_]u8{0} ** 8;
    for (password[0..@min(password.len, key.len)], 0..) |byte, i| key[i] = reverseByteBits(byte);
    defer std.crypto.secureZero(u8, &key);

    var ctx: mbedtls.mbedtls_des_context = undefined;
    mbedtls.mbedtls_des_init(&ctx);
    defer mbedtls.mbedtls_des_free(&ctx);
    if (mbedtls.mbedtls_des_setkey_enc(&ctx, &key) != 0) return error.VncAuthFailed;

    var response: [16]u8 = undefined;
    if (mbedtls.mbedtls_des_crypt_ecb(&ctx, challenge[0..8].ptr, response[0..8].ptr) != 0 or
        mbedtls.mbedtls_des_crypt_ecb(&ctx, challenge[8..16].ptr, response[8..16].ptr) != 0)
    {
        return error.VncAuthFailed;
    }
    return response;
}

fn rfbHandshake(client: *RfbReader, password: []const u8) !struct { width: u16, height: u16 } {
    var greeting: [12]u8 = undefined;
    try client.readExact(&greeting, 10 * std.time.ns_per_s);
    try std.testing.expectEqualStrings("RFB 003.008\n", &greeting);
    try sendRfb(client.stream, &greeting);

    var security_count: [1]u8 = undefined;
    try client.readExact(&security_count, 10 * std.time.ns_per_s);
    try std.testing.expect(security_count[0] > 0);
    var security_types: [32]u8 = undefined;
    if (security_count[0] > security_types.len) return error.TestUnexpectedResult;
    try client.readExact(security_types[0..security_count[0]], 10 * std.time.ns_per_s);
    try std.testing.expect(std.mem.indexOfScalar(u8, security_types[0..security_count[0]], 2) != null);
    try sendRfb(client.stream, &.{2});

    var challenge: [16]u8 = undefined;
    try client.readExact(&challenge, 10 * std.time.ns_per_s);
    var response = try vncAuthResponse(&challenge, password);
    defer std.crypto.secureZero(u8, &response);
    try sendRfb(client.stream, &response);

    var security_result: [4]u8 = undefined;
    try client.readExact(&security_result, 10 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, &security_result, .big));
    try sendRfb(client.stream, &.{1}); // shared session

    var server_init: [24]u8 = undefined;
    try client.readExact(&server_init, 10 * std.time.ns_per_s);
    const width = std.mem.readInt(u16, server_init[0..2], .big);
    const height = std.mem.readInt(u16, server_init[2..4], .big);
    const name_len = std.mem.readInt(u32, server_init[20..24], .big);
    if (width == 0 or height == 0 or name_len > 4096) return error.TestUnexpectedResult;
    var name: [4096]u8 = undefined;
    try client.readExact(name[0..name_len], 10 * std.time.ns_per_s);
    return .{ .width = width, .height = height };
}

fn requestRawFramebuffer(client: *RfbReader, width: u16, height: u16) !void {
    const pixel_format = [_]u8{
        0, 0, 0, 0, // SetPixelFormat + padding
        32, 24, 0, 1, // 32 bpp, depth 24, little-endian, true colour
        0, 255, 0, 255, 0, 255, // RGB max values
        16, 8, 0, 0, 0, 0, // RGB shifts + padding
    };
    try sendRfb(client.stream, &pixel_format);
    try sendRfb(client.stream, &.{ 2, 0, 0, 1, 0, 0, 0, 0 }); // raw encoding only

    var request = [_]u8{0} ** 10;
    request[0] = 3; // FramebufferUpdateRequest
    std.mem.writeInt(u16, request[6..8], width, .big);
    std.mem.writeInt(u16, request[8..10], height, .big);
    try sendRfb(client.stream, &request);
}

fn expectRawFramebuffer(client: *RfbReader) !void {
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 20 * std.time.ns_per_s;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        var message_type: [1]u8 = undefined;
        try client.readExact(&message_type, 20 * std.time.ns_per_s);
        if (message_type[0] == 2) continue; // bell
        if (message_type[0] != 0) return error.TestUnexpectedResult;

        var update_header: [3]u8 = undefined;
        try client.readExact(&update_header, 20 * std.time.ns_per_s);
        const rectangles = std.mem.readInt(u16, update_header[1..3], .big);
        var saw_pixels = false;
        var varied_pixels = false;
        for (0..rectangles) |_| {
            var rectangle: [12]u8 = undefined;
            try client.readExact(&rectangle, 20 * std.time.ns_per_s);
            const rect_width = std.mem.readInt(u16, rectangle[4..6], .big);
            const rect_height = std.mem.readInt(u16, rectangle[6..8], .big);
            const encoding = std.mem.readInt(i32, rectangle[8..12], .big);
            try std.testing.expectEqual(@as(i32, 0), encoding);
            const byte_count = @as(usize, rect_width) * @as(usize, rect_height) * 4;
            var remaining = byte_count;
            var first_pixel: ?[4]u8 = null;
            var chunk: [8192]u8 = undefined;
            while (remaining > 0) {
                const take = @min(remaining, chunk.len);
                try client.readExact(chunk[0..take], 20 * std.time.ns_per_s);
                var offset: usize = 0;
                while (offset + 4 <= take) : (offset += 4) {
                    const pixel: [4]u8 = chunk[offset..][0..4].*;
                    if (first_pixel) |first| {
                        if (!std.mem.eql(u8, &first, &pixel)) varied_pixels = true;
                    } else {
                        first_pixel = pixel;
                    }
                }
                remaining -= take;
            }
            saw_pixels = saw_pixels or byte_count > 0;
        }
        try std.testing.expect(saw_pixels);
        try std.testing.expect(varied_pixels);
        return;
    }
    return error.TestUnexpectedResult;
}

fn sendPointer(client: *RfbReader, x: u16, y: u16) !void {
    var event = [_]u8{ 5, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u16, event[2..4], x, .big);
    std.mem.writeInt(u16, event[4..6], y, .big);
    try sendRfb(client.stream, &event);
}

fn sendText(client: *RfbReader, text: []const u8) !void {
    var events: [512]u8 = undefined;
    var len: usize = 0;
    for (text) |byte| {
        const keysym: u32 = if (byte == '\n') 0xff0d else byte;
        for ([_]u8{ 1, 0 }) |down| {
            events[len..][0..8].* = .{ 4, down, 0, 0, 0, 0, 0, 0 };
            std.mem.writeInt(u32, events[len + 4 ..][0..4], keysym, .big);
            len += 8;
        }
    }
    try sendRfb(client.stream, events[0..len]);
}

test "integration: vnc setup, framebuffer, pointer, keyboard, tunnel teardown" {
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

    // A detached install survives the exec channel that starts it. A later
    // probe and waiter recover its state without starting a duplicate job.
    try execWait(&rig.manager, server_id, "rm -f /tmp/oars-vnc-install-release", 0, "");
    const install_start = try vncmod.installStartCommand(std.testing.allocator, 2, "while [ ! -f /tmp/oars-vnc-install-release ]; do sleep 1; done");
    defer std.testing.allocator.free(install_start);
    try execWait(&rig.manager, server_id, install_start, 0, "");
    var installing_probe = try dispatchParsed(&rig, VncProbeResp, "{\"id\":\"pi1\",\"command\":\"oars.vnc.probe\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":2}}");
    defer installing_probe.deinit();
    try std.testing.expectEqualStrings("installing", installing_probe.value.result.setup_state);
    try execWait(&rig.manager, server_id, "touch /tmp/oars-vnc-install-release", 0, "");
    const install_wait = try vncmod.installWaitCommand(std.testing.allocator, 2);
    defer std.testing.allocator.free(install_wait);
    try execWait(&rig.manager, server_id, install_wait, 0, "setup_state=installed");
    const mark_ready = try vncmod.setupStateCommand(std.testing.allocator, 2, "ready");
    defer std.testing.allocator.free(mark_ready);
    try execWait(&rig.manager, server_id, mark_ready, 0, "");
    var ready_probe = try dispatchParsed(&rig, VncProbeResp, "{\"id\":\"pi2\",\"command\":\"oars.vnc.probe\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":2}}");
    defer ready_probe.deinit();
    try std.testing.expectEqualStrings("ready", ready_probe.value.result.setup_state);

    // --- setup helper: plan first (approval), then execute + audit --------
    var dry = try dispatchParsed(&rig, VncSetupResp, "{\"id\":\"s1\",\"command\":\"oars.vnc.setup\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":1,\"dry_run\":true,\"install_desktop\":true}}");
    defer dry.deinit();
    try std.testing.expect(dry.value.result.ok);
    try std.testing.expect(!dry.value.result.executed);
    const action = dry.value.result.action;

    if (std.mem.eql(u8, action, "install") or std.mem.eql(u8, action, "configure")) {
        var install = try dispatchParsed(&rig, VncSetupResp, "{\"id\":\"s2\",\"command\":\"oars.vnc.setup\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":1,\"password\":\"oars-test-password\",\"install_desktop\":true}}");
        defer install.deinit();
        if (!install.value.result.ok) std.debug.print("VNC setup error: {s}\n", .{install.value.result.@"error"});
        try std.testing.expect(install.value.result.ok);
        try std.testing.expect(install.value.result.executed);
        if (std.mem.eql(u8, action, "install")) try std.testing.expect(std.mem.indexOf(u8, install.value.result.plan, "apk add") != null);
        try std.testing.expect(std.mem.indexOf(u8, install.value.result.hint, "-localhost") != null);
        try std.testing.expect(std.mem.indexOf(u8, install.value.result.hint, "-rfbauth") != null);
        try std.testing.expect(std.mem.indexOf(u8, install.value.result.hint, "-nopw") == null);
        try std.testing.expectEqualStrings("XFCE", install.value.result.desktop_name);
        try std.testing.expect(std.mem.eql(u8, install.value.result.desktop_action, "start") or
            std.mem.eql(u8, install.value.result.desktop_action, "install") or
            std.mem.eql(u8, install.value.result.desktop_action, "running"));
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

    // --- probe: x11vnc installed and listening on 5901 ----------------------
    // The daemons bind asynchronously; poll the probe until the listener
    // shows up (with a bounded deadline) instead of trusting fixed sleeps.
    var probe = try dispatchParsed(&rig, VncProbeResp, "{\"id\":\"p1\",\"command\":\"oars.vnc.probe\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":1}}");
    defer probe.deinit();
    const probe_deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 15 * std.time.ns_per_s;
    while (true) {
        try std.testing.expect(probe.value.result.ok);
        try std.testing.expect(probe.value.result.x11vnc);
        try std.testing.expect(probe.value.result.desktop_installed);
        try std.testing.expect(probe.value.result.window_manager_running);
        try std.testing.expect(probe.value.result.desktop_surface_running);
        try std.testing.expect(probe.value.result.desktop_panel_running);
        try std.testing.expect(probe.value.result.desktop_running);
        try std.testing.expectEqualStrings("XFCE", probe.value.result.desktop_name);
        try std.testing.expectEqualStrings("ready", probe.value.result.setup_state);
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
        probe = try dispatchParsed(&rig, VncProbeResp, "{\"id\":\"p1\",\"command\":\"oars.vnc.probe\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":1}}");
    }

    // Simulate the post-reboot stopped state without removing any packages.
    // These PIDs belong to daemons started above in the disposable fixture.
    try execWait(&rig.manager, server_id, "kill $(cat $HOME/.local/share/oars/vnc/display-1.pid) $(cat $HOME/.local/share/oars/vnc/display-1.xvfb.pid) 2>/dev/null || true", 0, "");
    testSleep(1500);
    var stopped_probe = try dispatchParsed(&rig, VncProbeResp, "{\"id\":\"stopped\",\"command\":\"oars.vnc.probe\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":1}}");
    defer stopped_probe.deinit();
    try std.testing.expect(stopped_probe.value.result.ok);
    try std.testing.expect(stopped_probe.value.result.x11vnc);
    try std.testing.expect(stopped_probe.value.result.desktop_installed);
    try std.testing.expect(!stopped_probe.value.result.desktop_running);
    for (stopped_probe.value.result.listening) |listener| try std.testing.expect(listener.port != vnc_port);
    try execWait(&rig.manager, server_id, "setsid sleep 600 </dev/null >/dev/null 2>&1 & echo $! >$HOME/.local/share/oars/vnc/stale-target.pid; cp $HOME/.local/share/oars/vnc/stale-target.pid $HOME/.local/share/oars/vnc/display-1.xfce.pid", 0, "");
    var restart_plan = try dispatchParsed(&rig, VncSetupResp, "{\"id\":\"restart-plan\",\"command\":\"oars.vnc.setup\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":1,\"dry_run\":true,\"install_desktop\":true}}");
    defer restart_plan.deinit();
    try std.testing.expect(restart_plan.value.result.ok);
    try std.testing.expectEqualStrings("configure", restart_plan.value.result.action);
    try std.testing.expectEqualStrings("", restart_plan.value.result.plan);
    try std.testing.expectEqualStrings("start", restart_plan.value.result.desktop_action);
    var restarted = try dispatchParsed(&rig, VncSetupResp, "{\"id\":\"restart\",\"command\":\"oars.vnc.setup\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":1,\"password\":\"oars-test-password\",\"install_desktop\":true}}");
    defer restarted.deinit();
    try std.testing.expect(restarted.value.result.ok and restarted.value.result.executed);
    try execWait(&rig.manager, server_id, "kill -0 $(cat $HOME/.local/share/oars/vnc/stale-target.pid)", 0, "");

    // A window manager alone can export a valid but black framebuffer. Remove
    // the XFCE desktop and panel, prove the probe reports an incomplete
    // session, then exercise the setup helper's repair path.
    try execWait(
        &rig.manager,
        server_id,
        "pkill -x xfdesktop 2>/dev/null || true; pkill -x xfce4-panel 2>/dev/null || true; " ++
            "i=0; while [ \"$i\" -lt 50 ]; do " ++
            "found=0; clients=$(DISPLAY=:1 xprop -root _NET_CLIENT_LIST 2>/dev/null | sed -n 's/.*# //p' | tr -d ','); " ++
            "for window in $clients; do class=$(DISPLAY=:1 xprop -id $window WM_CLASS 2>/dev/null || true); " ++
            "case \"$class\" in *xfdesktop*|*xfce4-panel*) found=1 ;; esac; done; [ \"$found\" -eq 0 ] && exit 0; " ++
            "sleep 0.2; i=$((i + 1)); done; exit 1",
        0,
        "",
    );
    var incomplete = try dispatchParsed(&rig, VncProbeResp, "{\"id\":\"p2\",\"command\":\"oars.vnc.probe\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":1}}");
    defer incomplete.deinit();
    try std.testing.expect(incomplete.value.result.window_manager_running);
    try std.testing.expect(!incomplete.value.result.desktop_surface_running);
    try std.testing.expect(!incomplete.value.result.desktop_panel_running);
    try std.testing.expect(!incomplete.value.result.desktop_running);

    var repair = try dispatchParsed(&rig, VncSetupResp, "{\"id\":\"s3\",\"command\":\"oars.vnc.setup\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":1,\"password\":\"oars-test-password\",\"install_desktop\":true}}");
    defer repair.deinit();
    if (!repair.value.result.ok) std.debug.print("VNC desktop repair error: {s}\n", .{repair.value.result.@"error"});
    try std.testing.expect(repair.value.result.ok);
    try std.testing.expect(repair.value.result.executed);
    try std.testing.expectEqualStrings("start", repair.value.result.desktop_action);

    var repaired = try dispatchParsed(&rig, VncProbeResp, "{\"id\":\"p3\",\"command\":\"oars.vnc.probe\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":1}}");
    defer repaired.deinit();
    try std.testing.expect(repaired.value.result.window_manager_running);
    try std.testing.expect(repaired.value.result.desktop_surface_running);
    try std.testing.expect(repaired.value.result.desktop_panel_running);
    try std.testing.expect(repaired.value.result.desktop_running);

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

    // --- WebSocket + RFB: auth, pixels, pointer, and keyboard ----------------
    var addr = try std.Io.net.IpAddress.parse("127.0.0.1", start.value.result.ws_port);
    var stream = try std.Io.net.IpAddress.connect(&addr, io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);
    var client = RfbReader{ .stream = stream };
    defer client.deinit();
    try wsHandshake(&client, token);
    const desktop = try rfbHandshake(&client, "oars-test-password");
    try std.testing.expectEqual(@as(u16, 1280), desktop.width);
    try std.testing.expectEqual(@as(u16, 800), desktop.height);
    try requestRawFramebuffer(&client, desktop.width, desktop.height);
    try expectRawFramebuffer(&client);

    // The framebuffer check above runs before any test window is added, so its
    // varied pixels must come from the XFCE desktop and panel. Add an xterm now
    // to make pointer and keyboard input observable.
    try execWait(
        &rig.manager,
        server_id,
        "pkill -x xterm 2>/dev/null || true; rm -f /tmp/oars-vnc-keyboard /tmp/oars-vnc-xterm.log; " ++
            "DISPLAY=:1 setsid xterm -geometry 80x24+20+20 -T OarsVncInput " ++
            "-e sh -c 'IFS= read -r line; printf \"%s\" \"$line\" >/tmp/oars-vnc-keyboard; sleep 2' " ++
            "</dev/null >/tmp/oars-vnc-xterm.log 2>&1 &",
        0,
        "",
    );
    try execWait(
        &rig.manager,
        server_id,
        "i=0; while [ \"$i\" -lt 50 ]; do " ++
            "wid=$(DISPLAY=:1 xdotool search --name OarsVncInput 2>/dev/null | head -n1); " ++
            "if [ -n \"$wid\" ] && DISPLAY=:1 xdotool windowfocus \"$wid\" 2>/dev/null; then exit 0; fi; " ++
            "sleep 0.2; i=$((i + 1)); done; exit 1",
        0,
        "",
    );

    try sendPointer(&client, 123, 234);
    var pointer_moved = false;
    var last_pointer: [128]u8 = undefined;
    var last_pointer_len: usize = 0;
    for (0..100) |_| {
        var pointer = try rig.manager.execWait(server_id, "DISPLAY=:1 xdotool getmouselocation --shell", 4096, 5 * std.time.ns_per_s);
        defer pointer.output.deinit(std.testing.allocator);
        last_pointer_len = @min(pointer.output.items.len, last_pointer.len);
        @memcpy(last_pointer[0..last_pointer_len], pointer.output.items[0..last_pointer_len]);
        if (!pointer.limited and pointer.exit == 0 and
            std.mem.indexOf(u8, pointer.output.items, "X=123") != null and
            std.mem.indexOf(u8, pointer.output.items, "Y=234") != null)
        {
            pointer_moved = true;
            break;
        }
        testSleep(100);
    }
    if (!pointer_moved) std.debug.print("VNC pointer did not move; last remote state: {s}\n", .{last_pointer[0..last_pointer_len]});
    try std.testing.expect(pointer_moved);

    try sendText(&client, "oars-vnc-input\n");
    var received_keyboard = false;
    for (0..100) |_| {
        var typed = try rig.manager.execWait(server_id, "cat /tmp/oars-vnc-keyboard 2>/dev/null", 4096, 5 * std.time.ns_per_s);
        defer typed.output.deinit(std.testing.allocator);
        if (typed.exit == 0 and std.mem.eql(u8, typed.output.items, "oars-vnc-input")) {
            received_keyboard = true;
            break;
        }
        testSleep(100);
    }
    try std.testing.expect(received_keyboard);

    // --- poll: connected with real byte counters -----------------------------
    var poll_buf: [256]u8 = undefined;
    const poll_req = try std.fmt.bufPrint(&poll_buf, "{{\"id\":\"v1\",\"command\":\"oars.vnc.poll\",\"payload\":{{\"server_id\":\"{s}\",\"tunnel_id\":{d}}}}}", .{ server_id, tunnel_id });
    var poll = try dispatchParsed(&rig, VncPollResp, poll_req);
    defer poll.deinit();
    try std.testing.expect(poll.value.result.ok);
    try std.testing.expectEqualStrings("connected", poll.value.result.state);
    try std.testing.expect(poll.value.result.bytes_down > 1024);
    try std.testing.expect(poll.value.result.bytes_up > 0);

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
    try execWait(&rig.manager, server_id, "pkill -x xterm 2>/dev/null; pkill -x xfce4-session 2>/dev/null; pkill -x xfwm4 2>/dev/null; pkill -x xfdesktop 2>/dev/null; pkill -x xfce4-panel 2>/dev/null; pkill -x x11vnc 2>/dev/null; pkill -x Xvfb 2>/dev/null; true", 0, "");
}

test "integration: vnc discovers authorization for an existing protected display" {
    const env = rig_mod.TestEnv.load();
    if (!env.active) return; // env-gated

    var rig: TestRig = undefined;
    try rig.init("vnc-auth");
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

    try execWait(&rig.manager, server_id, "umask 077; mkdir -p $HOME/.local/share/oars/auth-fixture; printf '\\377\\377\\000\\000\\000\\001\\063\\000\\022\\115\\111\\124\\055\\115\\101\\107\\111\\103\\055\\103\\117\\117\\113\\111\\105\\055\\061\\000\\020\\000\\021\\042\\063\\104\\125\\146\\167\\210\\231\\252\\273\\314\\335\\356\\377' >$HOME/.local/share/oars/auth-fixture/Xauthority; setsid Xvfb :3 -screen 0 640x480x24 -nolisten tcp -auth $HOME/.local/share/oars/auth-fixture/Xauthority </dev/null >/dev/null 2>&1 & echo $! >$HOME/.local/share/oars/auth-fixture/pid", 0, "");
    testSleep(1000);
    var probe = try dispatchParsed(&rig, VncProbeResp, "{\"id\":\"auth-probe\",\"command\":\"oars.vnc.probe\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":3}}");
    defer probe.deinit();
    try std.testing.expect(probe.value.result.ok);
    try std.testing.expect(probe.value.result.display_present);
    try std.testing.expect(probe.value.result.display_accessible);
    try std.testing.expect(!probe.value.result.display_managed);
    var shared = try dispatchParsed(&rig, VncSetupResp, "{\"id\":\"auth-start\",\"command\":\"oars.vnc.setup\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":3,\"password\":\"oars-test-password\",\"install_desktop\":false}}");
    defer shared.deinit();
    try std.testing.expect(shared.value.result.ok and shared.value.result.executed);
    try execWait(&rig.manager, server_id, "mv $HOME/.local/share/oars/auth-fixture/Xauthority $HOME/.local/share/oars/auth-fixture/hidden-cookie", 0, "");
    var unavailable = try dispatchParsed(&rig, VncProbeResp, "{\"id\":\"auth-missing\",\"command\":\"oars.vnc.probe\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":3}}");
    defer unavailable.deinit();
    try std.testing.expect(unavailable.value.result.ok and unavailable.value.result.display_present);
    try std.testing.expect(!unavailable.value.result.display_accessible);
    var blocked = try dispatchParsed(&rig, VncSetupResp, "{\"id\":\"auth-blocked\",\"command\":\"oars.vnc.setup\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\",\"display\":3,\"dry_run\":true,\"install_desktop\":true}}");
    defer blocked.deinit();
    try std.testing.expect(!blocked.value.result.ok);
    try std.testing.expect(std.mem.indexOf(u8, blocked.value.result.@"error", "already in use") != null);
}
