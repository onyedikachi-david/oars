//! Spec 11 integration coverage (container): the backend half of the AI
//! terminal — provider config round trip (no secrets), the context
//! bundle (monitor cache + the light OS/hostname/log-mtime probe),
//! approved-run auditing through `oars.ssh.exec`, and the audit-filtered
//! `oars.ai.history`. The model call itself is frontend-side (spec 11
//! §6) and needs no container.
//!
//! Imported from integration.zig so `zig build test` picks it up.
//! Skipped unless OARS_TEST_SSH_* is set.

const std = @import("std");
const servers = @import("servers.zig");
const rig_mod = @import("integration.zig");

const TestRig = rig_mod.TestRig;
const testSleep = rig_mod.testSleep;
const execWait = rig_mod.execWait;
const execOut = rig_mod.execOut;
const waitForStatus = rig_mod.waitForStatus;

const server_id = "itest-ai-1";
const log_path = "/var/log/oars-ai-test.log";
const run_marker = "/tmp/oars-ai-run.txt";

const ProviderResp = struct {
    result: struct {
        ok: bool = false,
        provider: ?struct {
            adapter: []const u8 = "",
            base_url: []const u8 = "",
            model: []const u8 = "",
        } = null,
    },
};

const AiContextResp = struct {
    result: struct {
        ok: bool = false,
        os: []const u8 = "",
        hostname: []const u8 = "",
        uptime_sec: u64 = 0,
        mem: struct { total_bytes: u64 = 0 } = .{},
        disk: struct { total_bytes: u64 = 0 } = .{},
        top_processes: []const struct {
            pid: u32 = 0,
            name: []const u8 = "",
        } = &.{},
        active_logs: []const struct {
            path: []const u8 = "",
            last_write: u64 = 0,
        } = &.{},
        probe_error: ?[]const u8 = null,
    },
};

const ExecResp = struct {
    result: struct {
        ok: bool = false,
        channel: u32 = 0,
    },
};

const AiHistoryResp = struct {
    result: struct {
        ok: bool = false,
        runs: []const struct {
            ts: i64 = 0,
            action: []const u8 = "",
            detail: []const u8 = "",
        } = &.{},
    },
};

/// Dispatches and parses with alloc_always (the rig's output buffer is
/// reused by the next dispatch).
fn dispatchParsed(rig: *TestRig, comptime T: type, req: []const u8) !std.json.Parsed(T) {
    const resp = rig.dispatch(req);
    return std.json.parseFromSlice(T, std.testing.allocator, resp, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

test "integration: ai context bundle, provider config, exec audit, and history" {
    const env = rig_mod.TestEnv.load();
    if (!env.active) return; // env-gated

    var rig: TestRig = undefined;
    try rig.init("ai");
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

    // --- start clean (the container persists) ------------------------------
    var clean_buf: [512]u8 = undefined;
    const clean = try std.fmt.bufPrint(&clean_buf, "rm -f {s} {s} && echo 'ai log line' > {s}", .{ log_path, run_marker, log_path });
    try execWait(&rig.manager, server_id, clean, 0, "");
    // The context probe reports configured log sources — add ours.
    var src_buf: [256]u8 = undefined;
    const src_req = try std.fmt.bufPrint(&src_buf, "{{\"id\":\"ls\",\"command\":\"oars.logs.addSource\",\"payload\":{{\"server_id\":\"{s}\",\"path\":\"{s}\"}}}}", .{ server_id, log_path });
    const src_resp = rig.dispatch(src_req);
    try std.testing.expect(std.mem.indexOf(u8, src_resp, "\"ok\":true") != null);

    // --- provider config round trip (key stays in the frontend Keychain) ---
    const set_req =
        \\{"id":"ps","command":"oars.ai.provider.set","payload":{"provider":{"adapter":"openai_compatible","base_url":"https://api.openai.com/v1","model":"gpt-4o-mini","capabilities":{"instruction_role":"developer","streaming":true,"structured_output":true}}}}
    ;
    var set_parsed = try dispatchParsed(&rig, ProviderResp, set_req);
    defer set_parsed.deinit();
    try std.testing.expect(set_parsed.value.result.ok);
    try std.testing.expectEqualStrings("openai_compatible", set_parsed.value.result.provider.?.adapter);
    var get_parsed = try dispatchParsed(&rig, ProviderResp, "{\"id\":\"pg\",\"command\":\"oars.ai.provider.get\",\"payload\":{}}");
    defer get_parsed.deinit();
    try std.testing.expectEqualStrings("gpt-4o-mini", get_parsed.value.result.provider.?.model);
    try std.testing.expectEqualStrings("https://api.openai.com/v1", get_parsed.value.result.provider.?.base_url);

    // --- context bundle: monitor snapshot + light probe ---------------------
    var ctx_parsed: ?std.json.Parsed(AiContextResp) = null;
    defer if (ctx_parsed) |*p| p.deinit();
    const ctx_deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 30 * std.time.ns_per_s;
    while (std.Io.Timestamp.now(io, .real).nanoseconds < ctx_deadline) {
        var p = try dispatchParsed(&rig, AiContextResp, "{\"id\":\"c1\",\"command\":\"oars.ai.context\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\"}}");
        if (p.value.result.ok and p.value.result.mem.total_bytes > 0 and p.value.result.os.len > 0) {
            ctx_parsed = p;
            break;
        }
        p.deinit();
        testSleep(250); // the first monitor probe is worker-async
    }
    const ctx = (ctx_parsed orelse return error.TestUnexpectedResult).value.result;
    try std.testing.expect(std.mem.indexOf(u8, ctx.os, "Alpine") != null);
    try std.testing.expect(ctx.hostname.len > 0);
    try std.testing.expect(ctx.uptime_sec > 0);
    try std.testing.expect(ctx.mem.total_bytes > 0);
    try std.testing.expect(ctx.disk.total_bytes > 0);
    try std.testing.expect(ctx.top_processes.len > 0); // sshd at minimum
    var log_found = false;
    for (ctx.active_logs) |l| {
        if (std.mem.eql(u8, l.path, log_path)) {
            try std.testing.expect(l.last_write > 0);
            log_found = true;
        }
    }
    try std.testing.expect(log_found);

    // A second call within the 5 s window serves the cached probe (os
    // stays the same without another exec; the snapshot refreshes).
    var ctx2 = try dispatchParsed(&rig, AiContextResp, "{\"id\":\"c2\",\"command\":\"oars.ai.context\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\"}}");
    defer ctx2.deinit();
    try std.testing.expectEqualStrings(ctx.os, ctx2.value.result.os);

    // --- approved run: oars.ssh.exec is audited; ai.history shows it --------
    var exec_buf: [512]u8 = undefined;
    const exec_req = try std.fmt.bufPrint(&exec_buf, "{{\"id\":\"e1\",\"command\":\"oars.ssh.exec\",\"payload\":{{\"server_id\":\"{s}\",\"command\":\"echo ai-run > {s}\"}}}}", .{ server_id, run_marker });
    var exec_parsed = try dispatchParsed(&rig, ExecResp, exec_req);
    defer exec_parsed.deinit();
    try std.testing.expect(exec_parsed.value.result.ok);
    const channel = exec_parsed.value.result.channel;

    // Drain the channel to completion (the exec already ran server-side).
    const drain_deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 20 * std.time.ns_per_s;
    var done = false;
    while (std.Io.Timestamp.now(io, .real).nanoseconds < drain_deadline) {
        const polls = try rig.manager.pollChannels(server_id, &.{.{ .id = channel, .pos = 0 }}, false, 64 * 1024, 64 * 1024);
        var eof = false;
        for (polls) |*poll| {
            if (poll.id == channel and poll.eof) eof = true;
        }
        for (polls) |*poll| poll.deinit(std.testing.allocator);
        std.testing.allocator.free(polls);
        if (eof) {
            done = true;
            break;
        }
        testSleep(50);
    }
    try std.testing.expect(done);
    const marker = try execOut(&rig.manager, server_id, "cat " ++ run_marker);
    defer std.testing.allocator.free(marker);
    try std.testing.expect(std.mem.indexOf(u8, marker, "ai-run") != null);

    var hist_buf: [256]u8 = undefined;
    const hist_req = try std.fmt.bufPrint(&hist_buf, "{{\"id\":\"h1\",\"command\":\"oars.ai.history\",\"payload\":{{\"server_id\":\"{s}\",\"limit\":10}}}}", .{server_id});
    var hist_parsed = try dispatchParsed(&rig, AiHistoryResp, hist_req);
    defer hist_parsed.deinit();
    try std.testing.expect(hist_parsed.value.result.ok);
    try std.testing.expect(hist_parsed.value.result.runs.len > 0);
    const newest = hist_parsed.value.result.runs[0];
    try std.testing.expectEqualStrings("ssh.exec", newest.action);
    try std.testing.expect(std.mem.indexOf(u8, newest.detail, "echo ai-run") != null);

    // --- cleanup -------------------------------------------------------------
    try execWait(&rig.manager, server_id, "rm -f " ++ log_path ++ " " ++ run_marker, 0, "");
}
