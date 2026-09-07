//! Spec 15 integration coverage (container): command history capture for
//! tracked execs — exit, duration, bounded snippet, write-time redaction
//! (pattern pass for `oars.ssh.exec`, the operation's own `***` masking
//! for script runs) — plus replay (chainable, redacted-refusal) and the
//! audit list/clear handlers.
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

const server_id = "itest-his-1";
const marker_one = "/tmp/oars-his-one.txt";
const marker_two = "/tmp/oars-his-two.txt";
const secret_value = "hunter2-secret";
const script_secret = "supersecret-value";

const HistoryEntryShape = struct {
    id: []const u8 = "",
    operation_id: []const u8 = "",
    ts: i64 = 0,
    server_id: []const u8 = "",
    kind: []const u8 = "",
    command: []const u8 = "",
    exit: ?i32 = null,
    duration_ms: ?i64 = null,
    output_snippet: []const u8 = "",
    redacted: bool = false,
};

const HistoryListResp = struct {
    result: struct {
        ok: bool = false,
        entries: []const HistoryEntryShape = &.{},
    },
};

const ExecResp = struct {
    result: struct {
        ok: bool = false,
        channel: u32 = 0,
    },
};

const AuditListResp = struct {
    result: struct {
        ok: bool = false,
        entries: []const struct {
            id: []const u8 = "",
            type: []const u8 = "",
            target: []const u8 = "",
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

/// Polls the channel until EOF (the worker records history at EOF, so a
/// subsequent history.list is complete for this run).
fn drainChannel(rig: *TestRig, channel: u32) !void {
    const io = std.testing.io;
    const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 20 * std.time.ns_per_s;
    while (true) {
        const polls = try rig.manager.pollChannels(server_id, &.{.{ .id = channel, .pos = 0 }}, false, 64 * 1024, 64 * 1024);
        var eof = false;
        for (polls) |*poll| {
            if (poll.id == channel and poll.eof) eof = true;
        }
        for (polls) |*poll| poll.deinit(std.testing.allocator);
        std.testing.allocator.free(polls);
        if (eof) return;
        if (std.Io.Timestamp.now(io, .real).nanoseconds >= deadline) return error.TestUnexpectedResult;
        testSleep(50);
    }
}

/// Runs a tracked exec via the bridge and drains it to EOF.
fn trackedExec(rig: *TestRig, command: []const u8) !u32 {
    var req_buf: [1024]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "{{\"id\":\"te\",\"command\":\"oars.ssh.exec\",\"payload\":{{\"server_id\":\"{s}\",\"command\":\"{s}\"}}}}", .{ server_id, command });
    var parsed = try dispatchParsed(rig, ExecResp, req);
    defer parsed.deinit();
    try std.testing.expect(parsed.value.result.ok);
    const channel = parsed.value.result.channel;
    try drainChannel(rig, channel);
    return channel;
}

/// Fetches history entries, retrying until at least `want_min` exist (the
/// worker capture is async relative to the poll that observed EOF).
fn historyEntries(rig: *TestRig, want_min: usize) !std.json.Parsed(HistoryListResp) {
    const io = std.testing.io;
    const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 10 * std.time.ns_per_s;
    while (true) {
        var p = try dispatchParsed(rig, HistoryListResp, "{\"id\":\"hl\",\"command\":\"oars.history.list\",\"payload\":{}}");
        if (p.value.result.entries.len >= want_min) return p;
        p.deinit();
        if (std.Io.Timestamp.now(io, .real).nanoseconds >= deadline) return error.TestUnexpectedResult;
        testSleep(100);
    }
}

test "integration: exec capture, redaction, script secrets, replay, and audit list/clear" {
    const env = rig_mod.TestEnv.load();
    if (!env.active) return; // env-gated

    var rig: TestRig = undefined;
    try rig.init("history");
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
    const clean = try std.fmt.bufPrint(&clean_buf, "rm -f {s} {s}", .{ marker_one, marker_two });
    try execWait(&rig.manager, server_id, clean, 0, "");

    var his: ?std.json.Parsed(HistoryListResp) = null;
    defer if (his) |*p| p.deinit();

    // --- 1. a tracked exec lands in history with exit + snippet ------------
    // The command prints a line (the snippet captures it) and writes the
    // marker file (the replay leg verifies the re-run actually executed).
    var cmd_buf: [256]u8 = undefined;
    const cmd1 = try std.fmt.bufPrint(&cmd_buf, "echo history-one; echo history-one > {s}", .{marker_one});
    _ = try trackedExec(&rig, cmd1);

    his = try historyEntries(&rig, 1);
    var first: ?HistoryEntryShape = null;
    for (his.?.value.result.entries) |e| {
        if (std.mem.eql(u8, e.kind, "exec") and std.mem.indexOf(u8, e.command, "echo history-one") != null) {
            first = e;
            break;
        }
    }
    const first_entry = first orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("exec", first_entry.kind);
    try std.testing.expectEqual(@as(?i32, 0), first_entry.exit);
    try std.testing.expect(first_entry.duration_ms != null and first_entry.duration_ms.? >= 0);
    try std.testing.expect(std.mem.indexOf(u8, first_entry.output_snippet, "history-one") != null);
    try std.testing.expect(!first_entry.redacted);

    // --- 2. a failing exec records its exit code ---------------------------
    _ = try trackedExec(&rig, "false");
    if (his) |*p| p.deinit();
    his = null;
    his = try historyEntries(&rig, 2);
    var failed: ?HistoryEntryShape = null;
    for (his.?.value.result.entries) |e| {
        if (std.mem.eql(u8, e.command, "false")) {
            failed = e;
            break;
        }
    }
    try std.testing.expectEqual(@as(?i32, 1), (failed orelse return error.TestUnexpectedResult).exit);

    // --- 3. a pattern-visible secret is masked at write time ---------------
    var secret_cmd_buf: [512]u8 = undefined;
    const secret_cmd = try std.fmt.bufPrint(&secret_cmd_buf, "export PASSWORD={s}; echo secret-ran > {s}", .{ secret_value, marker_two });
    _ = try trackedExec(&rig, secret_cmd);
    if (his) |*p| p.deinit();
    his = null;
    his = try historyEntries(&rig, 3);
    var masked: ?HistoryEntryShape = null;
    for (his.?.value.result.entries) |e| {
        if (std.mem.indexOf(u8, e.command, "PASSWORD=") != null) {
            masked = e;
            break;
        }
    }
    const masked_entry = masked orelse return error.TestUnexpectedResult;
    try std.testing.expect(masked_entry.redacted);
    try std.testing.expect(std.mem.indexOf(u8, masked_entry.command, secret_value) == null);
    try std.testing.expect(std.mem.indexOf(u8, masked_entry.command, "\u{2022}") != null);

    // The secret never reaches the journal on disk, and the exec audit row
    // is redacted the same way (spec 15 §8).
    const hist_content = try std.Io.Dir.cwd().readFileAlloc(io, rig.history_store.path, std.testing.allocator, .limited(512 * 1024));
    defer std.testing.allocator.free(hist_content);
    try std.testing.expect(std.mem.indexOf(u8, hist_content, secret_value) == null);
    const audit_content = try std.Io.Dir.cwd().readFileAlloc(io, rig.audit_store.path, std.testing.allocator, .limited(512 * 1024));
    defer std.testing.allocator.free(audit_content);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, secret_value) == null);

    // --- 4. a script run with a secret variable records the masked text ----
    const script_req =
        \\{"id":"s1","command":"oars.scripts.save","payload":{"script":{"id":"sc-secret","name":"secret","body":"echo {{pw}}"}}}
    ;
    const script_resp = rig.dispatch(script_req);
    try std.testing.expect(std.mem.indexOf(u8, script_resp, "\"ok\":true") != null);
    var run_buf: [512]u8 = undefined;
    const run_req = try std.fmt.bufPrint(&run_buf, "{{\"id\":\"s2\",\"command\":\"oars.scripts.run\",\"payload\":{{\"server_id\":\"{s}\",\"script_id\":\"sc-secret\",\"vars\":{{\"pw\":{{\"value\":\"{s}\",\"secret\":true}}}}}}}}", .{ server_id, script_secret });
    var run_parsed = try dispatchParsed(&rig, ExecResp, run_req);
    defer run_parsed.deinit();
    try std.testing.expect(run_parsed.value.result.ok);
    try drainChannel(&rig, run_parsed.value.result.channel);

    if (his) |*p| p.deinit();
    his = null;
    his = try historyEntries(&rig, 4);
    var script_entry: ?HistoryEntryShape = null;
    for (his.?.value.result.entries) |e| {
        if (std.mem.eql(u8, e.kind, "script")) {
            script_entry = e;
            break;
        }
    }
    const script_entry_v = script_entry orelse return error.TestUnexpectedResult;
    try std.testing.expect(script_entry_v.redacted);
    try std.testing.expect(std.mem.indexOf(u8, script_entry_v.command, script_secret) == null);
    try std.testing.expect(std.mem.indexOf(u8, script_entry_v.command, "***") != null);
    const hist_content2 = try std.Io.Dir.cwd().readFileAlloc(io, rig.history_store.path, std.testing.allocator, .limited(512 * 1024));
    defer std.testing.allocator.free(hist_content2);
    try std.testing.expect(std.mem.indexOf(u8, hist_content2, script_secret) == null);

    // --- 5. replay: a clean entry re-runs (chainable); redacted is refused --
    // Resolve the clean entry's id from the live list (ids shift on
    // operation updates; never hardcode them).
    var replay_id: []const u8 = "";
    for (his.?.value.result.entries) |e| {
        if (std.mem.eql(u8, e.kind, "exec") and std.mem.indexOf(u8, e.command, "echo history-one") != null) {
            replay_id = e.id;
            break;
        }
    }
    try std.testing.expect(replay_id.len > 0);
    var replay_buf: [256]u8 = undefined;
    const replay_req = try std.fmt.bufPrint(&replay_buf, "{{\"id\":\"r1\",\"command\":\"oars.history.replay\",\"payload\":{{\"entry_id\":\"{s}\"}}}}", .{replay_id});
    var replay_parsed = try dispatchParsed(&rig, ExecResp, replay_req);
    defer replay_parsed.deinit();
    try std.testing.expect(replay_parsed.value.result.ok);
    try drainChannel(&rig, replay_parsed.value.result.channel);

    // The re-run actually executed (the marker file exists again) and the
    // replay itself produced a fresh, chainable history entry.
    const marker = try execOut(&rig.manager, server_id, "cat " ++ marker_one);
    defer std.testing.allocator.free(marker);
    try std.testing.expect(std.mem.indexOf(u8, marker, "history-one") != null);
    if (his) |*p| p.deinit();
    his = null;
    his = try historyEntries(&rig, 5);
    var chained: usize = 0;
    for (his.?.value.result.entries) |e| {
        if (std.mem.eql(u8, e.kind, "exec") and std.mem.indexOf(u8, e.command, "echo history-one") != null) chained += 1;
    }
    try std.testing.expect(chained >= 2); // original + replay

    // Redacted entries refuse to replay (the marker must never be executed).
    // Resolve the id from the live parse — earlier parses were freed.
    var masked_id: []const u8 = "";
    for (his.?.value.result.entries) |e| {
        if (std.mem.indexOf(u8, e.command, "PASSWORD=") != null) {
            masked_id = e.id;
            break;
        }
    }
    try std.testing.expect(masked_id.len > 0);
    var red_replay_buf: [256]u8 = undefined;
    const red_replay_req = try std.fmt.bufPrint(&red_replay_buf, "{{\"id\":\"r2\",\"command\":\"oars.history.replay\",\"payload\":{{\"entry_id\":\"{s}\"}}}}", .{masked_id});
    const red_replay_resp = rig.dispatch(red_replay_req);
    try std.testing.expect(std.mem.indexOf(u8, red_replay_resp, "redacted secrets") != null);

    // --- 6. audit list + type-to-confirm clear ------------------------------
    var audit_parsed: ?std.json.Parsed(AuditListResp) = null;
    defer if (audit_parsed) |*p| p.deinit();
    audit_parsed = try dispatchParsed(&rig, AuditListResp, "{\"id\":\"a1\",\"command\":\"oars.audit.list\",\"payload\":{}}");
    try std.testing.expect(audit_parsed.?.value.result.entries.len > 0);
    var saw_exec = false;
    for (audit_parsed.?.value.result.entries) |e| {
        if (std.mem.eql(u8, e.type, "ssh.exec")) saw_exec = true;
    }
    try std.testing.expect(saw_exec); // every executed command is audited

    const wrong = rig.dispatch("{\"id\":\"a2\",\"command\":\"oars.audit.clear\",\"payload\":{\"confirm\":\"nope\"}}");
    try std.testing.expect(std.mem.indexOf(u8, wrong, "type CLEAR") != null);
    const cleared = rig.dispatch("{\"id\":\"a3\",\"command\":\"oars.audit.clear\",\"payload\":{\"confirm\":\"CLEAR\"}}");
    try std.testing.expect(std.mem.indexOf(u8, cleared, "\"ok\":true") != null);
    if (audit_parsed) |*p| p.deinit();
    audit_parsed = null;
    audit_parsed = try dispatchParsed(&rig, AuditListResp, "{\"id\":\"a4\",\"command\":\"oars.audit.list\",\"payload\":{}}");
    try std.testing.expectEqual(@as(usize, 0), audit_parsed.?.value.result.entries.len);

    // --- cleanup ------------------------------------------------------------
    try execWait(&rig.manager, server_id, clean, 0, "");
}
