//! Spec 10 integration coverage (container): the full backup pipeline
//! against a real S3-compatible store. One session to the dev sshd
//! container; rclone runs inside it (part of the dev image) and writes to
//! the oars-dev-minio MinIO container on the shared oars-dev-net network
//! (scripts/dev-sshd.sh). Imported from integration.zig so `zig build
//! test` picks it up.
//!
//! Coverage: job save over a live session, the capability test
//! (list/write/read/delete + sync delete authority on one sentinel), a
//! manual sync run polled to completion, an incremental second run
//! (no-changes detection), a third run after a source edit (incremental
//! copy), run history, and object-landing verification through a
//! host-side rclone lsf. Skipped unless OARS_TEST_SSH_* and
//! OARS_TEST_MINIO_* are set.
//!
//! Idempotency: the bucket and source dir are emptied/recreated each run;
//! the run temp config is deleted by the run finalize; history lives in a
//! fresh temp store per rig. The container's own key material is never
//! touched.

const std = @import("std");
const servers = @import("servers.zig");
const rig_mod = @import("integration.zig");

const TestRig = rig_mod.TestRig;
const testSleep = rig_mod.testSleep;
const execWait = rig_mod.execWait;
const execOut = rig_mod.execOut;
const waitForStatus = rig_mod.waitForStatus;

const server_id = "itest-bk-1";
const bucket = "oars-itest-bucket";
const src_dir = "/srv/bk-src";

const RunResp = struct {
    result: struct {
        ok: bool = false,
        run_id: []const u8 = "",
    },
};

const PollResp = struct {
    result: struct {
        ok: bool = false,
        status: []const u8 = "",
        bytes_done: u64 = 0,
        bytes_total: u64 = 0,
        files_done: u64 = 0,
        files_total: u64 = 0,
        @"error": []const u8 = "",
    },
};

const TestResp = struct {
    result: struct {
        ok: bool = false,
        checks: struct {
            list: bool = false,
            write: bool = false,
            read: bool = false,
            delete: bool = false,
        } = .{},
        @"error": []const u8 = "",
    },
};

const HistoryResp = struct {
    result: struct {
        ok: bool = false,
        runs: []const struct {
            id: []const u8 = "",
            job_id: []const u8 = "",
            status: []const u8 = "",
            files_done: u64 = 0,
            bytes_done: u64 = 0,
        } = &.{},
    },
};

/// Dispatches `oars.backup.run` for the job, then polls until the run is
/// terminal. Returns the parsed final poll (caller deinits).
fn runAndWait(rig: *TestRig, job_id: []const u8, access: []const u8, secret: []const u8, timeout_ns: i128) !std.json.Parsed(PollResp) {
    var run_buf: [2048]u8 = undefined;
    const run_req = try std.fmt.bufPrint(&run_buf, "{{\"id\":\"r\",\"command\":\"oars.backup.run\",\"payload\":{{\"server_id\":\"{s}\",\"job_id\":\"{s}\",\"credentials\":{{\"access_key\":\"{s}\",\"secret_key\":\"{s}\"}}}}}}", .{ server_id, job_id, access, secret });
    const run_resp = rig.dispatch(run_req);
    var run_parsed = try std.json.parseFromSlice(RunResp, std.testing.allocator, run_resp, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer run_parsed.deinit();
    if (!run_parsed.value.result.ok) return error.TestUnexpectedResult;
    const run_id = run_parsed.value.result.run_id;

    var poll_buf: [256]u8 = undefined;
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + timeout_ns;
    while (true) {
        const poll_req = try std.fmt.bufPrint(&poll_buf, "{{\"id\":\"p\",\"command\":\"oars.backup.poll\",\"payload\":{{\"run_id\":\"{s}\"}}}}", .{run_id});
        const poll_resp = rig.dispatch(poll_req);
        var parsed = try std.json.parseFromSlice(PollResp, std.testing.allocator, poll_resp, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        });
        if (!std.mem.eql(u8, parsed.value.result.status, "running")) return parsed;
        parsed.deinit();
        if (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds >= deadline) return error.TestUnexpectedResult;
        testSleep(100);
    }
}

test "integration: backup job save, capability test, manual run, poll, history" {
    const env = rig_mod.TestEnv.load();
    if (!env.active or env.minio_endpoint.len == 0) return; // env-gated

    var rig: TestRig = undefined;
    try rig.init("backup");
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
    const clean = try std.fmt.bufPrint(&clean_buf, "rm -rf {s} /tmp/oars-bk-* /root/.config/oars /root/.local/state/oars/backups && mkdir -p {s} && printf 'alpha\\n' > {s}/a.txt && printf 'beta\\n' > {s}/b.txt", .{ src_dir, src_dir, src_dir, src_dir });
    try execWait(&rig.manager, server_id, clean, 0, "");
    // rclone is part of the dev image (spec 10 install leg); assert it.
    try execWait(&rig.manager, server_id, "command -v rclone >/dev/null", 0, "");

    // Create the bucket through the job's exact remote shape (provider
    // Minio + endpoint) and empty it — the MinIO volume persists between
    // runs. The setup config stays in the container for the landing check.
    var setup_cfg_buf: [2048]u8 = undefined;
    const setup_cfg = try std.fmt.bufPrint(&setup_cfg_buf, "printf '[oars-itest]\\ntype = s3\\nprovider = Minio\\naccess_key_id = {s}\\nsecret_access_key = {s}\\nendpoint = {s}\\n' > /tmp/oars-bk-setup.conf && rclone mkdir oars-itest:{s} --config /tmp/oars-bk-setup.conf && rclone delete oars-itest:{s} --config /tmp/oars-bk-setup.conf", .{ env.minio_access, env.minio_secret, env.minio_endpoint, bucket, bucket });
    try execWait(&rig.manager, server_id, setup_cfg, 0, "");

    // --- save the job over the live session --------------------------------
    // Assembled in parts: only the body has format directives, so the
    // brace escaping stays verifiable.
    var save_buf: [4096]u8 = undefined;
    const save_head = "{\"id\":\"1\",\"command\":\"oars.backup.jobs.save\",\"payload\":{\"job\":{";
    const save_tail = "}}}"; // close job, close payload, close envelope
    var save_len = save_head.len;
    @memcpy(save_buf[0..save_len], save_head);
    const save_body = std.fmt.bufPrint(save_buf[save_len .. save_buf.len - save_tail.len], "\"server_id\":\"{s}\",\"name\":\"minio-sync\",\"source_path\":\"{s}\",\"destination\":{{\"type\":\"s3\",\"provider\":\"minio\",\"bucket\":\"{s}\",\"endpoint\":\"{s}\"}},\"transfer\":\"sync\",\"schedule\":{{\"mode\":\"manual\",\"enabled\":false}}", .{ server_id, src_dir, bucket, env.minio_endpoint }) catch return error.TestUnexpectedResult;
    save_len += save_body.len;
    @memcpy(save_buf[save_len .. save_len + save_tail.len], save_tail);
    save_len += save_tail.len;
    const save_req = save_buf[0..save_len];
    const saved = rig.dispatch(save_req);
    try std.testing.expect(std.mem.indexOf(u8, saved, "\"ok\":true") != null);
    const id_start = std.mem.indexOf(u8, saved, "\"id\":\"bk-") orelse return error.TestUnexpectedResult;
    var id_buf: [64]u8 = undefined;
    var id_len: usize = 0;
    for (saved[id_start + 6 ..]) |ch| {
        if (ch == '\"') break;
        if (id_len >= id_buf.len) return error.TestUnexpectedResult;
        id_buf[id_len] = ch;
        id_len += 1;
    }
    const job_id = id_buf[0..id_len];

    // --- capability test (spec 10 §5) ---------------------------------------
    var test_buf: [4096]u8 = undefined;
    const test_req = try std.fmt.bufPrint(&test_buf, "{{\"id\":\"2\",\"command\":\"oars.backup.test\",\"payload\":{{\"job\":{{\"server_id\":\"{s}\",\"name\":\"minio-sync\",\"source_path\":\"{s}\",\"destination\":{{\"type\":\"s3\",\"provider\":\"minio\",\"bucket\":\"{s}\",\"endpoint\":\"{s}\"}},\"transfer\":\"sync\"}},\"credentials\":{{\"access_key\":\"{s}\",\"secret_key\":\"{s}\"}}}}}}", .{ server_id, src_dir, bucket, env.minio_endpoint, env.minio_access, env.minio_secret });
    const test_resp = rig.dispatch(test_req);
    var test_parsed = try std.json.parseFromSlice(TestResp, std.testing.allocator, test_resp, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer test_parsed.deinit();
    try std.testing.expect(test_parsed.value.result.ok);
    try std.testing.expect(test_parsed.value.result.checks.list);
    try std.testing.expect(test_parsed.value.result.checks.write);
    try std.testing.expect(test_parsed.value.result.checks.read);
    try std.testing.expect(test_parsed.value.result.checks.delete); // sync jobs prove delete authority

    // --- run 1: full sync of two files --------------------------------------
    var run1 = try runAndWait(&rig, job_id, env.minio_access, env.minio_secret, 90 * std.time.ns_per_s);
    defer run1.deinit();
    try std.testing.expect(run1.value.result.ok);
    try std.testing.expectEqualStrings("success", run1.value.result.status);
    try std.testing.expectEqual(@as(u64, 2), run1.value.result.files_done);
    try std.testing.expect(run1.value.result.bytes_done > 0);

    // --- run 2: unchanged source → no_changes (exit 0, zero transfers) -----
    var run2 = try runAndWait(&rig, job_id, env.minio_access, env.minio_secret, 90 * std.time.ns_per_s);
    defer run2.deinit();
    try std.testing.expect(run2.value.result.ok);
    try std.testing.expectEqualStrings("no_changes", run2.value.result.status);
    try std.testing.expectEqual(@as(u64, 0), run2.value.result.files_done);

    // --- run 3: one new file → incremental copy ------------------------------
    var run3_cmd_buf: [256]u8 = undefined;
    const run3_cmd = try std.fmt.bufPrint(&run3_cmd_buf, "printf 'gamma\\n' > {s}/c.txt", .{src_dir});
    try execWait(&rig.manager, server_id, run3_cmd, 0, "");
    var run3 = try runAndWait(&rig, job_id, env.minio_access, env.minio_secret, 90 * std.time.ns_per_s);
    defer run3.deinit();
    try std.testing.expect(run3.value.result.ok);
    try std.testing.expectEqualStrings("success", run3.value.result.status);
    try std.testing.expectEqual(@as(u64, 1), run3.value.result.files_done);

    // --- history: newest first, all three runs, no_changes kept -------------
    var hist_buf: [256]u8 = undefined;
    const hist_req = try std.fmt.bufPrint(&hist_buf, "{{\"id\":\"5\",\"command\":\"oars.backup.history\",\"payload\":{{\"server_id\":\"{s}\",\"job_id\":\"{s}\",\"limit\":10}}}}", .{ server_id, job_id });
    const hist_resp = rig.dispatch(hist_req);
    var hist_parsed = try std.json.parseFromSlice(HistoryResp, std.testing.allocator, hist_resp, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer hist_parsed.deinit();
    try std.testing.expect(hist_parsed.value.result.ok);
    try std.testing.expectEqual(@as(usize, 3), hist_parsed.value.result.runs.len);
    try std.testing.expectEqualStrings("success", hist_parsed.value.result.runs[0].status);
    try std.testing.expectEqualStrings("no_changes", hist_parsed.value.result.runs[1].status);
    try std.testing.expectEqualStrings("success", hist_parsed.value.result.runs[2].status);

    // --- object landing: the bucket holds every file, no more ----------------
    var ls_buf: [512]u8 = undefined;
    const ls_cmd = try std.fmt.bufPrint(&ls_buf, "rclone lsf oars-itest:{s} --config /tmp/oars-bk-setup.conf", .{bucket});
    const ls_out = try execOut(&rig.manager, server_id, ls_cmd);
    defer std.testing.allocator.free(ls_out);
    try std.testing.expect(std.mem.indexOf(u8, ls_out, "a.txt") != null);
    try std.testing.expect(std.mem.indexOf(u8, ls_out, "b.txt") != null);
    try std.testing.expect(std.mem.indexOf(u8, ls_out, "c.txt") != null);
    try std.testing.expect(std.mem.indexOf(u8, ls_out, "oars-sentinel-") == null); // capability cleanup

    // --- cleanup --------------------------------------------------------------
    try execWait(&rig.manager, server_id, "rm -rf {s} /tmp/oars-bk-* /root/.config/oars /root/.local/state/oars/backups", 0, "");
}
