//! Spec 10 integration coverage against the existing Alpine sshd + MinIO
//! harness. The test uses the shipping plan/admit/poll contracts and never
//! places object-store credentials in an exec command.

const std = @import("std");
const backup = @import("backup.zig");
const servers = @import("servers.zig");
const sessions = @import("sessions.zig");
const rig_mod = @import("integration.zig");

const TestRig = rig_mod.TestRig;
const testSleep = rig_mod.testSleep;
const execWait = rig_mod.execWait;
const waitForStatus = rig_mod.waitForStatus;

const server_id = "itest-bk-1";
const bucket = "oars-itest-bucket";
const src_dir = "/srv/bk-src";

const ErrorShape = struct {
    code: []const u8 = "",
    @"error": []const u8 = "",
};

const RefreshAdmission = struct { result: struct { ok: bool = false, operation_id: []const u8 = "" } };
const PlanResponse = struct {
    result: struct {
        ok: bool = false,
        plan_id: []const u8 = "",
        job: struct {
            id: []const u8 = "",
            revision: u64 = 0,
        } = .{},
    },
};
const TestPlanResponse = struct { result: struct { ok: bool = false, test_plan_id: []const u8 = "", remote_object: []const u8 = "" } };
const OperationAdmission = struct { result: struct { ok: bool = false, operation_id: []const u8 = "", job_id: []const u8 = "" } };
const OperationPoll = struct {
    result: struct {
        ok: bool = false,
        state: []const u8 = "",
        result: ?struct {
            checks: ?struct {
                list: []const u8 = "",
                write: []const u8 = "",
                read: []const u8 = "",
                delete: []const u8 = "",
                cleanup_verify: []const u8 = "",
            } = null,
            capability_proof: ?struct {
                id: []const u8 = "",
            } = null,
            imported: usize = 0,
            warnings: usize = 0,
        } = null,
        @"error": ?ErrorShape = null,
    },
};
const RunAdmission = struct { result: struct { ok: bool = false, run_id: []const u8 = "" } };
const RunPoll = struct {
    result: struct {
        ok: bool = false,
        run_id: []const u8 = "",
        status: []const u8 = "",
        files_done: u64 = 0,
        bytes_done: u64 = 0,
        cleanup_state: []const u8 = "",
        @"error": ?ErrorShape = null,
    },
};
const HistoryResponse = struct {
    result: struct {
        ok: bool = false,
        runs: []const struct {
            run_id: []const u8 = "",
            status: []const u8 = "",
            files_done: u64 = 0,
        } = &.{},
    },
};
const DeletePlanResponse = struct { result: struct { ok: bool = false, plan_id: []const u8 = "", job_name: []const u8 = "" } };

fn parseResponse(comptime T: type, bytes: []const u8) !std.json.Parsed(T) {
    return std.json.parseFromSlice(T, std.testing.allocator, bytes, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
}

fn waitChannel(manager: *sessions.Manager, channel: u32, timeout_ns: i128) ![]u8 {
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + timeout_ns;
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(std.testing.allocator);
    var cursor: u64 = 0;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        const polls = try manager.pollChannels(server_id, &.{.{ .id = channel, .pos = cursor }}, false, 64 * 1024, 64 * 1024);
        var done = false;
        var exit: ?i32 = null;
        for (polls) |*poll| {
            if (poll.id == channel) {
                try output.appendSlice(std.testing.allocator, poll.data);
                cursor = poll.cursor;
                done = poll.eof;
                exit = poll.exit_status;
            }
            poll.deinit(std.testing.allocator);
        }
        std.testing.allocator.free(polls);
        if (done and exit != null) {
            if (exit.? != 0) {
                std.debug.print("backup integration exec failed exit={d}: {s}\n", .{ exit.?, output.items });
                return error.TestUnexpectedResult;
            }
            return output.toOwnedSlice(std.testing.allocator);
        }
        testSleep(25);
    }
    return error.TestUnexpectedResult;
}

fn execInput(manager: *sessions.Manager, command: []const u8, input: []const u8) ![]u8 {
    const channel = try manager.execWithInput(server_id, command, input);
    return waitChannel(manager, channel, 45 * std.time.ns_per_s);
}

fn minioConfig(allocator: std.mem.Allocator, endpoint: []const u8, access: []const u8, secret: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "[oars-itest]\ntype = s3\nprovider = Minio\naccess_key_id = {s}\nsecret_access_key = {s}\nendpoint = {s}\n",
        .{ access, secret, endpoint },
    );
}

fn waitOperation(rig: *TestRig, operation_id: []const u8, timeout_ns: i128) !std.json.Parsed(OperationPoll) {
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + timeout_ns;
    var request_buf: [512]u8 = undefined;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        const request = try std.fmt.bufPrint(&request_buf, "{{\"id\":\"poll-op\",\"command\":\"oars.backup.operationPoll\",\"payload\":{{\"operation_id\":\"{s}\"}}}}", .{operation_id});
        var parsed = try parseResponse(OperationPoll, rig.dispatch(request));
        if (std.mem.eql(u8, parsed.value.result.state, "done") or std.mem.eql(u8, parsed.value.result.state, "partial") or std.mem.eql(u8, parsed.value.result.state, "failed") or std.mem.eql(u8, parsed.value.result.state, "canceled")) return parsed;
        parsed.deinit();
        testSleep(50);
    }
    return error.TestUnexpectedResult;
}

fn waitRun(rig: *TestRig, run_id: []const u8, timeout_ns: i128) !std.json.Parsed(RunPoll) {
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + timeout_ns;
    var request_buf: [512]u8 = undefined;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        const request = try std.fmt.bufPrint(&request_buf, "{{\"id\":\"poll-run\",\"command\":\"oars.backup.poll\",\"payload\":{{\"run_id\":\"{s}\",\"log_cursor\":0}}}}", .{run_id});
        var parsed = try parseResponse(RunPoll, rig.dispatch(request));
        const status = parsed.value.result.status;
        if (std.mem.eql(u8, status, "success") or std.mem.eql(u8, status, "no_changes") or std.mem.eql(u8, status, "failed") or std.mem.eql(u8, status, "canceled") or std.mem.eql(u8, status, "interrupted") or std.mem.eql(u8, status, "partial")) return parsed;
        parsed.deinit();
        testSleep(50);
    }
    return error.TestUnexpectedResult;
}

fn refresh(rig: *TestRig, suffix: []const u8) !std.json.Parsed(OperationPoll) {
    var request_buf: [512]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buf, "{{\"id\":\"refresh\",\"command\":\"oars.backup.refresh\",\"payload\":{{\"operation_id\":\"refresh-{s}\",\"server_id\":\"{s}\"}}}}", .{ suffix, server_id });
    var admitted = try parseResponse(RefreshAdmission, rig.dispatch(request));
    defer admitted.deinit();
    try std.testing.expect(admitted.value.result.ok);
    return waitOperation(rig, admitted.value.result.operation_id, 45 * std.time.ns_per_s);
}

fn planJobFromSource(rig: *TestRig, endpoint: []const u8, name: []const u8, source: []const u8, prefix: []const u8, transfer: []const u8, schedule_json: []const u8) !std.json.Parsed(PlanResponse) {
    var request_buf: [8192]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &request_buf,
        "{{\"id\":\"plan\",\"command\":\"oars.backup.jobs.plan\",\"payload\":{{\"job\":{{\"server_id\":\"{s}\",\"name\":\"{s}\",\"source_path\":\"{s}\",\"destination\":{{\"type\":\"s3\",\"provider\":\"minio\",\"bucket\":\"{s}\",\"prefix\":\"{s}\",\"endpoint\":\"{s}\",\"region\":\"us-east-1\",\"credential_mode\":\"access_key\",\"storage_class\":\"\"}},\"transfer\":\"{s}\",\"schedule\":{s}}}}}}}",
        .{ server_id, name, source, bucket, prefix, endpoint, transfer, schedule_json },
    );
    return parseResponse(PlanResponse, rig.dispatch(request));
}

fn planJob(rig: *TestRig, endpoint: []const u8, name: []const u8, prefix: []const u8, transfer: []const u8, schedule_json: []const u8) !std.json.Parsed(PlanResponse) {
    return planJobFromSource(rig, endpoint, name, src_dir, prefix, transfer, schedule_json);
}

fn provePlan(rig: *TestRig, plan_id: []const u8, access: []const u8, secret: []const u8, suffix: []const u8) ![]u8 {
    var plan_buf: [512]u8 = undefined;
    const plan_request = try std.fmt.bufPrint(&plan_buf, "{{\"id\":\"test-plan\",\"command\":\"oars.backup.test.plan\",\"payload\":{{\"job_plan_id\":\"{s}\"}}}}", .{plan_id});
    var test_plan = try parseResponse(TestPlanResponse, rig.dispatch(plan_request));
    defer test_plan.deinit();
    try std.testing.expect(test_plan.value.result.ok);

    var test_buf: [2048]u8 = undefined;
    const test_request = try std.fmt.bufPrint(&test_buf, "{{\"id\":\"test\",\"command\":\"oars.backup.test\",\"payload\":{{\"operation_id\":\"test-{s}\",\"test_plan_id\":\"{s}\",\"credentials\":{{\"access_key\":\"{s}\",\"secret_key\":\"{s}\"}}}}}}", .{ suffix, test_plan.value.result.test_plan_id, access, secret });
    const started = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds;
    var admission = try parseResponse(OperationAdmission, rig.dispatch(test_request));
    defer admission.deinit();
    const elapsed = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds - started;
    try std.testing.expect(elapsed < 500 * std.time.ns_per_ms);
    try std.testing.expect(admission.value.result.ok);
    var terminal = try waitOperation(rig, admission.value.result.operation_id, 90 * std.time.ns_per_s);
    defer terminal.deinit();
    try std.testing.expectEqualStrings("done", terminal.value.result.state);
    const result = terminal.value.result.result orelse return error.TestUnexpectedResult;
    const checks = result.checks orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("passed", checks.list);
    try std.testing.expectEqualStrings("passed", checks.write);
    try std.testing.expectEqualStrings("passed", checks.read);
    try std.testing.expectEqualStrings("passed", checks.delete);
    try std.testing.expectEqualStrings("passed", checks.cleanup_verify);
    const proof = result.capability_proof orelse return error.TestUnexpectedResult;
    return std.testing.allocator.dupe(u8, proof.id);
}

fn savePlan(rig: *TestRig, plan_id: []const u8, proof_id: []const u8, access: []const u8, secret: []const u8, scheduled: bool, suffix: []const u8) !void {
    var request_buf: [4096]u8 = undefined;
    const credentials = if (scheduled)
        try std.fmt.bufPrint(request_buf[2048..], ",\"schedule_credentials\":{{\"access_key\":\"{s}\",\"secret_key\":\"{s}\"}}", .{ access, secret })
    else
        "";
    const request = try std.fmt.bufPrint(request_buf[0..2048], "{{\"id\":\"save\",\"command\":\"oars.backup.jobs.save\",\"payload\":{{\"operation_id\":\"save-{s}\",\"plan_id\":\"{s}\",\"capability_proof_id\":\"{s}\",\"approved_remote_secret\":{s}{s}}}}}", .{ suffix, plan_id, proof_id, if (scheduled) "true" else "false", credentials });
    var admitted = try parseResponse(OperationAdmission, rig.dispatch(request));
    defer admitted.deinit();
    try std.testing.expect(admitted.value.result.ok);
    var terminal = try waitOperation(rig, admitted.value.result.operation_id, 60 * std.time.ns_per_s);
    defer terminal.deinit();
    try std.testing.expectEqualStrings("done", terminal.value.result.state);
}

fn runJob(rig: *TestRig, job_id: []const u8, job_name: ?[]const u8, operation_id: []const u8, access: []const u8, secret: []const u8) !std.json.Parsed(RunPoll) {
    var request_buf: [4096]u8 = undefined;
    const confirmation = if (job_name) |name|
        try std.fmt.bufPrint(request_buf[3072..], ",\"confirm_job_name\":\"{s}\"", .{name})
    else
        "";
    const request = try std.fmt.bufPrint(request_buf[0..3072], "{{\"id\":\"run\",\"command\":\"oars.backup.run\",\"payload\":{{\"operation_id\":\"{s}\",\"server_id\":\"{s}\",\"job_id\":\"{s}\",\"expected_revision\":1,\"credentials\":{{\"access_key\":\"{s}\",\"secret_key\":\"{s}\"}}{s}}}}}", .{ operation_id, server_id, job_id, access, secret, confirmation });
    const started = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds;
    var admission = try parseResponse(RunAdmission, rig.dispatch(request));
    defer admission.deinit();
    try std.testing.expect(std.Io.Timestamp.now(std.testing.io, .real).nanoseconds - started < 500 * std.time.ns_per_ms);
    try std.testing.expect(admission.value.result.ok);
    return waitRun(rig, admission.value.result.run_id, 120 * std.time.ns_per_s);
}

fn remoteObjectExists(manager: *sessions.Manager, config: []const u8, object: []const u8) !bool {
    const slash = std.mem.lastIndexOfScalar(u8, object, '/') orelse return error.TestUnexpectedResult;
    const parent = object[0..slash];
    const name = object[slash + 1 ..];
    var command_buf: [1024]u8 = undefined;
    const command = try std.fmt.bufPrint(&command_buf, "umask 077; dd of=/tmp/.oars-itest-check.conf bs=4096 status=none && rclone lsf 'oars-itest:{s}' --files-only --config /tmp/.oars-itest-check.conf 2>/dev/null | grep -Fqx '{s}'; RC=$?; rm -f /tmp/.oars-itest-check.conf; printf '%s' \"$RC\"", .{ parent, name });
    const output = try execInput(manager, command, config);
    defer std.testing.allocator.free(output);
    return std.mem.eql(u8, std.mem.trim(u8, output, " \t\r\n"), "0");
}

fn putRemoteObject(manager: *sessions.Manager, config: []const u8, object: []const u8) !void {
    var command_buf: [1536]u8 = undefined;
    const command = try std.fmt.bufPrint(&command_buf, "umask 077; dd of=/tmp/.oars-itest-put.conf bs=4096 status=none && printf 'remote-only\\n' | rclone rcat 'oars-itest:{s}' --config /tmp/.oars-itest-put.conf; RC=$?; rm -f /tmp/.oars-itest-put.conf; exit $RC", .{object});
    const output = try execInput(manager, command, config);
    std.testing.allocator.free(output);
}

test "integration: real remote backup test, manual run, disconnected cron import" {
    const env = rig_mod.TestEnv.load();
    const has_required_config = env.active and
        env.host.len != 0 and
        env.password.len != 0 and
        env.minio_endpoint.len != 0 and
        env.minio_access.len != 0 and
        env.minio_secret.len != 0;
    if (!has_required_config) return error.SkipZigTest;

    var rig: TestRig = undefined;
    try rig.init("backup");
    defer rig.deinit();
    const io = std.testing.io;
    const server = servers.Server{ .id = server_id, .name = "dev-sshd", .host = env.host, .port = env.port, .user = env.user, .auth_method = .password };
    try rig.store.upsert(io, server);
    _ = try rig.manager.connect(server, env.password, null);
    try waitForStatus(&rig.manager, server_id, .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust(server_id, true);
    try waitForStatus(&rig.manager, server_id, .ready, 20 * std.time.ns_per_s);

    try execWait(&rig.manager, server_id, "crontab -r 2>/dev/null || true; rm -rf /srv/bk-src /root/.config/oars /root/.local/state/oars/backups && mkdir -p /srv/bk-src && printf 'alpha\\n' > /srv/bk-src/a.txt && printf 'beta\\n' > /srv/bk-src/b.txt", 0, "");
    try execWait(&rig.manager, server_id, "command -v rclone >/dev/null && command -v crontab >/dev/null && pgrep -x crond >/dev/null", 0, "");
    const setup_config = try minioConfig(std.testing.allocator, env.minio_endpoint, env.minio_access, env.minio_secret);
    defer {
        std.crypto.secureZero(u8, setup_config);
        std.testing.allocator.free(setup_config);
    }
    const setup_output = try execInput(&rig.manager, "umask 077; dd of=/tmp/.oars-itest.conf bs=4096 status=none && rclone mkdir oars-itest:oars-itest-bucket --config /tmp/.oars-itest.conf && rclone delete oars-itest:oars-itest-bucket --config /tmp/.oars-itest.conf; RC=$?; rm -f /tmp/.oars-itest.conf; exit $RC", setup_config);
    std.testing.allocator.free(setup_output);

    var refreshed = try refresh(&rig, "initial");
    defer refreshed.deinit();
    try std.testing.expectEqualStrings("done", refreshed.value.result.state);

    var manual_plan = try planJob(&rig, env.minio_endpoint, "minio-sync", "manual", "sync", "{\"mode\":\"manual\",\"enabled\":false}");
    defer manual_plan.deinit();
    try std.testing.expect(manual_plan.value.result.ok);
    const manual_proof = try provePlan(&rig, manual_plan.value.result.plan_id, env.minio_access, env.minio_secret, "manual");
    defer std.testing.allocator.free(manual_proof);
    try savePlan(&rig, manual_plan.value.result.plan_id, manual_proof, env.minio_access, env.minio_secret, false, "manual");

    var run_terminal = try runJob(&rig, manual_plan.value.result.job.id, "minio-sync", "run-op-1", env.minio_access, env.minio_secret);
    defer run_terminal.deinit();
    if (!std.mem.eql(u8, "success", run_terminal.value.result.status)) {
        if (run_terminal.value.result.@"error") |failure| {
            std.debug.print("manual backup terminal status={s} cleanup={s} error={s}: {s}\n", .{ run_terminal.value.result.status, run_terminal.value.result.cleanup_state, failure.code, failure.@"error" });
        } else {
            std.debug.print("manual backup terminal status={s} cleanup={s}\n", .{ run_terminal.value.result.status, run_terminal.value.result.cleanup_state });
        }
    }
    try std.testing.expectEqualStrings("success", run_terminal.value.result.status);
    try std.testing.expect(run_terminal.value.result.files_done >= 2);
    try std.testing.expectEqualStrings("complete", run_terminal.value.result.cleanup_state);
    try std.testing.expect(try remoteObjectExists(&rig.manager, setup_config, bucket ++ "/manual/a.txt"));
    try std.testing.expect(try remoteObjectExists(&rig.manager, setup_config, bucket ++ "/manual/b.txt"));

    var unchanged = try runJob(&rig, manual_plan.value.result.job.id, "minio-sync", "run-op-unchanged", env.minio_access, env.minio_secret);
    defer unchanged.deinit();
    try std.testing.expectEqualStrings("no_changes", unchanged.value.result.status);

    try execWait(&rig.manager, server_id, "printf 'alpha-updated\\n' > /srv/bk-src/a.txt && printf 'gamma\\n' > /srv/bk-src/c.txt", 0, "");
    var incremental = try runJob(&rig, manual_plan.value.result.job.id, "minio-sync", "run-op-incremental", env.minio_access, env.minio_secret);
    defer incremental.deinit();
    try std.testing.expectEqualStrings("success", incremental.value.result.status);
    try std.testing.expect(incremental.value.result.files_done >= 2);

    var copy_plan = try planJob(&rig, env.minio_endpoint, "minio-copy", "manual", "copy", "{\"mode\":\"manual\",\"enabled\":false}");
    defer copy_plan.deinit();
    try std.testing.expect(copy_plan.value.result.ok);
    const copy_proof = try provePlan(&rig, copy_plan.value.result.plan_id, env.minio_access, env.minio_secret, "copy");
    defer std.testing.allocator.free(copy_proof);
    try savePlan(&rig, copy_plan.value.result.plan_id, copy_proof, env.minio_access, env.minio_secret, false, "copy");

    try putRemoteObject(&rig.manager, setup_config, bucket ++ "/manual/destination-only.txt");
    var copied = try runJob(&rig, copy_plan.value.result.job.id, null, "run-op-copy", env.minio_access, env.minio_secret);
    defer copied.deinit();
    try std.testing.expect(std.mem.eql(u8, "success", copied.value.result.status) or std.mem.eql(u8, "no_changes", copied.value.result.status));
    try std.testing.expect(try remoteObjectExists(&rig.manager, setup_config, bucket ++ "/manual/destination-only.txt"));

    var missing_confirmation_buf: [2048]u8 = undefined;
    const missing_confirmation = try std.fmt.bufPrint(&missing_confirmation_buf, "{{\"id\":\"run-unconfirmed\",\"command\":\"oars.backup.run\",\"payload\":{{\"operation_id\":\"run-op-unconfirmed\",\"server_id\":\"{s}\",\"job_id\":\"{s}\",\"expected_revision\":1,\"credentials\":{{\"access_key\":\"{s}\",\"secret_key\":\"{s}\"}}}}}}", .{ server_id, manual_plan.value.result.job.id, env.minio_access, env.minio_secret });
    const rejected = rig.dispatch(missing_confirmation);
    try std.testing.expect(std.mem.indexOf(u8, rejected, "\"code\":\"invalid_payload\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rejected, "sync requires the exact confirm_job_name") != null);

    var mirrored = try runJob(&rig, manual_plan.value.result.job.id, "minio-sync", "run-op-mirror", env.minio_access, env.minio_secret);
    defer mirrored.deinit();
    try std.testing.expect(std.mem.eql(u8, "success", mirrored.value.result.status) or std.mem.eql(u8, "no_changes", mirrored.value.result.status));
    try std.testing.expect(!try remoteObjectExists(&rig.manager, setup_config, bucket ++ "/manual/destination-only.txt"));

    try execWait(&rig.manager, server_id, "mkdir -p /srv/bk-empty", 0, "");
    var empty_plan = try planJobFromSource(&rig, env.minio_endpoint, "minio-empty", "/srv/bk-empty", "empty", "copy", "{\"mode\":\"manual\",\"enabled\":false}");
    defer empty_plan.deinit();
    try std.testing.expect(empty_plan.value.result.ok);
    const empty_proof = try provePlan(&rig, empty_plan.value.result.plan_id, env.minio_access, env.minio_secret, "empty");
    defer std.testing.allocator.free(empty_proof);
    try savePlan(&rig, empty_plan.value.result.plan_id, empty_proof, env.minio_access, env.minio_secret, false, "empty");
    var empty_run = try runJob(&rig, empty_plan.value.result.job.id, null, "run-op-empty", env.minio_access, env.minio_secret);
    defer empty_run.deinit();
    try std.testing.expectEqualStrings("no_changes", empty_run.value.result.status);

    var missing_plan = try planJobFromSource(&rig, env.minio_endpoint, "minio-missing", "/srv/bk-missing", "missing", "copy", "{\"mode\":\"manual\",\"enabled\":false}");
    defer missing_plan.deinit();
    try std.testing.expect(missing_plan.value.result.ok);
    const missing_proof = try provePlan(&rig, missing_plan.value.result.plan_id, env.minio_access, env.minio_secret, "missing");
    defer std.testing.allocator.free(missing_proof);
    try savePlan(&rig, missing_plan.value.result.plan_id, missing_proof, env.minio_access, env.minio_secret, false, "missing");
    var missing_run = try runJob(&rig, missing_plan.value.result.job.id, null, "run-op-missing", env.minio_access, env.minio_secret);
    defer missing_run.deinit();
    try std.testing.expectEqualStrings("failed", missing_run.value.result.status);
    const missing_error = missing_run.value.result.@"error" orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("source_missing", missing_error.code);

    // Force the active rclone process to ignore TERM so cancellation must use
    // the bounded KILL escalation, then verify the process group is absent.
    try execWait(&rig.manager, server_id, "mkdir -p /usr/local/bin && printf '%s\\n' '#!/bin/sh' 'trap \"\" TERM' 'exec /usr/bin/rclone \"$@\"' > /usr/local/bin/rclone && chmod 755 /usr/local/bin/rclone && test \"$(command -v rclone)\" = /usr/local/bin/rclone", 0, "");
    try execWait(&rig.manager, server_id, "dd if=/dev/zero of=/srv/bk-src/large.bin bs=1048576 count=512 status=none", 0, "");
    var cancel_run_buf: [2048]u8 = undefined;
    const cancel_run_request = try std.fmt.bufPrint(&cancel_run_buf, "{{\"id\":\"run-cancel\",\"command\":\"oars.backup.run\",\"payload\":{{\"operation_id\":\"run-op-cancel\",\"server_id\":\"{s}\",\"job_id\":\"{s}\",\"expected_revision\":1,\"confirm_job_name\":\"minio-sync\",\"credentials\":{{\"access_key\":\"{s}\",\"secret_key\":\"{s}\"}}}}}}", .{ server_id, manual_plan.value.result.job.id, env.minio_access, env.minio_secret });
    var cancel_admitted = try parseResponse(RunAdmission, rig.dispatch(cancel_run_request));
    defer cancel_admitted.deinit();
    try std.testing.expect(cancel_admitted.value.result.ok);
    var running_seen = false;
    var running_poll_buf: [512]u8 = undefined;
    const running_deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 30 * std.time.ns_per_s;
    while (std.Io.Timestamp.now(io, .real).nanoseconds < running_deadline) {
        const running_request = try std.fmt.bufPrint(&running_poll_buf, "{{\"id\":\"poll-cancel\",\"command\":\"oars.backup.poll\",\"payload\":{{\"run_id\":\"{s}\",\"log_cursor\":0}}}}", .{cancel_admitted.value.result.run_id});
        var running_poll = try parseResponse(RunPoll, rig.dispatch(running_request));
        defer running_poll.deinit();
        if (std.mem.eql(u8, running_poll.value.result.status, "running")) {
            running_seen = true;
            break;
        }
        if (std.mem.eql(u8, running_poll.value.result.status, "failed") or std.mem.eql(u8, running_poll.value.result.status, "partial")) return error.TestUnexpectedResult;
        testSleep(25);
    }
    try std.testing.expect(running_seen);
    var cancel_buf: [512]u8 = undefined;
    const cancel_request = try std.fmt.bufPrint(&cancel_buf, "{{\"id\":\"cancel\",\"command\":\"oars.backup.cancel\",\"payload\":{{\"run_id\":\"{s}\"}}}}", .{cancel_admitted.value.result.run_id});
    try std.testing.expect(std.mem.indexOf(u8, rig.dispatch(cancel_request), "\"ok\":true") != null);
    var canceled = try waitRun(&rig, cancel_admitted.value.result.run_id, 60 * std.time.ns_per_s);
    defer canceled.deinit();
    try std.testing.expectEqualStrings("canceled", canceled.value.result.status);
    try std.testing.expectEqualStrings("complete", canceled.value.result.cleanup_state);
    try execWait(&rig.manager, server_id, "rm -f /srv/bk-src/large.bin /usr/local/bin/rclone", 0, "");

    var scheduled_plan = try planJob(&rig, env.minio_endpoint, "minio-cron", "scheduled", "copy", "{\"mode\":\"custom\",\"enabled\":true,\"expr\":\"* * * * *\"}");
    defer scheduled_plan.deinit();
    try std.testing.expect(scheduled_plan.value.result.ok);
    const scheduled_proof = try provePlan(&rig, scheduled_plan.value.result.plan_id, env.minio_access, env.minio_secret, "scheduled");
    defer std.testing.allocator.free(scheduled_proof);
    try savePlan(&rig, scheduled_plan.value.result.plan_id, scheduled_proof, env.minio_access, env.minio_secret, true, "scheduled");

    // Destroy the SSH manager and backup registry for the whole cron window.
    // The scheduled wrapper must complete without any live Oars worker, and
    // import must succeed through a fresh manager, registry, and dispatcher.
    const persisted_jobs_path = rig.backup_registry.jobs.path;
    const persisted_runs_path = rig.backup_registry.history.path;
    rig.backup_registry.deinit();
    rig.manager.deinit();
    testSleep(70_000);
    rig.backup_registry = backup.Registry.init(std.testing.allocator, persisted_jobs_path, persisted_runs_path);
    rig.manager = sessions.Manager.init(std.testing.allocator, io, &rig.store, &rig.audit_store, &rig.history_store, null);
    rig.ctx.manager = &rig.manager;
    rig.ctx.backup = &rig.backup_registry;
    rig.dispatcher = rig.ctx.dispatcher();
    _ = try rig.manager.connect(server, env.password, null);
    try waitForStatus(&rig.manager, server_id, .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust(server_id, true);
    try waitForStatus(&rig.manager, server_id, .ready, 20 * std.time.ns_per_s);
    var imported_refresh = try refresh(&rig, "import-1");
    defer imported_refresh.deinit();
    try std.testing.expectEqualStrings("done", imported_refresh.value.result.state);

    var history_buf: [512]u8 = undefined;
    const history_request = try std.fmt.bufPrint(&history_buf, "{{\"id\":\"history\",\"command\":\"oars.backup.history\",\"payload\":{{\"server_id\":\"{s}\",\"job_id\":\"{s}\",\"limit\":20}}}}", .{ server_id, scheduled_plan.value.result.job.id });
    var history = try parseResponse(HistoryResponse, rig.dispatch(history_request));
    defer history.deinit();
    try std.testing.expect(history.value.result.ok);
    try std.testing.expect(history.value.result.runs.len >= 1);
    const imported_count = history.value.result.runs.len;

    var second_refresh = try refresh(&rig, "import-2");
    defer second_refresh.deinit();
    try std.testing.expectEqualStrings("done", second_refresh.value.result.state);
    var history_again = try parseResponse(HistoryResponse, rig.dispatch(history_request));
    defer history_again.deinit();
    try std.testing.expectEqual(imported_count, history_again.value.result.runs.len);

    var delete_plan_buf: [512]u8 = undefined;
    const delete_plan_request = try std.fmt.bufPrint(&delete_plan_buf, "{{\"id\":\"delete-plan\",\"command\":\"oars.backup.jobs.deletePlan\",\"payload\":{{\"server_id\":\"{s}\",\"job_id\":\"{s}\",\"expected_revision\":1}}}}", .{ server_id, scheduled_plan.value.result.job.id });
    var delete_plan = try parseResponse(DeletePlanResponse, rig.dispatch(delete_plan_request));
    defer delete_plan.deinit();
    try std.testing.expect(delete_plan.value.result.ok);
    var delete_buf: [1024]u8 = undefined;
    const delete_request = try std.fmt.bufPrint(&delete_buf, "{{\"id\":\"delete\",\"command\":\"oars.backup.jobs.delete\",\"payload\":{{\"operation_id\":\"delete-scheduled\",\"plan_id\":\"{s}\",\"confirm_job_name\":\"{s}\"}}}}", .{ delete_plan.value.result.plan_id, delete_plan.value.result.job_name });
    var delete_admitted = try parseResponse(OperationAdmission, rig.dispatch(delete_request));
    defer delete_admitted.deinit();
    try std.testing.expect(delete_admitted.value.result.ok);
    var delete_terminal = try waitOperation(&rig, delete_admitted.value.result.operation_id, 60 * std.time.ns_per_s);
    defer delete_terminal.deinit();
    if (!std.mem.eql(u8, delete_terminal.value.result.state, "done")) {
        if (delete_terminal.value.result.@"error") |failure| {
            std.debug.print("scheduled delete ended {s}: {s}: {s}\n", .{ delete_terminal.value.result.state, failure.code, failure.@"error" });
        }
    }
    try std.testing.expectEqualStrings("done", delete_terminal.value.result.state);

    try execWait(&rig.manager, server_id, "rm -rf /srv/bk-src /srv/bk-empty /root/.config/oars /root/.local/state/oars/backups /tmp/.oars-itest.conf", 0, "");
}
