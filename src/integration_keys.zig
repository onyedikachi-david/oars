//! Spec 08 integration coverage against the asynchronous SSH-management bridge.
//! Imported from integration.zig so `zig build test` picks it up.

const std = @import("std");
const ssh = @import("ssh.zig");
const servers = @import("servers.zig");
const sessions = @import("sessions.zig");
const rig_mod = @import("integration.zig");

const TestRig = rig_mod.TestRig;
const testSleep = rig_mod.testSleep;
const execWait = rig_mod.execWait;
const execOut = rig_mod.execOut;
const waitForStatus = rig_mod.waitForStatus;

const StartResponse = struct {
    result: struct {
        ok: bool,
        snapshot_id: []const u8 = "",
        job_id: []const u8 = "",
        plan_id: []const u8 = "",
        fingerprint: []const u8 = "",
        new_fingerprint: []const u8 = "",
    },
};

const SnapshotSource = struct {
    path: []const u8,
    kind: []const u8,
    status: []const u8,
    file_sha256: ?[]const u8 = null,
    mode: ?u32 = null,
    owner: ?[]const u8 = null,
    @"error": ?[]const u8 = null,
};

const SnapshotKey = struct {
    source_path: []const u8,
    line_index: usize,
    line_hash: []const u8,
    parsed: bool,
    options: []const u8 = "",
    type: []const u8 = "",
    key: []const u8 = "",
    comment: []const u8 = "",
    fingerprint_sha256: []const u8 = "",
    bits: ?u16 = null,
    raw: []const u8 = "",
    @"error": []const u8 = "",
};

const SnapshotRole = struct {
    name: []const u8,
    kind: []const u8,
    home: ?[]const u8 = null,
    shell: ?[]const u8 = null,
    policy_state: []const u8,
    key_fingerprints: []const []const u8 = &.{},
};

const SnapshotDeployKey = struct {
    deploy_key_id: []const u8,
    repository_label: []const u8,
    path: []const u8,
    fingerprint: []const u8,
};

const SnapshotResponse = struct {
    result: struct {
        ok: bool,
        state: []const u8,
        scope: []const u8 = "",
        coverage: []const u8 = "",
        capabilities: struct {
            privilege: []const u8 = "",
            sftp_read_only: bool = false,
        } = .{},
        sources: []const SnapshotSource = &.{},
        keys: []const SnapshotKey = &.{},
        roles: []const SnapshotRole = &.{},
        deploy_keys: []const SnapshotDeployKey = &.{},
        warnings: []const []const u8 = &.{},
    },
};

const JobOutput = struct {
    public_key: []const u8 = "",
    private_path: []const u8 = "",
    fingerprint: []const u8 = "",
    keychain_account: []const u8 = "",
    new_fingerprint: []const u8 = "",
    deploy_key_id: []const u8 = "",
    idempotent: bool = false,
};

const JobResponse = struct {
    result: struct {
        ok: bool,
        state: []const u8,
        steps: []const struct {
            id: []const u8,
            state: []const u8,
            @"error": ?[]const u8 = null,
        } = &.{},
        result: ?JobOutput = null,
    },
};

const Snapshot = struct {
    allocator: std.mem.Allocator,
    id: []u8,
    parsed: std.json.Parsed(SnapshotResponse),

    fn deinit(self: *Snapshot) void {
        self.parsed.deinit();
        self.allocator.free(self.id);
    }
};

pub const GeneratedKey = struct {
    pub const Result = struct {
        ok: bool,
        public_key: []u8,
        private_path: []u8,
        fingerprint: []u8,
        keychain_account: []u8,
    };

    pub const Value = struct {
        result: Result,
    };

    allocator: std.mem.Allocator,
    value: Value,

    pub fn deinit(self: *GeneratedKey) void {
        self.allocator.free(self.value.result.public_key);
        self.allocator.free(self.value.result.private_path);
        self.allocator.free(self.value.result.fingerprint);
        self.allocator.free(self.value.result.keychain_account);
    }
};

fn dispatchParsed(comptime Response: type, rig: *TestRig, command: []const u8, payload: anytype) !std.json.Parsed(Response) {
    var request: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer request.deinit();
    try std.json.Stringify.value(.{
        .id = "keys-itest",
        .command = command,
        .payload = payload,
    }, .{}, &request.writer);
    const response = rig.dispatch(request.writer.buffered());
    return std.json.parseFromSlice(Response, std.testing.allocator, response, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |err| {
        std.debug.print("TEST {s} response could not be parsed: {s}\n", .{ command, response });
        return err;
    };
}

fn startJob(rig: *TestRig, command: []const u8, payload: anytype) !std.json.Parsed(StartResponse) {
    var response = try dispatchParsed(StartResponse, rig, command, payload);
    errdefer response.deinit();
    try std.testing.expect(response.value.result.ok);
    try std.testing.expect(response.value.result.job_id.len > 0);
    return response;
}

fn pollJob(rig: *TestRig, job_id: []const u8, return_when_waiting: bool, timeout_ns: i128) !std.json.Parsed(JobResponse) {
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + timeout_ns;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        var response = try dispatchParsed(JobResponse, rig, "oars.sshkeys.jobPoll", .{ .job_id = job_id });
        const state = response.value.result.state;
        if (std.mem.eql(u8, state, "done") or
            std.mem.eql(u8, state, "partial") or
            std.mem.eql(u8, state, "canceled") or
            (return_when_waiting and std.mem.eql(u8, state, "waiting_for_verification")))
        {
            return response;
        }
        response.deinit();
        testSleep(50);
    }
    std.debug.print("TEST sshkeys job {s} timed out\n", .{job_id});
    return error.TestUnexpectedResult;
}

fn expectJobDone(job: *const std.json.Parsed(JobResponse)) !void {
    if (!std.mem.eql(u8, job.value.result.state, "done")) {
        std.debug.print("TEST sshkeys job ended in {s}\n", .{job.value.result.state});
        for (job.value.result.steps) |step| {
            std.debug.print("  {s}: {s} {s}\n", .{ step.id, step.state, step.@"error" orelse "" });
        }
        return error.TestUnexpectedResult;
    }
}

fn expectJobStepState(job: *const std.json.Parsed(JobResponse), state: []const u8) !void {
    for (job.value.result.steps) |step| {
        if (std.mem.eql(u8, step.state, state)) return;
    }
    std.debug.print("TEST sshkeys job has no step in state {s}\n", .{state});
    return error.TestUnexpectedResult;
}

fn runJob(rig: *TestRig, command: []const u8, payload: anytype) !std.json.Parsed(JobResponse) {
    var started = try startJob(rig, command, payload);
    defer started.deinit();
    var job = try pollJob(rig, started.value.result.job_id, false, 40 * std.time.ns_per_s);
    errdefer job.deinit();
    try expectJobDone(&job);
    return job;
}

fn pollSnapshot(rig: *TestRig, snapshot_id: []const u8, timeout_ns: i128) !std.json.Parsed(SnapshotResponse) {
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + timeout_ns;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        var response = try dispatchParsed(SnapshotResponse, rig, "oars.sshkeys.snapshotPoll", .{ .snapshot_id = snapshot_id });
        const state = response.value.result.state;
        if (std.mem.eql(u8, state, "done") or std.mem.eql(u8, state, "partial")) return response;
        if (std.mem.eql(u8, state, "canceled")) {
            response.deinit();
            return error.TestUnexpectedResult;
        }
        response.deinit();
        testSleep(50);
    }
    std.debug.print("TEST sshkeys snapshot {s} timed out\n", .{snapshot_id});
    return error.TestUnexpectedResult;
}

fn takeSnapshot(rig: *TestRig, server_id: []const u8, account_name: ?[]const u8) !Snapshot {
    const Account = struct {
        kind: []const u8,
        name: ?[]const u8 = null,
    };
    const account = if (account_name) |name|
        Account{ .kind = "managed_role", .name = name }
    else
        Account{ .kind = "connected" };
    var started = try dispatchParsed(StartResponse, rig, "oars.sshkeys.snapshot", .{
        .server_id = server_id,
        .account = account,
    });
    defer started.deinit();
    try std.testing.expect(started.value.result.ok);
    try std.testing.expect(started.value.result.snapshot_id.len > 0);
    const id = try std.testing.allocator.dupe(u8, started.value.result.snapshot_id);
    errdefer std.testing.allocator.free(id);
    const parsed = try pollSnapshot(rig, id, 40 * std.time.ns_per_s);
    return .{
        .allocator = std.testing.allocator,
        .id = id,
        .parsed = parsed,
    };
}

fn primaryStaticSource(snapshot: *const Snapshot) !*const SnapshotSource {
    const sources = snapshot.parsed.value.result.sources;
    for (sources, 0..) |source, i| {
        if (std.mem.eql(u8, source.kind, "static") and
            std.mem.endsWith(u8, source.path, "/.ssh/authorized_keys") and
            (std.mem.eql(u8, source.status, "readable") or std.mem.eql(u8, source.status, "missing")))
        {
            try std.testing.expect(source.file_sha256 != null);
            return &sources[i];
        }
    }
    std.debug.print("TEST snapshot has no mutable authorized_keys source\n", .{});
    return error.TestUnexpectedResult;
}

fn findKey(snapshot: *const Snapshot, fingerprint: []const u8) ?*const SnapshotKey {
    const keys = snapshot.parsed.value.result.keys;
    for (keys, 0..) |key, i| {
        if (key.parsed and std.mem.eql(u8, key.fingerprint_sha256, fingerprint)) return &keys[i];
    }
    return null;
}

fn countKey(snapshot: *const Snapshot, fingerprint: []const u8) usize {
    var count: usize = 0;
    for (snapshot.parsed.value.result.keys) |key| {
        if (key.parsed and std.mem.eql(u8, key.fingerprint_sha256, fingerprint)) count += 1;
    }
    return count;
}

fn findRole(snapshot: *const Snapshot, name: []const u8) ?*const SnapshotRole {
    const roles = snapshot.parsed.value.result.roles;
    for (roles, 0..) |role, i| {
        if (std.mem.eql(u8, role.name, name)) return &roles[i];
    }
    return null;
}

fn findDeployKey(snapshot: *const Snapshot, id: []const u8) ?*const SnapshotDeployKey {
    const deploy_keys = snapshot.parsed.value.result.deploy_keys;
    for (deploy_keys, 0..) |deploy_key, i| {
        if (std.mem.eql(u8, deploy_key.deploy_key_id, id)) return &deploy_keys[i];
    }
    return null;
}

/// Generates a host-side key through `localGenerate` + `jobPoll`.
/// The caller owns the returned strings and must call `deinit`.
pub fn keysGenerate(rig: *TestRig, tag: []const u8) !GeneratedKey {
    const allocator = std.testing.allocator;
    const destination = try std.fmt.allocPrint(allocator, "/tmp/oars-itest-key-{s}", .{tag});
    defer allocator.free(destination);
    const public_path = try std.fmt.allocPrint(allocator, "{s}.pub", .{destination});
    defer allocator.free(public_path);
    std.Io.Dir.cwd().deleteFile(std.testing.io, destination) catch {};
    std.Io.Dir.cwd().deleteFile(std.testing.io, public_path) catch {};
    const operation_id = try std.fmt.allocPrint(allocator, "itest-local-{s}", .{tag});
    defer allocator.free(operation_id);

    var job = try runJob(rig, "oars.sshkeys.localGenerate", .{
        .operation_id = operation_id,
        .destination = destination,
        .comment = tag,
    });
    defer job.deinit();
    const result = job.value.result.result orelse return error.TestUnexpectedResult;
    try std.testing.expect(result.public_key.len > 0);
    try std.testing.expect(result.private_path.len > 0);
    try std.testing.expect(result.fingerprint.len > 0);

    const public_key = try allocator.dupe(u8, result.public_key);
    errdefer allocator.free(public_key);
    const private_path = try allocator.dupe(u8, result.private_path);
    errdefer allocator.free(private_path);
    const fingerprint = try allocator.dupe(u8, result.fingerprint);
    errdefer allocator.free(fingerprint);
    const keychain_account = try allocator.dupe(u8, result.keychain_account);
    errdefer allocator.free(keychain_account);
    return .{
        .allocator = allocator,
        .value = .{ .result = .{
            .ok = true,
            .public_key = public_key,
            .private_path = private_path,
            .fingerprint = fingerprint,
            .keychain_account = keychain_account,
        } },
    };
}

fn waitForSessionError(manager: *sessions.Manager, server_id: []const u8, timeout_ns: i128) !void {
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + timeout_ns;
    while (true) {
        const info = manager.sessionSnapshot(server_id) catch {
            std.debug.print("TEST session {s} vanished\n", .{server_id});
            return error.TestUnexpectedResult;
        };
        if (info.status == .@"error") return;
        if (info.status == .ready) return error.TestUnexpectedResult;
        if (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds >= deadline) {
            std.debug.print("TEST session {s} stuck at {s}\n", .{ server_id, info.status.jsonName() });
            return error.TestUnexpectedResult;
        }
        testSleep(50);
    }
}

fn execExit(manager: *sessions.Manager, server_id: []const u8, command: []const u8) !i32 {
    const channel = try manager.exec(server_id, command);
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 15 * std.time.ns_per_s;
    var cursor: u64 = 0;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        const polls = try manager.pollChannels(server_id, &.{.{ .id = channel, .pos = cursor }}, false, 64 * 1024, 64 * 1024);
        var eof = false;
        var exit: ?i32 = null;
        for (polls) |*poll| {
            if (poll.id != channel) continue;
            cursor = poll.cursor;
            eof = poll.eof;
            exit = poll.exit_status;
        }
        for (polls) |*poll| poll.deinit(std.testing.allocator);
        std.testing.allocator.free(polls);
        if (eof) return exit orelse 0;
        testSleep(50);
    }
    return error.TestUnexpectedResult;
}

fn releaseSftpOutcome(outcome: *sessions.SftpOutcome) void {
    if (!outcome.isDone() and !outcome.abandon()) return;
    if (outcome.json) |json_text| std.testing.allocator.free(json_text);
    std.testing.allocator.destroy(outcome);
}

fn waitSftpOutcome(outcome: *sessions.SftpOutcome) !void {
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 20 * std.time.ns_per_s;
    outcome.wait(std.testing.io, deadline);
    try std.testing.expect(outcome.isDone());
}

fn expectReadOnlySftp(manager: *sessions.Manager) !void {
    const allocator = std.testing.allocator;

    const read_out = try allocator.create(sessions.SftpOutcome);
    read_out.* = .{ .allocator = allocator };
    manager.sftpRead("itest-keys-ro", "/etc/hostname", 0, 4096, read_out) catch |err| {
        allocator.destroy(read_out);
        return err;
    };
    defer releaseSftpOutcome(read_out);
    try waitSftpOutcome(read_out);
    try std.testing.expect(read_out.ok);

    const write_out = try allocator.create(sessions.SftpOutcome);
    write_out.* = .{ .allocator = allocator };
    manager.sftpSave("itest-keys-ro", "/tmp/ro-write-test", "x", null, write_out) catch |err| {
        allocator.destroy(write_out);
        return err;
    };
    defer releaseSftpOutcome(write_out);
    try waitSftpOutcome(write_out);
    try std.testing.expect(!write_out.ok);

    const mkdir_out = try allocator.create(sessions.SftpOutcome);
    mkdir_out.* = .{ .allocator = allocator };
    manager.sftpMkdir("itest-keys-ro", "/tmp/ro-dir", mkdir_out) catch |err| {
        allocator.destroy(mkdir_out);
        return err;
    };
    defer releaseSftpOutcome(mkdir_out);
    try waitSftpOutcome(mkdir_out);
    try std.testing.expect(!mkdir_out.ok);

    const rm_out = try allocator.create(sessions.SftpOutcome);
    rm_out.* = .{ .allocator = allocator };
    manager.sftpRm("itest-keys-ro", "/etc/hostname", false, 0, rm_out) catch |err| {
        allocator.destroy(rm_out);
        return err;
    };
    defer releaseSftpOutcome(rm_out);
    try waitSftpOutcome(rm_out);
    try std.testing.expect(!rm_out.ok);

    const rename_out = try allocator.create(sessions.SftpOutcome);
    rename_out.* = .{ .allocator = allocator };
    manager.sftpRename("itest-keys-ro", "/etc/hostname", "/etc/hostname2", rename_out) catch |err| {
        allocator.destroy(rename_out);
        return err;
    };
    defer releaseSftpOutcome(rename_out);
    try waitSftpOutcome(rename_out);
    try std.testing.expect(!rename_out.ok);

    const chmod_out = try allocator.create(sessions.SftpOutcome);
    chmod_out.* = .{ .allocator = allocator };
    manager.sftpChmod("itest-keys-ro", "/etc/hostname", 0o644, chmod_out) catch |err| {
        allocator.destroy(chmod_out);
        return err;
    };
    defer releaseSftpOutcome(chmod_out);
    try waitSftpOutcome(chmod_out);
    try std.testing.expect(!chmod_out.ok);
}

fn expectForwardingDenied(rig: *TestRig, private_path: []const u8) !void {
    const allocator = std.testing.allocator;
    const private_key = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, private_path, allocator, .limited(256 * 1024));
    defer allocator.free(private_key);
    const upload = try allocator.create(sessions.SftpOutcome);
    upload.* = .{ .allocator = allocator };
    rig.manager.sftpSave("itest-keys", "/tmp/oars-role-key", private_key, null, upload) catch |err| {
        allocator.destroy(upload);
        return err;
    };
    defer releaseSftpOutcome(upload);
    try waitSftpOutcome(upload);
    try std.testing.expect(upload.ok);
    try execWait(&rig.manager, "itest-keys", "chmod 600 /tmp/oars-role-key", 0, "");

    const output = try execOut(&rig.manager, "itest-keys", "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -W 127.0.0.1:22 -i /tmp/oars-role-key ro-alice@127.0.0.1 </dev/null 2>&1; echo rc=$?");
    defer allocator.free(output);
    try execWait(&rig.manager, "itest-keys", "rm -f /tmp/oars-role-key", 0, "");
    try std.testing.expect(std.mem.indexOf(u8, output, "administratively prohibited") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "open failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "rc=255") != null);
}

fn expectAuditEntry(content: []const u8, action: []const u8) !void {
    if (std.mem.indexOf(u8, content, action) == null) {
        std.debug.print("TEST audit is missing {s}\n", .{action});
        return error.TestUnexpectedResult;
    }
}

test "integration: sshkeys async management, roles, and deploy keys" {
    const env = rig_mod.TestEnv.load();
    if (!env.active) return;

    ssh.initGlobal();

    var rig: TestRig = undefined;
    try rig.init("keys");
    defer rig.deinit();
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    const server = servers.Server{
        .id = "itest-keys",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
    };
    try rig.store.upsert(io, server);
    _ = try rig.manager.connect(server, env.password, null);
    try waitForStatus(&rig.manager, "itest-keys", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-keys", true);
    try waitForStatus(&rig.manager, "itest-keys", .ready, 20 * std.time.ns_per_s);

    try execWait(&rig.manager, "itest-keys", "rm -f ~/.ssh/authorized_keys ~/.ssh/oars_deploy_* /tmp/oars-role-key /tmp/oars-ak-before-conflict /var/log/faillog /var/log/lastlog; userdel -r ro-alice >/dev/null 2>&1 || true; rm -rf /home/ro-alice; rm -f /etc/oars-roles.json", 0, "");
    defer {
        execWait(&rig.manager, "itest-keys", "rm -f ~/.ssh/oars_deploy_* /tmp/oars-role-key /tmp/oars-ak-before-conflict; userdel ro-alice >/dev/null 2>&1 || true; rm -rf /home/ro-alice; rm -f /etc/oars-roles.json; cp ~/.ssh/id_ed25519.pub ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", 0, "") catch {};
        for ([_][]const u8{ "add", "rot", "role" }) |tag| {
            var path_buf: [256]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, "/tmp/oars-itest-key-{s}", .{tag}) catch continue;
            std.Io.Dir.cwd().deleteFile(io, path) catch {};
            var public_buf: [272]u8 = undefined;
            const public_path = std.fmt.bufPrint(&public_buf, "{s}.pub", .{path}) catch continue;
            std.Io.Dir.cwd().deleteFile(io, public_path) catch {};
        }
    }

    var generated = try keysGenerate(&rig, "add");
    defer generated.deinit();

    var initial_snapshot = try takeSnapshot(&rig, "itest-keys", null);
    defer initial_snapshot.deinit();
    try std.testing.expect(std.mem.eql(u8, initial_snapshot.parsed.value.result.capabilities.privilege, "root") or
        std.mem.eql(u8, initial_snapshot.parsed.value.result.capabilities.privilege, "sudo_n"));
    const initial_source = try primaryStaticSource(&initial_snapshot);
    var add_started = try startJob(&rig, "oars.sshkeys.add", .{
        .operation_id = "itest-add",
        .snapshot_id = initial_snapshot.id,
        .source_path = initial_source.path,
        .file_sha256 = initial_source.file_sha256.?,
        .public_key = generated.value.result.public_key,
        .comment = "oars-itest",
    });
    defer add_started.deinit();
    try std.testing.expectEqualStrings(generated.value.result.fingerprint, add_started.value.result.fingerprint);
    var add_job = try pollJob(&rig, add_started.value.result.job_id, false, 40 * std.time.ns_per_s);
    defer add_job.deinit();
    try expectJobDone(&add_job);
    const add_result = add_job.value.result.result orelse return error.TestUnexpectedResult;
    try std.testing.expect(!add_result.idempotent);

    var after_add = try takeSnapshot(&rig, "itest-keys", null);
    defer after_add.deinit();
    const added_key = findKey(&after_add, generated.value.result.fingerprint) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("ssh-ed25519", added_key.type);
    try std.testing.expectEqual(@as(?u16, 256), added_key.bits);
    try std.testing.expectEqualStrings("oars-itest", added_key.comment);
    const fingerprint_output = try execOut(&rig.manager, "itest-keys", "ssh-keygen -lf ~/.ssh/authorized_keys");
    defer allocator.free(fingerprint_output);
    try std.testing.expect(std.mem.indexOf(u8, fingerprint_output, generated.value.result.fingerprint) != null);

    const key_server = servers.Server{
        .id = "itest-keys-k",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .key,
        .key_path = generated.value.result.private_path,
    };
    try rig.store.upsert(io, key_server);
    _ = try rig.manager.connect(key_server, null, null);
    try waitForStatus(&rig.manager, "itest-keys-k", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-keys-k", true);
    try waitForStatus(&rig.manager, "itest-keys-k", .ready, 20 * std.time.ns_per_s);
    try execWait(&rig.manager, "itest-keys-k", "echo key-auth-ok", 0, "key-auth-ok");
    rig.manager.disconnect("itest-keys-k");

    const duplicate_source = try primaryStaticSource(&after_add);
    var duplicate_job = try runJob(&rig, "oars.sshkeys.add", .{
        .operation_id = "itest-add-duplicate",
        .snapshot_id = after_add.id,
        .source_path = duplicate_source.path,
        .file_sha256 = duplicate_source.file_sha256.?,
        .public_key = generated.value.result.public_key,
        .comment = "oars-itest",
    });
    defer duplicate_job.deinit();
    const duplicate_result = duplicate_job.value.result.result orelse return error.TestUnexpectedResult;
    try std.testing.expect(duplicate_result.idempotent);
    var after_duplicate = try takeSnapshot(&rig, "itest-keys", null);
    defer after_duplicate.deinit();
    try std.testing.expectEqual(@as(usize, 1), countKey(&after_duplicate, generated.value.result.fingerprint));

    const frozen_source = try primaryStaticSource(&after_duplicate);
    try execWait(&rig.manager, "itest-keys", "cp ~/.ssh/authorized_keys /tmp/oars-ak-before-conflict && printf '# oars-itest-conflict\\n' >> ~/.ssh/authorized_keys", 0, "");
    var conflict_started = try startJob(&rig, "oars.sshkeys.add", .{
        .operation_id = "itest-add-conflict",
        .snapshot_id = after_duplicate.id,
        .source_path = frozen_source.path,
        .file_sha256 = frozen_source.file_sha256.?,
        .public_key = generated.value.result.public_key,
        .comment = "oars-itest",
    });
    defer conflict_started.deinit();
    var conflict_job = try pollJob(&rig, conflict_started.value.result.job_id, false, 40 * std.time.ns_per_s);
    defer conflict_job.deinit();
    try std.testing.expectEqualStrings("partial", conflict_job.value.result.state);
    try expectJobStepState(&conflict_job, "conflict");
    try execWait(&rig.manager, "itest-keys", "mv /tmp/oars-ak-before-conflict ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", 0, "");

    var before_revoke = try takeSnapshot(&rig, "itest-keys", null);
    defer before_revoke.deinit();
    const revoke_source = try primaryStaticSource(&before_revoke);
    const revoke_key = findKey(&before_revoke, generated.value.result.fingerprint) orelse return error.TestUnexpectedResult;
    var revoke_job = try runJob(&rig, "oars.sshkeys.revoke", .{
        .operation_id = "itest-revoke",
        .snapshot_id = before_revoke.id,
        .source_path = revoke_source.path,
        .file_sha256 = revoke_source.file_sha256.?,
        .fingerprint = revoke_key.fingerprint_sha256,
        .line_hash = revoke_key.line_hash,
        .confirm_fingerprint = revoke_key.fingerprint_sha256,
    });
    defer revoke_job.deinit();

    var after_revoke = try takeSnapshot(&rig, "itest-keys", null);
    defer after_revoke.deinit();
    try std.testing.expect(findKey(&after_revoke, generated.value.result.fingerprint) == null);
    const revoked_server = servers.Server{
        .id = "itest-keys-revoked",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .key,
        .key_path = generated.value.result.private_path,
    };
    try rig.store.upsert(io, revoked_server);
    _ = try rig.manager.connect(revoked_server, null, null);
    try waitForStatus(&rig.manager, "itest-keys-revoked", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-keys-revoked", true);
    try waitForSessionError(&rig.manager, "itest-keys-revoked", 25 * std.time.ns_per_s);
    rig.manager.disconnect("itest-keys-revoked");

    const empty_source = try primaryStaticSource(&after_revoke);
    var readd_job = try runJob(&rig, "oars.sshkeys.add", .{
        .operation_id = "itest-readd",
        .snapshot_id = after_revoke.id,
        .source_path = empty_source.path,
        .file_sha256 = empty_source.file_sha256.?,
        .public_key = generated.value.result.public_key,
        .comment = "oars-itest",
    });
    defer readd_job.deinit();

    var replacement = try keysGenerate(&rig, "rot");
    defer replacement.deinit();
    var before_rotate = try takeSnapshot(&rig, "itest-keys", null);
    defer before_rotate.deinit();
    const rotate_source = try primaryStaticSource(&before_rotate);
    const rotate_old_key = findKey(&before_rotate, generated.value.result.fingerprint) orelse return error.TestUnexpectedResult;
    var rotate_started = try startJob(&rig, "oars.sshkeys.rotate", .{
        .operation_id = "itest-rotate",
        .snapshot_id = before_rotate.id,
        .source_path = rotate_source.path,
        .file_sha256 = rotate_source.file_sha256.?,
        .old_fingerprint = rotate_old_key.fingerprint_sha256,
        .line_hash = rotate_old_key.line_hash,
        .new_public_key = replacement.value.result.public_key,
    });
    defer rotate_started.deinit();
    try std.testing.expectEqualStrings(replacement.value.result.fingerprint, rotate_started.value.result.new_fingerprint);
    var waiting_rotation = try pollJob(&rig, rotate_started.value.result.job_id, true, 40 * std.time.ns_per_s);
    defer waiting_rotation.deinit();
    try std.testing.expectEqualStrings("waiting_for_verification", waiting_rotation.value.result.state);

    var staged_snapshot = try takeSnapshot(&rig, "itest-keys", null);
    defer staged_snapshot.deinit();
    try std.testing.expect(findKey(&staged_snapshot, generated.value.result.fingerprint) != null);
    try std.testing.expect(findKey(&staged_snapshot, replacement.value.result.fingerprint) != null);

    const staged_old_server = servers.Server{
        .id = "itest-keys-old-staged",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .key,
        .key_path = generated.value.result.private_path,
    };
    try rig.store.upsert(io, staged_old_server);
    _ = try rig.manager.connect(staged_old_server, null, null);
    try waitForStatus(&rig.manager, "itest-keys-old-staged", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-keys-old-staged", true);
    try waitForStatus(&rig.manager, "itest-keys-old-staged", .ready, 20 * std.time.ns_per_s);
    try execWait(&rig.manager, "itest-keys-old-staged", "echo old-key-still-valid", 0, "old-key-still-valid");
    rig.manager.disconnect("itest-keys-old-staged");

    var rotate_commit = try dispatchParsed(StartResponse, &rig, "oars.sshkeys.rotateCommit", .{
        .job_id = rotate_started.value.result.job_id,
        .verification = .{
            .kind = "local_private_key",
            .path = replacement.value.result.private_path,
        },
    });
    defer rotate_commit.deinit();
    try std.testing.expect(rotate_commit.value.result.ok);
    var rotated_job = try pollJob(&rig, rotate_started.value.result.job_id, false, 40 * std.time.ns_per_s);
    defer rotated_job.deinit();
    try expectJobDone(&rotated_job);

    var after_rotate = try takeSnapshot(&rig, "itest-keys", null);
    defer after_rotate.deinit();
    try std.testing.expect(findKey(&after_rotate, generated.value.result.fingerprint) == null);
    try std.testing.expect(findKey(&after_rotate, replacement.value.result.fingerprint) != null);

    var role_key = try keysGenerate(&rig, "role");
    defer role_key.deinit();
    var role_plan = try dispatchParsed(StartResponse, &rig, "oars.sshkeys.roles.plan", .{
        .server_id = "itest-keys",
        .name = "ro-alice",
        .kind = "read_only_sftp",
        .action = "create",
    });
    defer role_plan.deinit();
    try std.testing.expect(role_plan.value.result.ok);
    try std.testing.expect(role_plan.value.result.plan_id.len > 0);
    var role_create_job = try runJob(&rig, "oars.sshkeys.roles.commit", .{
        .operation_id = "itest-role-create",
        .plan_id = role_plan.value.result.plan_id,
        .public_key = role_key.value.result.public_key,
    });
    defer role_create_job.deinit();

    var role_snapshot = try takeSnapshot(&rig, "itest-keys", "ro-alice");
    defer role_snapshot.deinit();
    const role = findRole(&role_snapshot, "ro-alice") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("read_only_sftp", role.kind);
    try std.testing.expectEqualStrings("verified", role.policy_state);
    try std.testing.expect(role.home != null);
    try std.testing.expectEqualStrings("/home/ro-alice", role.home.?);
    try std.testing.expectEqual(@as(usize, 1), role.key_fingerprints.len);
    try std.testing.expectEqualStrings(role_key.value.result.fingerprint, role.key_fingerprints[0]);
    const role_installed_key = findKey(&role_snapshot, role_key.value.result.fingerprint) orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, role_installed_key.options, "restrict") != null);
    try std.testing.expect(std.mem.indexOf(u8, role_installed_key.options, "internal-sftp -R") != null);

    const read_only_server = servers.Server{
        .id = "itest-keys-ro",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = "ro-alice",
        .auth_method = .key,
        .key_path = role_key.value.result.private_path,
    };
    try rig.store.upsert(io, read_only_server);
    _ = try rig.manager.connect(read_only_server, null, null);
    try waitForStatus(&rig.manager, "itest-keys-ro", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-keys-ro", true);
    try waitForStatus(&rig.manager, "itest-keys-ro", .ready, 20 * std.time.ns_per_s);
    try std.testing.expect(try execExit(&rig.manager, "itest-keys-ro", "echo pwned") != 0);
    try expectReadOnlySftp(&rig.manager);
    try expectForwardingDenied(&rig, role_key.value.result.private_path);
    rig.manager.disconnect("itest-keys-ro");

    var role_delete_plan = try dispatchParsed(StartResponse, &rig, "oars.sshkeys.roles.plan", .{
        .server_id = "itest-keys",
        .name = "ro-alice",
        .kind = "read_only_sftp",
        .action = "delete",
    });
    defer role_delete_plan.deinit();
    try std.testing.expect(role_delete_plan.value.result.ok);
    try std.testing.expect(role_delete_plan.value.result.plan_id.len > 0);
    var role_delete_job = try runJob(&rig, "oars.sshkeys.roles.commit", .{
        .operation_id = "itest-role-delete",
        .plan_id = role_delete_plan.value.result.plan_id,
    });
    defer role_delete_job.deinit();
    try execWait(&rig.manager, "itest-keys", "! getent passwd ro-alice >/dev/null 2>&1 && test -d /home/ro-alice", 0, "");

    var after_role_delete = try takeSnapshot(&rig, "itest-keys", null);
    defer after_role_delete.deinit();
    try std.testing.expect(findRole(&after_role_delete, "ro-alice") == null);
    const deleted_role_server = servers.Server{
        .id = "itest-keys-role-deleted",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = "ro-alice",
        .auth_method = .key,
        .key_path = role_key.value.result.private_path,
    };
    try rig.store.upsert(io, deleted_role_server);
    _ = try rig.manager.connect(deleted_role_server, null, null);
    try waitForStatus(&rig.manager, "itest-keys-role-deleted", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-keys-role-deleted", true);
    try waitForSessionError(&rig.manager, "itest-keys-role-deleted", 25 * std.time.ns_per_s);
    rig.manager.disconnect("itest-keys-role-deleted");

    const authorized_before_deploy = try execOut(&rig.manager, "itest-keys", "cat ~/.ssh/authorized_keys");
    defer allocator.free(authorized_before_deploy);

    var deploy_one_job = try runJob(&rig, "oars.sshkeys.deployKeys.generate", .{
        .operation_id = "itest-deploy-one",
        .server_id = "itest-keys",
        .repository_label = "owner/repository-one",
        .comment = "oars-itest-deploy-one",
    });
    defer deploy_one_job.deinit();
    const deploy_one = deploy_one_job.value.result.result orelse return error.TestUnexpectedResult;
    try std.testing.expect(deploy_one.deploy_key_id.len > 0);
    try std.testing.expect(deploy_one.public_key.len > 0);
    try std.testing.expect(deploy_one.private_path.len > 0);
    try std.testing.expect(deploy_one.fingerprint.len > 0);

    var deploy_two_job = try runJob(&rig, "oars.sshkeys.deployKeys.generate", .{
        .operation_id = "itest-deploy-two",
        .server_id = "itest-keys",
        .repository_label = "owner/repository-two",
        .comment = "oars-itest-deploy-two",
    });
    defer deploy_two_job.deinit();
    const deploy_two = deploy_two_job.value.result.result orelse return error.TestUnexpectedResult;
    try std.testing.expect(!std.mem.eql(u8, deploy_one.deploy_key_id, deploy_two.deploy_key_id));
    try std.testing.expect(!std.mem.eql(u8, deploy_one.fingerprint, deploy_two.fingerprint));
    try std.testing.expect(!std.mem.eql(u8, deploy_one.private_path, deploy_two.private_path));

    var mode_command_buf: [1024]u8 = undefined;
    const mode_command = try std.fmt.bufPrint(&mode_command_buf, "test $(stat -c %a {s}) = 600 && test $(stat -c %a {s}) = 600", .{ deploy_one.private_path, deploy_two.private_path });
    try execWait(&rig.manager, "itest-keys", mode_command, 0, "");

    var deploy_snapshot = try takeSnapshot(&rig, "itest-keys", null);
    defer deploy_snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 2), deploy_snapshot.parsed.value.result.deploy_keys.len);
    const inventory_one = findDeployKey(&deploy_snapshot, deploy_one.deploy_key_id) orelse return error.TestUnexpectedResult;
    const inventory_two = findDeployKey(&deploy_snapshot, deploy_two.deploy_key_id) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("owner/repository-one", inventory_one.repository_label);
    try std.testing.expectEqualStrings("owner/repository-two", inventory_two.repository_label);
    try std.testing.expectEqualStrings(deploy_one.fingerprint, inventory_one.fingerprint);
    try std.testing.expectEqualStrings(deploy_two.fingerprint, inventory_two.fingerprint);

    const authorized_after_generate = try execOut(&rig.manager, "itest-keys", "cat ~/.ssh/authorized_keys");
    defer allocator.free(authorized_after_generate);
    try std.testing.expectEqualStrings(authorized_before_deploy, authorized_after_generate);

    var deploy_delete_job = try runJob(&rig, "oars.sshkeys.deployKeys.delete", .{
        .operation_id = "itest-deploy-delete-one",
        .server_id = "itest-keys",
        .deploy_key_id = deploy_one.deploy_key_id,
        .confirm_fingerprint = deploy_one.fingerprint,
    });
    defer deploy_delete_job.deinit();

    var after_deploy_delete = try takeSnapshot(&rig, "itest-keys", null);
    defer after_deploy_delete.deinit();
    try std.testing.expect(findDeployKey(&after_deploy_delete, deploy_one.deploy_key_id) == null);
    try std.testing.expect(findDeployKey(&after_deploy_delete, deploy_two.deploy_key_id) != null);
    try std.testing.expectEqual(@as(usize, 1), after_deploy_delete.parsed.value.result.deploy_keys.len);
    var existence_command_buf: [2048]u8 = undefined;
    const existence_command = try std.fmt.bufPrint(&existence_command_buf, "test ! -e {s} && test ! -e {s}.pub && test -e {s} && test -e {s}.pub", .{ deploy_one.private_path, deploy_one.private_path, deploy_two.private_path, deploy_two.private_path });
    try execWait(&rig.manager, "itest-keys", existence_command, 0, "");

    const authorized_after_delete = try execOut(&rig.manager, "itest-keys", "cat ~/.ssh/authorized_keys");
    defer allocator.free(authorized_after_delete);
    try std.testing.expectEqualStrings(authorized_before_deploy, authorized_after_delete);

    const audit_content = try std.Io.Dir.cwd().readFileAlloc(io, rig.audit_store.path, allocator, .limited(256 * 1024));
    defer allocator.free(audit_content);
    try expectAuditEntry(audit_content, "sshkeys.localGenerate");
    try expectAuditEntry(audit_content, "sshkeys.add");
    try expectAuditEntry(audit_content, "sshkeys.revoke");
    try expectAuditEntry(audit_content, "sshkeys.rotate");
    try expectAuditEntry(audit_content, "sshkeys.roles.create");
    try expectAuditEntry(audit_content, "sshkeys.roles.delete");
    try expectAuditEntry(audit_content, "sshkeys.deployKeys.generate");
    try expectAuditEntry(audit_content, "sshkeys.deployKeys.delete");

    try execWait(&rig.manager, "itest-keys", "rm -f ~/.ssh/oars_deploy_*; rm -rf /home/ro-alice; rm -f /etc/oars-roles.json; cp ~/.ssh/id_ed25519.pub ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", 0, "");
    rig.manager.disconnect("itest-keys");
}
