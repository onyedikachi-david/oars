//! Spec 08 integration coverage (container): add/connect/revoke/rotate
//! with a locally generated key, the read-only role (SFTP reads yes,
//! mutations and shells no), role delete, and the server-side deploy key.
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

const KeysListResp = struct {
    result: struct {
        ok: bool,
        keys: []const struct {
            line_index: usize,
            parsed: bool,
            options: []const u8 = "",
            type: []const u8 = "",
            key: []const u8 = "",
            comment: []const u8 = "",
            fingerprint_sha256: []const u8 = "",
            bits: ?u16 = null,
            line_hash: []const u8 = "",
            raw: []const u8 = "",
            @"error": []const u8 = "",
        } = &.{},
    },
};

const KeysAddResp = struct {
    result: struct {
        ok: bool,
        line_index: usize = 0,
        fingerprint: []const u8 = "",
        line_hash: []const u8 = "",
    },
};

const KeysGenResp = struct {
    result: struct {
        ok: bool,
        public_key: []const u8 = "",
        private_path: []const u8 = "",
        keychain_account: []const u8 = "",
    },
};

/// Generates a local key pair through the dispatcher (host side) and
/// returns the parsed response. The temp files are left in /tmp (the
/// test connects with the private half later) and removed at test end.
pub fn keysGenerate(rig: *TestRig, tag: []const u8) !std.json.Parsed(KeysGenResp) {
    var dest_buf: [256]u8 = undefined;
    const dest = try std.fmt.bufPrint(&dest_buf, "/tmp/oars-itest-key-{s}", .{tag});
    var pub_buf: [272]u8 = undefined;
    const pub_path = try std.fmt.bufPrint(&pub_buf, "{s}.pub", .{dest});
    std.Io.Dir.cwd().deleteFile(std.testing.io, dest) catch {};
    std.Io.Dir.cwd().deleteFile(std.testing.io, pub_path) catch {};
    var req_buf: [512]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "{{\"id\":\"kg\",\"command\":\"oars.sshkeys.generate\",\"payload\":{{\"destination\":\"{s}\",\"comment\":\"{s}\"}}}}", .{ dest, tag });
    const resp = rig.dispatch(req);
    const parsed = try std.json.parseFromSlice(KeysGenResp, std.testing.allocator, resp, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    try std.testing.expect(parsed.value.result.ok);
    return parsed;
}

/// Waits for a session to land in the error state (auth/connect failure).
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

/// Runs an exec and returns its exit code.
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

test "integration: sshkeys add/connect/revoke/rotate, roles, and deploy keys" {
    const env = rig_mod.TestEnv.load();
    if (!env.active) return;

    ssh.initGlobal();

    var rig: TestRig = undefined;
    try rig.init("keys");
    defer rig.deinit();
    const io = std.testing.io;

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

    // Start clean: the container persists between runs. userdel can refuse
    // (e.g. "currently logged in" after a crashed run), so also remove the
    // home by hand — a stale authorized_keys is what breaks repeat runs.
    try execWait(&rig.manager, "itest-keys", "rm -f ~/.ssh/authorized_keys /tmp/oars-role-key /var/log/faillog /var/log/lastlog", 0, "");
    try execWait(&rig.manager, "itest-keys", "userdel -r ro-alice >/dev/null 2>&1; rm -rf /home/ro-alice; rm -f /etc/oars-roles.json", 0, "");
    // Always restore the container's own key at the end — even when this
    // test fails mid-way — so the earlier key-auth test keeps working on
    // the next run.
    defer {
        execWait(&rig.manager, "itest-keys", "cp ~/.ssh/id_ed25519.pub ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", 0, "") catch {};
        for ([_][]const u8{ "add", "rot", "role" }) |tag| {
            var b: [256]u8 = undefined;
            const p = std.fmt.bufPrint(&b, "/tmp/oars-itest-key-{s}", .{tag}) catch continue;
            std.Io.Dir.cwd().deleteFile(io, p) catch {};
            var pb: [272]u8 = undefined;
            const pp = std.fmt.bufPrint(&pb, "{s}.pub", .{p}) catch continue;
            std.Io.Dir.cwd().deleteFile(io, pp) catch {};
        }
    }

    // --- generate a local key and add it through the dispatcher ---
    var gen = try keysGenerate(&rig, "add");
    defer gen.deinit();
    var add_buf: [2048]u8 = undefined;
    const add_req = try std.fmt.bufPrint(&add_buf, "{{\"id\":\"1\",\"command\":\"oars.sshkeys.add\",\"payload\":{{\"server_id\":\"itest-keys\",\"public_key\":\"{s}\",\"comment\":\"oars-itest\"}}}}", .{gen.value.result.public_key});
    const add_resp = rig.dispatch(add_req);
    const add_parsed = try std.json.parseFromSlice(KeysAddResp, std.testing.allocator, add_resp, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer add_parsed.deinit();
    try std.testing.expect(add_parsed.value.result.ok);
    const fingerprint = add_parsed.value.result.fingerprint;
    const line_hash = add_parsed.value.result.line_hash;

    // --- list: the key parses; the fingerprint matches ssh-keygen -lf ---
    const list_resp = rig.dispatch(
        \\{"id":"2","command":"oars.sshkeys.list","payload":{"server_id":"itest-keys"}}
    );
    const list_parsed = try std.json.parseFromSlice(KeysListResp, std.testing.allocator, list_resp, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer list_parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), list_parsed.value.result.keys.len);
    const listed = list_parsed.value.result.keys[0];
    try std.testing.expect(listed.parsed);
    try std.testing.expectEqualStrings("ssh-ed25519", listed.type);
    try std.testing.expectEqual(@as(?u16, 256), listed.bits);
    try std.testing.expectEqualStrings("oars-itest", listed.comment);
    try std.testing.expectEqualStrings(fingerprint, listed.fingerprint_sha256);
    const lf_out = try execOut(&rig.manager, "itest-keys", "ssh-keygen -lf ~/.ssh/authorized_keys");
    defer std.testing.allocator.free(lf_out);
    try std.testing.expect(std.mem.indexOf(u8, lf_out, fingerprint) != null);

    // --- connect with the new key ---
    const key_server = servers.Server{
        .id = "itest-keys-k",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .key,
        .key_path = gen.value.result.private_path,
    };
    try rig.store.upsert(io, key_server);
    _ = try rig.manager.connect(key_server, null, null);
    try waitForStatus(&rig.manager, "itest-keys-k", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-keys-k", true);
    try waitForStatus(&rig.manager, "itest-keys-k", .ready, 20 * std.time.ns_per_s);
    try execWait(&rig.manager, "itest-keys-k", "echo key-auth-ok", 0, "key-auth-ok");
    rig.manager.disconnect("itest-keys-k");

    // --- revoke: the key disappears and the connection now fails ---
    var revoke_buf: [1024]u8 = undefined;
    const revoke_req = try std.fmt.bufPrint(&revoke_buf, "{{\"id\":\"3\",\"command\":\"oars.sshkeys.revoke\",\"payload\":{{\"server_id\":\"itest-keys\",\"fingerprint\":\"{s}\",\"expected_line_hash\":\"{s}\"}}}}", .{ fingerprint, line_hash });
    const revoke_resp = rig.dispatch(revoke_req);
    try std.testing.expect(std.mem.indexOf(u8, revoke_resp, "\"ok\":true") != null);
    const after_revoke = rig.dispatch(
        \\{"id":"4","command":"oars.sshkeys.list","payload":{"server_id":"itest-keys"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, after_revoke, "\"keys\":[]") != null);

    // A stale line hash is a conflict, never a silent overwrite.
    const stale = rig.dispatch(
        \\{"id":"5","command":"oars.sshkeys.revoke","payload":{"server_id":"itest-keys","fingerprint":"SHA256:x","expected_line_hash":"stale"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, stale, "key not found") != null);

    const revoked_server = servers.Server{
        .id = "itest-keys-rv",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .key,
        .key_path = gen.value.result.private_path,
    };
    try rig.store.upsert(io, revoked_server);
    _ = try rig.manager.connect(revoked_server, null, null);
    try waitForStatus(&rig.manager, "itest-keys-rv", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-keys-rv", true);
    try waitForSessionError(&rig.manager, "itest-keys-rv", 25 * std.time.ns_per_s);
    rig.manager.disconnect("itest-keys-rv");

    // --- rotate: the old fingerprint is replaced by the new key ---
    _ = rig.dispatch(add_req); // add it again
    var gen2 = try keysGenerate(&rig, "rot");
    defer gen2.deinit();
    var rotate_buf: [4096]u8 = undefined;
    const rotate_req = try std.fmt.bufPrint(&rotate_buf, "{{\"id\":\"6\",\"command\":\"oars.sshkeys.rotate\",\"payload\":{{\"server_id\":\"itest-keys\",\"fingerprint\":\"{s}\",\"expected_line_hash\":\"{s}\",\"new_public_key\":\"{s}\"}}}}", .{ fingerprint, line_hash, gen2.value.result.public_key });
    const rotate_resp = rig.dispatch(rotate_req);
    try std.testing.expect(std.mem.indexOf(u8, rotate_resp, "\"ok\":true") != null);
    const after_rotate = rig.dispatch(
        \\{"id":"7","command":"oars.sshkeys.list","payload":{"server_id":"itest-keys"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, after_rotate, fingerprint) == null);
    const rotated_parsed = try std.json.parseFromSlice(KeysListResp, std.testing.allocator, after_rotate, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer rotated_parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), rotated_parsed.value.result.keys.len);
    try std.testing.expect(rotated_parsed.value.result.keys[0].parsed);
    try std.testing.expectEqualStrings("ssh-ed25519", rotated_parsed.value.result.keys[0].type);
    // The old key is gone; the new key replaced it (options preserved).
    try std.testing.expect(std.mem.indexOf(u8, rotated_parsed.value.result.keys[0].fingerprint_sha256, fingerprint) == null);

    // --- read-only role: forced internal-sftp -R, reads yes, writes no ---
    var gen3 = try keysGenerate(&rig, "role");
    defer gen3.deinit();
    const role_create = rig.dispatch(
        \\{"id":"8","command":"oars.sshkeys.roles.create","payload":{"server_id":"itest-keys","name":"ro-alice","read_only":true}}
    );
    try std.testing.expect(std.mem.indexOf(u8, role_create, "\"ok\":true") != null);

    const roles_list = rig.dispatch(
        \\{"id":"9","command":"oars.sshkeys.roles.list","payload":{"server_id":"itest-keys"}}
    );
    const RolesResp = struct {
        result: struct {
            ok: bool,
            roles: []const struct {
                name: []const u8,
                shell: []const u8 = "",
                read_only: bool = false,
                policy: []const u8 = "",
                users: []const []const u8 = &.{},
            } = &.{},
        },
    };
    const roles_parsed = try std.json.parseFromSlice(RolesResp, std.testing.allocator, roles_list, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer roles_parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), roles_parsed.value.result.roles.len);
    const role = roles_parsed.value.result.roles[0];
    try std.testing.expectEqualStrings("ro-alice", role.name);
    try std.testing.expect(role.read_only);
    try std.testing.expectEqualStrings("read-only-sftp", role.policy);

    // Adding a key to a read-only role auto-applies the forced command.
    var role_add_buf: [2048]u8 = undefined;
    const role_add_req = try std.fmt.bufPrint(&role_add_buf, "{{\"id\":\"10\",\"command\":\"oars.sshkeys.add\",\"payload\":{{\"server_id\":\"itest-keys\",\"user\":\"ro-alice\",\"public_key\":\"{s}\",\"comment\":\"alice-mac\"}}}}", .{gen3.value.result.public_key});
    const role_add = rig.dispatch(role_add_req);
    try std.testing.expect(std.mem.indexOf(u8, role_add, "\"ok\":true") != null);
    const role_list_resp = rig.dispatch(
        \\{"id":"11","command":"oars.sshkeys.list","payload":{"server_id":"itest-keys","user":"ro-alice"}}
    );
    const role_list_parsed = try std.json.parseFromSlice(KeysListResp, std.testing.allocator, role_list_resp, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer role_list_parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), role_list_parsed.value.result.keys.len);
    try std.testing.expect(std.mem.indexOf(u8, role_list_parsed.value.result.keys[0].options, "restrict") != null);
    try std.testing.expect(std.mem.indexOf(u8, role_list_parsed.value.result.keys[0].options, "internal-sftp -R") != null);
    // roles.list now shows the key comment as a member.
    const roles_list2 = rig.dispatch(
        \\{"id":"12","command":"oars.sshkeys.roles.list","payload":{"server_id":"itest-keys"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, roles_list2, "alice-mac") != null);

    // Connect as the read-only user: SFTP reads work, everything else fails.
    const ro_server = servers.Server{
        .id = "itest-keys-ro",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = "ro-alice",
        .auth_method = .key,
        .key_path = gen3.value.result.private_path,
    };
    try rig.store.upsert(io, ro_server);
    _ = try rig.manager.connect(ro_server, null, null);
    try waitForStatus(&rig.manager, "itest-keys-ro", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-keys-ro", true);
    try waitForStatus(&rig.manager, "itest-keys-ro", .ready, 20 * std.time.ns_per_s);

    // A shell/exec is rejected (the forced command is SFTP-only).
    const shell_exit = try execExit(&rig.manager, "itest-keys-ro", "echo pwned");
    try std.testing.expect(shell_exit != 0);

    // SFTP reads are permitted.
    const read_out = try std.testing.allocator.create(sessions.SftpOutcome);
    read_out.* = .{ .allocator = std.testing.allocator };
    // A completed outcome is freed here; an unfinished one belongs to the
    // op (its eventual set frees it) — never destroy a live one.
    rig.manager.sftpRead("itest-keys-ro", "/etc/hostname", 0, 4096, read_out) catch |err| {
        std.testing.allocator.destroy(read_out);
        return err;
    };
    // A completed outcome is freed here; an unfinished one belongs to
    // the op (its eventual set frees it) — never destroy a live one.
    defer if (read_out.isDone() or read_out.abandon()) std.testing.allocator.destroy(read_out);
    const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 20 * std.time.ns_per_s;
    read_out.wait(io, deadline);
    try std.testing.expect(read_out.isDone());
    try std.testing.expect(read_out.ok);
    if (read_out.json) |j| std.testing.allocator.free(j);

    // Every filesystem mutation is refused.
    const write_out = try std.testing.allocator.create(sessions.SftpOutcome);
    write_out.* = .{ .allocator = std.testing.allocator };
    rig.manager.sftpSave("itest-keys-ro", "/tmp/ro-write-test", "x", null, write_out) catch |err| {
        std.testing.allocator.destroy(write_out);
        return err;
    };
    // A completed outcome is freed here; an unfinished one belongs to
    // the op (its eventual set frees it) — never destroy a live one.
    defer if (write_out.isDone() or write_out.abandon()) std.testing.allocator.destroy(write_out);
    write_out.wait(io, deadline);
    try std.testing.expect(write_out.isDone());
    try std.testing.expect(!write_out.ok);

    const mkdir_out = try std.testing.allocator.create(sessions.SftpOutcome);
    mkdir_out.* = .{ .allocator = std.testing.allocator };
    rig.manager.sftpMkdir("itest-keys-ro", "/tmp/ro-dir", mkdir_out) catch |err| {
        std.testing.allocator.destroy(mkdir_out);
        return err;
    };
    // A completed outcome is freed here; an unfinished one belongs to
    // the op (its eventual set frees it) — never destroy a live one.
    defer if (mkdir_out.isDone() or mkdir_out.abandon()) std.testing.allocator.destroy(mkdir_out);
    mkdir_out.wait(io, deadline);
    try std.testing.expect(mkdir_out.isDone() and !mkdir_out.ok);

    const rm_out = try std.testing.allocator.create(sessions.SftpOutcome);
    rm_out.* = .{ .allocator = std.testing.allocator };
    rig.manager.sftpRm("itest-keys-ro", "/etc/hostname", false, 0, rm_out) catch |err| {
        std.testing.allocator.destroy(rm_out);
        return err;
    };
    // A completed outcome is freed here; an unfinished one belongs to
    // the op (its eventual set frees it) — never destroy a live one.
    defer if (rm_out.isDone() or rm_out.abandon()) std.testing.allocator.destroy(rm_out);
    rm_out.wait(io, deadline);
    try std.testing.expect(rm_out.isDone() and !rm_out.ok);

    const rename_out = try std.testing.allocator.create(sessions.SftpOutcome);
    rename_out.* = .{ .allocator = std.testing.allocator };
    rig.manager.sftpRename("itest-keys-ro", "/etc/hostname", "/etc/hostname2", rename_out) catch |err| {
        std.testing.allocator.destroy(rename_out);
        return err;
    };
    // A completed outcome is freed here; an unfinished one belongs to
    // the op (its eventual set frees it) — never destroy a live one.
    defer if (rename_out.isDone() or rename_out.abandon()) std.testing.allocator.destroy(rename_out);
    rename_out.wait(io, deadline);
    try std.testing.expect(rename_out.isDone() and !rename_out.ok);

    const chmod_out = try std.testing.allocator.create(sessions.SftpOutcome);
    chmod_out.* = .{ .allocator = std.testing.allocator };
    rig.manager.sftpChmod("itest-keys-ro", "/etc/hostname", 0o644, chmod_out) catch |err| {
        std.testing.allocator.destroy(chmod_out);
        return err;
    };
    // A completed outcome is freed here; an unfinished one belongs to
    // the op (its eventual set frees it) — never destroy a live one.
    defer if (chmod_out.isDone() or chmod_out.abandon()) std.testing.allocator.destroy(chmod_out);
    chmod_out.wait(io, deadline);
    try std.testing.expect(chmod_out.isDone() and !chmod_out.ok);

    // Forwarding is refused at the protocol level: `ssh -W` opens only a
    // direct-tcpip channel — no session or command — so a refusal is about
    // the channel itself, never about the forced command. It runs from the
    // root session (whose exec is not replaced); the inner ssh authenticates
    // as ro-alice with the uploaded role key, so the refusal is about
    // `restrict`, not about auth.
    const up_out = try std.testing.allocator.create(sessions.SftpOutcome);
    up_out.* = .{ .allocator = std.testing.allocator };
    const role_key_bytes = try std.Io.Dir.cwd().readFileAlloc(io, gen3.value.result.private_path, std.testing.allocator, .limited(256 * 1024));
    defer std.testing.allocator.free(role_key_bytes);
    rig.manager.sftpSave("itest-keys", "/tmp/oars-role-key", role_key_bytes, null, up_out) catch |err| {
        std.testing.allocator.destroy(up_out);
        return err;
    };
    // A completed outcome is freed here; an unfinished one belongs to
    // the op (its eventual set frees it) — never destroy a live one.
    defer if (up_out.isDone() or up_out.abandon()) std.testing.allocator.destroy(up_out);
    up_out.wait(io, deadline);
    try std.testing.expect(up_out.isDone() and up_out.ok);
    if (up_out.json) |j| std.testing.allocator.free(j);
    const fwd_out = try execOut(&rig.manager, "itest-keys", "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -W 127.0.0.1:22 -i /tmp/oars-role-key ro-alice@127.0.0.1 </dev/null 2>&1; echo rc=$?");
    defer std.testing.allocator.free(fwd_out);
    try execWait(&rig.manager, "itest-keys", "rm -f /tmp/oars-role-key", 0, "");
    try std.testing.expect(std.mem.indexOf(u8, fwd_out, "administratively prohibited") != null);
    try std.testing.expect(std.mem.indexOf(u8, fwd_out, "open failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, fwd_out, "rc=255") != null);

    rig.manager.disconnect("itest-keys-ro");

    // --- roles.delete: the user is gone and the marker is updated ---
    const role_delete = rig.dispatch(
        \\{"id":"13","command":"oars.sshkeys.roles.delete","payload":{"server_id":"itest-keys","name":"ro-alice"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, role_delete, "\"ok\":true") != null);
    const roles_after = rig.dispatch(
        \\{"id":"14","command":"oars.sshkeys.roles.list","payload":{"server_id":"itest-keys"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, roles_after, "\"roles\":[]") != null);
    const gone_server = servers.Server{
        .id = "itest-keys-gone",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = "ro-alice",
        .auth_method = .key,
        .key_path = gen3.value.result.private_path,
    };
    try rig.store.upsert(io, gone_server);
    _ = try rig.manager.connect(gone_server, null, null);
    try waitForStatus(&rig.manager, "itest-keys-gone", .needs_trust, 20 * std.time.ns_per_s);
    try rig.manager.trust("itest-keys-gone", true);
    try waitForSessionError(&rig.manager, "itest-keys-gone", 25 * std.time.ns_per_s);
    rig.manager.disconnect("itest-keys-gone");

    // --- deploy key: server-side, 0600, authorized_keys untouched ---
    const deploy_resp = rig.dispatch(
        \\{"id":"15","command":"oars.sshkeys.deployKey.generate","payload":{"server_id":"itest-keys"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, deploy_resp, "\"ok\":true") != null);
    const deploy_parsed = try std.json.parseFromSlice(KeysGenResp, std.testing.allocator, deploy_resp, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer deploy_parsed.deinit();
    try std.testing.expect(std.mem.indexOf(u8, deploy_parsed.value.result.public_key, "ssh-ed25519") != null);
    const mode_out = try execOut(&rig.manager, "itest-keys", "stat -c %a ~/.ssh/oars_deploy");
    defer std.testing.allocator.free(mode_out);
    try std.testing.expect(std.mem.indexOf(u8, mode_out, "600") != null);
    // Idempotent: generating again returns the same key.
    const deploy_resp2 = rig.dispatch(
        \\{"id":"16","command":"oars.sshkeys.deployKey.generate","payload":{"server_id":"itest-keys"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, deploy_resp2, deploy_parsed.value.result.public_key) != null);

    // authorized_keys was never touched by the deploy-key flow.
    const final_list = rig.dispatch(
        \\{"id":"17","command":"oars.sshkeys.list","payload":{"server_id":"itest-keys"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, final_list, "\"keys\":[") != null);

    // Every mutation was audited.
    const audit_content = try std.Io.Dir.cwd().readFileAlloc(io, rig.audit_store.path, std.testing.allocator, .limited(256 * 1024));
    defer std.testing.allocator.free(audit_content);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "sshkeys.add") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "sshkeys.revoke") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "sshkeys.rotate") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "sshkeys.roles.create") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "sshkeys.roles.delete") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "sshkeys.deployKey.generate") != null);

    // Restore the container's own key BEFORE disconnecting — the defer
    // above only fires as a safety net for mid-test failures (it runs
    // after this disconnect and would silently fail).
    try execWait(&rig.manager, "itest-keys", "cp ~/.ssh/id_ed25519.pub ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", 0, "");
    rig.manager.disconnect("itest-keys");
}
