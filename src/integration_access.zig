//! Spec 09 integration coverage (container): fleet scans (connected and
//! full), identity registry joins (people + unassigned), per-account sudo
//! status, sync errors for unreachable servers, offboard/onboard/rotate
//! jobs with conflict detection, and CSV/JSON export. Imported from
//! integration.zig so `zig build test` picks it up.
//!
//! One container serves as two "servers" (two sessions to the same box)
//! plus a dead-port server for the sync-error leg. Every setup step is
//! idempotent because the container persists between runs.

const std = @import("std");
const servers = @import("servers.zig");
const sshkeys = @import("sshkeys.zig");
const shellquote = @import("shellquote.zig");
const rig_mod = @import("integration.zig");
const integration_keys = @import("integration_keys.zig");

const TestRig = rig_mod.TestRig;
const testSleep = rig_mod.testSleep;
const execWait = rig_mod.execWait;
const execOut = rig_mod.execOut;
const waitForStatus = rig_mod.waitForStatus;
const keysGenerate = integration_keys.keysGenerate;

const AccessGrantResp = struct {
    fingerprint: []const u8 = "",
    server_id: []const u8 = "",
    server_name: []const u8 = "",
    user: []const u8 = "",
    sudo: []const u8 = "",
    comment: []const u8 = "",
    line_hash: []const u8 = "",
    source_path: []const u8 = "",
    file_sha256: []const u8 = "",
};

const AccessPersonResp = struct {
    identity_id: []const u8 = "",
    name: []const u8 = "",
    fingerprints: []const []const u8 = &.{},
    grants: []const AccessGrantResp = &.{},
};

const AccessUnassignedResp = struct {
    fingerprint: []const u8 = "",
    grants: []const AccessGrantResp = &.{},
};

const SavedIdentity = struct {
    id: []u8,
    revision: u64,

    fn deinit(self: *SavedIdentity) void {
        std.testing.allocator.free(self.id);
    }
};

const PollResp = struct {
    result: struct {
        ok: bool,
        scan_id: []const u8 = "",
        state: []const u8 = "",
        servers: []const struct {
            server_id: []const u8 = "",
            phase: []const u8 = "",
            @"error": []const u8 = "",
            connected_user: []const u8 = "",
            sudo: []const u8 = "",
            coverage: []const u8 = "",
            coverage_reason: []const u8 = "",
            accounts: []const struct {
                user: []const u8,
                skipped: bool = false,
                read: bool = false,
                @"error": []const u8 = "",
                sudo: []const u8 = "",
                key_count: usize = 0,
            } = &.{},
            sources: []const []const u8 = &.{},
        } = &.{},
        people_page: struct {
            total: usize = 0,
            rows: []const AccessPersonResp = &.{},
        },
        unassigned_page: struct {
            total: usize = 0,
            rows: []const AccessUnassignedResp = &.{},
        },
        metrics: struct {
            people: usize = 0,
            distinct_fingerprints: usize = 0,
            completed_servers: usize = 0,
            target_servers: usize = 0,
            observed_grants: usize = 0,
        },
        coverage: []const u8 = "",
        sync_errors: []const struct {
            server_id: []const u8 = "",
            reason: []const u8 = "",
        } = &.{},
    },
};

const JobPollResp = struct {
    result: struct {
        ok: bool,
        state: []const u8 = "",
        results: []const struct {
            server_id: []const u8 = "",
            user: []const u8 = "",
            state: []const u8 = "",
            @"error": []const u8 = "",
        } = &.{},
    },
};

/// Dispatches `oars.access.poll` until the scan is done (or fails).
/// Returns the final parsed response (caller deinits).
fn scanUntilDone(rig: *TestRig, scan_id: []const u8, timeout_ns: i128) !std.json.Parsed(PollResp) {
    var req_buf: [128]u8 = undefined;
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + timeout_ns;
    while (true) {
        const req = try std.fmt.bufPrint(&req_buf, "{{\"id\":\"sp\",\"command\":\"oars.access.poll\",\"payload\":{{\"scan_id\":\"{s}\"}}}}", .{scan_id});
        const resp = rig.dispatch(req);
        var parsed = try std.json.parseFromSlice(PollResp, std.testing.allocator, resp, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        });
        if (std.mem.eql(u8, parsed.value.result.state, "done")) return parsed;
        parsed.deinit();
        if (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds >= deadline) return error.TestUnexpectedResult;
        testSleep(60);
    }
}

/// Dispatches `oars.access.jobPoll` until every item is terminal.
fn jobUntilDone(rig: *TestRig, job_id: []const u8, timeout_ns: i128) !std.json.Parsed(JobPollResp) {
    var req_buf: [128]u8 = undefined;
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + timeout_ns;
    while (true) {
        const req = try std.fmt.bufPrint(&req_buf, "{{\"id\":\"jp\",\"command\":\"oars.access.jobPoll\",\"payload\":{{\"job_id\":\"{s}\"}}}}", .{job_id});
        const resp = rig.dispatch(req);
        var parsed = try std.json.parseFromSlice(JobPollResp, std.testing.allocator, resp, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        });
        if (!std.mem.eql(u8, parsed.value.result.state, "queued") and !std.mem.eql(u8, parsed.value.result.state, "running")) return parsed;
        parsed.deinit();
        if (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds >= deadline) return error.TestUnexpectedResult;
        testSleep(60);
    }
}

fn parseScanId(response: []const u8) ![]u8 {
    const StartResp = struct { result: struct { ok: bool, scan_id: []const u8 } };
    const parsed = std.json.parseFromSlice(StartResp, std.testing.allocator, response, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |err| {
        std.debug.print("TEST access scan start response: {s}\n", .{response});
        return err;
    };
    defer parsed.deinit();
    try std.testing.expect(parsed.value.result.ok);
    return std.testing.allocator.dupe(u8, parsed.value.result.scan_id);
}

fn parseJobId(response: []const u8) ![]u8 {
    const StartResp = struct { result: struct { ok: bool, job_id: []const u8 } };
    const parsed = std.json.parseFromSlice(StartResp, std.testing.allocator, response, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |err| {
        std.debug.print("TEST access job start response: {s}\n", .{response});
        return err;
    };
    defer parsed.deinit();
    try std.testing.expect(parsed.value.result.ok);
    return std.testing.allocator.dupe(u8, parsed.value.result.job_id);
}

/// The base64 blob of a public-key line (the only part that appears in
/// authorized_keys verbatim — comments get overridden).
fn keyBlob(line: []const u8) []const u8 {
    var tokens = std.mem.tokenizeAny(u8, line, " \t");
    _ = tokens.next(); // key type
    return tokens.next() orelse "";
}

/// Installs fixture data directly because this Spec 09 test exercises access
/// workflows, not the independently-covered SSH-key management API.
/// The normalized key line and path are shell-quoted before remote execution.
fn addKey(rig: *TestRig, server_id: []const u8, user: []const u8, public_key: []const u8, comment: []const u8) ![]u8 {
    const allocator = std.testing.allocator;
    const normalized = try sshkeys.normalizePublicKey(allocator, public_key, comment);
    defer allocator.free(normalized.line);
    errdefer allocator.free(normalized.fingerprint_sha256);

    const path = if (std.mem.eql(u8, user, "root"))
        try allocator.dupe(u8, "/root/.ssh/authorized_keys")
    else
        try std.fmt.allocPrint(allocator, "/home/{s}/.ssh/authorized_keys", .{user});
    defer allocator.free(path);
    const quoted_line = try shellquote.quote(allocator, normalized.line);
    defer allocator.free(quoted_line);
    const quoted_path = try shellquote.quote(allocator, path);
    defer allocator.free(quoted_path);
    const command = try std.fmt.allocPrint(allocator, "printf '%s\\n' {s} >> {s} && chmod 600 {s}", .{ quoted_line, quoted_path, quoted_path });
    defer allocator.free(command);
    try execWait(&rig.manager, server_id, command, 0, "");
    return normalized.fingerprint_sha256;
}

fn findGrant(scan: *const std.json.Parsed(PollResp), server_id: []const u8, user: []const u8, fingerprint: []const u8) ?*const AccessGrantResp {
    for (scan.value.result.people_page.rows) |*person| {
        for (person.grants) |*grant| {
            if (std.mem.eql(u8, grant.server_id, server_id) and std.mem.eql(u8, grant.user, user) and std.mem.eql(u8, grant.fingerprint, fingerprint)) return grant;
        }
    }
    for (scan.value.result.unassigned_page.rows) |*item| {
        for (item.grants) |*grant| {
            if (std.mem.eql(u8, grant.server_id, server_id) and std.mem.eql(u8, grant.user, user) and std.mem.eql(u8, grant.fingerprint, fingerprint)) return grant;
        }
    }
    return null;
}

test "integration: access scan, identities, offboard/onboard/rotate, export" {
    const env = rig_mod.TestEnv.load();
    if (!env.active) return;

    var rig: TestRig = undefined;
    try rig.init("access");
    defer rig.deinit();
    const io = std.testing.io;

    // Two sessions to the same container act as two fleet servers; a
    // dead-port server never connects (sync error leg).
    const server_a = servers.Server{
        .id = "itest-acc-1",
        .name = "dev-sshd",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
    };
    const server_b = servers.Server{
        .id = "itest-acc-2",
        .name = "dev-sshd-b",
        .host = env.host,
        .port = env.port,
        .user = env.user,
        .auth_method = .password,
    };
    const server_dead = servers.Server{
        .id = "itest-acc-dead",
        .name = "dead-box",
        .host = "127.0.0.1",
        .port = 59999,
        .user = env.user,
        .auth_method = .password,
    };
    try rig.store.upsert(io, server_a);
    try rig.store.upsert(io, server_b);
    try rig.store.upsert(io, server_dead);
    for ([_][]const u8{ "itest-acc-1", "itest-acc-2" }) |sid| {
        const server = if (std.mem.eql(u8, sid, "itest-acc-1")) server_a else server_b;
        _ = try rig.manager.connect(server, env.password, null);
        try waitForStatus(&rig.manager, sid, .needs_trust, 20 * std.time.ns_per_s);
        try rig.manager.trust(sid, true);
        try waitForStatus(&rig.manager, sid, .ready, 20 * std.time.ns_per_s);
    }

    // --- start clean (the container persists) ------------------------------
    try execWait(&rig.manager, "itest-acc-1", "rm -f /root/.ssh/authorized_keys /var/log/faillog /var/log/lastlog; userdel -r alice >/dev/null 2>&1; userdel -r carol >/dev/null 2>&1; userdel -r dave-ro >/dev/null 2>&1; rm -rf /home/alice /home/carol /home/dave-ro; rm -f /etc/oars-roles.json", 0, "");
    // Always restore the container's own key at the end — even on
    // mid-test failure — so the earlier key-auth test stays green. The
    // explicit restore below runs before the disconnect (the defer would
    // run after it and silently fail).
    defer {
        execWait(&rig.manager, "itest-acc-1", "cp /root/.ssh/id_ed25519.pub /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys", 0, "") catch {};
        for ([_][]const u8{ "acc-ada", "acc-ada2", "acc-bob", "acc-carol", "acc-un", "acc-dave" }) |tag| {
            var b: [256]u8 = undefined;
            const p = std.fmt.bufPrint(&b, "/tmp/oars-itest-key-{s}", .{tag}) catch continue;
            std.Io.Dir.cwd().deleteFile(io, p) catch {};
            var pb: [272]u8 = undefined;
            const pp = std.fmt.bufPrint(&pb, "{s}.pub", .{p}) catch continue;
            std.Io.Dir.cwd().deleteFile(io, pp) catch {};
        }
    }

    // Two plain users: alice has no sudo, carol has passwordless sudo
    // (the sudoers rule from the Dockerfile).
    try execWait(&rig.manager, "itest-acc-1", "useradd -m -s /bin/bash alice && useradd -m -s /bin/bash carol && mkdir -p /home/alice/.ssh /home/carol/.ssh && chmod 700 /home/alice/.ssh /home/carol/.ssh && touch /home/alice/.ssh/authorized_keys /home/carol/.ssh/authorized_keys && chmod 600 /home/alice/.ssh/authorized_keys /home/carol/.ssh/authorized_keys && chown -R alice:alice /home/alice/.ssh && chown -R carol:carol /home/carol/.ssh", 0, "");

    // --- keys and identities -----------------------------------------------
    var ada = try keysGenerate(&rig, "acc-ada");
    defer ada.deinit();
    var ada2 = try keysGenerate(&rig, "acc-ada2");
    defer ada2.deinit();
    var bob = try keysGenerate(&rig, "acc-bob");
    defer bob.deinit();
    var carol = try keysGenerate(&rig, "acc-carol");
    defer carol.deinit();
    var un = try keysGenerate(&rig, "acc-un");
    defer un.deinit();
    var dave = try keysGenerate(&rig, "acc-dave");
    defer dave.deinit();

    const fp_ada = try addKey(&rig, "itest-acc-1", "root", ada.value.result.public_key, "ada@mbp");
    defer std.testing.allocator.free(fp_ada);
    const fp_un = try addKey(&rig, "itest-acc-1", "root", un.value.result.public_key, "un@ghost");
    defer std.testing.allocator.free(fp_un);
    const fp_bob = try addKey(&rig, "itest-acc-1", "alice", bob.value.result.public_key, "bob@thinkpad");
    defer std.testing.allocator.free(fp_bob);
    const fp_carol = try addKey(&rig, "itest-acc-1", "carol", carol.value.result.public_key, "carol@work");
    defer std.testing.allocator.free(fp_carol);
    const fp_un2 = try addKey(&rig, "itest-acc-1", "alice", un.value.result.public_key, "un@ghost");
    defer std.testing.allocator.free(fp_un2);
    try std.testing.expectEqualStrings(fp_un, fp_un2);
    const seeded_root_keys = try execOut(&rig.manager, "itest-acc-1", "cat /root/.ssh/authorized_keys");
    defer std.testing.allocator.free(seeded_root_keys);
    try std.testing.expect(std.mem.indexOf(u8, seeded_root_keys, keyBlob(ada.value.result.public_key)) != null);
    try std.testing.expect(std.mem.indexOf(u8, seeded_root_keys, keyBlob(un.value.result.public_key)) != null);

    var fp_dave_buf: [256]u8 = undefined;
    const dave_fp = try deriveFingerprint(&rig, dave.value.result.public_key);
    defer std.testing.allocator.free(dave_fp);
    const ada_req = try std.fmt.bufPrint(&fp_dave_buf, "{{\"id\":\"id\",\"command\":\"oars.access.identities.save\",\"payload\":{{\"identity\":{{\"name\":\"Ada\",\"fingerprints\":[\"{s}\"]}}}}}}", .{fp_ada});
    const ada_saved = rig.dispatch(ada_req);
    try std.testing.expect(std.mem.indexOf(u8, ada_saved, "\"ok\":true") != null);
    var ada_identity = try parseIdentity(ada_saved);
    defer ada_identity.deinit();
    const ada_id = ada_identity.id;
    var bob_req_buf: [512]u8 = undefined;
    const bob_req = try std.fmt.bufPrint(&bob_req_buf, "{{\"id\":\"id\",\"command\":\"oars.access.identities.save\",\"payload\":{{\"identity\":{{\"name\":\"Bob\",\"fingerprints\":[\"{s}\"]}}}}}}", .{fp_bob});
    const bob_saved = rig.dispatch(bob_req);
    try std.testing.expect(std.mem.indexOf(u8, bob_saved, "\"ok\":true") != null);
    var bob_identity = try parseIdentity(bob_saved);
    defer bob_identity.deinit();
    const bob_id = bob_identity.id;
    var carol_req_buf: [512]u8 = undefined;
    const carol_req = try std.fmt.bufPrint(&carol_req_buf, "{{\"id\":\"id\",\"command\":\"oars.access.identities.save\",\"payload\":{{\"identity\":{{\"name\":\"Carol\",\"fingerprints\":[\"{s}\"]}}}}}}", .{fp_carol});
    const carol_saved = rig.dispatch(carol_req);
    try std.testing.expect(std.mem.indexOf(u8, carol_saved, "\"ok\":true") != null);

    // --- connected scan: root only, sudo yes, complete coverage -----------
    const scan1 = rig.dispatch(
        \\{"id":"s1","command":"oars.access.scan","payload":{"server_ids":["itest-acc-1","itest-acc-2"]}}
    );
    const scan1_id = try parseScanId(scan1);
    defer std.testing.allocator.free(scan1_id);
    var scan1_parsed = try scanUntilDone(&rig, scan1_id, 40 * std.time.ns_per_s);
    defer scan1_parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), scan1_parsed.value.result.servers.len);
    for (scan1_parsed.value.result.servers) |*s| {
        try std.testing.expectEqualStrings("done", s.phase);
        if (!std.mem.eql(u8, s.coverage, "complete")) {
            std.debug.print("TEST access scan server={s} coverage={s} reason={s} error={s}\n", .{ s.server_id, s.coverage, s.coverage_reason, s.@"error" });
            for (s.accounts) |a| std.debug.print("TEST access account={s} read={} error={s}\n", .{ a.user, a.read, a.@"error" });
            for (s.sources) |source| std.debug.print("TEST access source={s}\n", .{source});
        }
        try std.testing.expectEqualStrings("complete", s.coverage);
        try std.testing.expectEqualStrings("root", s.connected_user);
        try std.testing.expectEqualStrings("full", s.sudo);
        try std.testing.expectEqual(@as(usize, 1), s.accounts.len);
        try std.testing.expectEqualStrings("root", s.accounts[0].user);
        try std.testing.expectEqual(@as(usize, 2), s.accounts[0].key_count);
    }
    // All saved identities remain visible; only Ada has observed grants in
    // connected-account scope. The other root key is explicitly unassigned.
    try std.testing.expectEqual(@as(usize, 3), scan1_parsed.value.result.people_page.rows.len);
    var scan1_ada: ?*const AccessPersonResp = null;
    for (scan1_parsed.value.result.people_page.rows) |*person| {
        if (std.mem.eql(u8, person.name, "Ada")) scan1_ada = person;
    }
    try std.testing.expect(scan1_ada != null);
    try std.testing.expectEqual(@as(usize, 2), scan1_ada.?.grants.len);
    try std.testing.expectEqual(@as(usize, 1), scan1_parsed.value.result.unassigned_page.rows.len);
    try std.testing.expectEqualStrings(fp_un, scan1_parsed.value.result.unassigned_page.rows[0].fingerprint);
    try std.testing.expectEqual(@as(usize, 2), scan1_parsed.value.result.unassigned_page.rows[0].grants.len);
    try std.testing.expectEqual(@as(usize, 4), scan1_parsed.value.result.metrics.observed_grants);

    // --- full scan: all accounts, per-account sudo, unassigned keys ------
    const scan2 = rig.dispatch(
        \\{"id":"s2","command":"oars.access.scan","payload":{"server_ids":["itest-acc-1","itest-acc-2"],"scope":"all_login_accounts","approved_sensitive_read":true}}
    );
    const scan2_id = try parseScanId(scan2);
    defer std.testing.allocator.free(scan2_id);
    var scan2_parsed = try scanUntilDone(&rig, scan2_id, 60 * std.time.ns_per_s);
    defer scan2_parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), scan2_parsed.value.result.servers.len);
    for (scan2_parsed.value.result.servers) |*s| {
        try std.testing.expectEqualStrings("done", s.phase);
        try std.testing.expectEqualStrings("complete", s.coverage);
        // Full scope records every passwd entry. Login-capable accounts are
        // read; service/nologin accounts remain visible as skipped rows.
        try std.testing.expect(s.accounts.len >= 4);
        var saw_root = false;
        var saw_alice = false;
        var saw_carol = false;
        var saw_nobody = false;
        for (s.accounts) |*a| {
            if (std.mem.eql(u8, a.user, "nobody")) {
                saw_nobody = true;
                try std.testing.expect(a.skipped);
            }
            if (std.mem.eql(u8, a.user, "alice")) {
                saw_alice = true;
                try std.testing.expect(a.read);
                try std.testing.expectEqualStrings("none", a.sudo);
                try std.testing.expectEqual(@as(usize, 2), a.key_count); // bob + un
            }
            if (std.mem.eql(u8, a.user, "carol")) {
                saw_carol = true;
                try std.testing.expect(a.read);
                try std.testing.expectEqualStrings("full", a.sudo);
                try std.testing.expectEqual(@as(usize, 1), a.key_count);
            }
            if (std.mem.eql(u8, a.user, "root")) {
                saw_root = true;
                try std.testing.expectEqualStrings("full", a.sudo);
            }
        }
        try std.testing.expect(saw_root and saw_alice and saw_carol and saw_nobody);
    }
    // People: Ada (2 grants — one per server), Bob (2), Carol (2);
    // unassigned: fp_un with 4 grants (root + alice on both servers).
    try std.testing.expectEqual(@as(usize, 3), scan2_parsed.value.result.people_page.rows.len);
    try std.testing.expectEqual(@as(usize, 1), scan2_parsed.value.result.unassigned_page.rows.len);
    try std.testing.expectEqualStrings(fp_un, scan2_parsed.value.result.unassigned_page.rows[0].fingerprint);
    try std.testing.expectEqual(@as(usize, 4), scan2_parsed.value.result.unassigned_page.rows[0].grants.len);
    try std.testing.expectEqual(@as(usize, 10), scan2_parsed.value.result.metrics.observed_grants);
    try std.testing.expectEqual(@as(usize, 2), scan2_parsed.value.result.metrics.completed_servers);
    try std.testing.expectEqualStrings("complete", scan2_parsed.value.result.coverage);
    var ada_seen = false;
    var bob_seen = false;
    var carol_seen = false;
    for (scan2_parsed.value.result.people_page.rows) |*p| {
        if (std.mem.eql(u8, p.name, "Ada")) {
            ada_seen = true;
            try std.testing.expectEqual(@as(usize, 2), p.grants.len);
            try std.testing.expectEqualStrings("full", p.grants[0].sudo);
        }
        if (std.mem.eql(u8, p.name, "Bob")) {
            bob_seen = true;
            try std.testing.expectEqual(@as(usize, 2), p.grants.len);
            try std.testing.expectEqualStrings("none", p.grants[0].sudo);
        }
        if (std.mem.eql(u8, p.name, "Carol")) {
            carol_seen = true;
            try std.testing.expectEqual(@as(usize, 2), p.grants.len);
            try std.testing.expectEqualStrings("full", p.grants[0].sudo);
        }
    }
    try std.testing.expect(ada_seen and bob_seen and carol_seen);

    // --- sync error: the dead server is flagged, never silent -------------
    const scan3 = rig.dispatch(
        \\{"id":"s3","command":"oars.access.scan","payload":{"server_ids":["itest-acc-1","itest-acc-dead"]}}
    );
    const scan3_id = try parseScanId(scan3);
    defer std.testing.allocator.free(scan3_id);
    var scan3_parsed = try scanUntilDone(&rig, scan3_id, 40 * std.time.ns_per_s);
    defer scan3_parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), scan3_parsed.value.result.sync_errors.len);
    try std.testing.expectEqualStrings("itest-acc-dead", scan3_parsed.value.result.sync_errors[0].server_id);
    try std.testing.expect(std.mem.indexOf(u8, scan3_parsed.value.result.sync_errors[0].reason, "not connected") != null);
    try std.testing.expectEqualStrings("partial", scan3_parsed.value.result.coverage);

    // --- offboard: Bob's key dies on itest-acc-1 ---------------------------
    const bob_grant = findGrant(&scan2_parsed, "itest-acc-1", "alice", fp_bob) orelse return error.TestUnexpectedResult;
    var off_buf: [2048]u8 = undefined;
    const off_req = try std.fmt.bufPrint(&off_buf, "{{\"id\":\"o1\",\"command\":\"oars.access.offboard\",\"payload\":{{\"operation_id\":\"itest-access-offboard-1\",\"scan_id\":\"{s}\",\"identity_id\":\"{s}\",\"identity_revision\":{d},\"confirm_name\":\"Bob\",\"grants\":[{{\"fingerprint\":\"{s}\",\"server_id\":\"itest-acc-1\",\"user\":\"alice\",\"line_hash\":\"{s}\",\"source_path\":\"{s}\",\"file_sha256\":\"{s}\"}}]}}}}", .{ scan2_id, bob_id, bob_identity.revision, fp_bob, bob_grant.line_hash, bob_grant.source_path, bob_grant.file_sha256 });
    const off_resp = rig.dispatch(off_req);
    const job1_id = try parseJobId(off_resp);
    defer std.testing.allocator.free(job1_id);
    var job1 = try jobUntilDone(&rig, job1_id, 30 * std.time.ns_per_s);
    defer job1.deinit();
    try std.testing.expectEqual(@as(usize, 1), job1.value.result.results.len);
    try std.testing.expectEqualStrings("done", job1.value.result.results[0].state);
    const alice_keys = try execOut(&rig.manager, "itest-acc-1", "cat /home/alice/.ssh/authorized_keys");
    defer std.testing.allocator.free(alice_keys);
    try std.testing.expect(std.mem.indexOf(u8, alice_keys, keyBlob(bob.value.result.public_key)) == null);
    try std.testing.expect(std.mem.indexOf(u8, alice_keys, keyBlob(un.value.result.public_key)) != null); // untouched

    // A stale line hash is a conflict, never a silent overwrite: re-add
    // Bob's key with a different comment (so the line hash differs from
    // the scan's snapshot) and try to offboard with the old hash — the
    // key is still there, so the writer must refuse.
    const readded_fp = try addKey(&rig, "itest-acc-1", "alice", bob.value.result.public_key, "bob@new-laptop");
    defer std.testing.allocator.free(readded_fp);
    try std.testing.expectEqualStrings(fp_bob, readded_fp);
    var off2_buf: [2048]u8 = undefined;
    const off2_req = try std.fmt.bufPrint(&off2_buf, "{{\"id\":\"o2\",\"command\":\"oars.access.offboard\",\"payload\":{{\"operation_id\":\"itest-access-offboard-2\",\"scan_id\":\"{s}\",\"identity_id\":\"{s}\",\"identity_revision\":{d},\"confirm_name\":\"Bob\",\"grants\":[{{\"fingerprint\":\"{s}\",\"server_id\":\"itest-acc-1\",\"user\":\"alice\",\"line_hash\":\"{s}\",\"source_path\":\"{s}\",\"file_sha256\":\"{s}\"}}]}}}}", .{ scan2_id, bob_id, bob_identity.revision, fp_bob, bob_grant.line_hash, bob_grant.source_path, bob_grant.file_sha256 });
    const off2 = rig.dispatch(off2_req);
    const job2_id = try parseJobId(off2);
    defer std.testing.allocator.free(job2_id);
    var job2 = try jobUntilDone(&rig, job2_id, 30 * std.time.ns_per_s);
    defer job2.deinit();
    try std.testing.expectEqualStrings("conflict", job2.value.result.results[0].state);
    try std.testing.expect(std.mem.indexOf(u8, job2.value.result.results[0].@"error", "changed since the preview") != null);
    // The refused write left the re-added key untouched.
    const alice_after = try execOut(&rig.manager, "itest-acc-1", "cat /home/alice/.ssh/authorized_keys");
    defer std.testing.allocator.free(alice_after);
    try std.testing.expect(std.mem.indexOf(u8, alice_after, keyBlob(bob.value.result.public_key)) != null);

    // --- onboard: Dave gets plain access to carol and a read-only role ----
    var dave_ident_buf: [512]u8 = undefined;
    const dave_ident = try std.fmt.bufPrint(&dave_ident_buf, "{{\"id\":\"i2\",\"command\":\"oars.access.identities.save\",\"payload\":{{\"identity\":{{\"name\":\"Dave\",\"fingerprints\":[\"{s}\"]}}}}}}", .{dave_fp});
    const dave_saved = rig.dispatch(dave_ident);
    try std.testing.expect(std.mem.indexOf(u8, dave_saved, "\"ok\":true") != null);
    var dave_identity = try parseIdentity(dave_saved);
    defer dave_identity.deinit();
    const dave_id = dave_identity.id;
    var on_buf: [4096]u8 = undefined;
    const on_req = try std.fmt.bufPrint(&on_buf, "{{\"id\":\"n1\",\"command\":\"oars.access.onboard\",\"payload\":{{\"operation_id\":\"itest-access-onboard-1\",\"identity_id\":\"{s}\",\"identity_revision\":{d},\"public_key\":\"{s}\",\"grants\":[{{\"server_id\":\"itest-acc-1\",\"target\":{{\"kind\":\"account\",\"name\":\"carol\"}}}},{{\"server_id\":\"itest-acc-1\",\"target\":{{\"kind\":\"read_only_role\",\"name\":\"dave-ro\"}}}}]}}}}", .{ dave_id, dave_identity.revision, dave.value.result.public_key });
    const on_resp = rig.dispatch(on_req);
    const job3_id = try parseJobId(on_resp);
    defer std.testing.allocator.free(job3_id);
    var job3 = try jobUntilDone(&rig, job3_id, 40 * std.time.ns_per_s);
    defer job3.deinit();
    try std.testing.expectEqual(@as(usize, 2), job3.value.result.results.len);
    try std.testing.expectEqualStrings("done", job3.value.result.results[0].state);
    try std.testing.expectEqualStrings("done", job3.value.result.results[1].state);
    // The read-only role was created with the forced command.
    const ro_keys = try execOut(&rig.manager, "itest-acc-1", "cat /home/dave-ro/.ssh/authorized_keys");
    defer std.testing.allocator.free(ro_keys);
    try std.testing.expect(std.mem.indexOf(u8, ro_keys, "restrict") != null);
    try std.testing.expect(std.mem.indexOf(u8, ro_keys, "internal-sftp -R") != null);
    try std.testing.expect(std.mem.indexOf(u8, ro_keys, keyBlob(dave.value.result.public_key)) != null);

    // Idempotent: onboarding the same key again is a no-op, not a dupe.
    var on2_buf: [4096]u8 = undefined;
    const on2_req = try std.fmt.bufPrint(&on2_buf, "{{\"id\":\"n2\",\"command\":\"oars.access.onboard\",\"payload\":{{\"operation_id\":\"itest-access-onboard-2\",\"identity_id\":\"{s}\",\"identity_revision\":{d},\"public_key\":\"{s}\",\"grants\":[{{\"server_id\":\"itest-acc-1\",\"target\":{{\"kind\":\"account\",\"name\":\"carol\"}}}}]}}}}", .{ dave_id, dave_identity.revision, dave.value.result.public_key });
    const on2 = rig.dispatch(on2_req);
    const job4_id = try parseJobId(on2);
    defer std.testing.allocator.free(job4_id);
    var job4 = try jobUntilDone(&rig, job4_id, 30 * std.time.ns_per_s);
    defer job4.deinit();
    try std.testing.expectEqualStrings("done", job4.value.result.results[0].state);
    const carol_keys = try execOut(&rig.manager, "itest-acc-1", "grep -c Dave /home/carol/.ssh/authorized_keys");
    defer std.testing.allocator.free(carol_keys);
    try std.testing.expect(std.mem.indexOf(u8, carol_keys, "1") != null);

    // --- rotate: Ada's key is replaced on itest-acc-1 ----------------------
    const ada_grant = findGrant(&scan2_parsed, "itest-acc-1", "root", fp_ada) orelse return error.TestUnexpectedResult;
    var rot_buf: [4096]u8 = undefined;
    const rot_req = try std.fmt.bufPrint(&rot_buf, "{{\"id\":\"r1\",\"command\":\"oars.access.rotate\",\"payload\":{{\"operation_id\":\"itest-access-rotate-1\",\"scan_id\":\"{s}\",\"identity_id\":\"{s}\",\"identity_revision\":{d},\"old_fingerprint\":\"{s}\",\"new_public_key\":\"{s}\",\"grants\":[{{\"server_id\":\"itest-acc-1\",\"user\":\"root\",\"line_hash\":\"{s}\",\"source_path\":\"{s}\",\"file_sha256\":\"{s}\"}}]}}}}", .{ scan2_id, ada_id, ada_identity.revision, fp_ada, ada2.value.result.public_key, ada_grant.line_hash, ada_grant.source_path, ada_grant.file_sha256 });
    const rot_resp = rig.dispatch(rot_req);
    const job5_id = try parseJobId(rot_resp);
    defer std.testing.allocator.free(job5_id);
    var job5 = try jobUntilDone(&rig, job5_id, 30 * std.time.ns_per_s);
    defer job5.deinit();
    try std.testing.expectEqualStrings("done", job5.value.result.results[0].state);
    const root_keys = try execOut(&rig.manager, "itest-acc-1", "cat /root/.ssh/authorized_keys");
    defer std.testing.allocator.free(root_keys);
    try std.testing.expect(std.mem.indexOf(u8, root_keys, keyBlob(ada.value.result.public_key)) == null);
    try std.testing.expect(std.mem.indexOf(u8, root_keys, keyBlob(ada2.value.result.public_key)) != null);

    // --- export ------------------------------------------------------------
    var csv_path_buf: [512]u8 = undefined;
    const csv_path = try std.fmt.bufPrint(&csv_path_buf, "/tmp/{s}/access.csv", .{rig.dir_name});
    var csv_req_buf: [1024]u8 = undefined;
    const csv_req = try std.fmt.bufPrint(&csv_req_buf, "{{\"id\":\"e1\",\"command\":\"oars.access.export\",\"payload\":{{\"format\":\"csv\",\"scan_id\":\"{s}\",\"path\":\"{s}\"}}}}", .{ scan2_id, csv_path });
    const csv_resp = rig.dispatch(csv_req);
    try std.testing.expect(std.mem.indexOf(u8, csv_resp, "\"ok\":true") != null);
    const csv_content = try std.Io.Dir.cwd().readFileAlloc(io, csv_path, std.testing.allocator, .limited(256 * 1024));
    defer std.testing.allocator.free(csv_content);
    try std.testing.expect(std.mem.indexOf(u8, csv_content, "Ada") != null);
    try std.testing.expect(std.mem.indexOf(u8, csv_content, "Bob") != null);
    try std.testing.expect(std.mem.indexOf(u8, csv_content, "row_type,scan_id,scope,coverage,identity_id,name,fingerprint") != null);

    var json_path_buf: [512]u8 = undefined;
    const json_path = try std.fmt.bufPrint(&json_path_buf, "/tmp/{s}/access.json", .{rig.dir_name});
    var json_req_buf: [1024]u8 = undefined;
    const json_req = try std.fmt.bufPrint(&json_req_buf, "{{\"id\":\"e2\",\"command\":\"oars.access.export\",\"payload\":{{\"format\":\"json\",\"scan_id\":\"{s}\",\"path\":\"{s}\"}}}}", .{ scan2_id, json_path });
    const json_resp = rig.dispatch(json_req);
    try std.testing.expect(std.mem.indexOf(u8, json_resp, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_resp, "\"format\":\"json\"") != null);
    const json_content = try std.Io.Dir.cwd().readFileAlloc(io, json_path, std.testing.allocator, .limited(256 * 1024));
    defer std.testing.allocator.free(json_content);
    try std.testing.expect(std.mem.indexOf(u8, json_content, "\"people\"") != null);

    // --- every mutation was audited ----------------------------------------
    const audit_content = try std.Io.Dir.cwd().readFileAlloc(io, rig.audit_store.path, std.testing.allocator, .limited(256 * 1024));
    defer std.testing.allocator.free(audit_content);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "access.offboard") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "access.onboard") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "access.rotate") != null);

    // Restore the container's own key BEFORE disconnecting (the defer
    // above only covers mid-test failures — it runs after this
    // disconnect and would silently fail).
    try execWait(&rig.manager, "itest-acc-1", "cp /root/.ssh/id_ed25519.pub /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys", 0, "");
    rig.manager.disconnect("itest-acc-1");
    rig.manager.disconnect("itest-acc-2");
}

/// Derives the fingerprint of a public key the way the scan does: parse
/// the line and compute the SHA-256 fingerprint.
fn deriveFingerprint(rig: *TestRig, public_key: []const u8) ![]const u8 {
    _ = rig;
    const normalized = try sshkeys.normalizePublicKey(std.testing.allocator, public_key, null);
    defer {
        std.testing.allocator.free(normalized.line);
        std.testing.allocator.free(normalized.fingerprint_sha256);
    }
    return std.testing.allocator.dupe(u8, normalized.fingerprint_sha256);
}

/// Extracts the cryptographically random identity id and revision from the
/// current identities.save response envelope.
fn parseIdentity(response: []const u8) !SavedIdentity {
    const IdentitySaveResp = struct {
        result: struct {
            ok: bool,
            identity: struct { id: []const u8, revision: u64 },
        },
    };
    const parsed = try std.json.parseFromSlice(IdentitySaveResp, std.testing.allocator, response, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer parsed.deinit();
    try std.testing.expect(parsed.value.result.ok);
    return .{
        .id = try std.testing.allocator.dupe(u8, parsed.value.result.identity.id),
        .revision = parsed.value.result.identity.revision,
    };
}
