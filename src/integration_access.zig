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
const rig_mod = @import("integration.zig");
const integration_keys = @import("integration_keys.zig");

const TestRig = rig_mod.TestRig;
const testSleep = rig_mod.testSleep;
const execWait = rig_mod.execWait;
const execOut = rig_mod.execOut;
const waitForStatus = rig_mod.waitForStatus;
const keysGenerate = integration_keys.keysGenerate;

const PollResp = struct {
    result: struct {
        ok: bool,
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
                sudo: []const u8 = "",
                key_count: usize = 0,
            } = &.{},
            grants: []const struct {
                fingerprint: []const u8 = "",
                user: []const u8 = "",
                sudo: []const u8 = "",
                comment: []const u8 = "",
                line_hash: []const u8 = "",
            } = &.{},
        } = &.{},
        people: []const struct {
            identity_id: []const u8 = "",
            name: []const u8 = "",
            fingerprints: []const []const u8 = &.{},
            grants: []const struct {
                fingerprint: []const u8 = "",
                server_id: []const u8 = "",
                server_name: []const u8 = "",
                user: []const u8 = "",
                sudo: []const u8 = "",
                comment: []const u8 = "",
                line_hash: []const u8 = "",
            } = &.{},
        } = &.{},
        unassigned: []const struct {
            fingerprint: []const u8 = "",
            grants: []const struct {
                fingerprint: []const u8 = "",
                server_id: []const u8 = "",
                user: []const u8 = "",
                sudo: []const u8 = "",
                line_hash: []const u8 = "",
            } = &.{},
        } = &.{},
        servers_count: usize = 0,
        grants_count: usize = 0,
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

const AddResp = struct {
    result: struct {
        ok: bool,
        fingerprint: []const u8 = "",
        line_hash: []const u8 = "",
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
        if (std.mem.eql(u8, parsed.value.result.state, "done")) return parsed;
        parsed.deinit();
        if (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds >= deadline) return error.TestUnexpectedResult;
        testSleep(60);
    }
}

/// The base64 blob of a public-key line (the only part that appears in
/// authorized_keys verbatim — comments get overridden).
fn keyBlob(line: []const u8) []const u8 {
    var tokens = std.mem.tokenizeAny(u8, line, " \t");
    _ = tokens.next(); // key type
    return tokens.next() orelse "";
}

/// Adds a key through the dispatcher; returns the parsed response.
fn addKey(rig: *TestRig, server_id: []const u8, user: []const u8, public_key: []const u8, comment: []const u8) !std.json.Parsed(AddResp) {
    var req_buf: [4096]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "{{\"id\":\"ak\",\"command\":\"oars.sshkeys.add\",\"payload\":{{\"server_id\":\"{s}\",\"user\":\"{s}\",\"public_key\":\"{s}\",\"comment\":\"{s}\"}}}}", .{ server_id, user, public_key, comment });
    const resp = rig.dispatch(req);
    return std.json.parseFromSlice(AddResp, std.testing.allocator, resp, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

fn grantLineHash(scan: *const std.json.Parsed(PollResp), server_id: []const u8, user: []const u8, fingerprint: []const u8) ?[]const u8 {
    for (scan.value.result.servers) |*s| {
        if (!std.mem.eql(u8, s.server_id, server_id)) continue;
        for (s.grants) |*g| {
            if (std.mem.eql(u8, g.user, user) and std.mem.eql(u8, g.fingerprint, fingerprint)) {
                return g.line_hash;
            }
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
    try execWait(&rig.manager, "itest-acc-1", "useradd -m -s /bin/bash -p '' alice && useradd -m -s /bin/bash -p '' carol && mkdir -p /home/alice/.ssh /home/carol/.ssh && chmod 700 /home/alice/.ssh /home/carol/.ssh && touch /home/alice/.ssh/authorized_keys /home/carol/.ssh/authorized_keys && chmod 600 /home/alice/.ssh/authorized_keys /home/carol/.ssh/authorized_keys && chown -R alice:alice /home/alice/.ssh && chown -R carol:carol /home/carol/.ssh", 0, "");

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

    var add_ada = try addKey(&rig, "itest-acc-1", "root", ada.value.result.public_key, "ada@mbp");
    defer add_ada.deinit();
    try std.testing.expect(add_ada.value.result.ok);
    const fp_ada = add_ada.value.result.fingerprint;
    var add_un = try addKey(&rig, "itest-acc-1", "root", un.value.result.public_key, "un@ghost");
    defer add_un.deinit();
    try std.testing.expect(add_un.value.result.ok);
    const fp_un = add_un.value.result.fingerprint;
    var add_bob = try addKey(&rig, "itest-acc-1", "alice", bob.value.result.public_key, "bob@thinkpad");
    defer add_bob.deinit();
    try std.testing.expect(add_bob.value.result.ok);
    const fp_bob = add_bob.value.result.fingerprint;
    var add_carol = try addKey(&rig, "itest-acc-1", "carol", carol.value.result.public_key, "carol@work");
    defer add_carol.deinit();
    try std.testing.expect(add_carol.value.result.ok);
    const fp_carol = add_carol.value.result.fingerprint;
    var add_un2 = try addKey(&rig, "itest-acc-1", "alice", un.value.result.public_key, "un@ghost");
    defer add_un2.deinit();
    try std.testing.expect(add_un2.value.result.ok);

    var fp_dave_buf: [256]u8 = undefined;
    const dave_fp = try deriveFingerprint(&rig, dave.value.result.public_key);
    defer std.testing.allocator.free(dave_fp);
    const ada_req = try std.fmt.bufPrint(&fp_dave_buf, "{{\"id\":\"id\",\"command\":\"oars.access.identities.save\",\"payload\":{{\"identity\":{{\"name\":\"Ada\",\"fingerprints\":[\"{s}\"]}}}}}}", .{fp_ada});
    const ada_saved = rig.dispatch(ada_req);
    try std.testing.expect(std.mem.indexOf(u8, ada_saved, "\"ok\":true") != null);
    const ada_id = try parseIdentityId(ada_saved);
    defer std.testing.allocator.free(ada_id);
    var bob_req_buf: [512]u8 = undefined;
    const bob_req = try std.fmt.bufPrint(&bob_req_buf, "{{\"id\":\"id\",\"command\":\"oars.access.identities.save\",\"payload\":{{\"identity\":{{\"name\":\"Bob\",\"fingerprints\":[\"{s}\"]}}}}}}", .{fp_bob});
    const bob_saved = rig.dispatch(bob_req);
    try std.testing.expect(std.mem.indexOf(u8, bob_saved, "\"ok\":true") != null);
    const bob_id = try parseIdentityId(bob_saved);
    defer std.testing.allocator.free(bob_id);
    var carol_req_buf: [512]u8 = undefined;
    const carol_req = try std.fmt.bufPrint(&carol_req_buf, "{{\"id\":\"id\",\"command\":\"oars.access.identities.save\",\"payload\":{{\"identity\":{{\"name\":\"Carol\",\"fingerprints\":[\"{s}\"]}}}}}}", .{fp_carol});
    const carol_saved = rig.dispatch(carol_req);
    try std.testing.expect(std.mem.indexOf(u8, carol_saved, "\"ok\":true") != null);

    // --- connected scan: root only, sudo yes, complete coverage -----------
    const scan1 = rig.dispatch(
        \\{"id":"s1","command":"oars.access.scan","payload":{"server_ids":["itest-acc-1","itest-acc-2"]}}
    );
    try std.testing.expect(std.mem.indexOf(u8, scan1, "\"ok\":true") != null);
    const scan1_id_start = std.mem.indexOf(u8, scan1, "\"scan_id\":\"scan-") orelse return error.TestUnexpectedResult;
    var scan1_id_buf: [32]u8 = undefined;
    var scan1_id_len: usize = 0;
    for (scan1[scan1_id_start + 11 ..]) |ch| {
        if (ch == '"') break;
        if (scan1_id_len >= scan1_id_buf.len) return error.TestUnexpectedResult;
        scan1_id_buf[scan1_id_len] = ch;
        scan1_id_len += 1;
    }
    const scan1_id = scan1_id_buf[0..scan1_id_len];
    var scan1_parsed = try scanUntilDone(&rig, scan1_id, 40 * std.time.ns_per_s);
    defer scan1_parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), scan1_parsed.value.result.servers.len);
    for (scan1_parsed.value.result.servers) |*s| {
        try std.testing.expectEqualStrings("done", s.phase);
        try std.testing.expectEqualStrings("complete", s.coverage);
        try std.testing.expectEqualStrings("root", s.connected_user);
        try std.testing.expectEqualStrings("yes", s.sudo);
        try std.testing.expectEqual(@as(usize, 1), s.accounts.len);
        try std.testing.expectEqualStrings("root", s.accounts[0].user);
        // Root's file carries fp_ada + fp_un.
        var found_ada = false;
        var found_un = false;
        for (s.grants) |*g| {
            if (std.mem.eql(u8, g.fingerprint, fp_ada)) found_ada = true;
            if (std.mem.eql(u8, g.fingerprint, fp_un)) found_un = true;
        }
        try std.testing.expect(found_ada and found_un);
    }
    // Both servers: the same physical box, so the people map shows Ada's
    // grant on each of them.
    try std.testing.expectEqual(@as(usize, 4), scan1_parsed.value.result.grants_count);

    // --- full scan: all accounts, per-account sudo, unassigned keys ------
    const scan2 = rig.dispatch(
        \\{"id":"s2","command":"oars.access.scan","payload":{"server_ids":["itest-acc-1","itest-acc-2"],"full":true}}
    );
    const scan2_id_start = std.mem.indexOf(u8, scan2, "\"scan_id\":\"scan-") orelse return error.TestUnexpectedResult;
    var scan2_id_buf: [32]u8 = undefined;
    var scan2_id_len: usize = 0;
    for (scan2[scan2_id_start + 11 ..]) |ch| {
        if (ch == '"') break;
        if (scan2_id_len >= scan2_id_buf.len) return error.TestUnexpectedResult;
        scan2_id_buf[scan2_id_len] = ch;
        scan2_id_len += 1;
    }
    const scan2_id = scan2_id_buf[0..scan2_id_len];
    var scan2_parsed = try scanUntilDone(&rig, scan2_id, 60 * std.time.ns_per_s);
    defer scan2_parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), scan2_parsed.value.result.servers.len);
    for (scan2_parsed.value.result.servers) |*s| {
        try std.testing.expectEqualStrings("done", s.phase);
        try std.testing.expectEqualStrings("complete", s.coverage);
        // root (seeded) + alice + carol + nobody (skipped nologin).
        try std.testing.expectEqual(@as(usize, 4), s.accounts.len);
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
                try std.testing.expectEqualStrings("no", a.sudo);
                try std.testing.expectEqual(@as(usize, 2), a.key_count); // bob + un
            }
            if (std.mem.eql(u8, a.user, "carol")) {
                saw_carol = true;
                try std.testing.expect(a.read);
                try std.testing.expectEqualStrings("yes", a.sudo);
                try std.testing.expectEqual(@as(usize, 1), a.key_count);
            }
            if (std.mem.eql(u8, a.user, "root")) {
                try std.testing.expectEqualStrings("yes", a.sudo);
            }
        }
        try std.testing.expect(saw_alice and saw_carol and saw_nobody);
    }
    // People: Ada (2 grants — one per server), Bob (2), Carol (2);
    // unassigned: fp_un with 4 grants (root + alice on both servers).
    try std.testing.expectEqual(@as(usize, 3), scan2_parsed.value.result.people.len);
    try std.testing.expectEqual(@as(usize, 1), scan2_parsed.value.result.unassigned.len);
    try std.testing.expectEqualStrings(fp_un, scan2_parsed.value.result.unassigned[0].fingerprint);
    try std.testing.expectEqual(@as(usize, 4), scan2_parsed.value.result.unassigned[0].grants.len);
    try std.testing.expectEqual(@as(usize, 10), scan2_parsed.value.result.grants_count);
    try std.testing.expectEqual(@as(usize, 2), scan2_parsed.value.result.servers_count);
    try std.testing.expectEqualStrings("complete", scan2_parsed.value.result.coverage);
    var ada_seen = false;
    var bob_seen = false;
    var carol_seen = false;
    for (scan2_parsed.value.result.people) |*p| {
        if (std.mem.eql(u8, p.name, "Ada")) {
            ada_seen = true;
            try std.testing.expectEqual(@as(usize, 2), p.grants.len);
            try std.testing.expectEqualStrings("yes", p.grants[0].sudo);
        }
        if (std.mem.eql(u8, p.name, "Bob")) {
            bob_seen = true;
            try std.testing.expectEqual(@as(usize, 2), p.grants.len);
            try std.testing.expectEqualStrings("no", p.grants[0].sudo);
        }
        if (std.mem.eql(u8, p.name, "Carol")) {
            carol_seen = true;
            try std.testing.expectEqual(@as(usize, 2), p.grants.len);
            try std.testing.expectEqualStrings("yes", p.grants[0].sudo);
        }
    }
    try std.testing.expect(ada_seen and bob_seen and carol_seen);

    // --- sync error: the dead server is flagged, never silent -------------
    const scan3 = rig.dispatch(
        \\{"id":"s3","command":"oars.access.scan","payload":{"server_ids":["itest-acc-1","itest-acc-dead"]}}
    );
    const scan3_id_start = std.mem.indexOf(u8, scan3, "\"scan_id\":\"scan-") orelse return error.TestUnexpectedResult;
    var scan3_id_buf: [32]u8 = undefined;
    var scan3_id_len: usize = 0;
    for (scan3[scan3_id_start + 11 ..]) |ch| {
        if (ch == '"') break;
        if (scan3_id_len >= scan3_id_buf.len) return error.TestUnexpectedResult;
        scan3_id_buf[scan3_id_len] = ch;
        scan3_id_len += 1;
    }
    const scan3_id = scan3_id_buf[0..scan3_id_len];
    var scan3_parsed = try scanUntilDone(&rig, scan3_id, 40 * std.time.ns_per_s);
    defer scan3_parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), scan3_parsed.value.result.sync_errors.len);
    try std.testing.expectEqualStrings("itest-acc-dead", scan3_parsed.value.result.sync_errors[0].server_id);
    try std.testing.expect(std.mem.indexOf(u8, scan3_parsed.value.result.sync_errors[0].reason, "not connected") != null);
    try std.testing.expectEqualStrings("partial", scan3_parsed.value.result.coverage);

    // --- offboard: Bob's key dies on itest-acc-1 ---------------------------
    const bob_hash = grantLineHash(&scan2_parsed, "itest-acc-1", "alice", fp_bob) orelse return error.TestUnexpectedResult;
    var off_buf: [1024]u8 = undefined;
    const off_req = try std.fmt.bufPrint(&off_buf, "{{\"id\":\"o1\",\"command\":\"oars.access.offboard\",\"payload\":{{\"identity_id\":\"{s}\",\"grants\":[{{\"fingerprint\":\"{s}\",\"server_id\":\"itest-acc-1\",\"user\":\"alice\",\"expected_line_hash\":\"{s}\"}}]}}}}", .{ bob_id, fp_bob, bob_hash });
    const off_resp = rig.dispatch(off_req);
    try std.testing.expect(std.mem.indexOf(u8, off_resp, "\"ok\":true") != null);
    const job1_id_start = std.mem.indexOf(u8, off_resp, "\"job_id\":\"job-") orelse return error.TestUnexpectedResult;
    var job1_id_buf: [32]u8 = undefined;
    var job1_id_len: usize = 0;
    for (off_resp[job1_id_start + 10 ..]) |ch| {
        if (ch == '"') break;
        if (job1_id_len >= job1_id_buf.len) return error.TestUnexpectedResult;
        job1_id_buf[job1_id_len] = ch;
        job1_id_len += 1;
    }
    const job1_id = job1_id_buf[0..job1_id_len];
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
    var re_add = try addKey(&rig, "itest-acc-1", "alice", bob.value.result.public_key, "bob@new-laptop");
    defer re_add.deinit();
    try std.testing.expect(re_add.value.result.ok);
    var off2_buf: [1024]u8 = undefined;
    const off2_req = try std.fmt.bufPrint(&off2_buf, "{{\"id\":\"o2\",\"command\":\"oars.access.offboard\",\"payload\":{{\"identity_id\":\"{s}\",\"grants\":[{{\"fingerprint\":\"{s}\",\"server_id\":\"itest-acc-1\",\"user\":\"alice\",\"expected_line_hash\":\"{s}\"}}]}}}}", .{ bob_id, fp_bob, bob_hash });
    const off2 = rig.dispatch(off2_req);
    const job2_id_start = std.mem.indexOf(u8, off2, "\"job_id\":\"job-") orelse return error.TestUnexpectedResult;
    var job2_id_buf: [32]u8 = undefined;
    var job2_id_len: usize = 0;
    for (off2[job2_id_start + 10 ..]) |ch| {
        if (ch == '"') break;
        if (job2_id_len >= job2_id_buf.len) return error.TestUnexpectedResult;
        job2_id_buf[job2_id_len] = ch;
        job2_id_len += 1;
    }
    const job2_id = job2_id_buf[0..job2_id_len];
    var job2 = try jobUntilDone(&rig, job2_id, 30 * std.time.ns_per_s);
    defer job2.deinit();
    try std.testing.expectEqualStrings("error", job2.value.result.results[0].state);
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
    const dave_id = try parseIdentityId(dave_saved);
    defer std.testing.allocator.free(dave_id);
    var on_buf: [4096]u8 = undefined;
    const on_req = try std.fmt.bufPrint(&on_buf, "{{\"id\":\"n1\",\"command\":\"oars.access.onboard\",\"payload\":{{\"identity_id\":\"{s}\",\"public_key\":\"{s}\",\"grants\":[{{\"server_id\":\"itest-acc-1\",\"user\":\"carol\"}},{{\"server_id\":\"itest-acc-1\",\"user\":\"dave-ro\",\"read_only\":true}}]}}}}", .{ dave_id, dave.value.result.public_key });
    const on_resp = rig.dispatch(on_req);
    try std.testing.expect(std.mem.indexOf(u8, on_resp, "\"ok\":true") != null);
    const job3_id_start = std.mem.indexOf(u8, on_resp, "\"job_id\":\"job-") orelse return error.TestUnexpectedResult;
    var job3_id_buf: [32]u8 = undefined;
    var job3_id_len: usize = 0;
    for (on_resp[job3_id_start + 10 ..]) |ch| {
        if (ch == '"') break;
        if (job3_id_len >= job3_id_buf.len) return error.TestUnexpectedResult;
        job3_id_buf[job3_id_len] = ch;
        job3_id_len += 1;
    }
    const job3_id = job3_id_buf[0..job3_id_len];
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
    const on2_req = try std.fmt.bufPrint(&on2_buf, "{{\"id\":\"n2\",\"command\":\"oars.access.onboard\",\"payload\":{{\"identity_id\":\"{s}\",\"public_key\":\"{s}\",\"grants\":[{{\"server_id\":\"itest-acc-1\",\"user\":\"carol\"}}]}}}}", .{ dave_id, dave.value.result.public_key });
    const on2 = rig.dispatch(on2_req);
    const job4_id_start = std.mem.indexOf(u8, on2, "\"job_id\":\"job-") orelse return error.TestUnexpectedResult;
    var job4_id_buf: [32]u8 = undefined;
    var job4_id_len: usize = 0;
    for (on2[job4_id_start + 10 ..]) |ch| {
        if (ch == '"') break;
        if (job4_id_len >= job4_id_buf.len) return error.TestUnexpectedResult;
        job4_id_buf[job4_id_len] = ch;
        job4_id_len += 1;
    }
    const job4_id = job4_id_buf[0..job4_id_len];
    var job4 = try jobUntilDone(&rig, job4_id, 30 * std.time.ns_per_s);
    defer job4.deinit();
    try std.testing.expectEqualStrings("done", job4.value.result.results[0].state);
    const carol_keys = try execOut(&rig.manager, "itest-acc-1", "grep -c Dave /home/carol/.ssh/authorized_keys");
    defer std.testing.allocator.free(carol_keys);
    try std.testing.expect(std.mem.indexOf(u8, carol_keys, "1") != null);

    // --- rotate: Ada's key is replaced on itest-acc-1 ----------------------
    const ada_hash = grantLineHash(&scan2_parsed, "itest-acc-1", "root", fp_ada) orelse return error.TestUnexpectedResult;
    var rot_buf: [4096]u8 = undefined;
    const rot_req = try std.fmt.bufPrint(&rot_buf, "{{\"id\":\"r1\",\"command\":\"oars.access.rotate\",\"payload\":{{\"identity_id\":\"{s}\",\"old_fingerprint\":\"{s}\",\"new_public_key\":\"{s}\",\"grants\":[{{\"server_id\":\"itest-acc-1\",\"user\":\"root\",\"expected_line_hash\":\"{s}\"}}]}}}}", .{ ada_id, fp_ada, ada2.value.result.public_key, ada_hash });
    const rot_resp = rig.dispatch(rot_req);
    try std.testing.expect(std.mem.indexOf(u8, rot_resp, "\"ok\":true") != null);
    const job5_id_start = std.mem.indexOf(u8, rot_resp, "\"job_id\":\"job-") orelse return error.TestUnexpectedResult;
    var job5_id_buf: [32]u8 = undefined;
    var job5_id_len: usize = 0;
    for (rot_resp[job5_id_start + 10 ..]) |ch| {
        if (ch == '"') break;
        if (job5_id_len >= job5_id_buf.len) return error.TestUnexpectedResult;
        job5_id_buf[job5_id_len] = ch;
        job5_id_len += 1;
    }
    const job5_id = job5_id_buf[0..job5_id_len];
    var job5 = try jobUntilDone(&rig, job5_id, 30 * std.time.ns_per_s);
    defer job5.deinit();
    try std.testing.expectEqualStrings("done", job5.value.result.results[0].state);
    const root_keys = try execOut(&rig.manager, "itest-acc-1", "cat /root/.ssh/authorized_keys");
    defer std.testing.allocator.free(root_keys);
    try std.testing.expect(std.mem.indexOf(u8, root_keys, keyBlob(ada.value.result.public_key)) == null);
    try std.testing.expect(std.mem.indexOf(u8, root_keys, keyBlob(ada2.value.result.public_key)) != null);

    // --- export ------------------------------------------------------------
    const csv_resp = rig.dispatch(
        \\{"id":"e1","command":"oars.access.export","payload":{"format":"csv"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, csv_resp, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, csv_resp, "Ada") != null);
    try std.testing.expect(std.mem.indexOf(u8, csv_resp, "Bob") != null);
    try std.testing.expect(std.mem.indexOf(u8, csv_resp, "identity_id,name,fingerprint") != null);
    const json_resp = rig.dispatch(
        \\{"id":"e2","command":"oars.access.export","payload":{"format":"json"}}
    );
    try std.testing.expect(std.mem.indexOf(u8, json_resp, "people") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_resp, "\"format\":\"json\"") != null);

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

/// Extracts `"id":"id-<n>"` from an identities.save response.
fn parseIdentityId(response: []const u8) ![]const u8 {
    const start = std.mem.indexOf(u8, response, "\"id\":\"id-") orelse return error.TestUnexpectedResult;
    var buf: [64]u8 = undefined;
    var len: usize = 0;
    for (response[start + 6 ..]) |ch| {
        if (ch == '\"') break;
        if (len >= buf.len) return error.TestUnexpectedResult;
        buf[len] = ch;
        len += 1;
    }
    return std.testing.allocator.dupe(u8, buf[0..len]);
}
