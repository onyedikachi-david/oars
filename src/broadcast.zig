//! Broadcast runner state (spec 06 §6): the pure state machine for
//! safe-broadcast runs. The bridge handlers drive it with the session
//! manager's exec/poll/close primitives; this module holds the run records,
//! the queued-start accounting (at most `max_concurrent` servers running),
//! dedupe, and cancel bookkeeping. Main-thread access only (the handlers
//! serialize), guarded by a spinlock for safety.
//!
//! Per-server statuses: `queued` → `checking` → `running` → `done`/`failed`, or
//! `skipped` (unreachable at start) / `canceled`. A canceled running
//! server is reported `canceled` with "cancel requested": closing the
//! channel does not prove the remote process died (spec 06 §10).

const std = @import("std");
const scripts = @import("scripts.zig");

pub const max_concurrent: usize = 4;
/// Bounded completed-run history, mirroring the SFTP transfers registry.
pub const max_completed_runs: usize = 32;
/// Admission limits (spec 06 §5, v1 product limits): one broadcast may
/// select at most this many (deduplicated) servers; at most this many
/// broadcasts may be active at once; at most this many prepared previews
/// may exist uncommitted.
pub const max_servers_per_broadcast: usize = 64;
pub const max_active_runs: usize = 8;
pub const max_previews: usize = 32;
/// Prepared-preview lifetime: memory-only, short-lived (spec 06 §5).
pub const preview_ttl_ns: i128 = 10 * std.time.ns_per_min;

pub const Status = enum(u8) {
    queued,
    /// Worker-driven `bash -n` check in flight (spec 06 §5). Occupies one
    /// of the concurrency slots but never blocks the bridge poll.
    checking,
    running,
    done,
    failed,
    canceled,
    skipped,

    pub fn jsonName(self: Status) []const u8 {
        return @tagName(self);
    }
};

/// Completion record for a worker-driven `bash -n` syntax check (spec 06
/// §5): the broadcast poll enqueues the check op and reads the outcome on
/// later polls, so a slow check can never block a bridge call. Same heap +
/// `abandon()` ownership protocol as `SftpOutcome` (session 30): the
/// handler allocates; either side frees exactly once, under the mutex.
pub const ScriptCheckOutcome = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    done: bool = false,
    abandoned: bool = false,
    /// Exit status of `bash -n -c`; null until the check completes.
    exit: ?i32 = null,
    msg_buf: [512]u8 = undefined,
    msg_len: usize = 0,

    pub fn set(self: *ScriptCheckOutcome, exit: ?i32, msg: []const u8) void {
        lockSpin(&self.mutex);
        self.exit = exit;
        const n = @min(msg.len, self.msg_buf.len - 1);
        @memcpy(self.msg_buf[0..n], msg[0..n]);
        self.msg_len = n;
        self.done = true;
        const free = self.abandoned;
        self.mutex.unlock();
        if (free) self.allocator.destroy(self);
    }

    /// Handler-side teardown escape (cancel): marks the outcome abandoned
    /// so the worker's eventual set frees it. Returns true when the worker
    /// already completed it — the handler keeps ownership and frees.
    pub fn abandon(self: *ScriptCheckOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.abandoned = true;
        return self.done;
    }

    pub fn isDone(self: *ScriptCheckOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.done;
    }

    /// Slice into the struct; valid only while the handler owns it.
    pub fn message(self: *ScriptCheckOutcome) []const u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.msg_buf[0..self.msg_len];
    }

    pub fn exitStatus(self: *ScriptCheckOutcome) ?i32 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.exit;
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

pub const ServerState = struct {
    /// Owned.
    server_id: []const u8,
    channel: ?u32 = null,
    status: Status = .queued,
    exit: ?i32 = null,
    /// Static or owned error text. Handlers assign literals (matching the
    /// SFTP transfers registry); worker-check failures dupe their message
    /// and set `err_owned`.
    err: []const u8 = "",
    err_owned: bool = false,
    /// Owned bounded output snapshot captured before cancellation closes a
    /// channel. Independent consumers can still read canceled output.
    retained_data: []const u8 = &.{},
    retained_start: u64 = 0,
    retained_end: u64 = 0,
    /// Worker-driven syntax check in flight (status == .checking). The
    /// handler owns the outcome until it abandons it (cancel); the
    /// worker's set() frees an abandoned outcome.
    check_outcome: ?*ScriptCheckOutcome = null,

    pub fn deinit(self: *ServerState, allocator: std.mem.Allocator) void {
        if (self.check_outcome) |outcome| {
            if (outcome.abandon()) allocator.destroy(outcome);
            self.check_outcome = null;
        }
        allocator.free(self.server_id);
        if (self.err_owned) allocator.free(self.err);
        if (self.retained_data.len > 0) allocator.free(self.retained_data);
    }
};

pub const Run = struct {
    id: u32,
    /// Owned.
    script_id: []const u8,
    /// Owned.
    script_name: []const u8,
    /// Owned exact exec string (`bash -c '<expanded>'` — spec 06 §5).
    command: []const u8,
    /// Owned exact syntax-check string (`bash -n -c '<expanded>'`), built
    /// from the same expansion at start so check and exec see identical
    /// bytes. Never re-derived after start (preview-to-commit identity).
    check_command: []const u8,
    /// Owned copy of the command with secret values masked (spec 15: the
    /// history record for each server's run uses this text).
    redacted_command: []const u8 = "",
    /// Owned secret variable values (spec 15: history masks the output
    /// snippet with the exact values the operation knew).
    secrets: [][]const u8 = &.{},
    servers: std.ArrayList(ServerState) = .empty,
    /// Index of the next queued server to start.
    next_to_start: usize = 0,
    /// Occupied concurrency slots: servers that are `checking` or
    /// `running` (spec 06 §6: at most four at a time, checks included).
    running: usize = 0,
    canceled: bool = false,
    /// All servers terminal (kept briefly so polls can read results).
    finished: bool = false,

    pub fn deinit(self: *Run, allocator: std.mem.Allocator) void {
        allocator.free(self.script_id);
        allocator.free(self.script_name);
        allocator.free(self.command);
        allocator.free(self.check_command);
        allocator.free(self.redacted_command);
        // Empty (the common case) is the `.empty` comptime slice — only
        // owned when the run actually carries secrets.
        if (self.secrets.len > 0) {
            for (self.secrets) |s| allocator.free(s);
            allocator.free(self.secrets);
        }
        for (self.servers.items) |*s| s.deinit(allocator);
        self.servers.deinit(allocator);
    }

    pub fn allTerminal(self: *const Run) bool {
        for (self.servers.items) |*s| {
            switch (s.status) {
                .queued, .checking, .running => return false,
                else => {},
            }
        }
        return true;
    }

    pub fn findServer(self: *Run, server_id: []const u8) ?*ServerState {
        for (self.servers.items) |*s| {
            if (std.mem.eql(u8, s.server_id, server_id)) return s;
        }
        return null;
    }
};

pub const Runs = struct {
    allocator: std.mem.Allocator = undefined,
    mutex: std.atomic.Mutex = .unlocked,
    list: std.ArrayList(Run) = .empty,
    next_id: u32 = 1,

    pub fn lock(self: *Runs) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    pub fn unlock(self: *Runs) void {
        self.mutex.unlock();
    }

    pub fn deinit(self: *Runs) void {
        for (self.list.items) |*r| r.deinit(self.allocator);
        self.list.deinit(self.allocator);
    }

    /// Creates a run with one queued entry per server id (duplicates
    /// deduped, order preserved). Returns the run id. All strings are
    /// copied; `check_command` is the exact syntax-check string built at
    /// prepare time (preview-to-commit identity — never re-derived).
    pub fn start(
        self: *Runs,
        script_id: []const u8,
        script_name: []const u8,
        command: []const u8,
        check_command: []const u8,
        redacted_command: []const u8,
        secrets: []const []const u8,
        server_ids: []const []const u8,
    ) !u32 {
        var run = Run{
            .id = self.next_id,
            .script_id = try self.allocator.dupe(u8, script_id),
            .script_name = try self.allocator.dupe(u8, script_name),
            .command = try self.allocator.dupe(u8, command),
            .check_command = try self.allocator.dupe(u8, check_command),
            .redacted_command = try self.allocator.dupe(u8, redacted_command),
        };
        errdefer run.deinit(self.allocator);
        var secret_list: std.ArrayList([]const u8) = .empty;
        defer secret_list.deinit(self.allocator);
        for (secrets) |s| {
            const owned = try self.allocator.dupe(u8, s);
            secret_list.append(self.allocator, owned) catch {
                self.allocator.free(owned);
                return error.OutOfMemory;
            };
        }
        run.secrets = secret_list.toOwnedSlice(self.allocator) catch return error.OutOfMemory;
        self.next_id +%= 1;
        for (server_ids) |sid| {
            var dup = false;
            for (run.servers.items) |*s| {
                if (std.mem.eql(u8, s.server_id, sid)) {
                    dup = true;
                    break;
                }
            }
            if (dup) continue;
            run.servers.append(self.allocator, .{
                .server_id = try self.allocator.dupe(u8, sid),
            }) catch return error.OutOfMemory;
        }
        if (run.servers.items.len == 0) return error.NoServers;
        self.list.append(self.allocator, run) catch return error.OutOfMemory;
        return run.id;
    }

    /// Caller holds the lock.
    pub fn get(self: *Runs, id: u32) ?*Run {
        for (self.list.items) |*r| {
            if (r.id == id) return r;
        }
        return null;
    }

    /// Counts not-yet-finished runs (admission limit for new broadcasts —
    /// spec 06 §5: at most `max_active_runs`). Caller holds the lock.
    pub fn activeCount(self: *Runs) usize {
        var n: usize = 0;
        for (self.list.items) |*r| {
            if (!r.finished) n += 1;
        }
        return n;
    }

    /// Drops finished runs beyond the bounded history (oldest first) and
    /// removes the run entirely once every poll could have seen it
    /// finished and at least one poll has (spec 06: results are read via
    /// broadcastPoll; keeping terminal runs bounded is enough).
    pub fn evictFinished(self: *Runs) void {
        var finished_count: usize = 0;
        for (self.list.items) |*r| {
            if (r.finished) finished_count += 1;
        }
        var i: usize = 0;
        while (i < self.list.items.len and finished_count > max_completed_runs) {
            if (self.list.items[i].finished) {
                var r = self.list.orderedRemove(i);
                r.deinit(self.allocator);
                finished_count -= 1;
            } else {
                i += 1;
            }
        }
    }
};

/// A prepared broadcast (spec 06 §5 two-phase contract): the exact
/// expanded command, redacted copy, secret values, deduplicated target
/// list, variable names, and destructive state are frozen at prepare
/// time; commit executes this record verbatim, so a script edit between
/// preview and confirm can never change what runs. Memory-only; expired
/// after `preview_ttl_ns`; removed on commit, explicit cancel, and
/// shutdown. Never persisted, never audited, never touches run counts.
pub const Preview = struct {
    id: u32,
    /// Owned.
    script_id: []const u8,
    /// Owned.
    script_name: []const u8,
    /// Owned exact exec string (`bash -c '<expanded>'`).
    command: []const u8,
    /// Owned exact syntax-check string (`bash -n -c '<expanded>'`).
    check_command: []const u8,
    /// Owned exec string with secret values masked.
    redacted_command: []const u8,
    /// Owned secret values (history/output masking). `.empty` when none.
    secrets: [][]const u8 = &.{},
    /// Owned variable names in first-use order (audit at commit).
    names: []scripts.NameInfo,
    /// Owned deduplicated server ids, selection order preserved.
    servers: [][]const u8,
    destructive: bool,
    created_ns: i128,

    pub fn deinit(self: *Preview, allocator: std.mem.Allocator) void {
        allocator.free(self.script_id);
        allocator.free(self.script_name);
        allocator.free(self.command);
        allocator.free(self.check_command);
        allocator.free(self.redacted_command);
        if (self.secrets.len > 0) {
            for (self.secrets) |s| allocator.free(s);
            allocator.free(self.secrets);
        }
        for (self.names) |n| allocator.free(n.name);
        allocator.free(self.names);
        for (self.servers) |s| allocator.free(s);
        allocator.free(self.servers);
    }
};

/// Deep-copies a preview record from borrowed slices (the expansion's
/// strings are owned by the caller's `Expansion`; the record must own its
/// own copies). Caller frees with `deinit`.
pub fn previewInit(
    allocator: std.mem.Allocator,
    script_id: []const u8,
    script_name: []const u8,
    command: []const u8,
    check_command: []const u8,
    redacted_command: []const u8,
    secrets: []const []const u8,
    names: []const scripts.NameInfo,
    server_ids: []const []const u8,
    destructive: bool,
    created_ns: i128,
) !Preview {
    var out = Preview{
        .id = 0,
        .script_id = try allocator.dupe(u8, script_id),
        .script_name = try allocator.dupe(u8, script_name),
        .command = try allocator.dupe(u8, command),
        .check_command = try allocator.dupe(u8, check_command),
        .redacted_command = try allocator.dupe(u8, redacted_command),
        .destructive = destructive,
        .created_ns = created_ns,
        .names = &.{},
        .servers = &.{},
    };
    errdefer out.deinit(allocator);
    if (secrets.len > 0) {
        const buf = try allocator.alloc([]const u8, secrets.len);
        errdefer allocator.free(buf);
        for (secrets, 0..) |s, i| buf[i] = try allocator.dupe(u8, s);
        out.secrets = buf;
    }
    {
        const buf = try allocator.alloc(scripts.NameInfo, names.len);
        errdefer allocator.free(buf);
        for (names, 0..) |n, i| {
            buf[i] = .{ .name = try allocator.dupe(u8, n.name), .secret = n.secret };
        }
        out.names = buf;
    }
    {
        const buf = try allocator.alloc([]const u8, server_ids.len);
        errdefer allocator.free(buf);
        for (server_ids, 0..) |s, i| buf[i] = try allocator.dupe(u8, s);
        out.servers = buf;
    }
    return out;
}

/// Bounded, memory-only registry of prepared broadcasts. Main-thread
/// access only (bridge handlers serialize), guarded by a spinlock for
/// safety. Cleared on manager shutdown.
pub const Previews = struct {
    allocator: std.mem.Allocator = undefined,
    mutex: std.atomic.Mutex = .unlocked,
    list: std.ArrayList(Preview) = .empty,
    next_id: u32 = 1,

    pub fn lock(self: *Previews) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    pub fn unlock(self: *Previews) void {
        self.mutex.unlock();
    }

    pub fn deinit(self: *Previews) void {
        for (self.list.items) |*p| p.deinit(self.allocator);
        self.list.deinit(self.allocator);
    }

    /// Adopts the record (caller's ownership transfers on success) and
    /// returns its id. The record must not be touched by the caller after
    /// a successful call; on error the caller keeps ownership and must
    /// deinit it. Caller holds the lock.
    pub fn add(self: *Previews, p: Preview) !u32 {
        if (self.list.items.len >= max_previews) return error.TooManyPreviews;
        var adopted = p;
        adopted.id = self.next_id;
        self.next_id +%= 1;
        try self.list.append(self.allocator, adopted);
        return adopted.id;
    }

    /// Caller holds the lock.
    pub fn get(self: *Previews, id: u32) ?*Preview {
        for (self.list.items) |*p| {
            if (p.id == id) return p;
        }
        return null;
    }

    /// Removes and frees the record. Returns whether it existed. Caller
    /// holds the lock.
    pub fn remove(self: *Previews, id: u32) bool {
        for (self.list.items, 0..) |*p, i| {
            if (p.id == id) {
                var removed = self.list.orderedRemove(i);
                removed.deinit(self.allocator);
                return true;
            }
        }
        return false;
    }

    /// Drops records past their lifetime. Caller holds the lock.
    pub fn expire(self: *Previews, now_ns: i128) void {
        var i: usize = 0;
        while (i < self.list.items.len) {
            if (now_ns - self.list.items[i].created_ns >= preview_ttl_ns) {
                var p = self.list.orderedRemove(i);
                p.deinit(self.allocator);
            } else {
                i += 1;
            }
        }
    }
};

// --- tests -----------------------------------------------------------------

const testing = std.testing;

fn testRuns() Runs {
    return .{ .allocator = testing.allocator };
}

test "start dedupes server ids and orders queued work" {
    var runs = testRuns();
    defer runs.deinit();
    runs.lock();
    defer runs.unlock();

    const id = try runs.start("sc1", "disk cleanup", "bash -c 'rm -rf /tmp/x'", "bash -n -c 'rm -rf /tmp/x'", "", &.{}, &.{ "s1", "s2", "s1", "s3" });
    const run = runs.get(id).?;
    try testing.expectEqual(@as(usize, 3), run.servers.items.len);
    try testing.expectEqualStrings("s1", run.servers.items[0].server_id);
    try testing.expectEqualStrings("s3", run.servers.items[2].server_id);
    try testing.expectEqualStrings("bash -n -c 'rm -rf /tmp/x'", run.check_command);
    for (run.servers.items) |*s| try testing.expect(s.status == .queued);
    try testing.expect(!run.allTerminal());
}

test "status transitions and terminal accounting" {
    var runs = testRuns();
    defer runs.deinit();
    runs.lock();
    defer runs.unlock();

    const id = try runs.start("sc1", "x", "bash -c 'echo hi'", "bash -n -c 'echo hi'", "", &.{}, &.{ "s1", "s2" });
    const run = runs.get(id).?;
    run.servers.items[0].status = .running;
    run.running = 1;
    run.servers.items[1].status = .running;
    run.running = 2;
    try testing.expect(!run.allTerminal());

    run.servers.items[0].status = .done;
    run.servers.items[0].exit = 0;
    run.running -= 1;
    try testing.expect(!run.allTerminal());
    run.servers.items[1].status = .failed;
    run.servers.items[1].err = "syntax check failed";
    run.running -= 1;
    try testing.expect(run.allTerminal());
}

test "checking occupies a slot and keeps the run non-terminal" {
    var runs = testRuns();
    defer runs.deinit();
    runs.lock();
    defer runs.unlock();

    const id = try runs.start("sc1", "x", "bash -c 'echo hi'", "bash -n -c 'echo hi'", "", &.{}, &.{ "s1", "s2" });
    const run = runs.get(id).?;
    run.servers.items[0].status = .checking;
    run.running = 1;
    try testing.expect(!run.allTerminal());
    // A checking server that never completes keeps the run alive (the
    // outcome's worker timeout or session teardown must always complete it).
    run.servers.items[1].status = .done;
    run.servers.items[1].exit = 0;
    try testing.expect(!run.allTerminal());
}

test "activeCount counts only unfinished runs" {
    var runs = testRuns();
    defer runs.deinit();
    runs.lock();
    defer runs.unlock();

    try testing.expectEqual(@as(usize, 0), runs.activeCount());
    const a = try runs.start("sc1", "a", "c", "cc", "", &.{}, &.{"s1"});
    const b = try runs.start("sc1", "b", "c", "cc", "", &.{}, &.{"s1"});
    runs.get(a).?.finished = true;
    try testing.expectEqual(@as(usize, 1), runs.activeCount());
    runs.get(b).?.finished = true;
    try testing.expectEqual(@as(usize, 0), runs.activeCount());
}

test "cancel marks queued servers and keeps terminal statuses" {
    var runs = testRuns();
    defer runs.deinit();
    runs.lock();
    defer runs.unlock();

    const id = try runs.start("sc1", "x", "bash -c 'sleep 30'", "bash -n -c 'sleep 30'", "", &.{}, &.{ "s1", "s2", "s3" });
    const run = runs.get(id).?;
    run.servers.items[0].status = .running;
    run.running = 1;
    run.canceled = true;
    run.servers.items[0].status = .canceled;
    run.servers.items[0].err = "cancel requested";
    run.running = 0;
    run.servers.items[1].status = .canceled;
    // s3 stays queued -> canceled by the handler's cancel pass.
    run.servers.items[2].status = .canceled;
    run.servers.items[0].status = .canceled;

    try testing.expect(run.allTerminal());
    for (run.servers.items) |*s| try testing.expect(s.status == .canceled);
}

test "finished runs evict beyond the bounded history" {
    var runs = testRuns();
    defer runs.deinit();
    runs.lock();
    defer runs.unlock();

    var i: usize = 0;
    while (i < max_completed_runs + 4) : (i += 1) {
        const id = try runs.start("sc1", "x", "bash -c 'echo hi'", "bash -n -c 'echo hi'", "", &.{}, &.{"s1"});
        runs.get(id).?.finished = true;
    }
    try testing.expectEqual(max_completed_runs + 4, runs.list.items.len);
    runs.evictFinished();
    try testing.expectEqual(max_completed_runs, runs.list.items.len);
    // The surviving runs are the newest: ids 5..36, so the first is 5.
    try testing.expectEqual(@as(u32, 5), runs.list.items[0].id);
}

test "check outcome set/abandon protocol" {
    const allocator = testing.allocator;
    // The protocol is heap-only: the worker's set() may free the struct.
    const outcome = try allocator.create(ScriptCheckOutcome);
    outcome.* = .{ .allocator = allocator };
    try testing.expect(!outcome.isDone());
    outcome.set(0, "syntax ok");
    try testing.expect(outcome.isDone());
    try testing.expectEqual(@as(?i32, 0), outcome.exit);
    try testing.expectEqualStrings("syntax ok", outcome.message());
    // Abandon after completion keeps handler ownership: returns true, and
    // the handler destroys.
    try testing.expect(outcome.abandon());
    allocator.destroy(outcome);
}

test "check outcome abandon-before-set frees on the worker's set" {
    const allocator = testing.allocator;
    const outcome = try allocator.create(ScriptCheckOutcome);
    outcome.* = .{ .allocator = allocator };
    // Handler abandons (cancel); the worker's later set() must free the
    // struct — under the testing allocator a leak or double-free fails.
    try testing.expect(!outcome.abandon());
    outcome.set(127, "bash unavailable");
    // `outcome` is dangling here by design: the set() freed it.
}

test "previews: add, get, remove, expire, and the admission cap" {
    const allocator = testing.allocator;
    var previews = Previews{ .allocator = allocator };
    defer previews.deinit();

    const now: i128 = 1_000_000_000_000;
    const p = try previewInit(allocator, "sc1", "disk cleanup", "bash -c 'rm -rf /tmp/x'", "bash -n -c 'rm -rf /tmp/x'", "bash -c 'rm -rf ***'", &.{"hunter2"}, &.{.{ .name = "d", .secret = true }}, &.{ "s1", "s2" }, true, now);
    previews.lock();
    const id = try previews.add(p);
    try testing.expect(previews.get(id) != null);
    try testing.expectEqualStrings("disk cleanup", previews.get(id).?.script_name);
    try testing.expect(previews.get(id).?.destructive);

    // Expiry drops the record.
    previews.expire(now + preview_ttl_ns + 1);
    try testing.expect(previews.get(id) == null);

    // Cap: adding beyond max_previews is refused (caller keeps ownership).
    var i: usize = 0;
    var last: u32 = 0;
    while (i < max_previews + 2) : (i += 1) {
        var q = try previewInit(allocator, "sc1", "x", "c", "cc", "c", &.{}, &.{}, &.{"s1"}, false, now);
        if (previews.add(q)) |pid| {
            last = pid;
        } else |err| {
            q.deinit(allocator);
            try testing.expectEqual(error.TooManyPreviews, err);
            break;
        }
    }
    try testing.expectEqual(@as(usize, max_previews), previews.list.items.len);

    // Remove frees; a second remove reports not-found.
    try testing.expect(previews.remove(last));
    try testing.expect(!previews.remove(last));
    previews.unlock();
}
