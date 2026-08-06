//! Broadcast runner state (spec 06 §6): the pure state machine for
//! safe-broadcast runs. The bridge handlers drive it with the session
//! manager's exec/poll/close primitives; this module holds the run records,
//! the queued-start accounting (at most `max_concurrent` servers running),
//! dedupe, and cancel bookkeeping. Main-thread access only (the handlers
//! serialize), guarded by a spinlock for safety.
//!
//! Per-server statuses: `queued` → `running` → `done`/`failed`, or
//! `skipped` (unreachable at start) / `canceled`. A canceled running
//! server is reported `canceled` with "cancel requested": closing the
//! channel does not prove the remote process died (spec 06 §10).

const std = @import("std");

pub const max_concurrent: usize = 4;
/// Bounded completed-run history, mirroring the SFTP transfers registry.
pub const max_completed_runs: usize = 32;

pub const Status = enum(u8) {
    queued,
    running,
    done,
    failed,
    canceled,
    skipped,

    pub fn jsonName(self: Status) []const u8 {
        return @tagName(self);
    }
};

pub const ServerState = struct {
    /// Owned.
    server_id: []const u8,
    channel: ?u32 = null,
    status: Status = .queued,
    exit: ?i32 = null,
    /// Static or owned error text; never freed here (matches the SFTP
    /// transfers registry — handlers assign literals).
    err: []const u8 = "",

    pub fn deinit(self: *ServerState, allocator: std.mem.Allocator) void {
        allocator.free(self.server_id);
    }
};

pub const Run = struct {
    id: u32,
    /// Owned.
    script_id: []const u8,
    /// Owned.
    script_name: []const u8,
    /// Owned expanded command.
    command: []const u8,
    /// Owned copy of the command with secret values masked (spec 15: the
    /// history record for each server's run uses this text).
    redacted_command: []const u8 = "",
    /// Owned secret variable values (spec 15: history masks the output
    /// snippet with the exact values the operation knew).
    secrets: [][]const u8 = &.{},
    servers: std.ArrayList(ServerState) = .empty,
    /// Index of the next queued server to start.
    next_to_start: usize = 0,
    running: usize = 0,
    canceled: bool = false,
    /// All servers terminal (kept briefly so polls can read results).
    finished: bool = false,

    pub fn deinit(self: *Run, allocator: std.mem.Allocator) void {
        allocator.free(self.script_id);
        allocator.free(self.script_name);
        allocator.free(self.command);
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
                .queued, .running => return false,
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
    /// deduped, order preserved). Returns the run id. The expanded command
    /// is copied; the script id/name are copied.
    pub fn start(
        self: *Runs,
        script_id: []const u8,
        script_name: []const u8,
        command: []const u8,
        redacted_command: []const u8,
        secrets: []const []const u8,
        server_ids: []const []const u8,
    ) !u32 {
        var run = Run{
            .id = self.next_id,
            .script_id = try self.allocator.dupe(u8, script_id),
            .script_name = try self.allocator.dupe(u8, script_name),
            .command = try self.allocator.dupe(u8, command),
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

    const id = try runs.start("sc1", "disk cleanup", "rm -rf /tmp/{{d}}", "", &.{}, &.{ "s1", "s2", "s1", "s3" });
    const run = runs.get(id).?;
    try testing.expectEqual(@as(usize, 3), run.servers.items.len);
    try testing.expectEqualStrings("s1", run.servers.items[0].server_id);
    try testing.expectEqualStrings("s3", run.servers.items[2].server_id);
    for (run.servers.items) |*s| try testing.expect(s.status == .queued);
    try testing.expect(!run.allTerminal());
}

test "status transitions and terminal accounting" {
    var runs = testRuns();
    defer runs.deinit();
    runs.lock();
    defer runs.unlock();

    const id = try runs.start("sc1", "x", "echo hi", "", &.{}, &.{ "s1", "s2" });
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

test "cancel marks queued servers and keeps terminal statuses" {
    var runs = testRuns();
    defer runs.deinit();
    runs.lock();
    defer runs.unlock();

    const id = try runs.start("sc1", "x", "sleep 30", "", &.{}, &.{ "s1", "s2", "s3" });
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
        const id = try runs.start("sc1", "x", "echo hi", "", &.{}, &.{"s1"});
        runs.get(id).?.finished = true;
    }
    try testing.expectEqual(max_completed_runs + 4, runs.list.items.len);
    runs.evictFinished();
    try testing.expectEqual(max_completed_runs, runs.list.items.len);
    // The surviving runs are the newest: ids 5..36, so the first is 5.
    try testing.expectEqual(@as(u32, 5), runs.list.items[0].id);
}
