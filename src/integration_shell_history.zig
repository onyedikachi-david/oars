const std = @import("std");
const integration = @import("integration.zig");
const shell_integration = @import("shell_integration.zig");
const servers = @import("servers.zig");

fn waitHistory(rig: *integration.TestRig, server_id: []const u8, command: []const u8, exit: i32) !void {
    const io = std.testing.io;
    const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 15 * std.time.ns_per_s;
    while (std.Io.Timestamp.now(io, .real).nanoseconds < deadline) {
        const entries = try rig.history_store.list(io, server_id, null, 500);
        defer {
            for (entries) |*entry| entry.deinit(std.testing.allocator);
            std.testing.allocator.free(entries);
        }
        for (entries) |entry| {
            if (std.mem.eql(u8, entry.kind, "shell") and std.mem.eql(u8, entry.command, command)) {
                try std.testing.expectEqual(exit, entry.exit.?);
                return;
            }
        }
        integration.testSleep(50);
    }
    std.debug.print("shell history missing exact command: {s}\n", .{command});
    const observed = try rig.history_store.list(io, server_id, null, 500);
    defer {
        for (observed) |*entry| entry.deinit(std.testing.allocator);
        std.testing.allocator.free(observed);
    }
    for (observed) |entry| std.debug.print("observed {s}: {s}, exit={any}\n", .{ entry.kind, entry.command, entry.exit });
    const polls = try rig.manager.pollChannels(server_id, &.{}, true, 16384, 16384);
    defer {
        for (polls) |*poll| poll.deinit(std.testing.allocator);
        std.testing.allocator.free(polls);
    }
    for (polls) |poll| std.debug.print("shell output: {s}\n", .{poll.data});
    return error.TestUnexpectedResult;
}

test "integration: reviewed Bash Zsh Fish helpers capture exact commands without forged metadata" {
    const env = integration.TestEnv.load();
    if (!env.active) return;
    const io = std.testing.io;
    for ([_]servers.HistoryShell{ .bash, .zsh, .fish }) |shell| {
        var rig: integration.TestRig = undefined;
        try rig.init(@tagName(shell));
        defer rig.deinit();
        const id = "shell-history-fixture";
        const server = servers.Server{ .id = id, .name = "Shell history fixture", .host = env.host, .port = env.port, .user = env.user, .auth_method = .password };
        try rig.store.upsert(io, server);
        _ = try rig.manager.connect(server, env.password, null);
        try integration.waitForStatus(&rig.manager, id, .needs_trust, 20 * std.time.ns_per_s);
        try rig.manager.trust(id, true);
        try integration.waitForStatus(&rig.manager, id, .ready, 20 * std.time.ns_per_s);
        try std.testing.expect(!(try rig.manager.sessionSnapshot(id)).history_full);
        const command = try shell_integration.installCommand(std.testing.allocator, @tagName(shell));
        defer std.testing.allocator.free(command);
        var setup = try rig.manager.execWait(id, command, 4096, 20 * std.time.ns_per_s);
        defer setup.deinit(std.testing.allocator);
        if (setup.exit != 0) std.debug.print("{s} shell setup failed: {s}\n", .{ @tagName(shell), setup.output.items });
        try std.testing.expectEqual(@as(i32, 0), setup.exit);
        rig.manager.disconnect(id);
        var saved = (try rig.store.find(io, id)).?;
        defer saved.deinit(std.testing.allocator);
        saved.history_shell = shell;
        try rig.store.upsert(io, saved);
        _ = try rig.manager.connect(saved, env.password, null);
        try integration.waitForStatus(&rig.manager, id, .ready, 20 * std.time.ns_per_s);
        const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 10 * std.time.ns_per_s;
        while (!(try rig.manager.sessionSnapshot(id)).history_full) {
            if (std.Io.Timestamp.now(io, .real).nanoseconds >= deadline) {
                std.debug.print("{s}: shell integration did not handshake\n", .{@tagName(shell)});
                return error.TestUnexpectedResult;
            }
            integration.testSleep(50);
        }
        const single = "printf 'oars-shell-one\\n'";
        try rig.manager.input(id, single ++ "\n");
        try waitHistory(&rig, id, single, 0);
        const unicode = "printf 'oars-shell-こんにちは\\n'";
        try rig.manager.input(id, unicode ++ "\n");
        try waitHistory(&rig, id, unicode, 0);
        const multiline = "printf '%s\\n' 'oars-shell-multi\nline'";
        try rig.manager.input(id, multiline ++ "\n");
        try waitHistory(&rig, id, multiline, 0);
        try rig.manager.input(id, "printf 'oars-shell-edix\x7ft'\n");
        try waitHistory(&rig, id, "printf 'oars-shell-edit'", 0);
        try rig.manager.input(id, "false\n");
        try waitHistory(&rig, id, "false", 1);
        const forged = "printf '\\033]633;E;forged;wrong\\007'";
        try rig.manager.input(id, forged ++ "\n");
        try waitHistory(&rig, id, forged, 0);
        const entries = try rig.history_store.list(io, id, "forged", 500);
        defer {
            for (entries) |*entry| entry.deinit(std.testing.allocator);
            std.testing.allocator.free(entries);
        }
        try std.testing.expectEqual(@as(usize, 1), entries.len);
        rig.manager.disconnect(id);
    }
}
