//! Spec 11 SSH integration coverage for provider metadata, asynchronous
//! context collection, proposal approval, and exact tracked execution.
//!
//! Imported from integration.zig so `zig build test` picks it up. Skipped
//! unless OARS_TEST_SSH_* is set.

const std = @import("std");
const ai = @import("ai.zig");
const servers = @import("servers.zig");
const rig_mod = @import("integration.zig");

const TestRig = rig_mod.TestRig;
const testSleep = rig_mod.testSleep;
const execWait = rig_mod.execWait;
const waitForStatus = rig_mod.waitForStatus;

const server_id = "itest-ai-1";
const log_path = "/var/log/oars-ai-test.log";
const fixture_secret = "fixture-provider-credential";
const initial_command = "printf 'oars-ai-original\\n'";
const edited_command = "printf 'oars-ai-exact\\n'; rm -f /tmp/oars-ai-integration-marker; touch /tmp/oars-ai-integration-marker";
const cancel_command = "trap 'exit 143' TERM INT; sh -c 'while :; do sleep 1; done' oars-ai-cancel-token & child=$!; printf 'cancel-child-%s\\n' \"$child\"; wait \"$child\"";
const disconnect_command = "count=$(cat /tmp/oars-ai-disconnect-count 2>/dev/null || echo 0); count=$((count + 1)); printf '%s\\n' \"$count\" > /tmp/oars-ai-disconnect-count; printf 'disconnect-started\\n'; sh -c 'while :; do sleep 1; done' oars-ai-disconnect-token";

const CredentialFixture = struct {
    read: std.atomic.Value(bool) = .init(false),

    fn service(self: *CredentialFixture) ai.credentials.Service {
        return .{ .context = self, .set_fn = set, .get_fn = get, .delete_fn = delete };
    }

    fn set(_: *anyopaque, _: []const u8, _: []const u8, _: []const u8) ai.credentials.ServiceError!void {}

    fn get(context: *anyopaque, service_name: []const u8, account: []const u8, output: []u8) ai.credentials.ServiceError!?usize {
        const self: *CredentialFixture = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, service_name, ai.credentials.service_name) or account.len == 0 or output.len < fixture_secret.len) return error.Unavailable;
        @memcpy(output[0..fixture_secret.len], fixture_secret);
        self.read.store(true, .release);
        return fixture_secret.len;
    }

    fn delete(_: *anyopaque, _: []const u8, _: []const u8) ai.credentials.ServiceError!bool {
        return true;
    }
};

const ProviderFixture = struct {
    saw_credential: std.atomic.Value(bool) = .init(false),
    saw_selected_log: std.atomic.Value(bool) = .init(false),
    saw_command_output: std.atomic.Value(bool) = .init(false),

    fn adapter(self: *ProviderFixture) ai.coordinator.Runner {
        return .{ .context = self, .run_fn = run };
    }

    fn run(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        _: std.Io,
        _: *const ai.provider_domain.Public,
        secret: *const ai.credentials.SecretBuffer,
        _: []const u8,
        _: []const u8,
        context_json: []const u8,
        _: []const u8,
        cancellation: *ai.transport.Cancellation,
        observer: ai.transport.Observer,
    ) anyerror!ai.coordinator.RunOutput {
        const self: *ProviderFixture = @ptrCast(@alignCast(context.?));
        if (cancellation.isCanceled()) return error.Canceled;
        self.saw_credential.store(std.mem.eql(u8, secret.slice(), fixture_secret), .release);
        self.saw_selected_log.store(std.mem.indexOf(u8, context_json, "ai log line") != null, .release);
        self.saw_command_output.store(std.mem.indexOf(u8, context_json, "oars-ai-exact") != null, .release);
        observer.response_fn(observer.context, "fixture-request-1");
        observer.progress_fn(observer.context, .streaming, initial_command.len);
        const result_document = if (std.mem.indexOf(u8, context_json, "\"kind\":\"command_output\"") != null)
            \\{"kind":"message","message":"The retained command output confirms the reviewed operation completed.","command":null,"question":null,"explanation":"Summarized the selected retained output.","destructive":false,"needs_sudo":false}
        else
            \\{"kind":"command","message":null,"command":"printf 'oars-ai-original\\n'","question":null,"explanation":"Print a marker.","destructive":false,"needs_sudo":false}
        ;
        var validated = try ai.proposal.parse(allocator, result_document);
        errdefer validated.deinit(allocator);
        const continuation = try allocator.dupe(u8, "[]");
        var meta = ai.transport.Meta{ .status = 200 };
        const request_id = "fixture-request-1";
        @memcpy(meta.provider_request_id[0..request_id.len], request_id);
        meta.provider_request_id_len = request_id.len;
        return .{ .validated = validated, .meta = meta, .continuation_json = continuation, .received_bytes = initial_command.len };
    }
};

const ProviderSaveResp = struct {
    result: struct {
        ok: bool = false,
        provider: ?struct {
            id: []const u8 = "",
            adapter: []const u8 = "",
            base_url: []const u8 = "",
            model: []const u8 = "",
            revision: u64 = 0,
        } = null,
    },
};

const ProviderListResp = struct {
    result: struct {
        ok: bool = false,
        providers: []const struct {
            id: []const u8 = "",
            model: []const u8 = "",
        } = &.{},
    },
};

const ContextPollResp = struct {
    result: struct {
        ok: bool = false,
        cursor: u64 = 0,
        dropped: u64 = 0,
        finished: bool = false,
        state: []const u8 = "",
        events: []const struct {
            version: u8 = 0,
            sequence: u64 = 0,
            type: []const u8 = "",
        } = &.{},
    },
};

const ContextGetResp = struct {
    result: struct {
        ok: bool = false,
        state: []const u8 = "",
        stale: bool = true,
        context: ?struct {
            server_id: []const u8 = "",
            os: []const u8 = "",
            hostname: []const u8 = "",
            monitor: struct {
                cpu: struct { uptime_sec: u64 = 0 } = .{},
                mem: struct { total_bytes: u64 = 0 } = .{},
                disk: struct { total_bytes: u64 = 0 } = .{},
                processes: []const struct {
                    pid: u32 = 0,
                    name: []const u8 = "",
                } = &.{},
                probe_error: ?[]const u8 = null,
            } = .{},
            active_logs: []const struct {
                path: []const u8 = "",
                last_write: u64 = 0,
            } = &.{},
            partial: bool = true,
            errors: []const struct {
                code: []const u8 = "",
                @"error": []const u8 = "",
            } = &.{},
            updated_at_ms: i64 = 0,
        } = null,
    },
};

const TurnAdmissionResp = struct {
    result: struct {
        ok: bool = false,
        thread_id: []const u8 = "",
        turn_id: []const u8 = "",
        state: []const u8 = "",
    },
};

const TurnPollResp = struct {
    result: struct {
        ok: bool = false,
        cursor: u64 = 0,
        dropped: u64 = 0,
        finished: bool = false,
        state: []const u8 = "",
        events: []const struct {
            version: u8 = 0,
            sequence: u64 = 0,
            type: []const u8 = "",
        } = &.{},
    },
};

const ProposalView = struct {
    id: []const u8 = "",
    revision: u64 = 0,
    command: []const u8 = "",
    command_sha256: []const u8 = "",
    model_destructive: bool = false,
    local_destructive: bool = false,
    needs_sudo: bool = false,
    state: []const u8 = "",
};

const ThreadGetResp = struct {
    result: struct {
        ok: bool = false,
        thread: struct { revision: u64 = 0 } = .{},
        turns_start: usize = 0,
        turn_count: usize = 0,
        active_proposal: ?ProposalView = null,
    },
};

const ProposalResp = struct {
    result: struct {
        ok: bool = false,
        proposal: ?ProposalView = null,
    },
};

const ExecutionResp = struct {
    result: struct {
        ok: bool = false,
        code: []const u8 = "",
        execution_id: []const u8 = "",
        connection_id: u64 = 0,
        channel: u32 = 0,
        state: []const u8 = "",
    },
};

const TurnCancelResp = struct {
    result: struct {
        ok: bool = false,
        state: []const u8 = "",
    },
};

const ErrorResp = struct {
    result: struct {
        ok: bool = false,
        code: []const u8 = "",
        @"error": []const u8 = "",
    },
};

/// Dispatches and parses with alloc_always because the rig output buffer is
/// reused by the next dispatch.
fn dispatchParsed(rig: *TestRig, comptime T: type, req: []const u8) !std.json.Parsed(T) {
    const response = rig.dispatch(req);
    return std.json.parseFromSlice(T, std.testing.allocator, response, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
}

fn waitForTurnState(rig: *TestRig, turn_id: []const u8, want: []const u8, timeout_ns: i128) !void {
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + timeout_ns;
    var cursor: u64 = 0;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        const request = try std.fmt.allocPrint(std.testing.allocator, "{{\"id\":\"tp\",\"command\":\"oars.ai.turn.poll\",\"payload\":{{\"turn_id\":{f},\"cursor\":{d}}}}}", .{ std.json.fmt(turn_id, .{}), cursor });
        defer std.testing.allocator.free(request);
        var poll = try dispatchParsed(rig, TurnPollResp, request);
        defer poll.deinit();
        try std.testing.expect(poll.value.result.ok);
        try std.testing.expectEqual(@as(u64, 0), poll.value.result.dropped);
        for (poll.value.result.events) |event| try std.testing.expectEqual(@as(u8, 1), event.version);
        cursor = poll.value.result.cursor;
        if (std.mem.eql(u8, poll.value.result.state, want)) return;
        testSleep(25);
    }
    return error.TestUnexpectedResult;
}

fn refreshContext(rig: *TestRig, operation_id: []const u8) !void {
    const refresh_request = try std.fmt.allocPrint(std.testing.allocator, "{{\"id\":\"crx\",\"command\":\"oars.ai.context.refresh\",\"payload\":{{\"operation_id\":{f},\"server_id\":\"{s}\"}}}}", .{ std.json.fmt(operation_id, .{}), server_id });
    defer std.testing.allocator.free(refresh_request);
    try std.testing.expect(std.mem.indexOf(u8, rig.dispatch(refresh_request), "\"ok\":true") != null);
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 30 * std.time.ns_per_s;
    var cursor: u64 = 0;
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        const poll_request = try std.fmt.allocPrint(std.testing.allocator, "{{\"id\":\"cpx\",\"command\":\"oars.ai.context.poll\",\"payload\":{{\"operation_id\":{f},\"cursor\":{d}}}}}", .{ std.json.fmt(operation_id, .{}), cursor });
        defer std.testing.allocator.free(poll_request);
        var poll = try dispatchParsed(rig, ContextPollResp, poll_request);
        defer poll.deinit();
        try std.testing.expect(poll.value.result.ok);
        cursor = poll.value.result.cursor;
        if (poll.value.result.finished) {
            try std.testing.expectEqualStrings("ready", poll.value.result.state);
            return;
        }
        testSleep(25);
    }
    return error.TestUnexpectedResult;
}

fn waitForExecution(rig: *TestRig, channel: u32, want_output: []const u8) !u64 {
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 15 * std.time.ns_per_s;
    var cursor: u64 = 0;
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.testing.allocator);
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        const polls = try rig.manager.pollChannels(server_id, &.{.{ .id = channel, .pos = cursor }}, false, 64 * 1024, 64 * 1024);
        defer {
            for (polls) |*poll| poll.deinit(std.testing.allocator);
            std.testing.allocator.free(polls);
        }
        for (polls) |poll| {
            if (poll.id != channel) continue;
            try std.testing.expectEqual(@as(u64, 0), poll.gap);
            try output.appendSlice(std.testing.allocator, poll.data);
            cursor = poll.cursor;
            if (poll.eof and poll.exit_status != null) {
                try std.testing.expectEqual(@as(i32, 0), poll.exit_status.?);
                try std.testing.expect(std.mem.indexOf(u8, output.items, want_output) != null);
                return cursor;
            }
        }
        testSleep(25);
    }
    return error.TestUnexpectedResult;
}

fn waitForChannelOutput(rig: *TestRig, channel: u32, want_output: []const u8) !void {
    const deadline = std.Io.Timestamp.now(std.testing.io, .real).nanoseconds + 15 * std.time.ns_per_s;
    var cursor: u64 = 0;
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.testing.allocator);
    while (std.Io.Timestamp.now(std.testing.io, .real).nanoseconds < deadline) {
        const polls = try rig.manager.pollChannels(server_id, &.{.{ .id = channel, .pos = cursor }}, false, 64 * 1024, 64 * 1024);
        defer {
            for (polls) |*poll| poll.deinit(std.testing.allocator);
            std.testing.allocator.free(polls);
        }
        for (polls) |poll| {
            if (poll.id != channel) continue;
            try output.appendSlice(std.testing.allocator, poll.data);
            cursor = poll.cursor;
        }
        if (std.mem.indexOf(u8, output.items, want_output) != null) return;
        testSleep(25);
    }
    return error.TestUnexpectedResult;
}

test "integration: provider metadata and asynchronous AI context" {
    const env = rig_mod.TestEnv.load();
    if (!env.active) return;

    var rig: TestRig = undefined;
    try rig.init("ai");
    defer rig.deinit();
    const io = std.testing.io;
    var credential_fixture = CredentialFixture{};
    rig.ai_registry.credential_facade.install(credential_fixture.service());
    defer rig.ai_registry.credential_facade.clear();
    var provider_fixture = ProviderFixture{};
    rig.ai_registry.turns.?.runner = provider_fixture.adapter();

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

    try execWait(&rig.manager, server_id, "rm -f " ++ log_path ++ " && echo 'ai log line' > " ++ log_path, 0, "");
    var source_buffer: [256]u8 = undefined;
    const source_request = try std.fmt.bufPrint(&source_buffer, "{{\"id\":\"ls\",\"command\":\"oars.logs.addSource\",\"payload\":{{\"server_id\":\"{s}\",\"path\":\"{s}\"}}}}", .{ server_id, log_path });
    try std.testing.expect(std.mem.indexOf(u8, rig.dispatch(source_request), "\"ok\":true") != null);

    const save_request =
        \\{"id":"ps","command":"oars.ai.provider.save","payload":{"operation_id":"itest-provider-save","provider":{"name":"OpenAI","adapter":"openai_responses","base_url":"https://api.openai.com/v1","model":"gpt-5"}}}
    ;
    var saved = try dispatchParsed(&rig, ProviderSaveResp, save_request);
    defer saved.deinit();
    try std.testing.expect(saved.value.result.ok);
    try std.testing.expect(saved.value.result.provider.?.id.len > 4);
    try std.testing.expectEqualStrings("openai_responses", saved.value.result.provider.?.adapter);
    try std.testing.expectEqual(@as(u64, 1), saved.value.result.provider.?.revision);
    try rig.ai_registry.providers.bindCredential(io, saved.value.result.provider.?.id, saved.value.result.provider.?.base_url);
    const credential_generation = (try rig.ai_registry.providers.credentialGeneration(io, saved.value.result.provider.?.id, saved.value.result.provider.?.base_url)).?;
    const tested_at_ms: i64 = @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_ms));
    var tested = try rig.ai_registry.providers.recordTestResult(io, saved.value.result.provider.?.id, saved.value.result.provider.?.revision, credential_generation, .passed, tested_at_ms);
    defer tested.deinit(std.testing.allocator);
    var listed = try dispatchParsed(&rig, ProviderListResp, "{\"id\":\"pl\",\"command\":\"oars.ai.provider.list\",\"payload\":{}}");
    defer listed.deinit();
    try std.testing.expectEqual(@as(usize, 1), listed.value.result.providers.len);
    try std.testing.expectEqualStrings(saved.value.result.provider.?.id, listed.value.result.providers[0].id);

    const missing = rig.dispatch("{\"id\":\"cg0\",\"command\":\"oars.ai.context.get\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\"}}");
    try std.testing.expect(std.mem.indexOf(u8, missing, "\"state\":\"missing\"") != null);
    const refresh = rig.dispatch("{\"id\":\"cr\",\"command\":\"oars.ai.context.refresh\",\"payload\":{\"operation_id\":\"itest-context-refresh\",\"server_id\":\"" ++ server_id ++ "\"}}");
    try std.testing.expect(std.mem.indexOf(u8, refresh, "\"ok\":true") != null);

    var cursor: u64 = 0;
    var completed = false;
    const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 30 * std.time.ns_per_s;
    while (std.Io.Timestamp.now(io, .real).nanoseconds < deadline) {
        var poll_buffer: [256]u8 = undefined;
        const poll_request = try std.fmt.bufPrint(&poll_buffer, "{{\"id\":\"cp\",\"command\":\"oars.ai.context.poll\",\"payload\":{{\"operation_id\":\"itest-context-refresh\",\"cursor\":{d}}}}}", .{cursor});
        var poll = try dispatchParsed(&rig, ContextPollResp, poll_request);
        defer poll.deinit();
        try std.testing.expect(poll.value.result.ok);
        try std.testing.expectEqual(@as(u64, 0), poll.value.result.dropped);
        for (poll.value.result.events) |event| try std.testing.expectEqual(@as(u8, 1), event.version);
        cursor = poll.value.result.cursor;
        if (poll.value.result.finished) {
            try std.testing.expectEqualStrings("ready", poll.value.result.state);
            completed = true;
            break;
        }
        testSleep(50);
    }
    try std.testing.expect(completed);

    var cached = try dispatchParsed(&rig, ContextGetResp, "{\"id\":\"cg1\",\"command\":\"oars.ai.context.get\",\"payload\":{\"server_id\":\"" ++ server_id ++ "\"}}");
    defer cached.deinit();
    try std.testing.expect(cached.value.result.ok);
    try std.testing.expectEqualStrings("ready", cached.value.result.state);
    const context = cached.value.result.context.?;
    try std.testing.expectEqualStrings(server_id, context.server_id);
    try std.testing.expect(std.mem.indexOf(u8, context.os, "Alpine") != null);
    try std.testing.expect(context.hostname.len > 0);
    // Context refresh owns its complete one-shot probe. It must not depend on
    // the separate Monitor tab cache having been populated first.
    try std.testing.expect(context.monitor.mem.total_bytes > 0);
    try std.testing.expect(context.monitor.disk.total_bytes > 0);
    try std.testing.expect(context.monitor.processes.len > 0);
    try std.testing.expect(context.monitor.probe_error == null);
    var log_found = false;
    for (context.active_logs) |log| if (std.mem.eql(u8, log.path, log_path)) {
        try std.testing.expect(log.last_write > 0);
        log_found = true;
    };
    try std.testing.expect(log_found);

    // A cache read does not create an operation or perform SSH. The same
    // refresh stream remains readable from cursor zero for another consumer.
    var mirrored = try dispatchParsed(&rig, ContextPollResp, "{\"id\":\"cp2\",\"command\":\"oars.ai.context.poll\",\"payload\":{\"operation_id\":\"itest-context-refresh\",\"cursor\":0}}");
    defer mirrored.deinit();
    try std.testing.expect(mirrored.value.result.events.len >= 2);
    try std.testing.expect(mirrored.value.result.finished);

    const turn_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"id\":\"ts\",\"command\":\"oars.ai.turn.start\",\"payload\":{{\"operation_id\":\"itest-ai-turn\",\"server_id\":\"{s}\",\"provider_id\":{f},\"expected_provider_revision\":{d},\"message\":\"print and create the integration marker\",\"context_selection\":{{\"os\":true,\"monitor\":true,\"log\":{{\"source_id\":\"{s}\",\"tail_bytes\":4096}}}}}}}}",
        .{ server_id, std.json.fmt(saved.value.result.provider.?.id, .{}), saved.value.result.provider.?.revision, log_path },
    );
    defer std.testing.allocator.free(turn_request);
    var admitted = try dispatchParsed(&rig, TurnAdmissionResp, turn_request);
    defer admitted.deinit();
    try std.testing.expect(admitted.value.result.ok);
    try std.testing.expect(admitted.value.result.thread_id.len > 4);
    try std.testing.expect(admitted.value.result.turn_id.len > 4);
    try waitForTurnState(&rig, admitted.value.result.turn_id, "awaiting_approval", 15 * std.time.ns_per_s);
    try std.testing.expect(credential_fixture.read.load(.acquire));
    try std.testing.expect(provider_fixture.saw_credential.load(.acquire));
    try std.testing.expect(provider_fixture.saw_selected_log.load(.acquire));

    const thread_request = try std.fmt.allocPrint(std.testing.allocator, "{{\"id\":\"tg\",\"command\":\"oars.ai.thread.get\",\"payload\":{{\"thread_id\":{f}}}}}", .{std.json.fmt(admitted.value.result.thread_id, .{})});
    defer std.testing.allocator.free(thread_request);
    var detail = try dispatchParsed(&rig, ThreadGetResp, thread_request);
    defer detail.deinit();
    try std.testing.expect(detail.value.result.ok);
    try std.testing.expectEqual(@as(usize, 0), detail.value.result.turns_start);
    try std.testing.expectEqual(@as(usize, 1), detail.value.result.turn_count);
    const original = detail.value.result.active_proposal.?;
    try std.testing.expectEqualStrings(initial_command, original.command);
    try std.testing.expect(!original.local_destructive);

    const edit_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"id\":\"pe\",\"command\":\"oars.ai.proposal.edit\",\"payload\":{{\"operation_id\":\"itest-ai-edit\",\"proposal_id\":{f},\"expected_revision\":{d},\"command\":{f}}}}}",
        .{ std.json.fmt(original.id, .{}), original.revision, std.json.fmt(edited_command, .{}) },
    );
    defer std.testing.allocator.free(edit_request);
    var edited = try dispatchParsed(&rig, ProposalResp, edit_request);
    defer edited.deinit();
    try std.testing.expect(edited.value.result.ok);
    const proposal = edited.value.result.proposal.?;
    try std.testing.expectEqual(original.revision + 1, proposal.revision);
    try std.testing.expectEqualStrings(edited_command, proposal.command);
    try std.testing.expect(proposal.local_destructive);
    try std.testing.expectEqual(@as(usize, 64), proposal.command_sha256.len);

    const stale_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"id\":\"pr0\",\"command\":\"oars.ai.proposal.run\",\"payload\":{{\"operation_id\":\"itest-ai-run\",\"proposal_id\":{f},\"expected_revision\":{d},\"command_sha256\":{f},\"destructive_warning_ack\":true}}}}",
        .{ std.json.fmt(proposal.id, .{}), original.revision, std.json.fmt(original.command_sha256, .{}) },
    );
    defer std.testing.allocator.free(stale_request);
    var stale = try dispatchParsed(&rig, ErrorResp, stale_request);
    defer stale.deinit();
    try std.testing.expect(!stale.value.result.ok);
    try std.testing.expectEqualStrings("stale_revision", stale.value.result.code);

    const unconfirmed_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"id\":\"pr1\",\"command\":\"oars.ai.proposal.run\",\"payload\":{{\"operation_id\":\"itest-ai-run\",\"proposal_id\":{f},\"expected_revision\":{d},\"command_sha256\":{f},\"destructive_warning_ack\":false}}}}",
        .{ std.json.fmt(proposal.id, .{}), proposal.revision, std.json.fmt(proposal.command_sha256, .{}) },
    );
    defer std.testing.allocator.free(unconfirmed_request);
    var unconfirmed = try dispatchParsed(&rig, ErrorResp, unconfirmed_request);
    defer unconfirmed.deinit();
    try std.testing.expect(!unconfirmed.value.result.ok);
    try std.testing.expectEqualStrings("invalid_argument", unconfirmed.value.result.code);
    try std.testing.expect(std.mem.indexOf(u8, unconfirmed.value.result.@"error", "destructive") != null);

    const run_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"id\":\"pr2\",\"command\":\"oars.ai.proposal.run\",\"payload\":{{\"operation_id\":\"itest-ai-run\",\"proposal_id\":{f},\"expected_revision\":{d},\"command_sha256\":{f},\"destructive_warning_ack\":true}}}}",
        .{ std.json.fmt(proposal.id, .{}), proposal.revision, std.json.fmt(proposal.command_sha256, .{}) },
    );
    defer std.testing.allocator.free(run_request);
    var execution = try dispatchParsed(&rig, ExecutionResp, run_request);
    defer execution.deinit();
    try std.testing.expect(execution.value.result.ok);
    try std.testing.expect(execution.value.result.execution_id.len > 4);
    try std.testing.expect(execution.value.result.connection_id > 0);
    try std.testing.expect(execution.value.result.channel > 0);
    try std.testing.expectEqualStrings("executing", execution.value.result.state);

    var replayed = try dispatchParsed(&rig, ExecutionResp, run_request);
    defer replayed.deinit();
    try std.testing.expect(replayed.value.result.ok);
    try std.testing.expectEqualStrings(execution.value.result.execution_id, replayed.value.result.execution_id);
    try std.testing.expectEqual(execution.value.result.connection_id, replayed.value.result.connection_id);
    try std.testing.expectEqual(execution.value.result.channel, replayed.value.result.channel);

    const conflict_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"id\":\"pr3\",\"command\":\"oars.ai.proposal.run\",\"payload\":{{\"operation_id\":\"itest-ai-run-other\",\"proposal_id\":{f},\"expected_revision\":{d},\"command_sha256\":{f},\"destructive_warning_ack\":true}}}}",
        .{ std.json.fmt(proposal.id, .{}), proposal.revision, std.json.fmt(proposal.command_sha256, .{}) },
    );
    defer std.testing.allocator.free(conflict_request);
    var conflict = try dispatchParsed(&rig, ErrorResp, conflict_request);
    defer conflict.deinit();
    try std.testing.expect(!conflict.value.result.ok);
    try std.testing.expectEqualStrings("conflict", conflict.value.result.code);

    const execution_end = try waitForExecution(&rig, execution.value.result.channel, "oars-ai-exact");
    try waitForTurnState(&rig, admitted.value.result.turn_id, "completed", 15 * std.time.ns_per_s);
    try execWait(&rig.manager, server_id, "test -f /tmp/oars-ai-integration-marker && echo marker-present", 0, "marker-present");

    // The shell and earlier channels already contain output. Summarizing the
    // completed execution must still read this channel's exact retained range
    // instead of spending its byte budget on unrelated channel data.
    const summary_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"id\":\"sum\",\"command\":\"oars.ai.turn.summarize\",\"payload\":{{\"operation_id\":\"itest-ai-summary\",\"thread_id\":{f},\"execution_id\":{f},\"output_selection\":{{\"start_cursor\":0,\"end_cursor\":{d}}}}}}}",
        .{ std.json.fmt(admitted.value.result.thread_id, .{}), std.json.fmt(execution.value.result.execution_id, .{}), execution_end },
    );
    defer std.testing.allocator.free(summary_request);
    var summarized = try dispatchParsed(&rig, TurnAdmissionResp, summary_request);
    defer summarized.deinit();
    try std.testing.expect(summarized.value.result.ok);
    try waitForTurnState(&rig, summarized.value.result.turn_id, "completed", 15 * std.time.ns_per_s);
    try std.testing.expect(provider_fixture.saw_command_output.load(.acquire));

    var history_found = false;
    const history_deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 5 * std.time.ns_per_s;
    while (std.Io.Timestamp.now(io, .real).nanoseconds < history_deadline) {
        const entries = try rig.history_store.list(io, server_id, null, 10);
        defer {
            for (entries) |*entry| entry.deinit(std.testing.allocator);
            std.testing.allocator.free(entries);
        }
        for (entries) |entry| {
            if (!std.mem.eql(u8, entry.operation_id, "itest-ai-run")) continue;
            try std.testing.expectEqualStrings("ai", entry.kind);
            try std.testing.expectEqualStrings(edited_command, entry.command);
            try std.testing.expectEqual(@as(?i32, 0), entry.exit);
            history_found = true;
        }
        if (history_found) break;
        testSleep(25);
    }
    try std.testing.expect(history_found);

    const audits = try rig.audit_store.read(io, server_id, "ai.approved", 10);
    defer {
        for (audits) |*entry| entry.deinit(std.testing.allocator);
        std.testing.allocator.free(audits);
    }
    try std.testing.expectEqual(@as(usize, 1), audits.len);
    try std.testing.expectEqualStrings("itest-ai-run", audits[0].operation_id);
    try std.testing.expectEqualStrings(edited_command, audits[0].commands);
    try std.testing.expectEqualStrings("approved", audits[0].result);

    try refreshContext(&rig, "itest-context-cancel");
    const cancel_turn_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"id\":\"tsc\",\"command\":\"oars.ai.turn.start\",\"payload\":{{\"operation_id\":\"itest-ai-cancel-turn\",\"server_id\":\"{s}\",\"provider_id\":{f},\"expected_provider_revision\":{d},\"message\":\"run until canceled\",\"context_selection\":{{\"os\":true,\"monitor\":false,\"log\":null}}}}}}",
        .{ server_id, std.json.fmt(saved.value.result.provider.?.id, .{}), saved.value.result.provider.?.revision },
    );
    defer std.testing.allocator.free(cancel_turn_request);
    var cancel_turn = try dispatchParsed(&rig, TurnAdmissionResp, cancel_turn_request);
    defer cancel_turn.deinit();
    try std.testing.expect(cancel_turn.value.result.ok);
    try waitForTurnState(&rig, cancel_turn.value.result.turn_id, "awaiting_approval", 15 * std.time.ns_per_s);

    const cancel_thread_request = try std.fmt.allocPrint(std.testing.allocator, "{{\"id\":\"tgc\",\"command\":\"oars.ai.thread.get\",\"payload\":{{\"thread_id\":{f}}}}}", .{std.json.fmt(cancel_turn.value.result.thread_id, .{})});
    defer std.testing.allocator.free(cancel_thread_request);
    var cancel_detail = try dispatchParsed(&rig, ThreadGetResp, cancel_thread_request);
    defer cancel_detail.deinit();
    const cancel_original = cancel_detail.value.result.active_proposal.?;
    const cancel_edit_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"id\":\"pec\",\"command\":\"oars.ai.proposal.edit\",\"payload\":{{\"operation_id\":\"itest-ai-cancel-edit\",\"proposal_id\":{f},\"expected_revision\":{d},\"command\":{f}}}}}",
        .{ std.json.fmt(cancel_original.id, .{}), cancel_original.revision, std.json.fmt(cancel_command, .{}) },
    );
    defer std.testing.allocator.free(cancel_edit_request);
    var cancel_edited = try dispatchParsed(&rig, ProposalResp, cancel_edit_request);
    defer cancel_edited.deinit();
    const cancel_proposal = cancel_edited.value.result.proposal.?;
    try std.testing.expect(!cancel_proposal.local_destructive);

    const cancel_run_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"id\":\"prc\",\"command\":\"oars.ai.proposal.run\",\"payload\":{{\"operation_id\":\"itest-ai-cancel-run\",\"proposal_id\":{f},\"expected_revision\":{d},\"command_sha256\":{f},\"destructive_warning_ack\":false}}}}",
        .{ std.json.fmt(cancel_proposal.id, .{}), cancel_proposal.revision, std.json.fmt(cancel_proposal.command_sha256, .{}) },
    );
    defer std.testing.allocator.free(cancel_run_request);
    var cancel_execution = try dispatchParsed(&rig, ExecutionResp, cancel_run_request);
    defer cancel_execution.deinit();
    try std.testing.expect(cancel_execution.value.result.ok);
    try waitForChannelOutput(&rig, cancel_execution.value.result.channel, "cancel-child-");

    const cancel_request = try std.fmt.allocPrint(std.testing.allocator, "{{\"id\":\"tc\",\"command\":\"oars.ai.turn.cancel\",\"payload\":{{\"turn_id\":{f}}}}}", .{std.json.fmt(cancel_turn.value.result.turn_id, .{})});
    defer std.testing.allocator.free(cancel_request);
    var canceled = try dispatchParsed(&rig, TurnCancelResp, cancel_request);
    defer canceled.deinit();
    try std.testing.expect(canceled.value.result.ok);
    try std.testing.expect(std.mem.eql(u8, canceled.value.result.state, "cancel_requested") or std.mem.eql(u8, canceled.value.result.state, "canceled"));
    try waitForTurnState(&rig, cancel_turn.value.result.turn_id, "canceled", 15 * std.time.ns_per_s);
    try execWait(&rig.manager, server_id, "if pgrep -f '[o]ars-ai-cancel-token' >/dev/null; then exit 1; fi", 0, "");

    var canceled_history_found = false;
    const canceled_history_deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 5 * std.time.ns_per_s;
    while (std.Io.Timestamp.now(io, .real).nanoseconds < canceled_history_deadline) {
        const entries = try rig.history_store.list(io, server_id, null, 10);
        defer {
            for (entries) |*entry| entry.deinit(std.testing.allocator);
            std.testing.allocator.free(entries);
        }
        for (entries) |entry| {
            if (!std.mem.eql(u8, entry.operation_id, "itest-ai-cancel-run")) continue;
            try std.testing.expectEqualStrings("ai", entry.kind);
            try std.testing.expectEqualStrings(cancel_command, entry.command);
            canceled_history_found = true;
        }
        if (canceled_history_found) break;
        testSleep(25);
    }
    try std.testing.expect(canceled_history_found);

    try refreshContext(&rig, "itest-context-disconnect");
    const disconnect_turn_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"id\":\"tsd\",\"command\":\"oars.ai.turn.start\",\"payload\":{{\"operation_id\":\"itest-ai-disconnect-turn\",\"server_id\":\"{s}\",\"provider_id\":{f},\"expected_provider_revision\":{d},\"message\":\"run until the connection closes\",\"context_selection\":{{\"os\":true,\"monitor\":false,\"log\":null}}}}}}",
        .{ server_id, std.json.fmt(saved.value.result.provider.?.id, .{}), saved.value.result.provider.?.revision },
    );
    defer std.testing.allocator.free(disconnect_turn_request);
    var disconnect_turn = try dispatchParsed(&rig, TurnAdmissionResp, disconnect_turn_request);
    defer disconnect_turn.deinit();
    try std.testing.expect(disconnect_turn.value.result.ok);
    try waitForTurnState(&rig, disconnect_turn.value.result.turn_id, "awaiting_approval", 15 * std.time.ns_per_s);

    const disconnect_thread_request = try std.fmt.allocPrint(std.testing.allocator, "{{\"id\":\"tgd\",\"command\":\"oars.ai.thread.get\",\"payload\":{{\"thread_id\":{f}}}}}", .{std.json.fmt(disconnect_turn.value.result.thread_id, .{})});
    defer std.testing.allocator.free(disconnect_thread_request);
    var disconnect_detail = try dispatchParsed(&rig, ThreadGetResp, disconnect_thread_request);
    defer disconnect_detail.deinit();
    const disconnect_original = disconnect_detail.value.result.active_proposal.?;
    const disconnect_edit_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"id\":\"ped\",\"command\":\"oars.ai.proposal.edit\",\"payload\":{{\"operation_id\":\"itest-ai-disconnect-edit\",\"proposal_id\":{f},\"expected_revision\":{d},\"command\":{f}}}}}",
        .{ std.json.fmt(disconnect_original.id, .{}), disconnect_original.revision, std.json.fmt(disconnect_command, .{}) },
    );
    defer std.testing.allocator.free(disconnect_edit_request);
    var disconnect_edited = try dispatchParsed(&rig, ProposalResp, disconnect_edit_request);
    defer disconnect_edited.deinit();
    const disconnect_proposal = disconnect_edited.value.result.proposal.?;
    const disconnect_run_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"id\":\"prd\",\"command\":\"oars.ai.proposal.run\",\"payload\":{{\"operation_id\":\"itest-ai-disconnect-run\",\"proposal_id\":{f},\"expected_revision\":{d},\"command_sha256\":{f},\"destructive_warning_ack\":false}}}}",
        .{ std.json.fmt(disconnect_proposal.id, .{}), disconnect_proposal.revision, std.json.fmt(disconnect_proposal.command_sha256, .{}) },
    );
    defer std.testing.allocator.free(disconnect_run_request);
    var disconnect_execution = try dispatchParsed(&rig, ExecutionResp, disconnect_run_request);
    defer disconnect_execution.deinit();
    try std.testing.expect(disconnect_execution.value.result.ok);
    try waitForChannelOutput(&rig, disconnect_execution.value.result.channel, "disconnect-started");

    rig.manager.disconnect(server_id);
    try waitForTurnState(&rig, disconnect_turn.value.result.turn_id, "recovery_required", 15 * std.time.ns_per_s);
    var reconnect_server = (try rig.store.find(io, server_id)).?;
    defer reconnect_server.deinit(std.testing.allocator);
    _ = try rig.manager.connect(reconnect_server, env.password, null);
    try waitForStatus(&rig.manager, server_id, .ready, 20 * std.time.ns_per_s);
    try execWait(&rig.manager, server_id, "test \"$(cat /tmp/oars-ai-disconnect-count)\" = 1", 0, "");
    try execWait(&rig.manager, server_id, "pkill -f '[o]ars-ai-disconnect-token' 2>/dev/null || true; rm -f " ++ log_path ++ " /tmp/oars-ai-integration-marker /tmp/oars-ai-disconnect-count", 0, "");
}
