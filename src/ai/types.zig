//! Shared AI Terminal domain contract (Spec 11).
//!
//! These types contain no provider-specific wire data and no credentials.

const std = @import("std");

pub const schema_version: u8 = 1;

pub const max_providers: usize = 16;
pub const max_threads: usize = 100;
pub const max_turns_per_thread: usize = 50;
pub const max_message_bytes: usize = 16 * 1024;
pub const max_command_bytes: usize = 64 * 1024;
pub const max_explanation_bytes: usize = 8 * 1024;
pub const max_question_bytes: usize = 8 * 1024;
pub const max_log_tail_bytes: usize = 64 * 1024;
pub const max_request_body_bytes: usize = 128 * 1024;
pub const max_response_headers_bytes: usize = 64 * 1024;
pub const max_sse_event_bytes: usize = 256 * 1024;
pub const max_structured_output_bytes: usize = 128 * 1024;
pub const max_error_body_bytes: usize = 8 * 1024;
pub const max_events: usize = 1024;
pub const max_event_bytes: usize = 1024 * 1024;
pub const max_continuation_bytes: usize = 512 * 1024;
pub const max_provider_requests: usize = 2;
pub const max_provider_requests_per_thread: usize = 1;
pub const max_secret_bytes: usize = 4096;
pub const max_operation_id_bytes: usize = 64;

pub const ErrorCode = enum {
    invalid_argument,
    not_found,
    conflict,
    stale_revision,
    not_connected,
    credential_missing,
    provider_untested,
    busy,
    limit_exceeded,
    provider_auth,
    provider_rate_limited,
    provider_timeout,
    provider_protocol,
    recovery_required,
};

pub const TurnState = enum {
    queued,
    collecting_context,
    requesting,
    streaming,
    validating,
    awaiting_approval,
    approved,
    executing,
    summarizing,
    completed,
    failed,
    cancel_requested,
    canceled,
    interrupted,
    recovery_required,

    pub fn terminal(self: TurnState) bool {
        return self == .completed or self == .failed or self == .canceled or self == .interrupted or self == .recovery_required;
    }
};

pub const ProposalState = enum {
    awaiting_approval,
    approved,
    executing,
    completed,
    failed,
    canceled,
    expired,
    recovery_required,
};

pub const RetryPolicy = enum { explicit, never };

/// Stable mutation identifier accepted by all AI write commands.
pub fn validOperationId(value: []const u8) bool {
    if (value.len == 0 or value.len > max_operation_id_bytes) return false;
    for (value) |ch| switch (ch) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', ':', '_', '-' => {},
        else => return false,
    };
    return true;
}

/// Provider-neutral event. `payload_json` is validated and bounded before
/// insertion; bridge serialization writes it as an object, not a string.
pub const Event = struct {
    version: u8 = schema_version,
    sequence: u64,
    stream_id: []const u8,
    type: []const u8,
    payload_json: []const u8,
};

pub const EventPoll = struct {
    ok: bool = true,
    stream_id: []const u8,
    cursor: u64,
    dropped: u64,
    finished: bool,
    state: []const u8,
    events: []const Event,
};

pub const Proposal = struct {
    id: []const u8,
    turn_id: []const u8,
    revision: u64,
    server_id: []const u8,
    provider_id: []const u8,
    provider_revision: u64,
    context_hash: []const u8,
    command: []const u8,
    command_sha256: []const u8,
    explanation: []const u8,
    model_destructive: bool,
    local_destructive: bool,
    needs_sudo: bool,
    created_at_ms: i64,
    expires_at_ms: i64,
    state: ProposalState,
};

test "operation IDs use the frozen ASCII grammar" {
    try std.testing.expect(validOperationId("turn:01_save-retry.2"));
    try std.testing.expect(!validOperationId(""));
    try std.testing.expect(!validOperationId("has space"));
    try std.testing.expect(!validOperationId("slash/not-allowed"));
    try std.testing.expect(!validOperationId("non-ascii-\xc3\xa9"));
    var oversized: [max_operation_id_bytes + 1]u8 = @splat('a');
    try std.testing.expect(!validOperationId(&oversized));
}

test "frozen bounds remain explicit" {
    try std.testing.expectEqual(@as(usize, 16), max_providers);
    try std.testing.expectEqual(@as(usize, 50), max_turns_per_thread);
    try std.testing.expectEqual(@as(usize, 4096), max_secret_bytes);
    try std.testing.expectEqual(@as(usize, 128 * 1024), max_request_body_bytes);
    try std.testing.expectEqual(@as(usize, 1024 * 1024), max_event_bytes);
}
