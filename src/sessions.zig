//! SSH session manager.
//!
//! Each connected server gets one worker thread owning its libssh2
//! session (libssh2 is not thread-safe per session). The runtime's main
//! thread never blocks on the network: bridge handlers exchange data
//! through small locked structures — output streams with cursor-based
//! deltas (polled by the frontend), an input queue, and an op queue.

const std = @import("std");
const builtin = @import("builtin");
const ssh = @import("ssh.zig");
const servers = @import("servers.zig");
const openssh = @import("openssh.zig");
const monitor = @import("monitor.zig");
const history = @import("history.zig");
const logs = @import("logs.zig");
const sftpmod = @import("sftp.zig");
const shellquote = @import("shellquote.zig");
const broadcast = @import("broadcast.zig");
const deploy = @import("deploy.zig");
const preflight = @import("preflight.zig");
const wsmod = @import("ws.zig");
const agent = @import("agent.zig");
const shell_integration = @import("shell_integration.zig");

// Use the imported variadic C declaration. A fixed third argument uses
// the wrong ABI on Darwin ARM64 and can leave a supposedly non-blocking fd blocking.
fn configureNonBlockingSocket(fd: std.posix.socket_t) !void {
    const flags = ssh.c.fcntl(fd, ssh.c.F_GETFL);
    if (flags < 0 or ssh.c.fcntl(fd, ssh.c.F_SETFL, @as(c_int, flags | ssh.c.O_NONBLOCK)) < 0) return error.ConnectionFailed;
    if (comptime @hasDecl(ssh.c, "SO_NOSIGPIPE")) {
        var one: c_int = 1;
        _ = ssh.c.setsockopt(fd, ssh.c.SOL_SOCKET, ssh.c.SO_NOSIGPIPE, &one, @sizeOf(c_int));
    }
}

fn socketWriteNoSigpipe(fd: std.posix.socket_t, bytes: []const u8) isize {
    if (comptime @hasDecl(ssh.c, "MSG_NOSIGNAL")) {
        return ssh.c.send(fd, bytes.ptr, bytes.len, ssh.c.MSG_NOSIGNAL);
    }
    return ssh.c.write(fd, bytes.ptr, bytes.len);
}

/// Monitor cadence only needs differences over a few seconds. A signed 64-bit
/// nanosecond clock is atomic on every supported desktop target and covers real
/// timestamps through 2262; clamp defensively rather than requiring i128 atomics.
pub fn monitorTimeNs(value: i128) i64 {
    return std.math.cast(i64, value) orelse if (value < 0) std.math.minInt(i64) else std.math.maxInt(i64);
}

/// Blocking acquire on std.atomic.Mutex (spinlock) — 0.16's atomic.Mutex
/// only exposes tryLock. Sections are short (buffer/cursor updates), so
/// spinning is appropriate.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

fn secureFreeBytes(allocator: std.mem.Allocator, bytes: []u8) void {
    if (bytes.len == 0) return;
    std.crypto.secureZero(u8, bytes);
    allocator.rawFree(bytes, .fromByteUnits(@alignOf(u8)), @returnAddress());
}

pub const Status = enum(u8) {
    connecting,
    needs_trust,
    authenticating,
    ready,
    closed,
    @"error",

    pub fn jsonName(self: Status) []const u8 {
        return switch (self) {
            .connecting => "connecting",
            .needs_trust => "needs_trust",
            .authenticating => "authenticating",
            .ready => "ready",
            .closed => "closed",
            .@"error" => "error",
        };
    }
};

pub const ChannelKind = enum(u8) {
    shell,
    exec,
    /// Follow channel (spec 04): a long-lived tail stream.
    log,

    pub fn jsonName(self: ChannelKind) []const u8 {
        return switch (self) {
            .shell => "shell",
            .exec => "exec",
            .log => "log",
        };
    }
};

/// Bounded output stream with non-destructive reads.
/// Written by the session worker, read by bridge handlers; all access
/// under a spinlock (sections are short, no Io needed). Every consumer
/// supplies its own absolute cursor: reads never advance stream state, so
/// mirrored tabs drain the same retained bytes independently (spec 02 §6.3).
pub const Stream = struct {
    mutex: std.atomic.Mutex = .unlocked,
    allocator: std.mem.Allocator,
    data: std.ArrayList(u8) = .empty,
    /// Absolute position of data[0] in the logical stream.
    start_abs: u64 = 0,
    /// Absolute position one past the last byte in `data`.
    end_abs: u64 = 0,
    /// Bytes discarded because the buffer cap was hit before delivery.
    dropped: u64 = 0,
    eof: bool = false,
    exit_status: ?i32 = null,
    max_bytes: usize = 4 * 1024 * 1024,

    pub fn init(allocator: std.mem.Allocator) Stream {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Stream, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
    }

    pub fn append(self: *Stream, bytes: []const u8) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const needed = self.data.items.len + bytes.len;
        if (needed > self.max_bytes) {
            const drop = @min(needed - self.max_bytes, self.data.items.len);
            if (drop > 0) {
                std.mem.copyForwards(
                    u8,
                    self.data.items[0 .. self.data.items.len - drop],
                    self.data.items[drop..],
                );
                self.data.items.len -= drop;
                self.start_abs += drop;
                self.dropped += @intCast(drop);
            }
        }
        try self.data.appendSlice(self.allocator, bytes);
        self.end_abs += bytes.len;
    }

    /// Absolute position of the oldest retained byte.
    pub fn start(self: *Stream) u64 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.start_abs;
    }

    /// Non-destructive read: copies up to out.len retained bytes starting
    /// at absolute position `from` (clamped to the retained window).
    /// Returns bytes copied; no cursor advances.
    pub fn readAt(self: *Stream, from: u64, out: []u8) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const rel = from -| self.start_abs;
        if (rel >= self.data.items.len) return 0;
        const avail = self.data.items.len - rel;
        const n = @min(avail, out.len);
        @memcpy(out[0..n], self.data.items[rel .. rel + n]);
        return n;
    }

    pub const View = struct {
        /// Bytes this consumer missed because the buffer cap dropped them
        /// before its cursor (0 for a consumer at/after the retained start).
        gap: u64,
        /// Absolute position to read from (max of cursor and retained start).
        from: u64,
        /// Bytes available to this consumer right now.
        pending: u64,
    };

    /// Consumer view from absolute cursor `from` (spec 02 §5: each poll
    /// reports the requesting tab's own gap).
    pub fn view(self: *Stream, from: u64) View {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const read_from = @max(from, self.start_abs);
        return .{
            .gap = self.start_abs -| from,
            .from = read_from,
            .pending = self.end_abs - read_from,
        };
    }

    pub const Snapshot = struct {
        eof: bool,
        exit_status: ?i32,
    };

    pub fn snapshot(self: *Stream) Snapshot {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return .{ .eof = self.eof, .exit_status = self.exit_status };
    }
};

pub const ChannelEntry = struct {
    id: u32,
    kind: ChannelKind,
    /// Exec command text; allocated by the manager, freed at session
    /// teardown (or when the completed exec is evicted).
    command: []const u8 = "",
    /// Spec 15: non-null means this channel's completion is recorded in
    /// command history under this kind (`exec|script|deploy|backup|…`).
    /// Owned by the entry; freed with the command text.
    history_kind: ?[]const u8 = null,
    /// Optional pre-redacted command text to record (the executed command
    /// is recorded when null). Owned by the entry.
    history_command: ?[]const u8 = null,
    history_command_redacted: bool = true,
    /// Known secret values (owned array of owned strings) — the command
    /// and the output snippet are masked with them at capture.
    history_secrets: ?[][]const u8 = null,
    /// Stable feature operation ID used by AI approval/history recovery.
    /// When null, ordinary execs keep the session-local `exec-N` identity.
    history_operation_id: ?[]const u8 = null,
    /// Monotonic time the channel opened (duration for history).
    started_ns: i128 = 0,
    stream: *Stream,
    raw: *ssh.Channel,
    stdin_mutex: std.atomic.Mutex = .unlocked,
    stdin_queue: std.ArrayList(u8) = .empty,
    /// Set for execWithInput until all queued bytes and EOF reach libssh2.
    stdin_eof_pending: bool = false,
    eof_seen: bool = false,
    /// Set once the raw libssh2 channel is closed and freed; session
    /// teardown must not close it again.
    raw_closed: bool = false,
    /// Worker-internal channel (monitor probe): never exposed in polls;
    /// its output is consumed by the worker at EOF.
    internal: bool = false,
    /// Spec 06: worker-driven `bash -n` syntax check in flight. The worker
    /// completes the outcome at EOF, on timeout, or in session teardown;
    /// the handler owns it until abandoned (cancel). Only set on internal
    /// channels.
    check_outcome: ?*broadcast.ScriptCheckOutcome = null,
    /// Bounded wait for the syntax check (0 = no deadline).
    check_timeout_ns: i128 = 0,
    /// Spec 07: deploy preflight probe — read-only exec output buffered on
    /// the internal channel; drained at EOF into the preflight outcome.
    preflight_probe: ?*preflight.ProbeOutcome = null,
    preflight_timeout_ns: i128 = 0,
    preflight_id: ?[]const u8 = null,
    /// Spec 09: fleet scan inline exec. One internal `exec` per
    /// scan-phase command; outcome is consumed in the next poll.
    access_exec_outcome: ?*AccessExecOutcome = null,
    access_exec_timeout_ns: i128 = 0,
    access_exec_cap: usize = 0,
    /// Spec 11: asynchronous AI context probe. It is an untracked,
    /// read-only internal channel with an operation ID for cancellation.
    ai_context_outcome: ?*AiContextOutcome = null,
    ai_context_operation_id: ?[]const u8 = null,
    ai_context_timeout_ns: i128 = 0,
    ai_context_cap: usize = 0,
    /// Spec 10: bounded backup execs and streamed manual runs use dedicated
    /// outcomes so the coordinator can observe worker-owned libssh2 work.
    backup_outcome: ?*BackupOutcome = null,
    backup_timeout_ns: i128 = 0,
    backup_cap: usize = 0,
    backup_process: ?*BackupProcess = null,
    /// AI commands start in a dedicated remote process group. The worker
    /// consumes the private first-line marker and does not publish it as
    /// command output.
    ai_marker_pending: bool = false,
    ai_marker: [64]u8 = undefined,
    ai_marker_len: usize = 0,
    ai_pgid: [20]u8 = undefined,
    ai_pgid_len: usize = 0,

    /// Frees the command text and the optional history strings. Every
    /// path that drops an entry (eviction, close, teardown) must call
    /// this instead of freeing `command` alone.
    pub fn freeCommandText(self: *ChannelEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.command);
        if (self.history_kind) |hk| allocator.free(hk);
        if (self.history_command) |hc| allocator.free(hc);
        if (self.history_operation_id) |operation_id| allocator.free(operation_id);
        if (self.history_secrets) |hs| {
            for (hs) |s| allocator.free(s);
            allocator.free(hs);
        }
        if (self.ai_context_operation_id) |operation_id| allocator.free(operation_id);
    }

    fn clearStdin(self: *ChannelEntry, allocator: std.mem.Allocator) void {
        if (self.stdin_queue.items.len > 0) std.crypto.secureZero(u8, self.stdin_queue.items);
        if (self.stdin_queue.capacity > 0) allocator.rawFree(self.stdin_queue.allocatedSlice(), .fromByteUnits(@alignOf(u8)), @returnAddress());
        self.stdin_queue = .empty;
        self.stdin_eof_pending = false;
    }
};

const Op = union(enum) {
    exec: struct {
        id: u32,
        command: []const u8,
        /// Optional stdin for a bounded non-interactive exec. Owned by the
        /// op and cleared as soon as the worker has written it.
        stdin_data: ?[]u8 = null,
        /// Spec 15: when non-null the completed run is recorded in
        /// command history under this kind. Owned by the op; the channel
        /// entry takes them over (or frees them) when the op runs.
        history_kind: ?[]const u8 = null,
        history_command: ?[]const u8 = null,
        history_command_redacted: bool = true,
        /// Known secret values of the operation (spec 15: the stored
        /// command AND the output snippet are masked with them). Owned
        /// array of owned strings.
        history_secrets: ?[][]const u8 = null,
        history_operation_id: ?[]const u8 = null,
        ai_execution: bool = false,
    },
    follow: struct { id: u32, command: []const u8 },
    resize: struct { cols: c_int, rows: c_int },
    close,
    close_channel: struct { id: u32 },
    clear: struct { path: []const u8, expected: ClearExpected, outcome: *ClearOutcome },
    sftp_ls: struct { path: []const u8, outcome: *SftpOutcome },
    sftp_stat: struct { path: []const u8, outcome: *SftpOutcome },
    sftp_read: struct { path: []const u8, offset: u64, max: usize, outcome: *SftpOutcome },
    sftp_write_chunk: struct {
        path: []const u8,
        offset: u64,
        data: []const u8,
        total: u64,
        transfer_id: u32,
        outcome: *SftpOutcome,
    },
    sftp_save: struct {
        path: []const u8,
        data: []const u8,
        /// A null identity keeps the non-editor save behavior. The SHA-256
        /// slice inside a non-null value is owned by this operation.
        expected: ?SftpExpectedIdentity = null,
        outcome: *SftpOutcome,
    },
    sftp_mkdir: struct { path: []const u8, outcome: *SftpOutcome },
    sftp_rm: struct { path: []const u8, recursive: bool, transfer_id: u32, outcome: ?*SftpOutcome },
    sftp_rename: struct { from: []const u8, to: []const u8, outcome: *SftpOutcome },
    sftp_chmod: struct { path: []const u8, mode: u32, outcome: *SftpOutcome },
    sftp_download: struct {
        remote: []const u8,
        local_partial: []const u8,
        local_final: []const u8,
        transfer_id: u32,
        outcome: ?*SftpOutcome,
    },
    sftp_upload_local: struct {
        local: []const u8,
        remote: []const u8,
        transfer_id: u32,
    },
    sftp_unzip: struct {
        zip_path: []const u8,
        dest: []const u8,
        transfer_id: u32,
        outcome: ?*SftpOutcome,
    },
    sftp_zip_download: struct {
        paths: [][]const u8,
        local_partial: []const u8,
        local_final: []const u8,
        transfer_id: u32,
        outcome: ?*SftpOutcome,
    },
    sftp_cancel: struct { transfer_id: u32 },
    tunnel_start: struct {
        id: u32,
        token: []const u8,
        host: []const u8,
        port: u16,
        outcome: *TunnelStartOutcome,
    },
    tunnel_stop: struct { id: u32 },
    /// Spec 18: agent-forwarding toggle — reopens the shell with (or
    /// without) the auth-agent request.
    forward_set: struct { on: bool, outcome: *ForwardSetOutcome },
    /// Spec 18: opens the direct-tcpip channel to the target through
    /// this (via) session and registers the jump tunnel. `fd` is the
    /// local socketpair end the worker pumps against. Owns `host` and
    /// `target_server_id`.
    jump_start: struct {
        host: []const u8,
        port: u16,
        fd: std.posix.socket_t,
        target_server_id: []const u8,
        outcome: *JumpStartOutcome,
    },
    /// Spec 06: worker-driven `bash -n -c` syntax check for a broadcast
    /// server. Runs as an internal channel so the worker pump drives it
    /// without blocking; the poll handler reads the outcome on later
    /// polls. Owns `command`; the outcome follows the heap + abandon()
    /// protocol.
    syntax_check: struct {
        command: []const u8,
        timeout_ns: i128,
        outcome: *broadcast.ScriptCheckOutcome,
    },
    /// Spec 07: deploy preflight probes — read-only execs run by the
    /// session worker as internal channels (bounded output+deadline).
    preflight_probe: struct {
        id: []const u8,
        /// Owned; one command per probe. Required snapshot reads for Phase 2
        /// (os_release, node_version, etc.) inline as separate probes;
        /// mutation is never performed.
        command: []const u8,
        timeout_ns: i128,
        outcome: *preflight.ProbeOutcome,
    },
    /// Spec 09: fleet scan inline exec (bounded output + deadline).
    /// The probe pattern is reused: the command runs as an internal
    /// channel, the worker drains at EOF/timeout, and the poll thread
    /// consumes the result to advance scan state.
    access_exec: struct {
        command: []const u8,
        timeout_ns: i128,
        cap: usize,
        outcome: *AccessExecOutcome,
    },
    /// Spec 11: context probes are queued and drained on the owning SSH
    /// worker. The bridge only admits and polls this operation.
    ai_context: struct {
        operation_id: []const u8,
        command: []const u8,
        timeout_ns: i128,
        cap: usize,
        outcome: *AiContextOutcome,
    },
    ai_context_cancel: struct { operation_id: []const u8 },
    /// Spec 10: all backup exec/SFTP calls remain on the owning worker.
    backup: struct {
        request: BackupRequest,
        outcome: *BackupOutcome,
    },
    /// A long-lived rclone channel. The worker appends stream bytes and owns
    /// channel close; cancellation is performed by separate bounded execs.
    backup_run: struct {
        command: []const u8,
        stdin_data: ?[]u8,
        process: *BackupProcess,
    },
};

/// Not an observed SFTP status: the op failed before a protocol status
/// existed (local errors, transport loss, timeouts).
pub const fx_unknown: i64 = -1;

/// Completion record for synchronous SFTP ops (spec 05): the worker builds
/// the full success JSON (owned), the handler copies it into its output
/// buffer and frees it. Async ops (download/unzip/zip_download/recursive rm)
/// signal through the transfer record instead and pass a null outcome.
///
/// Lifetime: heap-allocated by the handler. The handler either reads a
/// completed result and destroys it, or its wait deadline expires and it
/// calls `abandon` — transferring ownership to the op, whose eventual
/// set()/setJson() (worker processing, or sessionDone's drain) then frees
/// the struct. The handshake happens under the mutex, so exactly one side
/// owns the free; a late set can never write into a dead stack frame
/// (the tunnel-start worker panic this design fixes).
pub const SftpOutcome = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    done: bool = false,
    ok: bool = false,
    abandoned: bool = false,
    msg_buf: [256]u8 = undefined,
    msg_len: usize = 0,
    /// The SFTP protocol status (LIBSSH2_FX_*) of a failed op, when the
    /// worker could observe one; fx_unknown otherwise. Lets typed
    /// consumers (spec 08 source outcomes) distinguish missing, denied,
    /// and transport failures instead of guessing from message text.
    fx: i64 = fx_unknown,
    /// Owned success payload (worker-built JSON). Read only after `isDone`.
    json: ?[]u8 = null,

    pub fn set(self: *SftpOutcome, ok: bool, msg: []const u8) void {
        lockSpin(&self.mutex);
        self.ok = ok;
        const n = @min(msg.len, self.msg_buf.len - 1);
        @memcpy(self.msg_buf[0..n], msg[0..n]);
        self.msg_len = n;
        self.done = true;
        const free = self.abandoned;
        self.mutex.unlock();
        if (free) self.allocator.destroy(self);
    }

    /// set() plus the observed SFTP status code (see `fx`).
    pub fn setFx(self: *SftpOutcome, ok: bool, msg: []const u8, fx: i64) void {
        lockSpin(&self.mutex);
        self.fx = fx;
        self.mutex.unlock();
        self.set(ok, msg);
    }

    pub fn setJson(self: *SftpOutcome, json: []u8) void {
        lockSpin(&self.mutex);
        self.json = json;
        self.ok = true;
        self.done = true;
        const free = self.abandoned;
        self.mutex.unlock();
        if (free) {
            self.allocator.free(json);
            self.allocator.destroy(self);
        }
    }

    /// Handler-side deadline escape: marks the outcome abandoned so the
    /// op's eventual set frees it. Returns true when the worker already
    /// completed it — the handler keeps ownership and reads the result.
    pub fn abandon(self: *SftpOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.abandoned = true;
        return self.done;
    }

    pub fn message(self: *SftpOutcome) []const u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.msg_buf[0..self.msg_len];
    }

    pub fn isDone(self: *SftpOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.done;
    }

    /// Spins until done or the deadline passes (the handler must never
    /// block the main thread indefinitely).
    pub fn wait(self: *SftpOutcome, io: std.Io, deadline_ns: i128) void {
        while (true) {
            lockSpin(&self.mutex);
            const done = self.done;
            self.mutex.unlock();
            if (done) return;
            if (std.Io.Timestamp.now(io, .real).nanoseconds >= deadline_ns) return;
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch return;
        }
    }
};

/// The exact remote-file version that an editor opened. Keeping the fields
/// together prevents save call sites from mixing identities from different
/// reads (spec 05 §4.2).
pub const SftpExpectedIdentity = struct {
    size: ?u64 = null,
    mtime: ?u64 = null,
    sha256: ?[]const u8 = null,
    /// True when the reviewed source did not exist. A file appearing before
    /// the atomic rename is a conflict, even if it is empty.
    missing: bool = false,
    /// Feature-specific hashing cap. Editor saves keep the 1 MiB default;
    /// SSH authorized_keys raises it to its bounded 4 MiB source limit.
    max_hash_bytes: u64 = sftpmod.max_inline_bytes,
};

pub const ClearExpected = struct {
    size: u64,
    mtime: u64,
    mode: u32,
};

/// Completion record for the clear op: the worker writes it (under its
/// mutex), the bridge handler waits on it (bounded). The path is validated
/// by the handler before the op is queued. Heap + abandonment lifetime:
/// see SftpOutcome's doc comment.
pub const ClearOutcome = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    done: bool = false,
    ok: bool = false,
    abandoned: bool = false,
    msg_buf: [256]u8 = undefined,
    msg_len: usize = 0,
    before_size: u64 = 0,
    after_size: u64 = 0,

    pub fn set(self: *ClearOutcome, ok: bool, msg: []const u8) void {
        lockSpin(&self.mutex);
        self.ok = ok;
        const n = @min(msg.len, self.msg_buf.len - 1);
        @memcpy(self.msg_buf[0..n], msg[0..n]);
        self.msg_len = n;
        self.done = true;
        const free = self.abandoned;
        self.mutex.unlock();
        if (free) self.allocator.destroy(self);
    }

    /// Handler-side deadline escape; see SftpOutcome.abandon.
    pub fn abandon(self: *ClearOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.abandoned = true;
        return self.done;
    }

    pub fn message(self: *ClearOutcome) []const u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.msg_buf[0..self.msg_len];
    }

    pub fn isDone(self: *ClearOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.done;
    }

    /// Spins until done or the deadline passes (the handler must never
    /// block the main thread indefinitely).
    pub fn wait(self: *ClearOutcome, io: std.Io, deadline_ns: i128) void {
        while (true) {
            lockSpin(&self.mutex);
            const done = self.done;
            self.mutex.unlock();
            if (done) return;
            if (std.Io.Timestamp.now(io, .real).nanoseconds >= deadline_ns) return;
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch return;
        }
    }
};

/// Spec 09: inline exec for fleet scans — one internal `exec` per phase
/// step. Mirrors `syntax_check` / `preflight_probe`: owning handler
/// enqueues the command, worker opens an internal channel, and the
/// bridge consumes the outcome on the next poll. Outcome heap +
/// `abandon()` protocol matches every other worker outcome (session 30).
pub const BackupOutcomeCode = enum {
    ok,
    timeout,
    disconnected,
    not_found,
    permission_denied,
    too_large,
    conflict,
    transport,
    unsupported,
    internal,
};

/// Coordinator-facing result for one bounded backup request. The requester
/// destroys a completed outcome; `abandon` transfers destruction to the worker.
pub const BackupOutcome = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    done: bool = false,
    abandoned: bool = false,
    code: BackupOutcomeCode = .internal,
    exit: ?i32 = null,
    fx: i64 = fx_unknown,
    overflow: bool = false,
    sensitive_result: bool = false,
    msg_buf: [256]u8 = undefined,
    msg_len: usize = 0,
    data: std.ArrayList(u8) = .empty,

    pub fn deinitData(self: *BackupOutcome) void {
        if (self.sensitive_result and self.data.items.len > 0) std.crypto.secureZero(u8, self.data.items);
        self.data.deinit(self.allocator);
    }

    pub const Result = struct {
        code: BackupOutcomeCode,
        exit: ?i32,
        fx: i64,
        overflow: bool,
        message: []u8,
        data: []u8,

        pub fn deinit(self: *Result, allocator: std.mem.Allocator, sensitive: bool) void {
            allocator.free(self.message);
            if (sensitive) {
                secureFreeBytes(allocator, self.data);
            } else {
                allocator.free(self.data);
            }
        }
    };

    pub fn set(self: *BackupOutcome, code: BackupOutcomeCode, exit: ?i32, fx: i64, overflow: bool, data: []const u8, message: []const u8) void {
        lockSpin(&self.mutex);
        if (data.len > 0) self.data.appendSlice(self.allocator, data) catch {
            self.code = .internal;
            self.exit = null;
            self.fx = fx_unknown;
            self.overflow = false;
            const fallback = "out of memory copying backup outcome";
            @memcpy(self.msg_buf[0..fallback.len], fallback);
            self.msg_len = fallback.len;
            self.done = true;
            const free = self.abandoned;
            self.mutex.unlock();
            if (free) {
                self.deinitData();
                self.allocator.destroy(self);
            }
            return;
        };
        self.code = code;
        self.exit = exit;
        self.fx = fx;
        self.overflow = overflow;
        const n = @min(message.len, self.msg_buf.len - 1);
        @memcpy(self.msg_buf[0..n], message[0..n]);
        self.msg_len = n;
        self.done = true;
        const free = self.abandoned;
        self.mutex.unlock();
        if (free) {
            self.deinitData();
            self.allocator.destroy(self);
        }
    }

    pub fn isDone(self: *BackupOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.done;
    }

    pub fn abandon(self: *BackupOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.done) return true;
        self.abandoned = true;
        return false;
    }

    pub fn copyResult(self: *BackupOutcome, allocator: std.mem.Allocator) !Result {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (!self.done) return error.NotDone;
        const message = try allocator.dupe(u8, self.msg_buf[0..self.msg_len]);
        errdefer allocator.free(message);
        const data = try allocator.dupe(u8, self.data.items);
        return .{
            .code = self.code,
            .exit = self.exit,
            .fx = self.fx,
            .overflow = self.overflow,
            .message = message,
            .data = data,
        };
    }
};

pub const BackupRequest = union(enum) {
    exec: struct {
        command: []const u8,
        stdin_data: ?[]const u8 = null,
        timeout_ns: i128,
        cap: usize,
        history_command: []const u8,
        sensitive_stdin: bool = false,
    },
    sftp_stat: struct { path: []const u8 },
    sftp_list: struct { path: []const u8 },
    sftp_read: struct { path: []const u8, max: usize },
    sftp_write: struct { path: []const u8, data: []const u8, sensitive: bool = false },
    sftp_mkdir: struct { path: []const u8 },
    sftp_chmod: struct { path: []const u8, mode: u32 },
    sftp_remove: struct { path: []const u8 },
    sftp_rename: struct { from: []const u8, to: []const u8 },
};

/// Stream retained for one manual backup process. Cursors are absolute and
/// non-destructive; overflow drops only the oldest retained bytes.
fn cloneBackupRequest(allocator: std.mem.Allocator, request: BackupRequest) !BackupRequest {
    return switch (request) {
        .exec => |value| blk: {
            const command = try allocator.dupe(u8, value.command);
            errdefer allocator.free(command);
            const stdin_data: ?[]u8 = if (value.stdin_data) |input| try allocator.dupe(u8, input) else null;
            errdefer {
                if (stdin_data) |input| {
                    if (value.sensitive_stdin) {
                        secureFreeBytes(allocator, input);
                    } else {
                        allocator.free(input);
                    }
                }
            }
            const history_command = try allocator.dupe(u8, value.history_command);
            break :blk .{ .exec = .{
                .command = command,
                .stdin_data = stdin_data,
                .timeout_ns = value.timeout_ns,
                .cap = value.cap,
                .history_command = history_command,
                .sensitive_stdin = value.sensitive_stdin,
            } };
        },
        .sftp_stat => |value| .{ .sftp_stat = .{ .path = try allocator.dupe(u8, value.path) } },
        .sftp_list => |value| .{ .sftp_list = .{ .path = try allocator.dupe(u8, value.path) } },
        .sftp_read => |value| .{ .sftp_read = .{ .path = try allocator.dupe(u8, value.path), .max = value.max } },
        .sftp_write => |value| blk: {
            const path = try allocator.dupe(u8, value.path);
            errdefer allocator.free(path);
            const data = try allocator.dupe(u8, value.data);
            break :blk .{ .sftp_write = .{ .path = path, .data = data, .sensitive = value.sensitive } };
        },
        .sftp_mkdir => |value| .{ .sftp_mkdir = .{ .path = try allocator.dupe(u8, value.path) } },
        .sftp_chmod => |value| .{ .sftp_chmod = .{ .path = try allocator.dupe(u8, value.path), .mode = value.mode } },
        .sftp_remove => |value| .{ .sftp_remove = .{ .path = try allocator.dupe(u8, value.path) } },
        .sftp_rename => |value| blk: {
            const from = try allocator.dupe(u8, value.from);
            errdefer allocator.free(from);
            const to = try allocator.dupe(u8, value.to);
            break :blk .{ .sftp_rename = .{ .from = from, .to = to } };
        },
    };
}

fn freeBackupRequest(allocator: std.mem.Allocator, request: BackupRequest) void {
    switch (request) {
        .exec => |value| {
            allocator.free(value.command);
            if (value.stdin_data) |input| {
                if (value.sensitive_stdin) {
                    secureFreeBytes(allocator, @constCast(input));
                } else {
                    allocator.free(input);
                }
            }
            allocator.free(value.history_command);
        },
        .sftp_stat => |value| allocator.free(value.path),
        .sftp_list => |value| allocator.free(value.path),
        .sftp_read => |value| allocator.free(value.path),
        .sftp_write => |value| {
            allocator.free(value.path);
            if (value.sensitive) {
                secureFreeBytes(allocator, @constCast(value.data));
            } else {
                allocator.free(value.data);
            }
        },
        .sftp_mkdir => |value| allocator.free(value.path),
        .sftp_chmod => |value| allocator.free(value.path),
        .sftp_remove => |value| allocator.free(value.path),
        .sftp_rename => |value| {
            allocator.free(value.from);
            allocator.free(value.to);
        },
    }
}

pub const BackupProcess = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    done: bool = false,
    abandoned: bool = false,
    exit: ?i32 = null,
    disconnected: bool = false,
    start_pos: u64 = 0,
    data: std.ArrayList(u8) = .empty,
    msg_buf: [256]u8 = undefined,
    msg_len: usize = 0,

    pub const Snapshot = struct {
        done: bool,
        exit: ?i32,
        disconnected: bool,
        cursor: u64,
        dropped: u64,
        data: []u8,
        message: []u8,

        pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
            allocator.free(self.data);
            allocator.free(self.message);
        }
    };

    fn append(self: *BackupProcess, bytes: []const u8) void {
        const cap = 4 * 1024 * 1024;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (bytes.len >= cap) {
            self.start_pos += self.data.items.len + bytes.len - cap;
            self.data.clearRetainingCapacity();
            self.data.appendSlice(self.allocator, bytes[bytes.len - cap ..]) catch {};
            return;
        }
        const excess = self.data.items.len + bytes.len -| cap;
        if (excess > 0) {
            std.mem.copyForwards(u8, self.data.items[0 .. self.data.items.len - excess], self.data.items[excess..]);
            self.data.items.len -= excess;
            self.start_pos += excess;
        }
        self.data.appendSlice(self.allocator, bytes) catch {};
    }

    pub fn complete(self: *BackupProcess, exit: ?i32, disconnected: bool, message: []const u8) void {
        lockSpin(&self.mutex);
        self.exit = exit;
        self.disconnected = disconnected;
        const n = @min(message.len, self.msg_buf.len - 1);
        @memcpy(self.msg_buf[0..n], message[0..n]);
        self.msg_len = n;
        self.done = true;
        const free = self.abandoned;
        self.mutex.unlock();
        if (free) {
            self.data.deinit(self.allocator);
            self.allocator.destroy(self);
        }
    }

    pub fn snapshot(self: *BackupProcess, allocator: std.mem.Allocator, cursor: u64, max: usize) !Snapshot {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const effective = @max(cursor, self.start_pos);
        const offset: usize = @intCast(@min(effective - self.start_pos, self.data.items.len));
        const len = @min(max, self.data.items.len - offset);
        const data = try allocator.dupe(u8, self.data.items[offset .. offset + len]);
        errdefer allocator.free(data);
        const message = try allocator.dupe(u8, self.msg_buf[0..self.msg_len]);
        return .{
            .done = self.done,
            .exit = self.exit,
            .disconnected = self.disconnected,
            .cursor = effective + len,
            .dropped = effective - cursor,
            .data = data,
            .message = message,
        };
    }

    pub fn abandon(self: *BackupProcess) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.done) return true;
        self.abandoned = true;
        return false;
    }
};

/// Spec 09: inline exec for fleet scans — one internal `exec` per phase
/// step. Mirrors `syntax_check` / `preflight_probe`: owning handler
/// enqueues the command, worker opens an internal channel, and the
/// bridge consumes the outcome on the next poll. Outcome heap +
/// `abandon()` protocol matches every other worker outcome (session 30).
pub const AccessExecOutcome = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    done: bool = false,
    abandoned: bool = false,
    exit: ?i32 = null,
    msg_buf: [256]u8 = undefined,
    msg_len: usize = 0,
    data: std.ArrayList(u8) = .empty,
    pub fn set(self: *AccessExecOutcome, exit: ?i32, data: []const u8, msg: []const u8) void {
        lockSpin(&self.mutex);
        if (data.len > 0) self.data.appendSlice(self.allocator, data) catch {};
        const n = @min(msg.len, self.msg_buf.len - 1);
        @memcpy(self.msg_buf[0..n], msg[0..n]);
        self.msg_len = n;
        self.exit = exit;
        self.done = true;
        const free = self.abandoned;
        self.mutex.unlock();
        if (free) {
            self.data.deinit(self.allocator);
            self.allocator.destroy(self);
        }
    }
    pub fn abandon(self: *AccessExecOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.abandoned = true;
        return self.done;
    }
    pub fn isDone(self: *AccessExecOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.done;
    }
    pub fn message(self: *AccessExecOutcome) []const u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.msg_buf[0..self.msg_len];
    }
};

/// Spec 11 context-probe completion. The SSH worker owns completion; the AI
/// operation registry owns the heap record until it calls `abandon`. A late
/// worker completion frees an abandoned record exactly once.
pub const AiContextOutcome = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    done: bool = false,
    abandoned: bool = false,
    canceled: bool = false,
    disconnected: bool = false,
    exit: ?i32 = null,
    message_buf: [256]u8 = undefined,
    message_len: usize = 0,
    data: std.ArrayList(u8) = .empty,

    pub const Snapshot = struct {
        done: bool,
        canceled: bool,
        disconnected: bool,
        exit: ?i32,
        message: []u8,
        data: []u8,

        pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
            allocator.free(self.message);
            allocator.free(self.data);
        }
    };

    pub fn complete(self: *AiContextOutcome, exit: ?i32, data: []const u8, message: []const u8, canceled: bool, disconnected: bool) void {
        lockSpin(&self.mutex);
        if (data.len > 0) self.data.appendSlice(self.allocator, data) catch {};
        const len = @min(message.len, self.message_buf.len);
        @memcpy(self.message_buf[0..len], message[0..len]);
        self.message_len = len;
        self.exit = exit;
        self.canceled = canceled;
        self.disconnected = disconnected;
        self.done = true;
        const free = self.abandoned;
        self.mutex.unlock();
        if (free) {
            self.data.deinit(self.allocator);
            self.allocator.destroy(self);
        }
    }

    pub fn snapshot(self: *AiContextOutcome, allocator: std.mem.Allocator) !Snapshot {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const message = try allocator.dupe(u8, self.message_buf[0..self.message_len]);
        errdefer allocator.free(message);
        const data = try allocator.dupe(u8, self.data.items);
        return .{
            .done = self.done,
            .canceled = self.canceled,
            .disconnected = self.disconnected,
            .exit = self.exit,
            .message = message,
            .data = data,
        };
    }

    pub fn abandon(self: *AiContextOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.abandoned = true;
        return self.done;
    }
};

const TrustState = struct {
    mutex: std.atomic.Mutex = .unlocked,
    pending: bool = false,
    /// Canonical fingerprint (`SHA256:` + unpadded base64, 50 bytes). The
    /// buffer is sized for the legacy 64-hex form so comparisons can reuse
    /// it; only `fingerprint_len` bytes are ever meaningful.
    fingerprint: [64]u8 = undefined,
    fingerprint_len: usize = 0,
    algorithm: ssh.HostKeyAlgorithm = .unknown,
    decided: bool = false,
    accept: bool = false,
};

/// folderSize cache entry (spec 05 §5): 5-minute freshness, bounded list.
const FolderSizeEntry = struct {
    path: []const u8,
    size: u64,
    ts_ns: i128,
};

// --- VNC tunnels (spec 12) ------------------------------------------------

/// A WebSocket → SSH direct-tcpip tunnel (spec 12 §6). Worker-owned: the
/// session worker is the only thread that mutates it; bridge handlers
/// copy stats under `tunnels_mutex` (state/bytes/error are written and
/// read under that lock — the list itself is guarded the same way).
pub const TunnelState = enum(u8) {
    listening,
    handshake,
    connected,
    closing,
    closed,
};

pub const Tunnel = struct {
    id: u32,
    /// 128-bit URL token (hex) — the unguessable half of the WS path.
    token: []const u8,
    /// Remote host as seen by the SSH server (owned; default loopback).
    host: []const u8,
    port: u16,
    listener: std.Io.net.Server,
    ws: ?std.Io.net.Stream = null,
    raw: ?*ssh.Channel = null,
    state: TunnelState = .listening,
    created_at_ns: i128 = 0,
    last_activity_ns: i128 = 0,
    /// Worker-only buffers (no lock).
    handshake_buf: std.ArrayList(u8) = .empty,
    recv_buf: std.ArrayList(u8) = .empty,
    msg_buf: std.ArrayList(u8) = .empty,
    to_channel: std.ArrayList(u8) = .empty,
    send_buf: std.ArrayList(u8) = .empty,
    bytes_up: u64 = 0,
    bytes_down: u64 = 0,
    error_buf: [160]u8 = undefined,
    error_len: usize = 0,
    /// Tombstone bookkeeping: when the tunnel reaches `.closed` its
    /// resources are released but the record survives so `oars.vnc.poll`
    /// keeps reporting `closed` (spec 12 §5) until it is pruned.
    closed_at_ns: i128 = 0,
    resources_released: bool = false,

    pub fn setError(self: *Tunnel, msg: []const u8) void {
        const n = @min(msg.len, self.error_buf.len - 1);
        @memcpy(self.error_buf[0..n], msg[0..n]);
        self.error_len = n;
    }

    pub fn deinit(self: *Tunnel, allocator: std.mem.Allocator, io: std.Io) void {
        if (!self.resources_released) {
            self.listener.deinit(io);
            if (self.ws) |*ws| ws.close(io);
            if (self.raw) |raw| raw.close(io);
        }
        allocator.free(self.token);
        allocator.free(self.host);
        self.handshake_buf.deinit(allocator);
        self.recv_buf.deinit(allocator);
        self.msg_buf.deinit(allocator);
        self.to_channel.deinit(allocator);
        self.send_buf.deinit(allocator);
    }
};

/// Completion record for `oars.vnc.start`: the worker binds the listener
/// and opens the SSH channel, then reports the ephemeral port.
pub const TunnelStartOutcome = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    done: bool = false,
    ok: bool = false,
    abandoned: bool = false,
    port: u16 = 0,
    msg_buf: [160]u8 = undefined,
    msg_len: usize = 0,

    pub fn set(self: *TunnelStartOutcome, ok: bool, port: u16, msg: []const u8) void {
        lockSpin(&self.mutex);
        self.ok = ok;
        self.port = port;
        const n = @min(msg.len, self.msg_buf.len - 1);
        @memcpy(self.msg_buf[0..n], msg[0..n]);
        self.msg_len = n;
        self.done = true;
        const free = self.abandoned;
        self.mutex.unlock();
        if (free) self.allocator.destroy(self);
    }

    /// Handler-side deadline escape; see SftpOutcome.abandon.
    pub fn abandon(self: *TunnelStartOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.abandoned = true;
        return self.done;
    }

    pub fn message(self: *TunnelStartOutcome) []const u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.msg_buf[0..self.msg_len];
    }

    pub fn isDone(self: *TunnelStartOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.done;
    }

    /// Spins until done or the deadline passes (the handler must never
    /// block the main thread indefinitely).
    pub fn wait(self: *TunnelStartOutcome, io: std.Io, deadline_ns: i128) void {
        while (true) {
            lockSpin(&self.mutex);
            const done = self.done;
            self.mutex.unlock();
            if (done) return;
            if (std.Io.Timestamp.now(io, .real).nanoseconds >= deadline_ns) return;
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch return;
        }
    }
};

/// Stats snapshot for `oars.vnc.poll` (copied under the tunnel lock).
pub const TunnelPollInfo = struct {
    state: TunnelState = .listening,
    bytes_up: u64 = 0,
    bytes_down: u64 = 0,
    error_buf: [160]u8 = undefined,
    error_len: usize = 0,
};

/// A tunnel with no WebSocket connection auto-destroys after this long.
const tunnel_idle_timeout_ns: i128 = 15 * std.time.ns_per_s;

/// Spec 18: cross-thread handoff for opening a jump tunnel on the via
/// session's worker (mirrors TunnelStartOutcome).
pub const JumpStartOutcome = struct {
    mutex: std.atomic.Mutex = .unlocked,
    done: bool = false,
    ok: bool = false,
    msg_buf: [160]u8 = undefined,
    msg_len: usize = 0,

    pub fn set(self: *JumpStartOutcome, ok: bool, msg: []const u8) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.ok = ok;
        const n = @min(msg.len, self.msg_buf.len - 1);
        @memcpy(self.msg_buf[0..n], msg[0..n]);
        self.msg_len = n;
        self.done = true;
    }

    pub fn message(self: *JumpStartOutcome) []const u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.msg_buf[0..self.msg_len];
    }

    pub fn isDone(self: *JumpStartOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.done;
    }

    pub fn wait(self: *JumpStartOutcome, io: std.Io) void {
        while (true) {
            lockSpin(&self.mutex);
            const done = self.done;
            self.mutex.unlock();
            if (done) return;
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch return;
        }
    }
};

/// Spec 18: one jump-host tunnel on the via session — the direct-tcpip
/// channel to the target, pumped against the local socketpair fd. The
/// via worker owns its lifecycle; the target session's transport runs
/// over the other socketpair end.
/// Per-direction pump buffer cap for jump tunnels (spec 18). A full
/// buffer backpressures: the source is not read until the buffer
/// drains, so the worker loop never blocks and no bytes are dropped.
const jump_frame_cap = 256 * 1024;

pub const JumpTunnel = struct {
    channel: *ssh.Channel,
    fd: std.posix.socket_t,
    /// Owned; the via worker cascades a clear close to this session
    /// when the tunnel dies.
    target_server_id: []const u8,
    /// Bytes read from the channel, not yet fully written to the fd.
    to_fd_buf: std.ArrayList(u8) = .empty,
    /// Bytes read from the fd, not yet fully written to the channel.
    to_channel_buf: std.ArrayList(u8) = .empty,
    bytes_up: u64 = 0,
    bytes_down: u64 = 0,

    pub fn deinit(self: *JumpTunnel, allocator: std.mem.Allocator, io: std.Io) void {
        _ = ssh.c.close(self.fd);
        self.channel.close(io);
        self.to_fd_buf.deinit(allocator);
        self.to_channel_buf.deinit(allocator);
        allocator.free(self.target_server_id);
    }
};

/// Spec 18: cross-thread handoff for the agent-forwarding toggle.
/// Heap + abandonment lifetime: see SftpOutcome's doc comment.
pub const ForwardSetOutcome = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    done: bool = false,
    ok: bool = false,
    abandoned: bool = false,
    msg_buf: [160]u8 = undefined,
    msg_len: usize = 0,

    pub fn set(self: *ForwardSetOutcome, ok: bool, msg: []const u8) void {
        lockSpin(&self.mutex);
        self.ok = ok;
        const n = @min(msg.len, self.msg_buf.len - 1);
        @memcpy(self.msg_buf[0..n], msg[0..n]);
        self.msg_len = n;
        self.done = true;
        const free = self.abandoned;
        self.mutex.unlock();
        if (free) self.allocator.destroy(self);
    }

    /// Handler-side deadline escape; see SftpOutcome.abandon.
    pub fn abandon(self: *ForwardSetOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.abandoned = true;
        return self.done;
    }

    pub fn message(self: *ForwardSetOutcome) []const u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.msg_buf[0..self.msg_len];
    }

    pub fn isDone(self: *ForwardSetOutcome) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.done;
    }

    pub fn wait(self: *ForwardSetOutcome, io: std.Io, deadline_ns: i128) void {
        while (true) {
            lockSpin(&self.mutex);
            const done = self.done;
            self.mutex.unlock();
            if (done) return;
            if (std.Io.Timestamp.now(io, .real).nanoseconds >= deadline_ns) return;
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch return;
        }
    }
};

/// Spec 18: one accepted auth-agent channel being proxied to the local
/// agent socket. Same buffered/non-blocking pump contract as
/// JumpTunnel (a blocking fd here would freeze the via worker's loop).
pub const ForwardTunnel = struct {
    channel: *ssh.Channel,
    agent_fd: std.posix.socket_t,
    /// Bytes read from the channel, not yet fully written to the socket.
    to_socket_buf: std.ArrayList(u8) = .empty,
    /// Bytes read from the socket, not yet fully written to the channel.
    to_channel_buf: std.ArrayList(u8) = .empty,
};

/// Closed tunnels survive this long as tombstones so polls keep
/// reporting `closed` before the record is pruned.
const tunnel_tombstone_ns: i128 = 60 * std.time.ns_per_s;

const error_buf_len = 512;

pub const Session = struct {
    id: u64,
    server: servers.Server,
    allocator: std.mem.Allocator,
    threaded: std.Io.Threaded,
    io: std.Io,
    transport: ssh.Session,
    store: *servers.Store,
    audit: *history.AuditStore,
    /// Spec 15 command history; the worker records completed tracked
    /// execs here at channel EOF.
    history: *history.HistoryStore,
    status: std.atomic.Value(Status) = .init(.connecting),
    error_mutex: std.atomic.Mutex = .unlocked,
    error_msg: [error_buf_len]u8 = undefined,
    error_len: usize = 0,
    trust: TrustState = .{},
    stop_flag: std.atomic.Value(bool) = .init(false),
    /// Set before a requested disconnect calls the backup lifecycle hook.
    /// Normal backup admission is rejected while cleanup/signaling requests
    /// remain available on the still-live worker transport.
    backup_admission_closed: std.atomic.Value(bool) = .init(false),
    /// Claimed by `requestDisconnect` before it allocates the detached-thread
    /// context.  This keeps duplicate bridge requests from racing each other;
    /// an admission failure rolls it back together with the normal-admission
    /// gate while the session is still otherwise live.
    disconnect_admitted: std.atomic.Value(bool) = .init(false),
    disconnect_started: std.atomic.Value(bool) = .init(false),
    /// Set by sessionDone inside its final ops_mutex section, after every
    /// list has been torn down. Op-enqueue paths check it under ops_mutex,
    /// so an op racing the worker's exit is either drained by sessionDone
    /// or rejected — never stranded in a queue nobody reads. The session
    /// itself outlives its worker (the manager map holds it until
    /// disconnect), so every teardown below must leave a valid empty
    /// container, never deinit-poisoned memory.
    worker_done: std.atomic.Value(bool) = .init(false),
    channels_mutex: std.atomic.Mutex = .unlocked,
    channels: std.ArrayList(*ChannelEntry) = .empty,
    shell: ?*ChannelEntry = null,
    ops_mutex: std.atomic.Mutex = .unlocked,
    ops: std.ArrayList(Op) = .empty,
    worker: ?std.Thread = null,
    next_channel_id: std.atomic.Value(u32) = .init(1),
    started_at_ns: i128 = 0,
    password: ?[]const u8 = null,
    passphrase: ?[]const u8 = null,
    /// Borrowed from Manager.home (outlives the session).
    home: ?[]const u8 = null,
    last_keepalive_ns: i128 = 0,
    keepalive_interval_ns: i128 = 30 * std.time.ns_per_s,
    /// Monitor probe state (spec 03). The cache is read by bridge handlers
    /// and written by the worker under its spinlock; the cadence fields are
    /// copied from the manager at connect.
    monitor_cache: monitor.Cache = .{},
    monitor_last_poll_ns: std.atomic.Value(i64) = .init(0),
    monitor_force: std.atomic.Value(bool) = .init(false),
    monitor_last_probe_ns: std.atomic.Value(i64) = .init(0),
    monitor_probe_active: std.atomic.Value(bool) = .init(false),
    monitor_interval_ns: i64 = 2 * std.time.ns_per_s,
    monitor_liveness_ns: i64 = 4 * std.time.ns_per_s,
    /// Set by dropCaches so the next completed probe writes the after
    /// snapshot audit entry (before/after contract, spec 03 §6).
    monitor_drop_pending: std.atomic.Value(bool) = .init(false),
    /// Per-session log scan cache (spec 04 §4: 60 s freshness).
    logs_cache: logs.ScanCache = .{},
    /// Async SFTP transfer registry (spec 05 §6).
    sftp_transfers: sftpmod.Transfers = .{},
    /// folderSize cache (spec 05 §5: 5 min per path; main thread only).
    folder_size_cache: std.ArrayList(FolderSizeEntry) = .empty,
    /// VNC tunnels (spec 12): list guarded by tunnels_mutex; the worker
    /// owns each tunnel's lifecycle.
    tunnels_mutex: std.atomic.Mutex = .unlocked,
    tunnels: std.ArrayList(*Tunnel) = .empty,
    /// Jump-host tunnels (spec 18): the direct-tcpip channel to the
    /// target, pumped against the local socketpair fd. Guarded by the
    /// same tunnels_mutex; the worker owns each tunnel's lifecycle.
    jump_tunnels: std.ArrayList(*JumpTunnel) = .empty,
    /// Owned name of the via hop, for error messages ("<name> unreachable").
    via_name: ?[]const u8 = null,
    /// The manager that owns this session (for the jump cascade).
    owner: *Manager = undefined,
    /// Spec 18: agent forwarding is enabled for this session's shell.
    forwarding: std.atomic.Value(bool) = .init(false),
    shell_channel_id: u32 = 0,
    shell_parser: ?shell_integration.Parser = null,
    history_capture_enabled: std.atomic.Value(bool) = .init(true),
    history_full: std.atomic.Value(bool) = .init(false),
    history_write_error: std.atomic.Value(bool) = .init(false),
    shell_command: [shell_integration.command_cap]u8 = undefined,
    shell_command_len: usize = 0,
    shell_started_ns: i128 = 0,
    shell_snippet: [history.snippet_cap]u8 = undefined,
    shell_snippet_len: usize = 0,
    shell_snippet_lines: usize = 0,
    /// Guards forward_queue / forward_active (worker + libssh2 callback).
    forward_mutex: std.atomic.Mutex = .unlocked,
    /// Accepted auth-agent channels awaiting their local agent socket
    /// connection (queued by the libssh2 callback on the worker thread).
    forward_queue: std.ArrayList(*ssh.Channel) = .empty,
    /// Accepted channels being pumped against the local agent socket.
    forward_active: std.ArrayList(*ForwardTunnel) = .empty,
    /// Owned validated agent socket path for proxy connections.
    forward_agent_path: ?[]const u8 = null,
    /// Monotonic counter for history operation ids (`exec-<n>`); the
    /// worker is the only writer.
    history_seq: u64 = 0,

    pub fn setError(self: *Session, msg: []const u8) void {
        lockSpin(&self.error_mutex);
        defer self.error_mutex.unlock();
        const len = @min(msg.len, self.error_msg.len - 1);
        @memcpy(self.error_msg[0..len], msg[0..len]);
        self.error_len = len;
    }

    pub fn errorText(self: *Session) []const u8 {
        lockSpin(&self.error_mutex);
        defer self.error_mutex.unlock();
        return self.error_msg[0..self.error_len];
    }

    fn trustPending(self: *Session) bool {
        lockSpin(&self.trust.mutex);
        defer self.trust.mutex.unlock();
        return self.trust.pending and !self.trust.decided;
    }

    fn trustFingerprint(self: *Session) []const u8 {
        lockSpin(&self.trust.mutex);
        defer self.trust.mutex.unlock();
        if (!self.trust.pending) return "";
        return self.trust.fingerprint[0..self.trust.fingerprint_len];
    }

    fn trustAlgorithm(self: *Session) []const u8 {
        lockSpin(&self.trust.mutex);
        defer self.trust.mutex.unlock();
        return self.trust.algorithm.label();
    }
};

pub const Manager = struct {
    pub const BackupDisconnectHook = struct {
        context: *anyopaque,
        prepare_fn: *const fn (context: *anyopaque, server_id: []const u8) bool,
    };

    allocator: std.mem.Allocator,
    store: *servers.Store,
    audit: *history.AuditStore,
    history: *history.HistoryStore,
    io: std.Io,
    /// Borrowed from the process environment (outlives the manager);
    /// used to expand "~/" in key paths on the worker threads.
    home: ?[]const u8 = null,
    /// Monitor probe cadence, copied to each session at connect (tests
    /// shrink these to keep probe assertions fast).
    monitor_interval_ns: i64 = 2 * std.time.ns_per_s,
    monitor_liveness_ns: i64 = 4 * std.time.ns_per_s,
    /// Monotonic VNC tunnel ids (the WS URL token carries the randomness).
    next_tunnel_id: std.atomic.Value(u32) = .init(1),
    mutex: std.atomic.Mutex = .unlocked,
    sessions: std.StringHashMap(*Session) = undefined,
    next_session_id: u64 = 1,
    /// Safe-broadcast runs (spec 06 §6): bridge handlers drive the state
    /// machine; the manager owns the registry and its memory.
    broadcasts: broadcast.Runs = .{},
    /// Prepared (uncommitted) broadcast previews (spec 06 §5): memory-only,
    /// bounded, expired after 10 minutes, cleared on shutdown.
    previews: broadcast.Previews = .{},
    /// One-click deploy runs (spec 07 §6): poll-driven sequential steps;
    /// the manager owns the registry and its memory.
    deploys: deploy.Runs = .{},
    /// One-click preflights (spec 07 §5): memory-only, bounded, expiring,
    /// capped at 32 — bridge handlers drive; worker owns probe channels.
    preflights: preflight.Preflights = .{},
    backup_disconnect_hook: ?BackupDisconnectHook = null,
    pending_disconnects: std.atomic.Value(u32) = .init(0),
    shutting_down: std.atomic.Value(bool) = .init(false),

    pub fn init(allocator: std.mem.Allocator, io: std.Io, store: *servers.Store, audit_store: *history.AuditStore, history_store: *history.HistoryStore, home: ?[]const u8) Manager {
        var self: Manager = .{
            .allocator = allocator,
            .store = store,
            .audit = audit_store,
            .history = history_store,
            .io = io,
            .home = home,
            .sessions = std.StringHashMap(*Session).init(allocator),
        };
        self.broadcasts = .{ .allocator = allocator };
        self.previews = .{ .allocator = allocator };
        self.deploys = .{ .allocator = allocator };
        self.preflights = .{ .allocator = allocator };
        return self;
    }

    pub fn deinit(self: *Manager) void {
        self.shutting_down.store(true, .release);
        self.drainBackupDisconnects();
        self.shutdownAll();
        self.sessions.deinit();
        self.broadcasts.deinit();
        self.previews.deinit();
        self.deploys.deinit();
        self.preflights.deinit();
    }

    pub fn get(self: *Manager, server_id: []const u8) ?*Session {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.sessions.get(server_id);
    }

    pub fn setBackupDisconnectHook(self: *Manager, hook: BackupDisconnectHook) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.backup_disconnect_hook = hook;
    }

    pub fn clearBackupDisconnectHook(self: *Manager, context: *anyopaque) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.backup_disconnect_hook) |hook| {
            if (hook.context == context) self.backup_disconnect_hook = null;
        }
    }

    /// Prevents any newly admitted disconnect from borrowing `context`, then
    /// waits until every thread admitted before the clear has released it.
    /// Registry teardown uses this before freeing coordinator state.
    pub fn detachBackupDisconnectHook(self: *Manager, context: *anyopaque) void {
        self.clearBackupDisconnectHook(context);
        self.drainBackupDisconnects();
    }

    pub fn drainBackupDisconnects(self: *Manager) void {
        while (self.pending_disconnects.load(.acquire) != 0) {
            std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(10), .awake) catch {};
        }
    }

    /// Starts a connection for `server`. `password`/`passphrase` are
    /// owned by the caller after this returns (the session copies them).
    pub fn connect(
        self: *Manager,
        server: servers.Server,
        password: ?[]const u8,
        passphrase: ?[]const u8,
    ) !*Session {
        lockSpin(&self.mutex);
        // A stale cleanly-closed session is replaced rather than leaked:
        // removed from the map here and torn down after the unlock
        // (joining under the manager mutex deadlocks against the dying
        // worker's dependant cascade — see disconnect). Defer order:
        // the unlock runs first (declared last), the teardown second.
        var stale_key: ?[]const u8 = null;
        var stale_session: ?*Session = null;
        defer if (stale_session) |ss| self.teardown(stale_key.?, ss);
        defer self.mutex.unlock();

        if (self.sessions.getEntry(server.id)) |existing| {
            if (existing.value_ptr.*.status.load(.acquire) != .closed) return error.AlreadyConnected;
            stale_key = existing.key_ptr.*;
            stale_session = existing.value_ptr.*;
            _ = self.sessions.remove(server.id);
        }

        const session = try self.allocator.create(Session);
        errdefer self.allocator.destroy(session);
        session.* = .{
            .id = self.next_session_id,
            .server = try server.copy(self.allocator),
            .allocator = self.allocator,
            .threaded = std.Io.Threaded.init(self.allocator, .{}),
            .io = undefined,
            .transport = try ssh.Session.init(self.allocator),
            .store = self.store,
            .audit = self.audit,
            .history = self.history,
            .owner = self,
            .monitor_interval_ns = self.monitor_interval_ns,
            .monitor_liveness_ns = self.monitor_liveness_ns,
            .started_at_ns = std.Io.Timestamp.now(self.io, .real).nanoseconds,
        };
        errdefer {
            session.threaded.deinit();
            var s = session.server;
            s.deinit(self.allocator);
        }
        session.io = session.threaded.io();
        session.home = self.home;
        if (password) |p| session.password = try self.allocator.dupe(u8, p);
        if (passphrase) |p| session.passphrase = try self.allocator.dupe(u8, p);
        session.last_keepalive_ns = session.started_at_ns;

        const key = try self.allocator.dupe(u8, server.id);
        try self.sessions.put(key, session);
        session.worker = std.Thread.spawn(.{}, workerMain, .{session}) catch |err| {
            _ = self.sessions.remove(server.id);
            self.allocator.free(key);
            return err;
        };
        return session;
    }

    /// Signals a session to stop, cancels any in-flight DNS lookup, then
    /// tears it down. Safe to call when no session exists. The map entry
    /// is removed under the manager mutex, but the join and destruction
    /// run OUTSIDE it: a dying worker's sessionDone jump-tunnel cascade
    /// resolves dependants through the manager mutex, so joining while
    /// holding it deadlocks both threads. The join stays bounded because
    /// the worker checks the stop signal between every connect phase and
    /// inside every deadline loop; only the kernel-bounded TCP connect
    /// itself can extend it (the std Io has no non-blocking connect —
    /// spec 02 §5).
    pub fn disconnect(self: *Manager, server_id: []const u8) void {
        lockSpin(&self.mutex);
        const entry = self.sessions.getEntry(server_id) orelse {
            self.mutex.unlock();
            return;
        };
        const session = entry.value_ptr.*;
        if (session.disconnect_started.swap(true, .acq_rel)) {
            self.mutex.unlock();
            return;
        }
        session.backup_admission_closed.store(true, .release);
        const hook = self.backup_disconnect_hook;
        self.mutex.unlock();

        // The hook is bounded. It requests TERM/KILL and verifies absence
        // while the worker still owns a usable SSH transport. A false result
        // means the registry retained interrupted/recovery evidence.
        if (hook) |value| _ = value.prepare_fn(value.context, server_id);

        lockSpin(&self.mutex);
        const current = self.sessions.getEntry(server_id) orelse {
            self.mutex.unlock();
            return;
        };
        if (current.value_ptr.* != session) {
            self.mutex.unlock();
            return;
        }
        const key = current.key_ptr.*;
        session.stop_flag.store(true, .release);
        session.transport.cancelConnect(session.io);
        _ = self.sessions.remove(server_id);
        self.mutex.unlock();

        self.teardown(key, session);
    }

    const AsyncDisconnect = struct {
        manager: *Manager,
        server_id: []u8,

        fn run(self: *AsyncDisconnect) void {
            defer {
                self.manager.allocator.free(self.server_id);
                const manager = self.manager;
                manager.allocator.destroy(self);
                _ = manager.pending_disconnects.fetchSub(1, .acq_rel);
            }
            self.manager.disconnect(self.server_id);
        }
    };

    /// Bridge-facing disconnect admission. It closes normal backup admission
    /// before returning, then runs the bounded backup hook and worker teardown
    /// on a detached thread. Manager.deinit waits for all admitted disconnects.
    pub fn requestDisconnect(self: *Manager, server_id: []const u8) !void {
        if (self.shutting_down.load(.acquire)) return error.ManagerShuttingDown;
        lockSpin(&self.mutex);
        const session = self.sessions.get(server_id) orelse {
            self.mutex.unlock();
            return;
        };
        if (session.disconnect_admitted.swap(true, .acq_rel) or session.disconnect_started.load(.acquire)) {
            self.mutex.unlock();
            return;
        }
        session.backup_admission_closed.store(true, .release);
        self.mutex.unlock();

        var admitted = false;
        defer if (!admitted) {
            lockSpin(&self.mutex);
            if (self.sessions.get(server_id)) |current| {
                if (current == session and !session.disconnect_started.load(.acquire)) {
                    session.disconnect_admitted.store(false, .release);
                    session.backup_admission_closed.store(false, .release);
                }
            }
            self.mutex.unlock();
        };

        const context = try self.allocator.create(AsyncDisconnect);
        errdefer self.allocator.destroy(context);
        context.* = .{ .manager = self, .server_id = try self.allocator.dupe(u8, server_id) };
        errdefer self.allocator.free(context.server_id);
        _ = self.pending_disconnects.fetchAdd(1, .acq_rel);
        const thread = std.Thread.spawn(.{}, AsyncDisconnect.run, .{context}) catch |err| {
            _ = self.pending_disconnects.fetchSub(1, .acq_rel);
            return err;
        };
        admitted = true;
        thread.detach();
    }

    /// Joins the worker and frees all session memory. The map entry must
    /// already be removed and the caller must not hold the manager mutex
    /// (see disconnect).
    fn teardown(self: *Manager, key: []const u8, session: *Session) void {
        if (session.worker) |thread| thread.join();
        self.allocator.free(key);
        var s = session.server;
        s.deinit(session.allocator);
        if (session.password) |p| {
            std.crypto.secureZero(u8, @constCast(p));
            session.allocator.free(p);
        }
        if (session.passphrase) |p| {
            std.crypto.secureZero(u8, @constCast(p));
            session.allocator.free(p);
        }
        session.threaded.deinit();
        session.allocator.destroy(session);
    }

    /// Marks a jump-tunnel dependant cascade-closed, resolving it under
    /// the manager mutex so a concurrent disconnect cannot destroy the
    /// target mid-update (disconnect removes the entry under the same
    /// mutex before tearing down, so a found entry is always live).
    fn cascadeCloseDependant(self: *Manager, target_server_id: []const u8, via_name: []const u8) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const target = self.sessions.get(target_server_id) orelse return;
        if (target.status.load(.acquire) == .ready) {
            target.status.store(.@"error", .release);
            var msg_buf: [256]u8 = undefined;
            target.setError(std.fmt.bufPrint(&msg_buf, "jump host {s} disconnected", .{via_name}) catch "jump host disconnected");
        }
    }

    pub fn shutdownAll(self: *Manager) void {
        var ids: std.ArrayList([]const u8) = .empty;
        defer ids.deinit(self.allocator);
        lockSpin(&self.mutex);
        var it = self.sessions.keyIterator();
        while (it.next()) |key| ids.append(self.allocator, key.*) catch {};
        self.mutex.unlock();
        for (ids.items) |id| self.disconnect(id);
    }

    /// Appends bytes to the shell channel's stdin. channels_mutex is held
    /// so sessionDone cannot destroy the shell entry mid-append (the
    /// worker owns entry teardown; lock order channels→stdin matches it).
    pub fn input(self: *Manager, server_id: []const u8, bytes: []const u8) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        lockSpin(&session.channels_mutex);
        defer session.channels_mutex.unlock();
        const shell = session.shell orelse return error.NotReady;
        lockSpin(&shell.stdin_mutex);
        defer shell.stdin_mutex.unlock();
        try shell.stdin_queue.appendSlice(self.allocator, bytes);
    }

    /// Queues an exec on a fresh channel. Returns the channel id that
    /// will carry the output (assigned by the worker). Untracked: the
    /// completed run is NOT recorded in command history (internal
    /// plumbing such as probes and checks — use `execTracked` for
    /// user-visible commands).
    pub fn exec(self: *Manager, server_id: []const u8, command: []const u8) !u32 {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        const id = session.next_channel_id.fetchAdd(1, .monotonic);
        const owned = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(owned);
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .exec = .{ .id = id, .command = owned } });
        return id;
    }

    /// Queues an untracked exec and writes bounded stdin before sending EOF.
    /// The worker clears the owned stdin buffer immediately after use.
    pub fn execWithInput(self: *Manager, server_id: []const u8, command: []const u8, stdin_data: []const u8) !u32 {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        const id = session.next_channel_id.fetchAdd(1, .monotonic);
        const owned = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(owned);
        const owned_stdin = try self.allocator.dupe(u8, stdin_data);
        errdefer {
            std.crypto.secureZero(u8, owned_stdin);
            self.allocator.free(owned_stdin);
        }
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .exec = .{
            .id = id,
            .command = owned,
            .stdin_data = owned_stdin,
        } });
        return id;
    }

    /// Queues a tracked exec (spec 15): the completed run is recorded in
    /// command history under `history_kind`. `history_command` (optional)
    /// is pre-redacted command text to store — used when the operation
    /// masks secret values itself (scripts); the executed command is
    /// recorded otherwise. `history_secrets` are the operation's known
    /// secret values, used to mask the stored command AND the output
    /// snippet at capture.
    pub fn execTracked(self: *Manager, server_id: []const u8, command: []const u8, history_kind: []const u8, history_command: ?[]const u8, history_secrets: []const []const u8) !u32 {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        const id = session.next_channel_id.fetchAdd(1, .monotonic);
        const owned = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(owned);
        const owned_kind = try self.allocator.dupe(u8, history_kind);
        errdefer self.allocator.free(owned_kind);
        const owned_hc: ?[]const u8 = if (history_command) |hc| try self.allocator.dupe(u8, hc) else null;
        errdefer if (owned_hc) |hc| self.allocator.free(hc);
        const owned_secrets: ?[][]const u8 = if (history_secrets.len > 0) blk: {
            const arr = try self.allocator.alloc([]const u8, history_secrets.len);
            errdefer self.allocator.free(arr);
            for (history_secrets, 0..) |s, i| {
                arr[i] = try self.allocator.dupe(u8, s);
            }
            break :blk arr;
        } else null;
        errdefer if (owned_secrets) |hs| {
            for (hs) |s| self.allocator.free(s);
            self.allocator.free(hs);
        };
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .exec = .{
            .id = id,
            .command = owned,
            .history_kind = owned_kind,
            .history_command = owned_hc,
            .history_secrets = owned_secrets,
        } });
        return id;
    }

    /// Dedicated Spec 11 execution admission. The command was already
    /// frozen and approved by the AI coordinator. This entry point retains
    /// its stable operation ID and enables the private process-group marker
    /// filter used for verified cancellation.
    pub fn execAiTracked(self: *Manager, server_id: []const u8, command: []const u8, history_command: []const u8, operation_id: []const u8) !u32 {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        const id = session.next_channel_id.fetchAdd(1, .monotonic);
        const owned = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(owned);
        const owned_kind = try self.allocator.dupe(u8, "ai");
        errdefer self.allocator.free(owned_kind);
        const owned_operation_id = try self.allocator.dupe(u8, operation_id);
        errdefer self.allocator.free(owned_operation_id);
        const owned_history_command = try self.allocator.dupe(u8, history_command);
        errdefer self.allocator.free(owned_history_command);
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .exec = .{
            .id = id,
            .command = owned,
            .history_kind = owned_kind,
            .history_command = owned_history_command,
            .history_command_redacted = false,
            .history_operation_id = owned_operation_id,
            .ai_execution = true,
        } });
        return id;
    }

    /// Queues a tracked exec with bounded stdin. The stdin bytes are never
    /// included in command history and are securely cleared by the worker.
    pub fn execTrackedWithInput(
        self: *Manager,
        server_id: []const u8,
        command: []const u8,
        stdin_data: []const u8,
        history_kind: []const u8,
        history_command: ?[]const u8,
        history_secrets: []const []const u8,
    ) !u32 {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        const id = session.next_channel_id.fetchAdd(1, .monotonic);
        const owned = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(owned);
        const owned_stdin = try self.allocator.dupe(u8, stdin_data);
        errdefer {
            std.crypto.secureZero(u8, owned_stdin);
            self.allocator.free(owned_stdin);
        }
        const owned_kind = try self.allocator.dupe(u8, history_kind);
        errdefer self.allocator.free(owned_kind);
        const owned_hc: ?[]const u8 = if (history_command) |hc| try self.allocator.dupe(u8, hc) else null;
        errdefer if (owned_hc) |hc| self.allocator.free(hc);
        const owned_secrets: ?[][]const u8 = if (history_secrets.len > 0) blk: {
            const arr = try self.allocator.alloc([]const u8, history_secrets.len);
            errdefer self.allocator.free(arr);
            for (history_secrets, 0..) |secret, i| arr[i] = try self.allocator.dupe(u8, secret);
            break :blk arr;
        } else null;
        errdefer if (owned_secrets) |secrets| {
            for (secrets) |secret| self.allocator.free(secret);
            self.allocator.free(secrets);
        };
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .exec = .{
            .id = id,
            .command = owned,
            .stdin_data = owned_stdin,
            .history_kind = owned_kind,
            .history_command = owned_hc,
            .history_secrets = owned_secrets,
        } });
        return id;
    }

    /// Queues a follow exec (spec 04): a long-lived tail whose channel is
    /// reported with kind `log` and stopped via closeChannel.
    pub fn follow(self: *Manager, server_id: []const u8, command: []const u8) !u32 {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        const id = session.next_channel_id.fetchAdd(1, .monotonic);
        const owned = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(owned);
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .follow = .{ .id = id, .command = owned } });
        return id;
    }

    /// Queues a worker-driven `bash -n -c` syntax check for a broadcast
    /// server (spec 06 §5): the check runs on the session worker as an
    /// internal channel, so a slow check can never block a bridge poll.
    /// The outcome is completed at EOF, on timeout, or in session
    /// teardown; the handler reads it on later polls (heap + abandon()
    /// ownership — session 30 protocol).
    pub fn enqueueSyntaxCheck(self: *Manager, server_id: []const u8, command: []const u8, timeout_ns: i128, outcome: *broadcast.ScriptCheckOutcome) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        const owned = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(owned);
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .syntax_check = .{
            .command = owned,
            .timeout_ns = timeout_ns,
            .outcome = outcome,
        } });
    }

    /// Queues the identity-bound SFTP truncate (spec 04 clear). The
    /// outcome record is written by the worker; the caller waits on it
    /// with a deadline. The path is duplicated here.
    pub fn clearLog(self: *Manager, server_id: []const u8, path: []const u8, expected: ClearExpected, outcome: *ClearOutcome) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .clear = .{ .path = owned, .expected = expected, .outcome = outcome } });
    }

    // --- SFTP ops (spec 05) -------------------------------------------------

    /// Queue helpers share the same shape: dupe the payload, append the op.
    fn queueSftp(self: *Manager, session: *Session, op: Op) !void {
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, op);
    }

    pub fn sftpLs(self: *Manager, server_id: []const u8, path: []const u8, outcome: *SftpOutcome) !void {
        const session = try self.sftpSession(server_id);
        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);
        try self.queueSftp(session, .{ .sftp_ls = .{ .path = owned, .outcome = outcome } });
    }

    pub fn sftpStat(self: *Manager, server_id: []const u8, path: []const u8, outcome: *SftpOutcome) !void {
        const session = try self.sftpSession(server_id);
        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);
        try self.queueSftp(session, .{ .sftp_stat = .{ .path = owned, .outcome = outcome } });
    }

    pub fn sftpRead(self: *Manager, server_id: []const u8, path: []const u8, offset: u64, max: usize, outcome: *SftpOutcome) !void {
        const session = try self.sftpSession(server_id);
        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);
        try self.queueSftp(session, .{ .sftp_read = .{ .path = owned, .offset = offset, .max = max, .outcome = outcome } });
    }

    /// Upload chunk: writes `data` at `offset` into `<path>.partial` and
    /// no-clobber renames to `path` once the written size reaches `total`
    /// (spec 05 §5). The transfer record is created by the handler on the
    /// first chunk.
    pub fn sftpWriteChunk(
        self: *Manager,
        server_id: []const u8,
        path: []const u8,
        offset: u64,
        data: []const u8,
        total: u64,
        transfer_id: u32,
        outcome: *SftpOutcome,
    ) !void {
        const session = try self.sftpSession(server_id);
        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);
        const owned_data = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(owned_data);
        try self.queueSftp(session, .{ .sftp_write_chunk = .{
            .path = owned,
            .offset = offset,
            .data = owned_data,
            .total = total,
            .transfer_id = transfer_id,
            .outcome = outcome,
        } });
    }

    /// Editor save: writes a temp file next to `path` and atomically
    /// replaces it via posix-rename (spec 05 §4.2). When an expected
    /// identity is supplied, the worker refuses the save with a conflict
    /// error if the remote file no longer matches it.
    pub fn sftpSave(
        self: *Manager,
        server_id: []const u8,
        path: []const u8,
        data: []const u8,
        expected: ?SftpExpectedIdentity,
        outcome: *SftpOutcome,
    ) !void {
        const session = try self.sftpSession(server_id);
        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);
        const owned_data = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(owned_data);
        const owned_sha: ?[]u8 = if (expected) |identity|
            if (identity.sha256) |sha| try self.allocator.dupe(u8, sha) else null
        else
            null;
        errdefer if (owned_sha) |s| self.allocator.free(s);
        const owned_expected: ?SftpExpectedIdentity = if (expected) |identity| .{
            .size = identity.size,
            .mtime = identity.mtime,
            .sha256 = owned_sha,
            .missing = identity.missing,
            .max_hash_bytes = identity.max_hash_bytes,
        } else null;
        try self.queueSftp(session, .{ .sftp_save = .{
            .path = owned,
            .data = owned_data,
            .expected = owned_expected,
            .outcome = outcome,
        } });
    }

    pub fn sftpMkdir(self: *Manager, server_id: []const u8, path: []const u8, outcome: *SftpOutcome) !void {
        const session = try self.sftpSession(server_id);
        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);
        try self.queueSftp(session, .{ .sftp_mkdir = .{ .path = owned, .outcome = outcome } });
    }

    /// Remove. Recursive deletes run as an async transfer (per-entry
    /// progress, cancelable) and pass a null outcome; plain deletes are
    /// synchronous and carry one.
    pub fn sftpRm(self: *Manager, server_id: []const u8, path: []const u8, recursive: bool, transfer_id: u32, outcome: ?*SftpOutcome) !void {
        const session = try self.sftpSession(server_id);
        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);
        try self.queueSftp(session, .{ .sftp_rm = .{
            .path = owned,
            .recursive = recursive,
            .transfer_id = transfer_id,
            .outcome = outcome,
        } });
    }

    pub fn sftpRename(self: *Manager, server_id: []const u8, from: []const u8, to: []const u8, outcome: *SftpOutcome) !void {
        const session = try self.sftpSession(server_id);
        const owned_from = try self.allocator.dupe(u8, from);
        errdefer self.allocator.free(owned_from);
        const owned_to = try self.allocator.dupe(u8, to);
        errdefer self.allocator.free(owned_to);
        try self.queueSftp(session, .{ .sftp_rename = .{ .from = owned_from, .to = owned_to, .outcome = outcome } });
    }

    pub fn sftpChmod(self: *Manager, server_id: []const u8, path: []const u8, mode: u32, outcome: *SftpOutcome) !void {
        const session = try self.sftpSession(server_id);
        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);
        try self.queueSftp(session, .{ .sftp_chmod = .{ .path = owned, .mode = mode, .outcome = outcome } });
    }

    /// Remote→local download into `<local_final>.partial`, no-clobber rename
    /// on success (spec 05 §5). Async: progress rides the transfer record.
    pub fn sftpDownload(
        self: *Manager,
        server_id: []const u8,
        remote: []const u8,
        local_partial: []const u8,
        local_final: []const u8,
        transfer_id: u32,
        outcome: ?*SftpOutcome,
    ) !void {
        const session = try self.sftpSession(server_id);
        const owned_remote = try self.allocator.dupe(u8, remote);
        errdefer self.allocator.free(owned_remote);
        const owned_partial = try self.allocator.dupe(u8, local_partial);
        errdefer self.allocator.free(owned_partial);
        const owned_final = try self.allocator.dupe(u8, local_final);
        errdefer self.allocator.free(owned_final);
        try self.queueSftp(session, .{ .sftp_download = .{
            .remote = owned_remote,
            .local_partial = owned_partial,
            .local_final = owned_final,
            .transfer_id = transfer_id,
            .outcome = outcome,
        } });
    }

    /// Local→remote upload selected from the native local pane. The session
    /// worker owns both file handles, progress, cancellation, and no-clobber
    /// finalization, so file bytes never cross the JSON bridge.
    pub fn sftpUploadLocal(
        self: *Manager,
        server_id: []const u8,
        local: []const u8,
        remote: []const u8,
        transfer_id: u32,
    ) !void {
        const session = try self.sftpSession(server_id);
        const owned_local = try self.allocator.dupe(u8, local);
        errdefer self.allocator.free(owned_local);
        const owned_remote = try self.allocator.dupe(u8, remote);
        errdefer self.allocator.free(owned_remote);
        try self.queueSftp(session, .{ .sftp_upload_local = .{
            .local = owned_local,
            .remote = owned_remote,
            .transfer_id = transfer_id,
        } });
    }

    /// Validated ZIP extraction into `dest` (spec 05 §5: central-directory
    /// preflight, overwrite disabled). Async: progress rides the transfer.
    pub fn sftpUnzip(
        self: *Manager,
        server_id: []const u8,
        zip_path: []const u8,
        dest: []const u8,
        transfer_id: u32,
        outcome: ?*SftpOutcome,
    ) !void {
        const session = try self.sftpSession(server_id);
        const owned_zip = try self.allocator.dupe(u8, zip_path);
        errdefer self.allocator.free(owned_zip);
        const owned_dest = try self.allocator.dupe(u8, dest);
        errdefer self.allocator.free(owned_dest);
        try self.queueSftp(session, .{ .sftp_unzip = .{
            .zip_path = owned_zip,
            .dest = owned_dest,
            .transfer_id = transfer_id,
            .outcome = outcome,
        } });
    }

    /// Remote `zip -r` of `paths` into a staging archive, downloaded through
    /// the same local writer as downloads; the staging archive is removed in
    /// success and failure (spec 05 §5).
    pub fn sftpZipDownload(
        self: *Manager,
        server_id: []const u8,
        paths: []const []const u8,
        local_partial: []const u8,
        local_final: []const u8,
        transfer_id: u32,
        outcome: ?*SftpOutcome,
    ) !void {
        const session = try self.sftpSession(server_id);
        const owned_paths = try self.allocator.alloc([]const u8, paths.len);
        errdefer self.allocator.free(owned_paths);
        for (paths, 0..) |p, i| {
            owned_paths[i] = try self.allocator.dupe(u8, p);
            errdefer self.allocator.free(owned_paths[i]);
        }
        const owned_partial = try self.allocator.dupe(u8, local_partial);
        errdefer self.allocator.free(owned_partial);
        const owned_final = try self.allocator.dupe(u8, local_final);
        errdefer self.allocator.free(owned_final);
        try self.queueSftp(session, .{ .sftp_zip_download = .{
            .paths = owned_paths,
            .local_partial = owned_partial,
            .local_final = owned_final,
            .transfer_id = transfer_id,
            .outcome = outcome,
        } });
    }

    /// Cancels an async transfer: sets the cancel flag immediately (long-
    /// running ops check it between entries) and queues the worker cleanup
    /// op (upload partial deletion).
    pub fn sftpCancel(self: *Manager, server_id: []const u8, transfer_id: u32) !void {
        const session = try self.sftpSession(server_id);
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t| t.cancel_flag = true;
        session.sftp_transfers.unlock();
        try self.queueSftp(session, .{ .sftp_cancel = .{ .transfer_id = transfer_id } });
    }

    fn sftpSession(self: *Manager, server_id: []const u8) !*Session {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        return session;
    }

    /// Starts a transfer record (async ops); the worker owns progress.
    pub fn sftpStartTransfer(self: *Manager, session: *Session, kind: []const u8, path: []const u8) !u32 {
        session.sftp_transfers.lock();
        defer session.sftp_transfers.unlock();
        return session.sftp_transfers.add(self.allocator, kind, path);
    }

    /// Registers an upload transfer under the frontend-chosen id (the
    /// unguessable transfer_id from the payload; spec 05 §5).
    pub fn sftpStartUpload(self: *Manager, session: *Session, transfer_id: u32, path: []const u8) !void {
        session.sftp_transfers.lock();
        defer session.sftp_transfers.unlock();
        if (session.sftp_transfers.get(transfer_id) != null) return;
        session.sftp_transfers.addWithId(self.allocator, transfer_id, "upload", path) catch {};
    }

    /// folderSize cache lookup (spec 05 §5: 5 min per path, exact bytes).
    /// Main thread only — the handler is the sole caller.
    pub fn sftpFolderSizeCached(self: *Manager, session: *Session, path: []const u8, now_ns: i128) ?u64 {
        _ = self;
        for (session.folder_size_cache.items) |e| {
            if (std.mem.eql(u8, e.path, path) and now_ns - e.ts_ns < 5 * std.time.ns_per_min) return e.size;
        }
        return null;
    }

    /// Stores a folderSize result (owned path; freed with the session).
    pub fn sftpFolderSizeCacheSet(self: *Manager, session: *Session, path: []const u8, size: u64, now_ns: i128) void {
        const owned = self.allocator.dupe(u8, path) catch return;
        session.folder_size_cache.append(self.allocator, .{ .path = owned, .size = size, .ts_ns = now_ns }) catch self.allocator.free(owned);
    }

    /// Runs an exec to completion (EOF) with bounded output and a deadline.
    /// Used by handlers whose contract is a synchronous result (logs
    /// scan/read). The output is owned by the caller.
    pub fn execWait(self: *Manager, server_id: []const u8, command: []const u8, max_bytes: usize, timeout_ns: i128) !ExecOutcome {
        const channel = try self.exec(server_id, command);
        return self.waitExec(server_id, channel, max_bytes, timeout_ns, .{});
    }

    /// Runs an exec to completion while a non-UI owner can request an early
    /// stop. Cancellation queues channel cleanup on the owning session
    /// worker; this thread never calls libssh2 directly.
    pub fn execWaitCancelable(self: *Manager, server_id: []const u8, command: []const u8, max_bytes: usize, timeout_ns: i128, cancellation: WaitCancellation) !ExecOutcome {
        const channel = try self.exec(server_id, command);
        return self.waitExec(server_id, channel, max_bytes, timeout_ns, cancellation);
    }

    /// Runs a tracked exec to completion from a non-UI coordinator thread.
    pub fn execWaitTracked(
        self: *Manager,
        server_id: []const u8,
        command: []const u8,
        history_kind: []const u8,
        history_command: ?[]const u8,
        history_secrets: []const []const u8,
        max_bytes: usize,
        timeout_ns: i128,
    ) !ExecOutcome {
        const channel = try self.execTracked(server_id, command, history_kind, history_command, history_secrets);
        return self.waitExec(server_id, channel, max_bytes, timeout_ns, .{});
    }

    /// Runs a bounded exec with stdin to completion. Secret input is never
    /// part of the command text or command history.
    pub fn execWaitWithInput(self: *Manager, server_id: []const u8, command: []const u8, stdin_data: []const u8, max_bytes: usize, timeout_ns: i128) !ExecOutcome {
        const channel = try self.execWithInput(server_id, command, stdin_data);
        return self.waitExec(server_id, channel, max_bytes, timeout_ns, .{});
    }

    /// Runs a tracked exec with stdin to completion from a non-UI coordinator
    /// thread. Stdin is never retained in command history.
    pub fn execWaitTrackedWithInput(
        self: *Manager,
        server_id: []const u8,
        command: []const u8,
        stdin_data: []const u8,
        history_kind: []const u8,
        history_command: ?[]const u8,
        history_secrets: []const []const u8,
        max_bytes: usize,
        timeout_ns: i128,
    ) !ExecOutcome {
        const channel = try self.execTrackedWithInput(server_id, command, stdin_data, history_kind, history_command, history_secrets);
        return self.waitExec(server_id, channel, max_bytes, timeout_ns, .{});
    }

    fn waitExec(self: *Manager, server_id: []const u8, channel: u32, max_bytes: usize, timeout_ns: i128, cancellation: WaitCancellation) !ExecOutcome {
        const deadline = std.Io.Timestamp.now(self.io, .real).nanoseconds + timeout_ns;
        var out = ExecOutcome{ .output = .empty };
        errdefer out.deinit(self.allocator);
        var cursor: u64 = 0;
        while (true) {
            if (cancellation.isCanceled()) {
                self.closeChannel(server_id, channel) catch {};
                return error.Canceled;
            }
            const polls = try self.pollSelectedChannels(server_id, &.{.{ .id = channel, .pos = cursor }}, false, 64 * 1024, 64 * 1024, channel);
            defer {
                for (polls) |*poll| poll.deinit(self.allocator);
                self.allocator.free(polls);
            }
            for (polls) |*poll| {
                if (poll.id != channel) continue;
                if (poll.gap > 0) out.limited = true;
                if (!out.limited) {
                    if (out.output.items.len + poll.data.len > max_bytes) out.limited = true;
                    if (!out.limited) out.output.appendSlice(self.allocator, poll.data) catch return error.OutOfMemory;
                }
                cursor = poll.cursor;
                if (poll.eof and poll.pending <= poll.data.len) {
                    out.exit = poll.exit_status orelse 0;
                    return out;
                }
            }
            if (std.Io.Timestamp.now(self.io, .real).nanoseconds >= deadline) {
                // The deadline cut the response: honest partial output.
                out.limited = true;
                return out;
            }
            std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(10), .awake) catch return out;
        }
    }

    /// Queues an explicit channel close (spec 04's `oars.ssh.closeChannel`):
    /// the worker sends EOF, closes the raw channel, and frees the entry.
    /// Shell channels, including replacements, are never closed this way.
    pub fn closeChannel(self: *Manager, server_id: []const u8, channel_id: u32) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        lockSpin(&session.channels_mutex);
        const is_shell = for (session.channels.items) |entry| {
            if (entry.id == channel_id and entry.kind == .shell) break true;
        } else false;
        session.channels_mutex.unlock();
        if (is_shell or channel_id == 0) return error.InvalidChannel;
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .close_channel = .{ .id = channel_id } });
    }

    pub fn resize(self: *Manager, server_id: []const u8, cols: u16, rows: u16) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .resize = .{ .cols = @intCast(cols), .rows = @intCast(rows) } });
    }

    pub fn close(self: *Manager, server_id: []const u8) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .close);
    }

    /// Resolves the host-key trust decision. `accept` resumes the
    /// connection and persists the fingerprint. The trust mutex is
    /// released before taking the manager mutex: `disconnect` holds the
    /// manager mutex while joining the worker, and the worker spin-waits
    /// on the trust mutex — holding both here in the opposite order
    /// deadlocks all three.
    pub fn trust(self: *Manager, server_id: []const u8, accept: bool) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        lockSpin(&session.trust.mutex);
        if (!session.trust.pending) {
            session.trust.mutex.unlock();
            return error.NotPending;
        }
        session.trust.accept = accept;
        session.trust.decided = true;
        const fp: ?[]const u8 = if (accept)
            try self.allocator.dupe(u8, session.trust.fingerprint[0..session.trust.fingerprint_len])
        else
            null;
        session.trust.mutex.unlock();

        if (fp) |f| {
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            // The session's server copy takes ownership of the fingerprint
            // (freed with it in disconnect); upsert duplicates it for the
            // store. Freeing through the copy alone would leave
            // session.server.host_fingerprint dangling.
            if (session.server.host_fingerprint) |old| self.allocator.free(old);
            session.server.host_fingerprint = f;
            try self.store.upsert(self.io, session.server);
        }
    }

    /// Snapshot of every channel for one poll. The command text is copied
    /// (entries may be evicted or closed while the poll serializes), and
    /// each channel's data is copied up to the budgets. Cursors are
    /// per-consumer: `cursors` carries the requesting tab's absolute
    /// positions; `rewind` replays from the retained buffer start.
    pub fn pollChannels(
        self: *Manager,
        server_id: []const u8,
        cursors: []const Cursor,
        rewind: bool,
        data_budget: usize,
        channel_budget: usize,
    ) ![]ChannelPoll {
        return self.pollSelectedChannels(server_id, cursors, rewind, data_budget, channel_budget, null);
    }

    // An internal command waiter must not spend its byte budget on unrelated
    // retained shell/log output. Public polling still returns all channels.
    fn pollSelectedChannels(
        self: *Manager,
        server_id: []const u8,
        cursors: []const Cursor,
        rewind: bool,
        data_budget: usize,
        channel_budget: usize,
        selected_channel: ?u32,
    ) ![]ChannelPoll {
        const session = self.get(server_id) orelse return error.NoSession;
        const allocator = self.allocator;
        var out: std.ArrayList(ChannelPoll) = .empty;
        errdefer {
            for (out.items) |*poll| poll.deinit(allocator);
            out.deinit(allocator);
        }
        lockSpin(&session.channels_mutex);
        defer session.channels_mutex.unlock();
        var budget = data_budget;
        for (session.channels.items) |entry| {
            if (entry.internal) continue; // monitor probes are worker-owned
            if (selected_channel) |selected| if (entry.id != selected) continue;
            const requested: u64 = if (rewind) 0 else cursorFor(cursors, entry.id) orelse 0;
            const view = entry.stream.view(requested);
            const take = @min(view.pending, @as(u64, @min(channel_budget, budget)));
            var data: []u8 = &.{};
            if (take > 0) {
                data = allocator.alloc(u8, @intCast(take)) catch continue;
                const got = entry.stream.readAt(view.from, data);
                data = data[0..got];
            }
            var command: []u8 = &.{};
            if (entry.command.len > 0) {
                const safe_command = history.redact(allocator, entry.history_command orelse entry.command, entry.history_secrets orelse &.{}) catch {
                    allocator.free(data);
                    continue;
                };
                command = safe_command.text;
            }
            const snap = entry.stream.snapshot();
            // Output may arrive between the first view and EOF observation.
            // Include that tail before a waiter decides the command is drained.
            const latest_view = entry.stream.view(view.from);
            out.append(allocator, .{
                .id = entry.id,
                .kind = entry.kind,
                .user_visible = entry.history_kind != null,
                .command = command,
                .eof = snap.eof,
                .exit_status = snap.exit_status,
                .gap = @max(view.gap, latest_view.gap),
                .cursor = view.from + data.len,
                .pending = latest_view.pending,
                .data = data,
            }) catch {
                allocator.free(data);
                allocator.free(command);
                continue;
            };
            budget = budget -| @min(budget, data.len);
            if (budget == 0) break;
        }
        return out.toOwnedSlice(allocator);
    }

    /// Copies one exact retained channel range. This is separate from the
    /// multi-channel poll budget because callers such as AI summaries must
    /// not let unrelated shell or exec output consume the selected range.
    pub fn readChannelRange(self: *Manager, server_id: []const u8, channel_id: u32, start: u64, end: u64) !?[]u8 {
        if (end < start) return error.InvalidRange;
        const range_len: usize = std.math.cast(usize, end - start) orelse return error.InvalidRange;
        const session = self.get(server_id) orelse return error.NoSession;
        lockSpin(&session.channels_mutex);
        defer session.channels_mutex.unlock();
        for (session.channels.items) |entry| {
            if (entry.id != channel_id or entry.internal) continue;
            lockSpin(&entry.stream.mutex);
            defer entry.stream.mutex.unlock();
            if (start < entry.stream.start_abs or end > entry.stream.end_abs) return error.OutputNotRetained;
            const offset: usize = @intCast(start - entry.stream.start_abs);
            const selected = try self.allocator.alloc(u8, range_len);
            @memcpy(selected, entry.stream.data.items[offset .. offset + range_len]);
            return selected;
        }
        return null;
    }

    /// Copies the verified AI process-group marker for one tracked channel.
    /// A null result means the channel exists but its private marker has not
    /// arrived. The marker is never exposed through `ssh.poll` output.
    pub fn aiProcessGroup(self: *Manager, server_id: []const u8, channel_id: u32, output: []u8) !?[]const u8 {
        const session = self.get(server_id) orelse return error.NoSession;
        lockSpin(&session.channels_mutex);
        defer session.channels_mutex.unlock();
        for (session.channels.items) |entry| {
            if (entry.id != channel_id) continue;
            if (entry.ai_pgid_len == 0) return null;
            if (entry.ai_pgid_len > output.len) return error.NoSpaceLeft;
            @memcpy(output[0..entry.ai_pgid_len], entry.ai_pgid[0..entry.ai_pgid_len]);
            return output[0..entry.ai_pgid_len];
        }
        return error.InvalidChannel;
    }

    fn cursorFor(cursors: []const Cursor, id: u32) ?u64 {
        for (cursors) |c| {
            if (c.id == id) return c.pos;
        }
        return null;
    }

    pub fn sessionSnapshot(self: *Manager, server_id: []const u8) !SessionInfo {
        const session = self.get(server_id) orelse return error.NoSession;
        const status = session.status.load(.acquire);
        return .{
            .status = status,
            .forwarding = session.forwarding.load(.acquire),
            .history_full = session.history_full.load(.acquire),
            .history_write_error = session.history_write_error.load(.acquire),
            .@"error" = if (status == .@"error") session.errorText() else "",
            .trust_pending = session.trustPending(),
            .trust_fingerprint = session.trustFingerprint(),
            .trust_algorithm = session.trustAlgorithm(),
        };
    }

    /// Stable identity for one live connection generation. A reconnect gets
    /// a new value, so an approval cannot cross session replacement.
    pub fn connectionIdentity(self: *Manager, server_id: []const u8) !u64 {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        return session.id;
    }

    /// Marks monitor poll activity: the worker probes only while polls are
    /// recent (spec 03 §6: no poll → no probe traffic).
    pub fn monitorTouch(self: *Manager, server_id: []const u8, now_ns: i64) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        session.monitor_last_poll_ns.store(now_ns, .release);
    }

    /// Enqueues an immediate probe (manual refresh, or right after a
    /// mutating monitor action so the cache refreshes).
    pub fn monitorForce(self: *Manager, server_id: []const u8, now_ns: i64) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        session.monitor_last_poll_ns.store(now_ns, .release);
        session.monitor_force.store(true, .release);
    }

    // --- VNC tunnels (spec 12) ---------------------------------------------

    pub fn nextTunnelId(self: *Manager) u32 {
        return self.next_tunnel_id.fetchAdd(1, .monotonic);
    }

    /// Queues a tunnel start: the worker binds 127.0.0.1:0 and opens the
    /// direct-tcpip channel, then fills `outcome` with the ephemeral port.
    pub fn tunnelStart(self: *Manager, server_id: []const u8, id: u32, token: []const u8, host: []const u8, port: u16, outcome: *TunnelStartOutcome) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        const token_owned = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(token_owned);
        const host_owned = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(host_owned);
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .tunnel_start = .{
            .id = id,
            .token = token_owned,
            .host = host_owned,
            .port = port,
            .outcome = outcome,
        } });
    }

    /// Queues a tunnel teardown (idempotent; unknown ids are a no-op).
    pub fn tunnelStop(self: *Manager, server_id: []const u8, id: u32) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .tunnel_stop = .{ .id = id } });
    }

    /// Spec 18: queues the agent-forwarding toggle on the session's
    /// worker (the shell is reopened with or without the auth-agent
    /// request). `outcome` is filled by the worker.
    pub fn setForwarding(self: *Manager, server_id: []const u8, on: bool, outcome: *ForwardSetOutcome) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .forward_set = .{ .on = on, .outcome = outcome } });
    }

    /// Copies the tunnel's stats under the lock; false when the tunnel is
    /// unknown (already removed).
    pub fn tunnelPoll(self: *Manager, server_id: []const u8, id: u32, info: *TunnelPollInfo) bool {
        const session = self.get(server_id) orelse return false;
        lockSpin(&session.tunnels_mutex);
        defer session.tunnels_mutex.unlock();
        for (session.tunnels.items) |t| {
            if (t.id == id) {
                info.state = t.state;
                info.bytes_up = t.bytes_up;
                info.bytes_down = t.bytes_down;
                info.error_len = t.error_len;
                @memcpy(info.error_buf[0..t.error_len], t.error_buf[0..t.error_len]);
                return true;
            }
        }
        return false;
    }

    /// Spec 09: queues an internal exec for a fleet-scan phase step.
    /// Bounded output+deadline; drained by the worker. Do not block.
    pub fn enqueueAccessExec(self: *Manager, server_id: []const u8, command: []const u8, timeout_ns: i128, cap: usize, outcome: *AccessExecOutcome) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        const owned = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(owned);
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .access_exec = .{ .command = owned, .timeout_ns = timeout_ns, .cap = cap, .outcome = outcome } });
    }

    /// Admits a bounded, untracked AI context probe to the selected session
    /// worker. No SSH work occurs on the calling bridge thread.
    pub fn enqueueAiContext(self: *Manager, server_id: []const u8, operation_id: []const u8, command: []const u8, timeout_ns: i128, cap: usize, outcome: *AiContextOutcome) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        const operation_owned = try self.allocator.dupe(u8, operation_id);
        errdefer self.allocator.free(operation_owned);
        const command_owned = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(command_owned);
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .ai_context = .{
            .operation_id = operation_owned,
            .command = command_owned,
            .timeout_ns = timeout_ns,
            .cap = cap,
            .outcome = outcome,
        } });
    }

    /// Queues idempotent cancellation on the same worker that owns the SSH
    /// channel. A cancel racing completion reports the observed final state.
    pub fn cancelAiContext(self: *Manager, server_id: []const u8, operation_id: []const u8) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        const operation_owned = try self.allocator.dupe(u8, operation_id);
        errdefer self.allocator.free(operation_owned);
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .ai_context_cancel = .{ .operation_id = operation_owned } });
    }

    /// Fast preflight before copying a backup payload. The session is not
    /// borrowed beyond the manager lock; publishBackupOp resolves it again.
    fn ensureBackupSessionReadyMode(self: *Manager, server_id: []const u8, cleanup: bool) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const session = self.sessions.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        if (!cleanup and session.backup_admission_closed.load(.acquire)) return error.NotReady;
    }

    /// Publishes an already-owned backup op while the manager still owns the
    /// session map entry. disconnect removes entries under the same mutex, so
    /// it cannot join and destroy this session before the op is queued. Payload
    /// allocation and all worker work stay outside the manager critical section.
    fn publishBackupOpMode(self: *Manager, server_id: []const u8, op: Op, cleanup: bool) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const session = self.sessions.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        if (!cleanup and session.backup_admission_closed.load(.acquire)) return error.NotReady;
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, op);
    }

    /// Queues one bounded backup request. Payloads are copied before return;
    /// secret stdin/SFTP data is securely cleared on every worker/drain path.
    pub fn enqueueBackup(self: *Manager, server_id: []const u8, request: BackupRequest, outcome: *BackupOutcome) !void {
        try self.ensureBackupSessionReadyMode(server_id, false);
        const owned = try cloneBackupRequest(self.allocator, request);
        errdefer freeBackupRequest(self.allocator, owned);
        try self.publishBackupOpMode(server_id, .{ .backup = .{ .request = owned, .outcome = outcome } }, false);
    }

    /// Cleanup requests are the only backup work accepted after disconnect
    /// begins. They let the registry signal and verify a tracked process group
    /// before Manager tears down the worker transport.
    pub fn enqueueBackupCleanup(self: *Manager, server_id: []const u8, request: BackupRequest, outcome: *BackupOutcome) !void {
        try self.ensureBackupSessionReadyMode(server_id, true);
        const owned = try cloneBackupRequest(self.allocator, request);
        errdefer freeBackupRequest(self.allocator, owned);
        try self.publishBackupOpMode(server_id, .{ .backup = .{ .request = owned, .outcome = outcome } }, true);
    }

    /// Starts a streamed backup process on the session worker. The command and
    /// optional stdin are copied; the caller owns `process` until completion or
    /// transfers ownership with `BackupProcess.abandon`.
    pub fn startBackupProcess(self: *Manager, server_id: []const u8, command: []const u8, stdin_data: ?[]const u8, process: *BackupProcess) !void {
        try self.ensureBackupSessionReadyMode(server_id, false);
        const owned_command = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(owned_command);
        const owned_stdin: ?[]u8 = if (stdin_data) |stdin_bytes| try self.allocator.dupe(u8, stdin_bytes) else null;
        errdefer if (owned_stdin) |stdin_bytes| secureFreeBytes(self.allocator, stdin_bytes);
        try self.publishBackupOpMode(server_id, .{ .backup_run = .{ .command = owned_command, .stdin_data = owned_stdin, .process = process } }, false);
    }

    /// Spec 07: queues a read-only preflight probe on the session worker.
    /// Each probe is a single exec whose exit/output land in the outcome.
    pub fn enqueuePreflightProbe(self: *Manager, server_id: []const u8, id: []const u8, command: []const u8, timeout_ns: i128, outcome: *preflight.ProbeOutcome) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        const id_owned = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(id_owned);
        const owned = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(owned);
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        if (session.worker_done.load(.acquire)) return error.NotReady;
        try session.ops.append(self.allocator, .{ .preflight_probe = .{
            .id = id_owned,
            .command = owned,
            .timeout_ns = timeout_ns,
            .outcome = outcome,
        } });
    }
};

pub const Cursor = struct {
    id: u32,
    pos: u64,
};

pub const WaitCancellation = struct {
    context: ?*anyopaque = null,
    is_canceled_fn: *const fn (?*anyopaque) bool = neverCanceled,

    pub fn isCanceled(self: WaitCancellation) bool {
        return self.is_canceled_fn(self.context);
    }

    fn neverCanceled(_: ?*anyopaque) bool {
        return false;
    }
};

/// Bounded synchronous exec result (spec 04 read/scan).
pub const ExecOutcome = struct {
    output: std.ArrayList(u8) = .empty,
    exit: i32 = 0,
    /// True when the byte cap or the deadline cut the output.
    limited: bool = false,

    pub fn toOwnedSlice(self: *ExecOutcome, allocator: std.mem.Allocator) ![]u8 {
        return self.output.toOwnedSlice(allocator);
    }

    pub fn deinit(self: *ExecOutcome, allocator: std.mem.Allocator) void {
        self.output.deinit(allocator);
    }
};

pub const ChannelPoll = struct {
    id: u32,
    /// Only tracked operations belong in the terminal run picker. Plumbing
    /// still remains readable by its owning feature through channel cursors.
    user_visible: bool = false,
    kind: ChannelKind,
    /// Owned copy of the command text (entries can be evicted or closed
    /// while the poll response is being serialized).
    command: []u8,
    eof: bool,
    exit_status: ?i32,
    /// Bytes this consumer missed (its cursor preceded the retained start).
    gap: u64,
    /// The consumer's next cursor: one past the bytes delivered below.
    cursor: u64,
    /// Bytes available to this consumer at snapshot time.
    pending: u64,
    /// Owned copy of the delivered delta bytes.
    data: []u8,

    pub fn deinit(self: *ChannelPoll, allocator: std.mem.Allocator) void {
        allocator.free(self.command);
        allocator.free(self.data);
    }
};

pub const SessionInfo = struct {
    status: Status,
    forwarding: bool,
    history_full: bool,
    history_write_error: bool,
    @"error": []const u8,
    trust_pending: bool,
    trust_fingerprint: []const u8,
    trust_algorithm: []const u8,
};

fn workerMain(session: *Session) void {
    defer sessionDone(session);
    const io = session.io;
    const allocator = session.allocator;
    var error_buf: [256]u8 = undefined;

    // The stop flag doubles as the cancellation signal for every deadline
    // loop inside the transport (DNS, handshake, auth, channel ops).
    session.transport.setStop(workerStop, session);

    // --- connect + handshake -------------------------------------------
    var connect_fd: ?std.posix.socket_t = null;
    if (session.server.via_server_id) |via_id| {
        // Jump host (spec 18): resolve the via record, ensure its session
        // (key/agent jumps connect automatically; password jumps need the
        // user to have connected first), wait for it to be ready, then
        // tunnel target:22 through it and handshake over the local
        // socketpair end. The chain recurses: the via session's own
        // worker resolves its own via (depth ≤ 3 enforced at save).
        // `Store.find` returns a deep copy. Do not retain a `Server` borrowed
        // from `loadParsed`: that record points into the parsed file buffer
        // and becomes invalid as soon as `Loaded.deinit` runs.
        var via_record = (session.store.find(io, via_id) catch {
            session.status.store(.@"error", .release);
            session.setError("jump host lookup failed");
            return;
        }) orelse {
            session.status.store(.@"error", .release);
            session.setError("jump host not found — edit the server and pick a valid jump host");
            return;
        };
        defer via_record.deinit(allocator);
        var via_session = session.owner.get(via_id) orelse blk: {
            const started = session.owner.connect(via_record, null, null) catch {
                session.status.store(.@"error", .release);
                session.setError(std.fmt.bufPrint(&error_buf, "jump host {s} unavailable", .{via_record.name}) catch "jump host unavailable");
                return;
            };
            break :blk started;
        };
        // Wait for the via to finish connecting (bounded by its own
        // transport timeouts; the target's stop flag is checked).
        while (true) {
            if (session.stop_flag.load(.acquire)) return;
            const st = via_session.status.load(.acquire);
            if (st == .ready) break;
            if (st == .@"error" or st == .closed) {
                session.status.store(.@"error", .release);
                session.setError(std.fmt.bufPrint(&error_buf, "jump host {s} unreachable: {s}", .{ via_record.name, via_session.errorText() }) catch "jump host unreachable");
                return;
            }
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(50), .awake) catch return;
        }
        var fds: [2]std.posix.socket_t = undefined;
        if (ssh.c.socketpair(ssh.c.AF_UNIX, ssh.c.SOCK_STREAM, 0, &fds) != 0) {
            session.status.store(.@"error", .release);
            session.setError("jump host tunnel socket failed");
            return;
        }
        // Both ends must be non-blocking: the via worker pumps fds[0] in
        // its run loop (a blocking read would freeze every other channel
        // of the via session), and the target's libssh2 runs EAGAIN loops
        // on fds[1] (libssh2_session_set_blocking does NOT alter the
        // socket itself). Darwin uses SO_NOSIGPIPE; Linux writes use
        // MSG_NOSIGNAL through socketWriteNoSigpipe.
        for (&fds) |fd| configureNonBlockingSocket(fd) catch {
            _ = ssh.c.close(fds[0]);
            _ = ssh.c.close(fds[1]);
            session.status.store(.@"error", .release);
            session.setError("could not configure the jump tunnel socket");
            return;
        };
        var outcome: JumpStartOutcome = .{};
        const host_owned = allocator.dupe(u8, session.server.host) catch {
            _ = ssh.c.close(fds[0]);
            _ = ssh.c.close(fds[1]);
            return;
        };
        // The tunnel's dependant is THIS session — the cascade resolves
        // it by id when the via dies (duping via_id here made the
        // cascade resolve the via itself, a silent no-op).
        const target_id_owned = allocator.dupe(u8, session.server.id) catch {
            allocator.free(host_owned);
            _ = ssh.c.close(fds[0]);
            _ = ssh.c.close(fds[1]);
            return;
        };
        lockSpin(&via_session.ops_mutex);
        via_session.ops.append(allocator, .{ .jump_start = .{
            .host = host_owned,
            .port = session.server.port,
            .fd = fds[0],
            .target_server_id = target_id_owned,
            .outcome = &outcome,
        } }) catch {
            via_session.ops_mutex.unlock();
            allocator.free(host_owned);
            allocator.free(target_id_owned);
            _ = ssh.c.close(fds[0]);
            _ = ssh.c.close(fds[1]);
            session.status.store(.@"error", .release);
            session.setError("jump host tunnel failed (out of memory)");
            return;
        };
        via_session.ops_mutex.unlock();
        outcome.wait(io);
        if (!outcome.ok) {
            _ = ssh.c.close(fds[1]);
            session.status.store(.@"error", .release);
            session.setError(std.fmt.bufPrint(&error_buf, "jump host {s} unreachable: {s}", .{ via_record.name, outcome.message() }) catch "jump host unreachable");
            return;
        }
        session.via_name = allocator.dupe(u8, via_record.name) catch null;
        connect_fd = fds[1];
    }
    if (connect_fd) |fd| {
        session.transport.connectFd(io, fd) catch |err| {
            session.status.store(.@"error", .release);
            if (err == error.Canceled) {
                session.status.store(.closed, .release);
                return;
            }
            session.setError(std.fmt.bufPrint(&error_buf, "jump host {s} unreachable: {s}", .{ session.via_name orelse "", @errorName(err) }) catch "jump host unreachable");
            return;
        };
    } else {
        session.transport.connect(io, session.server.host, session.server.port) catch |err| {
            session.status.store(.@"error", .release);
            if (err == error.Canceled) {
                session.status.store(.closed, .release);
                return;
            }
            session.setError(std.fmt.bufPrint(&error_buf, "connect failed: {s}", .{@errorName(err)}) catch "connect failed");
            return;
        };
    }
    session.transport.keepaliveConfig();

    // --- host key verification -----------------------------------------
    // Canonical form is `SHA256:<base64>` (spec 02 §4.2); legacy 64-hex
    // records still compare and migrate once the same key verifies.
    var fp_buf: [64]u8 = undefined;
    const fingerprint = session.transport.hostKeyFingerprint(&fp_buf) catch {
        session.status.store(.@"error", .release);
        session.setError("host key unavailable");
        return;
    };
    const host_key_algorithm = session.transport.hostKeyAlgorithm() catch .unknown;
    if (session.server.host_fingerprint == null) {
        lockSpin(&session.trust.mutex);
        session.trust.pending = true;
        @memcpy(session.trust.fingerprint[0..fingerprint.len], fingerprint);
        session.trust.fingerprint_len = fingerprint.len;
        session.trust.algorithm = host_key_algorithm;
        session.trust.decided = false;
        session.trust.mutex.unlock();
        session.status.store(.needs_trust, .release);
        while (true) {
            if (session.stop_flag.load(.acquire)) return;
            lockSpin(&session.trust.mutex);
            const decided = session.trust.decided;
            const accept = session.trust.accept;
            session.trust.mutex.unlock();
            if (decided) {
                if (!accept) {
                    session.status.store(.closed, .release);
                    return;
                }
                break;
            }
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(50), .awake) catch return;
        }
    } else {
        const stored = session.server.host_fingerprint.?;
        var hex_buf: [64]u8 = undefined;
        const hex_fingerprint = session.transport.hostKeySha256Hex(&hex_buf) catch {
            session.status.store(.@"error", .release);
            session.setError("host key unavailable");
            return;
        };
        const matches = if (std.mem.startsWith(u8, stored, "SHA256:"))
            std.mem.eql(u8, stored, fingerprint)
        else
            std.mem.eql(u8, stored, hex_fingerprint);
        if (!matches) {
            // Spec 02 §4.2: a changed key fails with both fingerprints.
            session.status.store(.@"error", .release);
            session.setError(std.fmt.bufPrint(
                &error_buf,
                "host key changed since last connection (old: {s}, new: {s}); re-trust by editing the server and verifying the new key",
                .{ stored, fingerprint },
            ) catch "host key changed since last connection");
            return;
        }
        // Legacy hex records migrate to the canonical form once the same
        // key verifies (spec 01 §12). The shallow copy shares all strings
        // with session.server except the fingerprint, so nothing dangles if
        // the write fails — a failed migration is cosmetic only (the key
        // just verified, so the security property already holds).
        if (!std.mem.startsWith(u8, stored, "SHA256:")) {
            const canonical = allocator.dupe(u8, fingerprint) catch return;
            var migrated = session.server;
            migrated.host_fingerprint = canonical;
            session.store.upsert(io, migrated) catch {
                allocator.free(canonical);
                return;
            };
        }
    }

    // --- authentication -------------------------------------------------
    session.status.store(.authenticating, .release);
    if (session.server.auth_method == .password) {
        const password = session.password orelse {
            session.status.store(.@"error", .release);
            session.setError("no password provided");
            return;
        };
        session.transport.authPassword(io, session.server.user, password) catch |err| {
            session.status.store(.@"error", .release);
            var msg_buf: [256]u8 = undefined;
            const msg = session.transport.lastErrorMessage(&msg_buf);
            session.setError(std.fmt.bufPrint(&error_buf, "authentication failed: {s} ({s})", .{ @errorName(err), msg }) catch "authentication failed");
            return;
        };
    } else if (session.server.auth_method == .key) {
        if (session.server.key_path.len == 0) {
            session.status.store(.@"error", .release);
            session.setError("no private key configured; edit the server to choose one");
            return;
        }
        // Stored paths may use shell tilde syntax ("~/.ssh/...") —
        // expand it before anything touches the filesystem.
        const key_expanded = servers.expandHome(allocator, session.server.key_path, session.home) catch {
            session.status.store(.@"error", .release);
            session.setError("out of memory preparing key auth");
            return;
        };
        defer allocator.free(key_expanded);
        // Keys are read into memory rather than handed to libssh2 as
        // paths: OpenSSH-format keys (the ssh-keygen default) cannot be
        // parsed by libssh2's mbedTLS backend at all, and Ed25519 keys
        // are signed natively (see authEd25519 in ssh.zig).
        const key_bytes = std.Io.Dir.cwd().readFileAlloc(io, key_expanded, allocator, .limited(256 * 1024)) catch {
            session.status.store(.@"error", .release);
            session.setError(std.fmt.bufPrint(&error_buf, "cannot read private key file '{s}'", .{key_expanded}) catch "cannot read private key file");
            return;
        };
        defer allocator.free(key_bytes);
        // The conventional "<key>.pub" sidecar is optional but helps
        // libssh2 skip re-deriving the public key for RSA/ECDSA keys.
        var pub_bytes: []const u8 = "";
        var pub_owned: ?[]u8 = null;
        defer if (pub_owned) |p| allocator.free(p);
        if (std.fmt.allocPrint(allocator, "{s}.pub", .{key_expanded}) catch null) |pub_path| {
            defer allocator.free(pub_path);
            pub_owned = std.Io.Dir.cwd().readFileAlloc(io, pub_path, allocator, .limited(64 * 1024)) catch null;
            if (pub_owned) |p| pub_bytes = p;
        }
        const passphrase = session.passphrase orelse "";
        const user_z = allocator.dupeZ(u8, session.server.user) catch {
            session.status.store(.@"error", .release);
            session.setError("out of memory preparing key auth");
            return;
        };
        defer allocator.free(user_z);

        if (openssh.parse(allocator, key_bytes, passphrase)) |parsed_value| {
            var parsed = parsed_value;
            defer parsed.deinit(allocator);
            if (parsed.ed25519_seed) |seed| {
                const key_pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch {
                    session.status.store(.@"error", .release);
                    session.setError("invalid Ed25519 key material");
                    return;
                };
                session.transport.authEd25519(io, user_z, parsed.public_wire, &key_pair) catch |err| {
                    reportKeyAuthError(session, &error_buf, err);
                    return;
                };
            } else {
                // RSA/ECDSA in OpenSSH armor: libssh2's own OpenSSH
                // parser (pem.c) handles these from memory.
                session.transport.authKeyMemory(io, session.server.user, pub_bytes, key_bytes, passphrase) catch |err| {
                    reportKeyAuthError(session, &error_buf, err);
                    return;
                };
            }
        } else |parse_err| switch (parse_err) {
            // Classic PEM (PKCS#1/PKCS#8/SEC1): straight to libssh2.
            error.NotOpenSsh => {
                session.transport.authKeyMemory(io, session.server.user, pub_bytes, key_bytes, passphrase) catch |err| {
                    reportKeyAuthError(session, &error_buf, err);
                    return;
                };
            },
            error.WrongPassphrase => {
                session.status.store(.@"error", .release);
                session.setError("could not decrypt the private key — is the stored passphrase correct?");
                return;
            },
            error.UnsupportedCipher => {
                session.status.store(.@"error", .release);
                session.setError("unsupported key encryption (only aes256-ctr and unencrypted keys are supported)");
                return;
            },
            else => {
                session.status.store(.@"error", .release);
                session.setError("malformed OpenSSH private key");
                return;
            },
        }
    } else {
        // SSH agent auth (spec 18): the private key never touches Oars —
        // the agent performs the signing. SSH_AUTH_SOCK or an explicit
        // socket, validated as an own Unix socket before connecting.
        const agent_path = agent.resolveSocket(allocator, null) catch {
            session.status.store(.@"error", .release);
            session.setError("no SSH agent — start ssh-agent or set SSH_AUTH_SOCK");
            return;
        };
        defer allocator.free(agent_path);
        agent.validateSocket(agent_path) catch |err| {
            session.status.store(.@"error", .release);
            session.setError(switch (err) {
                error.NotASocket => "SSH_AUTH_SOCK does not point to a socket",
                error.NotOwned => "the SSH agent socket is not owned by the current user",
                else => "no SSH agent — start ssh-agent or set SSH_AUTH_SOCK",
            });
            return;
        };
        var agent_conn = agent.Agent.init(session.transport.rawSession()) catch {
            session.status.store(.@"error", .release);
            session.setError("could not connect to the SSH agent");
            return;
        };
        defer agent_conn.deinit();
        agent_conn.auth(session.server.user, null) catch {
            session.status.store(.@"error", .release);
            var msg_buf: [256]u8 = undefined;
            const msg = session.transport.lastErrorMessage(&msg_buf);
            session.setError(std.fmt.bufPrint(&error_buf, "agent authentication failed: {s}", .{msg}) catch "agent authentication failed");
            return;
        };
    }

    // --- interactive shell ----------------------------------------------
    if (!openShellChannel(session, io)) return;
    session.status.store(.ready, .release);

    // --- run loop --------------------------------------------------------
    var read_buf: [32 * 1024]u8 = undefined;
    var input_buf: [16 * 1024]u8 = undefined;
    while (!session.stop_flag.load(.acquire)) {
        // shell stdin
        if (session.shell) |shell| {
            lockSpin(&shell.stdin_mutex);
            const n = @min(shell.stdin_queue.items.len, input_buf.len);
            if (n > 0) {
                @memcpy(input_buf[0..n], shell.stdin_queue.items[0..n]);
                std.mem.copyForwards(u8, shell.stdin_queue.items[0 .. shell.stdin_queue.items.len - n], shell.stdin_queue.items[n..]);
                shell.stdin_queue.items.len -= n;
            }
            shell.stdin_mutex.unlock();
            var written: usize = 0;
            while (written < n) {
                const w = shell.raw.write(input_buf[written..n]);
                if (w == 0) break;
                written += w;
            }
            if (written < n) {
                const rest = input_buf[written..n];
                lockSpin(&shell.stdin_mutex);
                shell.stdin_queue.insertSlice(allocator, 0, rest) catch {};
                shell.stdin_mutex.unlock();
            }
        }
        // queued ops
        processOps(session);
        if (session.stop_flag.load(.acquire)) break;
        driveExecStdin(session);

        // reads on all channels
        var i: usize = 0;
        while (true) {
            lockSpin(&session.channels_mutex);
            if (i >= session.channels.items.len) {
                session.channels_mutex.unlock();
                break;
            }
            const entry = session.channels.items[i];
            session.channels_mutex.unlock();

            // Closed channels must never be read again: `raw.close` freed
            // the libssh2 channel (its session pointer is nulled), and a
            // second read would dereference freed memory.
            if (entry.raw_closed) {
                i += 1;
                continue;
            }
            // Spec 06: a syntax check that outlives its deadline is closed
            // and completed honestly instead of occupying a broadcast slot
            // forever.
            if (entry.check_outcome != null and entry.check_timeout_ns > 0 and
                std.Io.Timestamp.now(io, .real).nanoseconds - entry.started_ns >= entry.check_timeout_ns)
            {
                entry.raw.sendEof();
                entry.raw.close(session.io);
                entry.raw_closed = true;
                entry.check_outcome.?.set(null, "syntax check timed out");
                entry.check_outcome = null;
                if (!dropEntryAt(session, i, entry)) i += 1;
                continue;
            }
            if (entry.ai_context_outcome != null and entry.ai_context_timeout_ns > 0 and
                std.Io.Timestamp.now(io, .real).nanoseconds - entry.started_ns >= entry.ai_context_timeout_ns)
            {
                entry.raw.sendEof();
                entry.raw.close(session.io);
                entry.raw_closed = true;
                entry.ai_context_outcome.?.complete(null, "", "context probe timed out", false, false);
                entry.ai_context_outcome = null;
                if (!dropEntryAt(session, i, entry)) i += 1;
                continue;
            }
            // Spec 07: a preflight probe that outlives its deadline is closed
            // and completed honestly (read-only — no rollback needed).
            if (entry.access_exec_outcome != null and entry.access_exec_timeout_ns > 0 and
                std.Io.Timestamp.now(io, .real).nanoseconds - entry.started_ns >= entry.access_exec_timeout_ns)
            {
                entry.raw.sendEof();
                entry.raw.close(session.io);
                entry.raw_closed = true;
                entry.access_exec_outcome.?.set(null, "", "access exec timed out");
                entry.access_exec_outcome = null;
                entry.access_exec_timeout_ns = 0;
                lockSpin(&entry.stream.mutex);
                entry.stream.eof = true;
                entry.stream.exit_status = null;
                entry.stream.mutex.unlock();
                recordExecHistory(session, entry);
                if (!dropEntryAt(session, i, entry)) i += 1;
                continue;
            }
            if (entry.backup_outcome != null and entry.backup_timeout_ns > 0 and
                std.Io.Timestamp.now(io, .real).nanoseconds - entry.started_ns >= entry.backup_timeout_ns)
            {
                entry.raw.sendEof();
                entry.raw.close(session.io);
                entry.raw_closed = true;
                entry.backup_outcome.?.set(.timeout, null, fx_unknown, false, "", "backup exec timed out");
                entry.backup_outcome = null;
                entry.backup_timeout_ns = 0;
                if (!dropEntryAt(session, i, entry)) i += 1;
                continue;
            }
            if (entry.preflight_probe != null and entry.preflight_timeout_ns > 0 and
                std.Io.Timestamp.now(io, .real).nanoseconds - entry.started_ns >= entry.preflight_timeout_ns)
            {
                entry.raw.sendEof();
                entry.raw.close(session.io);
                entry.raw_closed = true;
                entry.preflight_probe.?.set(null, "", "preflight probe timed out");
                entry.preflight_probe = null;
                if (entry.preflight_id) |pid| {
                    session.allocator.free(pid);
                    entry.preflight_id = null;
                }
                if (!dropEntryAt(session, i, entry)) i += 1;
                continue;
            }
            const read_result = if (entry.kind == .shell) entry.raw.readOpenStream(&read_buf) else entry.raw.read(&read_buf);
            switch (read_result) {
                .eof => {
                    if (entry.kind == .shell and session.shell_parser != null) {
                        var sink_context = ShellHistorySink{ .session = session, .entry = entry };
                        session.shell_parser.?.flush(sink_context.sink());
                        session.history_full.store(false, .release);
                    }
                    if (!entry.eof_seen) {
                        entry.eof_seen = true;
                        lockSpin(&entry.stream.mutex);
                        entry.stream.eof = true;
                        entry.stream.exit_status = entry.raw.exitStatus();
                        entry.stream.mutex.unlock();
                        entry.raw.sendEof();
                        entry.raw.close(session.io);
                        entry.raw_closed = true;
                        if (entry.internal) {
                            if (entry.check_outcome) |oc| {
                                drainSyntaxCheck(session, entry, oc);
                                entry.check_outcome = null;
                            } else if (entry.ai_context_outcome != null) {
                                drainAiContext(session, entry);
                                entry.ai_context_outcome = null;
                            } else if (entry.preflight_probe) |_| {
                                drainPreflightProbe(session, entry);
                                if (entry.preflight_id) |pid| {
                                    session.allocator.free(pid);
                                    entry.preflight_id = null;
                                }
                                entry.preflight_probe = null;
                                entry.preflight_timeout_ns = 0;
                            } else if (entry.access_exec_outcome != null) {
                                drainAccessExec(session, entry);
                                entry.access_exec_outcome = null;
                                entry.access_exec_timeout_ns = 0;
                                recordExecHistory(session, entry);
                            } else if (entry.backup_outcome != null) {
                                drainBackupExec(session, entry);
                                entry.backup_outcome = null;
                                entry.backup_timeout_ns = 0;
                                recordExecHistory(session, entry);
                            } else if (entry.backup_process) |process| {
                                process.complete(entry.stream.exit_status, false, "process exited");
                                entry.backup_process = null;
                                recordExecHistory(session, entry);
                            } else {
                                drainProbe(session, entry);
                                session.monitor_probe_active.store(false, .release);
                            }
                        }
                    }
                    if (entry.internal) {
                        // Consumed by the worker; drop the entry now (the
                        // next item shifts into slot i).
                        if (!dropEntryAt(session, i, entry)) i += 1;
                        continue;
                    } else if (entry.kind == .exec or entry.kind == .log) {
                        // Spec 15: a completed tracked exec lands in
                        // command history with exit, duration, and a
                        // bounded output snippet before eviction may
                        // free the entry.
                        if (entry.kind == .exec and entry.history_kind != null) recordExecHistory(session, entry);
                        evictCompletedExecs(session);
                    }
                    i += 1;
                },
                .data => |n| {
                    if (entry.kind == .shell and session.shell_parser != null) {
                        var sink_context = ShellHistorySink{ .session = session, .entry = entry };
                        session.shell_parser.?.feed(read_buf[0..n], sink_context.sink());
                    } else appendChannelData(entry, read_buf[0..n]);
                    if (entry.backup_process) |process| process.append(read_buf[0..n]);
                    i += 1;
                },
                .again => i += 1,
            }
        }
        // --- VNC tunnels (spec 12) -------------------------------------
        processTunnels(session, io, std.Io.Timestamp.now(io, .real).nanoseconds);

        // --- jump-host tunnels (spec 18) --------------------------------
        processJumpTunnels(session, io);

        // --- agent forwarding proxy (spec 18) ----------------------------
        processForwardChannels(session, io);

        // --- monitor probe (probe-on-demand, spec 03 §6) -----------------
        // The worker probes only while monitor polls are recent (liveness
        // window) or a poll explicitly enqueued one (force); a session with
        // no monitor view generates no probe traffic.
        if (!session.monitor_probe_active.load(.acquire)) {
            const force = session.monitor_force.swap(false, .acquire);
            const now = monitorTimeNs(std.Io.Timestamp.now(io, .real).nanoseconds);
            const poll_recent = now - session.monitor_last_poll_ns.load(.acquire) < session.monitor_liveness_ns;
            if (force or (poll_recent and now - session.monitor_last_probe_ns.load(.acquire) >= session.monitor_interval_ns)) {
                session.monitor_last_probe_ns.store(now, .release);
                startProbe(session) catch {
                    storeProbeFailure(session, "probe could not start");
                };
            }
        }

        // keepalive
        const now = std.Io.Timestamp.now(io, .real).nanoseconds;
        if (now - session.last_keepalive_ns >= session.keepalive_interval_ns) {
            session.last_keepalive_ns = now;
            _ = session.transport.keepaliveSend(io) catch {
                session.status.store(.@"error", .release);
                session.setError("connection lost");
                return;
            };
        }

        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch return;
    }
}

/// Bounded retention of completed exec channels. A stopped or slow frontend
/// must not let a session accumulate unbounded channel metadata, so once the
/// cap is exceeded the oldest completed exec is evicted (its undrained bytes
/// with it — the frontend has had many polls to drain it by then).
const max_completed_execs = 64;

fn evictCompletedExecs(session: *Session) void {
    lockSpin(&session.channels_mutex);
    defer session.channels_mutex.unlock();
    var completed: usize = 0;
    for (session.channels.items) |e| {
        if ((e.kind == .exec or e.kind == .log) and e.eof_seen and !e.internal) completed += 1;
    }
    while (completed > max_completed_execs) {
        var found: ?usize = null;
        for (session.channels.items, 0..) |e, i| {
            if ((e.kind == .exec or e.kind == .log) and e.eof_seen and !e.internal) {
                found = i;
                break;
            }
        }
        const i = found orelse break;
        const entry = session.channels.items[i];
        _ = session.channels.orderedRemove(i);
        entry.clearStdin(session.allocator);
        entry.freeCommandText(session.allocator);
        entry.stream.deinit(session.allocator);
        session.allocator.destroy(entry.stream);
        session.allocator.destroy(entry);
        completed -= 1;
    }
}

/// Spec 15 capture: records a completed tracked exec in command history.
/// Runs on the worker at channel EOF, so it owns the stream data and the
/// command text; everything the store needs is duplicated into the entry.
/// Failures are dropped like audit appends (the log must never take the
/// session down); the index stays consistent because record is atomic.
fn recordExecHistory(session: *Session, entry: *ChannelEntry) void {
    const allocator = session.allocator;
    const kind = entry.history_kind orelse return;
    const raw_command = entry.history_command orelse entry.command;
    const secrets = entry.history_secrets orelse &.{};
    const redacted = history.redact(allocator, raw_command, secrets) catch return;
    defer allocator.free(redacted.text);
    const now = std.Io.Timestamp.now(session.io, .real).nanoseconds;
    const duration_ms: ?i64 = if (entry.started_ns > 0)
        @intCast(@max(0, @divTrunc(now - entry.started_ns, std.time.ns_per_ms)))
    else
        null;
    // First two lines of output, bounded. The snippet is masked with the
    // operation's exact secret values (the script's echoed value must not
    // survive in stored text); patterns never apply to program output.
    var snippet_buf: [history.snippet_cap]u8 = undefined;
    const snippet_len = historySnippet(entry, &snippet_buf);
    var snippet_owned: []u8 = undefined;
    var snippet_redacted = false;
    if (secrets.len > 0) {
        const r = history.exactMask(allocator, snippet_buf[0..snippet_len], secrets) catch return;
        snippet_owned = r.text;
        snippet_redacted = r.redacted;
    } else {
        snippet_owned = allocator.dupe(u8, snippet_buf[0..snippet_len]) catch return;
    }
    defer allocator.free(snippet_owned);
    var op_buf: [64]u8 = undefined;
    const op_id = entry.history_operation_id orelse blk: {
        const generated = std.fmt.bufPrint(&op_buf, "exec-{d}", .{session.history_seq}) catch return;
        session.history_seq += 1;
        break :blk generated;
    };
    session.history.record(session.io, .{
        .id = "",
        .operation_id = op_id,
        .ts = @intCast(now),
        .server_id = session.server.id,
        .kind = kind,
        .command = redacted.text,
        .exit = entry.stream.exit_status,
        .duration_ms = duration_ms,
        .output_snippet = snippet_owned,
        .redacted = redacted.redacted or (entry.history_command != null and entry.history_command_redacted) or snippet_redacted,
    }) catch {};
}

const ai_pgid_prefix = "__OARS_AI_PGID__";

fn appendChannelData(entry: *ChannelEntry, bytes: []const u8) void {
    if (!entry.ai_marker_pending) {
        entry.stream.append(bytes) catch {};
        return;
    }
    const newline = std.mem.indexOfScalar(u8, bytes, '\n');
    const marker_part = if (newline) |index| bytes[0..index] else bytes;
    if (entry.ai_marker_len + marker_part.len > entry.ai_marker.len) {
        entry.ai_marker_pending = false;
        entry.stream.append(entry.ai_marker[0..entry.ai_marker_len]) catch {};
        entry.stream.append(bytes) catch {};
        return;
    }
    @memcpy(entry.ai_marker[entry.ai_marker_len .. entry.ai_marker_len + marker_part.len], marker_part);
    entry.ai_marker_len += marker_part.len;
    if (newline == null) return;
    const marker = entry.ai_marker[0..entry.ai_marker_len];
    if (std.mem.startsWith(u8, marker, ai_pgid_prefix)) {
        const pgid = marker[ai_pgid_prefix.len..];
        if (validDecimalProcessGroup(pgid)) {
            @memcpy(entry.ai_pgid[0..pgid.len], pgid);
            entry.ai_pgid_len = pgid.len;
        } else {
            entry.stream.append(marker) catch {};
            entry.stream.append("\n") catch {};
        }
    } else {
        entry.stream.append(marker) catch {};
        entry.stream.append("\n") catch {};
    }
    entry.ai_marker_pending = false;
    const remaining = bytes[newline.? + 1 ..];
    if (remaining.len > 0) entry.stream.append(remaining) catch {};
}

fn validDecimalProcessGroup(value: []const u8) bool {
    if (value.len == 0 or value.len > 20) return false;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return false;
    return true;
}

test "AI execution marker is fragmented safely and hidden from output" {
    const allocator = std.testing.allocator;
    var stream = Stream.init(allocator);
    defer stream.deinit(allocator);
    var entry = ChannelEntry{
        .id = 7,
        .kind = .exec,
        .stream = &stream,
        .raw = undefined,
        .ai_marker_pending = true,
    };
    appendChannelData(&entry, "__OARS_AI_");
    appendChannelData(&entry, "PGID__12345\nhello ");
    appendChannelData(&entry, "world\n");
    try std.testing.expectEqualStrings("12345", entry.ai_pgid[0..entry.ai_pgid_len]);
    var output: [64]u8 = undefined;
    const read = stream.readAt(0, &output);
    try std.testing.expectEqualStrings("hello world\n", output[0..read]);
}

/// Copies the first two lines of the stream into `buf`, trimmed of
/// trailing whitespace. Returns the length.
fn historySnippet(entry: *ChannelEntry, buf: []u8) usize {
    lockSpin(&entry.stream.mutex);
    defer entry.stream.mutex.unlock();
    const data = entry.stream.data.items;
    var end: usize = 0;
    var lines: usize = 0;
    while (end < data.len and lines < 2) {
        if (data[end] == '\n') lines += 1;
        end += 1;
    }
    const cap = @min(end, buf.len);
    if (cap > 0) @memcpy(buf[0..cap], data[0..cap]);
    var len = cap;
    while (len > 0 and (buf[len - 1] == '\n' or buf[len - 1] == '\r' or buf[len - 1] == ' ' or buf[len - 1] == '\t')) len -= 1;
    return len;
}

/// Opens an internal channel and runs the probe command on it. The entry
/// is marked internal so polls never see it; the worker drains and parses
/// it at EOF (spec 03 §6: probe via the exec path, bounded read).
fn startProbe(session: *Session) !void {
    const raw = try session.transport.openChannel(session.io);
    errdefer raw.close(session.io);
    try raw.exec(session.io, monitor.probe_command);
    const stream = try session.allocator.create(Stream);
    errdefer session.allocator.destroy(stream);
    stream.* = Stream.init(session.allocator);
    const entry = try session.allocator.create(ChannelEntry);
    errdefer session.allocator.destroy(entry);
    entry.* = .{
        .id = session.next_channel_id.fetchAdd(1, .monotonic),
        .kind = .exec,
        .command = "",
        .stream = stream,
        .raw = raw,
        .internal = true,
    };
    lockSpin(&session.channels_mutex);
    session.channels.append(session.allocator, entry) catch {
        session.channels_mutex.unlock();
        return error.OutOfMemory;
    };
    session.channels_mutex.unlock();
    session.monitor_probe_active.store(true, .release);
}

/// Drains an internal probe channel, parses the output, computes the CPU
/// delta against the previous sample, and commits the snapshot. Failures
/// surface as `probe_error` — the UI degrades honestly, it never sees
/// fabricated numbers.
fn drainProbe(session: *Session, entry: *ChannelEntry) void {
    const allocator = session.allocator;
    var total: std.ArrayList(u8) = .empty;
    defer total.deinit(allocator);
    var buf: [32 * 1024]u8 = undefined;
    const cap: usize = 256 * 1024;
    var cursor = entry.stream.start();
    while (true) {
        const n = entry.stream.readAt(cursor, &buf);
        if (n == 0) break;
        if (total.items.len + n > cap) {
            storeProbeFailure(session, "probe output exceeded the capture cap");
            return;
        }
        total.appendSlice(allocator, buf[0..n]) catch {
            storeProbeFailure(session, "out of memory capturing probe output");
            return;
        };
        cursor += n;
    }

    session.monitor_cache.lock();
    const previous = session.monitor_cache.previous_cpu;
    session.monitor_cache.unlock();
    var result = monitor.parseProbeOutput(allocator, total.items, previous);
    result.snapshot.ts = @intCast(std.Io.Timestamp.now(session.io, .real).nanoseconds);
    // A nonzero probe exit means the output is suspect even if it parsed.
    if (entry.stream.exit_status != null and entry.stream.exit_status.? != 0) {
        result.snapshot.probe_error = "probe command failed";
    }
    session.monitor_cache.commit(allocator, result.snapshot, result.cpu_sample);

    // Drop-caches before/after contract (spec 03 §6): the next completed
    // probe records the after snapshot.
    if (session.monitor_drop_pending.swap(false, .acquire)) {
        var detail_buf: [256]u8 = undefined;
        const detail = std.fmt.bufPrint(
            &detail_buf,
            "after drop_caches: mem_used_bytes={d} mem_available_bytes={d}",
            .{ result.snapshot.mem.used_bytes, result.snapshot.mem.available_bytes },
        ) catch "after drop_caches";
        session.audit.append(session.io, "monitor.drop_caches.after", session.server.id, detail) catch {};
    }
}

/// Commits an honest failure snapshot (zeros + explicit probe_error).
fn storeProbeFailure(session: *Session, msg: []const u8) void {
    var snap = monitor.Snapshot{};
    snap.ts = @intCast(std.Io.Timestamp.now(session.io, .real).nanoseconds);
    snap.probe_error = msg;
    session.monitor_cache.commit(session.allocator, snap, null);
}

/// Removes and frees the channel entry at index `i` (worker side, under
/// channels_mutex). Returns false when the slot changed under us (the
/// entry was already removed by a concurrent path) — the caller then
/// skips the slot instead of touching the stale pointer.
fn dropEntryAt(session: *Session, i: usize, entry: *ChannelEntry) bool {
    lockSpin(&session.channels_mutex);
    const still = i < session.channels.items.len and session.channels.items[i] == entry;
    if (still) _ = session.channels.orderedRemove(i);
    session.channels_mutex.unlock();
    if (still) {
        entry.clearStdin(session.allocator);
        entry.freeCommandText(session.allocator);
        entry.stream.deinit(session.allocator);
        session.allocator.destroy(entry.stream);
        session.allocator.destroy(entry);
    }
    return still;
}

/// Completes a worker-driven `bash -n -c` syntax check at channel EOF
/// (spec 06 §5): exit 0 means the checked command is valid; any other
/// exit is reported with a bounded output tail (127 = bash unavailable).
/// The outcome follows the heap + abandon() protocol, so a canceled run's
/// handler-side free is never double-freed here.
fn drainSyntaxCheck(session: *Session, entry: *ChannelEntry, outcome: *broadcast.ScriptCheckOutcome) void {
    const allocator = session.allocator;
    var total: std.ArrayList(u8) = .empty;
    defer total.deinit(allocator);
    var buf: [1024]u8 = undefined;
    var cursor = entry.stream.start();
    while (true) {
        const n = entry.stream.readAt(cursor, &buf);
        if (n == 0) break;
        total.appendSlice(allocator, buf[0..n]) catch break;
        cursor += n;
    }
    // The message carries only a bounded tail (syntax errors are one line).
    var tail = total.items;
    if (tail.len > 512) tail = tail[tail.len - 512 ..];
    while (tail.len > 0 and (tail[tail.len - 1] == '\n' or tail[tail.len - 1] == '\r' or tail[tail.len - 1] == ' ' or tail[tail.len - 1] == '\t')) tail = tail[0 .. tail.len - 1];
    const exit = entry.stream.exit_status;
    var msg_buf: [640]u8 = undefined;
    const msg = if (exit != null and exit.? == 0)
        "syntax ok"
    else if (exit != null and exit.? == 127)
        "bash unavailable"
    else
        std.fmt.bufPrint(&msg_buf, "syntax check failed (exit {d}): {s}", .{ exit orelse -1, tail }) catch "syntax check failed";
    outcome.set(exit, msg);
}

/// Opens an internal exec channel for a `bash -n -c` syntax check (spec
/// 06 §5). The worker pump reads the channel; at EOF (or the deadline)
/// the outcome is completed and the entry dropped. Owns `sc.command` on
/// every path.
fn syntaxCheckOp(session: *Session, sc: anytype) void {
    const allocator = session.allocator;
    const raw = session.transport.openChannel(session.io) catch {
        allocator.free(sc.command);
        sc.outcome.set(null, "could not open a channel for the syntax check");
        return;
    };
    raw.exec(session.io, sc.command) catch {
        raw.close(session.io);
        allocator.free(sc.command);
        sc.outcome.set(null, "syntax check could not start");
        return;
    };
    const stream = allocator.create(Stream) catch {
        raw.close(session.io);
        allocator.free(sc.command);
        sc.outcome.set(null, "out of memory");
        return;
    };
    stream.* = Stream.init(allocator);
    // The check's output is diagnostics only; bound the retained buffer.
    stream.max_bytes = 16 * 1024;
    const entry = allocator.create(ChannelEntry) catch {
        allocator.destroy(stream);
        raw.close(session.io);
        allocator.free(sc.command);
        sc.outcome.set(null, "out of memory");
        return;
    };
    entry.* = .{
        .id = session.next_channel_id.fetchAdd(1, .monotonic),
        .kind = .exec,
        .command = sc.command,
        .stream = stream,
        .raw = raw,
        .internal = true,
        .check_outcome = sc.outcome,
        .check_timeout_ns = sc.timeout_ns,
        .started_ns = std.Io.Timestamp.now(session.io, .real).nanoseconds,
    };
    lockSpin(&session.channels_mutex);
    session.channels.append(allocator, entry) catch {
        session.channels_mutex.unlock();
        entry.clearStdin(allocator);
        entry.freeCommandText(allocator);
        allocator.destroy(entry);
        allocator.destroy(stream);
        raw.close(session.io);
        sc.outcome.set(null, "out of memory");
        return;
    };
    session.channels_mutex.unlock();
}

/// Spec 07: read-only preflight probe — internal channel, bounded output.
/// Mirrors syntaxCheckOp: owns `preflight_id`/`command`, completion frees via abandon().
fn drainPreflightProbe(session: *Session, entry: *ChannelEntry) void {
    var total: std.ArrayList(u8) = .empty;
    defer total.deinit(session.allocator);
    var buf: [4096]u8 = undefined;
    var cursor = entry.stream.start();
    while (true) {
        const n = entry.stream.readAt(cursor, &buf);
        if (n == 0) break;
        total.appendSlice(session.allocator, buf[0..n]) catch break;
        cursor += n;
    }
    var tail = total.items;
    if (tail.len > 16 * 1024) tail = tail[tail.len - 16 * 1024 ..];
    while (tail.len > 0 and (tail[tail.len - 1] == '\n' or tail[tail.len - 1] == '\r' or tail[tail.len - 1] == ' ' or tail[tail.len - 1] == '\t')) tail = tail[0 .. tail.len - 1];
    const exit = entry.stream.exit_status;
    const msg = if (exit != null and exit.? == 0) "ok" else if (tail.len > 0) tail else "probe failed";
    const out = entry.preflight_probe orelse return;
    out.set(exit, tail, msg);
}

fn drainAccessExec(session: *Session, entry: *ChannelEntry) void {
    const out = entry.access_exec_outcome orelse return;
    const cap = entry.access_exec_cap;
    var total: std.ArrayList(u8) = .empty;
    defer total.deinit(session.allocator);
    var buf: [4096]u8 = undefined;
    var cursor = entry.stream.start();
    while (true) {
        const n = entry.stream.readAt(cursor, &buf);
        if (n == 0) break;
        var tail = buf[0..n];
        // cap bytes before handing to outcome; over-cap -> limited + truncated
        if (total.items.len >= cap) break;
        if (total.items.len + tail.len > cap) tail = tail[0 .. cap - total.items.len];
        total.appendSlice(session.allocator, tail) catch break;
        cursor += n;
    }
    // strip trailing whitespace to match bridge expectation (trimmed compare elsewhere)
    var tail = total.items;
    while (tail.len > 0 and (tail[tail.len - 1] == '\n' or tail[tail.len - 1] == '\r' or tail[tail.len - 1] == ' ' or tail[tail.len - 1] == '\t')) tail = tail[0 .. tail.len - 1];
    const exit = entry.stream.exit_status;
    const msg = if (tail.len > 0) tail else if (exit != null and exit.? == 0) "ok" else "failed";
    out.set(exit, total.items, msg);
}

fn drainBackupExec(session: *Session, entry: *ChannelEntry) void {
    const outcome = entry.backup_outcome orelse return;
    var total: std.ArrayList(u8) = .empty;
    defer total.deinit(session.allocator);
    var buf: [4096]u8 = undefined;
    var cursor = entry.stream.start();
    const overflow = cursor > 0;
    while (true) {
        const n = entry.stream.readAt(cursor, &buf);
        if (n == 0) break;
        if (total.items.len + n > entry.backup_cap) {
            outcome.set(.too_large, entry.stream.exit_status, fx_unknown, true, total.items, "backup exec output exceeded its cap");
            return;
        }
        total.appendSlice(session.allocator, buf[0..n]) catch {
            outcome.set(.internal, null, fx_unknown, false, "", "out of memory capturing backup output");
            return;
        };
        cursor += n;
    }
    if (overflow) {
        outcome.set(.too_large, entry.stream.exit_status, fx_unknown, true, total.items, "backup exec output exceeded its cap");
        return;
    }
    outcome.set(.ok, entry.stream.exit_status, fx_unknown, false, total.items, if (entry.stream.exit_status == 0) "ok" else "backup command failed");
}

fn backupExecOp(
    session: *Session,
    command: []const u8,
    stdin_data: ?[]const u8,
    timeout_ns: i128,
    cap: usize,
    history_command_owned: []const u8,
    outcome: *BackupOutcome,
) void {
    const allocator = session.allocator;
    const raw = session.transport.openChannel(session.io) catch {
        allocator.free(command);
        if (stdin_data) |input| secureFreeBytes(allocator, @constCast(input));
        allocator.free(history_command_owned);
        outcome.set(.transport, null, fx_unknown, false, "", "could not open a channel for backup exec");
        return;
    };
    raw.exec(session.io, command) catch {
        raw.close(session.io);
        allocator.free(command);
        if (stdin_data) |input| secureFreeBytes(allocator, @constCast(input));
        allocator.free(history_command_owned);
        outcome.set(.transport, null, fx_unknown, false, "", "backup exec could not start");
        return;
    };
    const stream = allocator.create(Stream) catch {
        raw.close(session.io);
        allocator.free(command);
        if (stdin_data) |input| secureFreeBytes(allocator, @constCast(input));
        allocator.free(history_command_owned);
        outcome.set(.internal, null, fx_unknown, false, "", "out of memory");
        return;
    };
    stream.* = Stream.init(allocator);
    stream.max_bytes = @max(cap, 16 * 1024);
    const entry = allocator.create(ChannelEntry) catch {
        allocator.destroy(stream);
        raw.close(session.io);
        allocator.free(command);
        if (stdin_data) |input| secureFreeBytes(allocator, @constCast(input));
        allocator.free(history_command_owned);
        outcome.set(.internal, null, fx_unknown, false, "", "out of memory");
        return;
    };
    const history_kind = allocator.dupe(u8, "backup") catch {
        allocator.destroy(entry);
        allocator.destroy(stream);
        raw.close(session.io);
        allocator.free(command);
        if (stdin_data) |input| secureFreeBytes(allocator, @constCast(input));
        allocator.free(history_command_owned);
        outcome.set(.internal, null, fx_unknown, false, "", "out of memory");
        return;
    };
    entry.* = .{
        .id = session.next_channel_id.fetchAdd(1, .monotonic),
        .kind = .exec,
        .command = command,
        .history_kind = history_kind,
        .history_command = history_command_owned,
        .started_ns = std.Io.Timestamp.now(session.io, .real).nanoseconds,
        .stream = stream,
        .raw = raw,
        .stdin_queue = if (stdin_data) |input| .{ .items = @constCast(input), .capacity = input.len } else .empty,
        .stdin_eof_pending = stdin_data != null,
        .internal = true,
        .backup_outcome = outcome,
        .backup_timeout_ns = timeout_ns,
        .backup_cap = cap,
    };
    lockSpin(&session.channels_mutex);
    session.channels.append(allocator, entry) catch {
        session.channels_mutex.unlock();
        entry.clearStdin(allocator);
        entry.freeCommandText(allocator);
        allocator.destroy(entry);
        allocator.destroy(stream);
        raw.close(session.io);
        outcome.set(.internal, null, fx_unknown, false, "", "out of memory");
        return;
    };
    session.channels_mutex.unlock();
}

fn backupOutcomeCode(ok: bool, fx: i64, message: []const u8) BackupOutcomeCode {
    if (ok) return .ok;
    if (fx == ssh.c.LIBSSH2_FX_NO_SUCH_FILE) return .not_found;
    if (fx == ssh.c.LIBSSH2_FX_PERMISSION_DENIED) return .permission_denied;
    if (std.mem.indexOf(u8, message, "conflict") != null) return .conflict;
    if (std.mem.indexOf(u8, message, "timed out") != null) return .timeout;
    if (std.mem.indexOf(u8, message, "unsupported") != null) return .unsupported;
    return .transport;
}

fn backupSftpFinish(outcome: *BackupOutcome, compat: *SftpOutcome) void {
    const message = compat.msg_buf[0..compat.msg_len];
    const payload = compat.json orelse "";
    outcome.set(backupOutcomeCode(compat.ok, compat.fx, message), null, compat.fx, false, payload, message);
    if (compat.json) |json_bytes| compat.allocator.free(json_bytes);
}

fn backupRequestOp(session: *Session, request: BackupRequest, outcome: *BackupOutcome) void {
    switch (request) {
        .exec => |value| backupExecOp(session, value.command, value.stdin_data, value.timeout_ns, value.cap, value.history_command, outcome),
        else => {
            var compat = SftpOutcome{ .allocator = session.allocator };
            switch (request) {
                .sftp_stat => |value| sftpOpStat(session, value.path, &compat),
                .sftp_list => |value| sftpOpLs(session, value.path, &compat),
                .sftp_read => |value| sftpOpRead(session, value.path, 0, value.max, &compat),
                .sftp_write => |value| sftpOpSave(session, value.path, value.data, null, &compat),
                .sftp_mkdir => |value| sftpOpMkdir(session, value.path, &compat),
                .sftp_chmod => |value| sftpOpChmod(session, value.path, value.mode, &compat),
                .sftp_remove => |value| sftpOpRm(session, value.path, false, 0, &compat),
                .sftp_rename => |value| sftpOpRename(session, value.from, value.to, &compat),
                .exec => unreachable,
            }
            backupSftpFinish(outcome, &compat);
        },
    }
}

fn backupRunOp(session: *Session, command: []const u8, stdin_data: ?[]u8, process: *BackupProcess) void {
    const allocator = session.allocator;
    const raw = session.transport.openChannel(session.io) catch {
        allocator.free(command);
        if (stdin_data) |input| secureFreeBytes(allocator, input);
        process.complete(null, false, "could not open the backup process channel");
        return;
    };
    raw.exec(session.io, command) catch {
        raw.close(session.io);
        allocator.free(command);
        if (stdin_data) |input| secureFreeBytes(allocator, input);
        process.complete(null, false, "backup process could not start");
        return;
    };
    const stream = allocator.create(Stream) catch {
        raw.close(session.io);
        allocator.free(command);
        if (stdin_data) |input| secureFreeBytes(allocator, input);
        process.complete(null, false, "out of memory");
        return;
    };
    stream.* = Stream.init(allocator);
    stream.max_bytes = 4 * 1024 * 1024;
    const entry = allocator.create(ChannelEntry) catch {
        allocator.destroy(stream);
        raw.close(session.io);
        allocator.free(command);
        if (stdin_data) |input| secureFreeBytes(allocator, input);
        process.complete(null, false, "out of memory");
        return;
    };
    const history_kind = allocator.dupe(u8, "backup") catch {
        allocator.destroy(entry);
        allocator.destroy(stream);
        raw.close(session.io);
        allocator.free(command);
        if (stdin_data) |input| secureFreeBytes(allocator, input);
        process.complete(null, false, "out of memory");
        return;
    };
    const history_command = allocator.dupe(u8, "rclone backup run") catch {
        allocator.free(history_kind);
        allocator.destroy(entry);
        allocator.destroy(stream);
        raw.close(session.io);
        allocator.free(command);
        if (stdin_data) |input| secureFreeBytes(allocator, input);
        process.complete(null, false, "out of memory");
        return;
    };
    entry.* = .{
        .id = session.next_channel_id.fetchAdd(1, .monotonic),
        .kind = .exec,
        .command = command,
        .history_kind = history_kind,
        .history_command = history_command,
        .started_ns = std.Io.Timestamp.now(session.io, .real).nanoseconds,
        .stream = stream,
        .raw = raw,
        .stdin_queue = if (stdin_data) |input| .{ .items = input, .capacity = input.len } else .empty,
        .stdin_eof_pending = stdin_data != null,
        .internal = true,
        .backup_process = process,
    };
    lockSpin(&session.channels_mutex);
    session.channels.append(allocator, entry) catch {
        session.channels_mutex.unlock();
        entry.clearStdin(allocator);
        entry.freeCommandText(allocator);
        allocator.destroy(entry);
        allocator.destroy(stream);
        raw.close(session.io);
        process.complete(null, false, "out of memory");
        return;
    };
    session.channels_mutex.unlock();
}

fn accessExecOp(session: *Session, ae: anytype) void {
    const allocator = session.allocator;
    const raw = session.transport.openChannel(session.io) catch {
        allocator.free(ae.command);
        ae.outcome.set(null, "", "could not open a channel for the access exec");
        return;
    };
    raw.exec(session.io, ae.command) catch {
        raw.close(session.io);
        allocator.free(ae.command);
        ae.outcome.set(null, "", "access exec could not start");
        return;
    };
    const stream = allocator.create(Stream) catch {
        raw.close(session.io);
        allocator.free(ae.command);
        ae.outcome.set(null, "", "out of memory");
        return;
    };
    stream.* = Stream.init(allocator);
    stream.max_bytes = @max(ae.cap, 16 * 1024);
    const entry = allocator.create(ChannelEntry) catch {
        allocator.destroy(stream);
        raw.close(session.io);
        allocator.free(ae.command);
        ae.outcome.set(null, "", "out of memory");
        return;
    };
    const history_kind = allocator.dupe(u8, "access.scan") catch {
        allocator.destroy(entry);
        allocator.destroy(stream);
        raw.close(session.io);
        allocator.free(ae.command);
        ae.outcome.set(null, "", "out of memory");
        return;
    };
    const history_command = allocator.dupe(u8, ae.command) catch {
        allocator.free(history_kind);
        allocator.destroy(entry);
        allocator.destroy(stream);
        raw.close(session.io);
        allocator.free(ae.command);
        ae.outcome.set(null, "", "out of memory");
        return;
    };
    entry.* = .{
        .id = session.next_channel_id.fetchAdd(1, .monotonic),
        .kind = .exec,
        .command = ae.command,
        .history_kind = history_kind,
        .history_command = history_command,
        .stream = stream,
        .raw = raw,
        .internal = true,
        .access_exec_outcome = ae.outcome,
        .access_exec_timeout_ns = ae.timeout_ns,
        .access_exec_cap = ae.cap,
        .started_ns = std.Io.Timestamp.now(session.io, .real).nanoseconds,
    };
    lockSpin(&session.channels_mutex);
    session.channels.append(allocator, entry) catch {
        session.channels_mutex.unlock();
        entry.freeCommandText(allocator);
        allocator.destroy(entry);
        allocator.destroy(stream);
        raw.close(session.io);
        ae.outcome.set(null, "", "out of memory");
        return;
    };
    session.channels_mutex.unlock();
}

fn drainAiContext(session: *Session, entry: *ChannelEntry) void {
    const outcome = entry.ai_context_outcome orelse return;
    var total: std.ArrayList(u8) = .empty;
    defer total.deinit(session.allocator);
    var buffer: [4096]u8 = undefined;
    var cursor = entry.stream.start();
    const overflow = cursor > 0;
    while (true) {
        const count = entry.stream.readAt(cursor, &buffer);
        if (count == 0) break;
        if (total.items.len + count > entry.ai_context_cap) break;
        total.appendSlice(session.allocator, buffer[0..count]) catch {
            outcome.complete(null, "", "out of memory capturing context", false, false);
            return;
        };
        cursor += count;
    }
    const exit = entry.stream.exit_status;
    if (overflow or total.items.len > entry.ai_context_cap) {
        outcome.complete(exit, total.items, "context probe output exceeded its cap", false, false);
    } else if (exit != null and exit.? == 0) {
        outcome.complete(exit, total.items, "ok", false, false);
    } else {
        outcome.complete(exit, total.items, "context probe failed", false, false);
    }
}

fn aiContextOp(session: *Session, probe: anytype) void {
    const allocator = session.allocator;
    const raw = session.transport.openChannel(session.io) catch {
        allocator.free(probe.operation_id);
        allocator.free(probe.command);
        probe.outcome.complete(null, "", "could not open a channel for the context probe", false, false);
        return;
    };
    raw.exec(session.io, probe.command) catch {
        raw.close(session.io);
        allocator.free(probe.operation_id);
        allocator.free(probe.command);
        probe.outcome.complete(null, "", "context probe could not start", false, false);
        return;
    };
    const stream = allocator.create(Stream) catch {
        raw.close(session.io);
        allocator.free(probe.operation_id);
        allocator.free(probe.command);
        probe.outcome.complete(null, "", "out of memory", false, false);
        return;
    };
    stream.* = Stream.init(allocator);
    stream.max_bytes = probe.cap;
    const entry = allocator.create(ChannelEntry) catch {
        allocator.destroy(stream);
        raw.close(session.io);
        allocator.free(probe.operation_id);
        allocator.free(probe.command);
        probe.outcome.complete(null, "", "out of memory", false, false);
        return;
    };
    entry.* = .{
        .id = session.next_channel_id.fetchAdd(1, .monotonic),
        .kind = .exec,
        .command = probe.command,
        .stream = stream,
        .raw = raw,
        .internal = true,
        .ai_context_outcome = probe.outcome,
        .ai_context_operation_id = probe.operation_id,
        .ai_context_timeout_ns = probe.timeout_ns,
        .ai_context_cap = probe.cap,
        .started_ns = std.Io.Timestamp.now(session.io, .real).nanoseconds,
    };
    lockSpin(&session.channels_mutex);
    session.channels.append(allocator, entry) catch {
        session.channels_mutex.unlock();
        entry.freeCommandText(allocator);
        allocator.destroy(entry);
        allocator.destroy(stream);
        raw.close(session.io);
        probe.outcome.complete(null, "", "out of memory", false, false);
        return;
    };
    session.channels_mutex.unlock();
}

fn aiContextCancelOp(session: *Session, operation_id: []const u8) void {
    defer session.allocator.free(operation_id);
    var found_index: ?usize = null;
    var found_entry: ?*ChannelEntry = null;
    lockSpin(&session.channels_mutex);
    for (session.channels.items, 0..) |entry, index| {
        const current = entry.ai_context_operation_id orelse continue;
        if (std.mem.eql(u8, current, operation_id)) {
            found_index = index;
            found_entry = entry;
            break;
        }
    }
    session.channels_mutex.unlock();
    const entry = found_entry orelse return;
    entry.raw.sendEof();
    entry.raw.close(session.io);
    entry.raw_closed = true;
    if (entry.ai_context_outcome) |outcome| outcome.complete(null, "", "context refresh canceled", true, false);
    entry.ai_context_outcome = null;
    _ = dropEntryAt(session, found_index.?, entry);
}

fn preflightProbeOp(session: *Session, pp: anytype) void {
    const allocator = session.allocator;
    const raw = session.transport.openChannel(session.io) catch {
        allocator.free(pp.id);
        allocator.free(pp.command);
        pp.outcome.set(null, "", "could not open a channel for the preflight probe");
        return;
    };
    raw.exec(session.io, pp.command) catch {
        raw.close(session.io);
        allocator.free(pp.id);
        allocator.free(pp.command);
        pp.outcome.set(null, "", "preflight probe could not start");
        return;
    };
    const stream = allocator.create(Stream) catch {
        raw.close(session.io);
        allocator.free(pp.id);
        allocator.free(pp.command);
        pp.outcome.set(null, "", "out of memory");
        return;
    };
    stream.* = Stream.init(allocator);
    stream.max_bytes = 64 * 1024;
    const entry = allocator.create(ChannelEntry) catch {
        allocator.destroy(stream);
        raw.close(session.io);
        allocator.free(pp.id);
        allocator.free(pp.command);
        pp.outcome.set(null, "", "out of memory");
        return;
    };
    entry.* = .{
        .id = session.next_channel_id.fetchAdd(1, .monotonic),
        .kind = .exec,
        .command = pp.command,
        .stream = stream,
        .raw = raw,
        .internal = true,
        .preflight_probe = pp.outcome,
        .preflight_timeout_ns = pp.timeout_ns,
        .preflight_id = pp.id,
        .started_ns = std.Io.Timestamp.now(session.io, .real).nanoseconds,
    };
    lockSpin(&session.channels_mutex);
    session.channels.append(allocator, entry) catch {
        session.channels_mutex.unlock();
        entry.freeCommandText(allocator);
        if (entry.preflight_id) |pid| allocator.free(pid);
        allocator.destroy(entry);
        allocator.destroy(stream);
        raw.close(session.io);
        pp.outcome.set(null, "", "out of memory");
        return;
    };
    session.channels_mutex.unlock();
}

fn processOps(session: *Session) void {
    const allocator = session.allocator;
    while (true) {
        lockSpin(&session.ops_mutex);
        if (session.ops.items.len == 0) {
            session.ops_mutex.unlock();
            return;
        }
        const op = session.ops.orderedRemove(0);
        session.ops_mutex.unlock();
        switch (op) {
            .close => session.stop_flag.store(true, .release),
            .resize => |r| {
                if (session.shell) |shell| {
                    // A failed resize leaves the remote PTY at the wrong
                    // size, so it is surfaced as an explicit error (spec
                    // 02 §5) rather than silently ignored.
                    shell.raw.resizePty(session.io, r.cols, r.rows) catch {
                        session.status.store(.@"error", .release);
                        session.setError("PTY resize failed");
                    };
                }
            },
            .close_channel => |cc| {
                lockSpin(&session.channels_mutex);
                var found: ?usize = null;
                for (session.channels.items, 0..) |e, i| {
                    if (e.id == cc.id) {
                        found = i;
                        break;
                    }
                }
                const i = found orelse {
                    session.channels_mutex.unlock();
                    continue;
                };
                const entry = session.channels.items[i];
                if (entry.kind == .shell) {
                    session.channels_mutex.unlock();
                    continue;
                }
                _ = session.channels.orderedRemove(i);
                session.channels_mutex.unlock();

                if (!entry.raw_closed) {
                    entry.raw.sendEof();
                    entry.raw.close(session.io);
                }
                entry.clearStdin(allocator);
                entry.freeCommandText(allocator);
                entry.stream.deinit(allocator);
                allocator.destroy(entry.stream);
                allocator.destroy(entry);
            },
            .exec => |e| tryOpenChannel(session, e.id, .exec, e.command, e.stdin_data, e.history_kind, e.history_command, e.history_command_redacted, e.history_secrets, e.history_operation_id, e.ai_execution),
            .follow => |f| tryOpenChannel(session, f.id, .log, f.command, null, null, null, false, null, null, false),
            .clear => |cl| clearLogFile(session, cl.path, cl.expected, cl.outcome),
            .sftp_ls => |so| sftpOpLs(session, so.path, so.outcome),
            .sftp_stat => |so| sftpOpStat(session, so.path, so.outcome),
            .sftp_read => |so| sftpOpRead(session, so.path, so.offset, so.max, so.outcome),
            .sftp_write_chunk => |so| sftpOpWriteChunk(session, so.path, so.offset, so.data, so.total, so.transfer_id, so.outcome),
            .sftp_save => |so| sftpOpSave(session, so.path, so.data, so.expected, so.outcome),
            .sftp_mkdir => |so| sftpOpMkdir(session, so.path, so.outcome),
            .sftp_rm => |so| sftpOpRm(session, so.path, so.recursive, so.transfer_id, so.outcome),
            .sftp_rename => |so| sftpOpRename(session, so.from, so.to, so.outcome),
            .sftp_chmod => |so| sftpOpChmod(session, so.path, so.mode, so.outcome),
            .sftp_download => |so| sftpOpDownload(session, so.remote, so.local_partial, so.local_final, so.transfer_id, so.outcome),
            .sftp_upload_local => |so| sftpOpUploadLocal(session, so.local, so.remote, so.transfer_id),
            .sftp_unzip => |so| sftpOpUnzip(session, so.zip_path, so.dest, so.transfer_id, so.outcome),
            .sftp_zip_download => |so| sftpOpZipDownload(session, so.paths, so.local_partial, so.local_final, so.transfer_id, so.outcome),
            .sftp_cancel => |so| sftpOpCancel(session, so.transfer_id),
            .tunnel_start => |t| tunnelStartOp(session, t),
            .tunnel_stop => |s| tunnelStopOp(session, s),
            .jump_start => |j| jumpStartOp(session, j),
            .forward_set => |f| forwardSetOp(session, f),
            .syntax_check => |sc| syntaxCheckOp(session, sc),
            .preflight_probe => |pp| preflightProbeOp(session, pp),
            .access_exec => |ae| accessExecOp(session, ae),
            .ai_context => |probe| aiContextOp(session, probe),
            .ai_context_cancel => |cancel| aiContextCancelOp(session, cancel.operation_id),
            .backup => |value| backupRequestOp(session, value.request, value.outcome),
            .backup_run => |value| backupRunOp(session, value.command, value.stdin_data, value.process),
        }
    }
}

/// Advances stdin for non-interactive exec channels without blocking the
/// worker. This lets libssh2 service EAGAIN between writes and preserves the
/// channel long enough to collect remote diagnostics on an early exit.
fn driveExecStdin(session: *Session) void {
    lockSpin(&session.channels_mutex);
    defer session.channels_mutex.unlock();
    for (session.channels.items) |entry| {
        if (!entry.stdin_eof_pending or entry.raw_closed) continue;
        if (entry.stdin_queue.items.len > 0) {
            const old_len = entry.stdin_queue.items.len;
            const written = entry.raw.write(entry.stdin_queue.items);
            if (written > 0) {
                std.mem.copyForwards(u8, entry.stdin_queue.items[0 .. old_len - written], entry.stdin_queue.items[written..old_len]);
                std.crypto.secureZero(u8, entry.stdin_queue.items[old_len - written .. old_len]);
                entry.stdin_queue.items.len -= written;
            }
        }
        if (entry.stdin_queue.items.len == 0 and entry.raw.trySendEof()) entry.clearStdin(session.allocator);
    }
}

/// Binds the loopback listener and opens the direct-tcpip channel.
/// Owns `t.token`/`t.host` on every path (the Tunnel takes them over on
/// success).
fn tunnelStartOp(session: *Session, t: anytype) void {
    const allocator = session.allocator;
    const now = std.Io.Timestamp.now(session.io, .real).nanoseconds;
    const addr = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch {
        allocator.free(t.token);
        allocator.free(t.host);
        t.outcome.set(false, 0, "could not bind the local listener");
        return;
    };
    var listener = std.Io.net.IpAddress.listen(&addr, session.io, .{ .mode = .stream, .protocol = .tcp, .reuse_address = true }) catch {
        allocator.free(t.token);
        allocator.free(t.host);
        t.outcome.set(false, 0, "could not bind the local listener");
        return;
    };
    const ws_port = listener.socket.address.getPort();
    const raw = session.transport.openTunnel(session.io, t.host, t.port) catch {
        listener.deinit(session.io);
        allocator.free(t.token);
        allocator.free(t.host);
        t.outcome.set(false, 0, "could not open the SSH tunnel to the VNC port");
        return;
    };
    const tunnel = allocator.create(Tunnel) catch {
        raw.close(session.io);
        listener.deinit(session.io);
        allocator.free(t.token);
        allocator.free(t.host);
        t.outcome.set(false, 0, "out of memory");
        return;
    };
    tunnel.* = .{
        .id = t.id,
        .token = t.token,
        .host = t.host,
        .port = t.port,
        .listener = listener,
        .raw = raw,
        .created_at_ns = now,
        .last_activity_ns = now,
    };
    lockSpin(&session.tunnels_mutex);
    session.tunnels.append(session.allocator, tunnel) catch {
        session.tunnels_mutex.unlock();
        tunnel.deinit(session.allocator, session.io);
        allocator.destroy(tunnel);
        t.outcome.set(false, 0, "out of memory");
        return;
    };
    session.tunnels_mutex.unlock();
    t.outcome.set(true, ws_port, "");
}

/// Marks the tunnel for teardown (the run loop removes it). Idempotent.
fn tunnelStopOp(session: *Session, s: anytype) void {
    lockSpin(&session.tunnels_mutex);
    defer session.tunnels_mutex.unlock();
    for (session.tunnels.items) |t| {
        if (t.id == s.id and t.state != .closed) {
            t.setError("stopped");
            t.state = .closing;
            return;
        }
    }
}

/// Spec 18: opens the direct-tcpip channel to the target on this (via)
/// session and registers the jump tunnel. Owns `j.host` and
/// `j.target_server_id` on every path; the fd is closed on failure.
fn jumpStartOp(session: *Session, j: anytype) void {
    const allocator = session.allocator;
    const raw = session.transport.openTunnel(session.io, j.host, j.port) catch {
        allocator.free(j.host);
        allocator.free(j.target_server_id);
        _ = ssh.c.close(j.fd);
        j.outcome.set(false, "could not open the SSH tunnel to the target");
        return;
    };
    allocator.free(j.host);
    const tunnel = allocator.create(JumpTunnel) catch {
        raw.close(session.io);
        allocator.free(j.target_server_id);
        _ = ssh.c.close(j.fd);
        j.outcome.set(false, "out of memory");
        return;
    };
    tunnel.* = .{
        .channel = raw,
        .fd = j.fd,
        .target_server_id = j.target_server_id,
    };
    lockSpin(&session.tunnels_mutex);
    session.jump_tunnels.append(allocator, tunnel) catch {
        session.tunnels_mutex.unlock();
        tunnel.deinit(allocator, session.io);
        allocator.destroy(tunnel);
        j.outcome.set(false, "out of memory");
        return;
    };
    session.tunnels_mutex.unlock();
    j.outcome.set(true, "");
}

/// One pass over every jump tunnel (spec 18): pump the channel ↔ local
/// fd in both directions with bounded frames; remove dead tunnels and
/// cascade a clear close state to the target session.
fn processJumpTunnels(session: *Session, io: std.Io) void {
    const allocator = session.allocator;
    var i: usize = 0;
    while (true) {
        lockSpin(&session.tunnels_mutex);
        if (i >= session.jump_tunnels.items.len) {
            session.tunnels_mutex.unlock();
            return;
        }
        const jt = session.jump_tunnels.items[i];
        session.tunnels_mutex.unlock();

        var remove = false;
        var buf: [16 * 1024]u8 = undefined;
        // Drain pending sends first. The socketpair is non-blocking, but
        // poll-gating is still required: it makes the no-stall contract
        // independent of platform fcntl behavior and avoids entering a
        // blocking libc write when the peer has applied backpressure.
        if (jt.to_fd_buf.items.len > 0) {
            var write_fds = [_]std.posix.pollfd{.{ .fd = jt.fd, .events = std.posix.POLL.OUT, .revents = 0 }};
            const ready = std.posix.poll(&write_fds, 0) catch 0;
            if (ready > 0) {
                const revents = write_fds[0].revents;
                if (revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL) != 0) {
                    remove = true;
                } else if (revents & std.posix.POLL.OUT != 0) {
                    const w = socketWriteNoSigpipe(jt.fd, jt.to_fd_buf.items);
                    if (w < 0) {
                        if (std.posix.errno(w) != .AGAIN) remove = true;
                    } else if (w > 0) {
                        const n: usize = @intCast(w);
                        jt.bytes_down += n;
                        std.mem.copyForwards(u8, jt.to_fd_buf.items[0 .. jt.to_fd_buf.items.len - n], jt.to_fd_buf.items[n..]);
                        jt.to_fd_buf.items.len -= n;
                    }
                }
            }
        }
        if (!remove and jt.to_channel_buf.items.len > 0) {
            const w = jt.channel.write(jt.to_channel_buf.items);
            if (w > 0) {
                jt.bytes_up += w;
                std.mem.copyForwards(u8, jt.to_channel_buf.items[0 .. jt.to_channel_buf.items.len - w], jt.to_channel_buf.items[w..]);
                jt.to_channel_buf.items.len -= w;
            }
        }
        // channel → to_fd_buf (only while the buffer has room — a full
        // buffer backpressures instead of blocking or dropping bytes).
        if (!remove and jt.to_fd_buf.items.len < jump_frame_cap) {
            switch (jt.channel.readOpenStream(&buf)) {
                .eof => remove = true,
                .again => {},
                .data => |n| {
                    jt.to_fd_buf.appendSlice(allocator, buf[0..n]) catch {};
                },
            }
        }
        // fd → to_channel_buf. Poll before the read so a failed or ignored
        // O_NONBLOCK setup cannot freeze the via worker. A readable zero-byte
        // result is EOF; HUP is drained first when POLLIN is also present.
        if (!remove and jt.to_channel_buf.items.len < jump_frame_cap) {
            var read_fds = [_]std.posix.pollfd{.{ .fd = jt.fd, .events = std.posix.POLL.IN, .revents = 0 }};
            const ready = std.posix.poll(&read_fds, 0) catch 0;
            if (ready > 0) {
                const revents = read_fds[0].revents;
                if (revents & (std.posix.POLL.ERR | std.posix.POLL.NVAL) != 0) {
                    remove = true;
                } else if (revents & std.posix.POLL.IN != 0) {
                    const n = std.posix.read(jt.fd, &buf) catch |err| blk: {
                        if (err != error.WouldBlock) remove = true;
                        break :blk 0;
                    };
                    if (n == 0) {
                        if (!remove) remove = true;
                    } else {
                        jt.to_channel_buf.appendSlice(allocator, buf[0..n]) catch {};
                    }
                } else if (revents & std.posix.POLL.HUP != 0) {
                    remove = true;
                }
            }
        }
        if (remove) {
            // Cascade: the target session gets a clear close state.
            const target_id = jt.target_server_id;
            if (session.owner.get(target_id)) |target| {
                if (target.status.load(.acquire) == .ready) {
                    target.status.store(.@"error", .release);
                    var msg_buf: [256]u8 = undefined;
                    target.setError(std.fmt.bufPrint(&msg_buf, "jump host {s} disconnected", .{session.server.name}) catch "jump host disconnected");
                }
            }
            lockSpin(&session.tunnels_mutex);
            _ = session.jump_tunnels.orderedRemove(i);
            session.tunnels_mutex.unlock();
            jt.deinit(allocator, io);
            allocator.destroy(jt);
            // Re-examine the new element at i.
            continue;
        }
        i += 1;
    }
}

// --- tunnel run-loop processing (spec 12 §6) ------------------------------

/// Marks the tunnel for teardown with an error; the run loop removes it.
fn tunnelFail(session: *Session, t: *Tunnel, msg: []const u8) void {
    lockSpin(&session.tunnels_mutex);
    t.setError(msg);
    t.state = .closing;
    session.tunnels_mutex.unlock();
}

/// Closes the tunnel's listener, WebSocket, and SSH channel. Runs at the
/// terminal transition: the record lives on as a tombstone (see
/// `tunnel_tombstone_ns`), so `deinit` skips the fds once released.
fn tunnelReleaseResources(t: *Tunnel, io: std.Io) void {
    t.listener.deinit(io);
    if (t.ws) |*ws| ws.close(io);
    if (t.raw) |raw| raw.close(io);
    t.ws = null;
    t.raw = null;
    t.resources_released = true;
}

/// The terminal transition: state `.closed` plus the tombstone clock.
fn tunnelMarkClosed(session: *Session, t: *Tunnel, now_ns: i128) void {
    lockSpin(&session.tunnels_mutex);
    t.state = .closed;
    t.closed_at_ns = now_ns;
    session.tunnels_mutex.unlock();
}

fn tunnelSetState(session: *Session, t: *Tunnel, state: TunnelState) void {
    lockSpin(&session.tunnels_mutex);
    t.state = state;
    session.tunnels_mutex.unlock();
}

fn tunnelTouch(session: *Session, t: *Tunnel, now_ns: i128) void {
    lockSpin(&session.tunnels_mutex);
    t.last_activity_ns = now_ns;
    session.tunnels_mutex.unlock();
}

fn tunnelAddUp(session: *Session, t: *Tunnel, n: u64) void {
    lockSpin(&session.tunnels_mutex);
    t.bytes_up += n;
    session.tunnels_mutex.unlock();
}

fn tunnelAddDown(session: *Session, t: *Tunnel, n: u64) void {
    lockSpin(&session.tunnels_mutex);
    t.bytes_down += n;
    session.tunnels_mutex.unlock();
}

const WsRead = union(enum) { none, data: usize, closed };

/// Poll-then-read on the WS socket: the socket stays blocking (no fcntl
/// on this platform), so readiness is checked first and the read never
/// blocks the worker loop.
fn tunnelReadWs(t: *Tunnel, buf: []u8) WsRead {
    const fd = t.ws.?.socket.handle;
    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const ready = std.posix.poll(&fds, 0) catch return .none;
    if (ready == 0) return .none;
    if (fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL) != 0) return .closed;
    if (fds[0].revents & std.posix.POLL.IN == 0) return .none;
    const n = std.posix.read(fd, buf) catch |err| switch (err) {
        error.ConnectionResetByPeer => return .closed,
        else => return .none,
    };
    if (n == 0) return .closed;
    return .{ .data = n };
}

/// Flushes the outbound buffer (handshake response + frames) to the WS
/// socket, POLLOUT-gated, ≤ 16 KB per write.
fn tunnelFlushWs(t: *Tunnel) usize {
    const fd = t.ws.?.socket.handle;
    var total: usize = 0;
    while (t.send_buf.items.len > 0) {
        var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 }};
        const ready = std.posix.poll(&fds, 0) catch return total;
        if (ready == 0 or fds[0].revents & std.posix.POLL.OUT == 0) return total;
        const chunk = t.send_buf.items[0..@min(t.send_buf.items.len, 16 * 1024)];
        const rc = socketWriteNoSigpipe(fd, chunk);
        if (rc <= 0) return total; // EAGAIN or error — retain the buffer
        const n: usize = @intCast(rc);
        std.mem.copyForwards(u8, t.send_buf.items[0 .. t.send_buf.items.len - n], t.send_buf.items[n..]);
        t.send_buf.items.len -= n;
        total += n;
    }
    return total;
}

fn tunnelQueueFrame(t: *Tunnel, allocator: std.mem.Allocator, opcode: wsmod.Opcode, payload: []const u8) void {
    var header_buf: [14]u8 = undefined;
    const header = wsmod.encodeFrame(&header_buf, opcode, payload.len, true);
    t.send_buf.appendSlice(allocator, header_buf[0..header]) catch {};
    t.send_buf.appendSlice(allocator, payload) catch {};
}

fn tunnelQueueClose(t: *Tunnel, allocator: std.mem.Allocator, code: wsmod.CloseCode, reason: []const u8) void {
    var frame_buf: [160]u8 = undefined;
    if (2 + 2 + reason.len > frame_buf.len) return;
    const n = wsmod.encodeCloseFrame(&frame_buf, code, reason);
    t.send_buf.appendSlice(allocator, frame_buf[0..n]) catch {};
}

const tunnel_ws_chunk: usize = 32 * 1024;

/// Consumes complete client frames from recv_buf: binary payloads flow
/// to the SSH channel, ping gets pong, close is echoed, text closes 1003.
fn tunnelDriveFrames(session: *Session, t: *Tunnel, now_ns: i128) void {
    const allocator = session.allocator;
    while (true) {
        const parsed = wsmod.parseFrame(t.recv_buf.items, true) catch |err| {
            tunnelQueueClose(t, allocator, if (err == error.TooBig) .too_big else .protocol_error, "protocol error");
            tunnelSetState(session, t, .closing);
            return;
        };
        switch (parsed) {
            .need_more => return,
            .frame => |f| {
                const frame_len = f.payload_offset + f.payload.len;
                // Unmask in place, then dispatch.
                wsmod.unmask(t.recv_buf.items[f.payload_offset .. f.payload_offset + f.payload.len], f.mask);
                const payload = t.recv_buf.items[f.payload_offset .. f.payload_offset + f.payload.len];
                switch (f.opcode) {
                    .binary => {
                        if (f.fin) {
                            if (t.to_channel.items.len + payload.len > wsmod.max_connection_buffer) {
                                tunnelQueueClose(t, allocator, .too_big, "buffer exceeded");
                                tunnelSetState(session, t, .closing);
                                return;
                            }
                            t.to_channel.appendSlice(allocator, payload) catch {};
                        } else {
                            if (t.msg_buf.items.len != 0) {
                                tunnelQueueClose(t, allocator, .protocol_error, "new message during reassembly");
                                tunnelSetState(session, t, .closing);
                                return;
                            }
                            if (payload.len > wsmod.max_frame_bytes) {
                                tunnelQueueClose(t, allocator, .too_big, "frame too big");
                                tunnelSetState(session, t, .closing);
                                return;
                            }
                            t.msg_buf.appendSlice(allocator, payload) catch {};
                        }
                    },
                    .continuation => {
                        if (t.msg_buf.items.len + payload.len > wsmod.max_frame_bytes) {
                            tunnelQueueClose(t, allocator, .too_big, "message too big");
                            tunnelSetState(session, t, .closing);
                            return;
                        }
                        t.msg_buf.appendSlice(allocator, payload) catch {};
                        if (f.fin) {
                            if (t.to_channel.items.len + t.msg_buf.items.len > wsmod.max_connection_buffer) {
                                tunnelQueueClose(t, allocator, .too_big, "buffer exceeded");
                                tunnelSetState(session, t, .closing);
                                return;
                            }
                            t.to_channel.appendSlice(allocator, t.msg_buf.items) catch {};
                            t.msg_buf.clearRetainingCapacity();
                        }
                    },
                    .text => {
                        // Not part of this VNC bridge (spec 12 §6).
                        tunnelQueueClose(t, allocator, .unsupported_data, "text is not supported");
                        tunnelSetState(session, t, .closing);
                        return;
                    },
                    .ping => {
                        tunnelQueueFrame(t, allocator, .pong, payload);
                    },
                    .pong => {},
                    .close => {
                        tunnelQueueClose(t, allocator, .normal, "");
                        tunnelSetState(session, t, .closing);
                        return;
                    },
                }
                tunnelTouch(session, t, now_ns);
                std.mem.copyForwards(u8, t.recv_buf.items[0 .. t.recv_buf.items.len - frame_len], t.recv_buf.items[frame_len..]);
                t.recv_buf.items.len -= frame_len;
            },
        }
    }
}

/// Opens the interactive shell channel (spec 02). With agent forwarding
/// enabled (spec 18) the auth-agent request is made before the pty, per
/// the libssh2 forwarding flow; a server refusal closes the channel,
/// rolls the toggle back off, and reports (the session stays usable).
/// Returns false after setting the session error; `.ready` is set by the
/// caller (workerMain only — the toggle reopens an already-ready session).
fn openShellChannel(session: *Session, io: std.Io) bool {
    const allocator = session.allocator;
    session.history_full.store(false, .release);
    session.shell_command_len = 0;
    session.shell_started_ns = 0;
    session.shell_parser = null;
    const raw_shell = session.transport.openChannel(io) catch {
        session.status.store(.@"error", .release);
        session.setError("failed to open shell channel");
        return false;
    };
    if (session.forwarding.load(.acquire)) {
        raw_shell.requestAuthAgent(io) catch {
            raw_shell.close(io);
            session.forwarding.store(false, .release);
            session.status.store(.@"error", .release);
            session.setError("agent forwarding refused (server policy or unsupported)");
            return false;
        };
    }
    raw_shell.requestPty(io, 120, 32) catch {};
    raw_shell.setEnv(io, "TERM", "xterm-256color") catch {};
    const started = if (session.server.history_shell == .off) raw_shell.shell(io) else blk: {
        var random: [16]u8 = undefined;
        std.Io.random(io, &random);
        const nonce = std.fmt.bytesToHex(random, .lower);
        session.shell_parser = shell_integration.Parser.init(nonce);
        const shell_name = @tagName(session.server.history_shell);
        const launch = if (session.server.history_shell == .bash)
            std.fmt.allocPrint(allocator, "exec env OARS_HISTORY_NONCE={s} bash --rcfile \"$HOME/.config/oars/shell/v1/bash-start.sh\" -i", .{nonce})
        else
            std.fmt.allocPrint(allocator, "exec env OARS_HISTORY_NONCE={s} {s} -il", .{ nonce, shell_name });
        const command = launch catch break :blk error.OutOfMemory;
        defer allocator.free(command);
        break :blk raw_shell.exec(io, command);
    };
    started catch {
        raw_shell.close(io);
        session.status.store(.@"error", .release);
        session.setError("failed to start shell");
        return false;
    };
    const shell_stream = allocator.create(Stream) catch {
        raw_shell.close(io);
        return false;
    };
    shell_stream.* = Stream.init(allocator);
    const shell_entry = allocator.create(ChannelEntry) catch {
        raw_shell.close(io);
        allocator.destroy(shell_stream);
        return false;
    };
    shell_entry.* = .{ .id = session.shell_channel_id, .kind = .shell, .stream = shell_stream, .raw = raw_shell };
    lockSpin(&session.channels_mutex);
    session.channels.append(allocator, shell_entry) catch {
        session.channels_mutex.unlock();
        allocator.destroy(shell_entry);
        allocator.destroy(shell_stream);
        return false;
    };
    session.shell = shell_entry;
    session.channels_mutex.unlock();
    return true;
}

/// Closes the interactive shell channel (used by the forwarding toggle,
/// which reopens it). Safe when no shell exists.
fn closeShellChannel(session: *Session) void {
    lockSpin(&session.channels_mutex);
    var i: usize = 0;
    while (i < session.channels.items.len) {
        const entry = session.channels.items[i];
        if (entry.kind == .shell) {
            if (!entry.raw_closed) entry.raw.close(session.io);
            entry.clearStdin(session.allocator);
            entry.freeCommandText(session.allocator);
            entry.stream.deinit(session.allocator);
            session.allocator.destroy(entry.stream);
            session.allocator.destroy(entry);
            _ = session.channels.orderedRemove(i);
            continue;
        }
        i += 1;
    }
    session.shell = null;
    session.channels_mutex.unlock();
}

/// Spec 18: the agent-forwarding toggle — resolve + validate the agent
/// socket once, register the auth-agent callback, and reopen the shell
/// with (or without) the request.
fn closeForwardTunnels(session: *Session) void {
    // Channel.close owns the channel allocation. Release the queue lock before
    // closing channels because libssh2 close calls may process incoming packets.
    lockSpin(&session.forward_mutex);
    var queued = session.forward_queue;
    session.forward_queue = .empty;
    var active = session.forward_active;
    session.forward_active = .empty;
    session.forward_mutex.unlock();
    defer queued.deinit(session.allocator);
    defer active.deinit(session.allocator);
    for (queued.items) |channel| channel.close(session.io);
    for (active.items) |tunnel| {
        _ = ssh.c.close(tunnel.agent_fd);
        tunnel.channel.close(session.io);
        tunnel.to_socket_buf.deinit(session.allocator);
        tunnel.to_channel_buf.deinit(session.allocator);
        session.allocator.destroy(tunnel);
    }
}

fn forwardSetOp(session: *Session, f: anytype) void {
    if (session.forwarding.load(.acquire) == f.on) {
        f.outcome.set(true, "");
        return;
    }
    // Validate before closing a working shell. A missing agent must leave it usable.
    const path: ?[]const u8 = if (f.on) blk: {
        const resolved = agent.resolveSocket(session.allocator, null) catch {
            f.outcome.set(false, "no SSH agent — start ssh-agent or set SSH_AUTH_SOCK");
            return;
        };
        agent.validateSocket(resolved) catch {
            session.allocator.free(resolved);
            f.outcome.set(false, "the agent socket is missing, not a socket, or not owned by the current user");
            return;
        };
        break :blk resolved;
    } else null;
    closeShellChannel(session);
    closeForwardTunnels(session);
    // A replacement shell has a new cursor namespace for every mirrored tab.
    session.shell_channel_id = session.next_channel_id.fetchAdd(1, .monotonic);
    session.forwarding.store(f.on, .release);
    if (session.forward_agent_path) |old_path| session.allocator.free(old_path);
    session.forward_agent_path = path;
    session.transport.setAbstract(@ptrCast(session));
    // OpenSSH can retain its per-connection agent listener after shell replacement.
    // Keep accepting-and-closing requests while off; never connect them to a local agent.
    session.transport.setAuthAgentCallback(authAgentCallback);
    if (!openShellChannel(session, session.io)) {
        session.forwarding.store(false, .release);
        session.transport.setAuthAgentCallback(authAgentCallback);
        if (session.forward_agent_path) |old_path| session.allocator.free(old_path);
        session.forward_agent_path = null;
        // Restore a normal shell after forwarding refusal where possible.
        if (openShellChannel(session, session.io)) session.status.store(.ready, .release);
        f.outcome.set(false, "could not enable agent forwarding; check the server's AllowAgentForwarding policy and reconnect if needed");
        return;
    }
    f.outcome.set(true, "");
}

/// Spec 18: libssh2's auth-agent callback — the library has already
/// confirmed the incoming channel; queue it for the worker's proxy pump.
fn authAgentCallback(session_raw: ?*ssh.c.LIBSSH2_SESSION, channel: ?*ssh.c.LIBSSH2_CHANNEL, abstract: ?*?*anyopaque) callconv(.c) void {
    _ = session_raw;
    const session_ptr: *Session = @ptrCast(@alignCast(abstract.?.* orelse return));
    const ch = channel orelse return;
    const wrapped = session_ptr.allocator.create(ssh.Channel) catch return;
    wrapped.* = .{ .raw = ch, .allocator = session_ptr.allocator };
    lockSpin(&session_ptr.forward_mutex);
    session_ptr.forward_queue.append(session_ptr.allocator, wrapped) catch {
        session_ptr.forward_mutex.unlock();
        session_ptr.allocator.destroy(wrapped);
        return;
    };
    session_ptr.forward_mutex.unlock();
}

/// Connects to the validated local agent socket for one proxy tunnel.
fn connectAgentSocket(session: *Session) !std.posix.socket_t {
    if (!session.forwarding.load(.acquire)) return error.NoAgent;
    const path = session.forward_agent_path orelse return error.NoAgent;
    const fd = ssh.c.socket(ssh.c.AF_UNIX, ssh.c.SOCK_STREAM, 0);
    if (fd < 0) return error.ConnectionFailed;
    errdefer _ = ssh.c.close(fd);
    // Non-blocking from the start (a blocking connect or write would freeze
    // the via worker's run loop); writes suppress SIGPIPE per platform.
    try configureNonBlockingSocket(fd);
    var addr: ssh.c.sockaddr_un = .{};
    addr.sun_family = ssh.c.AF_UNIX;
    if (@hasField(@TypeOf(addr), "sun_len")) {
        addr.sun_len = @intCast(@sizeOf(@TypeOf(addr.sun_len)) + @sizeOf(@TypeOf(addr.sun_family)) + path.len + 1);
    }
    @memcpy(@as([*]u8, @ptrCast(&addr.sun_path))[0..path.len], path[0..path.len]);
    const addr_len: c_uint = @intCast(@offsetOf(ssh.c.sockaddr_un, "sun_path") + path.len + 1);
    const connect_rc = ssh.c.connect(fd, @ptrCast(&addr), addr_len);
    if (connect_rc != 0) {
        switch (std.posix.errno(connect_rc)) {
            .AGAIN, .INPROGRESS => {
                // Non-blocking connect: wait for writability, then verify.
                var pfd = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 }};
                const ready = std.posix.poll(&pfd, 2000) catch return error.ConnectionFailed;
                if (ready == 0) return error.ConnectionFailed;
                var so_error: c_int = 0;
                var so_len: std.posix.socklen_t = @sizeOf(c_int);
                if (ssh.c.getsockopt(fd, ssh.c.SOL_SOCKET, ssh.c.SO_ERROR, &so_error, &so_len) != 0 or so_error != 0) return error.ConnectionFailed;
            },
            else => return error.ConnectionFailed,
        }
    }
    return fd;
}

/// One pass over the forwarding proxy (spec 18): move queued accepted
/// channels into the active pump (each with a fresh agent-socket
/// connection) and move bounded frames both ways.
fn processForwardChannels(session: *Session, io: std.Io) void {
    const allocator = session.allocator;
    while (true) {
        lockSpin(&session.forward_mutex);
        if (session.forward_queue.items.len == 0) {
            session.forward_mutex.unlock();
            break;
        }
        const ch = session.forward_queue.orderedRemove(0);
        session.forward_mutex.unlock();
        const agent_fd = connectAgentSocket(session) catch {
            ch.close(io);
            continue;
        };
        const ft = allocator.create(ForwardTunnel) catch {
            _ = ssh.c.close(agent_fd);
            ch.close(io);
            continue;
        };
        ft.* = .{ .channel = ch, .agent_fd = agent_fd };
        lockSpin(&session.forward_mutex);
        session.forward_active.append(allocator, ft) catch {
            session.forward_mutex.unlock();
            _ = ssh.c.close(agent_fd);
            ch.close(io);
            allocator.destroy(ft);
            continue;
        };
        session.forward_mutex.unlock();
    }
    var i: usize = 0;
    while (true) {
        lockSpin(&session.forward_mutex);
        if (i >= session.forward_active.items.len) {
            session.forward_mutex.unlock();
            return;
        }
        const ft = session.forward_active.items[i];
        session.forward_mutex.unlock();
        var remove = false;
        var buf: [16 * 1024]u8 = undefined;
        // Drain pending sends first (non-blocking; leftovers stay
        // buffered for the next pass, so no bytes are dropped and the
        // worker loop never stalls).
        if (ft.to_socket_buf.items.len > 0) {
            const w = socketWriteNoSigpipe(ft.agent_fd, ft.to_socket_buf.items);
            if (w < 0) {
                if (std.posix.errno(w) != .AGAIN) remove = true;
            } else if (w > 0) {
                const n: usize = @intCast(w);
                std.mem.copyForwards(u8, ft.to_socket_buf.items[0 .. ft.to_socket_buf.items.len - n], ft.to_socket_buf.items[n..]);
                ft.to_socket_buf.items.len -= n;
            }
        }
        if (!remove and ft.to_channel_buf.items.len > 0) {
            const w = ft.channel.write(ft.to_channel_buf.items);
            if (w > 0) {
                std.mem.copyForwards(u8, ft.to_channel_buf.items[0 .. ft.to_channel_buf.items.len - w], ft.to_channel_buf.items[w..]);
                ft.to_channel_buf.items.len -= w;
            }
        }
        // channel → to_socket_buf (backpressures when the buffer is full).
        if (!remove and ft.to_socket_buf.items.len < jump_frame_cap) {
            switch (ft.channel.readOpenStream(&buf)) {
                .eof => remove = true,
                .again => {},
                .data => |n| {
                    ft.to_socket_buf.appendSlice(allocator, buf[0..n]) catch {};
                },
            }
        }
        // socket → to_channel_buf (non-blocking; EAGAIN is quiet).
        if (!remove and ft.to_channel_buf.items.len < jump_frame_cap) {
            const n = ssh.c.read(ft.agent_fd, &buf, buf.len);
            if (n > 0) {
                ft.to_channel_buf.appendSlice(allocator, buf[0..@intCast(n)]) catch {
                    remove = true;
                };
            } else if (n == 0) {
                remove = true;
            } else if (std.posix.errno(n) != .AGAIN and std.posix.errno(n) != .INTR) {
                remove = true;
            }
        }
        if (remove) {
            lockSpin(&session.forward_mutex);
            _ = session.forward_active.orderedRemove(i);
            session.forward_mutex.unlock();
            _ = ssh.c.close(ft.agent_fd);
            const ch = ft.channel;
            ch.close(io);
            ft.to_socket_buf.deinit(allocator);
            ft.to_channel_buf.deinit(allocator);
            allocator.destroy(ft);
            continue;
        }
        i += 1;
    }
}

/// One pass over every tunnel (spec 12 §6): accept (≤ 1 per pass),
/// drive the WS handshake, pump frames both ways, enforce the 15 s idle
/// timeout, and remove closed tunnels.
fn processTunnels(session: *Session, io: std.Io, now_ns: i128) void {
    const allocator = session.allocator;
    var i: usize = 0;
    while (true) {
        lockSpin(&session.tunnels_mutex);
        if (i >= session.tunnels.items.len) {
            session.tunnels_mutex.unlock();
            return;
        }
        const tunnel = session.tunnels.items[i];
        const state = tunnel.state;
        session.tunnels_mutex.unlock();

        var remove = false;
        switch (state) {
            .listening => {
                if (now_ns - tunnel.created_at_ns >= tunnel_idle_timeout_ns) {
                    tunnelFail(session, tunnel, "no WebSocket connection arrived");
                    continue;
                }
                var fds = [_]std.posix.pollfd{.{ .fd = tunnel.listener.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
                const ready = std.posix.poll(&fds, 0) catch 0;
                if (ready == 0 or fds[0].revents & (std.posix.POLL.IN | std.posix.POLL.ERR | std.posix.POLL.HUP) == 0) continue;
                const ws = tunnel.listener.accept(io) catch continue;
                tunnel.ws = ws;
                tunnelSetState(session, tunnel, .handshake);
                tunnelTouch(session, tunnel, now_ns);
            },
            .handshake => {
                if (now_ns - tunnel.created_at_ns >= tunnel_idle_timeout_ns) {
                    tunnelFail(session, tunnel, "WebSocket handshake timed out");
                    continue;
                }
                var chunk: [tunnel_ws_chunk]u8 = undefined;
                switch (tunnelReadWs(tunnel, &chunk)) {
                    .closed => {
                        tunnelFail(session, tunnel, "client disconnected during the handshake");
                        continue;
                    },
                    .none => {},
                    .data => |n| {
                        if (tunnel.handshake_buf.items.len + n > wsmod.max_handshake_bytes) {
                            tunnelFail(session, tunnel, "handshake headers too large");
                            continue;
                        }
                        tunnel.handshake_buf.appendSlice(allocator, chunk[0..n]) catch {};
                        tunnelTouch(session, tunnel, now_ns);
                    },
                }
                if (std.mem.indexOf(u8, tunnel.handshake_buf.items, "\r\n\r\n") == null) continue;
                const parsed = wsmod.parseHandshake(tunnel.handshake_buf.items, tunnel.token) catch |err| {
                    tunnelFail(session, tunnel, handshakeErrorText(err));
                    continue;
                };
                var accept_buf: [28]u8 = undefined;
                const accept = wsmod.acceptKey(parsed.key, &accept_buf);
                var resp_buf: [256]u8 = undefined;
                const resp_len = wsmod.encodeUpgradeResponse(&resp_buf, accept);
                tunnel.send_buf.appendSlice(allocator, resp_buf[0..resp_len]) catch {};
                // Any bytes past the header terminator are frame data.
                const leftover = tunnel.handshake_buf.items[parsed.header_len..];
                if (leftover.len > 0) tunnel.recv_buf.appendSlice(allocator, leftover) catch {};
                tunnel.handshake_buf.clearRetainingCapacity();
                tunnelSetState(session, tunnel, .connected);
                tunnelTouch(session, tunnel, now_ns);
            },
            .connected => {
                // 1. ws → frames → to_channel / pong / close.
                var chunk: [tunnel_ws_chunk]u8 = undefined;
                switch (tunnelReadWs(tunnel, &chunk)) {
                    .closed => {
                        tunnelFail(session, tunnel, "WebSocket connection lost");
                        continue;
                    },
                    .none => {},
                    .data => |n| {
                        if (tunnel.recv_buf.items.len + n > wsmod.max_connection_buffer) {
                            tunnelQueueClose(tunnel, allocator, .too_big, "connection buffer exceeded");
                            tunnelSetState(session, tunnel, .closing);
                            continue;
                        }
                        tunnel.recv_buf.appendSlice(allocator, chunk[0..n]) catch {};
                        tunnelTouch(session, tunnel, now_ns);
                        tunnelDriveFrames(session, tunnel, now_ns);
                    },
                }
                // 2. to_channel → SSH channel (EAGAIN-tolerant).
                while (tunnel.to_channel.items.len > 0) {
                    const w = tunnel.raw.?.write(tunnel.to_channel.items[0..@min(tunnel.to_channel.items.len, tunnel_ws_chunk)]);
                    if (w == 0) break;
                    std.mem.copyForwards(u8, tunnel.to_channel.items[0 .. tunnel.to_channel.items.len - w], tunnel.to_channel.items[w..]);
                    tunnel.to_channel.items.len -= w;
                    tunnelAddUp(session, tunnel, w);
                    tunnelTouch(session, tunnel, now_ns);
                }
                // 3. SSH channel → binary frames on the WS socket. Drain all
                // queued libssh2 packets before returning to other channels.
                var remote_closed = false;
                read_remote: while (tunnel.send_buf.items.len + tunnel_ws_chunk + 14 <= wsmod.max_connection_buffer) {
                    switch (tunnel.raw.?.readOpenStream(&chunk)) {
                        .eof => {
                            remote_closed = true;
                            break :read_remote;
                        },
                        .again => break :read_remote,
                        .data => |n| {
                            tunnelAddDown(session, tunnel, n);
                            tunnelTouch(session, tunnel, now_ns);
                            tunnelQueueFrame(tunnel, allocator, .binary, chunk[0..n]);
                        },
                    }
                }
                if (remote_closed) {
                    tunnelFail(session, tunnel, "the remote VNC server closed the connection");
                    continue;
                }
                // 4. Flush the outbound buffer.
                if (tunnel.ws != null and tunnelFlushWs(tunnel) > 0) tunnelTouch(session, tunnel, now_ns);
                // 5. Idle timeout.
                lockSpin(&session.tunnels_mutex);
                const idle = now_ns - tunnel.last_activity_ns >= tunnel_idle_timeout_ns;
                session.tunnels_mutex.unlock();
                if (idle) {
                    tunnelFail(session, tunnel, "tunnel idle");
                    continue;
                }
            },
            .closing => {
                if (tunnel.ws != null) _ = tunnelFlushWs(tunnel);
                if (tunnel.send_buf.items.len == 0) {
                    // Terminal: release the fds but keep the record as a
                    // tombstone so polls report `closed` (spec 12 §5).
                    tunnelReleaseResources(tunnel, io);
                    tunnelMarkClosed(session, tunnel, now_ns);
                }
            },
            .closed => {
                // Tombstone: pruned once the grace period is up.
                if (now_ns - tunnel.closed_at_ns >= tunnel_tombstone_ns) remove = true;
            },
        }
        if (remove) {
            lockSpin(&session.tunnels_mutex);
            var found: ?usize = null;
            for (session.tunnels.items, 0..) |t, idx| {
                if (t == tunnel) {
                    found = idx;
                    break;
                }
            }
            if (found) |idx| _ = session.tunnels.orderedRemove(idx);
            session.tunnels_mutex.unlock();
            tunnel.deinit(allocator, io);
            allocator.destroy(tunnel);
            continue; // the next tunnel shifted into slot i
        }
        i += 1;
    }
}

fn handshakeErrorText(err: wsmod.HandshakeError) []const u8 {
    return switch (err) {
        error.Incomplete => "incomplete handshake",
        error.HeadersTooLarge => "handshake headers too large",
        error.InvalidRequestLine => "malformed handshake request line",
        error.InvalidMethod => "handshake method must be GET",
        error.InvalidPath => "unknown tunnel token",
        error.MissingHost => "handshake is missing the Host header",
        error.BadUpgrade => "handshake is missing Upgrade: websocket",
        error.BadConnection => "handshake is missing Connection: Upgrade",
        error.BadVersion => "unsupported WebSocket version",
        error.BadKey => "invalid Sec-WebSocket-Key",
        error.BadOrigin => "origin is not allowed",
        error.BadProtocol => "the client must offer the binary subprotocol",
    };
}

/// Shared exec-channel creation for one-shot execs and follow channels.
/// Opens an exec channel and registers it. Takes ownership of `command`,
/// the optional history strings, and the optional secret values on every
/// path: the entry frees them at eviction/close/teardown, the failure
/// paths free them here.
fn tryOpenChannel(session: *Session, id: u32, kind: ChannelKind, command: []const u8, stdin_data: ?[]u8, history_kind: ?[]const u8, history_command: ?[]const u8, history_command_redacted: bool, history_secrets: ?[][]const u8, history_operation_id: ?[]const u8, ai_execution: bool) void {
    const allocator = session.allocator;
    const raw = session.transport.openChannel(session.io) catch {
        freeChannelPayload(allocator, command, stdin_data, history_kind, history_command, history_secrets, history_operation_id);
        return;
    };
    raw.exec(session.io, command) catch {
        raw.close(session.io);
        freeChannelPayload(allocator, command, stdin_data, history_kind, history_command, history_secrets, history_operation_id);
        return;
    };
    const stream = allocator.create(Stream) catch {
        raw.close(session.io);
        freeChannelPayload(allocator, command, stdin_data, history_kind, history_command, history_secrets, history_operation_id);
        return;
    };
    stream.* = Stream.init(allocator);
    const entry = allocator.create(ChannelEntry) catch {
        allocator.destroy(stream);
        raw.close(session.io);
        freeChannelPayload(allocator, command, stdin_data, history_kind, history_command, history_secrets, history_operation_id);
        return;
    };
    entry.* = .{
        .id = id,
        .kind = kind,
        .command = command,
        .history_kind = history_kind,
        .history_command = history_command,
        .history_command_redacted = history_command_redacted,
        .history_secrets = history_secrets,
        .history_operation_id = history_operation_id,
        .ai_marker_pending = ai_execution,
        .started_ns = std.Io.Timestamp.now(session.io, .real).nanoseconds,
        .stream = stream,
        .raw = raw,
        .stdin_queue = if (stdin_data) |input| .{ .items = input, .capacity = input.len } else .empty,
        .stdin_eof_pending = stdin_data != null,
    };
    lockSpin(&session.channels_mutex);
    session.channels.append(allocator, entry) catch {
        session.channels_mutex.unlock();
        entry.clearStdin(allocator);
        entry.freeCommandText(allocator);
        allocator.destroy(entry);
        allocator.destroy(stream);
        raw.close(session.io);
        return;
    };
    session.channels_mutex.unlock();
}

/// Frees the channel-op payload strings on a failed open.
fn freeChannelPayload(allocator: std.mem.Allocator, command: []const u8, stdin_data: ?[]u8, history_kind: ?[]const u8, history_command: ?[]const u8, history_secrets: ?[][]const u8, history_operation_id: ?[]const u8) void {
    allocator.free(command);
    if (stdin_data) |input| {
        std.crypto.secureZero(u8, input);
        allocator.free(input);
    }
    if (history_kind) |hk| allocator.free(hk);
    if (history_command) |hc| allocator.free(hc);
    if (history_operation_id) |operation_id| allocator.free(operation_id);
    if (history_secrets) |hs| {
        for (hs) |s| allocator.free(s);
        allocator.free(hs);
    }
}

/// Bounded EAGAIN wait for SFTP calls (deadline + stop-aware). Returns
/// false when the caller should give up.
fn sftpRetry(session: *Session, deadline: i128) bool {
    if (std.Io.Timestamp.now(session.io, .real).nanoseconds >= deadline) return false;
    if (session.stop_flag.load(.acquire)) return false;
    std.Io.sleep(session.io, std.Io.Duration.fromMilliseconds(10), .awake) catch return false;
    return true;
}

fn matchesExpected(attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES, expected: ClearExpected) bool {
    return attrs.filesize == expected.size and
        attrs.mtime == expected.mtime and
        (attrs.permissions & 0o7777) == expected.mode;
}

/// Identity-bound truncate (spec 04 clear): lstat → reject symlinks and
/// non-regular files → open WITHOUT truncation → fstat the handle → compare
/// size/mtime/mode against the preview (conflict stops with an explicit
/// error) → set the handle's size to zero → audit before/after. The path
/// bytes go to libssh2 directly (SFTP, no shell). Runs on the worker: the
/// libssh2 session is not thread-safe.
fn clearLogFile(session: *Session, path: []const u8, expected: ClearExpected, outcome: *ClearOutcome) void {
    const allocator = session.allocator;
    defer allocator.free(path);
    const deadline = std.Io.Timestamp.now(session.io, .real).nanoseconds + 15 * std.time.ns_per_s;

    const sftp = session.transport.sftpInit(session.io) catch {
        outcome.set(false, "sftp unavailable");
        return;
    };
    const path_z = allocator.dupeZ(u8, path) catch {
        outcome.set(false, "out of memory");
        return;
    };
    defer allocator.free(path_z);

    var attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
    while (true) {
        const rc = ssh.c.libssh2_sftp_lstat(sftp, path_z.ptr, &attrs);
        if (rc == 0) break;
        if (rc != ssh.c.LIBSSH2_ERROR_EAGAIN) {
            var msg_buf: [256]u8 = undefined;
            outcome.set(false, sftpFail(session, "lstat failed", &msg_buf));
            return;
        }
        if (!sftpRetry(session, deadline)) {
            outcome.set(false, "timed out");
            return;
        }
    }
    const kind = attrs.permissions & ssh.c.LIBSSH2_SFTP_S_IFMT;
    if (kind == ssh.c.LIBSSH2_SFTP_S_IFLNK) {
        outcome.set(false, "refusing to clear a symlink");
        return;
    }
    if (kind != ssh.c.LIBSSH2_SFTP_S_IFREG) {
        outcome.set(false, "not a regular file");
        return;
    }
    if (!matchesExpected(attrs, expected)) {
        outcome.set(false, "file changed since preview; re-scan before clearing");
        return;
    }

    var handle: *ssh.c.LIBSSH2_SFTP_HANDLE = undefined;
    while (true) {
        if (ssh.c.libssh2_sftp_open_ex(
            sftp,
            path_z.ptr,
            @intCast(path.len),
            ssh.c.LIBSSH2_FXF_READ | ssh.c.LIBSSH2_FXF_WRITE,
            0,
            ssh.c.LIBSSH2_SFTP_OPENFILE,
        )) |h| {
            handle = h;
            break;
        }
        const rc = ssh.c.libssh2_session_last_errno(session.transport.raw);
        if (rc == ssh.c.LIBSSH2_ERROR_EAGAIN) {
            if (!sftpRetry(session, deadline)) {
                outcome.set(false, "timed out");
                return;
            }
            continue;
        }
        var msg_buf: [256]u8 = undefined;
        outcome.set(false, sftpFail(session, "open failed", &msg_buf));
        return;
    }
    defer _ = ssh.c.libssh2_sftp_close_handle(handle);

    // The identity check is repeated against the OPEN HANDLE, binding the
    // preview to the object that actually gets truncated.
    while (true) {
        const rc = ssh.c.libssh2_sftp_fstat(handle, &attrs);
        if (rc == 0) break;
        if (rc != ssh.c.LIBSSH2_ERROR_EAGAIN) {
            var msg_buf: [256]u8 = undefined;
            outcome.set(false, sftpFail(session, "fstat failed", &msg_buf));
            return;
        }
        if (!sftpRetry(session, deadline)) {
            outcome.set(false, "timed out");
            return;
        }
    }
    if (!matchesExpected(attrs, expected)) {
        outcome.set(false, "file changed since preview; re-scan before clearing");
        return;
    }
    const before = attrs.filesize;

    var set_attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = .{ .flags = ssh.c.LIBSSH2_SFTP_ATTR_SIZE, .filesize = 0 };
    while (true) {
        const rc = ssh.c.libssh2_sftp_fsetstat(handle, &set_attrs);
        if (rc == 0) break;
        if (rc != ssh.c.LIBSSH2_ERROR_EAGAIN) {
            var msg_buf: [256]u8 = undefined;
            outcome.set(false, sftpFail(session, "truncate failed", &msg_buf));
            return;
        }
        if (!sftpRetry(session, deadline)) {
            outcome.set(false, "timed out");
            return;
        }
    }

    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "before_size={d} after_size=0", .{before}) catch "logs.clear";
    session.audit.append(session.io, "logs.clear", session.server.id, detail) catch {};

    lockSpin(&outcome.mutex);
    outcome.ok = true;
    outcome.before_size = before;
    outcome.after_size = 0;
    outcome.done = true;
    outcome.mutex.unlock();
}

/// Prefix + libssh2's own error text, into `buf`.
fn sftpFail(session: *Session, prefix: []const u8, buf: []u8) []const u8 {
    var msg_buf: [256]u8 = undefined;
    const msg = session.transport.lastErrorMessage(&msg_buf);
    return std.fmt.bufPrint(buf, "{s}: {s}", .{ prefix, msg }) catch prefix;
}

/// The last SFTP error as the FX code stored on outcomes.
fn sftpLastFx(sftp: *ssh.c.LIBSSH2_SFTP) i64 {
    return @intCast(ssh.c.libssh2_sftp_last_error(sftp));
}

// --- SFTP worker ops (spec 05) -------------------------------------------

const sftp_timeout_ms = 15_000;
const max_listing_entries = 5000;

fn sftpDeadline(session: *Session) i128 {
    return std.Io.Timestamp.now(session.io, .real).nanoseconds + sftp_timeout_ms * std.time.ns_per_ms;
}

/// Heap JSON for an outcome payload (worker side).
fn outcomeJson(allocator: std.mem.Allocator, payload: anytype) ?[]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    std.json.Stringify.value(payload, .{}, &out.writer) catch return null;
    var list = out.toArrayList();
    return list.toOwnedSlice(allocator) catch null;
}

fn sftpSetJson(session: *Session, outcome: *SftpOutcome, payload: anytype) void {
    const json = outcomeJson(session.allocator, payload) orelse {
        outcome.set(false, "out of memory serializing the response");
        return;
    };
    outcome.setJson(json);
}

fn sftpAudit(session: *Session, action: []const u8, detail: []const u8) void {
    session.audit.append(session.io, action, session.server.id, detail) catch {};
}

/// EAGAIN-bounded open; null on failure.
fn sftpOpen(
    session: *Session,
    sftp: *ssh.c.LIBSSH2_SFTP,
    path_z: [:0]const u8,
    flags: c_ulong,
    mode: c_long,
    open_type: c_int,
    deadline: i128,
) ?*ssh.c.LIBSSH2_SFTP_HANDLE {
    while (true) {
        if (ssh.c.libssh2_sftp_open_ex(sftp, path_z.ptr, @intCast(path_z.len), flags, mode, open_type)) |h| return h;
        const rc = ssh.c.libssh2_session_last_errno(session.transport.raw);
        if (rc != ssh.c.LIBSSH2_ERROR_EAGAIN) return null;
        if (!sftpRetry(session, deadline)) return null;
    }
}

/// EAGAIN-bounded read; 0 = EOF, null = failure.
fn sftpRead(session: *Session, handle: *ssh.c.LIBSSH2_SFTP_HANDLE, buf: []u8, deadline: i128) ?usize {
    while (true) {
        const rc = ssh.c.libssh2_sftp_read(handle, buf.ptr, buf.len);
        if (rc >= 0) return @intCast(rc);
        if (rc != ssh.c.LIBSSH2_ERROR_EAGAIN) return null;
        if (!sftpRetry(session, deadline)) return null;
    }
}

/// EAGAIN-bounded readdir; 0 = end of directory, null = failure.
fn sftpReaddir(
    session: *Session,
    handle: *ssh.c.LIBSSH2_SFTP_HANDLE,
    name_buf: []u8,
    attrs: *ssh.c.LIBSSH2_SFTP_ATTRIBUTES,
    deadline: i128,
) ?usize {
    while (true) {
        const rc = ssh.c.libssh2_sftp_readdir_ex(handle, name_buf.ptr, name_buf.len, null, 0, attrs);
        if (rc == 0) return 0;
        if (rc > 0) return @intCast(rc);
        if (rc != ssh.c.LIBSSH2_ERROR_EAGAIN) return null;
        if (!sftpRetry(session, deadline)) return null;
    }
}

/// EAGAIN-bounded write-all; false on failure.
fn sftpWriteAll(session: *Session, handle: *ssh.c.LIBSSH2_SFTP_HANDLE, data: []const u8, deadline: i128) bool {
    var off: usize = 0;
    while (off < data.len) {
        const rc = ssh.c.libssh2_sftp_write(handle, data.ptr + off, data.len - off);
        if (rc > 0) {
            off += @intCast(rc);
            continue;
        }
        if (rc == ssh.c.LIBSSH2_ERROR_EAGAIN) {
            if (!sftpRetry(session, deadline)) return false;
            continue;
        }
        return false;
    }
    return true;
}

/// EAGAIN-bounded lstat; false on failure.
fn sftpLstat(session: *Session, sftp: *ssh.c.LIBSSH2_SFTP, path_z: [:0]const u8, attrs: *ssh.c.LIBSSH2_SFTP_ATTRIBUTES, deadline: i128) bool {
    while (true) {
        const rc = ssh.c.libssh2_sftp_stat_ex(sftp, path_z.ptr, @intCast(path_z.len), ssh.c.LIBSSH2_SFTP_LSTAT, attrs);
        if (rc == 0) return true;
        if (rc != ssh.c.LIBSSH2_ERROR_EAGAIN) return false;
        if (!sftpRetry(session, deadline)) return false;
    }
}

/// EAGAIN-bounded fstat; false on failure.
fn sftpFstat(session: *Session, handle: *ssh.c.LIBSSH2_SFTP_HANDLE, attrs: *ssh.c.LIBSSH2_SFTP_ATTRIBUTES, deadline: i128) bool {
    while (true) {
        const rc = ssh.c.libssh2_sftp_fstat_ex(handle, attrs, 0);
        if (rc == 0) return true;
        if (rc != ssh.c.LIBSSH2_ERROR_EAGAIN) return false;
        if (!sftpRetry(session, deadline)) return false;
    }
}

/// EAGAIN-bounded readlink; returns the target length, null on failure.
fn sftpReadlink(session: *Session, sftp: *ssh.c.LIBSSH2_SFTP, path_z: [:0]const u8, buf: []u8, deadline: i128) ?usize {
    @memset(buf, 0);
    while (true) {
        const rc = ssh.c.libssh2_sftp_symlink_ex(sftp, path_z.ptr, @as(c_uint, @intCast(path_z.len)), buf.ptr, @as(c_uint, @intCast(buf.len)), ssh.c.LIBSSH2_SFTP_READLINK);
        if (rc == 0) return std.mem.indexOfScalar(u8, buf, 0) orelse buf.len;
        if (rc != ssh.c.LIBSSH2_ERROR_EAGAIN) return null;
        if (!sftpRetry(session, deadline)) return null;
    }
}

/// Runs a one-shot SFTP call with EAGAIN retries; 0 on success, false on
/// failure. `call` is a function pointer taking (sftp, args...).
fn sftpCall(session: *Session, deadline: i128, comptime call: anytype, args: anytype) bool {
    while (true) {
        const rc = @call(.auto, call, args);
        if (rc == 0) return true;
        if (rc != ssh.c.LIBSSH2_ERROR_EAGAIN) return false;
        if (!sftpRetry(session, deadline)) return false;
    }
}

fn sftpUnlink(session: *Session, sftp: *ssh.c.LIBSSH2_SFTP, path_z: [:0]const u8, deadline: i128) bool {
    return sftpCall(session, deadline, ssh.c.libssh2_sftp_unlink_ex, .{ sftp, path_z.ptr, @as(c_uint, @intCast(path_z.len)) });
}

fn sftpRmdir(session: *Session, sftp: *ssh.c.LIBSSH2_SFTP, path_z: [:0]const u8, deadline: i128) bool {
    return sftpCall(session, deadline, ssh.c.libssh2_sftp_rmdir_ex, .{ sftp, path_z.ptr, @as(c_uint, @intCast(path_z.len)) });
}

fn sftpMkdir(session: *Session, sftp: *ssh.c.LIBSSH2_SFTP, path_z: [:0]const u8, mode: c_long, deadline: i128) bool {
    return sftpCall(session, deadline, ssh.c.libssh2_sftp_mkdir_ex, .{ sftp, path_z.ptr, @as(c_uint, @intCast(path_z.len)), mode });
}

fn sftpRenameEx(session: *Session, sftp: *ssh.c.LIBSSH2_SFTP, from_z: [:0]const u8, to_z: [:0]const u8, flags: c_long, deadline: i128) bool {
    return sftpCall(session, deadline, ssh.c.libssh2_sftp_rename_ex, .{ sftp, from_z.ptr, @as(c_uint, @intCast(from_z.len)), to_z.ptr, @as(c_uint, @intCast(to_z.len)), flags });
}

fn sftpPosixRename(session: *Session, sftp: *ssh.c.LIBSSH2_SFTP, from_z: [:0]const u8, to_z: [:0]const u8, deadline: i128) bool {
    return sftpCall(session, deadline, ssh.c.libssh2_sftp_posix_rename_ex, .{ sftp, from_z.ptr, @as(c_uint, @intCast(from_z.len)), to_z.ptr, @as(c_uint, @intCast(to_z.len)) });
}

fn sftpAttrs(attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES) sftpmod.Attrs {
    return .{
        .permissions = @intCast(attrs.permissions),
        .size = attrs.filesize,
        .mtime = attrs.mtime,
        .uid = @intCast(attrs.uid),
        .gid = @intCast(attrs.gid),
    };
}

fn sftpSessionHandle(session: *Session, outcome: ?*SftpOutcome) ?*ssh.c.LIBSSH2_SFTP {
    return session.transport.sftpInit(session.io) catch {
        if (outcome) |o| o.set(false, "sftp unavailable");
        return null;
    };
}

/// `<path>.partial` for uploads/downloads (spec 05 §10).
fn partialPath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}.partial", .{path});
}

/// `path + "/" + name` (owned).
fn joinPath(allocator: std.mem.Allocator, dir: []const u8, name: []const u8) ![]u8 {
    if (dir.len == 0) return allocator.dupe(u8, name);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, name });
}

fn sftpOpLs(session: *Session, path: []const u8, outcome: *SftpOutcome) void {
    const allocator = session.allocator;
    defer allocator.free(path);
    const sftp = sftpSessionHandle(session, outcome) orelse return;
    const path_z = allocator.dupeZ(u8, path) catch return outcome.set(false, "out of memory");
    defer allocator.free(path_z);
    const deadline = sftpDeadline(session);

    const handle = sftpOpen(session, sftp, path_z, 0, 0, ssh.c.LIBSSH2_SFTP_OPENDIR, deadline) orelse {
        var msg_buf: [256]u8 = undefined;
        outcome.set(false, sftpFail(session, "cannot open directory", &msg_buf));
        return;
    };
    defer _ = ssh.c.libssh2_sftp_close_handle(handle);

    var entries: std.ArrayList(sftpmod.Entry) = .empty;
    defer {
        for (entries.items) |*e| e.deinit(allocator);
        entries.deinit(allocator);
    }
    var name_buf: [4096]u8 = undefined;
    var attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
    var truncated = false;
    while (true) {
        const n = sftpReaddir(session, handle, &name_buf, &attrs, deadline) orelse {
            var msg_buf: [256]u8 = undefined;
            outcome.set(false, sftpFail(session, "readdir failed", &msg_buf));
            return;
        };
        if (n == 0) break;
        if (entries.items.len >= max_listing_entries) {
            truncated = true;
            break;
        }
        var entry = sftpmod.makeEntry(allocator, name_buf[0..n], sftpAttrs(attrs)) catch {
            outcome.set(false, "out of memory");
            return;
        };
        entries.append(allocator, entry) catch {
            entry.deinit(allocator);
            outcome.set(false, "out of memory");
            return;
        };
    }
    sftpSetJson(session, outcome, .{ .ok = true, .entries = entries.items, .truncated = truncated });
}

fn sftpOpStat(session: *Session, path: []const u8, outcome: *SftpOutcome) void {
    const allocator = session.allocator;
    defer allocator.free(path);
    const sftp = sftpSessionHandle(session, outcome) orelse return;
    const path_z = allocator.dupeZ(u8, path) catch return outcome.set(false, "out of memory");
    defer allocator.free(path_z);
    const deadline = sftpDeadline(session);

    var attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
    if (!sftpLstat(session, sftp, path_z, &attrs, deadline)) {
        var msg_buf: [256]u8 = undefined;
        outcome.setFx(false, sftpFail(session, "stat failed", &msg_buf), sftpLastFx(sftp));
        return;
    }
    const base = std.fs.path.basename(path);
    var entry = sftpmod.makeEntry(allocator, base, sftpAttrs(attrs)) catch {
        outcome.set(false, "out of memory");
        return;
    };
    defer entry.deinit(allocator);
    if (entry.kind == .symlink) {
        var target_buf: [4096]u8 = undefined;
        if (sftpReadlink(session, sftp, path_z, &target_buf, deadline)) |target_len| {
            entry.link_target = allocator.dupe(u8, target_buf[0..target_len]) catch null;
        }
    }
    sftpSetJson(session, outcome, .{ .ok = true, .entry = entry });
}

fn sftpOpRead(session: *Session, path: []const u8, offset: u64, max: usize, outcome: *SftpOutcome) void {
    const allocator = session.allocator;
    defer allocator.free(path);
    const sftp = sftpSessionHandle(session, outcome) orelse return;
    const path_z = allocator.dupeZ(u8, path) catch return outcome.set(false, "out of memory");
    defer allocator.free(path_z);
    const deadline = sftpDeadline(session);

    const handle = sftpOpen(session, sftp, path_z, ssh.c.LIBSSH2_FXF_READ, 0, ssh.c.LIBSSH2_SFTP_OPENFILE, deadline) orelse {
        var msg_buf: [256]u8 = undefined;
        outcome.setFx(false, sftpFail(session, "cannot open file", &msg_buf), sftpLastFx(sftp));
        return;
    };
    defer _ = ssh.c.libssh2_sftp_close_handle(handle);
    ssh.c.libssh2_sftp_seek64(handle, offset);

    const buf = allocator.alloc(u8, max) catch return outcome.set(false, "out of memory");
    defer allocator.free(buf);
    const n = sftpRead(session, handle, buf, deadline) orelse {
        var msg_buf: [256]u8 = undefined;
        outcome.setFx(false, sftpFail(session, "read failed", &msg_buf), sftpLastFx(sftp));
        return;
    };
    var attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
    const has_stat = sftpFstat(session, handle, &attrs, deadline);
    const eof = if (has_stat and attrs.flags & ssh.c.LIBSSH2_SFTP_ATTR_SIZE != 0)
        offset + n >= attrs.filesize
    else
        n == 0;
    const b64 = sftpmod.base64Encode(allocator, buf[0..n]) catch return outcome.set(false, "out of memory");
    // The JSON payload copies the bytes; the worker owns and frees the
    // base64 buffer itself (the handler frees the serialized json).
    defer allocator.free(b64);
    sftpSetJson(session, outcome, .{ .ok = true, .base64 = b64, .eof = eof });
}

fn sftpOpWriteChunk(
    session: *Session,
    path: []const u8,
    offset: u64,
    data: []const u8,
    total: u64,
    transfer_id: u32,
    outcome: *SftpOutcome,
) void {
    const allocator = session.allocator;
    defer allocator.free(path);
    defer allocator.free(data);
    const sftp = sftpSessionHandle(session, outcome) orelse return;
    const deadline = sftpDeadline(session);

    session.sftp_transfers.lock();
    const t = session.sftp_transfers.get(transfer_id) orelse {
        session.sftp_transfers.unlock();
        outcome.set(false, "unknown transfer");
        return;
    };
    if (t.cancel_flag) {
        t.status = .canceled;
        session.sftp_transfers.unlock();
        // The cancel op deletes the partial; do it again defensively in
        // case the flag was set directly by the handler (spec 05 §5).
        const partial = partialPath(allocator, path) catch return outcome.set(false, "canceled");
        defer allocator.free(partial);
        const partial_z = allocator.dupeZ(u8, partial) catch return outcome.set(false, "canceled");
        defer allocator.free(partial_z);
        _ = ssh.c.libssh2_sftp_unlink_ex(sftp, partial_z.ptr, @intCast(partial_z.len));
        outcome.set(false, "canceled");
        return;
    }
    t.status = .running;
    t.bytes_total = total;
    session.sftp_transfers.unlock();

    const partial = partialPath(allocator, path) catch return outcome.set(false, "out of memory");
    defer allocator.free(partial);
    const partial_z = allocator.dupeZ(u8, partial) catch return outcome.set(false, "out of memory");
    defer allocator.free(partial_z);
    const flags: c_ulong = @as(c_ulong, ssh.c.LIBSSH2_FXF_READ) | @as(c_ulong, ssh.c.LIBSSH2_FXF_WRITE) | @as(c_ulong, ssh.c.LIBSSH2_FXF_CREAT) | if (offset == 0) @as(c_ulong, ssh.c.LIBSSH2_FXF_TRUNC) else 0;
    const handle = sftpOpen(session, sftp, partial_z, flags, 0o600, ssh.c.LIBSSH2_SFTP_OPENFILE, deadline) orelse {
        var msg_buf: [256]u8 = undefined;
        outcome.set(false, sftpFail(session, "open failed", &msg_buf));
        return;
    };
    ssh.c.libssh2_sftp_seek64(handle, offset);
    if (!sftpWriteAll(session, handle, data, deadline)) {
        _ = ssh.c.libssh2_sftp_close_handle(handle);
        var msg_buf: [256]u8 = undefined;
        outcome.set(false, sftpFail(session, "write failed", &msg_buf));
        return;
    }
    var attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
    if (!sftpFstat(session, handle, &attrs, deadline)) {
        _ = ssh.c.libssh2_sftp_close_handle(handle);
        var msg_buf: [256]u8 = undefined;
        outcome.set(false, sftpFail(session, "fstat failed", &msg_buf));
        return;
    }
    const written = attrs.filesize;
    _ = ssh.c.libssh2_sftp_close_handle(handle);

    // `total == 0` is a real empty-file upload. The opened/truncated partial
    // file must still be finalized instead of reporting a UI-only success.
    const done = written >= total;
    if (done) {
        // No-clobber finalize: rename with no overwrite flag. A target that
        // appeared meanwhile is a conflict, not a silent overwrite.
        const path_z = allocator.dupeZ(u8, path) catch return outcome.set(false, "out of memory");
        defer allocator.free(path_z);
        if (!sftpRenameEx(session, sftp, partial_z, path_z, 0, deadline)) {
            var detail_buf: [256]u8 = undefined;
            const detail = std.fmt.bufPrint(&detail_buf, "path={s} bytes={d}", .{ path, written }) catch "sftp.upload";
            sftpAudit(session, "sftp.upload.failed", detail);
            _ = ssh.c.libssh2_sftp_unlink_ex(sftp, partial_z.ptr, @intCast(partial_z.len));
            session.sftp_transfers.lock();
            if (session.sftp_transfers.get(transfer_id)) |t2| t2.status = .failed;
            session.sftp_transfers.unlock();
            outcome.set(false, "target already exists; upload refused");
            return;
        }
        var detail_buf: [256]u8 = undefined;
        const detail = std.fmt.bufPrint(&detail_buf, "path={s} bytes={d}", .{ path, written }) catch "sftp.upload";
        sftpAudit(session, "sftp.upload", detail);
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t2| {
            t2.bytes_done = written;
            t2.status = .done;
        }
        session.sftp_transfers.unlock();
    } else {
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t2| t2.bytes_done = written;
        session.sftp_transfers.unlock();
    }
    sftpSetJson(session, outcome, .{ .ok = true, .written = written, .done = done });
}

/// Editor-save conflict preflight (spec 05 §4.2): the save only proceeds
/// when the remote file still matches the identity the editor opened
/// (size, mtime, and content hash — all optional). Returns a conflict
/// message when the check fails; null when it passes. The check is
/// advisory: the atomic rename itself replaces whatever is there, so the
/// window between check and rename is inherently racy — the conflict
/// prompt is the protection, not a lock.
fn sftpSaveConflict(
    session: *Session,
    sftp: *ssh.c.LIBSSH2_SFTP,
    path_z: [:0]const u8,
    expected: ?SftpExpectedIdentity,
    deadline: i128,
) ?[]const u8 {
    const identity = expected orelse return null;
    var attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
    if (!sftpLstat(session, sftp, path_z, &attrs, deadline)) {
        const fx = sftpLastFx(sftp);
        if (identity.missing and fx == ssh.c.LIBSSH2_FX_NO_SUCH_FILE) return null;
        return if (identity.missing)
            "conflict: cannot verify that the target is still missing; reload and review before saving"
        else
            "conflict: the file disappeared from the server; reload and review before saving";
    }
    if (identity.missing) {
        return "conflict: a file appeared at the reviewed path; reload and review before saving";
    }
    if (identity.size) |want| {
        if (attrs.filesize != want) {
            return "conflict: the file changed on the server (size); reload and review before saving";
        }
    }
    if (identity.mtime) |want| {
        if (attrs.mtime != want) {
            return "conflict: the file changed on the server (modification time); reload and review before saving";
        }
    }
    if (identity.sha256) |want_hex| {
        // Hash the remote file in full and compare, bounded by the owning
        // feature's admitted source limit.
        if (attrs.filesize > identity.max_hash_bytes) {
            return "conflict: the file is too large to verify; reload and review before saving";
        }
        const handle = sftpOpen(session, sftp, path_z, ssh.c.LIBSSH2_FXF_READ, 0, ssh.c.LIBSSH2_SFTP_OPENFILE, deadline) orelse {
            return "conflict: cannot re-read the file to verify it; reload and review before saving";
        };
        defer _ = ssh.c.libssh2_sftp_close_handle(handle);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        var buf: [sftpmod.chunk_size]u8 = undefined;
        while (true) {
            const n = sftpRead(session, handle, &buf, deadline) orelse {
                return "conflict: cannot re-read the file to verify it; reload and review before saving";
            };
            if (n == 0) break;
            hash.update(buf[0..n]);
        }
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        var hex_buf: [64]u8 = undefined;
        // Zig 0.16 has no fmtSliceHexLower; encode by hand.
        const hex_chars = "0123456789abcdef";
        for (digest, 0..) |byte, i| {
            hex_buf[i * 2] = hex_chars[byte >> 4];
            hex_buf[i * 2 + 1] = hex_chars[byte & 0xf];
        }
        const hex = hex_buf[0..64];
        if (want_hex.len != hex.len or !std.ascii.eqlIgnoreCase(want_hex, hex)) {
            return "conflict: the file changed on the server (content); reload and review before saving";
        }
    }
    return null;
}

fn sftpOpSave(
    session: *Session,
    path: []const u8,
    data: []const u8,
    expected: ?SftpExpectedIdentity,
    outcome: *SftpOutcome,
) void {
    const allocator = session.allocator;
    defer allocator.free(path);
    defer secureFreeBytes(allocator, @constCast(data));
    defer if (expected) |identity| if (identity.sha256) |sha| allocator.free(sha);
    const sftp = sftpSessionHandle(session, outcome) orelse return;
    const deadline = sftpDeadline(session);

    const path_z = allocator.dupeZ(u8, path) catch return outcome.set(false, "out of memory");
    defer allocator.free(path_z);
    if (sftpSaveConflict(session, sftp, path_z, expected, deadline)) |conflict| {
        outcome.set(false, conflict);
        return;
    }

    var random_bytes: [16]u8 = undefined;
    std.Io.randomSecure(session.io, &random_bytes) catch return outcome.set(false, "secure random unavailable");
    const random_hex = std.fmt.bytesToHex(random_bytes, .lower);
    const tmp = std.fmt.allocPrint(allocator, "{s}.oars-tmp-{s}", .{ path, random_hex }) catch return outcome.set(false, "out of memory");
    defer allocator.free(tmp);
    const tmp_z = allocator.dupeZ(u8, tmp) catch return outcome.set(false, "out of memory");
    defer allocator.free(tmp_z);
    const handle = sftpOpen(session, sftp, tmp_z, ssh.c.LIBSSH2_FXF_WRITE | ssh.c.LIBSSH2_FXF_CREAT | ssh.c.LIBSSH2_FXF_TRUNC, 0o600, ssh.c.LIBSSH2_SFTP_OPENFILE, deadline) orelse {
        var msg_buf: [256]u8 = undefined;
        outcome.set(false, sftpFail(session, "cannot create temp file", &msg_buf));
        return;
    };
    if (!sftpWriteAll(session, handle, data, deadline)) {
        _ = ssh.c.libssh2_sftp_close_handle(handle);
        _ = ssh.c.libssh2_sftp_unlink_ex(sftp, tmp_z.ptr, @intCast(tmp_z.len));
        var msg_buf: [256]u8 = undefined;
        outcome.set(false, sftpFail(session, "write failed", &msg_buf));
        return;
    }
    _ = ssh.c.libssh2_sftp_close_handle(handle);

    // Re-check after the potentially long temp-file write. SFTP has no
    // compare-and-swap rename primitive, so this closes the material race
    // window while the final protocol round trip remains advisory.
    if (sftpSaveConflict(session, sftp, path_z, expected, deadline)) |conflict| {
        _ = ssh.c.libssh2_sftp_unlink_ex(sftp, tmp_z.ptr, @intCast(tmp_z.len));
        outcome.set(false, conflict);
        return;
    }

    if (!sftpPosixRename(session, sftp, tmp_z, path_z, deadline)) {
        const fx = ssh.c.libssh2_sftp_last_error(sftp);
        _ = ssh.c.libssh2_sftp_unlink_ex(sftp, tmp_z.ptr, @intCast(tmp_z.len));
        if (fx == ssh.c.LIBSSH2_FX_OP_UNSUPPORTED) {
            outcome.set(false, "server lacks the atomic posix-rename extension; save refused");
        } else {
            var msg_buf: [256]u8 = undefined;
            outcome.set(false, sftpFail(session, "atomic rename failed", &msg_buf));
        }
        return;
    }
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "path={s} bytes={d}", .{ path, data.len }) catch "sftp.save";
    sftpAudit(session, "sftp.save", detail);
    sftpSetJson(session, outcome, .{ .ok = true });
}

fn sftpOpMkdir(session: *Session, path: []const u8, outcome: *SftpOutcome) void {
    const allocator = session.allocator;
    defer allocator.free(path);
    const sftp = sftpSessionHandle(session, outcome) orelse return;
    const path_z = allocator.dupeZ(u8, path) catch return outcome.set(false, "out of memory");
    defer allocator.free(path_z);
    const deadline = sftpDeadline(session);
    if (!sftpMkdir(session, sftp, path_z, 0o755, deadline)) {
        var msg_buf: [256]u8 = undefined;
        outcome.set(false, sftpFail(session, "mkdir failed", &msg_buf));
        return;
    }
    sftpAudit(session, "sftp.mkdir", path);
    sftpSetJson(session, outcome, .{ .ok = true });
}

fn sftpOpRename(session: *Session, from: []const u8, to: []const u8, outcome: *SftpOutcome) void {
    const allocator = session.allocator;
    defer allocator.free(from);
    defer allocator.free(to);
    const sftp = sftpSessionHandle(session, outcome) orelse return;
    const from_z = allocator.dupeZ(u8, from) catch return outcome.set(false, "out of memory");
    defer allocator.free(from_z);
    const to_z = allocator.dupeZ(u8, to) catch return outcome.set(false, "out of memory");
    defer allocator.free(to_z);
    const deadline = sftpDeadline(session);
    const flags = ssh.c.LIBSSH2_SFTP_RENAME_OVERWRITE | ssh.c.LIBSSH2_SFTP_RENAME_ATOMIC | ssh.c.LIBSSH2_SFTP_RENAME_NATIVE;
    if (!sftpRenameEx(session, sftp, from_z, to_z, flags, deadline)) {
        var msg_buf: [256]u8 = undefined;
        outcome.set(false, sftpFail(session, "rename failed", &msg_buf));
        return;
    }
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "from={s} to={s}", .{ from, to }) catch "sftp.rename";
    sftpAudit(session, "sftp.rename", detail);
    sftpSetJson(session, outcome, .{ .ok = true });
}

fn sftpOpChmod(session: *Session, path: []const u8, mode: u32, outcome: *SftpOutcome) void {
    const allocator = session.allocator;
    defer allocator.free(path);
    const sftp = sftpSessionHandle(session, outcome) orelse return;
    const path_z = allocator.dupeZ(u8, path) catch return outcome.set(false, "out of memory");
    defer allocator.free(path_z);
    const deadline = sftpDeadline(session);

    var attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
    if (!sftpLstat(session, sftp, path_z, &attrs, deadline)) {
        var msg_buf: [256]u8 = undefined;
        outcome.set(false, sftpFail(session, "stat failed", &msg_buf));
        return;
    }
    // Keep the file type bits; change only the permission bits.
    var set_attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = .{
        .flags = ssh.c.LIBSSH2_SFTP_ATTR_PERMISSIONS,
        .permissions = (attrs.permissions & 0o170000) | (mode & 0o7777),
    };
    while (true) {
        const rc = ssh.c.libssh2_sftp_stat_ex(sftp, path_z.ptr, @intCast(path_z.len), ssh.c.LIBSSH2_SFTP_SETSTAT, &set_attrs);
        if (rc == 0) break;
        if (rc != ssh.c.LIBSSH2_ERROR_EAGAIN) {
            var msg_buf: [256]u8 = undefined;
            outcome.set(false, sftpFail(session, "chmod failed", &msg_buf));
            return;
        }
        if (!sftpRetry(session, deadline)) {
            outcome.set(false, "timed out");
            return;
        }
    }
    var detail_buf: [128]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "path={s} mode={o}", .{ path, mode & 0o7777 }) catch "sftp.chmod";
    sftpAudit(session, "sftp.chmod", detail);
    sftpSetJson(session, outcome, .{ .ok = true });
}

/// True when the transfer was canceled (worker reads under the lock).
fn transferCanceled(session: *Session, transfer_id: u32) bool {
    session.sftp_transfers.lock();
    defer session.sftp_transfers.unlock();
    const t = session.sftp_transfers.get(transfer_id) orelse return true;
    return t.cancel_flag;
}

/// Counts entries under `path` (symlinks count once, never recursed).
fn sftpCountEntries(session: *Session, sftp: *ssh.c.LIBSSH2_SFTP, path_z: [:0]const u8, deadline: i128) ?u64 {
    var attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
    if (!sftpLstat(session, sftp, path_z, &attrs, deadline)) return null;
    const kind = attrs.permissions & ssh.c.LIBSSH2_SFTP_S_IFMT;
    if (kind != ssh.c.LIBSSH2_SFTP_S_IFDIR) return 1;
    const handle = sftpOpen(session, sftp, path_z, 0, 0, ssh.c.LIBSSH2_SFTP_OPENDIR, deadline) orelse return null;
    defer _ = ssh.c.libssh2_sftp_close_handle(handle);
    var count: u64 = 0;
    var name_buf: [4096]u8 = undefined;
    while (true) {
        const n = sftpReaddir(session, handle, &name_buf, &attrs, deadline) orelse return null;
        if (n == 0) break;
        const name = name_buf[0..n];
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        count += 1;
        const child = joinPath(session.allocator, path_z, name) catch return null;
        defer session.allocator.free(child);
        const child_z = session.allocator.dupeZ(u8, child) catch return null;
        defer session.allocator.free(child_z);
        const sub = sftpCountEntries(session, sftp, child_z, deadline) orelse return null;
        count += sub;
    }
    return count;
}

/// Recursive delete with per-entry progress on the transfer record. Returns
/// false when canceled or on failure (the caller audits the outcome).
fn sftpDeleteRecursive(session: *Session, sftp: *ssh.c.LIBSSH2_SFTP, path_z: [:0]const u8, transfer_id: u32, deadline: i128) bool {
    const allocator = session.allocator;
    if (transferCanceled(session, transfer_id)) return false;
    var attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
    if (!sftpLstat(session, sftp, path_z, &attrs, deadline)) return false;
    const kind = attrs.permissions & ssh.c.LIBSSH2_SFTP_S_IFMT;
    if (kind != ssh.c.LIBSSH2_SFTP_S_IFDIR) {
        if (!sftpUnlink(session, sftp, path_z, deadline)) return false;
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t| t.bytes_done += 1;
        session.sftp_transfers.unlock();
        return true;
    }
    const handle = sftpOpen(session, sftp, path_z, 0, 0, ssh.c.LIBSSH2_SFTP_OPENDIR, deadline) orelse return false;
    var name_buf: [4096]u8 = undefined;
    while (true) {
        const n = sftpReaddir(session, handle, &name_buf, &attrs, deadline) orelse {
            _ = ssh.c.libssh2_sftp_close_handle(handle);
            return false;
        };
        if (n == 0) break;
        const name = name_buf[0..n];
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        const child = joinPath(allocator, path_z, name) catch {
            _ = ssh.c.libssh2_sftp_close_handle(handle);
            return false;
        };
        defer allocator.free(child);
        const child_z = allocator.dupeZ(u8, child) catch {
            _ = ssh.c.libssh2_sftp_close_handle(handle);
            return false;
        };
        defer allocator.free(child_z);
        if (!sftpDeleteRecursive(session, sftp, child_z, transfer_id, deadline)) {
            _ = ssh.c.libssh2_sftp_close_handle(handle);
            return false;
        }
    }
    _ = ssh.c.libssh2_sftp_close_handle(handle);
    if (!sftpRmdir(session, sftp, path_z, deadline)) return false;
    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(transfer_id)) |t| t.bytes_done += 1;
    session.sftp_transfers.unlock();
    return true;
}

fn sftpOpRm(session: *Session, path: []const u8, recursive: bool, transfer_id: u32, outcome: ?*SftpOutcome) void {
    const allocator = session.allocator;
    defer allocator.free(path);

    if (!recursive) {
        const out = outcome orelse return; // plain deletes always carry one
        const sftp = sftpSessionHandle(session, out) orelse return;
        const path_z = allocator.dupeZ(u8, path) catch return out.set(false, "out of memory");
        defer allocator.free(path_z);
        const deadline = sftpDeadline(session);
        var attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
        if (!sftpLstat(session, sftp, path_z, &attrs, deadline)) {
            var msg_buf: [256]u8 = undefined;
            out.setFx(false, sftpFail(session, "stat failed", &msg_buf), sftpLastFx(sftp));
            return;
        }
        const kind = attrs.permissions & ssh.c.LIBSSH2_SFTP_S_IFMT;
        const ok = if (kind == ssh.c.LIBSSH2_SFTP_S_IFDIR)
            sftpRmdir(session, sftp, path_z, deadline)
        else
            sftpUnlink(session, sftp, path_z, deadline);
        if (!ok) {
            var msg_buf: [256]u8 = undefined;
            out.set(false, sftpFail(session, "delete failed", &msg_buf));
            return;
        }
        sftpAudit(session, "sftp.rm", path);
        sftpSetJson(session, out, .{ .ok = true });
        return;
    }

    // Async recursive delete with per-entry progress (spec 05 §5). Errors
    // ride the transfer record; the op carries no outcome on this path.
    const sftp = session.transport.sftpInit(session.io) catch {
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t2| {
            t2.status = .failed;
            t2.err = "sftp unavailable";
        }
        session.sftp_transfers.unlock();
        return;
    };
    const path_z = allocator.dupeZ(u8, path) catch {
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t2| {
            t2.status = .failed;
            t2.err = "out of memory";
        }
        session.sftp_transfers.unlock();
        return;
    };
    defer allocator.free(path_z);
    const deadline = sftpDeadline(session);
    session.sftp_transfers.lock();
    const t = session.sftp_transfers.get(transfer_id) orelse {
        session.sftp_transfers.unlock();
        return;
    };
    t.status = .running;
    session.sftp_transfers.unlock();
    const total = sftpCountEntries(session, sftp, path_z, deadline) orelse {
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t2| t2.status = .failed;
        session.sftp_transfers.unlock();
        return;
    };
    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(transfer_id)) |t2| t2.bytes_total = total;
    session.sftp_transfers.unlock();
    if (!sftpDeleteRecursive(session, sftp, path_z, transfer_id, deadline)) {
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t2| {
            t2.status = if (t2.cancel_flag) .canceled else .failed;
            t2.err = if (t2.cancel_flag) "canceled" else "delete failed";
        }
        session.sftp_transfers.unlock();
        return;
    }
    sftpAudit(session, "sftp.rm", path);
    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(transfer_id)) |t2| t2.status = .done;
    session.sftp_transfers.unlock();
}

/// Streams a remote file into `<local_final>.partial`, then no-clobber
/// renames it to `local_final`. Progress rides the transfer record; returns
/// false on failure (partial removed). Shared by downloads and zipDownload.
fn sftpStreamRemoteToLocal(
    session: *Session,
    sftp: *ssh.c.LIBSSH2_SFTP,
    remote_z: [:0]const u8,
    local_partial: []const u8,
    local_final: []const u8,
    transfer_id: u32,
    deadline: i128,
) bool {
    const cwd = std.Io.Dir.cwd();
    const handle = sftpOpen(session, sftp, remote_z, ssh.c.LIBSSH2_FXF_READ, 0, ssh.c.LIBSSH2_SFTP_OPENFILE, deadline) orelse return false;
    defer _ = ssh.c.libssh2_sftp_close_handle(handle);

    var attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
    if (!sftpFstat(session, handle, &attrs, deadline)) return false;
    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(transfer_id)) |t| t.bytes_total = attrs.filesize;
    session.sftp_transfers.unlock();

    var file = cwd.createFile(session.io, local_partial, .{ .truncate = true }) catch return false;
    var done_bytes: u64 = 0;
    var buf: [sftpmod.chunk_size]u8 = undefined;
    while (true) {
        if (transferCanceled(session, transfer_id)) {
            file.close(session.io);
            cwd.deleteFile(session.io, local_partial) catch {};
            return false;
        }
        const n = sftpRead(session, handle, &buf, deadline) orelse {
            file.close(session.io);
            cwd.deleteFile(session.io, local_partial) catch {};
            return false;
        };
        if (n == 0) break;
        file.writeStreamingAll(session.io, buf[0..n]) catch {
            file.close(session.io);
            cwd.deleteFile(session.io, local_partial) catch {};
            return false;
        };
        done_bytes += n;
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t| t.bytes_done = done_bytes;
        session.sftp_transfers.unlock();
    }
    file.close(session.io);

    // No-clobber finalize on the local side.
    if (cwd.access(session.io, local_final, .{})) |_| {
        cwd.deleteFile(session.io, local_partial) catch {};
        return false;
    } else |_| {}
    std.Io.Dir.renameAbsolute(local_partial, local_final, session.io) catch {
        cwd.deleteFile(session.io, local_partial) catch {};
        return false;
    };
    return true;
}

fn sftpOpUploadLocal(session: *Session, local: []const u8, remote: []const u8, transfer_id: u32) void {
    const allocator = session.allocator;
    defer allocator.free(local);
    defer allocator.free(remote);

    const fail = struct {
        fn call(s: *Session, id: u32, message: []const u8) void {
            s.sftp_transfers.lock();
            if (s.sftp_transfers.get(id)) |transfer| {
                transfer.status = if (transfer.cancel_flag) .canceled else .failed;
                transfer.err = if (transfer.cancel_flag) "canceled" else message;
            }
            s.sftp_transfers.unlock();
        }
    }.call;

    var file = std.Io.Dir.openFileAbsolute(session.io, local, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    }) catch {
        fail(session, transfer_id, "cannot open local file");
        return;
    };
    defer file.close(session.io);
    const stat = file.stat(session.io) catch {
        fail(session, transfer_id, "cannot stat local file");
        return;
    };
    if (stat.kind != .file) {
        fail(session, transfer_id, "local selection is not a regular file");
        return;
    }

    const sftp = sftpSessionHandle(session, null) orelse {
        fail(session, transfer_id, "sftp unavailable");
        return;
    };
    const deadline = sftpDeadline(session);
    const partial = partialPath(allocator, remote) catch {
        fail(session, transfer_id, "out of memory");
        return;
    };
    defer allocator.free(partial);
    const partial_z = allocator.dupeZ(u8, partial) catch {
        fail(session, transfer_id, "out of memory");
        return;
    };
    defer allocator.free(partial_z);
    const remote_z = allocator.dupeZ(u8, remote) catch {
        fail(session, transfer_id, "out of memory");
        return;
    };
    defer allocator.free(remote_z);

    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(transfer_id)) |transfer| {
        transfer.status = .running;
        transfer.bytes_total = stat.size;
    }
    session.sftp_transfers.unlock();

    const flags: c_ulong = ssh.c.LIBSSH2_FXF_WRITE | ssh.c.LIBSSH2_FXF_CREAT | ssh.c.LIBSSH2_FXF_TRUNC;
    const remote_handle = sftpOpen(session, sftp, partial_z, flags, 0o600, ssh.c.LIBSSH2_SFTP_OPENFILE, deadline) orelse {
        fail(session, transfer_id, "cannot create remote partial file");
        return;
    };
    var remote_open = true;
    defer if (remote_open) {
        _ = ssh.c.libssh2_sftp_close_handle(remote_handle);
    };

    var reader_buffer: [sftpmod.chunk_size]u8 = undefined;
    var file_reader = file.reader(session.io, &reader_buffer);
    var chunk: [sftpmod.chunk_size]u8 = undefined;
    var written: u64 = 0;
    while (true) {
        if (transferCanceled(session, transfer_id)) {
            _ = ssh.c.libssh2_sftp_close_handle(remote_handle);
            remote_open = false;
            _ = ssh.c.libssh2_sftp_unlink_ex(sftp, partial_z.ptr, @intCast(partial_z.len));
            fail(session, transfer_id, "canceled");
            return;
        }
        const n = file_reader.interface.readSliceShort(&chunk) catch {
            _ = ssh.c.libssh2_sftp_close_handle(remote_handle);
            remote_open = false;
            _ = ssh.c.libssh2_sftp_unlink_ex(sftp, partial_z.ptr, @intCast(partial_z.len));
            fail(session, transfer_id, "local read failed");
            return;
        };
        if (n == 0) break;
        if (!sftpWriteAll(session, remote_handle, chunk[0..n], deadline)) {
            _ = ssh.c.libssh2_sftp_close_handle(remote_handle);
            remote_open = false;
            _ = ssh.c.libssh2_sftp_unlink_ex(sftp, partial_z.ptr, @intCast(partial_z.len));
            fail(session, transfer_id, "remote write failed");
            return;
        }
        written += n;
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |transfer| transfer.bytes_done = written;
        session.sftp_transfers.unlock();
    }
    _ = ssh.c.libssh2_sftp_close_handle(remote_handle);
    remote_open = false;

    if (written != stat.size or !sftpRenameEx(session, sftp, partial_z, remote_z, 0, deadline)) {
        _ = ssh.c.libssh2_sftp_unlink_ex(sftp, partial_z.ptr, @intCast(partial_z.len));
        fail(session, transfer_id, if (written != stat.size) "local file changed during upload" else "target already exists; upload refused");
        return;
    }
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "local={s} remote={s} bytes={d}", .{ local, remote, written }) catch "sftp.upload_local";
    sftpAudit(session, "sftp.upload_local", detail);
    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(transfer_id)) |transfer| {
        transfer.bytes_done = written;
        transfer.status = .done;
    }
    session.sftp_transfers.unlock();
}

fn sftpOpDownload(
    session: *Session,
    remote: []const u8,
    local_partial: []const u8,
    local_final: []const u8,
    transfer_id: u32,
    outcome: ?*SftpOutcome,
) void {
    const allocator = session.allocator;
    defer allocator.free(remote);
    defer allocator.free(local_partial);
    defer allocator.free(local_final);
    const sftp = sftpSessionHandle(session, outcome) orelse {
        // With no outcome to report through, the failure rides the
        // transfer record — never leave a download stuck at queued.
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t| {
            t.status = .failed;
            t.err = "sftp unavailable";
        }
        session.sftp_transfers.unlock();
        return;
    };
    const deadline = sftpDeadline(session);
    const remote_z = allocator.dupeZ(u8, remote) catch {
        if (outcome) |o| o.set(false, "out of memory");
        return;
    };
    defer allocator.free(remote_z);

    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(transfer_id)) |t| t.status = .running;
    session.sftp_transfers.unlock();
    if (!sftpStreamRemoteToLocal(session, sftp, remote_z, local_partial, local_final, transfer_id, deadline)) {
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t| {
            t.status = if (t.cancel_flag) .canceled else .failed;
            t.err = if (t.cancel_flag) "canceled" else "download failed";
        }
        session.sftp_transfers.unlock();
        return;
    }
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "path={s}", .{remote}) catch "sftp.download";
    sftpAudit(session, "sftp.download", detail);
    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(transfer_id)) |t| t.status = .done;
    session.sftp_transfers.unlock();
}

fn zipErrorString(err: sftpmod.ZipError) []const u8 {
    return switch (err) {
        error.NotAZip => "not a zip archive",
        error.Truncated => "archive is truncated",
        error.UnsupportedZip64 => "zip64 archives are not supported",
        error.TooManyEntries => "archive has too many entries",
        error.EntryTooLarge => "an entry exceeds the size limit",
        error.TotalTooLarge => "total uncompressed size exceeds the limit",
        error.AbsolutePath => "archive contains an absolute path",
        error.ParentTraversal => "archive contains a parent-directory traversal",
        error.DriveLetter => "archive contains a drive-letter path",
        error.SymlinkEntry => "archive contains a symlink entry",
        error.DuplicateEntry => "archive contains duplicate entries",
        error.FileDirConflict => "archive has a file/directory conflict",
        error.PathTooLong => "an entry path is too long",
        error.DepthTooDeep => "an entry nests too deeply",
        error.CompressionRatioExceeded => "compression ratio exceeds the limit",
        error.UnsupportedMethod => "unsupported compression method",
        error.InvalidName => "an entry name is invalid",
        error.OutOfMemory => "out of memory",
    };
}

/// mkdir -p semantics over SFTP: creates each missing component. Absolute
/// paths walk from "/" so every component stays absolute (SFTP paths are
/// otherwise server-cwd-relative, and a relative walk would silently build
/// a parallel tree under the home directory).
fn sftpMkdirP(session: *Session, sftp: *ssh.c.LIBSSH2_SFTP, path_z: [:0]const u8, deadline: i128) bool {
    const allocator = session.allocator;
    var components: std.ArrayList([]const u8) = .empty;
    defer {
        // The component buffers are owned here (a defer inside the loop
        // body would free each buffer at iteration end, dangling the list).
        for (components.items) |c| allocator.free(c);
        components.deinit(allocator);
    }
    var root: [1]u8 = .{'/'};
    var cur: []u8 = if (path_z.len > 0 and path_z[0] == '/') root[0..] else &[_]u8{};
    var it = std.mem.splitScalar(u8, path_z, '/');
    while (it.next()) |part| {
        if (part.len == 0) continue;
        const next = joinPath(allocator, cur, part) catch return false;
        components.append(allocator, next) catch {
            allocator.free(next);
            return false;
        };
        cur = next;
    }
    for (components.items) |component| {
        const z = allocator.dupeZ(u8, component) catch return false;
        defer allocator.free(z);
        if (!sftpMkdir(session, sftp, z, 0o755, deadline)) {
            // Already exists is fine (mkdir -p semantics); anything else fails.
            var attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
            if (!sftpLstat(session, sftp, z, &attrs, deadline)) return false;
            if (attrs.permissions & ssh.c.LIBSSH2_SFTP_S_IFMT != ssh.c.LIBSSH2_SFTP_S_IFDIR) return false;
        }
    }
    return true;
}

fn sftpOpUnzip(session: *Session, zip_path: []const u8, dest: []const u8, transfer_id: u32, outcome: ?*SftpOutcome) void {
    const allocator = session.allocator;
    defer allocator.free(zip_path);
    defer allocator.free(dest);
    const sftp = sftpSessionHandle(session, outcome) orelse {
        // With no outcome to report through, the failure rides the
        // transfer record — never leave an unzip stuck at queued.
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t| {
            t.status = .failed;
            t.err = "sftp unavailable";
        }
        session.sftp_transfers.unlock();
        return;
    };
    const deadline = sftpDeadline(session);
    const zip_z = allocator.dupeZ(u8, zip_path) catch {
        if (outcome) |o| o.set(false, "out of memory");
        return;
    };
    defer allocator.free(zip_z);

    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(transfer_id)) |t| t.status = .running;
    session.sftp_transfers.unlock();

    const fail_transfer = struct {
        fn call(s: *Session, id: u32, msg: []const u8) void {
            s.sftp_transfers.lock();
            if (s.sftp_transfers.get(id)) |t| {
                t.status = .failed;
                t.err = msg;
            }
            s.sftp_transfers.unlock();
        }
    }.call;

    // Read the whole archive (bounded) for the central-directory preflight.
    const zip_limits = sftpmod.ZipLimits{};
    var attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
    if (!sftpLstat(session, sftp, zip_z, &attrs, deadline)) {
        fail_transfer(session, transfer_id, "cannot stat the archive");
        return;
    }
    if (attrs.filesize > zip_limits.max_archive_bytes) {
        fail_transfer(session, transfer_id, "archive too large");
        return;
    }
    const handle = sftpOpen(session, sftp, zip_z, ssh.c.LIBSSH2_FXF_READ, 0, ssh.c.LIBSSH2_SFTP_OPENFILE, deadline) orelse {
        fail_transfer(session, transfer_id, "cannot open the archive");
        return;
    };
    var zip_bytes: std.ArrayList(u8) = .empty;
    defer zip_bytes.deinit(allocator);
    var buf: [sftpmod.chunk_size]u8 = undefined;
    while (true) {
        if (transferCanceled(session, transfer_id)) {
            _ = ssh.c.libssh2_sftp_close_handle(handle);
            fail_transfer(session, transfer_id, "canceled");
            return;
        }
        const n = sftpRead(session, handle, &buf, deadline) orelse {
            _ = ssh.c.libssh2_sftp_close_handle(handle);
            fail_transfer(session, transfer_id, "read failed");
            return;
        };
        if (n == 0) break;
        if (zip_bytes.items.len + n > zip_limits.max_archive_bytes) {
            _ = ssh.c.libssh2_sftp_close_handle(handle);
            fail_transfer(session, transfer_id, "archive too large");
            return;
        }
        zip_bytes.appendSlice(allocator, buf[0..n]) catch {
            _ = ssh.c.libssh2_sftp_close_handle(handle);
            fail_transfer(session, transfer_id, "out of memory");
            return;
        };
    }
    _ = ssh.c.libssh2_sftp_close_handle(handle);

    const entries = sftpmod.scanZipCentralDirectory(allocator, zip_bytes.items, .{}) catch |err| {
        fail_transfer(session, transfer_id, zipErrorString(err));
        return;
    };
    defer allocator.free(entries);

    // Overwrite is disabled: every target must be absent before anything
    // is written (spec 05 §5).
    const dest_z = allocator.dupeZ(u8, dest) catch {
        fail_transfer(session, transfer_id, "out of memory");
        return;
    };
    defer allocator.free(dest_z);
    if (!sftpMkdirP(session, sftp, dest_z, deadline)) {
        fail_transfer(session, transfer_id, "cannot create the destination directory");
        return;
    }
    for (entries) |entry| {
        if (transferCanceled(session, transfer_id)) {
            fail_transfer(session, transfer_id, "canceled");
            return;
        }
        const target = joinPath(allocator, dest, entry.name) catch {
            fail_transfer(session, transfer_id, "out of memory");
            return;
        };
        defer allocator.free(target);
        const target_z = allocator.dupeZ(u8, target) catch {
            fail_transfer(session, transfer_id, "out of memory");
            return;
        };
        defer allocator.free(target_z);
        var target_attrs: ssh.c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
        if (sftpLstat(session, sftp, target_z, &target_attrs, deadline)) {
            fail_transfer(session, transfer_id, "a target already exists; choose an empty destination");
            return;
        }
    }

    // Extract.
    var total_done: u64 = 0;
    var total_size: u64 = 0;
    for (entries) |entry| total_size +|= entry.uncompressed_size;
    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(transfer_id)) |t| t.bytes_total = total_size;
    session.sftp_transfers.unlock();

    for (entries) |entry| {
        if (transferCanceled(session, transfer_id)) {
            fail_transfer(session, transfer_id, "canceled");
            return;
        }
        const target = joinPath(allocator, dest, entry.name) catch {
            fail_transfer(session, transfer_id, "out of memory");
            return;
        };
        defer allocator.free(target);
        const target_z = allocator.dupeZ(u8, target) catch {
            fail_transfer(session, transfer_id, "out of memory");
            return;
        };
        defer allocator.free(target_z);
        if (entry.is_dir) {
            if (!sftpMkdirP(session, sftp, target_z, deadline)) {
                fail_transfer(session, transfer_id, "cannot create directory");
                return;
            }
            continue;
        }
        const dir = std.fs.path.dirname(target) orelse dest;
        const dir_z = allocator.dupeZ(u8, dir) catch {
            fail_transfer(session, transfer_id, "out of memory");
            return;
        };
        defer allocator.free(dir_z);
        if (!sftpMkdirP(session, sftp, dir_z, deadline)) {
            fail_transfer(session, transfer_id, "cannot create directory");
            return;
        }
        const out_handle = sftpOpen(session, sftp, target_z, ssh.c.LIBSSH2_FXF_WRITE | ssh.c.LIBSSH2_FXF_CREAT, 0o644, ssh.c.LIBSSH2_SFTP_OPENFILE, deadline) orelse {
            var msg_buf: [256]u8 = undefined;
            fail_transfer(session, transfer_id, sftpFail(session, "cannot create entry file", &msg_buf));
            return;
        };
        var wrote: u64 = 0;
        const data_start = entry.local_offset + 30 + localHeaderNameExtra(zip_bytes.items, entry.local_offset);
        if (entry.method == 0) {
            const data = zip_bytes.items[data_start .. data_start + entry.compressed_size];
            if (!sftpWriteAll(session, out_handle, data, deadline)) {
                _ = ssh.c.libssh2_sftp_close_handle(out_handle);
                fail_transfer(session, transfer_id, "write failed");
                return;
            }
            wrote = data.len;
        } else {
            const compressed = zip_bytes.items[data_start .. data_start + entry.compressed_size];
            var mem = std.Io.Reader.fixed(compressed);
            var window: [std.compress.flate.max_window_len]u8 = undefined;
            var decomp = std.compress.flate.Decompress.init(&mem, .raw, &window);
            var out_buf: [sftpmod.chunk_size]u8 = undefined;
            while (wrote < entry.uncompressed_size) {
                const remaining: usize = @intCast(@min(entry.uncompressed_size - wrote, out_buf.len));
                const n = decomp.reader.readSliceShort(out_buf[0..remaining]) catch {
                    _ = ssh.c.libssh2_sftp_close_handle(out_handle);
                    fail_transfer(session, transfer_id, "decompression failed");
                    return;
                };
                if (n == 0) break;
                if (!sftpWriteAll(session, out_handle, out_buf[0..n], deadline)) {
                    _ = ssh.c.libssh2_sftp_close_handle(out_handle);
                    fail_transfer(session, transfer_id, "write failed");
                    return;
                }
                wrote += n;
            }
        }
        if (wrote != entry.uncompressed_size) {
            _ = ssh.c.libssh2_sftp_close_handle(out_handle);
            fail_transfer(session, transfer_id, "entry size mismatch after decompression");
            return;
        }
        _ = ssh.c.libssh2_sftp_close_handle(out_handle);
        total_done += wrote;
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t| t.bytes_done = total_done;
        session.sftp_transfers.unlock();
    }
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "zip={s} dest={s} entries={d}", .{ zip_path, dest, entries.len }) catch "sftp.unzip";
    sftpAudit(session, "sftp.unzip", detail);
    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(transfer_id)) |t| t.status = .done;
    session.sftp_transfers.unlock();
}

/// Reads the local file header's name+extra length at `offset`.
fn localHeaderNameExtra(bytes: []const u8, offset: u64) usize {
    const off: usize = @intCast(offset);
    if (off + 30 > bytes.len) return 0;
    const name_len = std.mem.readInt(u16, bytes[off + 26 ..][0..2], .little);
    const extra_len = std.mem.readInt(u16, bytes[off + 28 ..][0..2], .little);
    return name_len + extra_len;
}

/// One-shot exec on the worker (zip staging, etc.): drains to EOF, bounded.
fn execSync(session: *Session, command: []const u8, max_bytes: usize) !ExecOutcome {
    const raw = try session.transport.openChannel(session.io);
    defer raw.close(session.io);
    try raw.exec(session.io, command);
    var out = ExecOutcome{ .output = .empty };
    errdefer out.output.deinit(session.allocator);
    var buf: [32 * 1024]u8 = undefined;
    while (true) {
        switch (raw.read(&buf)) {
            .eof => break,
            .data => |n| {
                if (out.output.items.len + n > max_bytes) return error.TooLong;
                try out.output.appendSlice(session.allocator, buf[0..n]);
            },
            .again => {
                if (session.stop_flag.load(.acquire)) return error.Canceled;
                std.Io.sleep(session.io, std.Io.Duration.fromMilliseconds(10), .awake) catch return error.Canceled;
            },
        }
    }
    out.exit = raw.exitStatus();
    return out;
}

/// Longest common directory of absolute paths (for zipDownload staging).
/// The prefix of a single path is the path itself, which may be a file —
/// zipDownload needs the containing directory (the rel-path walk then
/// stays correct).
fn commonDir(paths: []const []const u8) []const u8 {
    var common: []const u8 = paths[0];
    for (paths[1..]) |p| {
        var i: usize = 0;
        while (i < common.len and i < p.len and common[i] == p[i]) : (i += 1) {}
        while (i > 0 and common[i - 1] != '/') : (i -= 1) {}
        common = common[0..i];
    }
    if (common.len == 0) return "/";
    for (paths) |p| {
        if (std.mem.eql(u8, p, common)) {
            return std.fs.path.dirname(common) orelse common;
        }
    }
    return common;
}

fn sftpOpZipDownload(
    session: *Session,
    paths: [][]const u8,
    local_partial: []const u8,
    local_final: []const u8,
    transfer_id: u32,
    outcome: ?*SftpOutcome,
) void {
    const allocator = session.allocator;
    defer {
        for (paths) |p| allocator.free(p);
        allocator.free(paths);
        allocator.free(local_partial);
        allocator.free(local_final);
    }
    const sftp = sftpSessionHandle(session, outcome) orelse {
        // With no outcome to report through, the failure rides the
        // transfer record — never leave a zip download stuck at queued.
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t| {
            t.status = .failed;
            t.err = "sftp unavailable";
        }
        session.sftp_transfers.unlock();
        return;
    };
    const deadline = sftpDeadline(session);

    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(transfer_id)) |t| t.status = .running;
    session.sftp_transfers.unlock();

    const fail_transfer = struct {
        fn call(s: *Session, id: u32, msg: []const u8) void {
            s.sftp_transfers.lock();
            if (s.sftp_transfers.get(id)) |t| {
                t.status = .failed;
                t.err = msg;
            }
            s.sftp_transfers.unlock();
        }
    }.call;

    const dir = commonDir(paths);
    const staging = std.fmt.allocPrint(allocator, "{s}/.oars-zip-{d}.zip", .{ dir, session.next_channel_id.fetchAdd(1, .monotonic) }) catch {
        fail_transfer(session, transfer_id, "out of memory");
        return;
    };
    defer allocator.free(staging);
    // Staging cleanup in success AND failure (spec 05 §5).
    const staging_z = allocator.dupeZ(u8, staging) catch {
        fail_transfer(session, transfer_id, "out of memory");
        return;
    };
    defer allocator.free(staging_z);
    defer _ = ssh.c.libssh2_sftp_unlink_ex(sftp, staging_z.ptr, @intCast(staging_z.len));

    var cmd: std.ArrayList(u8) = .empty;
    defer cmd.deinit(allocator);
    const dir_q = shellquote.quote(allocator, dir) catch {
        fail_transfer(session, transfer_id, "out of memory");
        return;
    };
    defer allocator.free(dir_q);
    const staging_q = shellquote.quote(allocator, staging) catch {
        fail_transfer(session, transfer_id, "out of memory");
        return;
    };
    defer allocator.free(staging_q);
    const head = std.fmt.allocPrint(allocator, "cd {s} && zip -r {s}", .{ dir_q, staging_q }) catch {
        fail_transfer(session, transfer_id, "out of memory");
        return;
    };
    defer allocator.free(head);
    cmd.appendSlice(allocator, head) catch {
        fail_transfer(session, transfer_id, "out of memory");
        return;
    };
    for (paths) |p| {
        const rel = if (std.mem.startsWith(u8, p, dir)) p[dir.len..] else p;
        const rel_trimmed = std.mem.trimStart(u8, rel, "/");
        var qbuf: [4096]u8 = undefined;
        if (shellquote.quotedLen(rel_trimmed) > qbuf.len) {
            fail_transfer(session, transfer_id, "path too long");
            return;
        }
        const quoted = shellquote.quoteAppend(&qbuf, rel_trimmed);
        cmd.append(allocator, ' ') catch {
            fail_transfer(session, transfer_id, "out of memory");
            return;
        };
        cmd.appendSlice(allocator, quoted) catch {
            fail_transfer(session, transfer_id, "out of memory");
            return;
        };
    }
    cmd.appendSlice(allocator, " 2>&1") catch {
        fail_transfer(session, transfer_id, "out of memory");
        return;
    };

    var result = execSync(session, cmd.items, 64 * 1024) catch |err| {
        fail_transfer(session, transfer_id, switch (err) {
            error.Canceled => "canceled",
            error.TooLong => "zip output too large",
            else => "zip failed to start",
        });
        return;
    };
    defer result.output.deinit(allocator);
    if (result.exit != 0) {
        const tail = if (result.output.items.len > 200) result.output.items[result.output.items.len - 200 ..] else result.output.items;
        var msg_buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "zip failed (exit {d}): {s}", .{ result.exit, tail }) catch "zip failed";
        fail_transfer(session, transfer_id, msg);
        return;
    }

    if (!sftpStreamRemoteToLocal(session, sftp, staging_z, local_partial, local_final, transfer_id, deadline)) {
        session.sftp_transfers.lock();
        if (session.sftp_transfers.get(transfer_id)) |t| {
            t.status = if (t.cancel_flag) .canceled else .failed;
            t.err = if (t.cancel_flag) "canceled" else "download failed";
        }
        session.sftp_transfers.unlock();
        return;
    }
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "paths={d} zip={s}", .{ paths.len, staging }) catch "sftp.zip_download";
    sftpAudit(session, "sftp.zip_download", detail);
    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(transfer_id)) |t| t.status = .done;
    session.sftp_transfers.unlock();
}

fn sftpOpCancel(session: *Session, transfer_id: u32) void {
    const allocator = session.allocator;
    session.sftp_transfers.lock();
    const t = session.sftp_transfers.get(transfer_id) orelse {
        session.sftp_transfers.unlock();
        return;
    };
    t.cancel_flag = true;
    const is_upload = std.mem.eql(u8, t.kind, "upload");
    session.sftp_transfers.unlock();
    if (!is_upload) return;
    // Uploads are driven by chunks: the cancel op deletes the partial and
    // marks the transfer (spec 05 §5).
    const sftp = session.transport.sftpInit(session.io) catch return;
    const partial = partialPath(allocator, t.path) catch return;
    defer allocator.free(partial);
    const partial_z = allocator.dupeZ(u8, partial) catch return;
    defer allocator.free(partial_z);
    const deadline = sftpDeadline(session);
    _ = sftpUnlink(session, sftp, partial_z, deadline);
    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(transfer_id)) |t2| t2.status = .canceled;
    session.sftp_transfers.unlock();
}

/// Surfaces a key-auth failure to the frontend with libssh2's own
/// message appended (it carries the useful detail).
fn reportKeyAuthError(session: *Session, error_buf: []u8, err: ssh.Error) void {
    session.status.store(.@"error", .release);
    var msg_buf: [256]u8 = undefined;
    const msg = session.transport.lastErrorMessage(&msg_buf);
    session.setError(std.fmt.bufPrint(error_buf, "key authentication failed: {s} ({s})", .{ @errorName(err), msg }) catch "key authentication failed");
}

/// Cleans up the session at the end of the worker's life. The session
/// stays in the manager map until disconnect, so every container the
/// bridge can reach must be left VALID-but-empty (clearAndFree, or a
/// locked cache deinit), never deinit-poisoned: the 80 ms poll loop,
/// keystrokes, and SFTP/monitor/tunnel handlers all keep arriving after
/// the worker dies, and Zig 0.16's ArrayList.deinit writes `undefined`
/// (0xAA in Debug) into the list — the idle-session segfault. The ops
/// drain runs last and publishes `worker_done` inside its ops_mutex
/// section, so op-enqueue paths checking the flag under the same mutex
/// either have their op drained below or reject it.
fn sessionDone(session: *Session) void {
    if (session.transport.session_open) session.transport.setAuthAgentCallback(null);
    // Channels first: nulling the shell under channels_mutex makes a
    // concurrent input() fail honestly instead of writing into an entry
    // being destroyed here.
    lockSpin(&session.channels_mutex);
    for (session.channels.items) |entry| {
        if (!entry.raw_closed) entry.raw.close(session.io);
        // Spec 06: an in-flight syntax check must complete honestly — the
        // broadcast poll reads the outcome and frees the slot; without
        // this it would poll a dead session's check forever.
        if (entry.check_outcome) |oc| {
            oc.set(null, "session disconnected");
        }
        if (entry.ai_context_outcome) |outcome| {
            outcome.complete(null, "", "session disconnected", false, true);
        }
        if (entry.access_exec_outcome) |oc| {
            oc.set(null, "", "session disconnected");
        }
        if (entry.backup_outcome) |oc| {
            oc.set(.disconnected, null, fx_unknown, false, "", "session disconnected");
        }
        if (entry.backup_process) |process| {
            process.complete(null, true, "session disconnected");
        }
        if (entry.preflight_probe) |pp| {
            pp.set(null, "", "session disconnected");
        }
        entry.clearStdin(session.allocator);
        entry.freeCommandText(session.allocator);
        entry.stream.deinit(session.allocator);
        session.allocator.destroy(entry.stream);
        session.allocator.destroy(entry);
    }
    session.shell = null;
    session.channels.clearAndFree(session.allocator);
    session.channels_mutex.unlock();

    // The monitor cache has no internal lock; bridge handlers serialize
    // against it, so teardown must take the same lock.
    session.monitor_cache.lock();
    session.monitor_cache.deinit(session.allocator);
    session.monitor_cache.unlock();
    session.logs_cache.deinit(session.allocator);
    session.sftp_transfers.reset(session.allocator);
    for (session.folder_size_cache.items) |e| session.allocator.free(e.path);
    session.folder_size_cache.clearAndFree(session.allocator);

    // VNC tunnels: everything dies with the session (spec 12 §8).
    lockSpin(&session.tunnels_mutex);
    for (session.tunnels.items) |t| {
        t.setError("session disconnected");
        t.state = .closed;
        t.deinit(session.allocator, session.io);
        session.allocator.destroy(t);
    }
    session.tunnels.clearAndFree(session.allocator);
    session.tunnels_mutex.unlock();

    // Jump-host tunnels (spec 18): everything dies with the via session,
    // and dependants get a clear cascade close state. The dependant is
    // resolved under the manager mutex (cascadeCloseDependant) so a
    // concurrent disconnect cannot tear it down mid-update.
    lockSpin(&session.tunnels_mutex);
    for (session.jump_tunnels.items) |jt| {
        session.owner.cascadeCloseDependant(jt.target_server_id, session.server.name);
        jt.deinit(session.allocator, session.io);
        session.allocator.destroy(jt);
    }
    session.jump_tunnels.clearAndFree(session.allocator);
    session.tunnels_mutex.unlock();
    if (session.via_name) |n| session.allocator.free(n);

    closeForwardTunnels(session);
    if (session.forward_agent_path) |p| session.allocator.free(p);

    session.transport.disconnect(session.io);
    const status = session.status.load(.acquire);
    if (status != .@"error" and status != .closed) session.status.store(.closed, .release);

    lockSpin(&session.ops_mutex);
    for (session.ops.items) |op| {
        switch (op) {
            .exec => |e| {
                session.allocator.free(e.command);
                if (e.stdin_data) |input| {
                    std.crypto.secureZero(u8, input);
                    session.allocator.free(input);
                }
                if (e.history_kind) |hk| session.allocator.free(hk);
                if (e.history_command) |hc| session.allocator.free(hc);
                if (e.history_operation_id) |operation_id| session.allocator.free(operation_id);
                if (e.history_secrets) |hs| {
                    for (hs) |s| session.allocator.free(s);
                    session.allocator.free(hs);
                }
            },
            .follow => |f| session.allocator.free(f.command),
            .syntax_check => |sc| {
                session.allocator.free(sc.command);
                sc.outcome.set(null, "session disconnected");
            },
            .access_exec => |ae| {
                session.allocator.free(ae.command);
                ae.outcome.set(null, "", "session disconnected");
            },
            .ai_context => |probe| {
                session.allocator.free(probe.operation_id);
                session.allocator.free(probe.command);
                probe.outcome.complete(null, "", "session disconnected", false, true);
            },
            .ai_context_cancel => |cancel| session.allocator.free(cancel.operation_id),
            .backup => |value| {
                freeBackupRequest(session.allocator, value.request);
                value.outcome.set(.disconnected, null, fx_unknown, false, "", "session disconnected");
            },
            .backup_run => |value| {
                session.allocator.free(value.command);
                if (value.stdin_data) |input| secureFreeBytes(session.allocator, input);
                value.process.complete(null, true, "session disconnected");
            },
            .clear => |cl| {
                session.allocator.free(cl.path);
                cl.outcome.set(false, "session disconnected");
            },
            .sftp_ls => |so| {
                session.allocator.free(so.path);
                so.outcome.set(false, "session disconnected");
            },
            .sftp_stat => |so| {
                session.allocator.free(so.path);
                so.outcome.set(false, "session disconnected");
            },
            .sftp_read => |so| {
                session.allocator.free(so.path);
                so.outcome.set(false, "session disconnected");
            },
            .sftp_write_chunk => |so| {
                session.allocator.free(so.path);
                session.allocator.free(so.data);
                so.outcome.set(false, "session disconnected");
            },
            .sftp_save => |so| {
                session.allocator.free(so.path);
                session.allocator.free(so.data);
                if (so.expected) |identity| if (identity.sha256) |sha| session.allocator.free(sha);
                so.outcome.set(false, "session disconnected");
            },
            .sftp_mkdir => |so| {
                session.allocator.free(so.path);
                so.outcome.set(false, "session disconnected");
            },
            .sftp_rm => |so| {
                session.allocator.free(so.path);
                if (so.outcome) |o| o.set(false, "session disconnected");
            },
            .sftp_rename => |so| {
                session.allocator.free(so.from);
                session.allocator.free(so.to);
                so.outcome.set(false, "session disconnected");
            },
            .sftp_chmod => |so| {
                session.allocator.free(so.path);
                so.outcome.set(false, "session disconnected");
            },
            .sftp_download => |so| {
                session.allocator.free(so.remote);
                session.allocator.free(so.local_partial);
                session.allocator.free(so.local_final);
                if (so.outcome) |o| o.set(false, "session disconnected");
            },
            .sftp_upload_local => |so| {
                session.allocator.free(so.local);
                session.allocator.free(so.remote);
                session.sftp_transfers.lock();
                if (session.sftp_transfers.get(so.transfer_id)) |transfer| {
                    transfer.status = .failed;
                    transfer.err = "session disconnected";
                }
                session.sftp_transfers.unlock();
            },
            .sftp_unzip => |so| {
                session.allocator.free(so.zip_path);
                session.allocator.free(so.dest);
                if (so.outcome) |o| o.set(false, "session disconnected");
            },
            .sftp_zip_download => |so| {
                for (so.paths) |p| session.allocator.free(p);
                session.allocator.free(so.paths);
                session.allocator.free(so.local_partial);
                session.allocator.free(so.local_final);
                if (so.outcome) |o| o.set(false, "session disconnected");
            },
            .tunnel_start => |t| {
                session.allocator.free(t.token);
                session.allocator.free(t.host);
                t.outcome.set(false, 0, "session disconnected");
            },
            .forward_set => |f| f.outcome.set(false, "session disconnected"),
            .jump_start => |j| {
                session.allocator.free(j.host);
                session.allocator.free(j.target_server_id);
                if (!j.outcome.isDone()) {
                    // The target session's worker spin-waits on this
                    // outcome with no deadline: leaving it unset hangs
                    // that worker (and disconnect's join) forever.
                    j.outcome.set(false, "jump host disconnected");
                    _ = ssh.c.close(j.fd);
                }
            },
            else => {},
        }
    }
    session.ops.clearAndFree(session.allocator);
    session.worker_done.store(true, .release);
    session.ops_mutex.unlock();
}

/// Stop signal for the transport's deadline loops: disconnect sets the
/// session stop flag, and every loop checks it between iterations.
fn workerStop(ctx: ?*anyopaque) bool {
    const session: *Session = @ptrCast(@alignCast(ctx));
    return session.stop_flag.load(.acquire);
}

// --- tests ---------------------------------------------------------------

const ZeroCheckAllocator = struct {
    backing: std.mem.Allocator,
    watch_alloc_index: usize,
    alloc_index: usize = 0,
    watched_ptr: ?[*]u8 = null,
    watched_frees: usize = 0,
    dirty_frees: usize = 0,

    fn allocator(self: *ZeroCheckAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, return_address: usize) ?[*]u8 {
        const self: *ZeroCheckAllocator = @ptrCast(@alignCast(ctx));
        const result = self.backing.rawAlloc(len, alignment, return_address) orelse return null;
        if (self.alloc_index == self.watch_alloc_index) self.watched_ptr = result;
        self.alloc_index += 1;
        return result;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, return_address: usize) bool {
        const self: *ZeroCheckAllocator = @ptrCast(@alignCast(ctx));
        return self.backing.rawResize(memory, alignment, new_len, return_address);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, return_address: usize) ?[*]u8 {
        const self: *ZeroCheckAllocator = @ptrCast(@alignCast(ctx));
        return self.backing.rawRemap(memory, alignment, new_len, return_address);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, return_address: usize) void {
        const self: *ZeroCheckAllocator = @ptrCast(@alignCast(ctx));
        if (self.watched_ptr) |watched| {
            if (memory.ptr == watched) {
                self.watched_frees += 1;
                for (memory) |byte| {
                    if (byte != 0) {
                        self.dirty_frees += 1;
                        break;
                    }
                }
            }
        }
        self.backing.rawFree(memory, alignment, return_address);
    }
};

fn cloneBackupRequestsAllocationTest(allocator: std.mem.Allocator) !void {
    const exec = try cloneBackupRequest(allocator, .{ .exec = .{
        .command = "run-backup",
        .stdin_data = "sensitive backup stdin",
        .timeout_ns = std.time.ns_per_s,
        .cap = 4096,
        .history_command = "backup command",
        .sensitive_stdin = true,
    } });
    defer freeBackupRequest(allocator, exec);

    const write = try cloneBackupRequest(allocator, .{ .sftp_write = .{
        .path = "/remote/config",
        .data = "sensitive sftp payload",
        .sensitive = true,
    } });
    defer freeBackupRequest(allocator, write);

    const rename = try cloneBackupRequest(allocator, .{ .sftp_rename = .{
        .from = "/remote/from",
        .to = "/remote/to",
    } });
    defer freeBackupRequest(allocator, rename);
}

fn copyBackupOutcomeAllocationTest(allocator: std.mem.Allocator) !void {
    var outcome = BackupOutcome{ .allocator = std.testing.allocator, .done = true, .code = .ok };
    defer outcome.data.deinit(std.testing.allocator);
    const message = "backup complete";
    @memcpy(outcome.msg_buf[0..message.len], message);
    outcome.msg_len = message.len;
    try outcome.data.appendSlice(std.testing.allocator, "backup result payload");

    var result = try outcome.copyResult(allocator);
    defer result.deinit(allocator, false);
}

fn snapshotBackupProcessAllocationTest(allocator: std.mem.Allocator) !void {
    var process = BackupProcess{ .allocator = std.testing.allocator, .done = true, .exit = 0 };
    defer process.data.deinit(std.testing.allocator);
    const message = "process complete";
    @memcpy(process.msg_buf[0..message.len], message);
    process.msg_len = message.len;
    try process.data.appendSlice(std.testing.allocator, "streamed backup output");

    var snapshot = try process.snapshot(allocator, 0, 4096);
    defer snapshot.deinit(allocator);
}

const BackupAdmissionTestMode = enum { request, process };

const BackupAdmissionTestContext = struct {
    manager: *Manager,
    server_id: []const u8,
    mode: BackupAdmissionTestMode,
    outcome: *BackupOutcome,
    process: *BackupProcess,
    err: ?anyerror = null,

    fn run(self: *BackupAdmissionTestContext) void {
        switch (self.mode) {
            .request => self.manager.enqueueBackup(self.server_id, .{ .sftp_write = .{
                .path = "/remote/backup-config",
                .data = "secret request admitted during disconnect",
                .sensitive = true,
            } }, self.outcome) catch |err| {
                self.err = err;
            },
            .process => self.manager.startBackupProcess(self.server_id, "rclone backup", "secret process admitted during disconnect", self.process) catch |err| {
                self.err = err;
            },
        }
    }
};

fn backupAdmissionTestWorker(session: *Session) void {
    while (!session.stop_flag.load(.acquire)) std.atomic.spinLoopHint();
    sessionDone(session);
}

fn backupAdmissionTestDisconnect(manager: *Manager, server_id: []const u8) void {
    manager.disconnect(server_id);
}

const BackupDisconnectOrderProbe = struct {
    manager: *Manager,
    outcome: *BackupOutcome,
    called: bool = false,
    stop_was_clear: bool = false,
    normal_rejected: bool = false,
    cleanup_admitted: bool = false,

    fn prepare(context: *anyopaque, server_id: []const u8) bool {
        const self: *BackupDisconnectOrderProbe = @ptrCast(@alignCast(context));
        self.called = true;
        const session = self.manager.get(server_id) orelse return false;
        self.stop_was_clear = !session.stop_flag.load(.acquire);
        var process = BackupProcess{ .allocator = self.manager.allocator };
        defer process.data.deinit(self.manager.allocator);
        self.normal_rejected = if (self.manager.startBackupProcess(server_id, "must reject", null, &process)) |_| false else |err| err == error.NotReady;
        self.manager.enqueueBackupCleanup(server_id, .{ .sftp_stat = .{ .path = "/tmp/exact" } }, self.outcome) catch return false;
        self.cleanup_admitted = true;
        return true;
    }
};

test "backup disconnect hook runs before transport stop and admits cleanup only" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var store: servers.Store = .{ .allocator = allocator, .path = "/tmp/oars-backup-disconnect-order-servers.json" };
    var audit: history.AuditStore = .{ .allocator = allocator, .path = "/tmp/oars-backup-disconnect-order-audit.jsonl" };
    var history_store: history.HistoryStore = .{ .allocator = allocator, .path = "/tmp/oars-backup-disconnect-order-history.jsonl" };
    var manager = Manager.init(allocator, io, &store, &audit, &history_store, null);
    defer manager.deinit();

    const session = try allocator.create(Session);
    session.* = .{
        .id = 102,
        .server = try (servers.Server{ .id = "disconnect-order", .name = "backup", .host = "host", .user = "user" }).copy(allocator),
        .allocator = allocator,
        .threaded = std.Io.Threaded.init(allocator, .{}),
        .io = undefined,
        .transport = try ssh.Session.init(allocator),
        .store = &store,
        .audit = &audit,
        .history = &history_store,
        .owner = &manager,
        .started_at_ns = std.Io.Timestamp.now(io, .real).nanoseconds,
    };
    session.io = session.threaded.io();
    session.status.store(.ready, .release);
    const key = try allocator.dupe(u8, session.server.id);
    lockSpin(&manager.mutex);
    try manager.sessions.put(key, session);
    manager.mutex.unlock();
    session.worker = try std.Thread.spawn(.{}, backupAdmissionTestWorker, .{session});

    var outcome = BackupOutcome{ .allocator = allocator };
    defer outcome.data.deinit(allocator);
    var probe = BackupDisconnectOrderProbe{ .manager = &manager, .outcome = &outcome };
    manager.setBackupDisconnectHook(.{ .context = &probe, .prepare_fn = BackupDisconnectOrderProbe.prepare });
    manager.disconnect(session.server.id);
    try std.testing.expect(probe.called);
    try std.testing.expect(probe.stop_was_clear);
    try std.testing.expect(probe.normal_rejected);
    try std.testing.expect(probe.cleanup_admitted);
    try std.testing.expect(outcome.isDone());
    try std.testing.expectEqual(BackupOutcomeCode.disconnected, outcome.code);
}

fn backupAdmissionLifecycleTest(mode: BackupAdmissionTestMode) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const server_id = switch (mode) {
        .request => "backup-admission-request",
        .process => "backup-admission-process",
    };
    var store: servers.Store = .{ .allocator = allocator, .path = "/tmp/oars-backup-admission-servers.json" };
    var audit: history.AuditStore = .{ .allocator = allocator, .path = "/tmp/oars-backup-admission-audit.jsonl" };
    var history_store: history.HistoryStore = .{ .allocator = allocator, .path = "/tmp/oars-backup-admission-history.jsonl" };
    var manager = Manager.init(allocator, io, &store, &audit, &history_store, null);
    defer manager.deinit();

    const session = try allocator.create(Session);
    session.* = .{
        .id = 101,
        .server = try (servers.Server{ .id = server_id, .name = "backup", .host = "host", .user = "user" }).copy(allocator),
        .allocator = allocator,
        .threaded = std.Io.Threaded.init(allocator, .{}),
        .io = undefined,
        .transport = try ssh.Session.init(allocator),
        .store = &store,
        .audit = &audit,
        .history = &history_store,
        .owner = &manager,
        .started_at_ns = std.Io.Timestamp.now(io, .real).nanoseconds,
    };
    session.io = session.threaded.io();
    session.status.store(.ready, .release);
    const key = try allocator.dupe(u8, server_id);
    lockSpin(&manager.mutex);
    try manager.sessions.put(key, session);
    manager.mutex.unlock();
    session.worker = try std.Thread.spawn(.{}, backupAdmissionTestWorker, .{session});

    var outcome = BackupOutcome{ .allocator = allocator };
    defer outcome.data.deinit(allocator);
    var process = BackupProcess{ .allocator = allocator };
    defer process.data.deinit(allocator);
    var context = BackupAdmissionTestContext{
        .manager = &manager,
        .server_id = server_id,
        .mode = mode,
        .outcome = &outcome,
        .process = &process,
    };

    lockSpin(&session.ops_mutex);
    var ops_locked = true;
    var admission_thread: ?std.Thread = try std.Thread.spawn(.{}, BackupAdmissionTestContext.run, .{&context});
    defer if (admission_thread) |thread| thread.join();
    defer if (ops_locked) session.ops_mutex.unlock();

    // Let admission finish cloning and block at publication. The manager lock
    // must remain held while it waits for ops_mutex, otherwise disconnect can
    // remove, join, and destroy the borrowed session.
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(20), .awake) catch {};
    var publication_protected = false;
    const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + std.time.ns_per_s;
    while (std.Io.Timestamp.now(io, .real).nanoseconds < deadline) {
        if (!manager.mutex.tryLock()) {
            publication_protected = true;
            break;
        }
        manager.mutex.unlock();
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
    try std.testing.expect(publication_protected);

    var disconnect_thread: ?std.Thread = try std.Thread.spawn(.{}, backupAdmissionTestDisconnect, .{ &manager, server_id });
    defer if (disconnect_thread) |thread| thread.join();
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    try std.testing.expect(!session.stop_flag.load(.acquire));

    session.ops_mutex.unlock();
    ops_locked = false;
    admission_thread.?.join();
    admission_thread = null;
    disconnect_thread.?.join();
    disconnect_thread = null;

    try std.testing.expect(context.err == null);
    switch (mode) {
        .request => {
            try std.testing.expect(outcome.isDone());
            try std.testing.expectEqual(BackupOutcomeCode.disconnected, outcome.code);
        },
        .process => {
            var snapshot = try process.snapshot(allocator, 0, 1024);
            defer snapshot.deinit(allocator);
            try std.testing.expect(snapshot.done);
            try std.testing.expect(snapshot.disconnected);
        },
    }
}

test "backup allocation failures roll back all owned memory" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, cloneBackupRequestsAllocationTest, .{});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, copyBackupOutcomeAllocationTest, .{});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, snapshotBackupProcessAllocationTest, .{});
}

test "backup clone scrubs sensitive partial and completed payloads exactly once" {
    const exec_secret = "partial-allocation-sensitive-stdin-payload-unique";
    var exec_tracker = ZeroCheckAllocator{ .backing = std.testing.allocator, .watch_alloc_index = 1 };
    var failing = std.testing.FailingAllocator.init(exec_tracker.allocator(), .{ .fail_index = 2 });
    try std.testing.expectError(error.OutOfMemory, cloneBackupRequest(failing.allocator(), .{ .exec = .{
        .command = "backup",
        .stdin_data = exec_secret,
        .timeout_ns = std.time.ns_per_s,
        .cap = 4096,
        .history_command = "history allocation fails",
        .sensitive_stdin = true,
    } }));
    try std.testing.expectEqual(@as(usize, 1), exec_tracker.watched_frees);
    try std.testing.expectEqual(@as(usize, 0), exec_tracker.dirty_frees);

    const write_secret = "completed-sensitive-sftp-write-payload-with-unique-size";
    var write_tracker = ZeroCheckAllocator{ .backing = std.testing.allocator, .watch_alloc_index = 1 };
    const cloned = try cloneBackupRequest(write_tracker.allocator(), .{ .sftp_write = .{
        .path = "/remote/secret",
        .data = write_secret,
        .sensitive = true,
    } });
    freeBackupRequest(write_tracker.allocator(), cloned);
    try std.testing.expectEqual(@as(usize, 1), write_tracker.watched_frees);
    try std.testing.expectEqual(@as(usize, 0), write_tracker.dirty_frees);
}

test "backup admission remains live through concurrent disconnect" {
    try backupAdmissionLifecycleTest(.request);
    try backupAdmissionLifecycleTest(.process);
}

test "backup outcome and process abandonment free exactly once" {
    const allocator = std.testing.allocator;

    const completed_outcome = try allocator.create(BackupOutcome);
    completed_outcome.* = .{ .allocator = allocator };
    completed_outcome.set(.ok, 0, fx_unknown, false, "result", "ok");
    try std.testing.expect(completed_outcome.abandon());
    try std.testing.expect(!completed_outcome.abandoned);
    completed_outcome.data.deinit(allocator);
    allocator.destroy(completed_outcome);

    const abandoned_outcome = try allocator.create(BackupOutcome);
    abandoned_outcome.* = .{ .allocator = allocator };
    try std.testing.expect(!abandoned_outcome.abandon());
    abandoned_outcome.set(.disconnected, null, fx_unknown, false, "late result", "disconnected");

    const completed_process = try allocator.create(BackupProcess);
    completed_process.* = .{ .allocator = allocator };
    try completed_process.data.appendSlice(allocator, "output");
    completed_process.complete(0, false, "done");
    try std.testing.expect(completed_process.abandon());
    try std.testing.expect(!completed_process.abandoned);
    completed_process.data.deinit(allocator);
    allocator.destroy(completed_process);

    const abandoned_process = try allocator.create(BackupProcess);
    abandoned_process.* = .{ .allocator = allocator };
    try abandoned_process.data.appendSlice(allocator, "late output");
    try std.testing.expect(!abandoned_process.abandon());
    abandoned_process.complete(null, true, "disconnected");

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    const failing_allocator = failing.allocator();
    const oom_outcome = try failing_allocator.create(BackupOutcome);
    oom_outcome.* = .{ .allocator = failing_allocator };
    try std.testing.expect(!oom_outcome.abandon());
    oom_outcome.set(.ok, 0, fx_unknown, false, "allocation must fail", "ignored");
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "stream overflow drops oldest and tracks absolute positions" {
    const allocator = std.testing.allocator;
    var stream = Stream.init(allocator);
    stream.max_bytes = 1024;
    defer stream.deinit(allocator);

    // Push 3000 bytes through a 1024 cap => at least 1976 dropped.
    var chunk: [300]u8 = undefined;
    @memset(&chunk, 'a');
    var i: usize = 0;
    while (i < 10) : (i += 1) try stream.append(&chunk);
    try std.testing.expect(stream.dropped >= 1976);
    // start_abs advanced past the dropped bytes; end_abs is the total.
    try std.testing.expectEqual(@as(u64, 3000), stream.end_abs);
    try std.testing.expect(stream.start_abs == 3000 - stream.data.items.len);
    try std.testing.expectEqual(@as(usize, 1024), stream.data.items.len);
}

test "stream reads are non-destructive: two consumers read the same bytes" {
    const allocator = std.testing.allocator;
    var stream = Stream.init(allocator);
    defer stream.deinit(allocator);
    try stream.append("abcdef");

    var a: [8]u8 = undefined;
    var b: [8]u8 = undefined;
    // Two tabs at the same cursor both get the full retained window.
    try std.testing.expectEqual(@as(usize, 6), stream.readAt(0, &a));
    try std.testing.expectEqual(@as(usize, 6), stream.readAt(0, &b));
    try std.testing.expectEqualStrings("abcdef", a[0..6]);
    try std.testing.expectEqualStrings("abcdef", b[0..6]);

    // A consumer a few bytes behind starts there and reads the tail.
    try std.testing.expectEqual(@as(usize, 3), stream.readAt(3, &a));
    try std.testing.expectEqualStrings("def", a[0..3]);
    // Reading past the end yields nothing, never an error.
    try std.testing.expectEqual(@as(usize, 0), stream.readAt(99, &a));
}

test "exact channel range ignores unrelated poll output" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var store: servers.Store = .{ .allocator = allocator, .path = "/tmp/oars-range-test-servers.json" };
    var audit: history.AuditStore = .{ .allocator = allocator, .path = "/tmp/oars-range-test-audit.jsonl" };
    var history_store: history.HistoryStore = .{ .allocator = allocator, .path = "/tmp/oars-range-test-history.jsonl" };
    var manager = Manager.init(allocator, io, &store, &audit, &history_store, null);
    defer manager.deinit();

    var shell_stream = Stream.init(allocator);
    defer shell_stream.deinit(allocator);
    try shell_stream.append("shell");
    var result_stream = Stream.init(allocator);
    defer result_stream.deinit(allocator);
    try result_stream.append("result");
    var shell_entry = ChannelEntry{ .id = 0, .kind = .shell, .stream = &shell_stream, .raw = undefined };
    var result_entry = ChannelEntry{ .id = 6, .kind = .exec, .stream = &result_stream, .raw = undefined };
    var session = Session{
        .id = 1,
        .server = .{ .id = "range-test", .name = "range-test", .host = "127.0.0.1", .user = "tester" },
        .allocator = allocator,
        .threaded = undefined,
        .io = io,
        .transport = undefined,
        .store = &store,
        .audit = &audit,
        .history = &history_store,
    };
    defer session.channels.deinit(allocator);
    try session.channels.append(allocator, &shell_entry);
    try session.channels.append(allocator, &result_entry);
    try manager.sessions.put("range-test", &session);
    defer _ = manager.sessions.remove("range-test");

    const selected = (try manager.readChannelRange("range-test", 6, 0, 6)).?;
    defer allocator.free(selected);
    try std.testing.expectEqualStrings("result", selected);
}

test "stream view reports each consumer's own gap and pending" {
    const allocator = std.testing.allocator;
    var stream = Stream.init(allocator);
    stream.max_bytes = 1024;
    defer stream.deinit(allocator);

    var chunk: [300]u8 = undefined;
    @memset(&chunk, 'a');
    var i: usize = 0;
    while (i < 10) : (i += 1) try stream.append(&chunk);
    const start = stream.start();

    // A fresh tab (cursor 0) missed the dropped bytes: gap = start_abs.
    const fresh = stream.view(0);
    try std.testing.expectEqual(start, fresh.gap);
    try std.testing.expectEqual(start, fresh.from);
    try std.testing.expectEqual(@as(u64, 1024), fresh.pending);

    // A tab that consumed everything has no gap and nothing pending.
    const caught_up = stream.view(stream.end_abs);
    try std.testing.expectEqual(@as(u64, 0), caught_up.gap);
    try std.testing.expectEqual(@as(u64, 0), caught_up.pending);

    // A tab inside the retained window reads from its own position.
    const mid = stream.view(start + 400);
    try std.testing.expectEqual(@as(u64, 0), mid.gap);
    try std.testing.expectEqual(start + 400, mid.from);
    try std.testing.expectEqual(@as(u64, 624), mid.pending);
}

test "stream eof and exit status snapshot" {
    const allocator = std.testing.allocator;
    var stream = Stream.init(allocator);
    defer stream.deinit(allocator);
    try stream.append("hello");
    lockSpin(&stream.mutex);
    stream.eof = true;
    stream.exit_status = 7;
    stream.mutex.unlock();
    const snap = stream.snapshot();
    try std.testing.expect(snap.eof);
    try std.testing.expectEqual(@as(?i32, 7), snap.exit_status);
}

test "status json names are stable" {
    try std.testing.expectEqualStrings("needs_trust", Status.needs_trust.jsonName());
    try std.testing.expectEqualStrings("ready", Status.ready.jsonName());
    try std.testing.expectEqualStrings("exec", ChannelKind.exec.jsonName());
}

test "dead worker leaves the session pollable: post-mortem access never crashes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [128]u8 = undefined;
    var store_path_buf: [512]u8 = undefined;
    var audit_path_buf: [512]u8 = undefined;
    var history_path_buf: [512]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "oars-sessions-test-{d}", .{now});
    const store_path = try std.fmt.bufPrint(&store_path_buf, "/tmp/{s}/servers.json", .{dir});
    const audit_path = try std.fmt.bufPrint(&audit_path_buf, "/tmp/{s}/audit.jsonl", .{dir});
    const history_path = try std.fmt.bufPrint(&history_path_buf, "/tmp/{s}/history.jsonl", .{dir});
    var store: servers.Store = .{ .allocator = allocator, .path = store_path };
    var audit: history.AuditStore = .{ .allocator = allocator, .path = audit_path };
    var history_store: history.HistoryStore = .{ .allocator = allocator, .path = history_path };
    var manager = Manager.init(allocator, io, &store, &audit, &history_store, null);
    defer manager.deinit();

    // 127.0.0.1:1 refuses the TCP connect instantly: the worker errors and
    // exits on its own, exactly as a keepalive-dropped idle session does.
    const server = servers.Server{
        .id = "dead-1",
        .name = "dead",
        .host = "127.0.0.1",
        .port = 1,
        .user = "u",
    };
    _ = try manager.connect(server, null, null);

    // Wait for the worker to die and its teardown to complete.
    const session = manager.get("dead-1").?;
    const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 10 * std.time.ns_per_s;
    while (!session.worker_done.load(.acquire)) {
        if (std.Io.Timestamp.now(io, .real).nanoseconds >= deadline) return error.WorkerStuck;
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(5), .awake) catch {};
    }

    // The reported crash: the frontend poll timer kept firing after the
    // worker died, and pollChannels iterated the torn-down channel list.
    const polls = try manager.pollChannels("dead-1", &.{}, false, 1024, 1024);
    try std.testing.expectEqual(@as(usize, 0), polls.len);
    allocator.free(polls);

    // Keystrokes, execs, and resizes against the dead session fail honestly.
    try std.testing.expectError(error.NotReady, manager.input("dead-1", "x"));
    try std.testing.expectError(error.NotReady, manager.exec("dead-1", "ls"));
    try std.testing.expectError(error.NotReady, manager.resize("dead-1", 80, 24));

    manager.disconnect("dead-1");
}

test "op outcomes survive handler abandonment: late set frees exactly once" {
    const allocator = std.testing.allocator;

    // Handler still waiting when the set arrives: the worker leaves
    // ownership with the handler, which destroys it after reading.
    const o1 = try allocator.create(SftpOutcome);
    o1.* = .{ .allocator = allocator };
    o1.set(false, "boom");
    try std.testing.expect(o1.isDone());
    try std.testing.expectEqualStrings("boom", o1.message());
    allocator.destroy(o1);

    // Handler's deadline expired first: abandon moves ownership to the
    // op, and the late set frees the struct itself (the test allocator
    // fails the run on a leak or double free).
    const o2 = try allocator.create(SftpOutcome);
    o2.* = .{ .allocator = allocator };
    try std.testing.expect(!o2.abandon()); // not done -> the op owns it now
    o2.set(false, "too late");

    // Set lands between the handler's isDone check and its abandon: the
    // handler keeps ownership and reads the result normally.
    const o3 = try allocator.create(TunnelStartOutcome);
    o3.* = .{ .allocator = allocator };
    o3.set(true, 5900, "");
    try std.testing.expect(o3.abandon()); // was already done -> handler owns
    allocator.destroy(o3);

    // setJson on an abandoned outcome frees the payload as well.
    const o4 = try allocator.create(SftpOutcome);
    o4.* = .{ .allocator = allocator };
    try std.testing.expect(!o4.abandon());
    o4.setJson(try allocator.dupe(u8, "{\"ok\":true}"));

    // Access scan execs use the same ownership transfer. The worker must
    // unlock the outcome before it frees an object abandoned by a handler.
    const o5 = try allocator.create(AccessExecOutcome);
    o5.* = .{ .allocator = allocator };
    try std.testing.expect(!o5.abandon());
    o5.set(0, "late data", "ok");

    const o6 = try allocator.create(AccessExecOutcome);
    o6.* = .{ .allocator = allocator };
    o6.set(0, "ready", "ok");
    try std.testing.expect(o6.abandon());
    o6.data.deinit(allocator);
    allocator.destroy(o6);
}

test "sessionDone completes queued op outcomes honestly" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [128]u8 = undefined;
    var store_path_buf: [512]u8 = undefined;
    var audit_path_buf: [512]u8 = undefined;
    var history_path_buf: [512]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "oars-sessions-test-{d}", .{now});
    const store_path = try std.fmt.bufPrint(&store_path_buf, "/tmp/{s}/servers.json", .{dir});
    const audit_path = try std.fmt.bufPrint(&audit_path_buf, "/tmp/{s}/audit.jsonl", .{dir});
    const history_path = try std.fmt.bufPrint(&history_path_buf, "/tmp/{s}/history.jsonl", .{dir});
    var store: servers.Store = .{ .allocator = allocator, .path = store_path };
    var audit: history.AuditStore = .{ .allocator = allocator, .path = audit_path };
    var history_store: history.HistoryStore = .{ .allocator = allocator, .path = history_path };
    var manager = Manager.init(allocator, io, &store, &audit, &history_store, null);
    defer manager.deinit();

    // A session whose worker never ran: ops sit queued until teardown.
    // (transport.init establishes nothing; disconnect inside sessionDone
    // is a documented no-op on it.)
    const session = try allocator.create(Session);
    session.* = .{
        .id = 99,
        .server = .{ .id = "s", .name = "s", .host = "s", .user = "s" },
        .allocator = allocator,
        .threaded = std.Io.Threaded.init(allocator, .{}),
        .io = undefined,
        .transport = try ssh.Session.init(allocator),
        .store = &store,
        .audit = &audit,
        .history = &history_store,
        .owner = &manager,
        .started_at_ns = now,
    };
    session.io = session.threaded.io();
    defer {
        session.threaded.deinit();
        allocator.destroy(session);
    }

    // One outcome the handler is still waiting on...
    const waited = try allocator.create(SftpOutcome);
    waited.* = .{ .allocator = allocator };
    // ...and one its handler already abandoned after a deadline.
    const abandoned = try allocator.create(ClearOutcome);
    abandoned.* = .{ .allocator = allocator };
    try std.testing.expect(!abandoned.abandon());
    // Backup outcomes exercise both ownership sides during the same queued-op
    // disconnect drain: one remains handler-owned, the others were abandoned.
    const backup_waited = try allocator.create(BackupOutcome);
    backup_waited.* = .{ .allocator = allocator };
    const backup_abandoned = try allocator.create(BackupOutcome);
    backup_abandoned.* = .{ .allocator = allocator };
    try std.testing.expect(!backup_abandoned.abandon());
    const process_abandoned = try allocator.create(BackupProcess);
    process_abandoned.* = .{ .allocator = allocator };
    try process_abandoned.data.appendSlice(allocator, "buffered process output");
    try std.testing.expect(!process_abandoned.abandon());
    {
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        try session.ops.append(allocator, .{ .sftp_ls = .{
            .path = try allocator.dupe(u8, "/etc"),
            .outcome = waited,
        } });
        try session.ops.append(allocator, .{ .clear = .{
            .path = try allocator.dupe(u8, "/var/log/a.log"),
            .expected = .{ .size = 1, .mtime = 2, .mode = 0o644 },
            .outcome = abandoned,
        } });
        try session.ops.append(allocator, .{ .backup = .{
            .request = try cloneBackupRequest(allocator, .{ .exec = .{
                .command = "backup-check",
                .stdin_data = "secret stdin queued before disconnect",
                .timeout_ns = std.time.ns_per_s,
                .cap = 4096,
                .history_command = "backup-check",
                .sensitive_stdin = true,
            } }),
            .outcome = backup_waited,
        } });
        try session.ops.append(allocator, .{ .backup = .{
            .request = try cloneBackupRequest(allocator, .{ .sftp_write = .{
                .path = "/remote/config",
                .data = "secret write queued before disconnect",
                .sensitive = true,
            } }),
            .outcome = backup_abandoned,
        } });
        try session.ops.append(allocator, .{ .backup_run = .{
            .command = try allocator.dupe(u8, "rclone run"),
            .stdin_data = try allocator.dupe(u8, "secret process stdin"),
            .process = process_abandoned,
        } });
    }

    sessionDone(session);

    // The waiting handler wakes to an honest failure and frees; the
    // abandoned outcome was freed by the drain's set (no leak).
    try std.testing.expect(waited.isDone());
    try std.testing.expect(!waited.ok);
    try std.testing.expectEqualStrings("session disconnected", waited.message());
    allocator.destroy(waited);
    try std.testing.expect(backup_waited.isDone());
    try std.testing.expectEqual(BackupOutcomeCode.disconnected, backup_waited.code);
    backup_waited.data.deinit(allocator);
    allocator.destroy(backup_waited);
    try std.testing.expect(session.worker_done.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), session.ops.items.len);
}

test "reconnect after clean close tears down the replaced session" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [128]u8 = undefined;
    var store_path_buf: [512]u8 = undefined;
    var audit_path_buf: [512]u8 = undefined;
    var history_path_buf: [512]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "oars-sessions-test-{d}", .{now});
    const store_path = try std.fmt.bufPrint(&store_path_buf, "/tmp/{s}/servers.json", .{dir});
    const audit_path = try std.fmt.bufPrint(&audit_path_buf, "/tmp/{s}/audit.jsonl", .{dir});
    const history_path = try std.fmt.bufPrint(&history_path_buf, "/tmp/{s}/history.jsonl", .{dir});
    var store: servers.Store = .{ .allocator = allocator, .path = store_path };
    var audit: history.AuditStore = .{ .allocator = allocator, .path = audit_path };
    var history_store: history.HistoryStore = .{ .allocator = allocator, .path = history_path };
    var manager = Manager.init(allocator, io, &store, &audit, &history_store, null);
    defer manager.deinit();

    const server = servers.Server{
        .id = "re-1",
        .name = "re",
        .host = "127.0.0.1",
        .port = 1,
        .user = "u",
    };
    _ = try manager.connect(server, null, null);
    const first = manager.get("re-1").?;
    const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 10 * std.time.ns_per_s;
    while (!first.worker_done.load(.acquire)) {
        if (std.Io.Timestamp.now(io, .real).nanoseconds >= deadline) return error.WorkerStuck;
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(5), .awake) catch {};
    }
    // A refused connect ends .error; the stale-replacement path is
    // specific to a cleanly-closed record, so close it out synthetically.
    first.status.store(.closed, .release);

    // The replacement must tear the stale session down (join + free),
    // not overwrite the map entry and leak it.
    _ = try manager.connect(server, null, null);
    const second = manager.get("re-1").?;
    try std.testing.expect(first != second);
    manager.disconnect("re-1");
    // std.testing.allocator fails the run unless the first session, its
    // server copy, and the replaced map key were all freed.
}

test "cascadeCloseDependant marks the dependant and tolerates a removed one" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [128]u8 = undefined;
    var store_path_buf: [512]u8 = undefined;
    var audit_path_buf: [512]u8 = undefined;
    var history_path_buf: [512]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "oars-sessions-test-{d}", .{now});
    const store_path = try std.fmt.bufPrint(&store_path_buf, "/tmp/{s}/servers.json", .{dir});
    const audit_path = try std.fmt.bufPrint(&audit_path_buf, "/tmp/{s}/audit.jsonl", .{dir});
    const history_path = try std.fmt.bufPrint(&history_path_buf, "/tmp/{s}/history.jsonl", .{dir});
    var store: servers.Store = .{ .allocator = allocator, .path = store_path };
    var audit: history.AuditStore = .{ .allocator = allocator, .path = audit_path };
    var history_store: history.HistoryStore = .{ .allocator = allocator, .path = history_path };
    var manager = Manager.init(allocator, io, &store, &audit, &history_store, null);
    defer manager.deinit();

    // A hand-built dependant session in the map (worker never ran).
    const target = try allocator.create(Session);
    target.* = .{
        .id = 7,
        .server = try (servers.Server{ .id = "t-1", .name = "t", .host = "h", .user = "u" }).copy(allocator),
        .allocator = allocator,
        .threaded = std.Io.Threaded.init(allocator, .{}),
        .io = undefined,
        .transport = try ssh.Session.init(allocator),
        .store = &store,
        .audit = &audit,
        .history = &history_store,
        .owner = &manager,
        .started_at_ns = now,
    };
    target.io = target.threaded.io();
    target.status.store(.ready, .release);
    const key = try allocator.dupe(u8, "t-1");
    {
        lockSpin(&manager.mutex);
        defer manager.mutex.unlock();
        try manager.sessions.put(key, target);
    }

    manager.cascadeCloseDependant("t-1", "jump-box");
    try std.testing.expectEqual(Status.@"error", target.status.load(.acquire));
    try std.testing.expect(std.mem.indexOf(u8, target.errorText(), "jump-box") != null);

    // Removed from the map first: the cascade is a no-op and touches
    // nothing (disconnect tears down under the same mutex discipline).
    {
        lockSpin(&manager.mutex);
        defer manager.mutex.unlock();
        _ = manager.sessions.remove("t-1");
    }
    manager.teardown(key, target);
    manager.cascadeCloseDependant("t-1", "jump-box");
}

const ShellHistorySink = struct {
    session: *Session,
    entry: *ChannelEntry,
    fn sink(self: *ShellHistorySink) shell_integration.Sink {
        return .{ .context = self, .output = output, .event = event };
    }
    fn output(context: *anyopaque, bytes: []const u8) void {
        const self: *ShellHistorySink = @ptrCast(@alignCast(context));
        appendChannelData(self.entry, bytes);
        const session = self.session;
        if (session.shell_started_ns == 0) return;
        for (bytes) |byte| {
            if (session.shell_snippet_len == session.shell_snippet.len or session.shell_snippet_lines >= 2) break;
            session.shell_snippet[session.shell_snippet_len] = byte;
            session.shell_snippet_len += 1;
            if (byte == '\n') session.shell_snippet_lines += 1;
        }
    }
    fn event(context: *anyopaque, value: shell_integration.Event) void {
        const self: *ShellHistorySink = @ptrCast(@alignCast(context));
        const session = self.session;
        switch (value) {
            .coverage => |full| {
                session.history_full.store(full and session.history_capture_enabled.load(.acquire), .release);
                if (!full) {
                    session.shell_started_ns = 0;
                    session.shell_command_len = 0;
                }
            },
            .command => |command| {
                @memcpy(session.shell_command[0..command.len], command);
                session.shell_command_len = command.len;
                session.shell_started_ns = 0;
                session.shell_snippet_len = 0;
                session.shell_snippet_lines = 0;
            },
            .start => {
                if (session.history_full.load(.acquire) and session.shell_command_len > 0) session.shell_started_ns = std.Io.Timestamp.now(session.io, .real).nanoseconds;
            },
            .finish => |exit_code| {
                defer {
                    session.shell_started_ns = 0;
                    session.shell_command_len = 0;
                }
                if (session.shell_started_ns == 0 or session.shell_command_len == 0 or !session.history_full.load(.acquire)) return;
                const allocator = session.allocator;
                const secrets = [_][]const u8{ session.password orelse "", session.passphrase orelse "" };
                const command = history.redact(allocator, session.shell_command[0..session.shell_command_len], &secrets) catch return;
                defer allocator.free(command.text);
                const snippet = history.exactMask(allocator, session.shell_snippet[0..session.shell_snippet_len], &secrets) catch return;
                defer allocator.free(snippet.text);
                const now = std.Io.Timestamp.now(session.io, .real).nanoseconds;
                var id_buf: [96]u8 = undefined;
                const operation_id = std.fmt.bufPrint(&id_buf, "shell-{d}-{d}-{d}", .{ session.id, session.shell_channel_id, session.history_seq }) catch return;
                session.history_seq += 1;
                session.history.record(session.io, .{ .id = "", .operation_id = operation_id, .ts = @intCast(now), .server_id = session.server.id, .kind = "shell", .command = command.text, .exit = exit_code, .duration_ms = @intCast(@max(0, @divTrunc(now - session.shell_started_ns, std.time.ns_per_ms))), .output_snippet = snippet.text, .redacted = command.redacted or snippet.redacted }) catch {
                    session.history_write_error.store(true, .release);
                };
            },
        }
    }
};

test "socket pumps enable non-blocking IO through the variadic fcntl ABI" {
    var fds: [2]std.posix.socket_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), ssh.c.socketpair(ssh.c.AF_UNIX, ssh.c.SOCK_STREAM, 0, &fds));
    defer for (fds) |fd| {
        _ = ssh.c.close(fd);
    };
    for (fds) |fd| {
        try configureNonBlockingSocket(fd);
        const flags = ssh.c.fcntl(fd, ssh.c.F_GETFL);
        try std.testing.expect(flags >= 0 and flags & ssh.c.O_NONBLOCK != 0);
    }
    var buffer: [1]u8 = undefined;
    try std.testing.expectError(error.WouldBlock, std.posix.read(fds[0], &buffer));
}

test "terminal results classify tracked runs without hiding feature-owned output" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var store: servers.Store = .{ .allocator = allocator, .path = "/tmp/oars-range-test-servers.json" };
    var audit: history.AuditStore = .{ .allocator = allocator, .path = "/tmp/oars-range-test-audit.jsonl" };
    var history_store: history.HistoryStore = .{ .allocator = allocator, .path = "/tmp/oars-range-test-history.jsonl" };
    var manager = Manager.init(allocator, io, &store, &audit, &history_store, null);
    defer manager.deinit();

    var shell_stream = Stream.init(allocator);
    defer shell_stream.deinit(allocator);
    try shell_stream.append("shell");
    var result_stream = Stream.init(allocator);
    defer result_stream.deinit(allocator);
    try result_stream.append("result");
    var shell_entry = ChannelEntry{ .id = 0, .kind = .shell, .stream = &shell_stream, .raw = undefined };
    var result_entry = ChannelEntry{ .id = 6, .kind = .exec, .stream = &result_stream, .raw = undefined };
    var session = Session{
        .id = 1,
        .server = .{ .id = "range-test", .name = "range-test", .host = "127.0.0.1", .user = "tester" },
        .allocator = allocator,
        .threaded = undefined,
        .io = io,
        .transport = undefined,
        .store = &store,
        .audit = &audit,
        .history = &history_store,
    };
    defer session.channels.deinit(allocator);
    try session.channels.append(allocator, &shell_entry);
    try session.channels.append(allocator, &result_entry);
    try manager.sessions.put("range-test", &session);
    defer _ = manager.sessions.remove("range-test");

    result_entry.history_kind = "exec";
    const polls = try manager.pollChannels("range-test", &.{}, false, 1024, 1024);
    defer {
        for (polls) |*poll| poll.deinit(allocator);
        allocator.free(polls);
    }
    try std.testing.expectEqual(@as(usize, 2), polls.len);
    try std.testing.expect(!polls[0].user_visible);
    try std.testing.expect(polls[1].user_visible);
    result_entry.history_kind = null;
    const internal = try manager.pollChannels("range-test", &.{}, false, 1024, 1024);
    defer {
        for (internal) |*poll| poll.deinit(allocator);
        allocator.free(internal);
    }
    try std.testing.expect(!internal[1].user_visible);
    try std.testing.expectEqualStrings("result", internal[1].data);
}

fn checkExecWaitOutput(unrelated_bytes: usize, result_bytes: usize) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var store: servers.Store = .{ .allocator = allocator, .path = "/tmp/oars-range-test-servers.json" };
    var audit: history.AuditStore = .{ .allocator = allocator, .path = "/tmp/oars-range-test-audit.jsonl" };
    var history_store: history.HistoryStore = .{ .allocator = allocator, .path = "/tmp/oars-range-test-history.jsonl" };
    var manager = Manager.init(allocator, io, &store, &audit, &history_store, null);
    defer manager.deinit();

    var shell_stream = Stream.init(allocator);
    defer shell_stream.deinit(allocator);
    const unrelated = try allocator.alloc(u8, unrelated_bytes);
    defer allocator.free(unrelated);
    @memset(unrelated, 'x');
    try shell_stream.append(unrelated);
    var result_stream = Stream.init(allocator);
    defer result_stream.deinit(allocator);
    const expected = try allocator.alloc(u8, result_bytes);
    defer allocator.free(expected);
    @memset(expected, 'v');
    try result_stream.append(expected);
    result_stream.eof = true;
    result_stream.exit_status = 0;
    var shell_entry = ChannelEntry{ .id = 0, .kind = .shell, .stream = &shell_stream, .raw = undefined };
    var result_entry = ChannelEntry{ .id = 6, .kind = .exec, .stream = &result_stream, .raw = undefined };
    var session = Session{
        .id = 1,
        .server = .{ .id = "range-test", .name = "range-test", .host = "127.0.0.1", .user = "tester" },
        .allocator = allocator,
        .threaded = undefined,
        .io = io,
        .transport = undefined,
        .store = &store,
        .audit = &audit,
        .history = &history_store,
    };
    defer session.channels.deinit(allocator);
    try session.channels.append(allocator, &shell_entry);
    try session.channels.append(allocator, &result_entry);
    try manager.sessions.put("range-test", &session);
    defer _ = manager.sessions.remove("range-test");

    var outcome = try manager.waitExec("range-test", 6, 256 * 1024, 100 * std.time.ns_per_ms, .{});
    defer outcome.deinit(allocator);
    try std.testing.expect(!outcome.limited);
    try std.testing.expectEqual(@as(i32, 0), outcome.exit);
    try std.testing.expectEqual(expected.len, outcome.output.items.len);
    try std.testing.expect(std.mem.eql(u8, expected, outcome.output.items));
}

test "exec wait is not starved by retained output from unrelated channels" {
    try checkExecWaitOutput(128 * 1024, 256);
}

test "exec wait drains EOF output beyond a single poll budget" {
    try checkExecWaitOutput(0, 128 * 1024);
}
