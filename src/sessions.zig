//! SSH session manager.
//!
//! Each connected server gets one worker thread owning its libssh2
//! session (libssh2 is not thread-safe per session). The runtime's main
//! thread never blocks on the network: bridge handlers exchange data
//! through small locked structures — output streams with cursor-based
//! deltas (polled by the frontend), an input queue, and an op queue.

const std = @import("std");
const ssh = @import("ssh.zig");
const servers = @import("servers.zig");
const openssh = @import("openssh.zig");

/// Blocking acquire on std.atomic.Mutex (spinlock) — 0.16's atomic.Mutex
/// only exposes tryLock. Sections are short (buffer/cursor updates), so
/// spinning is appropriate.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
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

    pub fn jsonName(self: ChannelKind) []const u8 {
        return switch (self) {
            .shell => "shell",
            .exec => "exec",
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
    stream: *Stream,
    raw: *ssh.Channel,
    stdin_mutex: std.atomic.Mutex = .unlocked,
    stdin_queue: std.ArrayList(u8) = .empty,
    eof_seen: bool = false,
    /// Set once the raw libssh2 channel is closed and freed; session
    /// teardown must not close it again.
    raw_closed: bool = false,
};

const Op = union(enum) {
    exec: struct { id: u32, command: []const u8 },
    resize: struct { cols: c_int, rows: c_int },
    close,
    close_channel: struct { id: u32 },
};

const TrustState = struct {
    mutex: std.atomic.Mutex = .unlocked,
    pending: bool = false,
    fingerprint: [64]u8 = undefined,
    decided: bool = false,
    accept: bool = false,
};

const error_buf_len = 512;

pub const Session = struct {
    id: u64,
    server: servers.Server,
    allocator: std.mem.Allocator,
    threaded: std.Io.Threaded,
    io: std.Io,
    transport: ssh.Session,
    store: *servers.Store,
    status: std.atomic.Value(Status) = .init(.connecting),
    error_mutex: std.atomic.Mutex = .unlocked,
    error_msg: [error_buf_len]u8 = undefined,
    error_len: usize = 0,
    trust: TrustState = .{},
    stop_flag: std.atomic.Value(bool) = .init(false),
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
        return &self.trust.fingerprint;
    }
};

pub const Manager = struct {
    allocator: std.mem.Allocator,
    store: *servers.Store,
    io: std.Io,
    /// Borrowed from the process environment (outlives the manager);
    /// used to expand "~/" in key paths on the worker threads.
    home: ?[]const u8 = null,
    mutex: std.atomic.Mutex = .unlocked,
    sessions: std.StringHashMap(*Session) = undefined,
    next_session_id: u64 = 1,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, store: *servers.Store, home: ?[]const u8) Manager {
        return .{
            .allocator = allocator,
            .store = store,
            .io = io,
            .home = home,
            .sessions = std.StringHashMap(*Session).init(allocator),
        };
    }

    pub fn deinit(self: *Manager) void {
        self.shutdownAll();
        self.sessions.deinit();
    }

    pub fn get(self: *Manager, server_id: []const u8) ?*Session {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.sessions.get(server_id);
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
        defer self.mutex.unlock();

        if (self.sessions.get(server.id)) |existing| {
            if (existing.status.load(.acquire) != .closed) return error.AlreadyConnected;
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

    /// Signals a session to stop, cancels any in-flight DNS lookup, joins
    /// its worker thread, then frees all session memory. Safe to call when
    /// no session exists. The join stays bounded because the worker checks
    /// the stop signal between every connect phase and inside every deadline
    /// loop; only the kernel-bounded TCP connect itself can extend it (the
    /// std Io has no non-blocking connect — spec 02 §5).
    pub fn disconnect(self: *Manager, server_id: []const u8) void {
        lockSpin(&self.mutex);
        const entry = self.sessions.getEntry(server_id) orelse {
            self.mutex.unlock();
            return;
        };
        const key = entry.key_ptr.*;
        const session = entry.value_ptr.*;
        session.stop_flag.store(true, .release);
        session.transport.cancelConnect(session.io);
        if (session.worker) |thread| thread.join();
        _ = self.sessions.remove(server_id);
        self.mutex.unlock();

        self.allocator.free(key);
        var s = session.server;
        s.deinit(session.allocator);
        if (session.password) |p| session.allocator.free(p);
        if (session.passphrase) |p| session.allocator.free(p);
        session.threaded.deinit();
        session.allocator.destroy(session);
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

    /// Appends bytes to the shell channel's stdin.
    pub fn input(self: *Manager, server_id: []const u8, bytes: []const u8) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        const shell = session.shell orelse return error.NotReady;
        lockSpin(&shell.stdin_mutex);
        defer shell.stdin_mutex.unlock();
        try shell.stdin_queue.appendSlice(self.allocator, bytes);
    }

    /// Queues an exec on a fresh channel. Returns the channel id that
    /// will carry the output (assigned by the worker).
    pub fn exec(self: *Manager, server_id: []const u8, command: []const u8) !u32 {
        const session = self.get(server_id) orelse return error.NoSession;
        if (session.status.load(.acquire) != .ready) return error.NotReady;
        const id = session.next_channel_id.fetchAdd(1, .monotonic);
        const owned = try self.allocator.dupe(u8, command);
        errdefer self.allocator.free(owned);
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        try session.ops.append(self.allocator, .{ .exec = .{ .id = id, .command = owned } });
        return id;
    }

    /// Queues an explicit channel close (spec 04's `oars.ssh.closeChannel`):
    /// the worker sends EOF, closes the raw channel, and frees the entry.
    /// The shell channel (id 0) is never closed this way.
    pub fn closeChannel(self: *Manager, server_id: []const u8, channel_id: u32) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        if (channel_id == 0) return error.InvalidChannel;
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        try session.ops.append(self.allocator, .{ .close_channel = .{ .id = channel_id } });
    }

    pub fn resize(self: *Manager, server_id: []const u8, cols: u16, rows: u16) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
        try session.ops.append(self.allocator, .{ .resize = .{ .cols = @intCast(cols), .rows = @intCast(rows) } });
    }

    pub fn close(self: *Manager, server_id: []const u8) !void {
        const session = self.get(server_id) orelse return error.NoSession;
        lockSpin(&session.ops_mutex);
        defer session.ops_mutex.unlock();
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
            try self.allocator.dupe(u8, &session.trust.fingerprint)
        else
            null;
        session.trust.mutex.unlock();

        if (fp) |f| {
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            var s = session.server;
            if (s.host_fingerprint) |old| self.allocator.free(old);
            s.host_fingerprint = f;
            try self.store.upsert(self.io, s);
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
                command = allocator.dupe(u8, entry.command) catch {
                    allocator.free(data);
                    continue;
                };
            }
            const snap = entry.stream.snapshot();
            out.append(allocator, .{
                .id = entry.id,
                .kind = entry.kind,
                .command = command,
                .eof = snap.eof,
                .exit_status = snap.exit_status,
                .gap = view.gap,
                .cursor = view.from + data.len,
                .pending = view.pending,
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
            .@"error" = if (status == .@"error") session.errorText() else "",
            .trust_pending = session.trustPending(),
            .trust_fingerprint = session.trustFingerprint(),
        };
    }
};

pub const Cursor = struct {
    id: u32,
    pos: u64,
};

pub const ChannelPoll = struct {
    id: u32,
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
    @"error": []const u8,
    trust_pending: bool,
    trust_fingerprint: []const u8,
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
    session.transport.connect(io, session.server.host, session.server.port) catch |err| {
        session.status.store(.@"error", .release);
        if (err == error.Canceled) {
            session.status.store(.closed, .release);
            return;
        }
        session.setError(std.fmt.bufPrint(&error_buf, "connect failed: {s}", .{@errorName(err)}) catch "connect failed");
        return;
    };
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
    if (session.server.host_fingerprint == null) {
        lockSpin(&session.trust.mutex);
        session.trust.pending = true;
        @memcpy(&session.trust.fingerprint, fingerprint);
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
    } else {
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
    }

    // --- interactive shell ----------------------------------------------
    const raw_shell = session.transport.openChannel(io) catch {
        session.status.store(.@"error", .release);
        session.setError("failed to open shell channel");
        return;
    };
    raw_shell.requestPty(io, 120, 32) catch {};
    raw_shell.setEnv(io, "TERM", "xterm-256color") catch {};
    raw_shell.shell(io) catch {
        session.status.store(.@"error", .release);
        session.setError("failed to start shell");
        return;
    };
    const shell_stream = allocator.create(Stream) catch return;
    shell_stream.* = Stream.init(allocator);
    const shell_entry = allocator.create(ChannelEntry) catch {
        allocator.destroy(shell_stream);
        return;
    };
    shell_entry.* = .{ .id = 0, .kind = .shell, .stream = shell_stream, .raw = raw_shell };
    lockSpin(&session.channels_mutex);
    session.channels.append(allocator, shell_entry) catch {
        session.channels_mutex.unlock();
        allocator.destroy(shell_entry);
        allocator.destroy(shell_stream);
        return;
    };
    session.shell = shell_entry;
    session.channels_mutex.unlock();
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

            switch (entry.raw.read(&read_buf)) {
                .eof => {
                    if (!entry.eof_seen) {
                        entry.eof_seen = true;
                        lockSpin(&entry.stream.mutex);
                        entry.stream.eof = true;
                        entry.stream.exit_status = entry.raw.exitStatus();
                        entry.stream.mutex.unlock();
                        entry.raw.sendEof();
                        if (entry.kind == .exec) {
                            // Exec output must survive for the frontend to
                            // drain through polls: release the raw channel
                            // but keep entry + stream until session teardown
                            // (bounded by evictCompletedExecs).
                            entry.raw.close(session.io);
                            entry.raw_closed = true;
                        }
                    }
                    if (entry.kind == .exec) evictCompletedExecs(session);
                    i += 1;
                },
                .data => |n| {
                    entry.stream.append(read_buf[0..n]) catch {};
                    i += 1;
                },
                .again => i += 1,
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
        if (e.kind == .exec and e.eof_seen) completed += 1;
    }
    while (completed > max_completed_execs) {
        var found: ?usize = null;
        for (session.channels.items, 0..) |e, i| {
            if (e.kind == .exec and e.eof_seen) {
                found = i;
                break;
            }
        }
        const i = found orelse break;
        const entry = session.channels.items[i];
        _ = session.channels.orderedRemove(i);
        entry.stdin_queue.deinit(session.allocator);
        session.allocator.free(entry.command);
        entry.stream.deinit(session.allocator);
        session.allocator.destroy(entry.stream);
        session.allocator.destroy(entry);
        completed -= 1;
    }
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
                _ = session.channels.orderedRemove(i);
                session.channels_mutex.unlock();

                if (!entry.raw_closed) {
                    entry.raw.sendEof();
                    entry.raw.close(session.io);
                }
                entry.stdin_queue.deinit(allocator);
                allocator.free(entry.command);
                entry.stream.deinit(allocator);
                allocator.destroy(entry.stream);
                allocator.destroy(entry);
            },
            .exec => |e| {
                const raw = session.transport.openChannel(session.io) catch {
                    allocator.free(e.command);
                    continue;
                };
                raw.exec(session.io, e.command) catch {
                    raw.close(session.io);
                    allocator.free(e.command);
                    continue;
                };
                const stream = allocator.create(Stream) catch {
                    raw.close(session.io);
                    allocator.free(e.command);
                    continue;
                };
                stream.* = Stream.init(allocator);
                const entry = allocator.create(ChannelEntry) catch {
                    allocator.destroy(stream);
                    raw.close(session.io);
                    allocator.free(e.command);
                    continue;
                };
                entry.* = .{ .id = e.id, .kind = .exec, .command = e.command, .stream = stream, .raw = raw };
                lockSpin(&session.channels_mutex);
                session.channels.append(allocator, entry) catch {};
                session.channels_mutex.unlock();
            },
        }
    }
}

/// Surfaces a key-auth failure to the frontend with libssh2's own
/// message appended (it carries the useful detail).
fn reportKeyAuthError(session: *Session, error_buf: []u8, err: ssh.Error) void {
    session.status.store(.@"error", .release);
    var msg_buf: [256]u8 = undefined;
    const msg = session.transport.lastErrorMessage(&msg_buf);
    session.setError(std.fmt.bufPrint(error_buf, "key authentication failed: {s} ({s})", .{ @errorName(err), msg }) catch "key authentication failed");
}

/// Cleans up channels and the transport at the end of the worker's life.
fn sessionDone(session: *Session) void {
    lockSpin(&session.ops_mutex);
    for (session.ops.items) |op| {
        if (op == .exec) session.allocator.free(op.exec.command);
    }
    session.ops.clearRetainingCapacity();
    session.ops_mutex.unlock();

    lockSpin(&session.channels_mutex);
    for (session.channels.items) |entry| {
        if (!entry.raw_closed) entry.raw.close(session.io);
        entry.stdin_queue.deinit(session.allocator);
        if (entry.kind == .exec) session.allocator.free(entry.command);
        entry.stream.deinit(session.allocator);
        session.allocator.destroy(entry.stream);
        session.allocator.destroy(entry);
    }
    session.channels.clearRetainingCapacity();
    session.channels_mutex.unlock();

    session.transport.disconnect(session.io);
    const status = session.status.load(.acquire);
    if (status != .@"error" and status != .closed) session.status.store(.closed, .release);
}

/// Stop signal for the transport's deadline loops: disconnect sets the
/// session stop flag, and every loop checks it between iterations.
fn workerStop(ctx: ?*anyopaque) bool {
    const session: *Session = @ptrCast(@alignCast(ctx));
    return session.stop_flag.load(.acquire);
}

// --- tests ---------------------------------------------------------------

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
