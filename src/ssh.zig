//! Low-level SSH transport wrapper over vendored libssh2 (mbedTLS backend).
//!
//! Every function here blocks; the session manager in `sessions.zig`
//! runs them on worker threads, never on the runtime's main thread.
//! All timeouts are enforced with non-blocking sockets + poll loops so a
//! dead server cannot hang the app.

const std = @import("std");

pub const c = @cImport({
    @cInclude("libssh2.h");
    @cInclude("libssh2_sftp.h");
    // Spec 18 jump tunnels: socketpair for the local tunnel bridge.
    @cInclude("sys/socket.h");
    @cInclude("sys/un.h");
    @cInclude("unistd.h");
});

pub const Error = error{
    Timeout,
    AuthFailed,
    ConnectionFailed,
    Protocol,
    NoChannel,
    Canceled,
    /// The server refused a channel request (spec 18: agent forwarding).
    Refused,
};

const poll_interval_ms = 10;
const handshake_timeout_ms = 15_000;
const auth_timeout_ms = 20_000;

/// Process-wide libssh2 init. libssh2's own counter is not thread-safe
/// (global.c increments it without a lock), so it must run once before any
/// worker thread can touch the library (spec 02 §6).
var init_global_done: std.atomic.Value(bool) = .init(false);
var init_global_mutex: std.atomic.Mutex = .unlocked;

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

pub fn initGlobal() void {
    if (init_global_done.load(.acquire)) return;
    lockSpin(&init_global_mutex);
    defer init_global_mutex.unlock();
    if (init_global_done.load(.acquire)) return;
    _ = c.libssh2_init(0);
    init_global_done.store(true, .release);
}

fn isEagain(rc: c_int) bool {
    return rc == c.LIBSSH2_ERROR_EAGAIN;
}

fn sleep(io: std.Io) !void {
    try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(poll_interval_ms), .awake);
}

fn nowNs(io: std.Io) i128 {
    return std.Io.Timestamp.now(io, .real).nanoseconds;
}

fn deadlineFromNow(io: std.Io, ms: u64) i128 {
    return nowNs(io) + @as(i128, ms) * std.time.ns_per_ms;
}

fn checkDeadline(io: std.Io, deadline: i128) Error!void {
    if (nowNs(io) >= deadline) return error.Timeout;
}

/// A live SSH session bound to one socket. Owns the socket while
/// `socket_open` and the libssh2 handle while `session_open`;
/// `disconnect` releases whichever half was established, so partial
/// failures in `connect` never double-close or leak.
pub const Session = struct {
    allocator: std.mem.Allocator,
    raw: *c.LIBSSH2_SESSION,
    socket: std.posix.fd_t,
    socket_open: bool = false,
    session_open: bool = false,
    /// Optional stop signal: checked by every deadline loop so a disconnect
    /// stays responsive while DNS, handshake, or auth is in progress.
    stop_fn: ?*const fn (?*anyopaque) bool = null,
    stop_ctx: ?*anyopaque = null,
    /// The in-flight cancelable DNS lookup, published so a disconnect on
    /// another thread can cancel it (see connect).
    dns_future: std.atomic.Value(?*std.Io.Future(anyerror!void)) = .init(null),
    /// Lazily initialized SFTP subsystem (spec 04 clear; spec 05 owns the
    /// rest). Only ever touched by the session worker.
    sftp: ?*c.LIBSSH2_SFTP = null,

    pub fn init(allocator: std.mem.Allocator) Error!Session {
        return .{ .allocator = allocator, .raw = undefined, .socket = undefined };
    }

    pub fn setStop(self: *Session, f: ?*const fn (?*anyopaque) bool, ctx: ?*anyopaque) void {
        self.stop_fn = f;
        self.stop_ctx = ctx;
    }

    fn checkStop(self: *const Session) Error!void {
        if (self.stop_fn) |f| if (f(self.stop_ctx)) return error.Canceled;
    }

    /// Cancels the in-flight DNS lookup from another thread (called by
    /// disconnect before joining the worker).
    pub fn cancelConnect(self: *Session, io: std.Io) void {
        if (self.dns_future.load(.acquire)) |future| future.cancel(io) catch {};
    }

    /// Resolves `host` to an address. Literal IPs parse directly; hostnames
    /// are looked up on the io's thread pool as a cancelable future so a
    /// disconnect never waits on a slow resolver.
    fn resolveAddress(self: *Session, io: std.Io, host: []const u8, port: u16) Error!std.Io.net.IpAddress {
        if (std.Io.net.IpAddress.parse(host, port)) |addr| return addr else |_| {}

        const name = std.Io.net.HostName.init(host) catch return error.ConnectionFailed;
        var queue_buf: [8]std.Io.net.HostName.LookupResult = undefined;
        var queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&queue_buf);

        const Lookup = struct {
            name: std.Io.net.HostName,
            io: std.Io,
            queue: *std.Io.Queue(std.Io.net.HostName.LookupResult),
            port: u16,

            fn run(l: *const @This()) anyerror!void {
                try std.Io.net.HostName.lookup(l.name, l.io, l.queue, .{ .port = l.port });
            }
        };
        var lookup = Lookup{ .name = name, .io = io, .queue = &queue, .port = port };
        var future = std.Io.concurrent(io, Lookup.run, .{&lookup}) catch return error.ConnectionFailed;
        self.dns_future.store(&future, .release);
        defer self.dns_future.store(null, .release);

        // Close the cancel window: if a disconnect raced ahead of the store
        // above, the stop signal is already set — cancel and leave now.
        self.checkStop() catch {
            future.cancel(io) catch {};
            return error.Canceled;
        };
        const result = future.await(io);
        if (result) |_| {} else |_| return error.ConnectionFailed;

        var results: [8]std.Io.net.HostName.LookupResult = undefined;
        const n = queue.get(io, &results, 0) catch 0;
        for (results[0..n]) |r| {
            switch (r) {
                .address => |addr| return addr,
                else => {},
            }
        }
        return error.ConnectionFailed;
    }

    /// Connects the TCP socket and runs the transport handshake with a
    /// deadline. Blocking connect is acceptable here (worker thread); the
    /// handshake itself is non-blocking. On failure the caller must still
    /// call `disconnect` to release partial state.
    pub fn connect(self: *Session, io: std.Io, host: []const u8, port: u16) Error!void {
        const addr = try self.resolveAddress(io, host, port);
        self.checkStop() catch return error.Canceled;
        const stream = std.Io.net.IpAddress.connect(&addr, io, .{
            .mode = .stream,
            .protocol = .tcp,
        }) catch return error.ConnectionFailed;
        self.socket = stream.socket.handle;
        self.socket_open = true;

        try self.handshake(io);
    }

    /// Spec 18: runs the SSH handshake over an existing socket — the
    /// local end of a jump-host tunnel (the target's SSH runs inside
    /// the jump's SSH). The caller owns the fd; `deinit` closes it.
    pub fn connectFd(self: *Session, io: std.Io, fd: std.posix.socket_t) Error!void {
        self.socket = fd;
        self.socket_open = true;
        try self.handshake(io);
    }

    fn handshake(self: *Session, io: std.Io) Error!void {
        self.raw = c.libssh2_session_init_ex(null, null, null, null) orelse {
            return error.Protocol;
        };
        self.session_open = true;

        c.libssh2_session_set_blocking(self.raw, 0);

        const deadline = deadlineFromNow(io, handshake_timeout_ms);
        while (true) {
            const rc = c.libssh2_session_handshake(self.raw, @intCast(self.socket));
            if (rc == 0) break;
            if (!isEagain(rc)) {
                return error.Protocol;
            }
            try checkDeadline(io, deadline);
            try self.checkStop();
            try sleep(io);
        }
    }

    /// SHA-256 fingerprint of the server host key, hex-encoded (64 chars).
    /// Legacy format: kept for comparing (and migrating) pre-2026 records;
    /// new records use hostKeyFingerprint.
    pub fn hostKeySha256Hex(self: *Session, out: []u8) Error![]const u8 {
        const hash = c.libssh2_hostkey_hash(self.raw, c.LIBSSH2_HOSTKEY_HASH_SHA256);
        if (hash == null) return error.Protocol;
        const bytes = hash[0..32];
        const hex = "0123456789abcdef";
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            out[i * 2] = hex[bytes[i] >> 4];
            out[i * 2 + 1] = hex[bytes[i] & 0xf];
        }
        return out[0..64];
    }

    /// Canonical OpenSSH fingerprint: `SHA256:` + unpadded base64 of the
    /// SHA-256 host key hash (spec 02 §4.2). `out` must hold 50 bytes.
    pub fn hostKeyFingerprint(self: *Session, out: []u8) Error![]const u8 {
        const hash = c.libssh2_hostkey_hash(self.raw, c.LIBSSH2_HOSTKEY_HASH_SHA256);
        if (hash == null) return error.Protocol;
        return fingerprintFromHash(hash[0..32].*, out);
    }

    /// Pure encoding helper (unit-testable): `SHA256:` + unpadded base64.
    pub fn fingerprintFromHash(hash: [32]u8, out: []u8) []const u8 {
        const prefix = "SHA256:";
        const encoded = std.base64.standard_no_pad.Encoder.calcSize(32);
        const total = prefix.len + encoded;
        @memcpy(out[0..prefix.len], prefix);
        _ = std.base64.standard_no_pad.Encoder.encode(out[prefix.len..total], &hash);
        return out[0..total];
    }

    pub fn rawSession(self: *Session) *c.LIBSSH2_SESSION {
        return self.raw;
    }

    /// Spec 18: the auth-agent callback type (libssh2's
    /// LIBSSH2_AUTHAGENT_FUNC). Fires on the worker thread during
    /// packet processing when the server opens an auth-agent channel
    /// (the channel is already confirmed by the library).
    pub const AuthAgentCallback = *const fn (?*c.LIBSSH2_SESSION, ?*c.LIBSSH2_CHANNEL, ?*?*anyopaque) callconv(.c) void;

    /// Stores `ptr` in the session's abstract slot (used by the
    /// auth-agent callback to reach the owning Session).
    pub fn setAbstract(self: *Session, ptr: *anyopaque) void {
        const slot = c.libssh2_session_abstract(self.raw);
        slot.* = ptr;
    }

    /// Registers (or clears, with null) the auth-agent callback.
    pub fn setAuthAgentCallback(self: *Session, callback: ?AuthAgentCallback) void {
        _ = c.libssh2_session_callback_set2(self.raw, c.LIBSSH2_CALLBACK_AUTHAGENT, @ptrCast(callback));
    }

    pub fn authPassword(self: *Session, io: std.Io, user: []const u8, password: []const u8) Error!void {
        const deadline = deadlineFromNow(io, auth_timeout_ms);
        while (true) {
            const rc = c.libssh2_userauth_password_ex(
                self.raw,
                user.ptr,
                @intCast(user.len),
                password.ptr,
                @intCast(password.len),
                null,
            );
            if (rc == 0) return;
            if (isEagain(rc)) {
                try checkDeadline(io, deadline);
                try self.checkStop();
                try sleep(io);
                continue;
            }
            return if (rc == c.LIBSSH2_ERROR_AUTHENTICATION_FAILED) error.AuthFailed else error.Protocol;
        }
    }

    /// Maps a libssh2 auth return code to an Error. Anything libssh2
    /// attributes to the key material or credentials is AuthFailed;
    /// transport-level problems are Protocol.
    fn authError(rc: c_int) Error {
        return switch (rc) {
            c.LIBSSH2_ERROR_AUTHENTICATION_FAILED,
            c.LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED,
            c.LIBSSH2_ERROR_FILE,
            => error.AuthFailed,
            else => error.Protocol,
        };
    }

    /// Public-key auth where the private key bytes are supplied in
    /// memory (for keys the app manages itself rather than file paths).
    pub fn authKeyMemory(
        self: *Session,
        io: std.Io,
        user: []const u8,
        public_key: []const u8,
        private_key: []const u8,
        passphrase: []const u8,
    ) Error!void {
        const deadline = deadlineFromNow(io, auth_timeout_ms);
        while (true) {
            const rc = c.libssh2_userauth_publickey_frommemory(
                self.raw,
                user.ptr,
                @intCast(user.len),
                if (public_key.len > 0) public_key.ptr else null,
                @intCast(public_key.len),
                private_key.ptr,
                @intCast(private_key.len),
                if (passphrase.len > 0) passphrase.ptr else null,
            );
            if (rc == 0) return;
            if (isEagain(rc)) {
                try checkDeadline(io, deadline);
                try self.checkStop();
                try sleep(io);
                continue;
            }
            return authError(rc);
        }
    }

    /// Ed25519 public-key auth implemented natively: the mbedTLS
    /// backend has no Ed25519 support (LIBSSH2_ED25519 == 0), so we use
    /// libssh2's generic publickey API with a sign callback backed by
    /// Zig std.crypto. `user` must be null-terminated (this API takes
    /// no username length).
    pub fn authEd25519(
        self: *Session,
        io: std.Io,
        user: [:0]const u8,
        public_wire: []const u8,
        key_pair: *const std.crypto.sign.Ed25519.KeyPair,
    ) Error!void {
        var abstract: ?*anyopaque = @ptrCast(@constCast(key_pair));
        const deadline = deadlineFromNow(io, auth_timeout_ms);
        while (true) {
            const rc = c.libssh2_userauth_publickey(
                self.raw,
                user.ptr,
                public_wire.ptr,
                public_wire.len,
                ed25519SignCallback,
                &abstract,
            );
            if (rc == 0) return;
            if (isEagain(rc)) {
                try checkDeadline(io, deadline);
                try self.checkStop();
                try sleep(io);
                continue;
            }
            return authError(rc);
        }
    }

    /// libssh2 sign callback: signs the auth payload with the Ed25519
    /// key pair carried in `abstract`. Returns ONLY the raw 64-byte
    /// signature — userauth.c wraps it in the signature blob (string
    /// method || string sig) itself. The buffer is malloc'd; libssh2
    /// frees it with its default allocator (free).
    fn ed25519SignCallback(
        session: ?*c.LIBSSH2_SESSION,
        sig: [*c][*c]u8,
        sig_len: [*c]usize,
        data: [*c]const u8,
        data_len: usize,
        abstract: [*c]?*anyopaque,
    ) callconv(.c) c_int {
        _ = session;
        const key_pair: *const std.crypto.sign.Ed25519.KeyPair = @ptrCast(@alignCast(abstract.*));
        const message = data[0..data_len];
        const signature = key_pair.sign(message, null) catch return -1;
        const sig_bytes = signature.toBytes();

        const blob = std.heap.c_allocator.alloc(u8, 64) catch return -1;
        @memcpy(blob, &sig_bytes);
        sig.* = blob.ptr;
        sig_len.* = blob.len;
        return 0;
    }

    /// Test-only alias so probes can drive the callback directly.
    pub const testSignCallback = ed25519SignCallback;

    /// Lazily initializes the SFTP subsystem (worker thread only; the
    /// libssh2 session is not thread-safe).
    pub fn sftpInit(self: *Session, io: std.Io) Error!*c.LIBSSH2_SFTP {
        if (self.sftp) |s| return s;
        const deadline = deadlineFromNow(io, handshake_timeout_ms);
        while (true) {
            if (c.libssh2_sftp_init(self.raw)) |sftp| {
                self.sftp = sftp;
                return sftp;
            }
            const rc = c.libssh2_session_last_errno(self.raw);
            if (!isEagain(rc)) return error.Protocol;
            try checkDeadline(io, deadline);
            try self.checkStop();
            try sleep(io);
        }
    }

    /// Releases the SFTP subsystem. Idempotent.
    pub fn sftpShutdown(self: *Session) void {
        if (self.sftp) |s| {
            _ = c.libssh2_sftp_shutdown(s);
            self.sftp = null;
        }
    }

    pub fn keepaliveConfig(self: *Session) void {
        _ = c.libssh2_keepalive_config(self.raw, 0, 30);
    }

    /// Sends a keepalive if one is due. Returns whether one was sent.
    pub fn keepaliveSend(self: *Session, io: std.Io) Error!bool {
        _ = io;
        var seconds_to_next: c_int = 0;
        const rc = c.libssh2_keepalive_send(self.raw, &seconds_to_next);
        if (rc == 0) return seconds_to_next == 0;
        if (isEagain(rc)) return false;
        return error.Protocol;
    }

    pub fn openChannel(self: *Session, io: std.Io) Error!*Channel {
        const deadline = deadlineFromNow(io, handshake_timeout_ms);
        while (true) {
            const raw = c.libssh2_channel_open_ex(
                self.raw,
                "session",
                7,
                @as(c_uint, 2 * 1024 * 1024),
                @as(c_uint, 32 * 1024),
                null,
                0,
            );
            if (raw != null) {
                const ch = self.allocator.create(Channel) catch return error.NoChannel;
                ch.* = .{
                    .raw = raw.?,
                    .allocator = self.allocator,
                    .stop_fn = self.stop_fn,
                    .stop_ctx = self.stop_ctx,
                };
                return ch;
            }
            const rc = c.libssh2_session_last_errno(self.raw);
            if (!isEagain(rc)) return error.NoChannel;
            try checkDeadline(io, deadline);
            try self.checkStop();
            try sleep(io);
        }
    }

    /// Opens a direct-tcpip channel to `host:port` as seen by the SSH
    /// server (spec 12: the VNC tunnel; the server sees the connection
    /// as coming from its own loopback).
    pub fn openTunnel(self: *Session, io: std.Io, host: []const u8, port: u16) Error!*Channel {
        const host_z = self.allocator.dupeZ(u8, host) catch return error.NoChannel;
        defer self.allocator.free(host_z);
        const deadline = deadlineFromNow(io, handshake_timeout_ms);
        while (true) {
            const raw = c.libssh2_channel_direct_tcpip_ex(self.raw, host_z.ptr, @intCast(port), "127.0.0.1", 0);
            if (raw != null) {
                const ch = self.allocator.create(Channel) catch {
                    _ = c.libssh2_channel_free(raw);
                    return error.NoChannel;
                };
                ch.* = .{
                    .raw = raw.?,
                    .allocator = self.allocator,
                    .stop_fn = self.stop_fn,
                    .stop_ctx = self.stop_ctx,
                };
                return ch;
            }
            const rc = c.libssh2_session_last_errno(self.raw);
            if (!isEagain(rc)) return error.NoChannel;
            try checkDeadline(io, deadline);
            try self.checkStop();
            try sleep(io);
        }
    }

    /// Human-readable message for the last session error, copied into
    /// `buf` (caller-owned, typically 256 bytes).
    pub fn lastErrorMessage(self: *Session, buf: []u8) []const u8 {
        var errmsg: [*c]u8 = null;
        var errmsg_len: c_int = 0;
        _ = c.libssh2_session_last_error(self.raw, &errmsg, &errmsg_len, 0);
        if (errmsg == null or errmsg_len <= 0) return "unknown SSH error";
        const len = @min(@as(usize, @intCast(errmsg_len)), buf.len - 1);
        @memcpy(buf[0..len], errmsg[0..len]);
        return buf[0..len];
    }

    /// Disconnects and frees whatever `connect` managed to establish.
    /// Idempotent: safe on a Session whose connect failed partway, and
    /// safe to call twice.
    pub fn disconnect(self: *Session, io: std.Io) void {
        if (self.session_open) {
            self.sftpShutdown();
            _ = c.libssh2_session_disconnect_ex(self.raw, c.LIBSSH2_ERROR_NONE, "oars: bye", "oars: bye");
            _ = c.libssh2_session_free(self.raw);
            self.session_open = false;
        }
        if (self.socket_open) {
            io.vtable.netClose(io.userdata, @as([]const i32, &.{self.socket}));
            self.socket_open = false;
        }
    }

    pub fn deinitGlobal() void {
        c.libssh2_exit();
    }
};

pub const Channel = struct {
    raw: *c.LIBSSH2_CHANNEL,
    allocator: std.mem.Allocator,
    /// Stop signal inherited from the owning session so channel deadline
    /// loops stay disconnect-responsive too.
    stop_fn: ?*const fn (?*anyopaque) bool = null,
    stop_ctx: ?*anyopaque = null,

    fn checkStop(self: *const Channel) Error!void {
        if (self.stop_fn) |f| if (f(self.stop_ctx)) return error.Canceled;
    }

    pub fn requestPty(self: *Channel, io: std.Io, cols: c_int, rows: c_int) Error!void {
        const deadline = deadlineFromNow(io, handshake_timeout_ms);
        while (true) {
            const rc = c.libssh2_channel_request_pty_ex(
                self.raw,
                "xterm-256color",
                13,
                null,
                0,
                cols,
                rows,
                0,
                0,
            );
            if (rc == 0) return;
            if (isEagain(rc)) {
                try checkDeadline(io, deadline);
                try self.checkStop();
                try sleep(io);
                continue;
            }
            return error.Protocol;
        }
    }

    /// Spec 18: requests auth-agent forwarding on this channel. The
    /// server must allow it (AllowAgentForwarding); denial surfaces as
    /// `error.Refused`. The request alone does not complete the data
    /// path — the session worker proxies accepted channels to the
    /// local agent socket.
    pub fn requestAuthAgent(self: *Channel, io: std.Io) Error!void {
        const deadline = deadlineFromNow(io, handshake_timeout_ms);
        while (true) {
            const rc = c.libssh2_channel_request_auth_agent(self.raw);
            if (rc == 0) return;
            if (isEagain(rc)) {
                try checkDeadline(io, deadline);
                try self.checkStop();
                try sleep(io);
                continue;
            }
            if (rc == c.LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED) return error.Refused;
            return error.Protocol;
        }
    }

    pub fn setEnv(self: *Channel, io: std.Io, name: []const u8, value: []const u8) Error!void {
        const deadline = deadlineFromNow(io, handshake_timeout_ms);
        while (true) {
            const rc = c.libssh2_channel_setenv_ex(
                self.raw,
                name.ptr,
                @intCast(name.len),
                value.ptr,
                @intCast(value.len),
            );
            if (rc == 0) return;
            if (isEagain(rc)) {
                try checkDeadline(io, deadline);
                try self.checkStop();
                try sleep(io);
                continue;
            }
            return error.Protocol;
        }
    }

    /// Requests a new PTY size on the live channel (spec 02 §5: resize is
    /// implemented and reports failure — it is not a no-op).
    pub fn resizePty(self: *Channel, io: std.Io, cols: c_int, rows: c_int) Error!void {
        const deadline = deadlineFromNow(io, handshake_timeout_ms);
        while (true) {
            const rc = c.libssh2_channel_request_pty_size_ex(self.raw, cols, rows, 0, 0);
            if (rc == 0) return;
            if (isEagain(rc)) {
                try checkDeadline(io, deadline);
                try self.checkStop();
                try sleep(io);
                continue;
            }
            return error.Protocol;
        }
    }

    pub fn shell(self: *Channel, io: std.Io) Error!void {
        const deadline = deadlineFromNow(io, handshake_timeout_ms);
        while (true) {
            // cImport cannot translate the libssh2_channel_shell inline
            // helper (usize->c_uint sizeof cast), so call the underlying
            // startup request directly.
            const rc = c.libssh2_channel_process_startup(self.raw, "shell", 5, null, 0);
            if (rc == 0) return;
            if (isEagain(rc)) {
                try checkDeadline(io, deadline);
                try self.checkStop();
                try sleep(io);
                continue;
            }
            return error.Protocol;
        }
    }

    pub fn exec(self: *Channel, io: std.Io, command: []const u8) Error!void {
        const deadline = deadlineFromNow(io, handshake_timeout_ms);
        while (true) {
            // See shell(): bypass the untranslatable inline helper.
            const rc = c.libssh2_channel_process_startup(self.raw, "exec", 4, command.ptr, @intCast(command.len));
            if (rc == 0) return;
            if (isEagain(rc)) {
                try checkDeadline(io, deadline);
                try self.checkStop();
                try sleep(io);
                continue;
            }
            return error.Protocol;
        }
    }

    /// Reads up to buf.len bytes. Returns:
    ///   .eof            channel is at end of file, or the transport
    ///                   underneath it failed (wound down like an eof so
    ///                   the run loop cannot spin on a dead session)
    ///   .data(n)        n bytes written into buf
    ///   .again          no data right now (non-blocking)
    pub const ReadResult = union(enum) { eof, data: usize, again };

    pub fn read(self: *Channel, buf: []u8) ReadResult {
        const rc = c.libssh2_channel_read_ex(self.raw, 0, buf.ptr, buf.len);
        if (rc == 0) return .eof;
        if (rc < 0) {
            const code: c_int = @intCast(rc);
            return if (isEagain(code)) .again else .eof;
        }
        return .{ .data = @intCast(rc) };
    }

    /// Writes data; returns bytes accepted (0 if EAGAIN).
    pub fn write(self: *Channel, data: []const u8) usize {
        const rc = c.libssh2_channel_write_ex(self.raw, 0, data.ptr, data.len);
        if (rc < 0) return 0;
        return @intCast(rc);
    }

    pub fn sendEof(self: *Channel) void {
        _ = c.libssh2_channel_send_eof(self.raw);
    }

    pub fn waitEof(self: *Channel, io: std.Io) Error!void {
        const deadline = deadlineFromNow(io, handshake_timeout_ms);
        while (true) {
            const rc = c.libssh2_channel_wait_eof(self.raw);
            if (rc == 0) return;
            if (isEagain(rc)) {
                try checkDeadline(io, deadline);
                try sleep(io);
                continue;
            }
            return error.Protocol;
        }
    }

    pub fn exitStatus(self: *Channel) i32 {
        return c.libssh2_channel_get_exit_status(self.raw);
    }

    /// Closes and frees the libssh2 channel and destroys the handle.
    /// Call exactly once per open channel (entry teardown is guarded by
    /// `raw_closed`); the handle must not be touched afterwards.
    pub fn close(self: *Channel, io: std.Io) void {
        _ = c.libssh2_channel_close(self.raw);
        _ = c.libssh2_channel_wait_closed(self.raw);
        _ = c.libssh2_channel_free(self.raw);
        _ = io;
        self.allocator.destroy(self);
    }
};

// --- tests ---------------------------------------------------------------

test "fingerprint is SHA256 base64 without padding" {
    // SHA-256 of the empty string, encoded with the standard unpadded
    // base64 alphabet (the OpenSSH canonical form).
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("", &digest, .{});
    var buf: [64]u8 = undefined;
    const fp = Session.fingerprintFromHash(digest, &buf);
    try std.testing.expectEqualStrings("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU", fp);
}

test "fingerprint buffer fits the trust dialog budget" {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("oars", &digest, .{});
    var buf: [64]u8 = undefined;
    const fp = Session.fingerprintFromHash(digest, &buf);
    try std.testing.expectEqual(@as(usize, 50), fp.len);
}
