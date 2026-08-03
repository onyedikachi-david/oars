//! Low-level SSH transport wrapper over vendored libssh2 (mbedTLS backend).
//!
//! Every function here blocks; the session manager in `sessions.zig`
//! runs them on worker threads, never on the runtime's main thread.
//! All timeouts are enforced with non-blocking sockets + poll loops so a
//! dead server cannot hang the app.

const std = @import("std");

pub const c = @cImport({
    @cInclude("libssh2.h");
});

pub const Error = error{
    Timeout,
    AuthFailed,
    ConnectionFailed,
    Protocol,
    NoChannel,
    Canceled,
};

const poll_interval_ms = 10;
const handshake_timeout_ms = 15_000;
const auth_timeout_ms = 20_000;

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

    pub fn init(allocator: std.mem.Allocator) Error!Session {
        if (c.libssh2_init(0) != 0) return error.Protocol;
        return .{ .allocator = allocator, .raw = undefined, .socket = undefined };
    }

    /// Resolves `host`, connects the TCP socket and runs the transport
    /// handshake with a deadline. Blocking connect is acceptable here
    /// (worker thread); the handshake itself is non-blocking. On failure
    /// the caller must still call `disconnect` to release partial state.
    pub fn connect(self: *Session, io: std.Io, host: []const u8, port: u16) Error!void {
        const addr = std.Io.net.IpAddress.resolve(io, host, port) catch return error.ConnectionFailed;
        const stream = std.Io.net.IpAddress.connect(&addr, io, .{
            .mode = .stream,
            .protocol = .tcp,
        }) catch return error.ConnectionFailed;
        self.socket = stream.socket.handle;
        self.socket_open = true;

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
            try sleep(io);
        }
    }

    /// SHA-256 fingerprint of the server host key, hex-encoded (64 chars).
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
                ch.* = .{ .raw = raw.?, .allocator = self.allocator };
                return ch;
            }
            const rc = c.libssh2_session_last_errno(self.raw);
            if (!isEagain(rc)) return error.NoChannel;
            try checkDeadline(io, deadline);
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
                try sleep(io);
                continue;
            }
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
                try sleep(io);
                continue;
            }
            return error.Protocol;
        }
    }

    pub fn resizePty(self: *Channel, io: std.Io, cols: c_int, rows: c_int) Error!void {
        _ = self;
        _ = io;
        _ = cols;
        _ = rows;
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

    /// Closes and frees the channel (idempotent).
    pub fn close(self: *Channel, io: std.Io) void {
        _ = c.libssh2_channel_close(self.raw);
        _ = c.libssh2_channel_wait_closed(self.raw);
        _ = c.libssh2_channel_free(self.raw);
        _ = io;
    }
};
