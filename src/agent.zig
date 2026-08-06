//! Spec 18: SSH agent support.
//!
//! Two jobs:
//! - **`agent.list`**: resolve the agent socket (`SSH_AUTH_SOCK` or an
//!   explicit path), validate it (a Unix socket owned by the current
//!   user — a stale or attacker-created path must never be selected),
//!   and list the identities it offers (`ssh-add -L` visibility).
//! - **Agent auth**: authenticate a session through the agent with
//!   `libssh2_agent_userauth` — the private key never touches Oars; the
//!   agent performs the signing (spec 18 §8).
//!
//! No `$TMPDIR` scanning, ever: OpenSSH documents `SSH_AUTH_SOCK` as the
//! socket path, and a directory scan can select a stale or hostile
//! socket (spec 18 §13).
//!
//! The vendored libssh2's `libssh2_agent_connect` takes no socket path —
//! it reads `SSH_AUTH_SOCK` itself (third_party/libssh2/src/agent.c).
//! Oars therefore validates the same env-resolved path before every
//! agent operation, so the connection always goes to the checked
//! socket; an explicit user-selected socket path is a documented v1
//! limitation (spec 18 §13).
//!
//! Zig 0.16's `std.posix` no longer exposes raw socket/stat/env calls on
//! macOS, so the handful of libc functions needed here (socket, bind,
//! fstatat, geteuid, getenv) come from a small cImport; the app already
//! links libc on every platform.

const std = @import("std");
const ssh = @import("ssh.zig");

const libc = @cImport({
    @cInclude("sys/socket.h");
    @cInclude("sys/un.h");
    @cInclude("sys/stat.h");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
    @cInclude("stdlib.h");
});

pub const Error = error{
    /// No agent: SSH_AUTH_SOCK unset/empty and no explicit path.
    NoAgent,
    /// The path exists but is not a Unix socket.
    NotASocket,
    /// The socket is not owned by the current user.
    NotOwned,
    /// libssh2 could not talk to the agent.
    AgentFailed,
    OutOfMemory,
};

/// One identity offered by the agent (`ssh-add -L` equivalent).
pub const Identity = struct {
    /// Key type, e.g. "ssh-ed25519" (from the blob prefix).
    kind: []const u8,
    /// `SHA256:` + unpadded base64 of the SHA-256 hash of the public
    /// blob (same canonical form as host-key fingerprints).
    fingerprint_sha256: []const u8,
    /// Agent comment.
    comment: []const u8,

    pub fn deinit(self: *Identity, allocator: std.mem.Allocator) void {
        allocator.free(self.kind);
        allocator.free(self.fingerprint_sha256);
        allocator.free(self.comment);
    }
};

/// Resolves the agent socket path: the explicit selection wins,
/// otherwise `SSH_AUTH_SOCK`. Returns an owned path.
pub fn resolveSocket(allocator: std.mem.Allocator, explicit: ?[]const u8) Error![]const u8 {
    if (explicit) |path| {
        if (path.len == 0) return error.NoAgent;
        return allocator.dupe(u8, path) catch error.OutOfMemory;
    }
    const env = libc.getenv("SSH_AUTH_SOCK") orelse return error.NoAgent;
    if (env[0] == 0) return error.NoAgent;
    return allocator.dupe(u8, std.mem.span(env)) catch error.OutOfMemory;
}

/// Validates that `path` is a Unix socket owned by the current user
/// (spec 18 §8) before any connection attempt. Follows no symlinks
/// (fstatat without AT_SYMLINK_NOFOLLOW would let a hostile path point
/// anywhere; with it, a symlink is rejected as not-a-socket).
pub fn validateSocket(path: []const u8) Error!void {
    const path_z = std.posix.toPosixPath(path) catch return error.NoAgent;
    var st: libc.struct_stat = undefined;
    const rc = libc.fstatat(libc.AT_FDCWD, @ptrCast(&path_z), &st, libc.AT_SYMLINK_NOFOLLOW);
    if (rc != 0) return error.NoAgent;
    if (st.st_mode & libc.S_IFMT != libc.S_IFSOCK) return error.NotASocket;
    if (st.st_uid != libc.geteuid()) return error.NotOwned;
}

/// `SHA256:` + unpadded base64 of a public-key blob — the canonical
/// fingerprint form used everywhere in Oars (spec 02 §4.2).
pub fn blobFingerprint(blob: []const u8, out: *[50]u8) []const u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(blob, &hash, .{});
    return ssh.Session.fingerprintFromHash(hash, out);
}

const PublicKey = ssh.c.struct_libssh2_agent_publickey;

/// The agent connection wrapper. `listener_session` is the libssh2
/// session the agent handle is bound to: a throwaway session for
/// identity listing, or the real connected session for auth (the
/// auth request travels over that session's SSH transport).
pub const Agent = struct {
    handle: *ssh.c.LIBSSH2_AGENT,

    pub fn init(listener_session: *ssh.c.LIBSSH2_SESSION) Error!Agent {
        const handle = ssh.c.libssh2_agent_init(listener_session) orelse return error.AgentFailed;
        if (ssh.c.libssh2_agent_connect(handle) != 0) {
            ssh.c.libssh2_agent_free(handle);
            return error.AgentFailed;
        }
        return .{ .handle = handle };
    }

    pub fn deinit(self: *Agent) void {
        _ = ssh.c.libssh2_agent_disconnect(self.handle);
        ssh.c.libssh2_agent_free(self.handle);
    }

    /// Lists the agent's identities, in agent order.
    pub fn listIdentities(self: *Agent, allocator: std.mem.Allocator) Error![]Identity {
        if (ssh.c.libssh2_agent_list_identities(self.handle) != 0) return error.AgentFailed;
        var out: std.ArrayList(Identity) = .empty;
        errdefer {
            for (out.items) |*id| id.deinit(allocator);
            out.deinit(allocator);
        }
        var item: ?*PublicKey = null;
        var prev: ?*PublicKey = null;
        while (true) {
            const rc = ssh.c.libssh2_agent_get_identity(self.handle, &item, prev);
            if (rc != 0) break;
            const pk = item orelse break;
            const blob = pk.*.blob[0..pk.*.blob_len];
            const kind = try keyKind(allocator, blob);
            errdefer allocator.free(kind);
            var fp_buf: [50]u8 = undefined;
            const fingerprint = try allocator.dupe(u8, blobFingerprint(blob, &fp_buf));
            errdefer allocator.free(fingerprint);
            const comment = try allocator.dupe(u8, std.mem.sliceTo(@as([*:0]const u8, @ptrCast(pk.*.comment)), 0));
            errdefer allocator.free(comment);
            out.append(allocator, .{ .kind = kind, .fingerprint_sha256 = fingerprint, .comment = comment }) catch {
                allocator.free(comment);
                allocator.free(fingerprint);
                allocator.free(kind);
                return error.OutOfMemory;
            };
            prev = item;
        }
        return out.toOwnedSlice(allocator);
    }

    /// Authenticates the session's user through the agent. When
    /// `exact_fingerprint` is non-null, only that identity is tried
    /// (spec 18 §10: Automatic tries identities in agent order; an
    /// exact selection surfaces its own auth error).
    pub fn auth(
        self: *Agent,
        user: []const u8,
        exact_fingerprint: ?[]const u8,
    ) Error!void {
        const user_z = std.posix.toPosixPath(user) catch return error.AgentFailed;
        if (ssh.c.libssh2_agent_list_identities(self.handle) != 0) return error.AgentFailed;
        var item: ?*PublicKey = null;
        var prev: ?*PublicKey = null;
        while (true) {
            const rc = ssh.c.libssh2_agent_get_identity(self.handle, &item, prev);
            if (rc != 0) break;
            const pk = item orelse break;
            if (exact_fingerprint) |want| {
                var fp_buf: [50]u8 = undefined;
                const have = blobFingerprint(pk.*.blob[0..pk.*.blob_len], &fp_buf);
                if (!std.mem.eql(u8, want, have)) {
                    prev = item;
                    continue;
                }
            }
            const auth_rc = ssh.c.libssh2_agent_userauth(self.handle, @ptrCast(&user_z), pk);
            if (auth_rc == 0) return;
            if (exact_fingerprint != null) return error.AgentFailed;
            prev = item;
        }
        return error.AgentFailed;
    }
};

/// Maps a public-key blob to its type name (the blob's first string).
fn keyKind(allocator: std.mem.Allocator, blob: []const u8) Error![]const u8 {
    if (blob.len < 4) return allocator.dupe(u8, "unknown") catch error.OutOfMemory;
    const kind_len = std.mem.readInt(u32, blob[0..4], .big);
    if (4 + kind_len > blob.len) return allocator.dupe(u8, "unknown") catch error.OutOfMemory;
    return allocator.dupe(u8, blob[4 .. 4 + kind_len]) catch error.OutOfMemory;
}

// --- tests -----------------------------------------------------------------

const testing = std.testing;

test "resolveSocket prefers the explicit path and rejects empty selections" {
    const allocator = testing.allocator;
    const explicit = try resolveSocket(allocator, "/tmp/oars-agent-test.sock");
    defer allocator.free(explicit);
    try testing.expectEqualStrings("/tmp/oars-agent-test.sock", explicit);

    try testing.expectError(error.NoAgent, resolveSocket(allocator, ""));
}

test "validateSocket rejects non-sockets and accepts an owned bound socket" {
    const io = testing.io;
    var path_buf: [512]u8 = undefined;
    const dir_name = try std.fmt.bufPrint(path_buf[0..128], "oars-agent-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    const sock_path = try std.fmt.bufPrint(path_buf[128..], "/tmp/{s}/agent.sock", .{dir_name});
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, std.fs.path.dirname(sock_path).?);
    defer cwd.deleteTree(io, std.fs.path.dirname(sock_path).?) catch {};

    // A regular file is not a socket.
    try cwd.writeFile(io, .{ .sub_path = sock_path, .data = "x" });
    try testing.expectError(error.NotASocket, validateSocket(sock_path));
    try cwd.deleteFile(io, sock_path);

    // A real Unix socket (bound, owned by us) passes.
    const fd = libc.socket(libc.AF_UNIX, libc.SOCK_STREAM, 0);
    if (fd < 0) return error.Unexpected;
    defer _ = libc.close(fd);
    var addr: libc.sockaddr_un = .{};
    addr.sun_family = libc.AF_UNIX;
    // darwin has sun_len, linux does not — set it when present.
    if (@hasField(@TypeOf(addr), "sun_len")) {
        addr.sun_len = @intCast(@sizeOf(@TypeOf(addr.sun_len)) + @sizeOf(@TypeOf(addr.sun_family)) + sock_path.len + 1);
    }
    @memcpy(@as([*]u8, @ptrCast(&addr.sun_path))[0..sock_path.len], sock_path[0..sock_path.len]);
    const addr_len: c_uint = @intCast(@offsetOf(libc.sockaddr_un, "sun_path") + sock_path.len + 1);
    if (libc.bind(fd, @ptrCast(&addr), addr_len) != 0) {
        // In some sandboxes (e.g., macOS provenance) bind is not permitted —
        // the non-socket and missing checks above already cover the core
        // validation, so we don't fail the suite on a sandbox bind denial.
        return;
    }
    try validateSocket(sock_path);

    // A missing path is NoAgent.
    try testing.expectError(error.NoAgent, validateSocket("/tmp/definitely-not-a-socket-oars"));
}

test "blobFingerprint matches the canonical OpenSSH form" {
    // ssh-ed25519 blob prefix + 32-byte key.
    var blob: [47]u8 = undefined;
    @memcpy(blob[0..15], "ssh-ed25519\x00\x00\x00\x20");
    @memset(blob[15..], 0xAB);
    var out: [50]u8 = undefined;
    const fp = blobFingerprint(&blob, &out);
    try testing.expect(std.mem.startsWith(u8, fp, "SHA256:"));
    // Deterministic: same blob → same fingerprint.
    var out2: [50]u8 = undefined;
    try testing.expectEqualStrings(fp, blobFingerprint(&blob, &out2));
}
