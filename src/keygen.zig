//! Local key generation (spec 08 §6): launches the installed OpenSSH
//! `ssh-keygen` through a private pseudo-terminal. Oars supplies
//! `-q -t ed25519 -f <temp>` and an optional comment; a non-empty
//! passphrase is written to the terminal ONLY, after validating the
//! expected prompt sequence — it never appears in process arguments,
//! environment variables, logs, or audit text (LC_ALL=C forces the
//! English prompts the state machine recognizes). Any unexpected prompt
//! or output aborts the run. The generated pair is verified (public key
//! parses, private mode is 0600) before a no-clobber install at the
//! approved destination; a partial install is rolled back.
//!
//! The PTY is created with posix_openpt in the parent; the child calls
//! setsid + TIOCSCTTY so ssh-keygen's `/dev/tty` passphrase prompt
//! resolves, then dup2s the slave over stdin/stdout/stderr and execs.
//! Everything the child touches between fork and exec is
//! async-signal-safe; argv/envp are fully built before the fork.

const std = @import("std");
const builtin = @import("builtin");

pub const keygen_timeout_ns: i128 = 30 * std.time.ns_per_s;
/// Bounded pty capture: unexpected output beyond this aborts.
const output_cap: usize = 16 * 1024;
const max_passphrase_bytes: usize = 1024;

pub const KeygenError = error{
    InvalidDestination,
    DestinationMissing,
    DestinationExists,
    SshKeygenMissing,
    PtyFailed,
    SpawnFailed,
    UnexpectedOutput,
    PromptFailed,
    GenerationFailed,
    VerifyFailed,
    InstallFailed,
    Timeout,
    OutOfMemory,
};

pub const Generated = struct {
    /// Canonical `type blob comment` line of the public key (owned).
    public_key: []u8,
    /// The installed private key path (owned).
    private_path: []u8,
    /// "SHA256:…" fingerprint of the public key (owned).
    fingerprint_sha256: []u8,
};

pub const GenerateOptions = struct {
    /// Absolute path for the private key; the public half lands at
    /// `<destination>.pub`. Neither may already exist.
    destination: []const u8,
    comment: ?[]const u8 = null,
    passphrase: ?[]const u8 = null,
};

// --- prompt state machine (pure, unit-tested) ------------------------------

/// The prompt sequence `ssh-keygen` emits for a non-empty passphrase
/// (LC_ALL=C): banner, "Enter passphrase (empty for no passphrase): ",
/// "Enter same passphrase again: ", then "Saving key …". Anything else —
/// an overwrite prompt, a mismatch loop, or a third prompt — aborts.
pub const PromptAction = union(enum) {
    /// Keep reading.
    await,
    /// Send the passphrase (first prompt).
    send_first,
    /// Send the passphrase again (confirmation prompt).
    send_confirm,
    /// The key was saved: stop feeding and wait for the child.
    saving,
    /// Abort: unexpected prompt or output (static reason).
    fail: []const u8,
};

const first_prompt = "(empty for no passphrase): ";
const confirm_prompt = "Enter same passphrase again: ";
const overwrite_prompt = "Overwrite (y/n)?";
const mismatch_text = "Passphrases do not match";
const saving_text = "Saving key";

pub fn promptAction(output: []const u8, sent: usize) PromptAction {
    if (std.mem.indexOf(u8, output, mismatch_text) != null) return .{ .fail = "passphrase mismatch" };
    if (std.mem.indexOf(u8, output, overwrite_prompt) != null) return .{ .fail = "the key already exists" };
    switch (sent) {
        0 => {
            if (std.mem.indexOf(u8, output, first_prompt) != null) return .send_first;
        },
        1 => {
            if (std.mem.indexOf(u8, output, confirm_prompt) != null) return .send_confirm;
        },
        else => {
            if (std.mem.indexOf(u8, output, saving_text) != null) return .saving;
            // A repeated first prompt after both sends is a mismatch loop
            // (the earlier prompts are still in the accumulated output,
            // so a loop is exactly two occurrences).
            if (std.mem.count(u8, output, first_prompt) > 1) {
                return .{ .fail = "passphrase prompts did not complete" };
            }
        },
    }
    return .await;
}

// --- PTY plumbing -----------------------------------------------------------

const c = struct {
    extern "c" fn posix_openpt(flags: c_int) c_int;
    extern "c" fn grantpt(fd: c_int) c_int;
    extern "c" fn unlockpt(fd: c_int) c_int;
    extern "c" fn ptsname_r(fd: c_int, buf: [*]u8, buflen: usize) c_int;
    extern "c" fn open(path: [*:0]const u8, oflag: c_int, ...) c_int;
    extern "c" fn close(fd: c_int) c_int;
    extern "c" fn fork() c_int;
    extern "c" fn setsid() c_int;
    extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;
    extern "c" fn dup2(oldfd: c_int, newfd: c_int) c_int;
    extern "c" fn execve(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) c_int;
    extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;
    extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
    extern "c" fn waitpid(pid: c_int, status: *c_int, options: c_int) c_int;
    extern "c" fn _exit(code: c_int) noreturn;
};

const o_flags = switch (builtin.os.tag) {
    .macos => struct {
        const rdwr: c_int = 0x0002;
        const noctty: c_int = 0x20000;
        const tioctty: c_ulong = 0x20007461;
    },
    .linux => struct {
        const rdwr: c_int = 0o2;
        const noctty: c_int = 0o400;
        const tioctty: c_ulong = 0x540E;
    },
    else => @compileError("keygen PTY support: macOS and Linux only"),
};

const POLLIN: c_short = 0x1;
const WNOHANG: c_int = 1;

/// Resolves `ssh-keygen` on PATH (executable check); null when missing.
fn findSshKeygen(io: std.Io, allocator: std.mem.Allocator) !?[:0]u8 {
    var path: []const u8 = "";
    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        const raw: []const u8 = std.mem.span(entry);
        if (std.mem.startsWith(u8, raw, "PATH=")) {
            path = raw[5..];
            break;
        }
    }
    var it = std.mem.splitScalar(u8, path, ':');
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = try std.fmt.allocPrint(allocator, "{s}/ssh-keygen", .{dir});
        defer allocator.free(candidate);
        if (std.Io.Dir.cwd().access(io, candidate, .{ .execute = true })) |_| {
            return try allocator.dupeZ(u8, candidate);
        } else |_| {}
    }
    return null;
}

/// Runs ssh-keygen with the given argv (built by the caller, exclusive
/// of the program name) and the passphrase protocol. `passphrase` null
/// means `-N ""` was passed (no prompts — output is drained only).
fn runSshKeygen(
    io: std.Io,
    allocator: std.mem.Allocator,
    ssh_keygen_path: [:0]const u8,
    argv_tail: []const []const u8,
    passphrase: ?[]const u8,
) KeygenError!void {
    const master = c.posix_openpt(o_flags.rdwr | o_flags.noctty);
    if (master < 0) return error.PtyFailed;
    defer _ = c.close(master);
    if (c.grantpt(master) != 0) return error.PtyFailed;
    if (c.unlockpt(master) != 0) return error.PtyFailed;
    var slave_name: [64]u8 = undefined;
    if (c.ptsname_r(master, &slave_name, slave_name.len) != 0) return error.PtyFailed;
    // ptsname_r NUL-terminates the buffer; the slice carries the sentinel.
    const slave_path: [:0]const u8 = @ptrCast(std.mem.sliceTo(&slave_name, 0));
    const slave = c.open(slave_path.ptr, o_flags.rdwr | o_flags.noctty);
    if (slave < 0) return error.PtyFailed;
    defer _ = c.close(slave);

    // Build argv/envp before the fork: the child must not allocate.
    const argv = try allocator.allocSentinel(?[*:0]const u8, argv_tail.len + 1, null);
    defer allocator.free(argv);
    argv[0] = ssh_keygen_path.ptr;
    for (argv_tail, 0..) |a, i| argv[i + 1] = try allocator.dupeZ(u8, a);
    defer for (argv[1 .. argv_tail.len + 1]) |a| allocator.free(std.mem.span(a.?));

    var env_count: usize = 0;
    while (std.c.environ[env_count]) |_| env_count += 1;
    const envp = try allocator.allocSentinel(?[*:0]const u8, env_count + 1, null);
    defer allocator.free(envp);
    var e: usize = 0;
    while (std.c.environ[e]) |entry| : (e += 1) envp[e] = entry;
    envp[env_count] = "LC_ALL=C";

    const pid = c.fork();
    if (pid < 0) return error.SpawnFailed;
    if (pid == 0) {
        // Child: async-signal-safe only.
        _ = c.setsid();
        _ = c.ioctl(slave, o_flags.tioctty, @as(c_int, 0));
        _ = c.dup2(slave, 0);
        _ = c.dup2(slave, 1);
        _ = c.dup2(slave, 2);
        if (slave > 2) _ = c.close(slave);
        _ = c.execve(ssh_keygen_path.ptr, argv.ptr, envp.ptr);
        c._exit(127);
    }

    // Parent: drive the prompts over the master.
    var scratch: std.ArrayList(u8) = .empty;
    defer {
        // The scratch holds pty output only (the passphrase is never
        // echoed back), but clear it anyway before freeing.
        std.crypto.secureZero(u8, scratch.items);
        scratch.deinit(allocator);
    }
    var sent: usize = 0;
    const pass = passphrase orelse "";
    var feeding = passphrase != null;
    const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + keygen_timeout_ns;
    var status: c_int = 0;
    var child_done = false;
    var saw_eof = false;

    while (true) {
        if (std.Io.Timestamp.now(io, .real).nanoseconds >= deadline) return error.Timeout;
        var fds = [_]std.posix.pollfd{.{ .fd = master, .events = POLLIN, .revents = 0 }};
        const nfds = std.posix.poll(&fds, 250) catch return error.SpawnFailed;
        if (nfds > 0 and (fds[0].revents & POLLIN) != 0) {
            var buf: [4096]u8 = undefined;
            const n = c.read(master, &buf, buf.len);
            if (n > 0) {
                if (scratch.items.len + @as(usize, @intCast(n)) > output_cap) return error.UnexpectedOutput;
                try scratch.appendSlice(allocator, buf[0..@intCast(n)]);
                if (feeding) {
                    const action = promptAction(scratch.items, sent);
                    switch (action) {
                        .send_first, .send_confirm => {
                            const written = c.write(master, pass.ptr, pass.len);
                            if (written != @as(isize, @intCast(pass.len))) return error.PromptFailed;
                            _ = c.write(master, "\n", 1);
                            sent += 1;
                        },
                        .saving => feeding = false,
                        .fail => |reason| {
                            _ = reason;
                            return error.PromptFailed;
                        },
                        .await => {},
                    }
                }
            } else {
                saw_eof = true;
            }
        }
        const wpid = c.waitpid(pid, &status, WNOHANG);
        if (wpid == pid) {
            child_done = true;
            break;
        }
        if (saw_eof and sent >= 2 or saw_eof and passphrase == null) break;
        if (saw_eof and feeding) return error.PromptFailed;
    }

    if (!child_done) {
        _ = c.waitpid(pid, &status, 0);
    }
    if (!std.posix.W.IFEXITED(@intCast(status)) or std.posix.W.EXITSTATUS(@intCast(status)) != 0) return error.GenerationFailed;
}

// --- public API -------------------------------------------------------------

/// Generates an ed25519 pair at `options.destination` (and `.pub`),
/// refusing existing destinations and rolling back partial installs.
pub fn generate(io: std.Io, allocator: std.mem.Allocator, options: GenerateOptions) KeygenError!Generated {
    if (!std.fs.path.isAbsolute(options.destination)) return error.InvalidDestination;
    if (options.destination.len > 2048) return error.InvalidDestination;
    if (options.passphrase) |p| {
        if (p.len > max_passphrase_bytes) return error.InvalidDestination;
        if (std.mem.indexOfAny(u8, p, "\r\n") != null) return error.InvalidDestination;
    }
    const dirname = std.fs.path.dirname(options.destination) orelse return error.InvalidDestination;
    const base = std.fs.path.basename(options.destination);
    if (base.len == 0 or std.mem.eql(u8, base, ".") or std.mem.eql(u8, base, "..")) return error.InvalidDestination;

    // The destination directory must exist; the outputs must not.
    std.Io.Dir.cwd().access(io, dirname, .{ .read = true }) catch return error.DestinationMissing;
    if (std.Io.Dir.cwd().access(io, options.destination, .{})) |_| {
        return error.DestinationExists;
    } else |_| {}
    const pub_dest = try std.fmt.allocPrint(allocator, "{s}.pub", .{options.destination});
    defer allocator.free(pub_dest);
    if (std.Io.Dir.cwd().access(io, pub_dest, .{})) |_| {
        return error.DestinationExists;
    } else |_| {}

    const ssh_keygen_path = (try findSshKeygen(io, allocator)) orelse return error.SshKeygenMissing;
    defer allocator.free(ssh_keygen_path);

    // Temp names in the destination directory (same filesystem, so the
    // no-clobber install can move them). Owner-only directory semantics
    // come from ssh-keygen creating 0600 files here.
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    const tmp = try std.fmt.allocPrint(allocator, "{s}/.{s}.oars-tmp-{d}", .{ dirname, base, now });
    defer allocator.free(tmp);
    const tmp_pub = try std.fmt.allocPrint(allocator, "{s}.pub", .{tmp});
    defer allocator.free(tmp_pub);
    if (std.Io.Dir.cwd().access(io, tmp, .{})) |_| {
        return error.DestinationExists;
    } else |_| {}

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, "-q");
    try argv.append(allocator, "-t");
    try argv.append(allocator, "ed25519");
    try argv.append(allocator, "-f");
    try argv.append(allocator, tmp);
    if (options.comment) |comment| {
        if (comment.len > 256 or std.mem.indexOfAny(u8, comment, "\r\n") != null) return error.InvalidDestination;
        try argv.append(allocator, "-C");
        try argv.append(allocator, comment);
    }
    if (options.passphrase == null) {
        try argv.append(allocator, "-N");
        try argv.append(allocator, "");
    }

    // Cleanup the temp pair on any failure after this point.
    var installed = false;
    errdefer {
        if (!installed) {
            std.Io.Dir.cwd().deleteFile(io, tmp) catch {};
            std.Io.Dir.cwd().deleteFile(io, tmp_pub) catch {};
        }
    }

    try runSshKeygen(io, allocator, ssh_keygen_path, argv.items, options.passphrase);

    // Verify before install: the private mode is 0600 and the public key
    // parses (spec 08 §6: verify, then no-clobber install).
    var priv_file = std.Io.Dir.cwd().openFile(io, tmp, .{}) catch return error.VerifyFailed;
    defer priv_file.close(io);
    const priv_stat = priv_file.stat(io) catch return error.VerifyFailed;
    if (priv_stat.permissions.toMode() & 0o777 != 0o600) return error.VerifyFailed;

    const pub_content = std.Io.Dir.cwd().readFileAlloc(io, tmp_pub, allocator, .limited(16 * 1024)) catch return error.VerifyFailed;
    defer allocator.free(pub_content);
    const sshkeys = @import("sshkeys.zig");
    const normalized = sshkeys.normalizePublicKey(allocator, std.mem.trim(u8, pub_content, " \t\r\n"), null) catch return error.VerifyFailed;
    errdefer {
        allocator.free(normalized.line);
        allocator.free(normalized.fingerprint_sha256);
    }

    // No-clobber install: private first, then public; roll back the
    // private half if the public install fails (two files cannot move as
    // one atomic operation — spec 08 §5).
    const cwd = std.Io.Dir.cwd();
    std.Io.Dir.renamePreserve(cwd, tmp, cwd, options.destination, io) catch |err| {
        return switch (err) {
            error.PathAlreadyExists => error.DestinationExists,
            else => error.InstallFailed,
        };
    };
    installed = true;
    errdefer std.Io.Dir.cwd().deleteFile(io, options.destination) catch {};
    std.Io.Dir.renamePreserve(cwd, tmp_pub, cwd, pub_dest, io) catch |err| {
        return switch (err) {
            error.PathAlreadyExists => error.DestinationExists,
            else => error.InstallFailed,
        };
    };

    return .{
        .public_key = normalized.line,
        .private_path = try allocator.dupe(u8, options.destination),
        .fingerprint_sha256 = normalized.fingerprint_sha256,
    };
}

// --- tests -----------------------------------------------------------------

const testing = std.testing;

test "prompt state machine walks the ssh-keygen passphrase sequence" {
    // Banner alone: keep reading.
    try testing.expect(promptAction("Generating public/private ed25519 key pair.", 0) == .await);
    // First prompt appears (the key path is part of it): send.
    try testing.expect(promptAction("Generating public/private ed25519 key pair.\r\nEnter passphrase for \"/tmp/x\" (empty for no passphrase): ", 0) == .send_first);
    // Confirmation prompt: send again.
    try testing.expect(promptAction("Enter passphrase for \"/tmp/x\" (empty for no passphrase): \r\nEnter same passphrase again: ", 1) == .send_confirm);
    // Saving after both sends (the earlier prompts stay in the output).
    try testing.expect(promptAction("Enter passphrase for \"/tmp/x\" (empty for no passphrase): \r\nEnter same passphrase again: \r\nSaving key \"/tmp/x\"", 2) == .saving);
}

fn failReason(a: PromptAction) ?[]const u8 {
    return switch (a) {
        .fail => |reason| reason,
        else => null,
    };
}

test "prompt state machine aborts on overwrite prompts and mismatch loops" {
    try testing.expectEqualStrings("the key already exists", failReason(promptAction("/tmp/x already exists.\r\nOverwrite (y/n)?", 0)).?);
    try testing.expectEqualStrings("passphrase mismatch", failReason(promptAction("Passphrases do not match. Try again.", 1)).?);
    // A repeated first prompt after both sends is a mismatch loop.
    const looped = "Enter passphrase for \"/tmp/x\" (empty for no passphrase): \r\nEnter same passphrase again: \r\nEnter passphrase for \"/tmp/x\" (empty for no passphrase): ";
    try testing.expectEqualStrings("passphrase prompts did not complete", failReason(promptAction(looped, 2)).?);
    // Random output is not answered.
    try testing.expect(promptAction("some unrelated output", 0) == .await);
}
