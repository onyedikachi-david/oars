//! Spec 09: fleet-wide access map — identity registry, scan model,
//! fingerprint-keyed grant matching, mutation jobs, and CSV/JSON export
//! formatting.
//!
//! This module is pure logic + registries. The bridge handlers drive the
//! per-server execs/SFTP ops one step per poll (the deploy pattern) and
//! feed the results back in; nothing here touches the network.
//!
//! Canonical identity key = the decoded-key fingerprint (SHA256:<base64>),
//! never the authorized_keys comment (spec 09 §5).

const std = @import("std");
const sshkeys = @import("sshkeys.zig");

// --- identity registry -----------------------------------------------------

pub const max_identity_name_len: usize = 100;
pub const max_identity_fingerprints: usize = 64;
pub const identity_store_name = "access_identities.json";
/// Number of sha256 bytes a canonical fingerprint decodes to.
const fp_digest_len: usize = 32;

pub const Identity = struct {
    id: []const u8,
    name: []const u8,
    fingerprints: []const []const u8 = &.{},
    shared: bool = false,
    created_at_ns: i64 = 0,

    pub fn deinit(self: *Identity, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        for (self.fingerprints) |fp| allocator.free(fp);
        allocator.free(self.fingerprints);
    }
};

pub const IdentityInput = struct {
    id: ?[]const u8 = null,
    name: []const u8,
    fingerprints: []const []const u8 = &.{},
    shared: bool = false,
};

pub const IdentitySaveError = error{
    MissingName,
    InvalidName,
    NoFingerprints,
    TooManyFingerprints,
    InvalidFingerprint,
    DuplicateFingerprint,
    FingerprintOwned,
    MissingId,
    UnknownId,
    StoreCorrupt,
    SerializeFailed,
    OutOfMemory,
};

/// A canonical fingerprint is `SHA256:` + the standard base64 of exactly
/// 32 bytes (the decoded SSH wire blob, matching `ssh-keygen -lf`).
pub fn validFingerprint(fp: []const u8) bool {
    if (!std.mem.startsWith(u8, fp, "SHA256:")) return false;
    const b64 = fp["SHA256:".len..];
    if (b64.len == 0) return false;
    var decoded: [fp_digest_len]u8 = undefined;
    // ssh-keygen emits unpadded base64; some tools pad. Accept both.
    if (std.base64.standard_no_pad.Decoder.calcSizeForSlice(b64)) |size| {
        if (size != fp_digest_len) return false;
        std.base64.standard_no_pad.Decoder.decode(&decoded, b64) catch return false;
        return true;
    } else |_| {}
    const size = std.base64.standard.Decoder.calcSizeForSlice(b64) catch return false;
    if (size != fp_digest_len) return false;
    std.base64.standard.Decoder.decode(&decoded, b64) catch return false;
    return true;
}

pub const IdentityStore = struct {
    allocator: std.mem.Allocator = undefined,
    path: []const u8 = "",
    /// Monotonic id generator for new identities (in-memory only).
    next_id: u32 = 1,
    mutex: std.atomic.Mutex = .unlocked,

    pub const Loaded = struct {
        parsed: std.json.Parsed([]Identity),
        content: ?[]u8,
        quarantined: ?[]const u8 = null,

        pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
            self.parsed.deinit();
            if (self.content) |c| allocator.free(c);
            if (self.quarantined) |q| allocator.free(q);
        }
    };

    pub fn loadParsed(self: *IdentityStore, io: std.Io) !Loaded {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.loadParsedLocked(io);
    }

    fn loadParsedLocked(self: *IdentityStore, io: std.Io) !Loaded {
        const cwd = std.Io.Dir.cwd();
        const content = cwd.readFileAlloc(io, self.path, self.allocator, .limited(4 * 1024 * 1024)) catch return emptyLoaded(self.allocator);
        const parsed = std.json.parseFromSlice([]Identity, self.allocator, content, .{}) catch {
            self.allocator.free(content);
            var loaded = try emptyLoaded(self.allocator);
            loaded.quarantined = self.quarantine(io) catch null;
            return loaded;
        };
        return .{ .parsed = parsed, .content = content };
    }

    fn emptyLoaded(allocator: std.mem.Allocator) !Loaded {
        return .{
            .parsed = try std.json.parseFromSlice([]Identity, allocator, "[]", .{}),
            .content = null,
        };
    }

    fn quarantine(self: *IdentityStore, io: std.Io) !?[]const u8 {
        const now = std.Io.Timestamp.now(io, .real).nanoseconds;
        var buf: [512]u8 = undefined;
        const dir = std.fs.path.dirname(self.path) orelse return null;
        const base = std.fs.path.basename(self.path);
        const new_path = try std.fmt.bufPrint(&buf, "{s}/{s}.corrupt-{d}", .{ dir, base, now });
        std.Io.Dir.renameAbsolute(self.path, new_path, io) catch return null;
        return try self.allocator.dupe(u8, new_path);
    }

    fn saveLocked(self: *IdentityStore, io: std.Io, identities: []const Identity) !void {
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(self.path)) |dir| try cwd.createDirPath(io, dir);
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        std.json.Stringify.value(identities, .{ .whitespace = .indent_2 }, &out.writer) catch return error.SerializeFailed;
        var file = try cwd.createFile(io, self.path, .{});
        defer file.close(io);
        if (file.stat(io)) |stat| {
            if (stat.permissions.toMode() & 0o077 != 0) file.setPermissions(io, .fromMode(0o600)) catch {};
        } else |_| {}
        try file.writeStreamingAll(io, out.writer.buffered());
        try file.sync(io);
    }

    /// Upserts an identity. A fingerprint can belong to at most one person
    /// unless that person is explicitly marked shared (spec 09 §5).
    /// Returns an owned copy.
    pub fn save(self: *IdentityStore, io: std.Io, input: IdentityInput, now_ns: i64) IdentitySaveError!Identity {
        const name = std.mem.trim(u8, input.name, " \t\r\n");
        if (name.len == 0) return error.MissingName;
        if (name.len > max_identity_name_len or hasControlChars(name)) return error.InvalidName;
        if (input.fingerprints.len == 0) return error.NoFingerprints;
        if (input.fingerprints.len > max_identity_fingerprints) return error.TooManyFingerprints;
        for (input.fingerprints, 0..) |fp, i| {
            if (!validFingerprint(fp)) return error.InvalidFingerprint;
            for (input.fingerprints[i + 1 ..]) |other| {
                if (std.mem.eql(u8, fp, other)) return error.DuplicateFingerprint;
            }
        }

        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);

        // Resolve the id before anything can fail: edits must exist, new
        // identities get a generated id. `errdefer` below must never run on
        // an unassigned `saved`.
        var id_owned: ?[]u8 = null;
        defer if (id_owned) |i| self.allocator.free(i);
        var id: []const u8 = undefined;
        if (input.id) |i| {
            id = i;
        } else {
            id_owned = std.fmt.allocPrint(self.allocator, "id-{d}", .{self.next_id}) catch return error.OutOfMemory;
            self.next_id +%= 1;
            id = id_owned.?;
        }

        var is_edit = false;
        if (input.id != null) {
            for (loaded.parsed.value) |i| {
                if (std.mem.eql(u8, i.id, id)) {
                    is_edit = true;
                    break;
                }
            }
            if (!is_edit) return error.UnknownId;
        }

        // Ownership: an unshared fingerprint claimed by another identity is
        // a conflict (editing the same identity excludes itself).
        for (input.fingerprints) |fp| {
            if (input.shared) break;
            for (loaded.parsed.value) |i| {
                if (is_edit and std.mem.eql(u8, i.id, id)) continue;
                if (i.shared) continue; // shared holders never block
                for (i.fingerprints) |other| {
                    if (std.mem.eql(u8, fp, other)) return error.FingerprintOwned;
                }
            }
        }

        var out_list: std.ArrayList(Identity) = .empty;
        defer {
            for (out_list.items) |*i| i.deinit(self.allocator);
            out_list.deinit(self.allocator);
        }
        var created_at: i64 = now_ns;
        if (is_edit) {
            // Preserve the original created_at.
            for (loaded.parsed.value) |i| {
                if (std.mem.eql(u8, i.id, id)) created_at = i.created_at_ns;
            }
        }
        // Build every owned piece before assembling `saved`, so the
        // errdefer only ever sees a fully constructed value.
        const id_copy = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(id_copy);
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);
        const fingerprints_copy = try dupFingerprints(self.allocator, input.fingerprints);
        errdefer {
            for (fingerprints_copy) |f| self.allocator.free(f);
            self.allocator.free(fingerprints_copy);
        }
        var saved = Identity{
            .id = id_copy,
            .name = name_copy,
            .fingerprints = fingerprints_copy,
            .shared = input.shared,
            .created_at_ns = created_at,
        };
        errdefer saved.deinit(self.allocator);
        for (loaded.parsed.value) |i| {
            if (is_edit and std.mem.eql(u8, i.id, id)) continue;
            try out_list.append(self.allocator, try cloneIdentity(self.allocator, i));
        }
        try out_list.append(self.allocator, try cloneIdentity(self.allocator, saved));
        self.saveLocked(io, out_list.items) catch return error.SerializeFailed;
        return saved;
    }

    pub fn list(self: *IdentityStore, io: std.Io) ![]Identity {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        var out: std.ArrayList(Identity) = .empty;
        errdefer {
            for (out.items) |*i| i.deinit(self.allocator);
            out.deinit(self.allocator);
        }
        for (loaded.parsed.value) |i| {
            try out.append(self.allocator, try cloneIdentity(self.allocator, i));
        }
        return out.toOwnedSlice(self.allocator);
    }

    /// Returns an owned copy of the identity with `id`, or null.
    pub fn find(self: *IdentityStore, io: std.Io, id: []const u8) !?Identity {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        for (loaded.parsed.value) |i| {
            if (std.mem.eql(u8, i.id, id)) return try cloneIdentity(self.allocator, i);
        }
        return null;
    }

    pub fn delete(self: *IdentityStore, io: std.Io, id: []const u8) IdentitySaveError!bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        var found = false;
        var out_list: std.ArrayList(Identity) = .empty;
        defer {
            for (out_list.items) |*i| i.deinit(self.allocator);
            out_list.deinit(self.allocator);
        }
        for (loaded.parsed.value) |i| {
            if (std.mem.eql(u8, i.id, id)) {
                found = true;
                continue;
            }
            try out_list.append(self.allocator, try cloneIdentity(self.allocator, i));
        }
        if (found) self.saveLocked(io, out_list.items) catch return error.SerializeFailed;
        return found;
    }
};

fn dupFingerprints(allocator: std.mem.Allocator, fingerprints: []const []const u8) IdentitySaveError![]const []const u8 {
    const buf = try allocator.alloc([]const u8, fingerprints.len);
    errdefer allocator.free(buf);
    for (fingerprints, 0..) |fp, i| {
        buf[i] = try allocator.dupe(u8, fp);
    }
    return buf;
}

fn cloneIdentity(allocator: std.mem.Allocator, identity: Identity) IdentitySaveError!Identity {
    return .{
        .id = try allocator.dupe(u8, identity.id),
        .name = try allocator.dupe(u8, identity.name),
        .fingerprints = try dupFingerprints(allocator, identity.fingerprints),
        .shared = identity.shared,
        .created_at_ns = identity.created_at_ns,
    };
}

fn hasControlChars(s: []const u8) bool {
    for (s) |ch| {
        if (ch == 0 or ch < 0x20 or ch == 0x7f) return true;
    }
    return false;
}

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// --- scan model ------------------------------------------------------------

/// Sudo vocabulary (spec 09 §13): "yes" only from an authoritative sudo
/// policy query; "no" only when sudoers explicitly excludes the account;
/// everything unprovable is "unknown" — never guessed.
pub const sudo_yes = "yes";
pub const sudo_no = "no";
pub const sudo_unknown = "unknown";

pub const coverage_complete = "complete";
pub const coverage_partial = "partial";

pub const ServerPhase = enum(u8) {
    queued,
    connecting,
    identity,
    sudo_probe,
    enumerate,
    read_accounts,
    sshd_config,
    done,
    @"error",

    pub fn jsonName(self: ServerPhase) []const u8 {
        return switch (self) {
            .queued => "queued",
            .connecting => "connecting",
            .identity => "identity",
            .sudo_probe => "sudo_probe",
            .enumerate => "enumerate",
            .read_accounts => "read_accounts",
            .sshd_config => "sshd_config",
            .done => "done",
            .@"error" => "error",
        };
    }
};

/// One parsed key observed in one account's authorized_keys on one server.
pub const Grant = struct {
    fingerprint: []const u8,
    user: []const u8,
    sudo: []const u8,
    comment: []const u8,
    line_hash: []const u8,

    pub fn deinit(self: *Grant, allocator: std.mem.Allocator) void {
        allocator.free(self.fingerprint);
        allocator.free(self.user);
        allocator.free(self.sudo);
        allocator.free(self.comment);
        allocator.free(self.line_hash);
    }
};

/// One login account on one server: whether it was read and why not.
pub const AccountScan = struct {
    user: []const u8,
    home: []const u8,
    /// True for nologin/false-shell accounts: they cannot log in, so no
    /// authorized_keys exists to read (recorded, not counted as partial).
    skipped: bool = false,
    read: bool = false,
    @"error": ?[]const u8 = null,
    sudo: ?[]const u8 = null,
    key_count: usize = 0,

    pub fn deinit(self: *AccountScan, allocator: std.mem.Allocator) void {
        allocator.free(self.user);
        allocator.free(self.home);
        if (self.@"error") |s| allocator.free(s);
        if (self.sudo) |s| allocator.free(s);
    }
};

pub const ServerScan = struct {
    server_id: []const u8,
    name: []const u8,
    host: []const u8,
    phase: ServerPhase = .queued,
    /// Null until set; owned when non-null.
    @"error": ?[]const u8 = null,
    connected_user: ?[]const u8 = null,
    privileged: bool = false,
    /// Sudo status of the connected account on this server.
    sudo: ?[]const u8 = null,
    accounts: std.ArrayList(AccountScan) = .empty,
    /// Next account index to read (read_accounts phase).
    next_account: usize = 0,
    /// Matched `AuthorizedKeys*` lines from the effective sshd config;
    /// non-empty ⇒ dynamic/alternate key sources ⇒ coverage partial.
    sources: std.ArrayList([]const u8) = .empty,
    grants: std.ArrayList(Grant) = .empty,
    /// Null until the scan finished the server.
    coverage: ?[]const u8 = null,
    /// Why coverage is partial (unreadable accounts, dynamic key
    /// sources, missing authority). Null ⇒ complete.
    coverage_reason: ?[]const u8 = null,
    done: bool = false,

    pub fn deinit(self: *ServerScan, allocator: std.mem.Allocator) void {
        allocator.free(self.server_id);
        allocator.free(self.name);
        allocator.free(self.host);
        if (self.@"error") |s| allocator.free(s);
        if (self.connected_user) |s| allocator.free(s);
        if (self.sudo) |s| allocator.free(s);
        for (self.accounts.items) |*a| a.deinit(allocator);
        self.accounts.deinit(allocator);
        for (self.sources.items) |s| allocator.free(s);
        self.sources.deinit(allocator);
        for (self.grants.items) |*g| g.deinit(allocator);
        self.grants.deinit(allocator);
        if (self.coverage) |c| allocator.free(c);
        if (self.coverage_reason) |r| allocator.free(r);
    }
};

pub const Scan = struct {
    id: []const u8,
    full: bool = false,
    created_at_ns: i64 = 0,
    servers: []ServerScan = &.{},

    pub fn deinit(self: *Scan, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        for (self.servers) |*s| s.deinit(allocator);
        allocator.free(self.servers);
    }
};

// --- mutation jobs ---------------------------------------------------------

pub const JobKind = enum(u8) {
    offboard,
    onboard,
    rotate,

    pub fn jsonName(self: JobKind) []const u8 {
        return switch (self) {
            .offboard => "offboard",
            .onboard => "onboard",
            .rotate => "rotate",
        };
    }
};

pub const JobItemState = enum(u8) {
    queued,
    done,
    @"error",

    pub fn jsonName(self: JobItemState) []const u8 {
        return switch (self) {
            .queued => "queued",
            .done => "done",
            .@"error" => "error",
        };
    }
};

/// One server-side mutation of one account's authorized_keys.
pub const JobItem = struct {
    server_id: []const u8,
    user: []const u8,
    /// Offboard/rotate: the target fingerprint. Onboard: the new key's.
    fingerprint: []const u8 = "",
    /// Conflict guard from the scan preview (offboard/rotate).
    expected_line_hash: []const u8 = "",
    /// The normalized single public-key line (onboard append / rotate
    /// replacement; read-only options are resolved at execution time).
    public_key_line: []const u8 = "",
    read_only: bool = false,
    state: JobItemState = .queued,
    @"error": ?[]const u8 = null,

    pub fn deinit(self: *JobItem, allocator: std.mem.Allocator) void {
        allocator.free(self.server_id);
        allocator.free(self.user);
        allocator.free(self.fingerprint);
        allocator.free(self.expected_line_hash);
        allocator.free(self.public_key_line);
        if (self.@"error") |e| allocator.free(e);
    }
};

pub const Job = struct {
    id: []const u8,
    kind: JobKind,
    identity_id: []const u8,
    created_at_ns: i64 = 0,
    items: std.ArrayList(JobItem) = .empty,

    pub fn deinit(self: *Job, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.identity_id);
        for (self.items.items) |*i| i.deinit(allocator);
        self.items.deinit(allocator);
    }

    /// True once every item reached a terminal state.
    pub fn finished(self: *const Job) bool {
        for (self.items.items) |*i| {
            if (i.state == .queued) return false;
        }
        return true;
    }
};

// --- registry --------------------------------------------------------------

/// Handler-owned registries for scans and jobs (main thread only, like the
/// deploy Runs). The identity store is file-backed.
pub const Registry = struct {
    allocator: std.mem.Allocator,
    identities: IdentityStore = .{},
    scans: std.ArrayList(*Scan) = .empty,
    jobs: std.ArrayList(*Job) = .empty,
    next_scan_id: u32 = 1,
    next_job_id: u32 = 1,
    const max_scans: usize = 8;
    const max_jobs: usize = 32;

    pub fn init(allocator: std.mem.Allocator, identity_path: []const u8) Registry {
        return .{
            .allocator = allocator,
            .identities = .{ .allocator = allocator, .path = identity_path },
        };
    }

    pub fn deinit(self: *Registry) void {
        for (self.scans.items) |s| {
            s.deinit(self.allocator);
            self.allocator.destroy(s);
        }
        self.scans.deinit(self.allocator);
        for (self.jobs.items) |j| {
            j.deinit(self.allocator);
            self.allocator.destroy(j);
        }
        self.jobs.deinit(self.allocator);
    }

    pub fn registerScan(self: *Registry, scan: *Scan) void {
        if (self.scans.items.len >= max_scans) {
            const oldest = self.scans.orderedRemove(0);
            oldest.deinit(self.allocator);
            self.allocator.destroy(oldest);
        }
        self.scans.append(self.allocator, scan) catch {
            // The registry cannot grow; drop the scan and keep the id.
            scan.deinit(self.allocator);
            self.allocator.destroy(scan);
        };
    }

    pub fn scanById(self: *Registry, id: []const u8) ?*Scan {
        for (self.scans.items) |s| {
            if (std.mem.eql(u8, s.id, id)) return s;
        }
        return null;
    }

    /// The most recently finished scan, for exports.
    pub fn lastFinishedScan(self: *Registry) ?*Scan {
        var i = self.scans.items.len;
        while (i > 0) {
            i -= 1;
            const s = self.scans.items[i];
            var all_done = true;
            for (s.servers) |*server| {
                if (!server.done) all_done = false;
            }
            if (all_done) return s;
        }
        return null;
    }

    pub fn registerJob(self: *Registry, job: *Job) void {
        if (self.jobs.items.len >= max_jobs) {
            const oldest = self.jobs.orderedRemove(0);
            oldest.deinit(self.allocator);
            self.allocator.destroy(oldest);
        }
        self.jobs.append(self.allocator, job) catch {
            job.deinit(self.allocator);
            self.allocator.destroy(job);
        };
    }

    pub fn jobById(self: *Registry, id: []const u8) ?*Job {
        for (self.jobs.items) |j| {
            if (std.mem.eql(u8, j.id, id)) return j;
        }
        return null;
    }
};

// --- pure parsers (unit-tested) --------------------------------------------

/// Parses `sudo -n -l` (or `sudo -n -l -U <user>`) output. Exit 0 with a
/// privilege listing ⇒ "yes". An explicit "not in the sudoers file" ⇒
/// "no". Anything else (password required, no tty, unknown errors) ⇒
/// "unknown" — never guessed (spec 09 §13).
pub fn parseSudoList(exit: i32, output: []const u8) []const u8 {
    // Some sudo builds report an explicit denial with exit 0 (Alpine's
    // sudo prints "User X is not allowed to run sudo" and still exits 0
    // for `-l -U` queries) — the message wins over the exit code.
    if (std.mem.indexOf(u8, output, "is not allowed to run sudo") != null) return sudo_no;
    if (std.mem.indexOf(u8, output, "not in the sudoers file") != null) return sudo_no;
    if (exit == 0) return sudo_yes;
    return sudo_unknown;
}

/// Parses `getent passwd` output into login accounts: uid >= 1000,
/// shell not nologin/false. Returns owned rows; skipped nologin accounts
/// are not included (callers record them separately via
/// `skippedAccounts`).
pub const PasswdEntry = struct {
    name: []const u8,
    uid: u32,
    home: []const u8,
    shell: []const u8,

    pub fn deinit(self: *PasswdEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.home);
        allocator.free(self.shell);
    }
};

pub fn isNologinShell(shell: []const u8) bool {
    return std.mem.eql(u8, shell, "/sbin/nologin") or
        std.mem.eql(u8, shell, "/usr/sbin/nologin") or
        std.mem.eql(u8, shell, "/bin/false") or
        std.mem.eql(u8, shell, "/usr/bin/false");
}

pub fn parsePasswd(allocator: std.mem.Allocator, output: []const u8) ![]PasswdEntry {
    var out: std.ArrayList(PasswdEntry) = .empty;
    errdefer {
        for (out.items) |*e| e.deinit(allocator);
        out.deinit(allocator);
    }
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, ':');
        const name = fields.next() orelse continue;
        _ = fields.next() orelse continue; // passwd x
        const uid_str = fields.next() orelse continue;
        const uid = std.fmt.parseInt(u32, uid_str, 10) catch continue;
        _ = fields.next() orelse continue; // gid
        _ = fields.next() orelse continue; // gecos
        const home = fields.next() orelse continue;
        const shell = fields.next() orelse continue;
        if (uid < 1000) continue;
        if (isNologinShell(shell)) continue;
        try out.append(allocator, .{
            .name = try allocator.dupe(u8, name),
            .uid = uid,
            .home = try allocator.dupe(u8, home),
            .shell = try allocator.dupe(u8, shell),
        });
    }
    return out.toOwnedSlice(allocator);
}

/// Names of nologin accounts in `getent passwd` output (recorded so the
/// scan can say which accounts were skipped and why).
pub fn skippedAccounts(allocator: std.mem.Allocator, output: []const u8) ![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |n| allocator.free(n);
        out.deinit(allocator);
    }
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, ':');
        const name = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const uid_str = fields.next() orelse continue;
        const uid = std.fmt.parseInt(u32, uid_str, 10) catch continue;
        _ = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const shell = fields.next() orelse continue;
        if (uid < 1000) continue;
        if (!isNologinShell(shell)) continue;
        try out.append(allocator, try allocator.dupe(u8, name));
    }
    return out.toOwnedSlice(allocator);
}

/// A login account name is safe to interpolate into a shell command when
/// it matches the conservative account grammar.
pub fn safeUserName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64) return false;
    const first = name[0];
    if (!((first >= 'a' and first <= 'z') or (first >= '0' and first <= '9') or first == '_')) return false;
    for (name[1..]) |ch| {
        if (!((ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '_' or ch == '-')) return false;
    }
    return true;
}

/// True when matched sshd `AuthorizedKeys*` lines force partial coverage:
/// an `AuthorizedKeysCommand`/`AuthorizedKeysUserCA` source, or an
/// `AuthorizedKeysFile` pointing somewhere other than the conventional
/// per-home path (spec 09 §5).
pub fn sshdSourcesForcePartial(sources: []const []const u8) bool {
    for (sources) |line| {
        if (std.mem.startsWith(u8, line, "AuthorizedKeysCommand") or
            std.mem.startsWith(u8, line, "AuthorizedKeysUserCA")) return true;
        if (std.mem.startsWith(u8, line, "AuthorizedKeysFile")) {
            const rest = std.mem.trim(u8, line["AuthorizedKeysFile".len..], " \t");
            if (!std.mem.eql(u8, rest, ".ssh/authorized_keys") and
                !std.mem.eql(u8, rest, "%h/.ssh/authorized_keys")) return true;
        }
    }
    return false;
}

// --- people map (pure join) ------------------------------------------------

pub const PersonGrant = struct {
    fingerprint: []const u8,
    server_id: []const u8,
    server_name: []const u8,
    user: []const u8,
    sudo: []const u8,
    comment: []const u8,
    line_hash: []const u8,

    pub fn deinit(self: *PersonGrant, allocator: std.mem.Allocator) void {
        allocator.free(self.fingerprint);
        allocator.free(self.server_id);
        allocator.free(self.server_name);
        allocator.free(self.user);
        allocator.free(self.sudo);
        allocator.free(self.comment);
        allocator.free(self.line_hash);
    }
};

pub const Person = struct {
    identity_id: []const u8,
    name: []const u8,
    fingerprints: []const []const u8 = &.{},
    grants: []PersonGrant = &.{},

    pub fn deinit(self: *Person, allocator: std.mem.Allocator) void {
        allocator.free(self.identity_id);
        allocator.free(self.name);
        for (self.fingerprints) |fp| allocator.free(fp);
        allocator.free(self.fingerprints);
        for (self.grants) |*g| g.deinit(allocator);
        allocator.free(self.grants);
    }
};

pub const Unassigned = struct {
    fingerprint: []const u8,
    grants: []PersonGrant = &.{},

    pub fn deinit(self: *Unassigned, allocator: std.mem.Allocator) void {
        allocator.free(self.fingerprint);
        for (self.grants) |*g| g.deinit(allocator);
        allocator.free(self.grants);
    }
};

pub const SyncError = struct {
    server_id: []const u8,
    reason: []const u8,

    pub fn deinit(self: *SyncError, allocator: std.mem.Allocator) void {
        allocator.free(self.server_id);
        allocator.free(self.reason);
    }
};

pub const Map = struct {
    people: []Person = &.{},
    unassigned: []Unassigned = &.{},
    server_count: usize = 0,
    grant_count: usize = 0,
    coverage: []const u8 = coverage_partial,
    sync_errors: []SyncError = &.{},

    pub fn deinit(self: *Map, allocator: std.mem.Allocator) void {
        for (self.people) |*p| p.deinit(allocator);
        allocator.free(self.people);
        for (self.unassigned) |*u| u.deinit(allocator);
        allocator.free(self.unassigned);
        allocator.free(self.coverage);
        for (self.sync_errors) |*e| e.deinit(allocator);
        allocator.free(self.sync_errors);
    }
};

/// Joins scanned grants with the explicit identity registry. The grouping
/// key is always the fingerprint; comments are display labels only. Shared
/// fingerprints appear in every identity that claims them; fingerprints
/// nobody claims land in `unassigned`.
pub fn buildMap(allocator: std.mem.Allocator, scans: []const *Scan, identities: []const Identity) !Map {
    // Every slice is allocator-owned from the start so `errdefer`/`deinit`
    // never touches comptime literals.
    var map: Map = .{
        .people = try allocator.alloc(Person, 0),
        .unassigned = try allocator.alloc(Unassigned, 0),
        .coverage = try allocator.dupe(u8, coverage_partial),
        .sync_errors = try allocator.alloc(SyncError, 0),
    };
    errdefer map.deinit(allocator);

    // Flatten grants (server_id + server_name resolved here) and collect
    // sync errors.
    var all_grants: std.ArrayList(PersonGrant) = .empty;
    defer {
        for (all_grants.items) |*g| g.deinit(allocator);
        all_grants.deinit(allocator);
    }
    var syncs: std.ArrayList(SyncError) = .empty;
    errdefer {
        for (syncs.items) |*e| e.deinit(allocator);
        syncs.deinit(allocator);
    }
    var complete = true;
    for (scans) |scan| {
        for (scan.servers) |*server| {
            if (server.phase == .@"error") {
                try syncs.append(allocator, .{
                    .server_id = try allocator.dupe(u8, server.server_id),
                    .reason = try allocator.dupe(u8, server.@"error" orelse "scan failed"),
                });
                complete = false;
                continue;
            }
            if (!server.done) {
                complete = false;
                continue;
            }
            if (!std.mem.eql(u8, server.coverage orelse coverage_partial, coverage_complete)) complete = false;
            for (server.grants.items) |*g| {
                try all_grants.append(allocator, .{
                    .fingerprint = try allocator.dupe(u8, g.fingerprint),
                    .server_id = try allocator.dupe(u8, server.server_id),
                    .server_name = try allocator.dupe(u8, server.name),
                    .user = try allocator.dupe(u8, g.user),
                    .sudo = try allocator.dupe(u8, g.sudo),
                    .comment = try allocator.dupe(u8, g.comment),
                    .line_hash = try allocator.dupe(u8, g.line_hash),
                });
            }
        }
    }
    // People: one row per identity, grants matched by fingerprint.
    var people: std.ArrayList(Person) = .empty;
    errdefer {
        for (people.items) |*p| p.deinit(allocator);
        people.deinit(allocator);
    }
    for (identities) |identity| {
        var person = Person{
            .identity_id = try allocator.dupe(u8, identity.id),
            .name = try allocator.dupe(u8, identity.name),
            .fingerprints = try dupStrings(allocator, identity.fingerprints),
        };
        errdefer person.deinit(allocator);
        var grants: std.ArrayList(PersonGrant) = .empty;
        errdefer {
            for (grants.items) |*g| g.deinit(allocator);
            grants.deinit(allocator);
        }
        for (identity.fingerprints) |fp| {
            for (all_grants.items) |*g| {
                if (!std.mem.eql(u8, g.fingerprint, fp)) continue;
                try grants.append(allocator, try clonePersonGrant(allocator, g));
            }
        }
        person.grants = try grants.toOwnedSlice(allocator);
        try people.append(allocator, person);
    }

    // Unassigned: fingerprints claimed by no identity.
    var unassigned: std.ArrayList(Unassigned) = .empty;
    errdefer {
        for (unassigned.items) |*u| u.deinit(allocator);
        unassigned.deinit(allocator);
    }
    // Builders keep the grant list growable; entries are finalized below.
    const Builder = struct {
        fingerprint: []const u8,
        grants: std.ArrayList(PersonGrant),
    };
    var builders: std.ArrayList(Builder) = .empty;
    defer {
        for (builders.items) |*b| {
            allocator.free(b.fingerprint);
            b.grants.deinit(allocator);
        }
        builders.deinit(allocator);
    }
    for (all_grants.items) |*g| {
        var claimed = false;
        for (identities) |identity| {
            for (identity.fingerprints) |fp| {
                if (std.mem.eql(u8, g.fingerprint, fp)) {
                    claimed = true;
                    break;
                }
            }
            if (claimed) break;
        }
        if (claimed) continue;
        // One row per distinct unassigned fingerprint.
        var seen: ?*std.ArrayList(PersonGrant) = null;
        for (builders.items) |*b| {
            if (std.mem.eql(u8, b.fingerprint, g.fingerprint)) {
                seen = &b.grants;
                break;
            }
        }
        if (seen) |list| {
            try list.append(allocator, try clonePersonGrant(allocator, g));
        } else {
            var builder = Builder{
                .fingerprint = try allocator.dupe(u8, g.fingerprint),
                .grants = .empty,
            };
            errdefer {
                allocator.free(builder.fingerprint);
                builder.grants.deinit(allocator);
            }
            try builder.grants.append(allocator, try clonePersonGrant(allocator, g));
            try builders.append(allocator, builder);
        }
    }
    for (builders.items) |*b| {
        const entry = Unassigned{
            .fingerprint = b.fingerprint,
            .grants = try b.grants.toOwnedSlice(allocator),
        };
        try unassigned.append(allocator, entry);
    }
    // Ownership of the fingerprint strings and grant lists moved into
    // `unassigned`; drop the builders without freeing them.
    builders.items.len = 0;

    allocator.free(map.people);
    map.people = try people.toOwnedSlice(allocator);
    allocator.free(map.unassigned);
    map.unassigned = try unassigned.toOwnedSlice(allocator);
    map.server_count = 0;
    for (scans) |scan| {
        for (scan.servers) |*server| {
            if (server.done) map.server_count += 1;
        }
    }
    map.grant_count = all_grants.items.len;
    allocator.free(map.coverage);
    map.coverage = try allocator.dupe(u8, if (complete) coverage_complete else coverage_partial);
    allocator.free(map.sync_errors);
    map.sync_errors = try syncs.toOwnedSlice(allocator);
    return map;
}

fn dupStrings(allocator: std.mem.Allocator, strings: []const []const u8) ![]const []const u8 {
    const buf = try allocator.alloc([]const u8, strings.len);
    errdefer allocator.free(buf);
    for (strings, 0..) |s, i| {
        buf[i] = try allocator.dupe(u8, s);
    }
    return buf;
}

fn clonePersonGrant(allocator: std.mem.Allocator, g: *const PersonGrant) !PersonGrant {
    return .{
        .fingerprint = try allocator.dupe(u8, g.fingerprint),
        .server_id = try allocator.dupe(u8, g.server_id),
        .server_name = try allocator.dupe(u8, g.server_name),
        .user = try allocator.dupe(u8, g.user),
        .sudo = try allocator.dupe(u8, g.sudo),
        .comment = try allocator.dupe(u8, g.comment),
        .line_hash = try allocator.dupe(u8, g.line_hash),
    };
}

// --- export formatting -----------------------------------------------------

/// RFC 4180 CSV: fields containing comma, quote, CR or LF are quoted and
/// embedded quotes doubled; rows end with CRLF.
fn csvField(writer: anytype, field: []const u8) !void {
    const needs_quote = std.mem.indexOfAny(u8, field, ",\"\r\n") != null;
    if (!needs_quote) {
        try writer.writeAll(field);
        return;
    }
    try writer.writeByte('"');
    for (field) |ch| {
        if (ch == '"') try writer.writeByte('"');
        try writer.writeByte(ch);
    }
    try writer.writeByte('"');
}

/// Exports the people map as RFC 4180 CSV (person/server/sudo audit
/// table; unassigned rows carry an empty identity).
pub fn exportCsv(allocator: std.mem.Allocator, map: *const Map) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try out.writer.writeAll("identity_id,name,fingerprint,server_id,user,sudo,comment\r\n");
    for (map.people) |*person| {
        for (person.grants) |*g| {
            try csvField(&out.writer, person.identity_id);
            try out.writer.writeByte(',');
            try csvField(&out.writer, person.name);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.fingerprint);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.server_id);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.user);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.sudo);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.comment);
            try out.writer.writeAll("\r\n");
        }
    }
    for (map.unassigned) |*u| {
        for (u.grants) |*g| {
            try out.writer.writeAll(",,");
            try csvField(&out.writer, g.fingerprint);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.server_id);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.user);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.sudo);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.comment);
            try out.writer.writeAll("\r\n");
        }
    }
    return out.toOwnedSlice();
}

/// The poll/export payload shape (shared by the scan poll and the export
/// handlers so the JSON contract stays in one place).
/// One account's row in the poll response (mirrors AccountScan, with the
/// comptime-literal defaults resolved).
pub const AccountView = struct {
    user: []const u8,
    home: []const u8,
    skipped: bool = false,
    read: bool = false,
    @"error": []const u8 = "",
    sudo: []const u8 = sudo_unknown,
    key_count: usize = 0,

    pub fn deinit(self: *AccountView, allocator: std.mem.Allocator) void {
        allocator.free(self.user);
        allocator.free(self.home);
        allocator.free(self.@"error");
        allocator.free(self.sudo);
    }
};

/// One parsed key's row in the poll response.
pub const GrantView = struct {
    fingerprint: []const u8,
    user: []const u8,
    sudo: []const u8,
    comment: []const u8,
    line_hash: []const u8,

    pub fn deinit(self: *GrantView, allocator: std.mem.Allocator) void {
        allocator.free(self.fingerprint);
        allocator.free(self.user);
        allocator.free(self.sudo);
        allocator.free(self.comment);
        allocator.free(self.line_hash);
    }
};

/// One server's progress/result row in the poll response.
pub const ServerView = struct {
    server_id: []const u8,
    name: []const u8,
    host: []const u8,
    phase: []const u8,
    @"error": []const u8 = "",
    connected_user: []const u8 = "",
    sudo: []const u8 = sudo_unknown,
    coverage: []const u8 = coverage_partial,
    coverage_reason: []const u8 = "",
    accounts: []AccountView = &.{},
    grants: []GrantView = &.{},
    sources: []const []const u8 = &.{},

    pub fn deinit(self: *ServerView, allocator: std.mem.Allocator) void {
        allocator.free(self.server_id);
        allocator.free(self.name);
        allocator.free(self.host);
        allocator.free(self.phase);
        allocator.free(self.@"error");
        allocator.free(self.connected_user);
        allocator.free(self.sudo);
        allocator.free(self.coverage);
        allocator.free(self.coverage_reason);
        for (self.accounts) |*a| a.deinit(allocator);
        allocator.free(self.accounts);
        for (self.grants) |*g| g.deinit(allocator);
        allocator.free(self.grants);
        for (self.sources) |s| allocator.free(s);
        allocator.free(self.sources);
    }
};

/// Owned snapshot of a ServerScan for serialization.
pub fn serverView(allocator: std.mem.Allocator, server: *const ServerScan) !ServerView {
    var view = ServerView{
        .server_id = try allocator.dupe(u8, server.server_id),
        .name = try allocator.dupe(u8, server.name),
        .host = try allocator.dupe(u8, server.host),
        .phase = try allocator.dupe(u8, server.phase.jsonName()),
        // Every field is dupe'd — even empty defaults — because deinit
        // frees them unconditionally.
        .@"error" = try allocator.dupe(u8, server.@"error" orelse ""),
        .connected_user = try allocator.dupe(u8, server.connected_user orelse ""),
        .sudo = try allocator.dupe(u8, server.sudo orelse sudo_unknown),
        .coverage = try allocator.dupe(u8, server.coverage orelse coverage_partial),
        .coverage_reason = try allocator.dupe(u8, server.coverage_reason orelse ""),
    };
    errdefer view.deinit(allocator);
    var accounts: std.ArrayList(AccountView) = .empty;
    defer {
        for (accounts.items) |*a| a.deinit(allocator);
        accounts.deinit(allocator);
    }
    for (server.accounts.items) |*a| {
        try accounts.append(allocator, .{
            .user = try allocator.dupe(u8, a.user),
            .home = try allocator.dupe(u8, a.home),
            .skipped = a.skipped,
            .read = a.read,
            .@"error" = try allocator.dupe(u8, a.@"error" orelse ""),
            .sudo = try allocator.dupe(u8, a.sudo orelse sudo_unknown),
            .key_count = a.key_count,
        });
    }
    var grants: std.ArrayList(GrantView) = .empty;
    defer {
        for (grants.items) |*g| g.deinit(allocator);
        grants.deinit(allocator);
    }
    for (server.grants.items) |*g| {
        try grants.append(allocator, .{
            .fingerprint = try allocator.dupe(u8, g.fingerprint),
            .user = try allocator.dupe(u8, g.user),
            .sudo = try allocator.dupe(u8, if (g.sudo.len > 0) g.sudo else sudo_unknown),
            .comment = try allocator.dupe(u8, g.comment),
            .line_hash = try allocator.dupe(u8, g.line_hash),
        });
    }
    var sources: std.ArrayList([]const u8) = .empty;
    defer {
        for (sources.items) |s| allocator.free(s);
        sources.deinit(allocator);
    }
    for (server.sources.items) |s| {
        try sources.append(allocator, try allocator.dupe(u8, s));
    }
    view.accounts = try accounts.toOwnedSlice(allocator);
    view.grants = try grants.toOwnedSlice(allocator);
    view.sources = try sources.toOwnedSlice(allocator);
    return view;
}

/// The scan poll / export payload shape (shared by the poll and export
/// handlers so the JSON contract stays in one place).
pub const PollPayload = struct {
    ok: bool = true,
    state: []const u8 = "scanning",
    servers: []ServerView = &.{},
    people: []Person = &.{},
    unassigned: []Unassigned = &.{},
    servers_count: usize = 0,
    grants_count: usize = 0,
    coverage: []const u8 = coverage_partial,
    sync_errors: []SyncError = &.{},

    pub fn deinit(self: *PollPayload, allocator: std.mem.Allocator) void {
        for (self.servers) |*s| s.deinit(allocator);
        allocator.free(self.servers);
        for (self.people) |*p| p.deinit(allocator);
        allocator.free(self.people);
        for (self.unassigned) |*u| u.deinit(allocator);
        allocator.free(self.unassigned);
        allocator.free(self.coverage);
        for (self.sync_errors) |*e| e.deinit(allocator);
        allocator.free(self.sync_errors);
    }
};

pub fn exportJson(allocator: std.mem.Allocator, map: *const Map) ![]u8 {
    var payload = PollPayload{
        .state = "done",
        .people = map.people,
        .unassigned = map.unassigned,
        .servers_count = map.server_count,
        .grants_count = map.grant_count,
        .coverage = map.coverage,
        .sync_errors = map.sync_errors,
    };
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try std.json.Stringify.value(&payload, .{ .whitespace = .indent_2 }, &out.writer);
    return out.toOwnedSlice();
}

// --- unit tests ------------------------------------------------------------

test "identity store: save, ownership conflicts, shared, list, delete" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [160]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-access-itest-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var path_buf: [200]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/access_identities.json", .{dir});
    var store = IdentityStore{ .allocator = allocator, .path = path };

    const fp1 = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const fp2 = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
    const fp3 = "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA";
    try std.testing.expect(validFingerprint(fp1));
    try std.testing.expect(!validFingerprint("nope"));
    try std.testing.expect(!validFingerprint("SHA256:AAAA"));
    try std.testing.expect(!validFingerprint(""));

    var alice = try store.save(io, .{ .name = "Alice", .fingerprints = &.{ fp1, fp2 } }, 1000);
    defer alice.deinit(allocator);
    try std.testing.expectEqualStrings("Alice", alice.name);
    try std.testing.expectEqual(@as(usize, 2), alice.fingerprints.len);
    try std.testing.expect(std.mem.startsWith(u8, alice.id, "id-") or alice.id.len > 0);

    // A second person cannot claim Alice's fingerprint.
    const conflict = store.save(io, .{ .name = "Bob", .fingerprints = &.{fp2} }, 1001);
    try std.testing.expectError(error.FingerprintOwned, conflict);

    // Shared identities may overlap.
    var shared = try store.save(io, .{ .name = "Ops Oncall", .fingerprints = &.{fp3}, .shared = true }, 1002);
    defer shared.deinit(allocator);
    try std.testing.expect(shared.shared);

    // Validation errors.
    try std.testing.expectError(error.MissingName, store.save(io, .{ .name = "  ", .fingerprints = &.{fp3} }, 1003));
    try std.testing.expectError(error.NoFingerprints, store.save(io, .{ .name = "X", .fingerprints = &.{} }, 1003));
    try std.testing.expectError(error.InvalidFingerprint, store.save(io, .{ .name = "X", .fingerprints = &.{"SHA256:AAAA"} }, 1003));
    try std.testing.expectError(error.InvalidName, store.save(io, .{ .name = "bad\x01name", .fingerprints = &.{fp3} }, 1003));
    try std.testing.expectError(error.DuplicateFingerprint, store.save(io, .{ .name = "X", .fingerprints = &.{ fp3, fp3 } }, 1003));
    try std.testing.expectError(error.UnknownId, store.save(io, .{ .id = "id-nope", .name = "X", .fingerprints = &.{fp3} }, 1003));

    // Edit: Bob takes over fp2 after Alice releases it.
    var edited = try store.save(io, .{ .id = alice.id, .name = "Alice", .fingerprints = &.{fp1} }, 1004);
    edited.deinit(allocator);
    var bob = try store.save(io, .{ .name = "Bob", .fingerprints = &.{fp2} }, 1005);
    defer bob.deinit(allocator);

    const listed = try store.list(io);
    defer {
        for (listed) |*i| i.deinit(allocator);
        allocator.free(listed);
    }
    try std.testing.expectEqual(@as(usize, 3), listed.len);

    try std.testing.expect((try store.delete(io, bob.id)) == true);
    try std.testing.expect((try store.delete(io, bob.id)) == false);
}

test "parseSudoList distinguishes yes/no/unknown" {
    try std.testing.expectEqualStrings(sudo_yes, parseSudoList(0, "User root may run the following commands on this host:\n (ALL) ALL\n"));
    try std.testing.expectEqualStrings(sudo_no, parseSudoList(1, "user alice is not in the sudoers file. This incident will be reported."));
    // Alpine's sudo prints the denial with exit 0 for `-l -U` queries.
    try std.testing.expectEqualStrings(sudo_no, parseSudoList(0, "User alice is not allowed to run sudo on b7ac8cc46a82."));
    try std.testing.expectEqualStrings(sudo_unknown, parseSudoList(1, "sudo: a password is required"));
    try std.testing.expectEqualStrings(sudo_unknown, parseSudoList(1, "sudo: no tty present and no askpass program specified"));
    try std.testing.expectEqualStrings(sudo_unknown, parseSudoList(127, "sh: sudo: not found"));
    try std.testing.expectEqualStrings(sudo_unknown, parseSudoList(1, ""));
}

test "parsePasswd and skippedAccounts classify getent output" {
    const allocator = std.testing.allocator;
    const sample =
        \\root:x:0:0:root:/root:/bin/bash
        \\daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        \\alice:x:1000:1000:Alice:/home/alice:/bin/bash
        \\carol:x:1001:1001::/home/carol:/usr/sbin/nologin
        \\dave:x:1002:1002:Dave:/home/dave:/bin/false
        \\
    ;
    const entries = try parsePasswd(allocator, sample);
    defer {
        for (entries) |*e| e.deinit(allocator);
        allocator.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqualStrings("alice", entries[0].name);
    try std.testing.expectEqual(@as(u32, 1000), entries[0].uid);
    try std.testing.expectEqualStrings("/home/alice", entries[0].home);

    const skipped = try skippedAccounts(allocator, sample);
    defer {
        for (skipped) |n| allocator.free(n);
        allocator.free(skipped);
    }
    try std.testing.expectEqual(@as(usize, 2), skipped.len);
    try std.testing.expectEqualStrings("carol", skipped[0]);
    try std.testing.expectEqualStrings("dave", skipped[1]);

    try std.testing.expect(safeUserName("alice_2"));
    try std.testing.expect(!safeUserName("al ice"));
    try std.testing.expect(!safeUserName("x;rm -rf /"));
    try std.testing.expect(!safeUserName(""));
}

test "buildMap joins identities with grants and separates unassigned" {
    const allocator = std.testing.allocator;

    const fp1 = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const fp2 = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
    const fp3 = "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA";

    var identities = [_]Identity{
        .{ .id = "id-a", .name = "Alice", .fingerprints = &.{ fp1, fp2 } },
        .{ .id = "id-s", .name = "Oncall", .fingerprints = &.{fp3}, .shared = true },
    };

    // One scan with one done server carrying three grants (fp1 as root,
    // fp2 as alice, fp3 shared on both accounts).
    var server = ServerScan{
        .server_id = try allocator.dupe(u8, "srv-1"),
        .name = try allocator.dupe(u8, "prod"),
        .host = try allocator.dupe(u8, "10.0.0.1"),
        .phase = .done,
        .coverage = try allocator.dupe(u8, coverage_complete),
        .done = true,
    };
    // Ownership of `server` (and its strings) moves into `scan` below;
    // only the scan is freed.
    try server.grants.append(allocator, .{
        .fingerprint = try allocator.dupe(u8, fp1),
        .user = try allocator.dupe(u8, "root"),
        .sudo = try allocator.dupe(u8, sudo_yes),
        .comment = try allocator.dupe(u8, "alice@mbp"),
        .line_hash = try allocator.dupe(u8, "h1"),
    });
    try server.grants.append(allocator, .{
        .fingerprint = try allocator.dupe(u8, fp2),
        .user = try allocator.dupe(u8, "alice"),
        .sudo = try allocator.dupe(u8, sudo_no),
        .comment = try allocator.dupe(u8, "alice@mbp"),
        .line_hash = try allocator.dupe(u8, "h2"),
    });
    try server.grants.append(allocator, .{
        .fingerprint = try allocator.dupe(u8, fp3),
        .user = try allocator.dupe(u8, "root"),
        .sudo = try allocator.dupe(u8, sudo_yes),
        .comment = try allocator.dupe(u8, "oncall@pg"),
        .line_hash = try allocator.dupe(u8, "h3"),
    });
    var scan = Scan{
        .id = try allocator.dupe(u8, "scan-1"),
        .servers = try allocator.alloc(ServerScan, 1),
    };
    defer scan.deinit(allocator);
    scan.servers[0] = server;

    const scans = [_]*Scan{&scan};
    var map = try buildMap(allocator, &scans, &identities);
    defer map.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), map.people.len);
    try std.testing.expectEqual(@as(usize, 3), map.grant_count);
    try std.testing.expectEqual(@as(usize, 1), map.server_count);
    try std.testing.expectEqualStrings(coverage_complete, map.coverage);

    // Alice has her two grants.
    const alice = map.people[0];
    try std.testing.expectEqualStrings("id-a", alice.identity_id);
    try std.testing.expectEqual(@as(usize, 2), alice.grants.len);
    try std.testing.expectEqualStrings("root", alice.grants[0].user);
    try std.testing.expectEqualStrings("prod", alice.grants[0].server_name);
    try std.testing.expectEqualStrings("h1", alice.grants[0].line_hash);

    // fp3 is unassigned (claimed only by a shared identity is still
    // claimed — so nothing here is unassigned).
    try std.testing.expectEqual(@as(usize, 0), map.unassigned.len);

    // Without the shared identity, fp2 and fp3 land in unassigned.
    const identities2 = [_]Identity{.{ .id = "id-a", .name = "Alice", .fingerprints = &.{fp1} }};
    var map2 = try buildMap(allocator, &scans, &identities2);
    defer map2.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), map2.people.len);
    try std.testing.expectEqual(@as(usize, 2), map2.unassigned.len);
    try std.testing.expectEqualStrings(fp2, map2.unassigned[0].fingerprint);
    try std.testing.expectEqualStrings(fp3, map2.unassigned[1].fingerprint);
    try std.testing.expectEqual(@as(usize, 1), map2.unassigned[1].grants.len);
    try std.testing.expectEqualStrings("root", map2.unassigned[1].grants[0].user);
}

test "buildMap flags errored servers as sync errors and partial coverage" {
    const allocator = std.testing.allocator;
    const server = ServerScan{
        .server_id = try allocator.dupe(u8, "srv-dead"),
        .name = try allocator.dupe(u8, "legacy-box"),
        .host = try allocator.dupe(u8, "10.0.0.9"),
        .phase = .@"error",
        .@"error" = try allocator.dupe(u8, "not connected (connect to this server first)"),
    };
    // Ownership of `server` moves into `scan` below; only the scan is
    // freed.
    var scan = Scan{
        .id = try allocator.dupe(u8, "scan-2"),
        .servers = try allocator.alloc(ServerScan, 1),
    };
    defer scan.deinit(allocator);
    scan.servers[0] = server;
    const scans = [_]*Scan{&scan};
    const identities = [_]Identity{};
    var map = try buildMap(allocator, &scans, &identities);
    defer map.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), map.people.len);
    try std.testing.expectEqual(@as(usize, 1), map.sync_errors.len);
    try std.testing.expectEqualStrings("srv-dead", map.sync_errors[0].server_id);
    try std.testing.expect(std.mem.indexOf(u8, map.sync_errors[0].reason, "not connected") != null);
    try std.testing.expectEqualStrings(coverage_partial, map.coverage);
    try std.testing.expectEqual(@as(usize, 0), map.server_count);
}

test "exportCsv quotes RFC 4180 fields and uses CRLF" {
    const allocator = std.testing.allocator;
    var map: Map = .{
        .coverage = try allocator.dupe(u8, coverage_complete),
        .people = try allocator.alloc(Person, 1),
        .unassigned = try allocator.alloc(Unassigned, 0),
        .sync_errors = try allocator.alloc(SyncError, 0),
    };
    defer map.deinit(allocator);
    const grants = try allocator.alloc(PersonGrant, 1);
    grants[0] = .{
        .fingerprint = try allocator.dupe(u8, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        .server_id = try allocator.dupe(u8, "srv-1"),
        .server_name = try allocator.dupe(u8, "prod"),
        .user = try allocator.dupe(u8, "root"),
        .sudo = try allocator.dupe(u8, sudo_yes),
        .comment = try allocator.dupe(u8, "has, a comma \"and quotes\""),
        .line_hash = try allocator.dupe(u8, "h"),
    };
    map.people[0] = .{
        .identity_id = try allocator.dupe(u8, "id-a"),
        .name = try allocator.dupe(u8, "Alice"),
        .fingerprints = try allocator.alloc([]const u8, 0),
        .grants = grants,
    };
    map.grant_count = 1;
    map.server_count = 1;

    const csv = try exportCsv(allocator, &map);
    defer allocator.free(csv);
    const expected =
        "identity_id,name,fingerprint,server_id,user,sudo,comment\r\n" ++
        "id-a,Alice,SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,srv-1,root,yes,\"has, a comma \"\"and quotes\"\"\"\r\n";
    try std.testing.expectEqualStrings(expected, csv);
}

test "exportJson serializes the people map" {
    const allocator = std.testing.allocator;
    var map: Map = .{
        .coverage = try allocator.dupe(u8, coverage_complete),
        .people = try allocator.alloc(Person, 0),
        .unassigned = try allocator.alloc(Unassigned, 0),
        .sync_errors = try allocator.alloc(SyncError, 0),
    };
    defer map.deinit(allocator);
    const json_out = try exportJson(allocator, &map);
    defer allocator.free(json_out);
    const parsed = try std.json.parseFromSlice(PollPayload, allocator, json_out, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer parsed.deinit();
    try std.testing.expect(parsed.value.ok);
    try std.testing.expectEqualStrings("done", parsed.value.state);
    try std.testing.expectEqualStrings(coverage_complete, parsed.value.coverage);
}

test "sshdSourcesForcePartial flags dynamic and alternate key sources" {
    try std.testing.expect(!sshdSourcesForcePartial(&.{}));
    try std.testing.expect(!sshdSourcesForcePartial(&.{"AuthorizedKeysFile .ssh/authorized_keys"}));
    try std.testing.expect(!sshdSourcesForcePartial(&.{"AuthorizedKeysFile %h/.ssh/authorized_keys"}));
    try std.testing.expect(sshdSourcesForcePartial(&.{"AuthorizedKeysFile /etc/ssh/keys/%u"}));
    try std.testing.expect(sshdSourcesForcePartial(&.{"AuthorizedKeysCommand /usr/bin/keys %u"}));
    try std.testing.expect(sshdSourcesForcePartial(&.{"AuthorizedKeysCommandUser sshd"}));
    try std.testing.expect(sshdSourcesForcePartial(&.{"AuthorizedKeysUserCA /etc/ssh/ca.pub"}));
    try std.testing.expect(!sshdSourcesForcePartial(&.{"PermitRootLogin yes"}));
}

test "serverView snapshots a ServerScan" {
    const allocator = std.testing.allocator;
    var server = ServerScan{
        .server_id = try allocator.dupe(u8, "srv-1"),
        .name = try allocator.dupe(u8, "prod"),
        .host = try allocator.dupe(u8, "10.0.0.1"),
        .phase = .done,
        .connected_user = try allocator.dupe(u8, "root"),
        .sudo = try allocator.dupe(u8, sudo_yes),
        .coverage = try allocator.dupe(u8, coverage_complete),
        .done = true,
    };
    defer server.deinit(allocator);
    try server.accounts.append(allocator, .{
        .user = try allocator.dupe(u8, "root"),
        .home = try allocator.dupe(u8, "/root"),
        .read = true,
        .sudo = try allocator.dupe(u8, sudo_yes),
        .key_count = 2,
    });
    try server.sources.append(allocator, try allocator.dupe(u8, "AuthorizedKeysFile .ssh/authorized_keys"));

    var view = try serverView(allocator, &server);
    defer view.deinit(allocator);
    try std.testing.expectEqualStrings("srv-1", view.server_id);
    try std.testing.expectEqualStrings("done", view.phase);
    try std.testing.expectEqualStrings("root", view.connected_user);
    try std.testing.expectEqualStrings(sudo_yes, view.sudo);
    try std.testing.expectEqualStrings(coverage_complete, view.coverage);
    try std.testing.expectEqual(@as(usize, 1), view.accounts.len);
    try std.testing.expectEqual(@as(usize, 2), view.accounts[0].key_count);
    try std.testing.expectEqual(@as(usize, 1), view.sources.len);
    try std.testing.expectEqualStrings("AuthorizedKeysFile .ssh/authorized_keys", view.sources[0]);
    try std.testing.expectEqual(@as(usize, 0), view.grants.len);
}
