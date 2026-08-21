//! Spec 08 SSH management: the snapshot, job, and role-plan records plus
//! the registry that owns them. Pure data + policy logic, no libssh2 and
//! no shell. The registry also owns the two bounded worker threads that
//! advance the records: one remote coordinator (sequences SSH/SFTP work
//! through session-worker outcomes) and one local job worker (runs
//! ssh-keygen). Bridge handlers only validate, register, and observe;
//! poll calls never advance an operation.
//!
//! Memory discipline: every record owns its strings; registry mutation
//! happens under `mutex`; fields documented as immutable-after-
//! registration may be read by drivers without the lock. Secret payloads
//! (passphrases) are zeroed before release and are never serialized.

const std = @import("std");
const sshkeys = @import("sshkeys.zig");

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// --- bounds (spec 08 corrected contract) ------------------------------------

pub const max_snapshots: usize = 32;
pub const max_jobs: usize = 64;
pub const max_plans: usize = 32;
pub const max_deploy_manifest_entries: usize = 64;
pub const max_keys_per_source: usize = 512;
pub const max_sources_per_snapshot: usize = 16;
pub const max_warnings: usize = 64;
pub const registry_idle_expiry_ns: i128 = 10 * 60 * std.time.ns_per_s;
pub const registry_terminal_retention_ns: i128 = 30 * 60 * std.time.ns_per_s;
pub const plan_ttl_ms: i64 = 5 * 60 * 1000;

// --- typed source outcomes ---------------------------------------------------

pub const SourceStatus = enum {
    missing,
    readable,
    denied,
    timeout,
    too_large,
    transport_error,
    parse_error,

    pub fn jsonName(self: SourceStatus) []const u8 {
        return @tagName(self);
    }
};

/// Only `missing` may produce a safe create plan; only `readable` may
/// produce a safe edit plan. Everything else blocks mutation.
pub fn statusAllowsMutation(status: SourceStatus) bool {
    return status == .missing or status == .readable;
}

// --- records -----------------------------------------------------------------

pub const Source = struct {
    /// Exact path for static sources; the directive for dynamic ones.
    path: []u8,
    /// "static" | "dynamic" | "certificate"
    kind: []u8,
    status: SourceStatus = .missing,
    file_sha256: ?[]u8 = null,
    mode: ?u32 = null,
    owner: ?[]u8 = null,
    @"error": ?[]u8 = null,

    pub fn deinit(self: *Source, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.kind);
        if (self.file_sha256) |v| allocator.free(v);
        if (self.owner) |v| allocator.free(v);
        if (self.@"error") |v| allocator.free(v);
    }
};

pub const PolicyAssessment = struct {
    /// "standard" | "restricted" | "role_forced" | "weak"
    level: []const u8,
    detail: []const u8,
};

/// The typed policy read of one key's exact options. Safety is never
/// inferred from the mere presence of options: a forced command without
/// `restrict` still allows PTY and forwarding, so it reads as weak.
pub fn assessKeyPolicy(options: []const u8) PolicyAssessment {
    if (options.len == 0) return .{ .level = "standard", .detail = "No key-level restrictions" };
    const has_restrict = hasOption(options, "restrict");
    const command = commandOption(options);
    if (has_restrict and command != null) {
        return .{ .level = "role_forced", .detail = "Forced command with all session features restricted" };
    }
    if (command != null and !has_restrict) {
        return .{ .level = "weak", .detail = "Forced command without restrict: PTY and forwarding stay available" };
    }
    if (hasCertificateAuthority(options)) {
        return .{ .level = "weak", .detail = "cert-authority trusts every certificate this key signs" };
    }
    return .{ .level = "restricted", .detail = "Key-level options limit this key" };
}

pub fn hasOption(options: []const u8, name: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, options, ',');
    while (tokens.next()) |raw| {
        const token = std.mem.trim(u8, raw, " \t");
        if (std.mem.eql(u8, token, name)) return true;
    }
    return false;
}

/// The exact `command="..."` value, or null. Options are comma-separated
/// with spaces allowed only inside double quotes (sshd(8)).
pub fn commandOption(options: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < options.len) {
        var end = i;
        var in_quote = false;
        while (end < options.len) : (end += 1) {
            const ch = options[end];
            if (in_quote) {
                if (ch == '\\' and end + 1 < options.len) end += 1;
                if (ch == '"') in_quote = false;
                continue;
            }
            if (ch == '"') in_quote = true;
            if (ch == ',') break;
        }
        const token = options[i..end];
        if (std.mem.startsWith(u8, token, "command=\"") and token.len >= 9 + 1 and token[token.len - 1] == '"') {
            return token[9 .. token.len - 1];
        }
        i = end + 1;
    }
    return null;
}

pub fn hasCertificateAuthority(options: []const u8) bool {
    return hasOption(options, "cert-authority");
}

/// The exact options every Oars-managed read-only key must carry.
pub fn readOnlyRoleOptions(allocator: std.mem.Allocator, forced_command: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "restrict,command=\"{s}\"", .{forced_command});
}

/// Fail-closed verification of a read-only role key's exact options:
/// `restrict`, the expected forced read-only SFTP command, and no
/// certificate trust (spec 08: no PTY, no forwarding, because `restrict`
/// disables both; any divergent option is drift).
pub fn verifyReadOnlyKeyOptions(options: []const u8, forced_command: []const u8) bool {
    if (!hasOption(options, "restrict")) return false;
    const command = commandOption(options) orelse return false;
    if (!std.mem.eql(u8, command, forced_command)) return false;
    if (hasCertificateAuthority(options)) return false;
    return true;
}

pub const KeyEntry = struct {
    source_path: []u8,
    line_index: usize,
    line_hash: []u8,
    parsed: bool,
    options: []u8 = &.{},
    key_type: []u8 = &.{},
    key: []u8 = &.{},
    comment: []u8 = &.{},
    fingerprint_sha256: []u8 = &.{},
    bits: ?u16 = null,
    raw: []u8 = &.{},
    @"error": []u8 = &.{},
    policy_level: []u8 = &.{},
    policy_detail: []u8 = &.{},

    pub fn deinit(self: *KeyEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.source_path);
        allocator.free(self.line_hash);
        allocator.free(self.options);
        allocator.free(self.key_type);
        allocator.free(self.key);
        allocator.free(self.comment);
        allocator.free(self.fingerprint_sha256);
        allocator.free(self.raw);
        allocator.free(self.@"error");
        allocator.free(self.policy_level);
        allocator.free(self.policy_detail);
    }
};

/// Builds the owned entry for one parsed key line (the caller applies
/// the max_keys_per_source clamp).
pub fn keyEntryFromParsed(allocator: std.mem.Allocator, source_path: []const u8, k: *const sshkeys.Key) !KeyEntry {
    const assessment = assessKeyPolicy(k.options);
    return .{
        .source_path = try allocator.dupe(u8, source_path),
        .line_index = k.line_index,
        .line_hash = try allocator.dupe(u8, k.line_hash),
        .parsed = k.parsed,
        .options = try allocator.dupe(u8, k.options),
        .key_type = try allocator.dupe(u8, k.key_type),
        .key = try allocator.dupe(u8, k.key),
        .comment = try allocator.dupe(u8, k.comment),
        .fingerprint_sha256 = try allocator.dupe(u8, k.fingerprint_sha256),
        .bits = k.bits,
        .raw = try allocator.dupe(u8, k.raw),
        .@"error" = try allocator.dupe(u8, k.@"error"),
        .policy_level = try allocator.dupe(u8, if (k.parsed) assessment.level else "weak"),
        .policy_detail = try allocator.dupe(u8, if (k.parsed) assessment.detail else "Malformed row: no mutation is allowed"),
    };
}

pub const RolePolicyState = enum {
    verified,
    missing,
    corrupt,
    stale,
    unreadable,
    drifted,

    pub fn jsonName(self: RolePolicyState) []const u8 {
        return @tagName(self);
    }
};

pub const RoleEntry = struct {
    name: []u8,
    /// "standard_ssh" | "read_only_sftp"
    kind: []u8,
    home: ?[]u8 = null,
    shell: ?[]u8 = null,
    policy_state: RolePolicyState = .verified,
    key_fingerprints: [][]u8 = &.{},
    forced_command: []u8 = &.{},

    pub fn deinit(self: *RoleEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.kind);
        if (self.home) |v| allocator.free(v);
        if (self.shell) |v| allocator.free(v);
        for (self.key_fingerprints) |fp| allocator.free(fp);
        allocator.free(self.key_fingerprints);
        allocator.free(self.forced_command);
    }
};

pub const DeployKeyEntry = struct {
    id: []u8,
    repository_label: []u8,
    /// Private key path on the server.
    path: []u8,
    fingerprint: []u8,
    comment: []u8 = &.{},
    created_at_ms: i64 = 0,

    pub fn deinit(self: *DeployKeyEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.repository_label);
        allocator.free(self.path);
        allocator.free(self.fingerprint);
        allocator.free(self.comment);
    }
};

pub const AccountKind = enum { connected, managed_role };

pub const SnapshotState = enum {
    queued,
    running,
    done,
    partial,
    canceled,

    pub fn jsonName(self: SnapshotState) []const u8 {
        return @tagName(self);
    }

    pub fn terminal(self: SnapshotState) bool {
        return self == .done or self == .partial or self == .canceled;
    }
};

pub const Snapshot = struct {
    // Immutable after registration (the driver reads without the lock).
    id: []u8,
    server_id: []u8,
    account_kind: AccountKind,
    account_name: ?[]u8, // managed_role only
    created_at_ns: i128,
    // Mutable under the registry mutex.
    state: SnapshotState = .queued,
    finished_at_ns: ?i128 = null,
    touched_ns: i128,
    /// "effective_policy" when `sshd -T -C` was evaluated,
    /// "single_source_fallback" when only the conventional file is shown.
    scope: []u8 = &.{},
    coverage: []u8 = &.{}, // "complete" | "partial"
    privilege: []u8 = &.{}, // "root" | "sudo_n" | "none" | "unknown"
    sftp_read_only: bool = false,
    /// The exact forced read-only SFTP command detected from the server's
    /// subsystem (e.g. "internal-sftp -R"); frozen into read-only role
    /// plans. Never serialized to the frontend.
    sftp_forced_command: []u8 = &.{},
    pubkey_authentication: ?bool = null,
    sources: std.ArrayList(Source) = .empty,
    keys: std.ArrayList(KeyEntry) = .empty,
    roles: std.ArrayList(RoleEntry) = .empty,
    deploy_keys: std.ArrayList(DeployKeyEntry) = .empty,
    warnings: std.ArrayList([]u8) = .empty,
    claimed: bool = false,
    cancel_requested: std.atomic.Value(bool) = .init(false),

    pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.server_id);
        if (self.account_name) |v| allocator.free(v);
        allocator.free(self.scope);
        allocator.free(self.coverage);
        allocator.free(self.privilege);
        allocator.free(self.sftp_forced_command);
        for (self.sources.items) |*s| s.deinit(allocator);
        self.sources.deinit(allocator);
        for (self.keys.items) |*k| k.deinit(allocator);
        self.keys.deinit(allocator);
        for (self.roles.items) |*r| r.deinit(allocator);
        self.roles.deinit(allocator);
        for (self.deploy_keys.items) |*d| d.deinit(allocator);
        self.deploy_keys.deinit(allocator);
        for (self.warnings.items) |w| allocator.free(w);
        self.warnings.deinit(allocator);
        allocator.destroy(self);
    }
};

pub const JobState = enum {
    queued,
    running,
    waiting_for_verification,
    done,
    partial,
    canceled,

    pub fn jsonName(self: JobState) []const u8 {
        return @tagName(self);
    }

    pub fn terminal(self: JobState) bool {
        return self == .done or self == .partial or self == .canceled;
    }
};

pub const StepState = enum {
    queued,
    running,
    waiting,
    done,
    conflict,
    @"error",
    canceled,

    pub fn jsonName(self: StepState) []const u8 {
        return @tagName(self);
    }
};

pub const Step = struct {
    id: []const u8, // static string
    state: StepState = .queued,
    @"error": ?[]u8 = null, // owned

    pub fn deinit(self: *Step, allocator: std.mem.Allocator) void {
        if (self.@"error") |e| allocator.free(e);
    }
};

pub const JobKind = enum {
    add,
    revoke,
    rotate,
    role_create,
    role_repair,
    role_delete,
    deploy_generate,
    deploy_delete,
    local_generate,

    pub fn auditName(self: JobKind) []const u8 {
        return switch (self) {
            .add => "sshkeys.add",
            .revoke => "sshkeys.revoke",
            .rotate => "sshkeys.rotate",
            .role_create => "sshkeys.roles.create",
            .role_repair => "sshkeys.roles.repair",
            .role_delete => "sshkeys.roles.delete",
            .deploy_generate => "sshkeys.deployKeys.generate",
            .deploy_delete => "sshkeys.deployKeys.delete",
            .local_generate => "sshkeys.localGenerate",
        };
    }

    pub fn steps(self: JobKind) []const []const u8 {
        return switch (self) {
            .add => &.{ "check_source", "write", "verify" },
            .revoke => &.{ "check_source", "write", "verify" },
            .rotate => &.{ "check_source", "stage", "verify_staged", "verify_access", "remove_old", "verify" },
            .role_create => &.{ "probe_privilege", "probe_capability", "create_account", "install_key", "write_policy", "verify" },
            .role_repair => &.{ "probe_privilege", "write_policy", "verify" },
            .role_delete => &.{ "probe_privilege", "delete_account", "write_policy" },
            .deploy_generate => &.{ "read_manifest", "generate", "write_manifest", "verify" },
            .deploy_delete => &.{ "read_manifest", "delete_files", "write_manifest" },
            .local_generate => &.{ "generate", "verify" },
        };
    }
};

pub const RotateVerification = union(enum) {
    local_private_key: struct {
        path: []u8,
        passphrase: ?[]u8, // secret: zeroed on deinit, never serialized
    },
    external_confirmation: struct {
        confirm_fingerprint: []u8,
    },

    pub fn deinit(self: *RotateVerification, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .local_private_key => |*v| {
                allocator.free(v.path);
                if (v.passphrase) |p| {
                    std.crypto.secureZero(u8, p);
                    allocator.free(p);
                }
            },
            .external_confirmation => |*v| allocator.free(v.confirm_fingerprint),
        }
    }
};

/// Kind-specific frozen request data. Every slice is owned by the job.
pub const JobPayload = union(enum) {
    add: struct {
        normalized_line: []u8,
        fingerprint: []u8,
    },
    revoke: struct {
        fingerprint: []u8,
        line_hash: []u8,
    },
    rotate: struct {
        old_fingerprint: []u8,
        line_hash: []u8,
        new_line: []u8,
        new_fingerprint: []u8,
        old_options: []u8,
    },
    role: struct {
        name: []u8,
        kind: []u8, // "standard_ssh" | "read_only_sftp"
        privilege: []u8, // privilege recorded at plan time
        /// The exact forced command frozen from the snapshot (read-only
        /// roles); every installed key must carry it.
        forced_command: []u8,
        home: ?[]u8,
        commands: [][]u8,
        first_key_line: ?[]u8, // normalized, with role options applied
    },
    deploy_generate: struct {
        repository_label: []u8,
        comment: ?[]u8,
    },
    deploy_delete: struct {
        deploy_key_id: []u8,
        confirm_fingerprint: []u8,
    },
    local_generate: struct {
        destination: []u8,
        comment: ?[]u8,
        passphrase: ?[]u8, // secret: zeroed on deinit, never serialized
        remember_passphrase: bool,
    },

    pub fn deinit(self: *JobPayload, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .add => |*p| {
                allocator.free(p.normalized_line);
                allocator.free(p.fingerprint);
            },
            .revoke => |*p| {
                allocator.free(p.fingerprint);
                allocator.free(p.line_hash);
            },
            .rotate => |*p| {
                allocator.free(p.old_fingerprint);
                allocator.free(p.line_hash);
                allocator.free(p.new_line);
                allocator.free(p.new_fingerprint);
                allocator.free(p.old_options);
            },
            .role => |*p| {
                allocator.free(p.name);
                allocator.free(p.kind);
                allocator.free(p.privilege);
                allocator.free(p.forced_command);
                if (p.home) |h| allocator.free(h);
                for (p.commands) |c| allocator.free(c);
                allocator.free(p.commands);
                if (p.first_key_line) |k| allocator.free(k);
            },
            .deploy_generate => |*p| {
                allocator.free(p.repository_label);
                if (p.comment) |c| allocator.free(c);
            },
            .deploy_delete => |*p| {
                allocator.free(p.deploy_key_id);
                allocator.free(p.confirm_fingerprint);
            },
            .local_generate => |*p| {
                allocator.free(p.destination);
                if (p.comment) |c| allocator.free(c);
                if (p.passphrase) |pp| {
                    std.crypto.secureZero(u8, pp);
                    allocator.free(pp);
                }
            },
        }
    }
};

pub const Job = struct {
    // Immutable after registration.
    id: []u8,
    operation_id: []u8,
    server_id: []u8,
    kind: JobKind,
    /// Target account name; null for the connected login. Key mutations
    /// against role accounts resolve their verified policy at run time.
    account_name: ?[]u8,
    source_path: []u8 = &.{},
    file_sha256: []u8 = &.{},
    payload: JobPayload,
    created_at_ns: i128,
    // Mutable under the registry mutex.
    state: JobState = .queued,
    steps: []Step,
    finished_at_ns: ?i128 = null,
    touched_ns: i128,
    result_json: ?[]u8 = null,
    /// The whole-file hash observed after staging a rotation; the commit
    /// phase re-checks it before removing the old line.
    staged_file_sha256: ?[]u8 = null,
    verification: ?RotateVerification = null,
    claimed: bool = false,
    cancel_requested: std.atomic.Value(bool) = .init(false),

    pub fn deinit(self: *Job, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.operation_id);
        allocator.free(self.server_id);
        if (self.account_name) |v| allocator.free(v);
        allocator.free(self.source_path);
        allocator.free(self.file_sha256);
        self.payload.deinit(allocator);
        for (self.steps) |*s| s.deinit(allocator);
        allocator.free(self.steps);
        if (self.result_json) |r| allocator.free(r);
        if (self.staged_file_sha256) |s| allocator.free(s);
        if (self.verification) |*v| v.deinit(allocator);
        allocator.destroy(self);
    }
};

/// The audit-safe one-line summary of a job, written into `buf`. Result
/// fragments never carry secrets: the local-generate passphrase and the
/// rotate verification material stay out of every detail string.
pub fn kindDetail(job: *const Job, buf: []u8) []const u8 {
    return switch (job.payload) {
        .add => |*p| std.fmt.bufPrint(buf, "fingerprint={s} source={s}", .{ p.fingerprint, job.source_path }) catch "",
        .revoke => |*p| std.fmt.bufPrint(buf, "fingerprint={s} source={s}", .{ p.fingerprint, job.source_path }) catch "",
        .rotate => |*p| std.fmt.bufPrint(buf, "old={s} new={s} source={s}", .{ p.old_fingerprint, p.new_fingerprint, job.source_path }) catch "",
        .role => |*p| std.fmt.bufPrint(buf, "name={s} kind={s}", .{ p.name, p.kind }) catch "",
        .deploy_generate => |*p| std.fmt.bufPrint(buf, "label={s}", .{p.repository_label}) catch "",
        .deploy_delete => |*p| std.fmt.bufPrint(buf, "id={s}", .{p.deploy_key_id}) catch "",
        .local_generate => |*p| std.fmt.bufPrint(buf, "destination={s}", .{p.destination}) catch "",
    };
}

pub const RolePlanAction = enum { create, repair, delete };

pub const RolePlan = struct {
    id: []u8,
    server_id: []u8,
    name: []u8,
    kind: []u8, // "standard_ssh" | "read_only_sftp"
    action: RolePlanAction,
    privilege: []u8, // "root" | "sudo_n"
    /// The exact forced read-only SFTP command frozen at plan time
    /// (empty for standard SSH roles).
    forced_command: []u8 = &.{},
    home: ?[]u8,
    commands: [][]u8,
    effects: [][]u8,
    created_at_ms: i128,
    expires_at_ms: i128,

    pub fn deinit(self: *RolePlan, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.server_id);
        allocator.free(self.name);
        allocator.free(self.kind);
        allocator.free(self.privilege);
        allocator.free(self.forced_command);
        if (self.home) |h| allocator.free(h);
        for (self.commands) |c| allocator.free(c);
        allocator.free(self.commands);
        for (self.effects) |e| allocator.free(e);
        allocator.free(self.effects);
        allocator.destroy(self);
    }

    pub fn expired(self: *const RolePlan, now_ms: i128) bool {
        return now_ms >= self.expires_at_ms;
    }
};

// --- ids ---------------------------------------------------------------------

/// "prefix-" ++ 16 lowercase hex chars of randomness.
pub fn randomId(allocator: std.mem.Allocator, io: std.Io, prefix: []const u8) ![]u8 {
    var bytes: [8]u8 = undefined;
    try std.Io.randomSecure(io, &bytes);
    const hex = std.fmt.bytesToHex(bytes, .lower);
    return std.fmt.allocPrint(allocator, "{s}-{s}", .{ prefix, hex });
}

// --- registry ------------------------------------------------------------------

pub const Driver = struct {
    context: *anyopaque,
    drive_snapshot: *const fn (context: *anyopaque, registry: *Registry, snap: *Snapshot) void,
    drive_job: *const fn (context: *anyopaque, registry: *Registry, job: *Job) void,
    drive_local_job: *const fn (context: *anyopaque, registry: *Registry, job: *Job) void,
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    snapshots: std.ArrayList(*Snapshot) = .empty,
    jobs: std.ArrayList(*Job) = .empty,
    plans: std.ArrayList(*RolePlan) = .empty,
    driver: ?Driver = null,
    io: ?std.Io = null,
    coordinator: ?std.Thread = null,
    local_worker: ?std.Thread = null,
    stop: std.atomic.Value(bool) = .init(false),

    pub fn init(allocator: std.mem.Allocator) Registry {
        return .{ .allocator = allocator };
    }

    fn nowNs(self: *Registry) i128 {
        const io = self.io orelse return 0;
        return std.Io.Timestamp.now(io, .real).nanoseconds;
    }

    /// Starts the two bounded worker threads (idempotent). Called lazily
    /// by the first SSH-management bridge command; the driver callbacks
    /// live in bridge.zig and own all session/keygen interaction.
    pub fn ensureStarted(self: *Registry, io: std.Io, driver: Driver) void {
        lockSpin(&self.mutex);
        const started = self.coordinator != null;
        if (!started) {
            self.io = io;
            self.driver = driver;
        }
        self.mutex.unlock();
        if (started) return;
        self.coordinator = std.Thread.spawn(.{}, coordinatorMain, .{self}) catch null;
        self.local_worker = std.Thread.spawn(.{}, localWorkerMain, .{self}) catch null;
    }

    pub fn deinit(self: *Registry) void {
        self.stop.store(true, .release);
        if (self.coordinator) |t| t.join();
        if (self.local_worker) |t| t.join();
        lockSpin(&self.mutex);
        // Anything left behind never started or was interrupted: mark it
        // canceled so retained records never claim active work.
        for (self.snapshots.items) |snap| {
            if (!snap.state.terminal()) {
                snap.state = .canceled;
                snap.finished_at_ns = snap.touched_ns;
            }
        }
        for (self.jobs.items) |job| {
            if (!job.state.terminal()) {
                job.state = .canceled;
                job.finished_at_ns = job.touched_ns;
            }
        }
        for (self.snapshots.items) |snap| snap.deinit(self.allocator);
        self.snapshots.deinit(self.allocator);
        for (self.jobs.items) |job| job.deinit(self.allocator);
        self.jobs.deinit(self.allocator);
        for (self.plans.items) |plan| plan.deinit(self.allocator);
        self.plans.deinit(self.allocator);
        self.mutex.unlock();
    }

    // --- registration (handler side) --------------------------------------------

    pub const RegisterError = error{ TooManyActive, OutOfMemory };

    pub fn registerSnapshot(self: *Registry, snap: *Snapshot) RegisterError!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.makeRoomLocked(Snapshot, &self.snapshots, max_snapshots);
        try self.snapshots.append(self.allocator, snap);
    }

    pub fn registerJob(self: *Registry, job: *Job) RegisterError!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.makeRoomLocked(Job, &self.jobs, max_jobs);
        try self.jobs.append(self.allocator, job);
    }

    /// Evicts expired records, then the oldest terminal records until a
    /// slot opens. Active work is never evicted: when every record is
    /// active, registration fails instead.
    fn makeRoomLocked(self: *Registry, comptime T: type, list: *std.ArrayList(*T), cap: usize) RegisterError!void {
        self.sweepExpiredLocked(self.nowNs());
        while (list.items.len >= cap) {
            var oldest_idx: ?usize = null;
            var oldest_ns: i128 = std.math.maxInt(i128);
            for (list.items, 0..) |item, i| {
                if (!item.state.terminal()) continue;
                if (item.touched_ns < oldest_ns) {
                    oldest_ns = item.touched_ns;
                    oldest_idx = i;
                }
            }
            const idx = oldest_idx orelse return error.TooManyActive;
            const removed = list.orderedRemove(idx);
            removed.deinit(self.allocator);
        }
    }

    /// Expiry: unfinished records idle for 10 minutes are canceled;
    /// terminal records older than 30 minutes are deleted. Claimed
    /// (actively driven) records are never touched.
    fn sweepExpiredLocked(self: *Registry, now_ns: i128) void {
        sweepList(Snapshot, self, &self.snapshots, now_ns);
        sweepList(Job, self, &self.jobs, now_ns);
        const now_ms = @divTrunc(now_ns, std.time.ns_per_ms);
        var i: usize = 0;
        while (i < self.plans.items.len) {
            const plan = self.plans.items[i];
            if (plan.expired(now_ms)) {
                plan.deinit(self.allocator);
                _ = self.plans.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    fn sweepList(comptime T: type, self: *Registry, list: *std.ArrayList(*T), now_ns: i128) void {
        var i: usize = 0;
        while (i < list.items.len) {
            const item = list.items[i];
            if (!item.state.terminal() and !item.claimed and now_ns - item.touched_ns > registry_idle_expiry_ns) {
                item.state = .canceled;
                item.finished_at_ns = now_ns;
                item.touched_ns = now_ns;
                if (T == Job) self.clearJobSecretsLocked(item);
            }
            if (item.state.terminal() and now_ns - item.touched_ns > registry_terminal_retention_ns) {
                item.deinit(self.allocator);
                _ = list.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    pub fn sweepExpired(self: *Registry, now_ns: i128) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.sweepExpiredLocked(now_ns);
    }

    // --- lookups ----------------------------------------------------------------

    pub fn snapshotById(self: *Registry, id: []const u8) ?*Snapshot {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.snapshots.items) |snap| {
            if (std.mem.eql(u8, snap.id, id)) return snap;
        }
        return null;
    }

    pub fn jobById(self: *Registry, id: []const u8) ?*Job {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.jobs.items) |job| {
            if (std.mem.eql(u8, job.id, id)) return job;
        }
        return null;
    }

    /// Idempotency: a repeated operation_id returns the existing job.
    pub fn jobByOperationId(self: *Registry, operation_id: []const u8) ?*Job {
        if (operation_id.len == 0) return null;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.jobs.items) |job| {
            if (std.mem.eql(u8, job.operation_id, operation_id)) return job;
        }
        return null;
    }

    /// The latest completed snapshot for a server (role plans and the UI
    /// build on its capabilities and frozen source identities).
    pub fn lastCompletedSnapshot(self: *Registry, server_id: []const u8) ?*Snapshot {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var best: ?*Snapshot = null;
        for (self.snapshots.items) |snap| {
            if (!std.mem.eql(u8, snap.server_id, server_id)) continue;
            if (snap.state != .done and snap.state != .partial) continue;
            if (best == null or snap.created_at_ns > best.?.created_at_ns) best = snap;
        }
        return best;
    }

    pub fn registerPlan(self: *Registry, plan: *RolePlan) RegisterError!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.sweepExpiredLocked(self.nowNs());
        while (self.plans.items.len >= max_plans) {
            const removed = self.plans.orderedRemove(0);
            removed.deinit(self.allocator);
        }
        try self.plans.append(self.allocator, plan);
    }

    /// Takes ownership of a plan (removes it from the registry).
    pub fn takePlan(self: *Registry, id: []const u8) ?*RolePlan {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.plans.items, 0..) |plan, i| {
            if (std.mem.eql(u8, plan.id, id)) {
                _ = self.plans.orderedRemove(i);
                return plan;
            }
        }
        return null;
    }

    // --- driver-side mutation helpers (each locks briefly) ----------------------

    pub fn snapshotSwap(
        self: *Registry,
        snap: *Snapshot,
        sources: std.ArrayList(Source),
        keys: std.ArrayList(KeyEntry),
        roles: std.ArrayList(RoleEntry),
        deploy_keys: std.ArrayList(DeployKeyEntry),
        warnings: std.ArrayList([]u8),
    ) void {
        lockSpin(&self.mutex);
        for (snap.sources.items) |*s| s.deinit(self.allocator);
        snap.sources.deinit(self.allocator);
        snap.sources = sources;
        for (snap.keys.items) |*k| k.deinit(self.allocator);
        snap.keys.deinit(self.allocator);
        snap.keys = keys;
        for (snap.roles.items) |*r| r.deinit(self.allocator);
        snap.roles.deinit(self.allocator);
        snap.roles = roles;
        for (snap.deploy_keys.items) |*d| d.deinit(self.allocator);
        snap.deploy_keys.deinit(self.allocator);
        snap.deploy_keys = deploy_keys;
        for (snap.warnings.items) |w| self.allocator.free(w);
        snap.warnings.deinit(self.allocator);
        snap.warnings = warnings;
        self.mutex.unlock();
    }

    pub fn snapshotFinish(
        self: *Registry,
        snap: *Snapshot,
        state: SnapshotState,
        scope: []const u8,
        coverage: []const u8,
        privilege: []const u8,
        sftp_read_only: bool,
        sftp_forced_command: []const u8,
        pubkey_authentication: ?bool,
    ) void {
        lockSpin(&self.mutex);
        const now_ns = self.nowNs();
        snap.state = state;
        self.allocator.free(snap.scope);
        snap.scope = self.allocator.dupe(u8, scope) catch &.{};
        self.allocator.free(snap.coverage);
        snap.coverage = self.allocator.dupe(u8, coverage) catch &.{};
        self.allocator.free(snap.privilege);
        snap.privilege = self.allocator.dupe(u8, privilege) catch &.{};
        snap.sftp_read_only = sftp_read_only;
        self.allocator.free(snap.sftp_forced_command);
        snap.sftp_forced_command = self.allocator.dupe(u8, sftp_forced_command) catch &.{};
        snap.pubkey_authentication = pubkey_authentication;
        snap.finished_at_ns = now_ns;
        snap.touched_ns = now_ns;
        snap.claimed = false;
        self.mutex.unlock();
    }

    pub fn jobSetStep(self: *Registry, job: *Job, index: usize, state: StepState, err_msg: ?[]const u8) void {
        if (index >= job.steps.len) return;
        lockSpin(&self.mutex);
        const step = &job.steps[index];
        step.state = state;
        if (step.@"error") |e| {
            self.allocator.free(e);
            step.@"error" = null;
        }
        if (err_msg) |m| step.@"error" = self.allocator.dupe(u8, m) catch null;
        job.touched_ns = self.nowNs();
        self.mutex.unlock();
    }

    fn clearJobSecretsLocked(self: *Registry, job: *Job) void {
        switch (job.payload) {
            .local_generate => |*payload| {
                if (payload.passphrase) |passphrase| {
                    std.crypto.secureZero(u8, passphrase);
                    self.allocator.free(passphrase);
                    payload.passphrase = null;
                }
            },
            else => {},
        }
        if (job.verification) |*verification| {
            verification.deinit(self.allocator);
            job.verification = null;
        }
    }

    pub fn jobClearSecrets(self: *Registry, job: *Job) void {
        lockSpin(&self.mutex);
        self.clearJobSecretsLocked(job);
        self.mutex.unlock();
    }

    pub fn jobSetState(self: *Registry, job: *Job, state: JobState) void {
        lockSpin(&self.mutex);
        job.state = state;
        job.touched_ns = self.nowNs();
        if (state.terminal()) {
            job.finished_at_ns = job.touched_ns;
            job.claimed = false;
            self.clearJobSecretsLocked(job);
        } else if (state == .waiting_for_verification) {
            job.claimed = false;
        }
        self.mutex.unlock();
    }

    pub fn jobSetResult(self: *Registry, job: *Job, result_json: []u8) void {
        lockSpin(&self.mutex);
        if (job.result_json) |old| self.allocator.free(old);
        job.result_json = result_json;
        self.mutex.unlock();
    }

    pub fn jobSetStagedHash(self: *Registry, job: *Job, hash: []u8) void {
        lockSpin(&self.mutex);
        if (job.staged_file_sha256) |old| self.allocator.free(old);
        job.staged_file_sha256 = hash;
        self.mutex.unlock();
    }

    /// rotateCommit: attach the verification and requeue the job, by id.
    /// The whole check-and-submit happens under one lock so the record
    /// cannot be evicted between lookup and mutation. Returns false when
    /// the job is not waiting for verification; the caller still owns
    /// (and must release) the verification in that case.
    pub fn jobSubmitVerificationById(self: *Registry, id: []const u8, verification: RotateVerification) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.jobs.items) |job| {
            if (!std.mem.eql(u8, job.id, id)) continue;
            if (job.state != .waiting_for_verification or job.verification != null) {
                return false;
            }
            job.verification = verification;
            job.state = .queued;
            job.claimed = false;
            job.touched_ns = self.nowNs();
            return true;
        }
        return false;
    }

    pub fn touchSnapshot(self: *Registry, snap: *Snapshot) void {
        lockSpin(&self.mutex);
        snap.touched_ns = self.nowNs();
        self.mutex.unlock();
    }

    pub fn touchJob(self: *Registry, job: *Job) void {
        lockSpin(&self.mutex);
        job.touched_ns = self.nowNs();
        self.mutex.unlock();
    }

    /// Poll serializers hold the registry lock while copying state out.
    pub fn lock(self: *Registry) void {
        lockSpin(&self.mutex);
    }

    pub fn unlock(self: *Registry) void {
        self.mutex.unlock();
    }

    /// The audit-safe summary of a canceled job: owned copies, because
    /// the record may be evicted as soon as the lock is released.
    pub const CancelInfo = struct {
        /// True when this call made the terminal transition (the caller
        /// audits exactly once); false when the driver will finish.
        transitioned: bool,
        kind: JobKind,
        server_id: []u8,
        detail: []u8,

        pub fn deinit(self: *CancelInfo, allocator: std.mem.Allocator) void {
            allocator.free(self.server_id);
            allocator.free(self.detail);
        }
    };

    /// Handler-side cancel, by id. Queued and waiting jobs transition to
    /// canceled immediately; running jobs get the cooperative flag and
    /// finish through the driver. Null: unknown id.
    pub fn jobCancelById(self: *Registry, id: []const u8) ?CancelInfo {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const job = self.jobByIdLocked(id) orelse return null;
        var detail_buf: [256]u8 = undefined;
        var info = CancelInfo{
            .transitioned = false,
            .kind = job.kind,
            .server_id = self.allocator.dupe(u8, job.server_id) catch return null,
            .detail = self.allocator.dupe(u8, kindDetail(job, &detail_buf)) catch return null,
        };
        if (job.state == .queued or job.state == .waiting_for_verification) {
            job.state = .canceled;
            job.finished_at_ns = self.nowNs();
            job.touched_ns = job.finished_at_ns.?;
            job.claimed = false;
            self.clearJobSecretsLocked(job);
            for (job.steps) |*s| {
                if (s.state == .queued or s.state == .running or s.state == .waiting) s.state = .canceled;
            }
            info.transitioned = true;
            return info;
        }
        if (job.state == .running) {
            job.cancel_requested.store(true, .release);
        }
        return info;
    }

    /// Snapshot cancel, by id. True: a queued snapshot was canceled
    /// immediately; false: the flag was set (running) or the snapshot
    /// was already terminal. Null: unknown id.
    pub fn snapshotCancelById(self: *Registry, id: []const u8) ?bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const snap = self.snapshotByIdLocked(id) orelse return null;
        if (snap.state == .queued) {
            snap.cancel_requested.store(true, .release);
            snap.state = .canceled;
            snap.finished_at_ns = self.nowNs();
            snap.touched_ns = snap.finished_at_ns.?;
            return true;
        }
        if (snap.state == .running) {
            snap.cancel_requested.store(true, .release);
        }
        return false;
    }

    fn snapshotByIdLocked(self: *Registry, id: []const u8) ?*Snapshot {
        for (self.snapshots.items) |snap| {
            if (std.mem.eql(u8, snap.id, id)) return snap;
        }
        return null;
    }

    fn jobByIdLocked(self: *Registry, id: []const u8) ?*Job {
        for (self.jobs.items) |job| {
            if (std.mem.eql(u8, job.id, id)) return job;
        }
        return null;
    }

    /// Idempotency lookup with owned copies: the record could be evicted
    /// the moment the lock is released, so handlers get what they need
    /// up front.
    pub const OperationMatch = struct {
        id: []u8,
        kind: JobKind,
        /// add: the key fingerprint; rotate: the new fingerprint.
        fingerprint: ?[]u8,

        pub fn deinit(self: *OperationMatch, allocator: std.mem.Allocator) void {
            allocator.free(self.id);
            if (self.fingerprint) |f| allocator.free(f);
        }
    };

    pub fn operationLookup(self: *Registry, operation_id: []const u8) ?OperationMatch {
        if (operation_id.len == 0) return null;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.jobs.items) |job| {
            if (!std.mem.eql(u8, job.operation_id, operation_id)) continue;
            const fingerprint: ?[]u8 = switch (job.payload) {
                .add => |*p| self.allocator.dupe(u8, p.fingerprint) catch null,
                .rotate => |*p| self.allocator.dupe(u8, p.new_fingerprint) catch null,
                else => null,
            };
            return .{
                .id = self.allocator.dupe(u8, job.id) catch return null,
                .kind = job.kind,
                .fingerprint = fingerprint,
            };
        }
        return null;
    }

    // --- coordinator ------------------------------------------------------------

    const WorkItem = union(enum) {
        snapshot: *Snapshot,
        job: *Job,
    };

    fn claimNext(self: *Registry) ?WorkItem {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.snapshots.items) |snap| {
            if (snap.state == .queued and !snap.claimed) {
                snap.claimed = true;
                snap.state = .running;
                return .{ .snapshot = snap };
            }
        }
        for (self.jobs.items) |job| {
            if (job.state == .queued and !job.claimed and job.kind != .local_generate) {
                job.claimed = true;
                job.state = .running;
                return .{ .job = job };
            }
        }
        return null;
    }

    fn claimNextLocal(self: *Registry) ?*Job {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.jobs.items) |job| {
            if (job.state == .queued and !job.claimed and job.kind == .local_generate) {
                job.claimed = true;
                job.state = .running;
                return job;
            }
        }
        return null;
    }

    fn coordinatorMain(self: *Registry) void {
        const io = self.io orelse return;
        while (!self.stop.load(.acquire)) {
            if (self.claimNext()) |work| {
                const driver = self.driver orelse continue;
                switch (work) {
                    .snapshot => |snap| driver.drive_snapshot(driver.context, self, snap),
                    .job => |job| driver.drive_job(driver.context, self, job),
                }
                continue;
            }
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch return;
        }
    }

    fn localWorkerMain(self: *Registry) void {
        const io = self.io orelse return;
        while (!self.stop.load(.acquire)) {
            if (self.claimNextLocal()) |job| {
                const driver = self.driver orelse continue;
                driver.drive_local_job(driver.context, self, job);
                continue;
            }
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch return;
        }
    }
};

// --- tests ---------------------------------------------------------------------

const testing = std.testing;

test "assessKeyPolicy distinguishes standard, restricted, role-forced, and weak" {
    try testing.expectEqualStrings("standard", assessKeyPolicy("").level);
    try testing.expectEqualStrings("restricted", assessKeyPolicy("no-port-forwarding").level);
    try testing.expectEqualStrings("restricted", assessKeyPolicy("from=\"10.0.0.0/8\"").level);
    try testing.expectEqualStrings("role_forced", assessKeyPolicy("restrict,command=\"internal-sftp -R\"").level);
    try testing.expectEqualStrings("weak", assessKeyPolicy("command=\"internal-sftp -R\"").level);
    try testing.expectEqualStrings("weak", assessKeyPolicy("restrict,cert-authority").level);
}

test "commandOption extracts quoted values with commas and escapes" {
    try testing.expectEqualStrings("internal-sftp -R", commandOption("restrict,command=\"internal-sftp -R\"").?);
    try testing.expectEqualStrings("a b,c", commandOption("command=\"a b,c\",restrict").?);
    try testing.expect(commandOption("restrict") == null);
    try testing.expect(commandOption("command=\"unterminated") == null);
}

test "verifyReadOnlyKeyOptions is exact and fail-closed" {
    try testing.expect(verifyReadOnlyKeyOptions("restrict,command=\"internal-sftp -R\"", "internal-sftp -R"));
    try testing.expect(!verifyReadOnlyKeyOptions("command=\"internal-sftp -R\"", "internal-sftp -R"));
    try testing.expect(!verifyReadOnlyKeyOptions("restrict", "internal-sftp -R"));
    try testing.expect(!verifyReadOnlyKeyOptions("restrict,command=\"internal-sftp\"", "internal-sftp -R"));
    try testing.expect(!verifyReadOnlyKeyOptions("restrict,cert-authority,command=\"internal-sftp -R\"", "internal-sftp -R"));
    try testing.expect(!verifyReadOnlyKeyOptions("", "internal-sftp -R"));
}

test "statusAllowsMutation gates on missing or readable only" {
    try testing.expect(statusAllowsMutation(.missing));
    try testing.expect(statusAllowsMutation(.readable));
    try testing.expect(!statusAllowsMutation(.denied));
    try testing.expect(!statusAllowsMutation(.timeout));
    try testing.expect(!statusAllowsMutation(.too_large));
    try testing.expect(!statusAllowsMutation(.transport_error));
    try testing.expect(!statusAllowsMutation(.parse_error));
}

test "randomId is prefixed, hex, and unique" {
    const allocator = testing.allocator;
    const a = try randomId(allocator, testing.io, "snap");
    defer allocator.free(a);
    const b = try randomId(allocator, testing.io, "snap");
    defer allocator.free(b);
    try testing.expect(std.mem.startsWith(u8, a, "snap-"));
    try testing.expectEqual(@as(usize, 5 + 16), a.len);
    try testing.expect(!std.mem.eql(u8, a, b));
}

fn testJob(allocator: std.mem.Allocator, id: []const u8, operation_id: []const u8, kind: JobKind, now_ns: i128) !*Job {
    const job = try allocator.create(Job);
    const steps = try allocator.alloc(Step, kind.steps().len);
    for (kind.steps(), 0..) |step_id, i| steps[i] = .{ .id = step_id };
    job.* = .{
        .id = try allocator.dupe(u8, id),
        .operation_id = try allocator.dupe(u8, operation_id),
        .server_id = try allocator.dupe(u8, "srv"),
        .kind = kind,
        .account_name = null,
        .source_path = try allocator.dupe(u8, ""),
        .file_sha256 = try allocator.dupe(u8, ""),
        .payload = .{ .revoke = .{
            .fingerprint = try allocator.dupe(u8, "SHA256:x"),
            .line_hash = try allocator.dupe(u8, "hash"),
        } },
        .created_at_ns = now_ns,
        .steps = steps,
        .touched_ns = now_ns,
    };
    return job;
}

fn deinitTestJobs(registry: *Registry, allocator: std.mem.Allocator) void {
    lockSpin(&registry.mutex);
    for (registry.jobs.items) |job| job.deinit(allocator);
    registry.jobs.deinit(allocator);
    registry.jobs = .empty;
    registry.mutex.unlock();
}

test "registry dedupes operation ids and looks jobs up" {
    const allocator = testing.allocator;
    var registry = Registry.init(allocator);
    registry.io = testing.io;
    defer deinitTestJobs(&registry, allocator);
    const now = std.Io.Timestamp.now(testing.io, .real).nanoseconds;
    const job = try testJob(allocator, "job-1", "op-1", .revoke, now);
    try registry.registerJob(job);
    try testing.expect(registry.jobByOperationId("op-1") == job);
    try testing.expect(registry.jobByOperationId("op-2") == null);
    try testing.expect(registry.jobById("job-1") == job);
}

test "registry expires idle unfinished records and deletes old terminal ones" {
    const allocator = testing.allocator;
    var registry = Registry.init(allocator);
    registry.io = testing.io;
    defer deinitTestJobs(&registry, allocator);
    const now = std.Io.Timestamp.now(testing.io, .real).nanoseconds;
    const idle = try testJob(allocator, "job-idle", "op-idle", .revoke, now - registry_idle_expiry_ns - 1);
    idle.touched_ns = now - registry_idle_expiry_ns - 1;
    try registry.registerJob(idle);
    const terminal = try testJob(allocator, "job-old", "op-old", .revoke, now - registry_terminal_retention_ns - 1);
    terminal.state = .done;
    terminal.touched_ns = now - registry_terminal_retention_ns - 1;
    try registry.registerJob(terminal);
    registry.sweepExpired(now);
    try testing.expectEqual(JobState.canceled, idle.state);
    try testing.expect(registry.jobById("job-old") == null);
    // A claimed (active) record past the idle deadline is never canceled.
    const active = try testJob(allocator, "job-active", "op-active", .revoke, now - registry_idle_expiry_ns - 1);
    active.touched_ns = now - registry_idle_expiry_ns - 1;
    active.claimed = true;
    try registry.registerJob(active);
    registry.sweepExpired(now);
    try testing.expectEqual(JobState.queued, active.state);
}

test "waiting jobs release their claim and expire when abandoned" {
    const allocator = testing.allocator;
    var registry = Registry.init(allocator);
    registry.io = testing.io;
    defer deinitTestJobs(&registry, allocator);
    const now = std.Io.Timestamp.now(testing.io, .real).nanoseconds;
    const job = try testJob(allocator, "job-waiting", "op-waiting", .rotate, now);
    job.claimed = true;
    try registry.registerJob(job);

    registry.jobSetState(job, .waiting_for_verification);
    try testing.expect(!job.claimed);
    registry.sweepExpired(job.touched_ns + registry_idle_expiry_ns + 1);
    try testing.expectEqual(JobState.canceled, job.state);
}

test "terminal jobs clear retained passphrases" {
    const allocator = testing.allocator;
    var registry = Registry.init(allocator);
    registry.io = testing.io;
    defer deinitTestJobs(&registry, allocator);
    const now = std.Io.Timestamp.now(testing.io, .real).nanoseconds;
    const job = try testJob(allocator, "job-secret", "op-secret", .local_generate, now);
    job.payload.deinit(allocator);
    job.payload = .{ .local_generate = .{
        .destination = try allocator.dupe(u8, "/tmp/id"),
        .comment = null,
        .passphrase = try allocator.dupe(u8, "secret"),
        .remember_passphrase = false,
    } };
    job.verification = .{ .local_private_key = .{
        .path = try allocator.dupe(u8, "/tmp/id"),
        .passphrase = try allocator.dupe(u8, "verify-secret"),
    } };
    try registry.registerJob(job);

    registry.jobSetState(job, .done);
    try testing.expect(job.payload.local_generate.passphrase == null);
    try testing.expect(job.verification == null);
}

test "role plans expire at their ttl" {
    const plan = RolePlan{
        .id = @constCast("plan-1"),
        .server_id = @constCast("srv"),
        .name = @constCast("reports"),
        .kind = @constCast("read_only_sftp"),
        .action = .create,
        .privilege = @constCast("root"),
        .home = null,
        .commands = &.{},
        .effects = &.{},
        .created_at_ms = 1000,
        .expires_at_ms = 1000 + plan_ttl_ms,
    };
    try testing.expect(!plan.expired(1000 + plan_ttl_ms - 1));
    try testing.expect(plan.expired(1000 + plan_ttl_ms));
}
