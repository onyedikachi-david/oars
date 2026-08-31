//! Spec 10: backups — local job/history stores, bounded plans and operations,
//! provider validation, config generation, cron editing, and rclone log parsing.
//! The registry coordinator owns operation completion; bridge handlers only
//! validate, copy, register, and serialize owned snapshots.
//!
//! Secret rules (spec 10 §8): bucket credentials live in Keychain
//! (`backup:<job_id>`) and never in jobs.json, run history, or audit.
//! The dedicated remote config for unattended schedules is the only
//! server-side secret copy (mode 0600, reversible obscuring disclosure).

const std = @import("std");
const sessions = @import("sessions.zig");
const shellquote = @import("shellquote.zig");

// --- constants -------------------------------------------------------------

pub const max_job_name_len: usize = 80;
pub const max_source_path_len: usize = 1024;
pub const max_bucket_len: usize = 255;
pub const max_endpoint_len: usize = 512;
pub const max_prefix_len: usize = 512;
pub const max_cron_expr_len: usize = 128;
pub const max_runs: usize = 200;
pub const history_retention_days: i64 = 90;
pub const history_log_cap: usize = 200 * 1024;
pub const remote_config_dir = ".config/oars";
pub const remote_config_path = "~/.config/oars/rclone.conf";
pub const state_dir = "~/.local/state/oars/backups";
pub const max_manual_runs_per_server: usize = 1;
pub const max_id_len: usize = 128;
pub const max_jobs_per_server: usize = 128;
pub const max_job_store_records: usize = 4096;
pub const max_credentials_len: usize = 4096;
pub const history_retention_ns: i64 = history_retention_days * 86_400_000_000_000;
const backup_store_version: u32 = 1;
const max_history_error_len: usize = 4096;

/// Bounds for NEXT-SPEC §Exact bounds — centralize here.
pub fn validId(id: []const u8) bool {
    if (id.len == 0 or id.len > max_id_len) return false;
    for (id) |ch| {
        if (ch == 0 or ch < 0x20 or ch == 0x7f) return false;
        if (ch == '/' or ch == '\\' or ch == '"' or ch == '\'' or ch == '`' or ch == '$' or ch == '\n' or ch == '\r') return false;
    }
    return true;
}

pub fn validStagedName(name: []const u8) bool {
    if (name.len == 0 or name.len > 255) return false;
    if (!std.mem.endsWith(u8, name, ".status") and !std.mem.endsWith(u8, name, ".log")) return false;
    for (name) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_' and ch != '.') return false;
    }
    return true;
}

pub fn validCredentials(s: []const u8) bool {
    if (s.len == 0 or s.len > max_credentials_len) return false;
    return !hasControlChars(s);
}

/// "prefix" normalization: strip one leading/trailing `/`, reject empties
/// that become empty only due to slashes, keep interior.
pub fn normalizePrefix(allocator: std.mem.Allocator, prefix: []const u8) ![]u8 {
    var s = std.mem.trim(u8, prefix, " \t\r\n");
    if (s.len > 0 and s[0] == '/') s = s[1..];
    if (s.len > 0 and s[s.len - 1] == '/') s = s[0 .. s.len - 1];
    return allocator.dupe(u8, s);
}

/// Random path-safe IDs. Persisted IDs are still collision-checked by JobStore.
pub fn randomId(allocator: std.mem.Allocator, io: std.Io, prefix: []const u8) ![]u8 {
    var bytes: [16]u8 = undefined;
    try std.Io.randomSecure(io, &bytes);
    const hex = std.fmt.bytesToHex(bytes, .lower);
    return std.fmt.allocPrint(allocator, "{s}-{s}", .{ prefix, hex });
}

pub fn randomJobId(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    return randomId(allocator, io, "bk");
}

pub fn randomRunId(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    return randomId(allocator, io, "run");
}

fn auditPlanHash(kind: []const u8, server_id: []const u8, job_id: []const u8, payload: []const u8) [64]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(kind);
    hasher.update(&.{0});
    hasher.update(server_id);
    hasher.update(&.{0});
    hasher.update(job_id);
    hasher.update(&.{0});
    hasher.update(payload);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

fn runPlanHash(job: *const Job) [64]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    const fields = [_][]const u8{
        job.id,
        job.server_id,
        job.name,
        job.source_path,
        job.destination.type,
        job.destination.provider,
        job.destination.bucket,
        job.destination.prefix,
        job.destination.endpoint,
        job.destination.region,
        job.destination.credential_mode.jsonName(),
        job.destination.storage_class,
        job.transfer.jsonName(),
        job.schedule.mode,
        job.schedule.expr,
        job.schedule.unit,
    };
    for (fields) |field| {
        hasher.update(field);
        hasher.update(&.{0});
    }
    var number_buf: [64]u8 = undefined;
    const numbers = std.fmt.bufPrint(&number_buf, "{d}:{d}:{d}:{d}", .{ job.revision, job.schedule.every, job.schedule.anchor_epoch_sec, @intFromBool(job.schedule.enabled) }) catch "";
    hasher.update(numbers);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn secureFree(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

pub const CredentialsView = struct {
    access_key: []const u8,
    secret_key: []const u8,
};

pub const OwnedCredentials = struct {
    access_key: []u8,
    secret_key: []u8,

    pub fn init(allocator: std.mem.Allocator, credentials: CredentialsView) !OwnedCredentials {
        if (!validCredentials(credentials.access_key) or !validCredentials(credentials.secret_key)) return error.InvalidCredentials;
        const access_key = try allocator.dupe(u8, credentials.access_key);
        errdefer secureFree(allocator, access_key);
        const secret_key = try allocator.dupe(u8, credentials.secret_key);
        return .{ .access_key = access_key, .secret_key = secret_key };
    }

    pub fn deinit(self: *OwnedCredentials, allocator: std.mem.Allocator) void {
        secureFree(allocator, self.access_key);
        secureFree(allocator, self.secret_key);
        self.* = undefined;
    }
};

// --- providers -------------------------------------------------------------

pub const Provider = enum(u8) {
    aws,
    r2,
    b2_s3,
    wasabi,
    minio,
    spaces,

    pub fn jsonName(self: Provider) []const u8 {
        return @tagName(self);
    }

    pub fn fromJsonName(name: []const u8) ?Provider {
        if (std.mem.eql(u8, name, "aws")) return .aws;
        if (std.mem.eql(u8, name, "r2")) return .r2;
        if (std.mem.eql(u8, name, "b2_s3")) return .b2_s3;
        if (std.mem.eql(u8, name, "wasabi")) return .wasabi;
        if (std.mem.eql(u8, name, "minio")) return .minio;
        if (std.mem.eql(u8, name, "spaces")) return .spaces;
        return null;
    }

    /// The provider's rclone `provider` value (s3 backend).
    /// B2 is accessed through the S3-compatible endpoint, so the rclone S3
    /// `provider` is `Other` — there is no `B2` value in rclone's S3
    /// backend. R2's S3 adapter is `Cloudflare` (region = auto).
    pub fn rcloneName(self: Provider) []const u8 {
        return switch (self) {
            .aws => "AWS",
            .r2 => "Cloudflare",
            .b2_s3 => "Other",
            .wasabi => "Wasabi",
            .minio => "Minio",
            .spaces => "DigitalOcean",
        };
    }

    pub fn needsEndpoint(self: Provider) bool {
        return switch (self) {
            .aws => false,
            else => true,
        };
    }

    pub fn needsRegion(self: Provider) bool {
        return switch (self) {
            .aws => true,
            else => false,
        };
    }

    /// Storage classes the s3 backend accepts for this provider (the
    /// spec's adapter-scoped set — never universal Glacier names).
    /// Empty means provider default; only the allow-list is exposed.
    pub fn storageClasses(self: Provider) []const []const u8 {
        return switch (self) {
            .aws => &aws_classes,
            .wasabi => &wasabi_classes,
            else => &generic_classes,
        };
    }

    /// Non-AWS adapters expose only the default class in v1; named classes
    /// are provider-specific and require direct evidence.
    const generic_classes = [_][]const u8{"standard"};
    const aws_classes = [_][]const u8{
        "standard",            "reduced_redundancy",
        "standard_ia",         "onezone_ia",
        "intelligent_tiering", "glacier",
        "deep_archive",        "glacier_ir",
    };
    const wasabi_classes = [_][]const u8{"standard"};

    pub fn supportsStorageClass(self: Provider, class: []const u8) bool {
        if (class.len == 0) return true; // provider default — omitted from config
        const classes = self.storageClasses();
        for (classes) |c| {
            if (std.mem.eql(u8, c, class)) return true;
        }
        return false;
    }
};

// --- job model -------------------------------------------------------------

pub const Transfer = enum(u8) {
    sync,
    copy,

    pub fn jsonName(self: Transfer) []const u8 {
        return @tagName(self);
    }

    pub fn fromJsonName(name: []const u8) ?Transfer {
        if (std.mem.eql(u8, name, "sync")) return .sync;
        if (std.mem.eql(u8, name, "copy")) return .copy;
        return null;
    }
};

pub const CredentialMode = enum {
    access_key,
    aws_runtime,

    pub fn jsonName(self: CredentialMode) []const u8 {
        return @tagName(self);
    }
};

/// Shipping v1 destination. Local destinations and legacy `use_iam` are not
/// accepted by bridge payload parsing.
pub const Destination = struct {
    type: []const u8 = "s3",
    provider: []const u8 = "aws",
    bucket: []const u8 = "",
    prefix: []const u8 = "",
    endpoint: []const u8 = "",
    region: []const u8 = "",
    credential_mode: CredentialMode = .access_key,
    storage_class: []const u8 = "",
};

pub const Schedule = struct {
    mode: []const u8 = "manual", // manual | interval | custom
    enabled: bool = false,
    every: u32 = 24,
    unit: []const u8 = "hours",
    anchor_epoch_sec: i64 = 0,
    expr: []const u8 = "",
};

pub const Job = struct {
    id: []const u8,
    server_id: []const u8,
    name: []const u8,
    source_path: []const u8,
    destination: Destination,
    transfer: Transfer = .copy,
    schedule: Schedule = .{},
    revision: u64 = 1,
    created_at_ns: i64 = 0,
    updated_at_ns: i64 = 0,

    pub fn deinit(self: *Job, allocator: std.mem.Allocator) void {
        // Every owned string is either a non-empty dupe or the comptime
        // empty literal (dupOrLiteral) — never free a literal.
        if (self.id.len > 0) allocator.free(self.id);
        if (self.server_id.len > 0) allocator.free(self.server_id);
        if (self.name.len > 0) allocator.free(self.name);
        if (self.source_path.len > 0) allocator.free(self.source_path);
        if (self.destination.type.len > 0) allocator.free(self.destination.type);
        if (self.destination.provider.len > 0) allocator.free(self.destination.provider);
        if (self.destination.bucket.len > 0) allocator.free(self.destination.bucket);
        if (self.destination.prefix.len > 0) allocator.free(self.destination.prefix);
        if (self.destination.endpoint.len > 0) allocator.free(self.destination.endpoint);
        if (self.destination.region.len > 0) allocator.free(self.destination.region);
        if (self.destination.storage_class.len > 0) allocator.free(self.destination.storage_class);
        if (self.schedule.mode.len > 0) allocator.free(self.schedule.mode);

        if (self.schedule.unit.len > 0) allocator.free(self.schedule.unit);
        if (self.schedule.expr.len > 0) allocator.free(self.schedule.expr);
    }
};

fn cloneJobOwned(allocator: std.mem.Allocator, job: Job) !Job {
    var copy = Job{
        .id = "",
        .server_id = "",
        .name = "",
        .source_path = "",
        .destination = .{},
        .transfer = job.transfer,
        .schedule = .{},
        .revision = job.revision,
        .created_at_ns = job.created_at_ns,
        .updated_at_ns = job.updated_at_ns,
    };
    errdefer copy.deinit(allocator);
    copy.id = try dupOrLiteral(allocator, job.id);
    copy.server_id = try dupOrLiteral(allocator, job.server_id);
    copy.name = try dupOrLiteral(allocator, job.name);
    copy.source_path = try dupOrLiteral(allocator, job.source_path);
    copy.destination.type = try dupOrLiteral(allocator, job.destination.type);
    copy.destination.provider = try dupOrLiteral(allocator, job.destination.provider);
    copy.destination.bucket = try dupOrLiteral(allocator, job.destination.bucket);
    copy.destination.prefix = try dupOrLiteral(allocator, job.destination.prefix);
    copy.destination.endpoint = try dupOrLiteral(allocator, job.destination.endpoint);
    copy.destination.region = try dupOrLiteral(allocator, job.destination.region);
    copy.destination.credential_mode = job.destination.credential_mode;
    copy.destination.storage_class = try dupOrLiteral(allocator, job.destination.storage_class);
    copy.schedule.mode = try dupOrLiteral(allocator, job.schedule.mode);
    copy.schedule.enabled = job.schedule.enabled;
    copy.schedule.every = job.schedule.every;
    copy.schedule.unit = try dupOrLiteral(allocator, job.schedule.unit);
    copy.schedule.anchor_epoch_sec = job.schedule.anchor_epoch_sec;
    copy.schedule.expr = try dupOrLiteral(allocator, job.schedule.expr);
    return copy;
}

/// Owned copy unless the source is empty: an empty string is never
/// owned (deinit skips it), so `Job.deinit`/`RunRecord.deinit` can never
/// free a comptime literal. Use for every string a Job may own.
pub fn dupOrLiteral(allocator: std.mem.Allocator, s: []const u8) ![]const u8 {
    if (s.len == 0) return "";
    return allocator.dupe(u8, s);
}

pub const JobInput = struct {
    id: ?[]const u8 = null,
    server_id: []const u8,
    name: []const u8,
    source_path: []const u8,
    destination: Destination,
    transfer: []const u8 = "copy",
    schedule: Schedule = .{},
};

fn sameDestination(a: Destination, b: Destination) bool {
    return std.mem.eql(u8, a.type, b.type) and
        std.mem.eql(u8, a.provider, b.provider) and
        std.mem.eql(u8, a.bucket, b.bucket) and
        std.mem.eql(u8, a.prefix, b.prefix) and
        std.mem.eql(u8, a.endpoint, b.endpoint) and
        std.mem.eql(u8, a.region, b.region) and
        a.credential_mode == b.credential_mode and
        std.mem.eql(u8, a.storage_class, b.storage_class);
}

pub fn capabilityFieldsChanged(previous: ?*const Job, input: JobInput) bool {
    const old = previous orelse return true;
    return !sameDestination(old.destination, input.destination) or !std.mem.eql(u8, old.transfer.jsonName(), input.transfer);
}

pub fn scheduledConfigNeedsCredentials(previous: ?*const Job, input: JobInput) bool {
    if (!input.schedule.enabled or input.destination.credential_mode != .access_key) return false;
    const old = previous orelse return true;
    return !old.schedule.enabled or !sameDestination(old.destination, input.destination);
}

pub fn capabilityBinding(input: JobInput) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    const fields = [_][]const u8{
        input.destination.type,
        input.destination.provider,
        input.destination.bucket,
        input.destination.prefix,
        input.destination.endpoint,
        input.destination.region,
        input.destination.credential_mode.jsonName(),
        input.destination.storage_class,
        input.transfer,
    };
    for (fields) |field| {
        hasher.update(field);
        hasher.update(&.{0});
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

pub const SaveError = error{
    MissingId,
    UnknownId,
    MissingServer,
    MissingName,
    InvalidName,
    MissingSource,
    InvalidSource,
    InvalidDestination,
    InvalidProvider,
    InvalidBucket,
    InvalidEndpoint,
    InvalidRegion,
    InvalidStorageClass,
    IamRequiresAws,
    InvalidTransfer,
    InvalidSchedule,
    InvalidCronExpr,
    EnabledScheduleNeedsCredentials,
    StoreCorrupt,
    SerializeFailed,
    OutOfMemory,
    TooManyJobs,
    ImmutableServerId,
    RevConflict,
    InvalidId,
    InvalidPrefix,
    InvalidCredentials,
    StorePermissionDenied,
    StoreTimeout,
    StoreTooLarge,
    StoreQuarantineFailed,
    StoreIo,
};

const StoreAccessError = error{
    StorePermissionDenied,
    StoreTimeout,
    StoreTooLarge,
    StoreIo,
    OutOfMemory,
};

fn classifyStoreAccessError(err: anyerror) StoreAccessError {
    return switch (err) {
        error.AccessDenied, error.PermissionDenied => error.StorePermissionDenied,
        error.WouldBlock => error.StoreTimeout,
        error.StreamTooLong, error.FileTooBig => error.StoreTooLarge,
        error.OutOfMemory => error.OutOfMemory,
        else => error.StoreIo,
    };
}

fn saveErrorFromStore(err: anyerror) SaveError {
    return switch (err) {
        error.StorePermissionDenied => error.StorePermissionDenied,
        error.StoreTimeout => error.StoreTimeout,
        error.StoreTooLarge => error.StoreTooLarge,
        error.StoreQuarantineFailed => error.StoreQuarantineFailed,
        error.StoreIo => error.StoreIo,
        error.OutOfMemory => error.OutOfMemory,
        else => error.SerializeFailed,
    };
}

fn storeFailureCode(err: anyerror) FailureCode {
    return switch (err) {
        error.StorePermissionDenied => .permission_denied,
        error.StoreTimeout => .timeout,
        error.StoreTooLarge => .source_too_large,
        else => .store_corrupt,
    };
}

fn storeFailureRetryable(err: anyerror) bool {
    return switch (err) {
        error.StoreTimeout, error.StoreIo, error.SerializeFailed, error.StoreCorrupt, error.StoreQuarantineFailed => true,
        else => false,
    };
}

fn hasControlChars(s: []const u8) bool {
    for (s) |ch| {
        if (ch == 0 or ch < 0x20 or ch == 0x7f) return true;
    }
    return false;
}

pub fn validBucketName(bucket: []const u8) bool {
    if (bucket.len == 0 or bucket.len > max_bucket_len) return false;
    if (hasControlChars(bucket) or std.mem.indexOfAny(u8, bucket, " \t/\\\"'") != null) return false;
    return true;
}

pub fn validEndpoint(endpoint: []const u8) bool {
    if (endpoint.len == 0 or endpoint.len > max_endpoint_len) return false;
    // http(s)://host[:port] — anything else is a typing error.
    if (!std.mem.startsWith(u8, endpoint, "http://") and !std.mem.startsWith(u8, endpoint, "https://")) return false;
    return !hasControlChars(endpoint);
}

pub fn validRegion(region: []const u8) bool {
    if (region.len == 0 or region.len > 64) return false;
    if (hasControlChars(region) or std.mem.indexOfAny(u8, region, " \t/\\\"'") != null) return false;
    return true;
}

pub fn validate(input: JobInput) SaveError!void {
    // Generated ids are validated at admission; edits verify revision/server.
    if (input.id) |jid| if (!validId(jid)) return error.InvalidId;
    const name = std.mem.trim(u8, input.name, " \t\r\n");
    if (name.len == 0) return error.MissingName;
    if (name.len > max_job_name_len or hasControlChars(name)) return error.InvalidName;
    if (input.server_id.len == 0) return error.MissingServer;
    if (!validId(input.server_id)) return error.InvalidId;
    const source = std.mem.trim(u8, input.source_path, " \t\r\n");
    if (source.len == 0) return error.MissingSource;
    if (source.len > max_source_path_len or hasControlChars(source) or source[0] != '/') return error.InvalidSource;

    if (!std.mem.eql(u8, input.destination.type, "s3")) return error.InvalidDestination;
    const provider = Provider.fromJsonName(input.destination.provider) orelse return error.InvalidProvider;
    if (!validBucketName(input.destination.bucket)) return error.InvalidBucket;
    // Reject, rather than trim away, control bytes in every value that can
    // reach a generated path, command, metadata document, or INI line.
    if (input.destination.prefix.len > max_prefix_len or hasControlChars(input.destination.prefix)) return error.InvalidPrefix;
    // Endpoint: adapter-owned requirement; plain http only for MinIO test adapter.
    if (provider.needsEndpoint()) {
        if (!validEndpoint(input.destination.endpoint)) return error.InvalidEndpoint;
        if (std.mem.startsWith(u8, input.destination.endpoint, "http://") and provider != .minio) return error.InvalidEndpoint;
    } else if (input.destination.endpoint.len > 0 and !validEndpoint(input.destination.endpoint)) {
        return error.InvalidEndpoint;
    }
    if (input.destination.region.len > 0 and !validRegion(input.destination.region)) return error.InvalidRegion;
    if (provider.needsRegion() and input.destination.region.len == 0) return error.InvalidRegion;
    if (input.destination.storage_class.len > 64 or hasControlChars(input.destination.storage_class) or !provider.supportsStorageClass(input.destination.storage_class)) return error.InvalidStorageClass;
    if (input.destination.credential_mode == .aws_runtime and provider != .aws) return error.IamRequiresAws;

    if (Transfer.fromJsonName(input.transfer) == null) return error.InvalidTransfer;

    const mode = input.schedule.mode;
    if (!std.mem.eql(u8, mode, "manual") and !std.mem.eql(u8, mode, "interval") and !std.mem.eql(u8, mode, "custom")) return error.InvalidSchedule;
    if (std.mem.eql(u8, mode, "interval")) {
        if (!std.mem.eql(u8, input.schedule.unit, "hours") and !std.mem.eql(u8, input.schedule.unit, "days")) return error.InvalidSchedule;
        if (input.schedule.every == 0 or input.schedule.anchor_epoch_sec <= 0) return error.InvalidSchedule;
        // Bounds per NEXT-SPEC §Exact bounds.
        if (std.mem.eql(u8, input.schedule.unit, "hours") and input.schedule.every > 168) return error.InvalidSchedule;
        if (std.mem.eql(u8, input.schedule.unit, "days") and input.schedule.every > 365) return error.InvalidSchedule;
    }
    if (std.mem.eql(u8, mode, "custom")) {
        if (!validCronExpr(input.schedule.expr)) return error.InvalidCronExpr;
    }
    if (std.mem.eql(u8, mode, "manual") and input.schedule.enabled) return error.InvalidSchedule;
}

// --- cron expression grammar ----------------------------------------------

/// Validates cronie's five-field grammar (numeric, wildcards, steps,
/// ranges, lists). Names (JAN, SUN) are not accepted — the supported
/// grammar is the documented subset (spec 10 §13). Tabs are accepted as
/// field separators like spaces (cronie behaviour); `%` is rejected because
/// cron treats it as newline.
pub fn validCronExpr(expr: []const u8) bool {
    if (expr.len == 0 or expr.len > max_cron_expr_len) return false;
    if (std.mem.indexOfScalar(u8, expr, '%') != null) return false;
    if (std.mem.indexOfScalar(u8, expr, '\n') != null or std.mem.indexOfScalar(u8, expr, '\r') != null) return false;
    if (std.mem.indexOfScalar(u8, expr, 0) != null) return false;
    var fields: [5][]const u8 = undefined;
    var n: usize = 0;
    var i: usize = 0;
    while (i < expr.len) {
        while (i < expr.len and (expr[i] == ' ' or expr[i] == '\t')) : (i += 1) {}
        if (i >= expr.len) break;
        const start = i;
        while (i < expr.len and expr[i] != ' ' and expr[i] != '\t') : (i += 1) {}
        const f = expr[start..i];
        if (f.len == 0) return false;
        if (n >= fields.len) return false;
        fields[n] = f;
        n += 1;
    }
    if (n != 5) return false;
    const bounds = [_][2]u32{ .{ 0, 59 }, .{ 0, 23 }, .{ 1, 31 }, .{ 1, 12 }, .{ 0, 7 } };
    for (fields, 0..) |field, idx| {
        if (!validCronField(field, bounds[idx][0], bounds[idx][1])) return false;
    }
    return true;
}

fn validCronField(field: []const u8, min: u32, max: u32) bool {
    // Lists of range-or-number elements.
    var lists = std.mem.splitScalar(u8, field, ',');
    while (lists.next()) |element| {
        if (!validCronElement(element, min, max)) return false;
    }
    return true;
}

fn validCronElement(element: []const u8, min: u32, max: u32) bool {
    if (element.len == 0) return false;
    if (std.mem.indexOfScalar(u8, element, '%') != null) return false;
    if (std.mem.indexOfScalar(u8, element, '\t') != null) return false;
    if (std.mem.eql(u8, element, "*")) return true;
    // Step forms contain '/', handle them before bare '-' so "1-5/2" works.
    if (std.mem.indexOfScalar(u8, element, '/') != null) {
        var parts = std.mem.splitScalar(u8, element, '/');
        const range = parts.next() orelse return false;
        const step_str = parts.next() orelse return false;
        if (parts.next() != null) return false;
        if (range.len == 0 or step_str.len == 0) return false;
        const step = std.fmt.parseInt(u32, step_str, 10) catch return false;
        if (step == 0) return false;
        if (std.mem.eql(u8, range, "*")) return true;
        if (std.mem.indexOfScalar(u8, range, '-') != null) {
            var rp = std.mem.splitScalar(u8, range, '-');
            const a_str = rp.next() orelse return false;
            const b_str = rp.next() orelse return false;
            if (rp.next() != null) return false;
            const a = std.fmt.parseInt(u32, a_str, 10) catch return false;
            const b = std.fmt.parseInt(u32, b_str, 10) catch return false;
            if (a < min or b > max or a > b) return false;
            return true;
        }
        const v = std.fmt.parseInt(u32, range, 10) catch return false;
        return v >= min and v <= max;
    }
    // Bare range a-b
    if (std.mem.indexOfScalar(u8, element, '-') != null) {
        var parts = std.mem.splitScalar(u8, element, '-');
        const a_str = parts.next() orelse return false;
        const b_str = parts.next() orelse return false;
        if (parts.next() != null) return false;
        const a = std.fmt.parseInt(u32, a_str, 10) catch return false;
        const b = std.fmt.parseInt(u32, b_str, 10) catch return false;
        if (a < min or b > max or a > b) return false;
        return true;
    }
    // Wildcard step "*/n" without the '/' path above (kept for clarity)
    if (std.mem.startsWith(u8, element, "*/")) {
        const step = std.fmt.parseInt(u32, element[2..], 10) catch return false;
        return step > 0;
    }
    const value = std.fmt.parseInt(u32, element, 10) catch return false;
    return value >= min and value <= max;
}

/// Interval schedules as five-field expressions (v1 shim).
/// The guide notes that `*/N` in hours operates within the calendar field
/// (e.g. `*/23` is 0 and 23, not every 23h) and `*/N` in month-day resets
/// each month — neither is a truthful elapsed-interval. The next spec
/// replaces this with a once-per-minute wrapper gated on `next_due_epoch`.
/// For now, cap to truthful bounds and reject out-of-range values rather
/// than silently clamping to a different interval.
pub fn intervalToCronExpr(allocator: std.mem.Allocator, unit: []const u8, every: u32) ![]u8 {
    if (std.mem.eql(u8, unit, "days")) {
        if (every == 0 or every > 365) return error.InvalidSchedule;
        if (every > 31) return error.InvalidSchedule; // field-step cannot represent >31 truthfully
        return std.fmt.allocPrint(allocator, "0 0 */{d} * *", .{every});
    }
    if (std.mem.eql(u8, unit, "hours")) {
        if (every == 0 or every > 168) return error.InvalidSchedule;
        if (every > 23) return error.InvalidSchedule;
        return std.fmt.allocPrint(allocator, "0 */{d} * * *", .{every});
    }
    return error.InvalidSchedule;
}

/// `%` is newline to cron — escape it in generated commands.
pub fn escapePercent(allocator: std.mem.Allocator, command: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (command) |ch| {
        if (ch == '%') {
            try out.appendSlice(allocator, "\\%");
        } else {
            try out.append(allocator, ch);
        }
    }
    return out.toOwnedSlice(allocator);
}

/// The marker comment for a job's crontab lines.
pub fn crontabMarker(allocator: std.mem.Allocator, job_id: []const u8) ![]u8 {
    if (!validMarkerId(job_id)) return error.InvalidId;
    return std.fmt.allocPrint(allocator, "# oars:job:{s}", .{job_id});
}

const CronBlock = struct {
    job_id: []const u8,
    marker_start: usize,
    command_end: usize,
};

fn validMarkerId(id: []const u8) bool {
    if (id.len == 0 or id.len > max_id_len) return false;
    for (id) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_' and ch != '.') return false;
    }
    return true;
}

fn lineEnd(existing: []const u8, start: usize) usize {
    const relative = std.mem.indexOfScalar(u8, existing[start..], '\n') orelse return existing.len;
    return start + relative;
}

fn lineAfter(existing: []const u8, end: usize) usize {
    return if (end < existing.len) end + 1 else end;
}

fn markerId(line: []const u8) !?[]const u8 {
    const prefix = "# oars:job:";
    const marker_like = std.mem.indexOf(u8, line, "oars:job") != null or std.mem.startsWith(u8, line, "# oars:");
    if (!std.mem.startsWith(u8, line, prefix)) {
        if (marker_like) return error.MalformedMarker;
        return null;
    }
    const id = line[prefix.len..];
    if (!validMarkerId(id)) return error.MalformedMarker;
    return id;
}

fn validOarsCronCommand(line: []const u8, job_id: []const u8) bool {
    if (line.len == 0 or hasControlChars(line)) return false;
    var fields: [5][]const u8 = undefined;
    var cursor: usize = 0;
    for (&fields) |*field| {
        while (cursor < line.len and (line[cursor] == ' ' or line[cursor] == '\t')) : (cursor += 1) {}
        const start = cursor;
        while (cursor < line.len and line[cursor] != ' ' and line[cursor] != '\t') : (cursor += 1) {}
        if (start == cursor) return false;
        field.* = line[start..cursor];
    }
    const bounds = [_][2]u32{ .{ 0, 59 }, .{ 0, 23 }, .{ 1, 31 }, .{ 1, 12 }, .{ 0, 7 } };
    for (fields, 0..) |field, index| if (!validCronField(field, bounds[index][0], bounds[index][1])) return false;
    if (cursor >= line.len) return false;
    while (cursor < line.len and (line[cursor] == ' ' or line[cursor] == '\t')) : (cursor += 1) {}
    const command = line[cursor..];
    const shell_prefix = "/bin/sh ";
    if (!std.mem.startsWith(u8, command, shell_prefix)) return false;
    const wrapper_word = command[shell_prefix.len..];
    if (wrapper_word.len == 0) return false;
    var needle_buf: [max_id_len + 48]u8 = undefined;
    const needle = std.fmt.bufPrint(&needle_buf, "/.local/state/oars/backups/{s}/run.sh", .{job_id}) catch return false;
    if (!std.mem.endsWith(u8, wrapper_word, needle) and
        !(wrapper_word[wrapper_word.len - 1] == '\'' and wrapper_word.len > needle.len and std.mem.eql(u8, wrapper_word[wrapper_word.len - needle.len - 1 .. wrapper_word.len - 1], needle))) return false;
    // The generated invocation contains exactly one shell word after /bin/sh.
    // Accept the shellquote module's single-quoted/spliced form, but no flags,
    // redirections, or additional arguments around the wrapper path.
    if (wrapper_word[0] == '\'') {
        if (wrapper_word[wrapper_word.len - 1] != '\'') return false;
        var index: usize = 1;
        while (index + 1 < wrapper_word.len) {
            if (wrapper_word[index] == '\'') {
                if (index + 3 >= wrapper_word.len or !std.mem.eql(u8, wrapper_word[index .. index + 4], "'\\''")) return false;
                index += 4;
                continue;
            }
            index += 1;
        }
        return true;
    }
    if (wrapper_word[0] != '/' and !std.mem.startsWith(u8, wrapper_word, "~/")) return false;
    return std.mem.indexOfAny(u8, wrapper_word, " \t'\"\\;&|<>()$`") == null;
}

fn parseCronBlocks(allocator: std.mem.Allocator, existing: []const u8) ![]CronBlock {
    var blocks: std.ArrayList(CronBlock) = .empty;
    errdefer blocks.deinit(allocator);
    var cursor: usize = 0;
    while (cursor < existing.len) {
        const marker_end = lineEnd(existing, cursor);
        const line = existing[cursor..marker_end];
        const id = (try markerId(line)) orelse {
            cursor = lineAfter(existing, marker_end);
            continue;
        };
        for (blocks.items) |block| if (std.mem.eql(u8, block.job_id, id)) return error.DuplicateMarker;
        const command_start = lineAfter(existing, marker_end);
        if (command_start >= existing.len) return error.OrphanMarker;
        const command_end_no_newline = lineEnd(existing, command_start);
        const command_line = existing[command_start..command_end_no_newline];
        if ((try markerId(command_line)) != null) return error.AdjacentMarkers;
        if (!validOarsCronCommand(command_line, id)) return error.OrphanMarker;
        try blocks.append(allocator, .{
            .job_id = id,
            .marker_start = cursor,
            .command_end = lineAfter(existing, command_end_no_newline),
        });
        cursor = lineAfter(existing, command_end_no_newline);
    }
    return blocks.toOwnedSlice(allocator);
}

fn ensureFinalNewline(allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
    if (out.items.len > 0 and out.items[out.items.len - 1] != '\n') try out.append(allocator, '\n');
}

/// Adds or replaces exactly one validated Oars marker block. Every unrelated
/// byte is copied from the original table without line-ending normalization.
pub fn crontabAdd(allocator: std.mem.Allocator, existing: []const u8, job_id: []const u8, line: []const u8) !struct { content: []u8, changed: bool } {
    if (!validMarkerId(job_id) or !validOarsCronCommand(line, job_id)) return error.InvalidCronBlock;
    const blocks = try parseCronBlocks(allocator, existing);
    defer allocator.free(blocks);
    const marker = try crontabMarker(allocator, job_id);
    defer allocator.free(marker);
    var selected: ?CronBlock = null;
    for (blocks) |block| {
        if (std.mem.eql(u8, block.job_id, job_id)) selected = block;
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    if (selected) |block| {
        try out.appendSlice(allocator, existing[0..block.marker_start]);
        try out.appendSlice(allocator, marker);
        try out.append(allocator, '\n');
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
        try out.appendSlice(allocator, existing[block.command_end..]);
    } else {
        try out.appendSlice(allocator, existing);
        try ensureFinalNewline(allocator, &out);
        try out.appendSlice(allocator, marker);
        try out.append(allocator, '\n');
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
    }
    try ensureFinalNewline(allocator, &out);
    const content = try out.toOwnedSlice(allocator);
    return .{ .content = content, .changed = !std.mem.eql(u8, content, existing) };
}

/// Removes exactly one validated Oars marker block without consuming an
/// unrelated line after a malformed/orphan marker.
pub fn crontabRemove(allocator: std.mem.Allocator, existing: []const u8, job_id: []const u8) !struct { content: []u8, changed: bool } {
    if (!validMarkerId(job_id)) return error.InvalidId;
    const blocks = try parseCronBlocks(allocator, existing);
    defer allocator.free(blocks);
    var selected: ?CronBlock = null;
    for (blocks) |block| {
        if (std.mem.eql(u8, block.job_id, job_id)) selected = block;
    }
    const block = selected orelse return .{ .content = try allocator.dupe(u8, existing), .changed = false };
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, existing[0..block.marker_start]);
    try out.appendSlice(allocator, existing[block.command_end..]);
    try ensureFinalNewline(allocator, &out);
    return .{ .content = try out.toOwnedSlice(allocator), .changed = true };
}

// --- rclone config generation ---------------------------------------------

/// The dedicated remote name for a job.
pub fn remoteName(allocator: std.mem.Allocator, job_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "oars-{s}", .{job_id});
}

/// Builds the `[remote]` section for the s3 backend. In AWS runtime/IAM
/// mode the config must be `env_auth = true` with blank key fields so
/// rclone falls back to its env/role chain (omitting keys is not enough).
/// Values are written verbatim; secrets never appear in argv.
/// An empty/default storage_class is omitted — only adapter allow-listed
/// values are emitted.
// INI injection: access/secret keys must be validated (no CR/LF/NUL)
// before calling this; bridge admission rejects them.
pub fn remoteConfigSection(
    allocator: std.mem.Allocator,
    job: *const Job,
    remote: []const u8,
    access_key: ?[]const u8,
    secret_key: ?[]const u8,
) ![]u8 {
    const provider = Provider.fromJsonName(job.destination.provider) orelse return error.InvalidProvider;
    if (!validMarkerId(remote) or hasControlChars(remote)) return error.InvalidProvider;
    if (job.destination.endpoint.len > 0 and !validEndpoint(job.destination.endpoint)) return error.InvalidEndpoint;
    if (job.destination.region.len > 0 and !validRegion(job.destination.region)) return error.InvalidRegion;
    if (hasControlChars(job.destination.storage_class) or !provider.supportsStorageClass(job.destination.storage_class)) return error.InvalidStorageClass;
    var out: std.ArrayList(u8) = .empty;
    errdefer {
        std.crypto.secureZero(u8, out.items);
        out.deinit(allocator);
    }
    {
        const part = try std.fmt.allocPrint(allocator, "[{s}]\ntype = s3\nprovider = {s}\n", .{ remote, provider.rcloneName() });
        defer allocator.free(part);
        try out.appendSlice(allocator, part);
    }
    if (job.destination.credential_mode == .aws_runtime) {
        if (provider != .aws or access_key != null or secret_key != null) return error.InvalidCredentials;
        try out.appendSlice(allocator, "env_auth = true\n");
    } else {
        const ak = access_key orelse return error.InvalidCredentials;
        const sk = secret_key orelse return error.InvalidCredentials;
        if (!validCredentials(ak) or !validCredentials(sk)) return error.InvalidCredentials;
        const part = try std.fmt.allocPrint(allocator, "access_key_id = {s}\nsecret_access_key = {s}\n", .{ ak, sk });
        defer secureFree(allocator, part);
        try out.appendSlice(allocator, part);
    }
    const is_r2 = provider == .r2;
    if (job.destination.endpoint.len > 0) {
        const part = try std.fmt.allocPrint(allocator, "endpoint = {s}\n", .{job.destination.endpoint});
        defer allocator.free(part);
        try out.appendSlice(allocator, part);
    } else if (is_r2) {
        return error.InvalidEndpoint; // R2 requires endpoint
    }
    if (is_r2) {
        try out.appendSlice(allocator, "region = auto\n");
    } else if (job.destination.region.len > 0) {
        const part = try std.fmt.allocPrint(allocator, "region = {s}\n", .{job.destination.region});
        defer allocator.free(part);
        try out.appendSlice(allocator, part);
    }
    // Only emit storage_class for providers with an explicit allow-list
    // beyond the default; empty/default means provider default.
    if (job.destination.storage_class.len > 0 and !std.mem.eql(u8, job.destination.storage_class, "standard")) {
        if (!provider.supportsStorageClass(job.destination.storage_class)) return error.InvalidStorageClass;
        var sc_buf: [64]u8 = undefined;
        if (job.destination.storage_class.len > sc_buf.len) return error.InvalidStorageClass;
        const sc = std.ascii.upperString(sc_buf[0..job.destination.storage_class.len], job.destination.storage_class);
        const part = try std.fmt.allocPrint(allocator, "storage_class = {s}\n", .{sc});
        defer allocator.free(part);
        try out.appendSlice(allocator, part);
    }
    return out.toOwnedSlice(allocator);
}

/// Merges a section into an existing config: replaces a section with the
/// same name (header and body), otherwise appends. Other sections are
/// never touched.
pub fn configMergeSection(
    allocator: std.mem.Allocator,
    existing: []const u8,
    section_name: []const u8,
    section_content: []const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator); // safe after toOwnedSlice (list empties)
    var replaced = false;
    var in_replaced = false;
    var lines = std.mem.splitScalar(u8, existing, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, "\r");
        if (std.mem.startsWith(u8, trimmed, "[") and std.mem.endsWith(u8, trimmed, "]")) {
            const name = std.mem.trim(u8, trimmed[1 .. trimmed.len - 1], " \t");
            if (std.mem.eql(u8, name, section_name)) {
                if (replaced) continue; // drop any duplicate section
                try out.appendSlice(allocator, section_content);
                if (section_content.len > 0 and section_content[section_content.len - 1] != '\n') try out.append(allocator, '\n');
                replaced = true;
                in_replaced = true;
                continue;
            }
            in_replaced = false;
        }
        if (in_replaced) continue; // the old section's body is replaced
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
    }
    if (!replaced) {
        try out.appendSlice(allocator, section_content);
        if (section_content.len > 0 and section_content[section_content.len - 1] != '\n') try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

pub fn configRemoveSection(allocator: std.mem.Allocator, existing: []const u8, section_name: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var skipping = false;
    var lines = std.mem.splitScalar(u8, existing, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, "\r");
        if (std.mem.startsWith(u8, trimmed, "[") and std.mem.endsWith(u8, trimmed, "]")) {
            const name = std.mem.trim(u8, trimmed[1 .. trimmed.len - 1], " \t");
            skipping = std.mem.eql(u8, name, section_name);
            if (skipping) continue;
        }
        if (skipping) continue;
        if (line.len == 0 and lines.peek() == null) continue;
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

/// The rclone destination `remote:bucket[/prefix]` (shell-quoted later).
pub fn destinationArg(allocator: std.mem.Allocator, job: *const Job, remote: []const u8) ![]u8 {
    if (job.destination.prefix.len == 0) {
        return std.fmt.allocPrint(allocator, "{s}:{s}", .{ remote, job.destination.bucket });
    }
    return std.fmt.allocPrint(allocator, "{s}:{s}/{s}", .{ remote, job.destination.bucket, job.destination.prefix });
}

// --- scheduled-run wrapper -------------------------------------------------

/// Versioned wrapper for scheduled runs (spec 10 §9).
/// Increment when the wrapper shape changes; import rejects wrong versions.
pub const wrapper_version: u32 = 3;

/// The wrapper cron executes: one run log + one machine-readable status
/// file per run under the job's state dir, with a per-job lock so a job
/// cannot overlap itself (spec 10 §9). Numeric versioned status, atomic
/// publish (tmp+rename after log closed), interval gating via next_due,
/// bounded retention, no secrets.
pub fn wrapperScript(
    allocator: std.mem.Allocator,
    job_id: []const u8,
    rclone_invocation: []const u8,
) ![]u8 {
    // Legacy shape for compat with existing unit tests; new jobs use
    // wrapperScriptV2 which takes rclone path and schedule metadata.
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const header = try std.fmt.allocPrint(allocator,
        \\#!/bin/sh
        \\# oars:job:{s}
        \\# version={d}
        \\# Generated by Oars (spec 10 v2). Do not edit; re-saving the job rewrites this.
        \\STATE_DIR={s}/{s}
        \\mkdir -p "$STATE_DIR" 2>/dev/null || exit 1
        \\TS=$(date +%s)
        \\LOG="$STATE_DIR/$TS.log"
        \\STATUS="$STATE_DIR/$TS.status"
        \\TMP_STATUS="$STATUS.tmp"
        \\START=$(date +%s)
        \\(\n
        \\  flock -n 9 || {{ TS2=$(date +%s); printf '\\{{\"v\":{d},\"job_id\":\"{s}\",\"run_id\":\"skipped-%s\",\"ts\":%s,\"exit\":0,\"status\":\"skipped_overlap\",\"started_at\":%s,\"finished_at\":%s\\}}\n' "$TS2" "$TS2" "$TS2" > "$TMP_STATUS" 2>/dev/null && mv "$TMP_STATUS" "$STATUS" 2>/dev/null; exit 0; }}
        \\  {s} > "$LOG" 2>&1
        \\  EXIT=$?
        \\  END=$(date +%s)
        \\  ST="success"; if [ "$EXIT" -ne 0 ]; then ST="failed"; fi
        \\  printf '\\{{\"v\":{d},\"job_id\":\"{s}\",\"run_id\":\"sched-%s-%s\",\"ts\":%s,\"exit\":%s,\"status\":\"%s\",\"started_at\":%s,\"finished_at\":%s\\}}\n' "$TS" "$EXIT" "$ST" "$START" "$END" > "$TMP_STATUS" 2>/dev/null
        \\  mv "$TMP_STATUS" "$STATUS" 2>/dev/null || true
        \\  n=$(ls -1 "$STATE_DIR"/*.status 2>/dev/null | wc -l); if [ "$n" -gt 20 ]; then ls -1t "$STATE_DIR"/*.status 2>/dev/null | tail -n +21 | xargs -r rm -f 2>/dev/null; ls -1t "$STATE_DIR"/*.log 2>/dev/null | tail -n +21 | xargs -r rm -f 2>/dev/null; fi
        \\) 9>"/tmp/oars-backup-{s}.lock"
        \\exit 0
        \\
    , .{ job_id, wrapper_version, state_dir, job_id, wrapper_version, job_id, rclone_invocation, wrapper_version, job_id, job_id });
    try out.appendSlice(allocator, header);
    return out.toOwnedSlice(allocator);
}

pub fn scheduledWrapper(
    allocator: std.mem.Allocator,
    job: *const Job,
    basis: ScheduleBasis,
    config_path: []const u8,
    job_dir: []const u8,
) ![]u8 {
    const remote_name = try remoteName(allocator, job.id);
    defer allocator.free(remote_name);
    const destination = try destinationArg(allocator, job, remote_name);
    defer allocator.free(destination);
    const runs_dir = try std.fmt.allocPrint(allocator, "{s}/runs", .{job_dir});
    defer allocator.free(runs_dir);
    const lock_dir = try std.fmt.allocPrint(allocator, "{s}/.lock", .{job_dir});
    defer allocator.free(lock_dir);
    const due_path = try std.fmt.allocPrint(allocator, "{s}/next_due", .{job_dir});
    defer allocator.free(due_path);
    const quoted_rclone = try shellquote.quote(allocator, basis.rclone_path);
    defer allocator.free(quoted_rclone);
    const quoted_source = try shellquote.quote(allocator, job.source_path);
    defer allocator.free(quoted_source);
    const quoted_destination = try shellquote.quote(allocator, destination);
    defer allocator.free(quoted_destination);
    const quoted_config = try shellquote.quote(allocator, config_path);
    defer allocator.free(quoted_config);
    const quoted_runs = try shellquote.quote(allocator, runs_dir);
    defer allocator.free(quoted_runs);
    const quoted_lock = try shellquote.quote(allocator, lock_dir);
    defer allocator.free(quoted_lock);
    const quoted_due = try shellquote.quote(allocator, due_path);
    defer allocator.free(quoted_due);
    const interval_seconds: i64 = if (std.mem.eql(u8, job.schedule.mode, "interval"))
        @as(i64, job.schedule.every) * if (std.mem.eql(u8, job.schedule.unit, "days")) @as(i64, 86_400) else @as(i64, 3_600)
    else
        0;
    const initial_due = if (job.schedule.anchor_epoch_sec > 0) job.schedule.anchor_epoch_sec else 0;

    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try out.writer.print(
        \\#!/bin/sh
        \\# oars:job:{s}
        \\# version={d}
        \\set -u
        \\umask 077
        \\RUNS={s}
        \\LOCK={s}
        \\DUE={s}
        \\mkdir -p "$RUNS" || exit 1
        \\NOW=$(date +%s)
        \\RID="sched-$NOW-$$"
        \\LOG="$RUNS/$RID.log"
        \\STATUS="$RUNS/$RID.status"
        \\TMP="$STATUS.tmp-$$"
        \\publish() {{
        \\  CODE="$1"; STATE="$2"; START="$3"; END="$4"
        \\  printf '{{"v":{d},"server_id":"{s}","job_id":"{s}","job_revision":{d},"run_id":"%s","started_at":%s,"finished_at":%s,"exit":%s,"status":"%s","cleanup_state":"complete"}}\n' "$RID" "$START" "$END" "$CODE" "$STATE" > "$TMP" || return 1
        \\  sync "$TMP" 2>/dev/null || sync
        \\  mv "$TMP" "$STATUS"
        \\}}
        \\if ! mkdir "$LOCK" 2>/dev/null; then
        \\  START="$NOW"; RID="overlap-$NOW-$$"; STATUS="$RUNS/$RID.status"; TMP="$STATUS.tmp-$$"
        \\  : > "$RUNS/$RID.log" || exit 1
        \\  publish 0 skipped_overlap "$START" "$NOW"
        \\  exit 0
        \\fi
        \\trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT HUP INT TERM
        \\INTERVAL={d}
        \\INITIAL_DUE={d}
        \\if [ "$INTERVAL" -gt 0 ]; then
        \\  NEXT="$INITIAL_DUE"
        \\  if [ -r "$DUE" ]; then IFS= read -r NEXT < "$DUE" || NEXT="$INITIAL_DUE"; fi
        \\  case "$NEXT" in ''|*[!0-9]*) NEXT="$INITIAL_DUE" ;; esac
        \\  if [ "$NEXT" -gt 0 ] && [ "$NOW" -lt "$NEXT" ]; then exit 0; fi
        \\fi
        \\advance_due() {{
        \\  AFTER="$1"
        \\  if [ "$INTERVAL" -gt 0 ]; then
        \\    while [ "$NEXT" -le "$AFTER" ]; do NEXT="$((NEXT + INTERVAL))"; done
        \\    printf '%s\n' "$NEXT" > "$DUE.tmp-$$" && mv "$DUE.tmp-$$" "$DUE"
        \\  fi
        \\}}
        \\START="$NOW"
        \\if [ ! -e {s} ]; then END=$(date +%s); : > "$LOG"; publish 2 source_missing "$START" "$END"; advance_due "$END"; exit 0; fi
        \\if [ ! -r {s} ]; then END=$(date +%s); : > "$LOG"; publish 3 source_unreadable "$START" "$END"; advance_due "$END"; exit 0; fi
        \\{s} {s} {s} {s} --config {s} --use-json-log --stats 1s --stats-log-level NOTICE --ask-password=false > "$LOG" 2>&1
        \\RC=$?
        \\END=$(date +%s)
        \\STATE=success
        \\if [ "$RC" -ne 0 ]; then STATE=failed; fi
        \\publish "$RC" "$STATE" "$START" "$END"
        \\advance_due "$END"
        \\set -- "$RUNS"/*.status
        \\while [ "$#" -gt 20 ]; do OLD="$1"; shift; BASE="${{OLD%.status}}"; rm -f "$OLD" "$BASE.log"; done
        \\if [ -f "$LOG" ]; then SIZE=$(wc -c < "$LOG" 2>/dev/null || printf 0); if [ "$SIZE" -gt 1048576 ]; then tail -c 1048576 "$LOG" > "$LOG.tmp-$$" && mv "$LOG.tmp-$$" "$LOG"; fi; fi
        \\exit 0
        \\
    , .{
        job.id,
        wrapper_version,
        quoted_runs,
        quoted_lock,
        quoted_due,
        wrapper_version,
        job.server_id,
        job.id,
        job.revision,
        interval_seconds,
        initial_due,
        quoted_source,
        quoted_source,
        quoted_rclone,
        job.transfer.jsonName(),
        quoted_source,
        quoted_destination,
        quoted_config,
    });
    return out.toOwnedSlice();
}

// --- JSON-log stats parsing ------------------------------------------------

pub const Stats = struct {
    bytes_done: u64 = 0,
    bytes_total: u64 = 0,
    files_done: u64 = 0,
    files_total: u64 = 0,
    speed_bps: u64 = 0,
    eta_sec: i64 = 0,
};

pub const LogLine = union(enum) {
    stats: Stats,
    @"error": []const u8,
    other,
};

const RawLine = struct {
    level: ?[]const u8 = null,
    msg: ?[]const u8 = null,
    bytes: ?u64 = null,
    eta: ?f64 = null,
    speed: ?f64 = null,
    totalBytes: ?u64 = null,
    totalTransfers: ?u64 = null,
    transfers: ?u64 = null,
    stats: ?struct {
        bytes: ?u64 = null,
        totalBytes: ?u64 = null,
        transfers: ?u64 = null,
        totalTransfers: ?u64 = null,
        speed: ?f64 = null,
        eta: ?f64 = null,
    } = null,
};

/// Parses one `--use-json-log` line. Stats records carry their fields
/// top-level on modern rclone and inside a `stats` object on older ones
/// (spec 10 §13) — both are accepted. `level == "error"` lines are
/// surfaced for the run error. Returned error messages view `line` (no
/// allocations); the caller copies what it keeps.
pub fn parseJsonLogLine(allocator: std.mem.Allocator, line: []const u8) LogLine {
    var parsed = std.json.parseFromSlice(RawLine, allocator, line, .{
        .ignore_unknown_fields = true,
        // alloc_never: strings view `line` and stay valid while it does.
    }) catch return .other;
    defer parsed.deinit();
    const raw = parsed.value;
    if (raw.level) |level| {
        if (std.mem.eql(u8, level, "error")) {
            return .{ .@"error" = raw.msg orelse "rclone error" };
        }
    }
    var stats: ?Stats = null;
    if (raw.stats) |s| {
        stats = .{
            .bytes_done = s.bytes orelse 0,
            .bytes_total = s.totalBytes orelse 0,
            .files_done = s.transfers orelse 0,
            .files_total = s.totalTransfers orelse 0,
            .speed_bps = @intFromFloat(s.speed orelse 0),
            .eta_sec = @intFromFloat(s.eta orelse 0),
        };
    } else if (raw.bytes != null or raw.transfers != null or raw.totalTransfers != null or raw.speed != null) {
        stats = .{
            .bytes_done = raw.bytes orelse 0,
            .bytes_total = raw.totalBytes orelse 0,
            .files_done = raw.transfers orelse 0,
            .files_total = raw.totalTransfers orelse 0,
            .speed_bps = @intFromFloat(raw.speed orelse 0),
            .eta_sec = @intFromFloat(raw.eta orelse 0),
        };
    }
    if (stats) |s| return .{ .stats = s };
    return .other;
}

pub const StatsResult = struct {
    stats: Stats = .{},
    /// Views `log` (never allocated) — valid while the log is alive.
    @"error": []const u8 = "",
};

/// Scans a run log and returns the last stats record and the last error
/// message. Both view the input; the caller copies what it keeps.
pub fn lastStatsFromLog(allocator: std.mem.Allocator, log: []const u8) StatsResult {
    var result: StatsResult = .{};
    var lines = std.mem.splitScalar(u8, log, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        switch (parseJsonLogLine(allocator, trimmed)) {
            .stats => |s| result.stats = s,
            .@"error" => |msg| result.@"error" = msg,
            .other => {},
        }
    }
    return result;
}

// --- run records -----------------------------------------------------------

pub const RunStatus = enum(u8) {
    queued,
    preparing,
    running,
    cancel_requested,
    success,
    failed,
    no_changes,
    canceled,
    interrupted,
    partial,
    skipped_overlap,

    pub fn jsonName(self: RunStatus) []const u8 {
        return @tagName(self);
    }

    pub fn terminal(self: RunStatus) bool {
        return switch (self) {
            .success, .failed, .no_changes, .canceled, .interrupted, .partial, .skipped_overlap => true,
            .queued, .preparing, .running, .cancel_requested => false,
        };
    }
};

/// A completed or in-flight run (manual or imported-scheduled).
pub const RunRecord = struct {
    id: []const u8,
    job_id: []const u8,
    server_id: []const u8,
    operation_id: []const u8 = "",
    source: []const u8 = "manual", // manual | scheduled
    status: RunStatus = .running,
    started_at_ns: i64 = 0,
    finished_at_ns: i64 = 0,
    bytes_done: u64 = 0,
    bytes_total: u64 = 0,
    files_done: u64 = 0,
    files_total: u64 = 0,
    /// Optional so a fresh record (Runs.start) has no dangling empty
    /// literal to free; only ever set to an owned dupe.
    @"error": ?[]const u8 = null,
    error_code: ?FailureCode = null,
    error_retryable: bool = false,
    log: ?[]const u8 = null,

    pub fn deinit(self: *RunRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.job_id);
        allocator.free(self.server_id);
        if (self.operation_id.len > 0) allocator.free(self.operation_id);
        allocator.free(self.source);
        if (self.@"error") |e| allocator.free(e);
        if (self.log) |l| allocator.free(l);
    }

    /// Trims the log to the history cap (bounded history, spec 10 §7).
    pub fn trimLog(self: *RunRecord, allocator: std.mem.Allocator, log: []const u8) !void {
        if (self.log) |l| allocator.free(l);
        if (log.len <= history_log_cap) {
            self.log = try allocator.dupe(u8, log);
            return;
        }
        self.log = try allocator.dupe(u8, log[log.len - history_log_cap ..]);
    }
};

fn readStoreContent(io: std.Io, path: []const u8, allocator: std.mem.Allocator, limit: usize) !?[]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(limit)) catch |err| {
        if (err == error.FileNotFound) return null;
        return classifyStoreAccessError(err);
    };
}

fn syncStoreParent(io: std.Io, path: []const u8) !void {
    const parent_path = std.fs.path.dirname(path) orelse ".";
    var parent_file = std.Io.Dir.cwd().openFile(io, parent_path, .{
        .mode = .read_only,
        .allow_directory = true,
    }) catch |err| return classifyStoreAccessError(err);
    defer parent_file.close(io);
    parent_file.sync(io) catch |err| return classifyStoreAccessError(err);
}

fn writeStoreAtomically(allocator: std.mem.Allocator, io: std.Io, path: []const u8, bytes: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |dir| cwd.createDirPath(io, dir) catch |err| return classifyStoreAccessError(err);
    var nonce: [12]u8 = undefined;
    std.Io.randomSecure(io, &nonce) catch |err| return classifyStoreAccessError(err);
    const nonce_hex = std.fmt.bytesToHex(nonce, .lower);
    const tmp = std.fmt.allocPrint(allocator, "{s}.tmp-{s}", .{ path, nonce_hex }) catch return error.OutOfMemory;
    defer allocator.free(tmp);
    var renamed = false;
    defer if (!renamed) cwd.deleteFile(io, tmp) catch {};
    {
        var file = cwd.createFile(io, tmp, .{ .exclusive = true, .permissions = .fromMode(0o600) }) catch |err| return classifyStoreAccessError(err);
        defer file.close(io);
        file.writeStreamingAll(io, bytes) catch |err| return classifyStoreAccessError(err);
        file.sync(io) catch |err| return classifyStoreAccessError(err);
    }
    std.Io.Dir.renameAbsolute(tmp, path, io) catch |err| return classifyStoreAccessError(err);
    renamed = true;
    // Verify and durably persist the owner-only mode as well as the rename.
    var file = cwd.openFile(io, path, .{ .mode = .read_write }) catch |err| return classifyStoreAccessError(err);
    defer file.close(io);
    const stat = file.stat(io) catch |err| return classifyStoreAccessError(err);
    if (stat.permissions.toMode() & 0o077 != 0) file.setPermissions(io, .fromMode(0o600)) catch |err| return classifyStoreAccessError(err);
    file.sync(io) catch |err| return classifyStoreAccessError(err);
    try syncStoreParent(io, path);
}

fn quarantineStore(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var nonce: [8]u8 = undefined;
    std.Io.randomSecure(io, &nonce) catch return error.StoreQuarantineFailed;
    const nonce_hex = std.fmt.bytesToHex(nonce, .lower);
    const dir = std.fs.path.dirname(path) orelse ".";
    const base = std.fs.path.basename(path);
    const new_path = std.fmt.allocPrint(allocator, "{s}/{s}.corrupt-{d}-{s}", .{ dir, base, now, nonce_hex }) catch return error.OutOfMemory;
    errdefer allocator.free(new_path);
    std.Io.Dir.renameAbsolute(path, new_path, io) catch return error.StoreQuarantineFailed;
    syncStoreParent(io, path) catch return error.StoreQuarantineFailed;
    return new_path;
}

const HistoryDocument = struct {
    version: u32,
    runs: []RunRecord,
};

pub const HistoryStore = struct {
    allocator: std.mem.Allocator = undefined,
    path: []const u8 = "",
    mutex: std.atomic.Mutex = .unlocked,
    recovery_error: ?[]u8 = null,

    pub const Loaded = struct {
        parsed: std.json.Parsed(HistoryDocument),
        content: ?[]u8,
        quarantined: ?[]const u8 = null,
        recovery_error: ?[]const u8 = null,
        recovered: bool = false,

        pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
            self.parsed.deinit();
            if (self.content) |c| allocator.free(c);
            if (self.quarantined) |q| allocator.free(q);
            if (self.recovery_error) |message| allocator.free(message);
        }
    };

    pub const ListResult = struct {
        runs: []RunRecord,
        recovery_error: ?[]const u8 = null,

        pub fn deinit(self: *ListResult, allocator: std.mem.Allocator) void {
            for (self.runs) |*run| run.deinit(allocator);
            allocator.free(self.runs);
            if (self.recovery_error) |message| allocator.free(message);
        }
    };

    pub fn loadParsed(self: *HistoryStore, io: std.Io) !Loaded {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.loadParsedLocked(io);
    }

    fn loadParsedLocked(self: *HistoryStore, io: std.Io) !Loaded {
        const content = (try readStoreContent(io, self.path, self.allocator, 32 * 1024 * 1024)) orelse return self.missingLoaded();
        const parsed = std.json.parseFromSlice(HistoryDocument, self.allocator, content, .{}) catch |err| {
            if (err == error.OutOfMemory) {
                self.allocator.free(content);
                return error.OutOfMemory;
            }
            const migrated = self.migrateBareLocked(io, content) catch |migration_err| {
                self.allocator.free(content);
                if (migration_err == error.OutOfMemory) return error.OutOfMemory;
                return self.recoveredEmpty(io);
            };
            return .{ .parsed = migrated, .content = content };
        };
        if (!validHistoryDocument(parsed.value)) {
            parsed.deinit();
            self.allocator.free(content);
            return self.recoveredEmpty(io);
        }
        return .{ .parsed = parsed, .content = content };
    }

    fn migrateBareLocked(self: *HistoryStore, io: std.Io, content: []const u8) !std.json.Parsed(HistoryDocument) {
        var bare = try std.json.parseFromSlice([]RunRecord, self.allocator, content, .{});
        defer bare.deinit();
        const document = HistoryDocument{ .version = backup_store_version, .runs = bare.value };
        if (!validHistoryDocument(document)) return error.InvalidStoreDocument;
        try self.saveLocked(io, bare.value);
        var encoded: std.Io.Writer.Allocating = .init(self.allocator);
        defer encoded.deinit();
        try std.json.Stringify.value(document, .{}, &encoded.writer);
        return std.json.parseFromSlice(HistoryDocument, self.allocator, encoded.writer.buffered(), .{ .allocate = .alloc_always });
    }

    fn validHistoryDocument(document: HistoryDocument) bool {
        if (document.version != backup_store_version or document.runs.len > max_runs) return false;
        for (document.runs, 0..) |run, index| {
            if (!validId(run.id) or !validId(run.job_id) or !validId(run.server_id)) return false;
            if (run.operation_id.len > 0 and !validId(run.operation_id)) return false;
            if (!std.mem.eql(u8, run.source, "manual") and !std.mem.eql(u8, run.source, "scheduled")) return false;
            if (!run.status.terminal()) return false;
            if (run.started_at_ns < 0 or run.finished_at_ns < 0) return false;
            if (run.finished_at_ns != 0 and run.finished_at_ns < run.started_at_ns) return false;
            if (run.@"error") |message| if (message.len > max_history_error_len or hasControlChars(message)) return false;
            if (run.log) |log| if (log.len > history_log_cap) return false;
            for (document.runs[0..index]) |previous| if (std.mem.eql(u8, previous.id, run.id)) return false;
        }
        return true;
    }

    fn emptyLoaded(allocator: std.mem.Allocator) !Loaded {
        return .{
            .parsed = try std.json.parseFromSlice(HistoryDocument, allocator, "{\"version\":1,\"runs\":[]}", .{}),
            .content = null,
        };
    }

    fn missingLoaded(self: *HistoryStore) !Loaded {
        var loaded = try emptyLoaded(self.allocator);
        errdefer loaded.deinit(self.allocator);
        if (self.recovery_error) |message| loaded.recovery_error = try self.allocator.dupe(u8, message);
        return loaded;
    }

    fn recoveredEmpty(self: *HistoryStore, io: std.Io) !Loaded {
        const quarantined = try self.quarantine(io);
        errdefer self.allocator.free(quarantined);
        const remembered = try self.allocator.dupe(u8, quarantined);
        if (self.recovery_error) |old| self.allocator.free(old);
        self.recovery_error = remembered;
        var loaded = try emptyLoaded(self.allocator);
        errdefer loaded.deinit(self.allocator);
        loaded.quarantined = quarantined;
        loaded.recovery_error = try self.allocator.dupe(u8, quarantined);
        loaded.recovered = true;
        return loaded;
    }

    fn quarantine(self: *HistoryStore, io: std.Io) ![]u8 {
        return quarantineStore(self.allocator, io, self.path);
    }

    pub fn recoveryErrorSnapshot(self: *HistoryStore) !?[]u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return if (self.recovery_error) |message| try self.allocator.dupe(u8, message) else null;
    }

    pub fn deinitRecovery(self: *HistoryStore) void {
        if (self.recovery_error) |message| self.allocator.free(message);
        self.recovery_error = null;
    }

    fn saveLocked(self: *HistoryStore, io: std.Io, runs: []const RunRecord) !void {
        if (!validHistoryDocument(.{ .version = backup_store_version, .runs = @constCast(runs) })) return error.SerializeFailed;
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        const document = HistoryDocument{ .version = backup_store_version, .runs = @constCast(runs) };
        std.json.Stringify.value(document, .{ .whitespace = .indent_2 }, &out.writer) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.SerializeFailed;
        try writeStoreAtomically(self.allocator, io, self.path, out.writer.buffered());
        if (self.recovery_error) |message| self.allocator.free(message);
        self.recovery_error = null;
    }

    /// Appends a completed run; prunes records older than the retention
    /// window and caps the store (spec 10 §7). Idempotent by run id.
    pub fn append(self: *HistoryStore, io: std.Io, run: *const RunRecord, now_ns: i64) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch |err| return err;
        defer loaded.deinit(self.allocator);
        if (loaded.recovered) return error.StoreCorrupt;
        var list: std.ArrayList(RunRecord) = .empty;
        defer {
            for (list.items) |*r| r.deinit(self.allocator);
            list.deinit(self.allocator);
        }
        var replaced = false;
        for (loaded.parsed.value.runs) |existing| {
            if (std.mem.eql(u8, existing.id, run.id)) {
                if (!std.mem.eql(u8, existing.server_id, run.server_id) or !std.mem.eql(u8, existing.job_id, run.job_id)) return error.RunIdConflict;
                try list.append(self.allocator, try cloneRun(self.allocator, run.*));
                replaced = true;
                continue;
            }
            if (existing.started_at_ns < now_ns - history_retention_days * 86_400_000_000_000) continue;
            try list.append(self.allocator, try cloneRun(self.allocator, existing));
        }
        if (!replaced) try list.append(self.allocator, try cloneRun(self.allocator, run.*));
        while (list.items.len > max_runs) {
            var oldest: usize = 0;
            for (list.items, 0..) |*r, i| {
                if (r.started_at_ns < list.items[oldest].started_at_ns) oldest = i;
            }
            var removed = list.orderedRemove(oldest);
            removed.deinit(self.allocator);
        }
        try self.saveLocked(io, list.items);
    }

    /// Newest-first owned copies for one job, capped by `limit`.
    pub fn listForJobWithRecovery(self: *HistoryStore, io: std.Io, job_id: []const u8, limit: usize) !ListResult {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = try self.loadParsedLocked(io);
        defer loaded.deinit(self.allocator);
        var out: std.ArrayList(RunRecord) = .empty;
        errdefer {
            for (out.items) |*run| run.deinit(self.allocator);
            out.deinit(self.allocator);
        }
        var i = loaded.parsed.value.runs.len;
        while (i > 0) {
            i -= 1;
            const existing = loaded.parsed.value.runs[i];
            if (!std.mem.eql(u8, existing.job_id, job_id)) continue;
            if (out.items.len >= limit) break;
            try out.append(self.allocator, try cloneRun(self.allocator, existing));
        }
        const recovery = if (loaded.recovery_error) |message| try self.allocator.dupe(u8, message) else null;
        return .{ .runs = try out.toOwnedSlice(self.allocator), .recovery_error = recovery };
    }

    pub fn listForJob(self: *HistoryStore, io: std.Io, job_id: []const u8, limit: usize) ![]RunRecord {
        var result = try self.listForJobWithRecovery(io, job_id, limit);
        if (result.recovery_error != null) {
            result.deinit(self.allocator);
            return error.StoreCorrupt;
        }
        const runs = result.runs;
        result.runs = &.{};
        return runs;
    }

    pub fn findRun(self: *HistoryStore, io: std.Io, run_id: []const u8) !?RunRecord {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = try self.loadParsedLocked(io);
        defer loaded.deinit(self.allocator);
        if (loaded.recovered) return error.StoreCorrupt;
        for (loaded.parsed.value.runs) |run| {
            if (std.mem.eql(u8, run.id, run_id)) return try cloneRun(self.allocator, run);
        }
        return null;
    }

    pub fn findRunByOperation(self: *HistoryStore, io: std.Io, operation_id: []const u8) !?RunRecord {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = try self.loadParsedLocked(io);
        defer loaded.deinit(self.allocator);
        if (loaded.recovered) return error.StoreCorrupt;
        for (loaded.parsed.value.runs) |run| {
            if (run.operation_id.len > 0 and std.mem.eql(u8, run.operation_id, operation_id)) return try cloneRun(self.allocator, run);
        }
        return null;
    }

    fn cloneRun(allocator: std.mem.Allocator, run: RunRecord) !RunRecord {
        return .{
            .id = try allocator.dupe(u8, run.id),
            .job_id = try allocator.dupe(u8, run.job_id),
            .server_id = try allocator.dupe(u8, run.server_id),
            .operation_id = try dupOrLiteral(allocator, run.operation_id),
            .source = try allocator.dupe(u8, run.source),
            .status = run.status,
            .started_at_ns = run.started_at_ns,
            .finished_at_ns = run.finished_at_ns,
            .bytes_done = run.bytes_done,
            .bytes_total = run.bytes_total,
            .files_done = run.files_done,
            .files_total = run.files_total,
            .@"error" = if (run.@"error") |e| try allocator.dupe(u8, e) else null,
            .error_code = run.error_code,
            .error_retryable = run.error_retryable,
            .log = if (run.log) |l| try allocator.dupe(u8, l) else null,
        };
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// --- job store -------------------------------------------------------------

const JobDocument = struct {
    version: u32,
    jobs: []Job,
};

pub const JobStore = struct {
    const LegacyDestination = struct {
        type: []const u8 = "s3",
        provider: []const u8 = "aws",
        bucket: []const u8 = "",
        prefix: []const u8 = "",
        endpoint: []const u8 = "",
        region: []const u8 = "",
        use_iam: bool = false,
        storage_class: []const u8 = "standard",
    };

    const LegacySchedule = struct {
        mode: []const u8 = "manual",
        interval_unit: []const u8 = "hours",
        interval_every: u32 = 24,
        expr: []const u8 = "",
        enabled: bool = false,
    };

    const LegacyJob = struct {
        id: []const u8,
        server_id: []const u8,
        name: []const u8,
        source_path: []const u8,
        destination: LegacyDestination,
        transfer: Transfer = .copy,
        schedule: LegacySchedule = .{},
        revision: u64 = 1,
        created_at_ns: i64 = 0,
        updated_at_ns: i64 = 0,
    };

    allocator: std.mem.Allocator = undefined,
    path: []const u8 = "",
    /// Monotonic id generator for new jobs (in-memory only).
    next_id: u32 = 1,
    mutex: std.atomic.Mutex = .unlocked,
    recovery_error: ?[]u8 = null,

    pub const Loaded = struct {
        parsed: std.json.Parsed(JobDocument),
        content: ?[]u8,
        quarantined: ?[]const u8 = null,
        recovery_error: ?[]const u8 = null,
        recovered: bool = false,

        pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
            self.parsed.deinit();
            if (self.content) |c| allocator.free(c);
            if (self.quarantined) |q| allocator.free(q);
            if (self.recovery_error) |message| allocator.free(message);
        }
    };

    pub const ListResult = struct {
        jobs: []Job,
        recovery_error: ?[]const u8 = null,

        pub fn deinit(self: *ListResult, allocator: std.mem.Allocator) void {
            for (self.jobs) |*job| job.deinit(allocator);
            allocator.free(self.jobs);
            if (self.recovery_error) |message| allocator.free(message);
        }
    };

    pub fn loadParsed(self: *JobStore, io: std.Io) !Loaded {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.loadParsedLocked(io);
    }

    fn loadParsedLocked(self: *JobStore, io: std.Io) !Loaded {
        const content = (try readStoreContent(io, self.path, self.allocator, 16 * 1024 * 1024)) orelse return self.missingLoaded();
        const parsed = std.json.parseFromSlice(JobDocument, self.allocator, content, .{}) catch |parse_err| {
            if (parse_err == error.OutOfMemory) {
                self.allocator.free(content);
                return error.OutOfMemory;
            }
            const migrated = self.migrateBareOrLegacyLocked(io, content) catch |migration_err| {
                self.allocator.free(content);
                return switch (migration_err) {
                    error.OutOfMemory,
                    error.StorePermissionDenied,
                    error.StoreTimeout,
                    error.StoreTooLarge,
                    error.StoreIo,
                    error.SerializeFailed,
                    => migration_err,
                    else => self.recoveredEmpty(io),
                };
            };
            return .{ .parsed = migrated, .content = content };
        };
        if (!validJobDocument(parsed.value)) {
            parsed.deinit();
            self.allocator.free(content);
            return self.recoveredEmpty(io);
        }
        return .{ .parsed = parsed, .content = content };
    }

    fn migrateBareOrLegacyLocked(self: *JobStore, io: std.Io, content: []const u8) !std.json.Parsed(JobDocument) {
        var current = std.json.parseFromSlice([]Job, self.allocator, content, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.migrateLegacyLocked(io, content),
        };
        defer current.deinit();
        const document = JobDocument{ .version = backup_store_version, .jobs = current.value };
        if (!validJobDocument(document)) return error.InvalidStoreDocument;
        try self.saveLocked(io, current.value);
        return self.ownedDocument(document);
    }

    fn migrateLegacyLocked(self: *JobStore, io: std.Io, content: []const u8) !std.json.Parsed(JobDocument) {
        var legacy = try std.json.parseFromSlice([]LegacyJob, self.allocator, content, .{});
        defer legacy.deinit();
        var jobs: std.ArrayList(Job) = .empty;
        defer jobs.deinit(self.allocator);
        for (legacy.value) |old| {
            if (!std.mem.eql(u8, old.destination.type, "s3")) return error.InvalidDestination;
            const provider = if (std.mem.eql(u8, old.destination.provider, "b2")) "b2_s3" else old.destination.provider;
            try jobs.append(self.allocator, .{
                .id = old.id,
                .server_id = old.server_id,
                .name = old.name,
                .source_path = old.source_path,
                .destination = .{
                    .provider = provider,
                    .bucket = old.destination.bucket,
                    .prefix = old.destination.prefix,
                    .endpoint = old.destination.endpoint,
                    .region = old.destination.region,
                    .credential_mode = if (old.destination.use_iam) .aws_runtime else .access_key,
                    .storage_class = if (std.mem.eql(u8, old.destination.storage_class, "standard")) "" else old.destination.storage_class,
                },
                .transfer = old.transfer,
                .schedule = .{
                    .mode = old.schedule.mode,
                    .enabled = old.schedule.enabled,
                    .every = old.schedule.interval_every,
                    .unit = old.schedule.interval_unit,
                    // Legacy interval schedules did not persist an anchor.
                    // Use the earliest valid epoch second so the migrated
                    // cadence stays deterministic instead of depending on
                    // the migration time.
                    .anchor_epoch_sec = if (old.created_at_ns >= 1_000_000_000) @divTrunc(old.created_at_ns, 1_000_000_000) else 1,
                    .expr = old.schedule.expr,
                },
                .revision = old.revision,
                .created_at_ns = old.created_at_ns,
                .updated_at_ns = old.updated_at_ns,
            });
        }
        var encoded: std.Io.Writer.Allocating = .init(self.allocator);
        defer encoded.deinit();
        const document = JobDocument{ .version = backup_store_version, .jobs = jobs.items };
        if (!validJobDocument(document)) return error.InvalidStoreDocument;
        try std.json.Stringify.value(document, .{}, &encoded.writer);
        var parsed = try std.json.parseFromSlice(JobDocument, self.allocator, encoded.writer.buffered(), .{ .allocate = .alloc_always });
        errdefer parsed.deinit();
        try self.saveLocked(io, parsed.value.jobs);
        return parsed;
    }

    fn ownedDocument(self: *JobStore, document: JobDocument) !std.json.Parsed(JobDocument) {
        var encoded: std.Io.Writer.Allocating = .init(self.allocator);
        defer encoded.deinit();
        try std.json.Stringify.value(document, .{}, &encoded.writer);
        return std.json.parseFromSlice(JobDocument, self.allocator, encoded.writer.buffered(), .{ .allocate = .alloc_always });
    }

    fn validJobDocument(document: JobDocument) bool {
        if (document.version != backup_store_version or document.jobs.len > max_job_store_records) return false;
        for (document.jobs, 0..) |job, index| {
            validate(.{
                .id = job.id,
                .server_id = job.server_id,
                .name = job.name,
                .source_path = job.source_path,
                .destination = job.destination,
                .transfer = job.transfer.jsonName(),
                .schedule = job.schedule,
            }) catch return false;
            if (job.revision == 0 or job.created_at_ns < 0 or job.updated_at_ns < job.created_at_ns) return false;
            var server_count: usize = 1;
            for (document.jobs[0..index]) |previous| {
                if (std.mem.eql(u8, previous.id, job.id)) return false;
                if (std.mem.eql(u8, previous.server_id, job.server_id)) server_count += 1;
            }
            if (server_count > max_jobs_per_server) return false;
        }
        return true;
    }

    fn emptyLoaded(allocator: std.mem.Allocator) !Loaded {
        return .{
            .parsed = try std.json.parseFromSlice(JobDocument, allocator, "{\"version\":1,\"jobs\":[]}", .{}),
            .content = null,
        };
    }

    fn missingLoaded(self: *JobStore) !Loaded {
        var loaded = try emptyLoaded(self.allocator);
        errdefer loaded.deinit(self.allocator);
        if (self.recovery_error) |message| loaded.recovery_error = try self.allocator.dupe(u8, message);
        return loaded;
    }

    fn recoveredEmpty(self: *JobStore, io: std.Io) !Loaded {
        const quarantined = try self.quarantine(io);
        errdefer self.allocator.free(quarantined);
        const remembered = try self.allocator.dupe(u8, quarantined);
        if (self.recovery_error) |old| self.allocator.free(old);
        self.recovery_error = remembered;
        var loaded = try emptyLoaded(self.allocator);
        errdefer loaded.deinit(self.allocator);
        loaded.quarantined = quarantined;
        loaded.recovery_error = try self.allocator.dupe(u8, quarantined);
        loaded.recovered = true;
        return loaded;
    }

    fn quarantine(self: *JobStore, io: std.Io) ![]u8 {
        return quarantineStore(self.allocator, io, self.path);
    }

    pub fn recoveryErrorSnapshot(self: *JobStore) !?[]u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return if (self.recovery_error) |message| try self.allocator.dupe(u8, message) else null;
    }

    pub fn deinitRecovery(self: *JobStore) void {
        if (self.recovery_error) |message| self.allocator.free(message);
        self.recovery_error = null;
    }

    fn saveLocked(self: *JobStore, io: std.Io, jobs: []const Job) !void {
        if (!validJobDocument(.{ .version = backup_store_version, .jobs = @constCast(jobs) })) return error.SerializeFailed;
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        const document = JobDocument{ .version = backup_store_version, .jobs = @constCast(jobs) };
        std.json.Stringify.value(document, .{ .whitespace = .indent_2 }, &out.writer) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.SerializeFailed;
        try writeStoreAtomically(self.allocator, io, self.path, out.writer.buffered());
        if (self.recovery_error) |message| self.allocator.free(message);
        self.recovery_error = null;
    }

    pub fn save(self: *JobStore, io: std.Io, input: JobInput, expected_revision: ?u64, now_ns: i64) SaveError!Job {
        return self.savePlanned(io, input, expected_revision, false, now_ns);
    }

    /// Upserts a job (secrets never persisted). `allow_planned_create_id` is
    /// used only by the coordinator after a create plan has frozen a random,
    /// collision-checked ID.
    pub fn savePlanned(self: *JobStore, io: std.Io, input: JobInput, expected_revision: ?u64, allow_planned_create_id: bool, now_ns: i64) SaveError!Job {
        try validate(input);
        if (input.id) |jid| if (!validId(jid)) return error.InvalidId;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        if (loaded.recovered) return error.StoreCorrupt;

        var id_owned: ?[]u8 = null;
        defer if (id_owned) |i| self.allocator.free(i);
        var id: []const u8 = undefined;
        if (input.id) |i| {
            id = i;
        } else {
            // Random ID; verify collision against persisted jobs.
            var attempts: usize = 0;
            var found_unique = false;
            while (attempts < 8) : (attempts += 1) {
                const cand = randomJobId(self.allocator, io) catch return error.OutOfMemory;
                var dup = false;
                for (loaded.parsed.value.jobs) |j| if (std.mem.eql(u8, j.id, cand)) {
                    dup = true;
                    break;
                };
                if (!dup) {
                    id_owned = cand;
                    found_unique = true;
                    break;
                }
                self.allocator.free(cand);
            }
            if (!found_unique) return error.SerializeFailed;
            id = id_owned.?;
        }
        var is_edit = false;
        var existing_job: ?Job = null;
        if (input.id != null) {
            for (loaded.parsed.value.jobs) |j| {
                if (std.mem.eql(u8, j.id, id)) {
                    is_edit = true;
                    existing_job = j;
                    break;
                }
            }
            if (is_edit and allow_planned_create_id and expected_revision == null) return error.RevConflict;
            if (!is_edit) {
                if (!allow_planned_create_id) return error.UnknownId;
            } else {
                // Immutable server_id and optimistic concurrency.
                if (!std.mem.eql(u8, existing_job.?.server_id, input.server_id)) return error.ImmutableServerId;
                if (expected_revision) |exp| {
                    if (existing_job.?.revision != exp) return error.RevConflict;
                }
            }
        }
        // Per-server cap (only for new jobs).
        if (!is_edit) {
            var count: usize = 0;
            for (loaded.parsed.value.jobs) |j| {
                if (std.mem.eql(u8, j.server_id, input.server_id)) count += 1;
            }
            if (count >= max_jobs_per_server) return error.TooManyJobs;
        }

        var created_at: i64 = now_ns;
        var new_revision: u64 = 1;
        if (is_edit) {
            created_at = existing_job.?.created_at_ns;
            new_revision = existing_job.?.revision + 1;
        }
        const transfer = Transfer.fromJsonName(input.transfer) orelse return error.InvalidTransfer;
        const id_copy = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(id_copy);
        const server_copy = try self.allocator.dupe(u8, input.server_id);
        errdefer self.allocator.free(server_copy);
        const name_copy = try self.allocator.dupe(u8, std.mem.trim(u8, input.name, " \t\r\n"));
        errdefer self.allocator.free(name_copy);
        const source_copy = try self.allocator.dupe(u8, std.mem.trim(u8, input.source_path, " \t\r\n"));
        errdefer self.allocator.free(source_copy);
        var saved = Job{
            .id = id_copy,
            .server_id = server_copy,
            .name = name_copy,
            .source_path = source_copy,
            .destination = try dupDestination(self.allocator, input.destination),
            .transfer = transfer,
            .schedule = try dupSchedule(self.allocator, input.schedule),
            .revision = new_revision,
            .created_at_ns = created_at,
            .updated_at_ns = now_ns,
        };
        errdefer saved.deinit(self.allocator);

        var list: std.ArrayList(Job) = .empty;
        defer {
            for (list.items) |*j| j.deinit(self.allocator);
            list.deinit(self.allocator);
        }
        for (loaded.parsed.value.jobs) |j| {
            if (is_edit and std.mem.eql(u8, j.id, id)) continue;
            try list.append(self.allocator, try cloneJob(self.allocator, j));
        }
        try list.append(self.allocator, try cloneJob(self.allocator, saved));
        self.saveLocked(io, list.items) catch return error.SerializeFailed;
        return saved;
    }

    /// Owned copies of every job on a server.
    pub fn listForServerWithRecovery(self: *JobStore, io: std.Io, server_id: []const u8) !ListResult {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = try self.loadParsedLocked(io);
        defer loaded.deinit(self.allocator);
        var out: std.ArrayList(Job) = .empty;
        errdefer {
            for (out.items) |*job| job.deinit(self.allocator);
            out.deinit(self.allocator);
        }
        for (loaded.parsed.value.jobs) |job| {
            if (std.mem.eql(u8, job.server_id, server_id)) try out.append(self.allocator, try cloneJob(self.allocator, job));
        }
        std.mem.sort(Job, out.items, {}, struct {
            fn lessThan(_: void, a: Job, b: Job) bool {
                if (a.updated_at_ns != b.updated_at_ns) return a.updated_at_ns < b.updated_at_ns;
                return std.mem.order(u8, a.id, b.id) == .lt;
            }
        }.lessThan);
        const recovery = if (loaded.recovery_error) |message| try self.allocator.dupe(u8, message) else null;
        return .{ .jobs = try out.toOwnedSlice(self.allocator), .recovery_error = recovery };
    }

    pub fn listForServer(self: *JobStore, io: std.Io, server_id: []const u8) ![]Job {
        var result = try self.listForServerWithRecovery(io, server_id);
        if (result.recovery_error != null) {
            result.deinit(self.allocator);
            return error.StoreCorrupt;
        }
        return result.jobs;
    }

    /// Owned copy of one job, or null.
    pub fn find(self: *JobStore, io: std.Io, job_id: []const u8) !?Job {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        if (loaded.recovered) return error.StoreCorrupt;
        for (loaded.parsed.value.jobs) |j| {
            if (std.mem.eql(u8, j.id, job_id)) return try cloneJob(self.allocator, j);
        }
        return null;
    }

    pub fn delete(self: *JobStore, io: std.Io, job_id: []const u8) SaveError!bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        if (loaded.recovered) return error.StoreCorrupt;
        var found = false;
        var list: std.ArrayList(Job) = .empty;
        defer {
            for (list.items) |*j| j.deinit(self.allocator);
            list.deinit(self.allocator);
        }
        for (loaded.parsed.value.jobs) |j| {
            if (std.mem.eql(u8, j.id, job_id)) {
                found = true;
                continue;
            }
            try list.append(self.allocator, try cloneJob(self.allocator, j));
        }
        if (found) self.saveLocked(io, list.items) catch return error.SerializeFailed;
        return found;
    }

    fn dupDestination(allocator: std.mem.Allocator, d: Destination) !Destination {
        return .{
            .type = try dupOrLiteral(allocator, d.type),
            .provider = try dupOrLiteral(allocator, d.provider),
            .bucket = try dupOrLiteral(allocator, d.bucket),
            .prefix = try dupOrLiteral(allocator, d.prefix),
            .endpoint = try dupOrLiteral(allocator, d.endpoint),
            .region = try dupOrLiteral(allocator, d.region),
            .credential_mode = d.credential_mode,
            .storage_class = try dupOrLiteral(allocator, d.storage_class),
        };
    }

    fn dupSchedule(allocator: std.mem.Allocator, s: Schedule) !Schedule {
        return .{
            .mode = try dupOrLiteral(allocator, s.mode),
            .enabled = s.enabled,
            .every = s.every,
            .unit = try dupOrLiteral(allocator, s.unit),
            .anchor_epoch_sec = s.anchor_epoch_sec,
            .expr = try dupOrLiteral(allocator, s.expr),
        };
    }

    fn cloneJob(allocator: std.mem.Allocator, job: Job) !Job {
        return .{
            .id = try dupOrLiteral(allocator, job.id),
            .server_id = try dupOrLiteral(allocator, job.server_id),
            .revision = job.revision,
            .name = try dupOrLiteral(allocator, job.name),
            .source_path = try dupOrLiteral(allocator, job.source_path),
            .destination = try dupDestination(allocator, job.destination),
            .transfer = job.transfer,
            .schedule = try dupSchedule(allocator, job.schedule),
            .created_at_ns = job.created_at_ns,
            .updated_at_ns = job.updated_at_ns,
        };
    }
};

// --- live runs -------------------------------------------------------------

/// An in-flight or recently finished run (handler-owned registry). The
/// record doubles as the poll response source once the channel ends.
pub const LiveRun = struct {
    record: RunRecord,
    operation_id: []const u8 = "",
    phase: []const u8 = "queued",
    cleanup_state: []const u8 = "pending",
    speed_bps: u64 = 0,
    eta_sec: i64 = 0,
    finalized: bool = false,
    outcome_status: RunStatus = .failed,
    cancel_requested: bool = false,
    cancel_verified: bool = false,
    cleanup_retry: bool = false,
    job: ?Job = null,
    credentials: ?OwnedCredentials = null,
    process: ?*sessions.BackupProcess = null,
    process_cursor: u64 = 0,
    log_start: u64 = 0,
    live_log: std.ArrayList(u8) = .empty,
    pgid: []const u8 = "",
    temp_config: []const u8 = "",
    state_dir_path: []const u8 = "",
    failure: ?BackupFailure = null,
    admission_reported: bool = false,
    terminal_reported: bool = false,
    plan_hash: [64]u8 = [_]u8{'0'} ** 64,
    audit_attempt: u32 = 1,

    pub fn deinit(self: *LiveRun, allocator: std.mem.Allocator) void {
        self.record.deinit(allocator);
        if (self.operation_id.len > 0) allocator.free(self.operation_id);
        if (self.phase.len > 0) allocator.free(self.phase);
        if (self.cleanup_state.len > 0) allocator.free(self.cleanup_state);
        if (self.job) |*job| job.deinit(allocator);
        if (self.credentials) |*credentials| credentials.deinit(allocator);
        if (self.process) |process| {
            if (process.abandon()) {
                process.data.deinit(allocator);
                allocator.destroy(process);
            }
        }
        self.live_log.deinit(allocator);
        if (self.pgid.len > 0) allocator.free(self.pgid);
        if (self.temp_config.len > 0) allocator.free(self.temp_config);
        if (self.state_dir_path.len > 0) allocator.free(self.state_dir_path);
        if (self.failure) |*failure| failure.deinit(allocator);
    }
};

pub const Runs = struct {
    allocator: std.mem.Allocator = undefined,
    mutex: std.atomic.Mutex = .unlocked,
    list: std.ArrayList(*LiveRun) = .empty,
    const max_completed: usize = 16;

    pub fn lock(self: *Runs) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    pub fn unlock(self: *Runs) void {
        self.mutex.unlock();
    }

    pub fn deinit(self: *Runs) void {
        for (self.list.items) |r| {
            r.deinit(self.allocator);
            self.allocator.destroy(r);
        }
        self.list.deinit(self.allocator);
    }

    pub fn byId(self: *Runs, id: []const u8) ?*LiveRun {
        for (self.list.items) |r| {
            if (std.mem.eql(u8, r.record.id, id)) return r;
        }
        return null;
    }

    /// A running manual run on the server blocks another one (spec 10 §9).
    pub fn runningForServer(self: *Runs, server_id: []const u8) ?*LiveRun {
        for (self.list.items) |r| {
            if (r.finalized) continue;
            if (!r.record.status.terminal() and std.mem.eql(u8, r.record.server_id, server_id)) return r;
        }
        return null;
    }

    pub fn startEx(self: *Runs, run_id: []const u8, job_id: []const u8, server_id: []const u8, source: []const u8, now_ns: i64) !*LiveRun {
        const run = try self.allocator.create(LiveRun);
        errdefer self.allocator.destroy(run);
        const id = run_id;
        run.* = .{
            .record = .{
                .id = try self.allocator.dupe(u8, id),
                .job_id = try self.allocator.dupe(u8, job_id),
                .server_id = try self.allocator.dupe(u8, server_id),
                .source = try self.allocator.dupe(u8, source),
                .status = .running,
                .started_at_ns = now_ns,
            },
            .phase = try self.allocator.dupe(u8, "running"),
            .cleanup_state = try self.allocator.dupe(u8, "pending"),
        };
        errdefer run.deinit(self.allocator);
        try self.list.append(self.allocator, run);
        return run;
    }

    pub fn start(self: *Runs, job_id: []const u8, server_id: []const u8, source: []const u8, now_ns: i64) !*LiveRun {
        // Transitional shim: generate a temporary monotonic id. Prefer startEx.
        var buf: [64]u8 = undefined;
        const tmp = std.fmt.bufPrint(&buf, "run-{d}", .{self.list.items.len + 1}) catch "run-0";
        return self.startEx(tmp, job_id, server_id, source, now_ns);
    }

    /// Drops finished runs beyond the completed cap (oldest first).
    pub fn evictCompleted(self: *Runs) void {
        var completed: usize = 0;
        for (self.list.items) |r| {
            if (r.finalized and r.terminal_reported) completed += 1;
        }
        var i: usize = 0;
        while (completed > max_completed and i < self.list.items.len) {
            const r = self.list.items[i];
            if (r.finalized and r.terminal_reported) {
                _ = self.list.orderedRemove(i);
                r.deinit(self.allocator);
                self.allocator.destroy(r);
                completed -= 1;
                continue;
            }
            i += 1;
        }
    }
};

const coordinator_idle_ms: u64 = 10;
const coordinator_plan_ttl_ms: i64 = 5 * 60 * 1000;
const coordinator_op_ttl_ms: i64 = 30 * 60 * 1000;
pub const backup_max_ops: usize = 64;
pub const backup_max_plans: usize = 32;

pub const OperationState = enum {
    queued,
    running,
    done,
    partial,
    failed,
    canceled,

    pub fn jsonName(self: OperationState) []const u8 {
        return @tagName(self);
    }

    pub fn terminal(self: OperationState) bool {
        return switch (self) {
            .done, .partial, .failed, .canceled => true,
            .queued, .running => false,
        };
    }
};

pub const StepState = enum {
    pending,
    running,
    done,
    conflict,
    failed,
    cancel_requested,
    canceled,
    skipped,

    pub fn jsonName(self: StepState) []const u8 {
        return @tagName(self);
    }
};

pub const FailureCode = enum {
    invalid_payload,
    invalid_job,
    invalid_credentials,
    not_connected,
    session_not_ready,
    unsupported_target,
    rclone_missing,
    cron_missing,
    cron_stopped,
    source_missing,
    source_unreadable,
    source_too_large,
    plan_expired,
    conflict,
    busy,
    not_found,
    permission_denied,
    timeout,
    transport_error,
    capability_failed,
    cleanup_failed,
    store_corrupt,
    canceled,
    interrupted,
    internal,

    pub fn jsonName(self: FailureCode) []const u8 {
        return @tagName(self);
    }
};

pub const BackupFailure = struct {
    code: FailureCode,
    message: []const u8,
    retryable: bool = false,
    step: []const u8 = "",
    path: []const u8 = "",
    remote_object: []const u8 = "",

    pub fn init(allocator: std.mem.Allocator, code: FailureCode, message: []const u8, retryable: bool, step: []const u8) !BackupFailure {
        const message_copy = try dupOrLiteral(allocator, message);
        errdefer if (message_copy.len > 0) allocator.free(message_copy);
        return .{
            .code = code,
            .message = message_copy,
            .retryable = retryable,
            .step = try dupOrLiteral(allocator, step),
        };
    }

    pub fn clone(self: BackupFailure, allocator: std.mem.Allocator) !BackupFailure {
        var copy = BackupFailure{ .code = self.code, .message = "", .retryable = self.retryable };
        errdefer copy.deinit(allocator);
        copy.message = try dupOrLiteral(allocator, self.message);
        copy.step = try dupOrLiteral(allocator, self.step);
        copy.path = try dupOrLiteral(allocator, self.path);
        copy.remote_object = try dupOrLiteral(allocator, self.remote_object);
        return copy;
    }

    pub fn deinit(self: *BackupFailure, allocator: std.mem.Allocator) void {
        if (self.message.len > 0) allocator.free(self.message);
        if (self.step.len > 0) allocator.free(self.step);
        if (self.path.len > 0) allocator.free(self.path);
        if (self.remote_object.len > 0) allocator.free(self.remote_object);
    }
};

pub const OperationStep = struct {
    id: []const u8,
    state: StepState = .pending,
    failure: ?BackupFailure = null,

    pub fn clone(self: OperationStep, allocator: std.mem.Allocator) !OperationStep {
        const id = try allocator.dupe(u8, self.id);
        errdefer allocator.free(id);
        return .{
            .id = id,
            .state = self.state,
            .failure = if (self.failure) |failure| try failure.clone(allocator) else null,
        };
    }

    pub fn deinit(self: *OperationStep, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        if (self.failure) |*failure| failure.deinit(allocator);
    }
};

pub const OperationKind = enum {
    refresh,
    @"test",
    save,
    delete,
    install,
    cleanup,

    pub fn jsonName(self: OperationKind) []const u8 {
        return @tagName(self);
    }
};

pub const PlanKind = enum { save, delete, @"test", install };

pub const ScheduleBasis = struct {
    home: []const u8,
    rclone_path: []const u8,
    crontab_path: []const u8,
    timezone: []const u8,
    target: []const u8,
    privilege: []const u8,
    process_groups: bool,
    crontab: []const u8,
    crontab_sha256: [32]u8,
};

pub const SavePlanPayload = struct {
    job: JobInput,
    expected_revision: ?u64 = null,
    previous_job: ?Job = null,
    schedule_basis: ?ScheduleBasis = null,
    requires_capability_proof: bool = true,
};

pub const DeletePlanPayload = struct {
    server_id: []const u8,
    job_id: []const u8,
    expected_revision: u64,
    job_name: []const u8,
    schedule_basis: ?ScheduleBasis = null,
};

pub const InstallPlanPayload = struct {
    server_id: []const u8,
    what: []const u8,
    target: []const u8 = "unknown",
    command: []const u8 = "",
    manual: bool = true,
};

/// Narrow boundary from the backup coordinator into sessions.Manager. The
/// adapter only enqueues; all libssh2/SFTP work remains on the session worker.
pub const RemoteAdapter = struct {
    context: *anyopaque,
    submit_fn: *const fn (context: *anyopaque, server_id: []const u8, request: sessions.BackupRequest, outcome: *sessions.BackupOutcome) anyerror!void,
    submit_cleanup_fn: ?*const fn (context: *anyopaque, server_id: []const u8, request: sessions.BackupRequest, outcome: *sessions.BackupOutcome) anyerror!void = null,
    start_fn: *const fn (context: *anyopaque, server_id: []const u8, command: []const u8, stdin_data: ?[]const u8, process: *sessions.BackupProcess) anyerror!void,
    detach_fn: ?*const fn (context: *anyopaque, registry_context: *anyopaque) void = null,

    fn submit(self: RemoteAdapter, server_id: []const u8, request: sessions.BackupRequest, outcome: *sessions.BackupOutcome) !void {
        try self.submit_fn(self.context, server_id, request, outcome);
    }

    fn submitCleanup(self: RemoteAdapter, server_id: []const u8, request: sessions.BackupRequest, outcome: *sessions.BackupOutcome) !void {
        const callback = self.submit_cleanup_fn orelse self.submit_fn;
        try callback(self.context, server_id, request, outcome);
    }

    fn start(self: RemoteAdapter, server_id: []const u8, command: []const u8, stdin_data: ?[]const u8, process: *sessions.BackupProcess) !void {
        try self.start_fn(self.context, server_id, command, stdin_data, process);
    }
};

pub const CrontabReadState = enum {
    ok,
    missing,
    denied,
    failed,

    fn parse(value: []const u8) ?CrontabReadState {
        inline for (std.meta.tags(CrontabReadState)) |tag| {
            if (std.mem.eql(u8, value, @tagName(tag))) return tag;
        }
        return null;
    }
};

pub const RuntimeFacts = struct {
    observed_at_ms: i64 = 0,
    os: []const u8 = "",
    arch: []const u8 = "",
    user: []const u8 = "",
    home: []const u8 = "",
    timezone: []const u8 = "UTC",
    rclone_path: []const u8 = "",
    rclone_version: []const u8 = "",
    crontab_path: []const u8 = "",
    cron_running: bool = false,
    service_manager: []const u8 = "unknown",
    target: []const u8 = "unknown",
    privilege: []const u8 = "unknown",
    process_groups: bool = false,
    crontab_read: CrontabReadState = .failed,
    crontab: []const u8 = "",
    crontab_sha256: [32]u8 = [_]u8{0} ** 32,

    pub fn deinit(self: *RuntimeFacts, allocator: std.mem.Allocator) void {
        inline for (.{ "os", "arch", "user", "home", "timezone", "rclone_path", "rclone_version", "crontab_path", "service_manager", "target", "privilege", "crontab" }) |field| {
            const value = @field(self, field);
            if (value.len > 0) allocator.free(value);
        }
    }

    pub fn clone(self: RuntimeFacts, allocator: std.mem.Allocator) !RuntimeFacts {
        var copy = self;
        inline for (.{ "os", "arch", "user", "home", "timezone", "rclone_path", "rclone_version", "crontab_path", "service_manager", "target", "privilege", "crontab" }) |field| {
            @field(copy, field) = try dupOrLiteral(allocator, @field(self, field));
        }
        return copy;
    }
};

const runtime_probe_command =
    "printf '__OARS_FACTS_V1__\\n'; " ++
    "printf 'os='; uname -s 2>/dev/null || true; " ++
    "printf 'arch='; uname -m 2>/dev/null || true; " ++
    "printf 'user='; id -un 2>/dev/null || true; " ++
    "printf 'home=%s\\n' \"$HOME\"; " ++
    "printf 'timezone='; date +%Z 2>/dev/null || printf UTC; printf '\\n'; " ++
    "printf 'target='; if [ -r /etc/os-release ]; then ( . /etc/os-release; printf '%s' \"$ID\" ); else printf unknown; fi; printf '\\n'; " ++
    "printf 'privilege='; if [ \"$(id -u 2>/dev/null)\" = 0 ]; then printf root; elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then printf sudo; else printf none; fi; printf '\\n'; " ++
    "printf 'rclone_path='; command -v rclone 2>/dev/null || true; " ++
    "printf 'rclone_version='; rclone version 2>/dev/null | sed -n '1p'; " ++
    "printf 'crontab_path='; command -v crontab 2>/dev/null || true; " ++
    "printf 'cron_running='; if pgrep -x crond >/dev/null 2>&1 || pgrep -x cron >/dev/null 2>&1; then printf true; else printf false; fi; printf '\\n'; " ++
    "printf 'service_manager='; if command -v rc-service >/dev/null 2>&1; then printf openrc; elif command -v systemctl >/dev/null 2>&1; then printf systemd; elif command -v service >/dev/null 2>&1; then printf sysv; else printf none; fi; printf '\\n'; " ++
    "printf 'process_groups='; if command -v setsid >/dev/null 2>&1 && command -v kill >/dev/null 2>&1; then printf true; else printf false; fi; printf '\\n'; " ++
    "umask 077; CRON_OUT=\"${TMPDIR:-/tmp}/.oars-crontab-$$\"; CRON_ERR=\"${TMPDIR:-/tmp}/.oars-crontab-err-$$\"; " ++
    "if crontab -l >\"$CRON_OUT\" 2>\"$CRON_ERR\"; then CRON_READ=ok; " ++
    "elif grep -Eiq 'no crontab|does not exist' \"$CRON_ERR\"; then CRON_READ=missing; : >\"$CRON_OUT\"; " ++
    "elif grep -Eiq 'permission denied|access denied|not allowed|not permitted' \"$CRON_ERR\"; then CRON_READ=denied; : >\"$CRON_OUT\"; " ++
    "else CRON_READ=failed; : >\"$CRON_OUT\"; fi; " ++
    "printf 'crontab_read=%s\\n' \"$CRON_READ\"; printf '__OARS_CRONTAB_HEX_BEGIN__\\n'; od -An -v -tx1 <\"$CRON_OUT\"; printf '__OARS_CRONTAB_HEX_END__\\n'; rm -f \"$CRON_OUT\" \"$CRON_ERR\"";

fn lineValue(prefix: []const u8, input: []const u8) []const u8 {
    var lines = std.mem.splitScalar(u8, input, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, prefix)) return std.mem.trim(u8, line[prefix.len..], " \t\r");
    }
    return "";
}

fn decodeHexWhitespace(allocator: std.mem.Allocator, text: []const u8, max: usize) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var high: ?u8 = null;
    for (text) |ch| {
        if (std.ascii.isWhitespace(ch)) continue;
        const nibble = std.fmt.charToDigit(ch, 16) catch return error.InvalidHex;
        if (high) |h| {
            if (out.items.len >= max) return error.TooLarge;
            try out.append(allocator, (h << 4) | nibble);
            high = null;
        } else high = nibble;
    }
    if (high != null) return error.InvalidHex;
    return out.toOwnedSlice(allocator);
}

fn parseRuntimeFacts(allocator: std.mem.Allocator, output: []const u8, now_ms: i64) !RuntimeFacts {
    const begin_marker = "__OARS_CRONTAB_HEX_BEGIN__\n";
    const end_marker = "__OARS_CRONTAB_HEX_END__";
    const begin = std.mem.indexOf(u8, output, begin_marker) orelse return error.InvalidProbe;
    const hex_start = begin + begin_marker.len;
    const end_relative = std.mem.indexOf(u8, output[hex_start..], end_marker) orelse return error.InvalidProbe;
    const crontab = try decodeHexWhitespace(allocator, output[hex_start .. hex_start + end_relative], 256 * 1024);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(crontab, &digest, .{});
    var facts = RuntimeFacts{ .observed_at_ms = now_ms, .crontab = crontab, .crontab_sha256 = digest };
    errdefer facts.deinit(allocator);
    facts.os = try dupOrLiteral(allocator, lineValue("os=", output[0..begin]));
    facts.arch = try dupOrLiteral(allocator, lineValue("arch=", output[0..begin]));
    facts.user = try dupOrLiteral(allocator, lineValue("user=", output[0..begin]));
    facts.home = try dupOrLiteral(allocator, lineValue("home=", output[0..begin]));
    facts.timezone = try dupOrLiteral(allocator, lineValue("timezone=", output[0..begin]));
    facts.rclone_path = try dupOrLiteral(allocator, lineValue("rclone_path=", output[0..begin]));
    facts.rclone_version = try dupOrLiteral(allocator, lineValue("rclone_version=", output[0..begin]));
    facts.crontab_path = try dupOrLiteral(allocator, lineValue("crontab_path=", output[0..begin]));
    facts.service_manager = try dupOrLiteral(allocator, lineValue("service_manager=", output[0..begin]));
    facts.target = try dupOrLiteral(allocator, lineValue("target=", output[0..begin]));
    facts.privilege = try dupOrLiteral(allocator, lineValue("privilege=", output[0..begin]));
    facts.cron_running = std.mem.eql(u8, lineValue("cron_running=", output[0..begin]), "true");
    facts.process_groups = std.mem.eql(u8, lineValue("process_groups=", output[0..begin]), "true");
    facts.crontab_read = CrontabReadState.parse(lineValue("crontab_read=", output[0..begin])) orelse return error.InvalidProbe;
    if (facts.home.len == 0 or facts.home[0] != '/' or facts.home.len > 1024) return error.InvalidProbe;
    if (facts.rclone_path.len > 0 and (facts.rclone_path[0] != '/' or facts.rclone_path.len > 1024)) return error.InvalidProbe;
    return facts;
}

fn runtimeStatusJson(allocator: std.mem.Allocator, facts: *const RuntimeFacts, warnings: []const []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try std.json.Stringify.value(.{
        .observed_at_ms = facts.observed_at_ms,
        .os = facts.os,
        .arch = facts.arch,
        .user = facts.user,
        .home = facts.home,
        .timezone = facts.timezone,
        .rclone_path = facts.rclone_path,
        .rclone_version = facts.rclone_version,
        .crontab_implementation = if (facts.crontab_path.len > 0) "crontab" else "missing",
        .cron_installed = facts.crontab_path.len > 0,
        .cron_running = facts.cron_running,
        .crontab_read = @tagName(facts.crontab_read),
        .service_manager = facts.service_manager,
        .scheduler_supported = facts.crontab_path.len > 0 and facts.rclone_path.len > 0,
        .process_groups = facts.process_groups,
        .target = facts.target,
        .privilege = facts.privilege,
        .warnings = warnings,
    }, .{}, &out.writer);
    return out.toOwnedSlice();
}

const StagedStatus = struct {
    v: u32,
    server_id: []const u8,
    job_id: []const u8,
    job_revision: u64,
    run_id: []const u8,
    started_at: i64,
    finished_at: i64,
    exit: i32,
    status: []const u8,
    cleanup_state: []const u8,
};

fn epochSecondsToNs(epoch_seconds: i64) !i64 {
    if (epoch_seconds <= 0) return error.InvalidEpoch;
    return std.math.mul(i64, epoch_seconds, std.time.ns_per_s) catch error.InvalidEpoch;
}

fn validEpochSeconds(epoch_seconds: i64) bool {
    _ = epochSecondsToNs(epoch_seconds) catch return false;
    return true;
}

pub fn nextIntervalDue(previous_due: i64, now: i64, interval_seconds: i64) !i64 {
    if (previous_due <= 0 or interval_seconds <= 0) return error.InvalidSchedule;
    var due = previous_due;
    while (due <= now) due = std.math.add(i64, due, interval_seconds) catch return error.InvalidSchedule;
    return due;
}

fn importedRunRecord(allocator: std.mem.Allocator, staged: StagedStatus, job: *const Job, server_id: []const u8, status: RunStatus, stats: Stats) !RunRecord {
    var record = RunRecord{
        .id = "",
        .job_id = "",
        .server_id = "",
        .source = "",
        .status = status,
        .started_at_ns = try epochSecondsToNs(staged.started_at),
        .finished_at_ns = try epochSecondsToNs(staged.finished_at),
        .bytes_done = stats.bytes_done,
        .bytes_total = stats.bytes_total,
        .files_done = stats.files_done,
        .files_total = stats.files_total,
    };
    errdefer record.deinit(allocator);
    record.id = try allocator.dupe(u8, staged.run_id);
    record.job_id = try allocator.dupe(u8, job.id);
    record.server_id = try allocator.dupe(u8, server_id);
    record.source = try allocator.dupe(u8, "scheduled");
    return record;
}

fn stagedRunStatus(status: []const u8, exit_code: i32, files_done: u64) ?RunStatus {
    if (std.mem.eql(u8, status, "skipped_overlap")) return .skipped_overlap;
    if (std.mem.eql(u8, status, "source_missing") or std.mem.eql(u8, status, "source_unreadable")) return .failed;
    if (std.mem.eql(u8, status, "failed") or exit_code != 0) return .failed;
    if (std.mem.eql(u8, status, "success")) return if (files_done == 0) .no_changes else .success;
    return null;
}

const CleanupTaskKind = enum {
    reconcile_save,
    reconcile_delete,
    test_sentinel,
};

const CleanupTask = struct {
    kind: CleanupTaskKind,
    config_path: []const u8 = "",
    job: ?Job = null,
    rclone_path: []const u8 = "",
    exact_destination: []const u8 = "",
    remote_object: []const u8 = "",

    fn clone(self: CleanupTask, allocator: std.mem.Allocator) !CleanupTask {
        var copy = CleanupTask{ .kind = self.kind };
        errdefer copy.deinit(allocator);
        copy.config_path = try dupOrLiteral(allocator, self.config_path);
        if (self.job) |job| copy.job = try cloneJobOwned(allocator, job);
        copy.rclone_path = try dupOrLiteral(allocator, self.rclone_path);
        copy.exact_destination = try dupOrLiteral(allocator, self.exact_destination);
        copy.remote_object = try dupOrLiteral(allocator, self.remote_object);
        return copy;
    }

    fn deinit(self: *CleanupTask, allocator: std.mem.Allocator) void {
        if (self.config_path.len > 0) allocator.free(self.config_path);
        if (self.job) |*job| job.deinit(allocator);
        if (self.rclone_path.len > 0) allocator.free(self.rclone_path);
        if (self.exact_destination.len > 0) allocator.free(self.exact_destination);
        if (self.remote_object.len > 0) allocator.free(self.remote_object);
        self.* = undefined;
    }
};

pub const BackupOperation = struct {
    id: []const u8,
    kind: OperationKind,
    state: OperationState = .queued,
    server_id: []const u8 = "",
    job_id: []const u8 = "",
    plan_id: []const u8 = "",
    payload_json: []const u8 = "",
    remote_object: []const u8 = "",
    started_at_ms: i64 = 0,
    touched_at_ms: i64 = 0,
    finished_at_ms: ?i64 = null,
    cancel_requested: bool = false,
    remote_required: bool = false,
    credentials: ?OwnedCredentials = null,
    steps: std.ArrayList(OperationStep) = .empty,
    failure: ?BackupFailure = null,
    result_json: ?[]u8 = null,
    cleanup_task: ?CleanupTask = null,
    sync_advance_approved: bool = false,
    admission_reported: bool = false,
    terminal_reported: bool = false,
    plan_hash: [64]u8 = [_]u8{'0'} ** 64,
    audit_attempt: u32 = 1,

    pub fn deinit(self: *BackupOperation, allocator: std.mem.Allocator) void {
        if (self.id.len > 0) allocator.free(self.id);
        if (self.server_id.len > 0) allocator.free(self.server_id);
        if (self.job_id.len > 0) allocator.free(self.job_id);
        if (self.plan_id.len > 0) allocator.free(self.plan_id);
        if (self.payload_json.len > 0) allocator.free(self.payload_json);
        if (self.remote_object.len > 0) allocator.free(self.remote_object);
        if (self.credentials) |*credentials| credentials.deinit(allocator);
        for (self.steps.items) |*step| step.deinit(allocator);
        self.steps.deinit(allocator);
        if (self.failure) |*failure| failure.deinit(allocator);
        if (self.result_json) |result| allocator.free(result);
        if (self.cleanup_task) |*task| task.deinit(allocator);
    }
};

pub const BackupPlan = struct {
    id: []const u8,
    kind: PlanKind,
    server_id: []const u8 = "",
    job_id: []const u8 = "",
    job_name: []const u8 = "",
    created_at_ms: i64 = 0,
    expires_at_ms: i64 = 0,
    payload_json: []const u8 = "",
    remote_object: []const u8 = "",
    remote_required: bool = false,
    consumed_by_operation_id: []const u8 = "",

    pub fn deinit(self: *BackupPlan, allocator: std.mem.Allocator) void {
        if (self.id.len > 0) allocator.free(self.id);
        if (self.server_id.len > 0) allocator.free(self.server_id);
        if (self.job_id.len > 0) allocator.free(self.job_id);
        if (self.job_name.len > 0) allocator.free(self.job_name);
        if (self.payload_json.len > 0) allocator.free(self.payload_json);
        if (self.remote_object.len > 0) allocator.free(self.remote_object);
        if (self.consumed_by_operation_id.len > 0) allocator.free(self.consumed_by_operation_id);
    }

    pub fn expired(self: *const BackupPlan, now_ms: i64) bool {
        return now_ms >= self.expires_at_ms;
    }
};

pub const PlanSnapshot = struct {
    id: []const u8,
    kind: PlanKind,
    server_id: []const u8,
    job_id: []const u8,
    job_name: []const u8,
    expires_at_ms: i64,
    payload_json: []const u8,
    remote_object: []const u8,
    remote_required: bool,

    pub fn deinit(self: *PlanSnapshot, allocator: std.mem.Allocator) void {
        if (self.id.len > 0) allocator.free(self.id);
        if (self.server_id.len > 0) allocator.free(self.server_id);
        if (self.job_id.len > 0) allocator.free(self.job_id);
        if (self.job_name.len > 0) allocator.free(self.job_name);
        if (self.payload_json.len > 0) allocator.free(self.payload_json);
        if (self.remote_object.len > 0) allocator.free(self.remote_object);
    }
};

pub const OperationSnapshot = struct {
    id: []const u8,
    kind: OperationKind,
    state: OperationState,
    steps: []OperationStep,
    started_at_ms: i64,
    finished_at_ms: ?i64,
    failure: ?BackupFailure,
    result_json: ?[]const u8,

    pub fn deinit(self: *OperationSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        for (self.steps) |*step| step.deinit(allocator);
        allocator.free(self.steps);
        if (self.failure) |*failure| failure.deinit(allocator);
        if (self.result_json) |result| allocator.free(result);
    }
};

pub const OperationEvent = struct {
    operation_id: []const u8,
    kind: OperationKind,
    server_id: []const u8,
    job_id: []const u8,
    state: OperationState,
    admitted: bool,
    failure_code: ?FailureCode = null,
    plan_hash: [64]u8 = [_]u8{'0'} ** 64,
    audit_attempt: u32 = 1,

    pub fn deinit(self: *OperationEvent, allocator: std.mem.Allocator) void {
        if (self.operation_id.len > 0) allocator.free(self.operation_id);
        if (self.server_id.len > 0) allocator.free(self.server_id);
        if (self.job_id.len > 0) allocator.free(self.job_id);
    }
};

pub const RunEvent = struct {
    operation_id: []const u8,
    run_id: []const u8,
    server_id: []const u8,
    job_id: []const u8,
    status: RunStatus,
    admitted: bool,
    failure_code: ?FailureCode = null,
    plan_hash: [64]u8 = [_]u8{'0'} ** 64,
    audit_attempt: u32 = 1,

    pub fn deinit(self: *RunEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.operation_id);
        allocator.free(self.run_id);
        allocator.free(self.server_id);
        allocator.free(self.job_id);
    }
};

pub const Observer = struct {
    context: *anyopaque,
    notify: *const fn (context: *anyopaque, event: *const OperationEvent) bool,
    notify_run: ?*const fn (context: *anyopaque, event: *const RunEvent) bool = null,
};

const EventDispatch = struct {
    observer: Observer,
    event: OperationEvent,

    fn deinit(self: *EventDispatch, allocator: std.mem.Allocator) void {
        self.event.deinit(allocator);
    }
};

pub const OperationReceipt = struct {
    operation_id: []const u8,
    job_id: []const u8,

    pub fn deinit(self: *OperationReceipt, allocator: std.mem.Allocator) void {
        allocator.free(self.operation_id);
        if (self.job_id.len > 0) allocator.free(self.job_id);
    }
};

pub const Admission = struct {
    receipt: OperationReceipt,
    inserted: bool,
    coalesced: bool = false,
};

const OperationAlias = struct {
    id: []const u8,
    target_id: []const u8,
    kind: OperationKind,
    server_id: []const u8,
    plan_id: []const u8,

    fn deinit(self: *OperationAlias, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.target_id);
        if (self.server_id.len > 0) allocator.free(self.server_id);
        if (self.plan_id.len > 0) allocator.free(self.plan_id);
    }
};

pub const OperationDraft = struct {
    operation_id: []const u8,
    kind: OperationKind,
    server_id: []const u8 = "",
    plan_id: ?[]const u8 = null,
    credentials: ?CredentialsView = null,
    sync_advance_approved: bool = false,
};

const CapabilityProof = struct {
    id: []const u8,
    binding: [32]u8,
    expires_at_ms: i64,

    fn deinit(self: *CapabilityProof, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
    }
};

pub const CachedServerStatus = struct {
    server_id: []const u8 = "",
    stale: bool = true,
    updated_at_ms: i64 = 0,
    json: ?[]u8 = null,
    facts: ?RuntimeFacts = null,

    pub fn deinit(self: *CachedServerStatus, allocator: std.mem.Allocator) void {
        if (self.server_id.len > 0) allocator.free(self.server_id);
        if (self.json) |value| allocator.free(value);
        if (self.facts) |*facts| facts.deinit(allocator);
    }
};

pub const RuntimeFactsSnapshot = struct {
    facts: RuntimeFacts,

    pub fn deinit(self: *RuntimeFactsSnapshot, allocator: std.mem.Allocator) void {
        self.facts.deinit(allocator);
    }
};

pub const RunReceipt = struct {
    run_id: []const u8,

    pub fn deinit(self: *RunReceipt, allocator: std.mem.Allocator) void {
        allocator.free(self.run_id);
    }
};

pub const RunSnapshot = struct {
    run_id: []const u8,
    status: RunStatus,
    phase: []const u8,
    bytes_done: u64,
    bytes_total: u64,
    files_done: u64,
    files_total: u64,
    speed_bps: u64,
    eta_sec: i64,
    started_at_ms: i64,
    finished_at_ms: ?i64,
    log_cursor: u64,
    log_delta: []const u8,
    dropped: u64,
    cleanup_state: []const u8,
    failure: ?BackupFailure,

    pub fn deinit(self: *RunSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.run_id);
        allocator.free(self.phase);
        allocator.free(self.log_delta);
        allocator.free(self.cleanup_state);
        if (self.failure) |*failure| failure.deinit(allocator);
    }
};

pub const StatusSnapshot = struct {
    stale: bool,
    json: ?[]const u8,

    pub fn deinit(self: *StatusSnapshot, allocator: std.mem.Allocator) void {
        if (self.json) |value| allocator.free(value);
    }
};

/// Coordinator-owned registry: job store, run history, live runs, plus
/// bounded plans/ops and cached server status. One coordinator thread
/// (plus optional helpers) drives queued ops off the bridge thread.
const OperationWork = struct {
    operation_id: []const u8,
    kind: OperationKind,
    server_id: []const u8,
    job_id: []const u8,
    payload_json: []const u8,
    remote_object: []const u8,
    remote_required: bool,
    credentials: ?OwnedCredentials = null,
    cleanup_task: ?CleanupTask = null,
    sync_advance_approved: bool = false,

    fn deinit(self: *OperationWork, allocator: std.mem.Allocator) void {
        if (self.operation_id.len > 0) allocator.free(self.operation_id);
        if (self.server_id.len > 0) allocator.free(self.server_id);
        if (self.job_id.len > 0) allocator.free(self.job_id);
        if (self.payload_json.len > 0) allocator.free(self.payload_json);
        if (self.remote_object.len > 0) allocator.free(self.remote_object);
        if (self.credentials) |*credentials| credentials.deinit(allocator);
        if (self.cleanup_task) |*task| task.deinit(allocator);
    }
};

const Completion = struct {
    state: OperationState,
    failure: ?BackupFailure = null,
    result_json: ?[]u8 = null,
    cleanup_task: ?CleanupTask = null,
    committed: bool = false,

    fn deinit(self: *Completion, allocator: std.mem.Allocator) void {
        if (self.failure) |*failure| failure.deinit(allocator);
        if (self.result_json) |result| allocator.free(result);
        if (self.cleanup_task) |*task| task.deinit(allocator);
    }
};

const refresh_steps = [_][]const u8{ "probe", "import" };
const test_steps = [_][]const u8{ "list", "write", "read", "delete", "cleanup_verify" };
const save_steps = [_][]const u8{ "validate_plan", "apply_remote", "persist_local" };
const save_local_steps = [_][]const u8{ "validate_plan", "persist_local" };
const delete_steps = [_][]const u8{ "validate_plan", "remove_remote", "persist_local" };
const delete_local_steps = [_][]const u8{ "validate_plan", "persist_local" };
const install_steps = [_][]const u8{"install"};
const cleanup_steps = [_][]const u8{ "cleanup", "cleanup_verify" };

fn stepIds(kind: OperationKind, remote_required: bool) []const []const u8 {
    return switch (kind) {
        .refresh => &refresh_steps,
        .@"test" => &test_steps,
        .save => if (remote_required) &save_steps else &save_local_steps,
        .delete => if (remote_required) &delete_steps else &delete_local_steps,
        .install => &install_steps,
        .cleanup => &cleanup_steps,
    };
}

fn expectedPlanKind(kind: OperationKind) ?PlanKind {
    return switch (kind) {
        .save => .save,
        .delete => .delete,
        .@"test" => .@"test",
        .install => .install,
        .refresh, .cleanup => null,
    };
}

const operation_journal_version: u32 = 1;

const JournalOperation = struct {
    id: []const u8,
    kind: OperationKind,
    state: OperationState,
    server_id: []const u8 = "",
    job_id: []const u8 = "",
    plan_id: []const u8 = "",
    payload_json: []const u8 = "",
    remote_object: []const u8 = "",
    started_at_ms: i64,
    touched_at_ms: i64,
    finished_at_ms: ?i64 = null,
    remote_required: bool,
    sync_advance_approved: bool = false,
    failure: ?BackupFailure = null,
    result_json: ?[]const u8 = null,
    cleanup_task: ?CleanupTask = null,
    audit_attempt: u32 = 1,
    plan_hash: []const u8,
};

const OperationJournalDocument = struct {
    version: u32,
    operations: []JournalOperation,
};

fn operationJournalPath(allocator: std.mem.Allocator, history_path: []const u8) ![]u8 {
    const parent = std.fs.path.dirname(history_path) orelse ".";
    return std.fs.path.join(allocator, &.{ parent, "backup_operations.json" });
}

pub const Registry = struct {
    const StoreCacheState = enum { loading, ready, failed };

    allocator: std.mem.Allocator,
    jobs: JobStore = .{},
    history: HistoryStore = .{},
    cached_jobs: std.ArrayList(Job) = .empty,
    cached_history: std.ArrayList(RunRecord) = .empty,
    jobs_recovery_error: ?[]u8 = null,
    history_recovery_error: ?[]u8 = null,
    store_cache_state: StoreCacheState = .loading,
    runs: Runs = .{},
    ops: std.ArrayList(*BackupOperation) = .empty,
    operation_aliases: std.ArrayList(OperationAlias) = .empty,
    plans: std.ArrayList(*BackupPlan) = .empty,
    statuses: std.ArrayList(*CachedServerStatus) = .empty,
    proofs: std.ArrayList(CapabilityProof) = .empty,
    disconnecting_servers: std.ArrayList([]u8) = .empty,
    mutex: std.atomic.Mutex = .unlocked,
    coordinator: ?std.Thread = null,
    manual_runner: ?std.Thread = null,
    stop: std.atomic.Value(bool) = .init(false),
    io: ?std.Io = null,
    observer: ?Observer = null,
    remote: ?RemoteAdapter = null,
    journal_generation: u64 = 1,
    journal_persisted_generation: u64 = 1,
    journal_loaded: bool = false,

    pub const AdmitError = error{
        TooManyActive,
        OutOfMemory,
        PlanExpired,
        PlanKindMismatch,
        PlanConsumed,
        IdempotencyConflict,
        Busy,
        SessionNotReady,
    };

    pub fn init(allocator: std.mem.Allocator, jobs_path: []const u8, history_path: []const u8) Registry {
        return .{
            .allocator = allocator,
            .jobs = .{ .allocator = allocator, .path = jobs_path },
            .history = .{ .allocator = allocator, .path = history_path },
            .runs = .{ .allocator = allocator },
        };
    }

    fn markJournalDirtyLocked(self: *Registry) void {
        self.journal_generation +|= 1;
    }

    fn recoveryCleanupFor(self: *Registry, record: JournalOperation) ?CleanupTask {
        if (record.cleanup_task) |task| return task.clone(self.allocator) catch null;
        return switch (record.kind) {
            .save => CleanupTask{ .kind = .reconcile_save },
            .delete => CleanupTask{ .kind = .reconcile_delete },
            .@"test" => test_cleanup: {
                var parsed = std.json.parseFromSlice(SavePlanPayload, self.allocator, record.payload_json, .{}) catch break :test_cleanup null;
                defer parsed.deinit();
                const transfer = Transfer.fromJsonName(parsed.value.job.transfer) orelse break :test_cleanup null;
                const job = Job{
                    .id = parsed.value.job.id orelse record.job_id,
                    .server_id = parsed.value.job.server_id,
                    .name = parsed.value.job.name,
                    .source_path = parsed.value.job.source_path,
                    .destination = parsed.value.job.destination,
                    .transfer = transfer,
                    .schedule = parsed.value.job.schedule,
                };
                const remote_name = remoteName(self.allocator, job.id) catch break :test_cleanup null;
                defer self.allocator.free(remote_name);
                const exact_destination = std.fmt.allocPrint(self.allocator, "{s}:{s}/{s}", .{ remote_name, job.destination.bucket, record.remote_object }) catch break :test_cleanup null;
                defer self.allocator.free(exact_destination);
                const config_path = std.fmt.allocPrint(self.allocator, "/tmp/.oars-{s}.conf", .{record.id}) catch break :test_cleanup null;
                defer self.allocator.free(config_path);
                const borrowed = CleanupTask{
                    .kind = .test_sentinel,
                    .config_path = config_path,
                    .job = job,
                    .rclone_path = "",
                    .exact_destination = exact_destination,
                    .remote_object = record.remote_object,
                };
                break :test_cleanup borrowed.clone(self.allocator) catch null;
            },
            .refresh, .install, .cleanup => null,
        };
    }

    fn validJournalOperation(record: JournalOperation, operations: []JournalOperation, index: usize) bool {
        if (!validId(record.id) or
            (record.server_id.len > 0 and !validId(record.server_id)) or
            (record.job_id.len > 0 and !validId(record.job_id)) or
            (record.plan_id.len > 0 and !validId(record.plan_id)) or
            record.payload_json.len > 2 * 1024 * 1024 or
            record.remote_object.len > max_prefix_len + max_id_len + 1 or
            record.plan_hash.len != 64 or
            record.started_at_ms < 0 or
            record.touched_at_ms < record.started_at_ms or
            (record.finished_at_ms != null and record.finished_at_ms.? < record.started_at_ms) or
            record.audit_attempt == 0)
        {
            return false;
        }
        for (operations[0..index]) |previous| if (std.mem.eql(u8, previous.id, record.id)) return false;
        return true;
    }

    fn loadOperationJournal(self: *Registry, io: std.Io) !void {
        const path = try operationJournalPath(self.allocator, self.history.path);
        defer self.allocator.free(path);
        const content = (try readStoreContent(io, path, self.allocator, 16 * 1024 * 1024)) orelse {
            lockSpin(&self.mutex);
            self.journal_loaded = true;
            self.mutex.unlock();
            return;
        };
        defer self.allocator.free(content);
        var parsed = std.json.parseFromSlice(OperationJournalDocument, self.allocator, content, .{ .allocate = .alloc_always }) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            const quarantined = quarantineStore(self.allocator, io, path) catch return error.StoreQuarantineFailed;
            self.allocator.free(quarantined);
            return error.StoreCorrupt;
        };
        defer parsed.deinit();
        if (parsed.value.version != operation_journal_version or parsed.value.operations.len > backup_max_ops) {
            const quarantined = quarantineStore(self.allocator, io, path) catch return error.StoreQuarantineFailed;
            self.allocator.free(quarantined);
            return error.StoreCorrupt;
        }

        const now_ms = @as(i64, @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_ms)));
        var restored: std.ArrayList(*BackupOperation) = .empty;
        errdefer {
            for (restored.items) |op| {
                op.deinit(self.allocator);
                self.allocator.destroy(op);
            }
            restored.deinit(self.allocator);
        }
        var recovered_nonterminal = false;
        for (parsed.value.operations, 0..) |record, index| {
            if (!validJournalOperation(record, parsed.value.operations, index)) {
                const quarantined = quarantineStore(self.allocator, io, path) catch return error.StoreQuarantineFailed;
                self.allocator.free(quarantined);
                return error.StoreCorrupt;
            }
            if (record.state.terminal() and now_ms - (record.finished_at_ms orelse record.touched_at_ms) > coordinator_op_ttl_ms) continue;
            const op = try self.allocator.create(BackupOperation);
            op.* = .{
                .id = "",
                .kind = record.kind,
                .state = record.state,
                .started_at_ms = record.started_at_ms,
                .touched_at_ms = record.touched_at_ms,
                .finished_at_ms = record.finished_at_ms,
                .remote_required = record.remote_required,
                .sync_advance_approved = record.sync_advance_approved,
                .audit_attempt = record.audit_attempt,
            };
            errdefer {
                op.deinit(self.allocator);
                self.allocator.destroy(op);
            }
            op.id = try self.allocator.dupe(u8, record.id);
            op.server_id = try dupOrLiteral(self.allocator, record.server_id);
            op.job_id = try dupOrLiteral(self.allocator, record.job_id);
            op.plan_id = try dupOrLiteral(self.allocator, record.plan_id);
            op.payload_json = try dupOrLiteral(self.allocator, record.payload_json);
            op.remote_object = try dupOrLiteral(self.allocator, record.remote_object);
            @memcpy(op.plan_hash[0..], record.plan_hash);
            if (record.failure) |failure| op.failure = try failure.clone(self.allocator);
            if (record.result_json) |result| op.result_json = try self.allocator.dupe(u8, result);
            if (record.cleanup_task) |task| op.cleanup_task = try task.clone(self.allocator);
            for (stepIds(op.kind, op.remote_required)) |step_id| try op.steps.append(self.allocator, .{ .id = try self.allocator.dupe(u8, step_id) });
            if (!record.state.terminal()) {
                recovered_nonterminal = true;
                op.state = .partial;
                op.finished_at_ms = now_ms;
                op.touched_at_ms = now_ms;
                if (op.failure) |*failure| failure.deinit(self.allocator);
                op.failure = try BackupFailure.init(self.allocator, .interrupted, "Oars restarted before the operation reached a verified terminal state", true, "recovery");
                if (op.cleanup_task == null) op.cleanup_task = self.recoveryCleanupFor(record);
                self.finishStepsLocked(op, .partial);
            } else {
                self.finishStepsLocked(op, op.state);
            }
            try restored.append(self.allocator, op);
        }

        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (restored.items) |restored_op| {
            var current_index: ?usize = null;
            for (self.ops.items, 0..) |current, index| {
                if (std.mem.eql(u8, current.id, restored_op.id)) {
                    current_index = index;
                    break;
                }
            }
            if (current_index) |index| {
                const current = self.ops.orderedRemove(index);
                current.deinit(self.allocator);
                self.allocator.destroy(current);
            }
            try self.ops.append(self.allocator, restored_op);
        }
        restored.deinit(self.allocator);
        restored = .empty;
        self.journal_loaded = true;
        if (recovered_nonterminal) self.markJournalDirtyLocked();
    }

    fn persistOperationJournal(self: *Registry, io: std.Io) !void {
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        var generation: u64 = 0;
        {
            lockSpin(&self.mutex);
            defer self.mutex.unlock();
            if (!self.journal_loaded or self.journal_persisted_generation == self.journal_generation) return;
            generation = self.journal_generation;
            try out.writer.print("{{\"version\":{d},\"operations\":[", .{operation_journal_version});
            for (self.ops.items, 0..) |op, index| {
                if (index > 0) try out.writer.writeAll(",");
                const record = JournalOperation{
                    .id = op.id,
                    .kind = op.kind,
                    .state = op.state,
                    .server_id = op.server_id,
                    .job_id = op.job_id,
                    .plan_id = op.plan_id,
                    .payload_json = op.payload_json,
                    .remote_object = op.remote_object,
                    .started_at_ms = op.started_at_ms,
                    .touched_at_ms = op.touched_at_ms,
                    .finished_at_ms = op.finished_at_ms,
                    .remote_required = op.remote_required,
                    .sync_advance_approved = op.sync_advance_approved,
                    .failure = op.failure,
                    .result_json = op.result_json,
                    .cleanup_task = op.cleanup_task,
                    .audit_attempt = op.audit_attempt,
                    .plan_hash = &op.plan_hash,
                };
                try std.json.Stringify.value(record, .{}, &out.writer);
            }
            try out.writer.writeAll("]}");
        }
        const path = try operationJournalPath(self.allocator, self.history.path);
        defer self.allocator.free(path);
        try writeStoreAtomically(self.allocator, io, path, out.writer.buffered());
        lockSpin(&self.mutex);
        if (self.journal_generation == generation) self.journal_persisted_generation = generation;
        self.mutex.unlock();
    }

    fn operationJournalFailed(self: *Registry, now_ms: i64) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.store_cache_state = .failed;
        for (self.ops.items) |op| {
            if (op.state == .queued or op.state == .running) {
                op.state = .failed;
                op.finished_at_ms = now_ms;
                op.touched_at_ms = now_ms;
                if (op.failure) |*old| old.deinit(self.allocator);
                op.failure = BackupFailure.init(self.allocator, .store_corrupt, "the durable backup operation journal could not be written", true, "journal") catch null;
                self.finishStepsLocked(op, .failed);
                self.clearCredentialsLocked(op);
            } else if (op.state == .done) {
                op.state = .partial;
                if (op.failure) |*old| old.deinit(self.allocator);
                op.failure = BackupFailure.init(self.allocator, .store_corrupt, "the backup completed but its durable operation record could not be written", true, "journal") catch null;
            }
        }
    }

    fn deinitJobList(self: *Registry, list: *std.ArrayList(Job)) void {
        for (list.items) |*job| job.deinit(self.allocator);
        list.deinit(self.allocator);
        list.* = .empty;
    }

    fn deinitHistoryList(self: *Registry, list: *std.ArrayList(RunRecord)) void {
        for (list.items) |*run| run.deinit(self.allocator);
        list.deinit(self.allocator);
        list.* = .empty;
    }

    fn markStoreCacheFailed(self: *Registry) void {
        lockSpin(&self.mutex);
        self.store_cache_state = .failed;
        self.mutex.unlock();
    }

    fn loadStoreCaches(self: *Registry, io: std.Io) !void {
        // Disk parsing, migration, and quarantine happen here on the
        // coordinator, never in a bridge handler.
        var loaded_jobs = self.jobs.loadParsed(io) catch |err| {
            self.markStoreCacheFailed();
            return err;
        };
        defer loaded_jobs.deinit(self.allocator);
        var loaded_history = self.history.loadParsed(io) catch |err| {
            self.markStoreCacheFailed();
            return err;
        };
        defer loaded_history.deinit(self.allocator);
        self.loadOperationJournal(io) catch |err| {
            self.markStoreCacheFailed();
            return err;
        };

        var jobs_copy: std.ArrayList(Job) = .empty;
        errdefer self.deinitJobList(&jobs_copy);
        for (loaded_jobs.parsed.value.jobs) |job| try jobs_copy.append(self.allocator, try JobStore.cloneJob(self.allocator, job));
        var history_copy: std.ArrayList(RunRecord) = .empty;
        errdefer self.deinitHistoryList(&history_copy);
        for (loaded_history.parsed.value.runs) |run| try history_copy.append(self.allocator, try HistoryStore.cloneRun(self.allocator, run));
        const jobs_recovery = if (loaded_jobs.recovery_error) |message| try self.allocator.dupe(u8, message) else null;
        errdefer if (jobs_recovery) |message| self.allocator.free(message);
        const history_recovery = if (loaded_history.recovery_error) |message| try self.allocator.dupe(u8, message) else null;
        errdefer if (history_recovery) |message| self.allocator.free(message);

        lockSpin(&self.mutex);
        self.deinitJobList(&self.cached_jobs);
        self.deinitHistoryList(&self.cached_history);
        self.cached_jobs = jobs_copy;
        jobs_copy = .empty;
        self.cached_history = history_copy;
        history_copy = .empty;
        if (self.jobs_recovery_error) |message| self.allocator.free(message);
        if (self.history_recovery_error) |message| self.allocator.free(message);
        self.jobs_recovery_error = jobs_recovery;
        self.history_recovery_error = history_recovery;
        self.store_cache_state = .ready;
        self.mutex.unlock();
    }

    pub const StoreSnapshotError = error{ StoreNotReady, StoreCorrupt, OutOfMemory };

    fn cacheReadyLocked(self: *Registry) StoreSnapshotError!void {
        return switch (self.store_cache_state) {
            .loading => error.StoreNotReady,
            .failed => error.StoreCorrupt,
            .ready => {},
        };
    }

    pub fn jobSnapshot(self: *Registry, job_id: []const u8) StoreSnapshotError!?Job {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.cacheReadyLocked();
        for (self.cached_jobs.items) |job| {
            if (std.mem.eql(u8, job.id, job_id)) return JobStore.cloneJob(self.allocator, job) catch error.OutOfMemory;
        }
        return null;
    }

    pub fn jobsForServerSnapshot(self: *Registry, server_id: []const u8) StoreSnapshotError!JobStore.ListResult {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.cacheReadyLocked();
        var out: std.ArrayList(Job) = .empty;
        errdefer self.deinitJobList(&out);
        for (self.cached_jobs.items) |job| {
            if (std.mem.eql(u8, job.server_id, server_id)) try out.append(self.allocator, JobStore.cloneJob(self.allocator, job) catch return error.OutOfMemory);
        }
        std.mem.sort(Job, out.items, {}, struct {
            fn lessThan(_: void, a: Job, b: Job) bool {
                if (a.updated_at_ns != b.updated_at_ns) return a.updated_at_ns < b.updated_at_ns;
                return std.mem.order(u8, a.id, b.id) == .lt;
            }
        }.lessThan);
        return .{
            .jobs = out.toOwnedSlice(self.allocator) catch return error.OutOfMemory,
            .recovery_error = if (self.jobs_recovery_error) |message| self.allocator.dupe(u8, message) catch return error.OutOfMemory else null,
        };
    }

    pub fn historyForJobSnapshot(self: *Registry, job_id: []const u8, limit: usize) StoreSnapshotError!HistoryStore.ListResult {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.cacheReadyLocked();
        var out: std.ArrayList(RunRecord) = .empty;
        errdefer self.deinitHistoryList(&out);
        var index = self.cached_history.items.len;
        while (index > 0 and out.items.len < limit) {
            index -= 1;
            const run = self.cached_history.items[index];
            if (!std.mem.eql(u8, run.job_id, job_id)) continue;
            try out.append(self.allocator, HistoryStore.cloneRun(self.allocator, run) catch return error.OutOfMemory);
        }
        return .{
            .runs = out.toOwnedSlice(self.allocator) catch return error.OutOfMemory,
            .recovery_error = if (self.history_recovery_error) |message| self.allocator.dupe(u8, message) catch return error.OutOfMemory else null,
        };
    }

    pub fn historyRunSnapshot(self: *Registry, run_id: []const u8) StoreSnapshotError!?RunRecord {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.cacheReadyLocked();
        for (self.cached_history.items) |run| {
            if (std.mem.eql(u8, run.id, run_id)) return HistoryStore.cloneRun(self.allocator, run) catch error.OutOfMemory;
        }
        return null;
    }

    fn historyRunByOperationSnapshot(self: *Registry, operation_id: []const u8) StoreSnapshotError!?RunRecord {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.cacheReadyLocked();
        for (self.cached_history.items) |run| {
            if (run.operation_id.len > 0 and std.mem.eql(u8, run.operation_id, operation_id)) return HistoryStore.cloneRun(self.allocator, run) catch error.OutOfMemory;
        }
        return null;
    }

    fn upsertCachedJob(self: *Registry, job: *const Job) !void {
        var copy = try JobStore.cloneJob(self.allocator, job.*);
        errdefer copy.deinit(self.allocator);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.store_cache_state != .ready) return error.StoreNotReady;
        for (self.cached_jobs.items) |*existing| {
            if (!std.mem.eql(u8, existing.id, job.id)) continue;
            existing.deinit(self.allocator);
            existing.* = copy;
            return;
        }
        try self.cached_jobs.append(self.allocator, copy);
    }

    fn removeCachedJob(self: *Registry, job_id: []const u8) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.cached_jobs.items, 0..) |*job, index| {
            if (!std.mem.eql(u8, job.id, job_id)) continue;
            var removed = self.cached_jobs.orderedRemove(index);
            removed.deinit(self.allocator);
            return;
        }
    }

    fn upsertCachedHistory(self: *Registry, record: *const RunRecord) !void {
        var copy = try HistoryStore.cloneRun(self.allocator, record.*);
        errdefer copy.deinit(self.allocator);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.store_cache_state != .ready) return error.StoreNotReady;
        for (self.cached_history.items) |*existing| {
            if (!std.mem.eql(u8, existing.id, record.id)) continue;
            existing.deinit(self.allocator);
            existing.* = copy;
            return;
        }
        try self.cached_history.append(self.allocator, copy);
        while (self.cached_history.items.len > max_runs) {
            var oldest: usize = 0;
            for (self.cached_history.items, 0..) |run, index| {
                if (run.started_at_ns < self.cached_history.items[oldest].started_at_ns) oldest = index;
            }
            var removed = self.cached_history.orderedRemove(oldest);
            removed.deinit(self.allocator);
        }
    }

    pub const StoreHealthSnapshot = struct {
        ready: bool,
        failed: bool,
        jobs_recovery_error: ?[]u8 = null,
        history_recovery_error: ?[]u8 = null,

        pub fn deinit(self: *StoreHealthSnapshot, allocator: std.mem.Allocator) void {
            if (self.jobs_recovery_error) |message| allocator.free(message);
            if (self.history_recovery_error) |message| allocator.free(message);
        }
    };

    pub fn storeHealthSnapshot(self: *Registry) !StoreHealthSnapshot {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return .{
            .ready = self.store_cache_state == .ready,
            .failed = self.store_cache_state == .failed,
            .jobs_recovery_error = if (self.jobs_recovery_error) |message| try self.allocator.dupe(u8, message) else null,
            .history_recovery_error = if (self.history_recovery_error) |message| try self.allocator.dupe(u8, message) else null,
        };
    }

    fn nowMs(self: *Registry) i64 {
        const io = self.io orelse return 0;
        return @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_ms));
    }

    pub fn setObserver(self: *Registry, observer: Observer) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.observer = observer;
    }

    pub fn setRemoteAdapter(self: *Registry, adapter: RemoteAdapter) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.remote = adapter;
    }

    fn serverDisconnectingLocked(self: *Registry, server_id: []const u8) bool {
        for (self.disconnecting_servers.items) |current| {
            if (std.mem.eql(u8, current, server_id)) return true;
        }
        return false;
    }

    pub fn allowServer(self: *Registry, server_id: []const u8) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var index: usize = 0;
        while (index < self.disconnecting_servers.items.len) {
            if (!std.mem.eql(u8, self.disconnecting_servers.items[index], server_id)) {
                index += 1;
                continue;
            }
            const removed = self.disconnecting_servers.orderedRemove(index);
            self.allocator.free(removed);
        }
    }

    /// Runs before sessions.Manager stops the SSH worker. Normal backup
    /// admission is closed first, then live manual runs get a bounded window
    /// to signal and verify their process groups over cleanup-only channels.
    pub fn prepareDisconnect(self: *Registry, server_id: []const u8) bool {
        lockSpin(&self.mutex);
        if (!self.serverDisconnectingLocked(server_id)) {
            const owned = self.allocator.dupe(u8, server_id) catch {
                self.mutex.unlock();
                return false;
            };
            self.disconnecting_servers.append(self.allocator, owned) catch {
                self.allocator.free(owned);
                self.mutex.unlock();
                return false;
            };
        }
        for (self.ops.items) |op| {
            if (!op.state.terminal() and std.mem.eql(u8, op.server_id, server_id)) {
                op.cancel_requested = true;
                self.markJournalDirtyLocked();
            }
        }
        self.mutex.unlock();

        self.runs.lock();
        var affected: usize = 0;
        for (self.runs.list.items) |run| {
            if (run.record.status.terminal() or !std.mem.eql(u8, run.record.server_id, server_id)) continue;
            affected += 1;
            run.cancel_requested = true;
            run.record.status = .cancel_requested;
            self.replaceRunText(&run.phase, "disconnect_cancel_requested");
        }
        self.runs.unlock();
        if (affected == 0) return true;

        const io = self.io orelse return false;
        const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + 12 * std.time.ns_per_s;
        while (std.Io.Timestamp.now(io, .real).nanoseconds < deadline) {
            var pending = false;
            var verified = true;
            self.runs.lock();
            for (self.runs.list.items) |run| {
                if (!std.mem.eql(u8, run.record.server_id, server_id)) continue;
                if (!run.record.status.terminal()) pending = true;
                if (run.record.status == .interrupted or (run.pgid.len > 0 and !run.cancel_verified)) verified = false;
            }
            self.runs.unlock();
            if (!pending) return verified;
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(20), .awake) catch break;
        }
        return false;
    }

    /// Race-free one-time startup: the thread handle is published while the
    /// registry lock is held, so concurrent callers cannot spawn duplicates.
    pub fn ensureStarted(self: *Registry, io: std.Io) !void {
        lockSpin(&self.mutex);
        if (self.coordinator != null) {
            self.mutex.unlock();
            return;
        }
        self.io = io;
        self.stop.store(false, .release);
        const manual_runner = std.Thread.spawn(.{}, manualRunnerMain, .{self}) catch |err| {
            self.mutex.unlock();
            return err;
        };
        const coordinator = std.Thread.spawn(.{}, coordinatorMain, .{self}) catch |err| {
            self.stop.store(true, .release);
            self.mutex.unlock();
            manual_runner.join();
            return err;
        };
        self.manual_runner = manual_runner;
        self.coordinator = coordinator;
        self.mutex.unlock();
    }

    pub fn deinit(self: *Registry) void {
        if (self.remoteAdapter()) |adapter| {
            if (adapter.detach_fn) |detach| detach(adapter.context, self);
        }
        self.runs.lock();
        for (self.runs.list.items) |run| {
            if (run.record.status.terminal()) continue;
            run.cancel_requested = true;
            run.record.status = .cancel_requested;
            self.replaceRunText(&run.phase, "cancel_requested");
        }
        self.runs.unlock();
        self.stop.store(true, .release);
        if (self.coordinator) |thread| thread.join();
        if (self.manual_runner) |thread| thread.join();
        self.coordinator = null;
        self.manual_runner = null;
        // A run can be admitted just as shutdown begins, before the manual
        // runner observes it. Close that race after both workers have joined
        // so every admitted run has durable terminal and audit evidence.
        while (true) {
            self.runs.lock();
            var unfinished: ?*LiveRun = null;
            for (self.runs.list.items) |run| {
                if (!run.record.status.terminal()) {
                    unfinished = run;
                    break;
                }
            }
            self.runs.unlock();
            const run = unfinished orelse break;
            const failure = BackupFailure.init(self.allocator, .interrupted, "backup coordinator stopped before remote execution", true, "shutdown") catch null;
            self.finishLiveRun(self.io.?, run, .interrupted, true, failure);
        }
        lockSpin(&self.mutex);
        const now_ms = self.nowMs();
        for (self.ops.items) |op| {
            if (!op.state.terminal()) {
                op.state = .failed;
                op.finished_at_ms = now_ms;
                if (op.failure) |*old| old.deinit(self.allocator);
                op.failure = BackupFailure.init(self.allocator, .interrupted, "backup coordinator stopped before completion", true, "shutdown") catch null;
                self.finishStepsLocked(op, .failed);
                self.clearCredentialsLocked(op);
                self.markJournalDirtyLocked();
            }
        }
        self.mutex.unlock();
        if (self.io) |io| self.persistOperationJournal(io) catch {};
        self.drainEvents();
        self.runs.deinit();
        lockSpin(&self.mutex);
        for (self.ops.items) |op| {
            op.deinit(self.allocator);
            self.allocator.destroy(op);
        }
        self.ops.deinit(self.allocator);
        for (self.operation_aliases.items) |*alias| alias.deinit(self.allocator);
        self.operation_aliases.deinit(self.allocator);
        for (self.plans.items) |plan| {
            plan.deinit(self.allocator);
            self.allocator.destroy(plan);
        }
        self.plans.deinit(self.allocator);
        for (self.statuses.items) |status| {
            status.deinit(self.allocator);
            self.allocator.destroy(status);
        }
        self.statuses.deinit(self.allocator);
        for (self.proofs.items) |*proof| proof.deinit(self.allocator);
        self.proofs.deinit(self.allocator);
        for (self.disconnecting_servers.items) |server_id| self.allocator.free(server_id);
        self.disconnecting_servers.deinit(self.allocator);
        self.deinitJobList(&self.cached_jobs);
        self.deinitHistoryList(&self.cached_history);
        if (self.jobs_recovery_error) |message| self.allocator.free(message);
        if (self.history_recovery_error) |message| self.allocator.free(message);
        self.jobs_recovery_error = null;
        self.history_recovery_error = null;
        self.mutex.unlock();
        self.jobs.deinitRecovery();
        self.history.deinitRecovery();
    }

    fn planNeededByActiveOperationLocked(self: *Registry, plan_id: []const u8) bool {
        for (self.ops.items) |op| {
            if (!op.state.terminal() and std.mem.eql(u8, op.plan_id, plan_id)) return true;
        }
        return false;
    }

    fn removeAliasesForTargetLocked(self: *Registry, target_id: []const u8) void {
        var index: usize = 0;
        while (index < self.operation_aliases.items.len) {
            if (!std.mem.eql(u8, self.operation_aliases.items[index].target_id, target_id)) {
                index += 1;
                continue;
            }
            var removed = self.operation_aliases.orderedRemove(index);
            removed.deinit(self.allocator);
        }
    }

    fn sweepLocked(self: *Registry, now_ms: i64) void {
        var i: usize = 0;
        while (i < self.plans.items.len) {
            const plan = self.plans.items[i];
            if (plan.expired(now_ms) and !self.planNeededByActiveOperationLocked(plan.id)) {
                const removed = self.plans.orderedRemove(i);
                removed.deinit(self.allocator);
                self.allocator.destroy(removed);
            } else i += 1;
        }
        i = 0;
        while (i < self.ops.items.len) {
            const op = self.ops.items[i];
            if (op.state.terminal() and now_ms - (op.finished_at_ms orelse op.touched_at_ms) > coordinator_op_ttl_ms) {
                self.removeAliasesForTargetLocked(op.id);
                op.deinit(self.allocator);
                self.allocator.destroy(op);
                _ = self.ops.orderedRemove(i);
                self.markJournalDirtyLocked();
            } else i += 1;
        }
    }

    fn makeRoomForOpLocked(self: *Registry, now_ms: i64) AdmitError!void {
        self.sweepLocked(now_ms);
        while (self.ops.items.len >= backup_max_ops) {
            var victim: ?usize = null;
            var oldest: i64 = std.math.maxInt(i64);
            for (self.ops.items, 0..) |op, index| {
                if (!op.state.terminal()) continue;
                if (op.touched_at_ms < oldest) {
                    oldest = op.touched_at_ms;
                    victim = index;
                }
            }
            const index = victim orelse return error.TooManyActive;
            const removed = self.ops.orderedRemove(index);
            self.removeAliasesForTargetLocked(removed.id);
            removed.deinit(self.allocator);
            self.allocator.destroy(removed);
            self.markJournalDirtyLocked();
        }
    }

    fn registerCapabilityProof(self: *Registry, id: []const u8, binding: [32]u8, expires_at_ms: i64) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var i: usize = 0;
        while (i < self.proofs.items.len) {
            if (self.proofs.items[i].expires_at_ms <= self.nowMs()) {
                var removed = self.proofs.orderedRemove(i);
                removed.deinit(self.allocator);
            } else i += 1;
        }
        while (self.proofs.items.len >= backup_max_plans) {
            var removed = self.proofs.orderedRemove(0);
            removed.deinit(self.allocator);
        }
        try self.proofs.append(self.allocator, .{ .id = try self.allocator.dupe(u8, id), .binding = binding, .expires_at_ms = expires_at_ms });
    }

    pub fn validateCapabilityProof(self: *Registry, id: []const u8, binding: [32]u8, now_ms: i64) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.proofs.items) |proof| {
            if (proof.expires_at_ms > now_ms and std.mem.eql(u8, proof.id, id) and std.mem.eql(u8, &proof.binding, &binding)) return true;
        }
        return false;
    }

    pub fn registerPlan(self: *Registry, plan: *BackupPlan) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.sweepLocked(self.nowMs());
        for (self.plans.items) |existing| {
            if (std.mem.eql(u8, existing.id, plan.id)) return error.Conflict;
        }
        if (self.plans.items.len >= backup_max_plans) return error.TooManyPlans;
        try self.plans.append(self.allocator, plan);
    }

    pub fn planSnapshot(self: *Registry, id: []const u8, now_ms: i64) !?PlanSnapshot {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.sweepLocked(now_ms);
        for (self.plans.items) |plan| {
            if (!std.mem.eql(u8, plan.id, id)) continue;
            var snapshot = PlanSnapshot{
                .id = "",
                .kind = plan.kind,
                .server_id = "",
                .job_id = "",
                .job_name = "",
                .expires_at_ms = plan.expires_at_ms,
                .payload_json = "",
                .remote_object = "",
                .remote_required = plan.remote_required,
            };
            errdefer snapshot.deinit(self.allocator);
            snapshot.id = try dupOrLiteral(self.allocator, plan.id);
            snapshot.server_id = try dupOrLiteral(self.allocator, plan.server_id);
            snapshot.job_id = try dupOrLiteral(self.allocator, plan.job_id);
            snapshot.job_name = try dupOrLiteral(self.allocator, plan.job_name);
            snapshot.payload_json = try dupOrLiteral(self.allocator, plan.payload_json);
            snapshot.remote_object = try dupOrLiteral(self.allocator, plan.remote_object);
            return snapshot;
        }
        return null;
    }

    fn receiptLocked(self: *Registry, op: *const BackupOperation) !OperationReceipt {
        const operation_id = try self.allocator.dupe(u8, op.id);
        errdefer self.allocator.free(operation_id);
        return .{
            .operation_id = operation_id,
            .job_id = try dupOrLiteral(self.allocator, op.job_id),
        };
    }

    fn operationByIdLocked(self: *Registry, id: []const u8) ?*BackupOperation {
        for (self.ops.items) |op| if (std.mem.eql(u8, op.id, id)) return op;
        return null;
    }

    fn aliasReceiptLocked(self: *Registry, alias: *const OperationAlias, kind: OperationKind, server_id: []const u8, plan_id: ?[]const u8) AdmitError!OperationReceipt {
        if (alias.kind != kind) return error.IdempotencyConflict;
        if (server_id.len > 0 and !std.mem.eql(u8, alias.server_id, server_id)) return error.IdempotencyConflict;
        if (plan_id) |expected| if (!std.mem.eql(u8, alias.plan_id, expected)) return error.IdempotencyConflict;
        const target = self.operationByIdLocked(alias.target_id) orelse return error.IdempotencyConflict;
        return self.receiptLocked(target) catch return error.OutOfMemory;
    }

    fn registerAliasLocked(self: *Registry, draft: OperationDraft, target: *const BackupOperation) AdmitError!void {
        if (self.operation_aliases.items.len >= backup_max_ops) return error.TooManyActive;
        var alias = OperationAlias{
            .id = self.allocator.dupe(u8, draft.operation_id) catch return error.OutOfMemory,
            .target_id = "",
            .kind = draft.kind,
            .server_id = "",
            .plan_id = "",
        };
        errdefer alias.deinit(self.allocator);
        alias.target_id = self.allocator.dupe(u8, target.id) catch return error.OutOfMemory;
        alias.server_id = dupOrLiteral(self.allocator, draft.server_id) catch return error.OutOfMemory;
        alias.plan_id = dupOrLiteral(self.allocator, draft.plan_id orelse "") catch return error.OutOfMemory;
        self.operation_aliases.append(self.allocator, alias) catch return error.OutOfMemory;
    }

    pub fn existingReceipt(self: *Registry, operation_id: []const u8, kind: OperationKind, plan_id: ?[]const u8) AdmitError!?OperationReceipt {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.ops.items) |op| {
            if (!std.mem.eql(u8, op.id, operation_id)) continue;
            if (op.kind != kind) return error.IdempotencyConflict;
            if (plan_id) |expected| {
                if (!std.mem.eql(u8, op.plan_id, expected)) return error.IdempotencyConflict;
            }
            return self.receiptLocked(op) catch return error.OutOfMemory;
        }
        for (self.operation_aliases.items) |*alias| {
            if (std.mem.eql(u8, alias.id, operation_id)) return try self.aliasReceiptLocked(alias, kind, "", plan_id);
        }
        return null;
    }

    fn newOperationLocked(self: *Registry, draft: OperationDraft, plan: ?*BackupPlan, now_ms: i64) !*BackupOperation {
        const op = try self.allocator.create(BackupOperation);
        op.* = .{
            .id = "",
            .kind = draft.kind,
            .started_at_ms = now_ms,
            .touched_at_ms = now_ms,
            .remote_required = if (plan) |value| value.remote_required else true,
            .sync_advance_approved = draft.sync_advance_approved,
        };
        errdefer {
            op.deinit(self.allocator);
            self.allocator.destroy(op);
        }
        op.id = try self.allocator.dupe(u8, draft.operation_id);
        op.server_id = try dupOrLiteral(self.allocator, if (plan) |value| value.server_id else draft.server_id);
        op.job_id = try dupOrLiteral(self.allocator, if (plan) |value| value.job_id else "");
        op.plan_id = try dupOrLiteral(self.allocator, if (plan) |value| value.id else "");
        op.payload_json = try dupOrLiteral(self.allocator, if (plan) |value| value.payload_json else "");
        op.remote_object = try dupOrLiteral(self.allocator, if (plan) |value| value.remote_object else "");
        op.plan_hash = auditPlanHash(op.kind.jsonName(), op.server_id, op.job_id, op.payload_json);
        if (draft.credentials) |credentials| op.credentials = try OwnedCredentials.init(self.allocator, credentials);
        for (stepIds(draft.kind, op.remote_required)) |step_id| {
            const owned_id = try self.allocator.dupe(u8, step_id);
            op.steps.append(self.allocator, .{ .id = owned_id }) catch |err| {
                self.allocator.free(owned_id);
                return err;
            };
        }
        return op;
    }

    pub fn admitOperation(self: *Registry, draft: OperationDraft, now_ms: i64) AdmitError!Admission {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.sweepLocked(now_ms);
        for (self.ops.items) |existing| {
            if (!std.mem.eql(u8, existing.id, draft.operation_id)) continue;
            if (existing.kind != draft.kind) return error.IdempotencyConflict;
            if (draft.plan_id) |plan_id| if (!std.mem.eql(u8, existing.plan_id, plan_id)) return error.IdempotencyConflict;
            if (draft.server_id.len > 0 and !std.mem.eql(u8, existing.server_id, draft.server_id)) return error.IdempotencyConflict;
            return .{ .receipt = self.receiptLocked(existing) catch return error.OutOfMemory, .inserted = false };
        }
        for (self.operation_aliases.items) |*alias| {
            if (!std.mem.eql(u8, alias.id, draft.operation_id)) continue;
            return .{ .receipt = try self.aliasReceiptLocked(alias, draft.kind, draft.server_id, draft.plan_id), .inserted = false, .coalesced = true };
        }

        var plan: ?*BackupPlan = null;
        if (draft.plan_id) |plan_id| {
            for (self.plans.items) |candidate| {
                if (std.mem.eql(u8, candidate.id, plan_id)) {
                    plan = candidate;
                    break;
                }
            }
            const selected = plan orelse return error.PlanExpired;
            if (selected.expired(now_ms)) return error.PlanExpired;
            if (expectedPlanKind(draft.kind) != selected.kind) return error.PlanKindMismatch;
            if (selected.consumed_by_operation_id.len > 0 and !std.mem.eql(u8, selected.consumed_by_operation_id, draft.operation_id)) return error.PlanConsumed;
            if (draft.server_id.len > 0 and !std.mem.eql(u8, draft.server_id, selected.server_id)) return error.IdempotencyConflict;
        } else if (expectedPlanKind(draft.kind) != null) {
            return error.PlanExpired;
        }

        const target_server = if (plan) |value| value.server_id else draft.server_id;
        const needs_remote = if (plan) |value| value.remote_required else true;
        if (draft.kind != .cleanup and needs_remote and self.serverDisconnectingLocked(target_server)) return error.SessionNotReady;

        if (draft.kind == .refresh) {
            for (self.ops.items) |existing| {
                if (existing.kind == .refresh and !existing.state.terminal() and std.mem.eql(u8, existing.server_id, draft.server_id)) {
                    try self.registerAliasLocked(draft, existing);
                    return .{ .receipt = self.receiptLocked(existing) catch return error.OutOfMemory, .inserted = false, .coalesced = true };
                }
            }
        } else {
            const server_id = if (plan) |value| value.server_id else draft.server_id;
            for (self.ops.items) |existing| {
                if (!existing.state.terminal() and existing.kind != .refresh and std.mem.eql(u8, existing.server_id, server_id)) return error.Busy;
            }
        }

        try self.makeRoomForOpLocked(now_ms);
        const op = self.newOperationLocked(draft, plan, now_ms) catch return error.OutOfMemory;
        errdefer {
            op.deinit(self.allocator);
            self.allocator.destroy(op);
        }
        var consumed_copy: ?[]u8 = null;
        if (plan) |selected| {
            if (selected.consumed_by_operation_id.len == 0) consumed_copy = self.allocator.dupe(u8, draft.operation_id) catch return error.OutOfMemory;
        }
        errdefer if (consumed_copy) |value| self.allocator.free(value);
        var receipt = self.receiptLocked(op) catch return error.OutOfMemory;
        errdefer receipt.deinit(self.allocator);
        self.ops.append(self.allocator, op) catch return error.OutOfMemory;
        self.markJournalDirtyLocked();
        if (plan) |selected| {
            if (consumed_copy) |value| selected.consumed_by_operation_id = value;
        }
        return .{ .receipt = receipt, .inserted = true };
    }

    pub fn operationSnapshot(self: *Registry, id: []const u8) !?OperationSnapshot {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.ops.items) |op| {
            if (!std.mem.eql(u8, op.id, id)) continue;
            const steps = try self.allocator.alloc(OperationStep, op.steps.items.len);
            var cloned: usize = 0;
            errdefer {
                for (steps[0..cloned]) |*step| step.deinit(self.allocator);
                self.allocator.free(steps);
            }
            for (op.steps.items, 0..) |step, index| {
                steps[index] = try step.clone(self.allocator);
                cloned += 1;
            }
            const snapshot_id = try self.allocator.dupe(u8, op.id);
            errdefer self.allocator.free(snapshot_id);
            var failure_copy: ?BackupFailure = if (op.failure) |failure| try failure.clone(self.allocator) else null;
            errdefer if (failure_copy) |*failure| failure.deinit(self.allocator);
            const result_copy: ?[]const u8 = if (op.result_json) |result| try self.allocator.dupe(u8, result) else null;
            return .{
                .id = snapshot_id,
                .kind = op.kind,
                .state = op.state,
                .steps = steps,
                .started_at_ms = op.started_at_ms,
                .finished_at_ms = op.finished_at_ms,
                .failure = failure_copy,
                .result_json = result_copy,
            };
        }
        return null;
    }

    fn clearCredentialsLocked(self: *Registry, op: *BackupOperation) void {
        if (op.credentials) |*credentials| credentials.deinit(self.allocator);
        op.credentials = null;
    }

    fn finishStepsLocked(self: *Registry, op: *BackupOperation, state: OperationState) void {
        _ = self;
        if (state == .failed) {
            const failure_step = if (op.failure) |failure| failure.step else "";
            if (failure_step.len > 0) {
                var matched = false;
                for (op.steps.items) |*step| {
                    if (std.mem.eql(u8, step.id, failure_step)) {
                        step.state = .failed;
                        matched = true;
                    } else if (!matched) {
                        step.state = .done;
                    } else {
                        step.state = .skipped;
                    }
                }
                if (matched) return;
            }
        }
        var terminal_set = false;
        for (op.steps.items) |*step| {
            if (state == .done) {
                if (step.state == .pending or step.state == .running or step.state == .cancel_requested) step.state = .done;
                continue;
            }
            if (!terminal_set and (step.state == .running or step.state == .cancel_requested or step.state == .pending)) {
                step.state = if (state == .canceled) .canceled else .failed;
                terminal_set = true;
            } else if (step.state == .pending) {
                step.state = .skipped;
            }
        }
    }

    fn resetStepsLocked(self: *Registry, op: *BackupOperation, ids: []const []const u8) !void {
        var replacement: std.ArrayList(OperationStep) = .empty;
        errdefer {
            for (replacement.items) |*step| step.deinit(self.allocator);
            replacement.deinit(self.allocator);
        }
        for (ids) |id| {
            const owned = try self.allocator.dupe(u8, id);
            replacement.append(self.allocator, .{ .id = owned }) catch |err| {
                self.allocator.free(owned);
                return err;
            };
        }
        for (op.steps.items) |*step| step.deinit(self.allocator);
        op.steps.deinit(self.allocator);
        op.steps = replacement;
    }

    pub const CancelOperationResult = enum { accepted, busy, invalid_credentials, internal, not_found };

    pub fn cancelOperation(self: *Registry, id: []const u8, credentials: ?CredentialsView, now_ms: i64) CancelOperationResult {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.ops.items) |op| {
            if (!std.mem.eql(u8, op.id, id)) continue;
            if (op.state.terminal() and op.cleanup_task != null) {
                // NEXT-SPEC exposes no separate cleanup command. A protected
                // operationCancel on retained partial evidence is therefore
                // the explicit Retry cleanup action; it never broad-deletes.
                for (self.ops.items) |active| {
                    if (active == op or active.state.terminal() or active.kind == .refresh) continue;
                    if (std.mem.eql(u8, active.server_id, op.server_id)) return .busy;
                }
                const task = &op.cleanup_task.?;
                const needs_credentials = task.kind == .test_sentinel and task.remote_object.len > 0 and task.job != null and task.job.?.destination.credential_mode == .access_key;
                if (needs_credentials and credentials == null) {
                    if (op.failure) |*old| old.deinit(self.allocator);
                    op.failure = BackupFailure.init(self.allocator, .invalid_credentials, "fresh credentials are required to retry exact cleanup", false, "cleanup") catch null;
                    if (op.result_json) |old| self.allocator.free(old);
                    op.result_json = self.cleanupRequiredResult(op.job_id, true);
                    op.touched_at_ms = now_ms;
                    self.markJournalDirtyLocked();
                    return .invalid_credentials;
                }
                if (!needs_credentials and credentials != null) return .invalid_credentials;
                self.clearCredentialsLocked(op);
                if (credentials) |fresh| {
                    op.credentials = OwnedCredentials.init(self.allocator, fresh) catch return .invalid_credentials;
                }
                self.resetStepsLocked(op, &cleanup_steps) catch return .internal;
                op.kind = .cleanup;
                op.state = .queued;
                op.finished_at_ms = null;
                op.touched_at_ms = now_ms;
                op.cancel_requested = false;
                op.admission_reported = false;
                op.terminal_reported = false;
                op.audit_attempt +|= 1;
                self.markJournalDirtyLocked();
            } else if (op.state == .queued) {
                op.state = .canceled;
                op.finished_at_ms = now_ms;
                op.touched_at_ms = now_ms;
                if (op.failure) |*old| old.deinit(self.allocator);
                op.failure = BackupFailure.init(self.allocator, .canceled, "operation canceled before execution", false, "admission") catch null;
                self.finishStepsLocked(op, .canceled);
                self.clearCredentialsLocked(op);
                self.markJournalDirtyLocked();
            } else if (op.state == .running) {
                op.cancel_requested = true;
                for (op.steps.items) |*step| {
                    if (step.state == .running) {
                        step.state = .cancel_requested;
                        break;
                    }
                }
                self.markJournalDirtyLocked();
            }
            return .accepted;
        }
        return .not_found;
    }

    pub const RunAdmitError = error{ Busy, IdempotencyConflict, SessionNotReady, StoreNotReady, StoreCorrupt, OutOfMemory };

    pub fn admitRun(self: *Registry, operation_id: []const u8, job: *const Job, credentials: ?CredentialsView, now_ns: i64) RunAdmitError!RunReceipt {
        const io = self.io orelse return error.OutOfMemory;
        var historical = self.historyRunByOperationSnapshot(operation_id) catch |err| return switch (err) {
            error.StoreNotReady => error.StoreNotReady,
            error.StoreCorrupt => error.StoreCorrupt,
            error.OutOfMemory => error.OutOfMemory,
        };
        if (historical) |*record| {
            defer record.deinit(self.allocator);
            if (!std.mem.eql(u8, record.job_id, job.id) or !std.mem.eql(u8, record.server_id, job.server_id)) return error.IdempotencyConflict;
            return .{ .run_id = self.allocator.dupe(u8, record.id) catch return error.OutOfMemory };
        }
        lockSpin(&self.mutex);
        const disconnecting = self.serverDisconnectingLocked(job.server_id);
        self.mutex.unlock();
        if (disconnecting) return error.SessionNotReady;
        self.runs.lock();
        defer self.runs.unlock();
        for (self.runs.list.items) |run| {
            if (!std.mem.eql(u8, run.operation_id, operation_id)) continue;
            if (!std.mem.eql(u8, run.record.job_id, job.id) or !std.mem.eql(u8, run.record.server_id, job.server_id)) return error.IdempotencyConflict;
            return .{ .run_id = self.allocator.dupe(u8, run.record.id) catch return error.OutOfMemory };
        }
        if (self.runs.runningForServer(job.server_id) != null) return error.Busy;
        const run_id = randomRunId(self.allocator, io) catch return error.OutOfMemory;
        errdefer self.allocator.free(run_id);
        const operation_copy = self.allocator.dupe(u8, operation_id) catch return error.OutOfMemory;
        errdefer self.allocator.free(operation_copy);
        const record_operation_copy = self.allocator.dupe(u8, operation_id) catch return error.OutOfMemory;
        errdefer self.allocator.free(record_operation_copy);
        const phase = self.allocator.dupe(u8, "queued") catch return error.OutOfMemory;
        errdefer self.allocator.free(phase);
        const cleanup_state = self.allocator.dupe(u8, "pending") catch return error.OutOfMemory;
        errdefer self.allocator.free(cleanup_state);
        var job_copy = cloneJobOwned(self.allocator, job.*) catch return error.OutOfMemory;
        errdefer job_copy.deinit(self.allocator);
        var credentials_copy: ?OwnedCredentials = if (credentials) |value| OwnedCredentials.init(self.allocator, value) catch return error.OutOfMemory else null;
        errdefer if (credentials_copy) |*value| value.deinit(self.allocator);
        const job_id = self.allocator.dupe(u8, job.id) catch return error.OutOfMemory;
        errdefer self.allocator.free(job_id);
        const server_id = self.allocator.dupe(u8, job.server_id) catch return error.OutOfMemory;
        errdefer self.allocator.free(server_id);
        const source = self.allocator.dupe(u8, "manual") catch return error.OutOfMemory;
        errdefer self.allocator.free(source);
        const receipt_id = self.allocator.dupe(u8, run_id) catch return error.OutOfMemory;
        errdefer self.allocator.free(receipt_id);
        const run = self.allocator.create(LiveRun) catch return error.OutOfMemory;
        errdefer self.allocator.destroy(run);
        run.* = .{
            .record = .{
                .id = run_id,
                .job_id = job_id,
                .server_id = server_id,
                .operation_id = record_operation_copy,
                .source = source,
                .status = .queued,
                .started_at_ns = now_ns,
            },
            .operation_id = operation_copy,
            .phase = phase,
            .cleanup_state = cleanup_state,
            .job = job_copy,
            .credentials = credentials_copy,
            .plan_hash = runPlanHash(job),
        };
        self.runs.list.append(self.allocator, run) catch return error.OutOfMemory;
        return .{ .run_id = receipt_id };
    }

    pub fn runSnapshot(self: *Registry, run_id: []const u8, cursor_value: u64) !?RunSnapshot {
        self.runs.lock();
        defer self.runs.unlock();
        const run = self.runs.byId(run_id) orelse return null;
        const cursor = @max(cursor_value, run.log_start);
        const offset: usize = @intCast(@min(cursor - run.log_start, run.live_log.items.len));
        const delta_len = @min(@as(usize, 256 * 1024), run.live_log.items.len - offset);
        const id_copy = try self.allocator.dupe(u8, run.record.id);
        errdefer self.allocator.free(id_copy);
        const phase_copy = try self.allocator.dupe(u8, run.phase);
        errdefer self.allocator.free(phase_copy);
        const delta = try self.allocator.dupe(u8, run.live_log.items[offset .. offset + delta_len]);
        errdefer self.allocator.free(delta);
        const cleanup_copy = try self.allocator.dupe(u8, run.cleanup_state);
        errdefer self.allocator.free(cleanup_copy);
        return .{
            .run_id = id_copy,
            .status = run.record.status,
            .phase = phase_copy,
            .bytes_done = run.record.bytes_done,
            .bytes_total = run.record.bytes_total,
            .files_done = run.record.files_done,
            .files_total = run.record.files_total,
            .speed_bps = run.speed_bps,
            .eta_sec = run.eta_sec,
            .started_at_ms = @divFloor(run.record.started_at_ns, std.time.ns_per_ms),
            .finished_at_ms = if (run.record.finished_at_ns > 0) @divFloor(run.record.finished_at_ns, std.time.ns_per_ms) else null,
            .log_cursor = cursor + delta_len,
            .log_delta = delta,
            .dropped = cursor - cursor_value,
            .cleanup_state = cleanup_copy,
            .failure = if (run.failure) |failure| try failure.clone(self.allocator) else null,
        };
    }

    pub fn cancelRun(self: *Registry, run_id: []const u8) bool {
        self.runs.lock();
        defer self.runs.unlock();
        const run = self.runs.byId(run_id) orelse return false;
        if (run.record.status.terminal()) {
            if (run.record.status != .partial or !std.mem.eql(u8, run.cleanup_state, "failed") or (run.temp_config.len == 0 and run.state_dir_path.len == 0)) return true;
            run.cleanup_retry = true;
            run.cancel_requested = false;
            run.cancel_verified = false;
            run.finalized = false;
            run.admission_reported = false;
            run.terminal_reported = false;
            run.audit_attempt +|= 1;
            run.record.status = .queued;
            run.record.finished_at_ns = 0;
            self.replaceRunText(&run.phase, "cleanup_retry_queued");
            self.replaceRunText(&run.cleanup_state, "pending");
            return true;
        }
        run.cancel_requested = true;
        run.record.status = .cancel_requested;
        if (run.phase.len > 0) self.allocator.free(run.phase);
        run.phase = self.allocator.dupe(u8, "cancel_requested") catch "";
        return true;
    }

    pub fn setStatus(self: *Registry, server_id: []const u8, value: []const u8, stale: bool, now_ms: i64) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.statuses.items) |status| {
            if (!std.mem.eql(u8, status.server_id, server_id)) continue;
            const copy = try self.allocator.dupe(u8, value);
            if (status.json) |old| self.allocator.free(old);
            status.json = copy;
            status.stale = stale;
            status.updated_at_ms = now_ms;
            return;
        }
        const status = try self.allocator.create(CachedServerStatus);
        status.* = .{ .stale = stale, .updated_at_ms = now_ms };
        errdefer {
            status.deinit(self.allocator);
            self.allocator.destroy(status);
        }
        status.server_id = try self.allocator.dupe(u8, server_id);
        status.json = try self.allocator.dupe(u8, value);
        try self.statuses.append(self.allocator, status);
    }

    fn setRuntimeFacts(self: *Registry, server_id: []const u8, facts_value: *const RuntimeFacts, value: []const u8, now_ms: i64) !void {
        var facts = try facts_value.clone(self.allocator);
        var facts_owned = true;
        errdefer if (facts_owned) facts.deinit(self.allocator);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.statuses.items) |status| {
            if (!std.mem.eql(u8, status.server_id, server_id)) continue;
            const copy = try self.allocator.dupe(u8, value);
            if (status.json) |old| self.allocator.free(old);
            if (status.facts) |*old| old.deinit(self.allocator);
            status.json = copy;
            status.facts = facts;
            facts_owned = false;
            status.stale = false;
            status.updated_at_ms = now_ms;
            return;
        }
        const status = try self.allocator.create(CachedServerStatus);
        status.* = .{ .stale = false, .updated_at_ms = now_ms };
        errdefer {
            status.deinit(self.allocator);
            self.allocator.destroy(status);
        }
        status.server_id = try self.allocator.dupe(u8, server_id);
        status.json = try self.allocator.dupe(u8, value);
        status.facts = facts;
        facts_owned = false;
        try self.statuses.append(self.allocator, status);
    }

    pub fn runtimeFactsSnapshot(self: *Registry, server_id: []const u8) !?RuntimeFactsSnapshot {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.statuses.items) |status| {
            if (!std.mem.eql(u8, status.server_id, server_id)) continue;
            const facts = status.facts orelse return null;
            return .{ .facts = try facts.clone(self.allocator) };
        }
        return null;
    }

    pub fn statusSnapshot(self: *Registry, server_id: []const u8) !?StatusSnapshot {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.statuses.items) |status| {
            if (!std.mem.eql(u8, status.server_id, server_id)) continue;
            return .{
                .stale = status.stale,
                .json = if (status.json) |value| try self.allocator.dupe(u8, value) else null,
            };
        }
        return null;
    }

    fn operationEventLocked(self: *Registry, op: *const BackupOperation, admitted: bool) !OperationEvent {
        var event = OperationEvent{
            .operation_id = "",
            .kind = op.kind,
            .server_id = "",
            .job_id = "",
            .state = if (admitted) .queued else op.state,
            .admitted = admitted,
            .failure_code = if (!admitted and op.failure != null) op.failure.?.code else null,
            .plan_hash = op.plan_hash,
            .audit_attempt = op.audit_attempt,
        };
        errdefer event.deinit(self.allocator);
        event.operation_id = try self.allocator.dupe(u8, op.id);
        event.server_id = try dupOrLiteral(self.allocator, op.server_id);
        event.job_id = try dupOrLiteral(self.allocator, op.job_id);
        return event;
    }

    fn nextEvent(self: *Registry) !?EventDispatch {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        // Audit only a state that is already recoverable from the operation
        // journal. This keeps admission and terminal audit claims aligned
        // with the durable coordinator state.
        if (!self.journal_loaded or self.journal_persisted_generation != self.journal_generation) return null;
        const observer = self.observer orelse return null;
        for (self.ops.items) |op| {
            if (!op.admission_reported) {
                const event = try self.operationEventLocked(op, true);
                return .{ .observer = observer, .event = event };
            }
            if (op.state.terminal() and !op.terminal_reported) {
                const event = try self.operationEventLocked(op, false);
                return .{ .observer = observer, .event = event };
            }
        }
        return null;
    }

    fn acknowledgeOperationEvent(self: *Registry, event: *const OperationEvent) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.ops.items) |op| {
            if (!std.mem.eql(u8, op.id, event.operation_id)) continue;
            if (event.admitted) op.admission_reported = true else op.terminal_reported = true;
            return;
        }
    }

    fn operationAuditFailed(self: *Registry, event: *const OperationEvent) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.ops.items) |op| {
            if (!std.mem.eql(u8, op.id, event.operation_id)) continue;
            if (event.admitted and !op.state.terminal()) {
                op.state = .failed;
                op.finished_at_ms = self.nowMs();
                if (op.failure) |*old| old.deinit(self.allocator);
                op.failure = BackupFailure.init(self.allocator, .store_corrupt, "durable backup admission audit failed", true, "audit") catch null;
                self.finishStepsLocked(op, .failed);
                self.clearCredentialsLocked(op);
            } else if (!event.admitted and op.state == .done) {
                op.state = .partial;
                if (op.failure) |*old| old.deinit(self.allocator);
                op.failure = BackupFailure.init(self.allocator, .store_corrupt, "backup completed but durable terminal audit failed", true, "audit") catch null;
            }
            self.markJournalDirtyLocked();
            return;
        }
    }

    fn acknowledgeRunEvent(self: *Registry, event: *const RunEvent) void {
        self.runs.lock();
        defer self.runs.unlock();
        const run = self.runs.byId(event.run_id) orelse return;
        if (event.admitted) {
            run.admission_reported = true;
        } else {
            run.terminal_reported = true;
            self.runs.evictCompleted();
        }
    }

    fn runAuditFailed(self: *Registry, event: *const RunEvent) void {
        const io = self.io orelse return;
        self.runs.lock();
        const run = self.runs.byId(event.run_id) orelse {
            self.runs.unlock();
            return;
        };
        if (event.admitted and !run.record.status.terminal()) {
            run.record.status = .partial;
            run.outcome_status = .failed;
            run.record.finished_at_ns = @intCast(std.Io.Timestamp.now(io, .real).nanoseconds);
            self.replaceRunText(&run.phase, "finished");
            if (run.credentials) |*credentials| credentials.deinit(self.allocator);
            run.credentials = null;
            run.finalized = true;
        } else if (!event.admitted and (run.record.status == .success or run.record.status == .no_changes)) {
            run.record.status = .partial;
        } else {
            self.runs.unlock();
            return;
        }
        if (run.failure) |*old| old.deinit(self.allocator);
        run.failure = BackupFailure.init(self.allocator, .store_corrupt, "backup run could not durably append its audit outcome", true, "audit") catch null;
        if (run.record.@"error") |old| self.allocator.free(old);
        run.record.@"error" = dupOrLiteral(self.allocator, "backup run could not durably append its audit outcome") catch null;
        var record = HistoryStore.cloneRun(self.allocator, run.record) catch null;
        self.runs.unlock();
        if (record) |*value| {
            self.history.append(io, value, value.finished_at_ns) catch {};
            self.upsertCachedHistory(value) catch {};
            value.deinit(self.allocator);
        }
    }

    fn drainEvents(self: *Registry) void {
        while (self.nextEvent() catch null) |dispatch_value| {
            var dispatch = dispatch_value;
            const delivered = dispatch.observer.notify(dispatch.observer.context, &dispatch.event);
            if (delivered) self.acknowledgeOperationEvent(&dispatch.event) else self.operationAuditFailed(&dispatch.event);
            dispatch.deinit(self.allocator);
            if (!delivered) return;
        }
        while (self.nextRunEvent() catch null) |event_value| {
            var event = event_value;
            const observer = self.observer orelse {
                event.deinit(self.allocator);
                break;
            };
            const notify = observer.notify_run orelse {
                event.deinit(self.allocator);
                break;
            };
            const delivered = notify(observer.context, &event);
            if (delivered) self.acknowledgeRunEvent(&event) else self.runAuditFailed(&event);
            event.deinit(self.allocator);
            if (!delivered) return;
        }
    }

    fn nextRunEvent(self: *Registry) !?RunEvent {
        const observer = self.observer orelse return null;
        if (observer.notify_run == null) return null;
        self.runs.lock();
        defer self.runs.unlock();
        for (self.runs.list.items) |run| {
            const admitted = !run.admission_reported;
            const terminal = run.record.status.terminal() and !run.terminal_reported;
            if (!admitted and !terminal) continue;
            const operation_id = try self.allocator.dupe(u8, run.operation_id);
            errdefer self.allocator.free(operation_id);
            const run_id = try self.allocator.dupe(u8, run.record.id);
            errdefer self.allocator.free(run_id);
            const server_id = try self.allocator.dupe(u8, run.record.server_id);
            errdefer self.allocator.free(server_id);
            const job_id = try self.allocator.dupe(u8, run.record.job_id);
            return .{
                .operation_id = operation_id,
                .run_id = run_id,
                .server_id = server_id,
                .job_id = job_id,
                .status = if (admitted) .queued else run.record.status,
                .admitted = admitted,
                .failure_code = if (!admitted and run.failure != null) run.failure.?.code else null,
                .plan_hash = run.plan_hash,
                .audit_attempt = run.audit_attempt,
            };
        }
        return null;
    }

    fn claimNextWork(self: *Registry, now_ms: i64) !?OperationWork {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.ops.items) |op| {
            if (op.state != .queued) continue;
            // The durable admission audit is the execution barrier. Bridge
            // admission can return immediately, but the coordinator must not
            // claim work until the observer has acknowledged that record.
            if (!op.admission_reported) continue;
            var work = OperationWork{
                .operation_id = "",
                .kind = op.kind,
                .server_id = "",
                .job_id = "",
                .payload_json = "",
                .remote_object = "",
                .remote_required = op.remote_required,
                .sync_advance_approved = op.sync_advance_approved,
            };
            errdefer work.deinit(self.allocator);
            work.operation_id = try self.allocator.dupe(u8, op.id);
            work.server_id = try dupOrLiteral(self.allocator, op.server_id);
            work.job_id = try dupOrLiteral(self.allocator, op.job_id);
            work.payload_json = try dupOrLiteral(self.allocator, op.payload_json);
            work.remote_object = try dupOrLiteral(self.allocator, op.remote_object);
            if (op.credentials) |credentials| {
                work.credentials = try OwnedCredentials.init(self.allocator, .{ .access_key = credentials.access_key, .secret_key = credentials.secret_key });
            }
            if (op.cleanup_task) |task| work.cleanup_task = try task.clone(self.allocator);
            op.state = .running;
            op.touched_at_ms = now_ms;
            if (op.steps.items.len > 0) op.steps.items[0].state = .running;
            self.markJournalDirtyLocked();
            return work;
        }
        return null;
    }

    fn remoteAdapter(self: *Registry) ?RemoteAdapter {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.remote;
    }

    const RemoteCallError = error{ NotConnected, SessionNotReady, Interrupted, OutOfMemory };
    const shutdown_remote_wait_ns: i128 = 2 * std.time.ns_per_s;
    const remote_outcome_slack_ns: i128 = 5 * std.time.ns_per_s;

    fn remoteCall(self: *Registry, server_id: []const u8, request: sessions.BackupRequest) RemoteCallError!sessions.BackupOutcome.Result {
        return self.remoteCallMode(server_id, request, false, false);
    }

    fn cleanupRemoteCall(self: *Registry, server_id: []const u8, request: sessions.BackupRequest) RemoteCallError!sessions.BackupOutcome.Result {
        return self.remoteCallMode(server_id, request, true, false);
    }

    fn remoteCallSensitive(self: *Registry, server_id: []const u8, request: sessions.BackupRequest, allow_shutdown: bool) RemoteCallError!sessions.BackupOutcome.Result {
        return self.remoteCallMode(server_id, request, allow_shutdown, true);
    }

    fn remoteCallMode(self: *Registry, server_id: []const u8, request: sessions.BackupRequest, allow_shutdown: bool, sensitive_result: bool) RemoteCallError!sessions.BackupOutcome.Result {
        const adapter = self.remoteAdapter() orelse return error.NotConnected;
        const outcome = self.allocator.create(sessions.BackupOutcome) catch return error.OutOfMemory;
        outcome.* = .{ .allocator = self.allocator, .sensitive_result = sensitive_result };
        if (allow_shutdown) adapter.submitCleanup(server_id, request, outcome) catch |err| {
            self.allocator.destroy(outcome);
            return switch (err) {
                error.NoSession => error.NotConnected,
                error.NotReady => error.SessionNotReady,
                else => error.OutOfMemory,
            };
        } else adapter.submit(server_id, request, outcome) catch |err| {
            self.allocator.destroy(outcome);
            return switch (err) {
                error.NoSession => error.NotConnected,
                error.NotReady => error.SessionNotReady,
                else => error.OutOfMemory,
            };
        };
        const io = self.io orelse {
            if (outcome.abandon()) {
                outcome.deinitData();
                self.allocator.destroy(outcome);
            }
            return error.Interrupted;
        };
        const requested_wait: i128 = switch (request) {
            .exec => |value| value.timeout_ns + remote_outcome_slack_ns,
            else => 30 * std.time.ns_per_s,
        };
        const max_wait = if (allow_shutdown and self.stop.load(.acquire)) shutdown_remote_wait_ns else requested_wait;
        const deadline = std.Io.Timestamp.now(io, .real).nanoseconds + max_wait;
        while (!outcome.isDone()) {
            if ((!allow_shutdown and self.stop.load(.acquire)) or std.Io.Timestamp.now(io, .real).nanoseconds >= deadline) {
                if (outcome.abandon()) {
                    outcome.deinitData();
                    self.allocator.destroy(outcome);
                }
                return error.Interrupted;
            }
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(coordinator_idle_ms), .awake) catch {};
        }
        const result = outcome.copyResult(self.allocator) catch {
            outcome.deinitData();
            self.allocator.destroy(outcome);
            return error.OutOfMemory;
        };
        outcome.deinitData();
        self.allocator.destroy(outcome);
        return result;
    }

    fn remoteFailure(self: *Registry, err: RemoteCallError, step: []const u8) Completion {
        const code: FailureCode = switch (err) {
            error.NotConnected => .not_connected,
            error.SessionNotReady => .session_not_ready,
            error.Interrupted => .interrupted,
            error.OutOfMemory => .internal,
        };
        return .{ .state = .failed, .failure = BackupFailure.init(self.allocator, code, @errorName(err), code == .not_connected or code == .session_not_ready, step) catch null };
    }

    fn remoteResultFailure(self: *Registry, result: *const sessions.BackupOutcome.Result, step: []const u8) ?Completion {
        if (result.code == .ok and result.exit != null and result.exit.? == 0) return null;
        const code: FailureCode = switch (result.code) {
            .timeout => .timeout,
            .disconnected => .interrupted,
            .not_found => .not_found,
            .permission_denied => .permission_denied,
            .too_large => .source_too_large,
            .conflict => .conflict,
            .unsupported => .unsupported_target,
            .transport => .transport_error,
            .internal => .internal,
            .ok => .capability_failed,
        };
        const message = if (result.message.len > 0) result.message else "remote backup request failed";
        return .{ .state = .failed, .failure = BackupFailure.init(self.allocator, code, message, code == .timeout or code == .transport_error, step) catch null };
    }

    fn unsupportedCompletion(self: *Registry, step: []const u8, message: []const u8) Completion {
        return .{
            .state = .failed,
            .failure = BackupFailure.init(self.allocator, .unsupported_target, message, false, step) catch null,
        };
    }

    fn execRemote(self: *Registry, server_id: []const u8, command: []const u8, stdin_data: ?[]const u8, history_command: []const u8, cap: usize, timeout_seconds: i128, sensitive_stdin: bool) RemoteCallError!sessions.BackupOutcome.Result {
        return self.execRemoteMode(server_id, command, stdin_data, history_command, cap, timeout_seconds, sensitive_stdin, false);
    }

    fn execRemoteCleanup(self: *Registry, server_id: []const u8, command: []const u8, stdin_data: ?[]const u8, history_command: []const u8, cap: usize, timeout_seconds: i128, sensitive_stdin: bool) RemoteCallError!sessions.BackupOutcome.Result {
        return self.execRemoteMode(server_id, command, stdin_data, history_command, cap, timeout_seconds, sensitive_stdin, true);
    }

    fn execRemoteMode(self: *Registry, server_id: []const u8, command: []const u8, stdin_data: ?[]const u8, history_command: []const u8, cap: usize, timeout_seconds: i128, sensitive_stdin: bool, allow_shutdown: bool) RemoteCallError!sessions.BackupOutcome.Result {
        const request: sessions.BackupRequest = .{ .exec = .{
            .command = command,
            .stdin_data = stdin_data,
            .timeout_ns = timeout_seconds * std.time.ns_per_s,
            .cap = cap,
            .history_command = history_command,
            .sensitive_stdin = sensitive_stdin,
        } };
        return if (allow_shutdown) self.cleanupRemoteCall(server_id, request) else self.remoteCall(server_id, request);
    }

    fn completionFailure(self: *Registry, code: FailureCode, message: []const u8, retryable: bool, step: []const u8) Completion {
        return .{ .state = .failed, .failure = BackupFailure.init(self.allocator, code, message, retryable, step) catch null };
    }

    fn cleanupRequiredResult(self: *Registry, job_id: []const u8, needs_credentials: bool) ?[]u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"cleanup\":\"required\",\"retry_action\":\"operationCancel\",\"needs_credentials\":{s},\"job_id\":\"{s}\"}}",
            .{ if (needs_credentials) "true" else "false", job_id },
        ) catch null;
    }

    fn reconciliationFailure(self: *Registry, kind: CleanupTaskKind, code: FailureCode, message: []const u8, step: []const u8, path: []const u8) Completion {
        var completion = Completion{
            .state = .partial,
            .failure = BackupFailure.init(self.allocator, code, message, true, step) catch null,
            .cleanup_task = .{ .kind = kind },
        };
        if (path.len > 0) {
            if (completion.failure) |*failure| failure.path = dupOrLiteral(self.allocator, path) catch "";
        }
        return completion;
    }

    fn setFailureRemoteObject(self: *Registry, completion: *Completion, remote_object: []const u8) void {
        if (completion.failure) |*failure| failure.remote_object = dupOrLiteral(self.allocator, remote_object) catch "";
    }

    fn remotePathAbsent(self: *Registry, server_id: []const u8, path: []const u8, allow_shutdown: bool) bool {
        var result = (if (allow_shutdown)
            self.cleanupRemoteCall(server_id, .{ .sftp_stat = .{ .path = path } })
        else
            self.remoteCall(server_id, .{ .sftp_stat = .{ .path = path } })) catch return false;
        defer result.deinit(self.allocator, false);
        return result.code == .not_found;
    }

    fn removeRemoteFileMode(self: *Registry, server_id: []const u8, path: []const u8, allow_shutdown: bool) bool {
        var result = (if (allow_shutdown)
            self.cleanupRemoteCall(server_id, .{ .sftp_remove = .{ .path = path } })
        else
            self.remoteCall(server_id, .{ .sftp_remove = .{ .path = path } })) catch return false;
        defer result.deinit(self.allocator, false);
        if (result.code != .ok and result.code != .not_found) return false;
        return self.remotePathAbsent(server_id, path, allow_shutdown);
    }

    fn removeRemoteFile(self: *Registry, server_id: []const u8, path: []const u8) bool {
        return self.removeRemoteFileMode(server_id, path, false);
    }

    fn removeRemoteFileDuringShutdown(self: *Registry, server_id: []const u8, path: []const u8) bool {
        return self.removeRemoteFileMode(server_id, path, true);
    }

    const ImportWarning = enum {
        unknown_record,
        malformed_status,
        oversized_record,
        ownership_conflict,
        audit_failed,
        cleanup_failed,
        store_failed,
    };

    const ImportSummary = struct {
        imported: usize = 0,
        warning_count: usize = 0,
        warnings: [std.meta.tags(ImportWarning).len]bool = [_]bool{false} ** std.meta.tags(ImportWarning).len,

        fn warn(self: *ImportSummary, kind: ImportWarning) void {
            self.warning_count += 1;
            self.warnings[@intFromEnum(kind)] = true;
        }

        fn messages(self: *const ImportSummary, out: *[std.meta.tags(ImportWarning).len][]const u8) []const []const u8 {
            var count: usize = 0;
            const descriptions = [_][]const u8{
                "unknown or unpaired staged backup files were retained",
                "malformed or unsupported staged status records were retained",
                "oversized staged status or log records were retained",
                "a staged run ID conflicts with local history ownership and was retained",
                "an imported run audit record could not be verified and the staged pair was retained",
                "an imported staged pair could not be removed and remains retryable",
                "the local backup store could not be read or updated during import",
            };
            for (self.warnings, 0..) |present, index| {
                if (!present) continue;
                out[count] = descriptions[index];
                count += 1;
            }
            return out[0..count];
        }
    };

    fn remoteNamePresent(names: []const []u8, expected: []const u8) bool {
        for (names) |name| if (std.mem.eql(u8, name, expected)) return true;
        return false;
    }

    fn notifyImportedRun(self: *Registry, record: *const RunRecord) bool {
        lockSpin(&self.mutex);
        const observer = self.observer;
        self.mutex.unlock();
        const selected = observer orelse return true;
        const notify = selected.notify_run orelse return true;
        var operation_buf: [160]u8 = undefined;
        const operation_id = std.fmt.bufPrint(&operation_buf, "import:{s}", .{record.id}) catch "import";
        const event = RunEvent{
            .operation_id = operation_id,
            .run_id = record.id,
            .server_id = record.server_id,
            .job_id = record.job_id,
            .status = record.status,
            .admitted = false,
            .plan_hash = auditPlanHash("scheduled_import", record.server_id, record.job_id, record.id),
        };
        return notify(selected.context, &event);
    }

    fn importScheduledRuns(self: *Registry, io: std.Io, server_id: []const u8, facts: *const RuntimeFacts, now_ms: i64) ImportSummary {
        var summary: ImportSummary = .{};
        const jobs = self.jobs.listForServer(io, server_id) catch {
            summary.warn(.store_failed);
            return summary;
        };
        defer {
            for (jobs) |*job| job.deinit(self.allocator);
            self.allocator.free(jobs);
        }
        for (jobs) |*job| {
            if (!job.schedule.enabled) continue;
            const runs_dir = std.fmt.allocPrint(self.allocator, "{s}/.local/state/oars/backups/{s}/runs", .{ facts.home, job.id }) catch {
                summary.warn(.store_failed);
                continue;
            };
            defer self.allocator.free(runs_dir);
            const names = self.listRemoteNames(server_id, runs_dir) catch {
                summary.warn(.unknown_record);
                continue;
            };
            defer {
                for (names) |name| self.allocator.free(name);
                self.allocator.free(names);
            }
            for (names) |name| {
                if (!validStagedName(name)) {
                    summary.warn(.unknown_record);
                    continue;
                }
                if (std.mem.endsWith(u8, name, ".log")) {
                    const base = name[0 .. name.len - ".log".len];
                    const expected_status = std.fmt.allocPrint(self.allocator, "{s}.status", .{base}) catch {
                        summary.warn(.store_failed);
                        continue;
                    };
                    defer self.allocator.free(expected_status);
                    if (!remoteNamePresent(names, expected_status)) summary.warn(.unknown_record);
                    continue;
                }
                if (!std.mem.endsWith(u8, name, ".status")) {
                    summary.warn(.unknown_record);
                    continue;
                }
                const status_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ runs_dir, name }) catch {
                    summary.warn(.store_failed);
                    continue;
                };
                defer self.allocator.free(status_path);
                const status_bytes_opt = self.readRemoteFile(server_id, status_path, 64 * 1024) catch |err| {
                    summary.warn(if (err == error.RemoteTooLarge) .oversized_record else .unknown_record);
                    continue;
                };
                const status_bytes = status_bytes_opt orelse {
                    summary.warn(.unknown_record);
                    continue;
                };
                defer self.allocator.free(status_bytes);
                var parsed = std.json.parseFromSlice(StagedStatus, self.allocator, status_bytes, .{ .allocate = .alloc_always }) catch {
                    summary.warn(.malformed_status);
                    continue;
                };
                defer parsed.deinit();
                const staged = parsed.value;
                if (staged.v != wrapper_version or
                    !validId(staged.run_id) or
                    !std.mem.eql(u8, staged.server_id, server_id) or
                    !std.mem.eql(u8, staged.job_id, job.id) or
                    staged.job_revision != job.revision or
                    !std.mem.eql(u8, staged.cleanup_state, "complete") or
                    staged.finished_at < staged.started_at or
                    !validEpochSeconds(staged.started_at) or
                    !validEpochSeconds(staged.finished_at))
                {
                    summary.warn(.malformed_status);
                    continue;
                }
                const base = name[0 .. name.len - ".status".len];
                if (!std.mem.eql(u8, base, staged.run_id)) {
                    summary.warn(.malformed_status);
                    continue;
                }
                const log_name = std.fmt.allocPrint(self.allocator, "{s}.log", .{base}) catch {
                    summary.warn(.store_failed);
                    continue;
                };
                defer self.allocator.free(log_name);
                const log_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ runs_dir, log_name }) catch {
                    summary.warn(.store_failed);
                    continue;
                };
                defer self.allocator.free(log_path);
                const log_opt = self.readRemoteFile(server_id, log_path, 1024 * 1024) catch |err| {
                    summary.warn(if (err == error.RemoteTooLarge) .oversized_record else .unknown_record);
                    continue;
                };
                const log_bytes = log_opt orelse {
                    summary.warn(.unknown_record);
                    continue;
                };
                defer self.allocator.free(log_bytes);
                const stats = lastStatsFromLog(self.allocator, log_bytes);
                const run_status = stagedRunStatus(staged.status, staged.exit, stats.stats.files_done) orelse {
                    summary.warn(.malformed_status);
                    continue;
                };
                var record = importedRunRecord(self.allocator, staged, job, server_id, run_status, stats.stats) catch {
                    summary.warn(.malformed_status);
                    continue;
                };
                defer record.deinit(self.allocator);
                record.trimLog(self.allocator, log_bytes) catch {
                    summary.warn(.store_failed);
                    continue;
                };
                if (stats.@"error".len > 0) {
                    record.@"error" = self.allocator.dupe(u8, stats.@"error") catch {
                        summary.warn(.store_failed);
                        continue;
                    };
                    record.error_code = .capability_failed;
                    record.error_retryable = true;
                } else if (std.mem.eql(u8, staged.status, "source_missing")) {
                    record.@"error" = self.allocator.dupe(u8, "backup source does not exist") catch {
                        summary.warn(.store_failed);
                        continue;
                    };
                    record.error_code = .source_missing;
                    record.error_retryable = false;
                } else if (std.mem.eql(u8, staged.status, "source_unreadable")) {
                    record.@"error" = self.allocator.dupe(u8, "backup source is not readable") catch {
                        summary.warn(.store_failed);
                        continue;
                    };
                    record.error_code = .source_unreadable;
                    record.error_retryable = false;
                }
                var existing_record = self.history.findRun(io, record.id) catch {
                    summary.warn(.store_failed);
                    continue;
                };
                const existed = existing_record != null;
                if (existing_record) |*existing| {
                    if (!std.mem.eql(u8, existing.server_id, server_id) or !std.mem.eql(u8, existing.job_id, job.id)) {
                        existing.deinit(self.allocator);
                        summary.warn(.ownership_conflict);
                        continue;
                    }
                    existing.deinit(self.allocator);
                }
                const now_ns = std.math.mul(i64, now_ms, std.time.ns_per_ms) catch {
                    summary.warn(.store_failed);
                    continue;
                };
                self.history.append(io, &record, now_ns) catch |err| {
                    summary.warn(if (err == error.RunIdConflict) .ownership_conflict else .store_failed);
                    continue;
                };
                self.upsertCachedHistory(&record) catch {
                    summary.warn(.store_failed);
                    continue;
                };
                // The staged pair remains the durable retry record until its
                // imported-result audit row is present. The audit adapter is
                // idempotent by run ID, so a retry cannot create duplicates.
                if (!self.notifyImportedRun(&record)) {
                    summary.warn(.audit_failed);
                    continue;
                }
                // The status is the retry record. Remove and verify the log
                // first; remove the status only after its pair is absent.
                if (!self.removeRemoteFile(server_id, log_path)) {
                    summary.warn(.cleanup_failed);
                    continue;
                }
                if (!self.removeRemoteFile(server_id, status_path)) {
                    summary.warn(.cleanup_failed);
                    continue;
                }
                if (!existed) summary.imported += 1;
            }
        }
        return summary;
    }

    fn refreshCompletion(self: *Registry, work: *const OperationWork, now_ms: i64) Completion {
        var probe = self.execRemote(work.server_id, runtime_probe_command, null, "probe backup runtime", 256 * 1024, 20, false) catch |err| return self.remoteFailure(err, "probe");
        defer probe.deinit(self.allocator, false);
        if (self.remoteResultFailure(&probe, "probe")) |failure| return failure;
        var facts = parseRuntimeFacts(self.allocator, probe.data, now_ms) catch return self.completionFailure(.unsupported_target, "remote runtime probe returned invalid or oversized facts", false, "probe");
        defer facts.deinit(self.allocator);
        if (facts.crontab_read == .denied) return self.completionFailure(.permission_denied, "crontab exists but cannot be read by the connected account", false, "probe");
        if (facts.crontab_read == .failed) return self.completionFailure(.transport_error, "crontab could not be read; refusing to treat it as empty", true, "probe");
        const imported = self.importScheduledRuns(self.io.?, work.server_id, &facts, now_ms);
        var warning_buffer: [std.meta.tags(ImportWarning).len][]const u8 = undefined;
        const warning_values = imported.messages(&warning_buffer);
        const status_json = runtimeStatusJson(self.allocator, &facts, warning_values) catch return self.completionFailure(.internal, "could not serialize backup runtime status", false, "probe");
        defer self.allocator.free(status_json);
        self.setRuntimeFacts(work.server_id, &facts, status_json, now_ms) catch return self.completionFailure(.internal, "could not cache backup runtime status", true, "probe");
        const result = std.fmt.allocPrint(self.allocator, "{{\"status\":{s},\"imported\":{d},\"warnings\":{d}}}", .{ status_json, imported.imported, imported.warning_count }) catch null;
        return .{ .state = .done, .result_json = result, .committed = true };
    }

    const SentinelCleanupResult = struct {
        delete_ok: bool = false,
        absent: bool = false,
    };

    fn cleanupExactSentinel(self: *Registry, server_id: []const u8, delete_command: []const u8, verify_command: []const u8) SentinelCleanupResult {
        var result: SentinelCleanupResult = .{};
        if (self.execRemoteCleanup(server_id, delete_command, null, "rclone delete backup sentinel", 256 * 1024, 30, false)) |delete_value| {
            var deleted = delete_value;
            defer deleted.deinit(self.allocator, false);
            if (self.remoteResultFailure(&deleted, "delete")) |failure_value| {
                var failure = failure_value;
                failure.deinit(self.allocator);
            } else {
                result.delete_ok = true;
            }
        } else |_| {}
        if (self.execRemoteCleanup(server_id, verify_command, null, "verify backup sentinel cleanup", 256 * 1024, 30, false)) |verify_value| {
            var verified = verify_value;
            defer verified.deinit(self.allocator, false);
            result.absent = verified.code == .ok and verified.exit != null and verified.exit.? == 0 and std.mem.trim(u8, verified.data, " \t\r\n").len == 0;
        } else |_| {}
        return result;
    }

    fn retainedTestCleanup(self: *Registry, config_path: []const u8, job: *const Job, rclone_path: []const u8, exact_destination: []const u8, remote_object: []const u8) ?CleanupTask {
        const borrowed = CleanupTask{
            .kind = .test_sentinel,
            .config_path = config_path,
            .job = job.*,
            .rclone_path = rclone_path,
            .exact_destination = exact_destination,
            .remote_object = remote_object,
        };
        return borrowed.clone(self.allocator) catch null;
    }

    fn testCompletion(self: *Registry, work: *const OperationWork, now_ms: i64) Completion {
        var parsed = std.json.parseFromSlice(SavePlanPayload, self.allocator, work.payload_json, .{}) catch {
            return self.completionFailure(.internal, "saved connection-test plan is unreadable", false, "list");
        };
        defer parsed.deinit();
        const credentials = work.credentials;
        if (parsed.value.job.destination.credential_mode == .access_key and credentials == null) {
            return self.completionFailure(.invalid_credentials, "connection test credentials are missing", false, "list");
        }
        const transfer = Transfer.fromJsonName(parsed.value.job.transfer) orelse return self.completionFailure(.invalid_job, "saved connection-test transfer is invalid", false, "list");
        const job = Job{
            .id = parsed.value.job.id orelse work.job_id,
            .server_id = parsed.value.job.server_id,
            .name = parsed.value.job.name,
            .source_path = parsed.value.job.source_path,
            .destination = parsed.value.job.destination,
            .transfer = transfer,
            .schedule = parsed.value.job.schedule,
        };
        const remote_name = remoteName(self.allocator, job.id) catch return self.completionFailure(.internal, "could not prepare the test remote", false, "list");
        defer self.allocator.free(remote_name);
        const config = remoteConfigSection(self.allocator, &job, remote_name, if (credentials) |value| value.access_key else null, if (credentials) |value| value.secret_key else null) catch return self.completionFailure(.invalid_credentials, "could not build the test config", false, "list");
        defer secureFree(self.allocator, config);
        // The admitted operation ID is already unique and path-safe. A
        // deterministic path lets restart recovery remove a partially written
        // secret config without storing the secret or guessing a filename.
        const config_path = std.fmt.allocPrint(self.allocator, "/tmp/.oars-{s}.conf", .{work.operation_id}) catch return self.completionFailure(.internal, "could not allocate a temporary config path", false, "list");
        defer self.allocator.free(config_path);
        const sentinel = std.fmt.allocPrint(self.allocator, "oars-sentinel-v1:{s}", .{work.operation_id}) catch return self.completionFailure(.internal, "could not build sentinel content", false, "write");
        defer self.allocator.free(sentinel);
        const base_destination = destinationArg(self.allocator, &job, remote_name) catch return self.completionFailure(.internal, "could not build the test destination", false, "list");
        defer self.allocator.free(base_destination);
        const exact_destination = std.fmt.allocPrint(self.allocator, "{s}:{s}/{s}", .{ remote_name, job.destination.bucket, work.remote_object }) catch return self.completionFailure(.internal, "could not build the exact sentinel destination", false, "write");
        defer self.allocator.free(exact_destination);
        const quoted_config = shellquote.quote(self.allocator, config_path) catch return self.completionFailure(.internal, "could not quote the temporary config path", false, "list");
        defer self.allocator.free(quoted_config);
        const quoted_base = shellquote.quote(self.allocator, base_destination) catch return self.completionFailure(.internal, "could not quote the test destination", false, "list");
        defer self.allocator.free(quoted_base);
        const quoted_exact = shellquote.quote(self.allocator, exact_destination) catch return self.completionFailure(.internal, "could not quote the sentinel destination", false, "write");
        defer self.allocator.free(quoted_exact);

        var probe = self.execRemote(work.server_id, "command -v rclone", null, "probe rclone path", 4096, 10, false) catch |err| return self.remoteFailure(err, "list");
        defer probe.deinit(self.allocator, false);
        if (self.remoteResultFailure(&probe, "list")) |failure| return failure;
        const rclone_path = std.mem.trim(u8, probe.data, " \t\r\n");
        if (rclone_path.len == 0 or rclone_path[0] != '/') return self.completionFailure(.rclone_missing, "rclone was not found at an absolute path", false, "list");
        const quoted_rclone = shellquote.quote(self.allocator, rclone_path) catch return self.completionFailure(.internal, "could not quote rclone path", false, "list");
        defer self.allocator.free(quoted_rclone);
        const list_command = std.fmt.allocPrint(self.allocator, "{s} lsf {s} --config {s} --max-depth 1 --ask-password=false", .{ quoted_rclone, quoted_base, quoted_config }) catch return self.completionFailure(.internal, "could not build list command", false, "list");
        defer self.allocator.free(list_command);
        const write_command = std.fmt.allocPrint(self.allocator, "{s} rcat {s} --config {s} --ask-password=false", .{ quoted_rclone, quoted_exact, quoted_config }) catch return self.completionFailure(.internal, "could not build write command", false, "write");
        defer self.allocator.free(write_command);
        const read_command = std.fmt.allocPrint(self.allocator, "{s} cat {s} --config {s} --ask-password=false", .{ quoted_rclone, quoted_exact, quoted_config }) catch return self.completionFailure(.internal, "could not build read command", false, "read");
        defer self.allocator.free(read_command);
        const delete_command = std.fmt.allocPrint(self.allocator, "{s} deletefile {s} --config {s} --ask-password=false", .{ quoted_rclone, quoted_exact, quoted_config }) catch return self.completionFailure(.internal, "could not build delete command", false, "delete");
        defer self.allocator.free(delete_command);
        const verify_command = std.fmt.allocPrint(self.allocator, "{s} lsf {s} --config {s} --ask-password=false", .{ quoted_rclone, quoted_exact, quoted_config }) catch return self.completionFailure(.internal, "could not build cleanup verification", false, "cleanup_verify");
        defer self.allocator.free(verify_command);

        var terminal_failure: ?Completion = null;
        var list_passed = false;
        var write_passed = false;
        var read_passed = false;
        var sentinel_write_admitted = false;

        // Cleanup ownership is armed before the worker can create even a
        // partial secret file. Every path below converges on exact removal and
        // a worker-owned stat proving absence.
        const config_write_admitted = true;
        self.writeRemoteFile(work.server_id, config_path, config, 0o600, true) catch {
            terminal_failure = self.completionFailure(.transport_error, "temporary backup config write or mode verification failed", true, "list");
        };

        if (terminal_failure == null) {
            if (self.execRemote(work.server_id, list_command, null, "rclone list backup prefix", 256 * 1024, 30, false)) |result_value| {
                var list_result = result_value;
                defer list_result.deinit(self.allocator, false);
                if (self.remoteResultFailure(&list_result, "list")) |failure| terminal_failure = failure else list_passed = true;
            } else |err| terminal_failure = self.remoteFailure(err, "list");
        }

        if (terminal_failure == null) {
            sentinel_write_admitted = true;
            if (self.execRemote(work.server_id, write_command, sentinel, "rclone write backup sentinel", 256 * 1024, 30, false)) |result_value| {
                var write_result = result_value;
                defer write_result.deinit(self.allocator, false);
                if (self.remoteResultFailure(&write_result, "write")) |failure| terminal_failure = failure else write_passed = true;
            } else |err| terminal_failure = self.remoteFailure(err, "write");
        }

        if (terminal_failure == null) {
            if (self.execRemote(work.server_id, read_command, null, "rclone read backup sentinel", 256 * 1024, 30, false)) |result_value| {
                var read_result = result_value;
                defer read_result.deinit(self.allocator, false);
                if (self.remoteResultFailure(&read_result, "read")) |failure| {
                    terminal_failure = failure;
                } else if (!std.mem.eql(u8, read_result.data, sentinel)) {
                    terminal_failure = self.completionFailure(.capability_failed, "sentinel content did not match exactly", false, "read");
                } else read_passed = true;
            } else |err| terminal_failure = self.remoteFailure(err, "read");
        }

        const sentinel_cleanup = if (sentinel_write_admitted) self.cleanupExactSentinel(work.server_id, delete_command, verify_command) else SentinelCleanupResult{};
        const config_removed = !config_write_admitted or self.removeRemoteFileDuringShutdown(work.server_id, config_path);
        if ((sentinel_write_admitted and (!sentinel_cleanup.delete_ok or !sentinel_cleanup.absent)) or !config_removed) {
            if (terminal_failure) |*old| old.deinit(self.allocator);
            var cleanup = self.completionFailure(.cleanup_failed, "connection-test cleanup could not be verified", true, "cleanup_verify");
            cleanup.state = .partial;
            if (cleanup.failure) |*failure| {
                if (!config_removed) failure.path = dupOrLiteral(self.allocator, config_path) catch "";
                if (sentinel_write_admitted and (!sentinel_cleanup.delete_ok or !sentinel_cleanup.absent)) failure.remote_object = dupOrLiteral(self.allocator, work.remote_object) catch "";
            }
            cleanup.cleanup_task = self.retainedTestCleanup(config_path, &job, rclone_path, exact_destination, if (sentinel_write_admitted and !sentinel_cleanup.absent) work.remote_object else "");
            cleanup.result_json = self.cleanupRequiredResult(work.job_id, cleanup.cleanup_task != null and cleanup.cleanup_task.?.remote_object.len > 0 and job.destination.credential_mode == .access_key);
            return cleanup;
        }
        if (terminal_failure) |failure| return failure;
        if (!list_passed or !write_passed or !read_passed or !sentinel_cleanup.delete_ok or !sentinel_cleanup.absent) return self.completionFailure(.capability_failed, "connection test did not complete every required check", false, "cleanup_verify");

        const proof_id = randomId(self.allocator, self.io.?, "proof") catch return self.completionFailure(.internal, "could not create capability proof", false, "cleanup_verify");
        defer self.allocator.free(proof_id);
        const binding_digest = capabilityBinding(parsed.value.job);
        const binding_hex = std.fmt.bytesToHex(binding_digest, .lower);
        const proof_expiry = now_ms + 5 * 60 * 1000;
        self.registerCapabilityProof(proof_id, binding_digest, proof_expiry) catch return self.completionFailure(.internal, "could not retain capability proof", false, "cleanup_verify");
        const result = std.fmt.allocPrint(
            self.allocator,
            "{{\"checks\":{{\"list\":\"passed\",\"write\":\"passed\",\"read\":\"passed\",\"delete\":\"passed\",\"cleanup_verify\":\"passed\"}},\"capability_proof\":{{\"id\":\"{s}\",\"expires_at_ms\":{d},\"binding_sha256\":\"{s}\"}}}}",
            .{ proof_id, proof_expiry, binding_hex },
        ) catch null;
        return .{ .state = .done, .result_json = result, .committed = true };
    }

    const SftpReadWire = struct { ok: bool = false, base64: []const u8 = "", eof: bool = false };
    const SftpStatWire = struct {
        ok: bool = false,
        entry: struct {
            kind: []const u8 = "unknown",
            mode: []const u8 = "",
        } = .{},
    };
    const SftpListWire = struct {
        ok: bool = false,
        truncated: bool = false,
        entries: []const struct {
            name: struct { utf8: ?[]const u8 = null, base64: ?[]const u8 = null } = .{},
            kind: []const u8 = "unknown",
        } = &.{},
    };

    fn listRemoteNames(self: *Registry, server_id: []const u8, path: []const u8) ![][]u8 {
        var result = try self.remoteCall(server_id, .{ .sftp_list = .{ .path = path } });
        defer result.deinit(self.allocator, false);
        if (result.code == .not_found) return try self.allocator.alloc([]u8, 0);
        if (result.code != .ok) return error.RemoteListFailed;
        var parsed = try std.json.parseFromSlice(SftpListWire, self.allocator, result.data, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        if (!parsed.value.ok or parsed.value.truncated) return error.RemoteListFailed;
        var names: std.ArrayList([]u8) = .empty;
        errdefer {
            for (names.items) |name| self.allocator.free(name);
            names.deinit(self.allocator);
        }
        for (parsed.value.entries) |entry| {
            const name = entry.name.utf8 orelse continue;
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            try names.append(self.allocator, try self.allocator.dupe(u8, name));
        }
        return names.toOwnedSlice(self.allocator);
    }

    fn readRemoteFileMode(self: *Registry, server_id: []const u8, path: []const u8, max: usize, allow_shutdown: bool, sensitive: bool) !?[]u8 {
        var result = try (if (sensitive)
            self.remoteCallSensitive(server_id, .{ .sftp_read = .{ .path = path, .max = max } }, allow_shutdown)
        else if (allow_shutdown)
            self.cleanupRemoteCall(server_id, .{ .sftp_read = .{ .path = path, .max = max } })
        else
            self.remoteCall(server_id, .{ .sftp_read = .{ .path = path, .max = max } }));
        defer result.deinit(self.allocator, sensitive);
        if (result.code == .not_found) return null;
        if (result.code != .ok) return error.RemoteReadFailed;
        var parsed = try std.json.parseFromSlice(SftpReadWire, self.allocator, result.data, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        if (!parsed.value.ok or !parsed.value.eof) return error.RemoteTooLarge;
        const size = try std.base64.standard.Decoder.calcSizeForSlice(parsed.value.base64);
        if (size > max) return error.RemoteTooLarge;
        const bytes = try self.allocator.alloc(u8, size);
        errdefer self.allocator.free(bytes);
        try std.base64.standard.Decoder.decode(bytes, parsed.value.base64);
        return bytes;
    }

    fn readRemoteFile(self: *Registry, server_id: []const u8, path: []const u8, max: usize) !?[]u8 {
        return self.readRemoteFileMode(server_id, path, max, false, false);
    }

    fn readRemoteFileSensitive(self: *Registry, server_id: []const u8, path: []const u8, max: usize) !?[]u8 {
        return self.readRemoteFileMode(server_id, path, max, false, true);
    }

    fn readRemoteFileDuringShutdown(self: *Registry, server_id: []const u8, path: []const u8, max: usize) !?[]u8 {
        return self.readRemoteFileMode(server_id, path, max, true, false);
    }

    fn remoteFileAbsent(self: *Registry, server_id: []const u8, path: []const u8) bool {
        return self.remotePathAbsent(server_id, path, false);
    }

    fn expectedModeText(mode: u32, out: *[9]u8) []const u8 {
        const chars = [_]u8{ 'r', 'w', 'x' };
        var index: usize = 0;
        for (0..3) |group| {
            const shift: u5 = @intCast((2 - group) * 3);
            for (0..3) |bit| {
                out[index] = if ((mode >> shift) & (@as(u32, 1) << @intCast(2 - bit)) != 0) chars[bit] else '-';
                index += 1;
            }
        }
        return out;
    }

    fn remoteFileHasMode(self: *Registry, server_id: []const u8, path: []const u8, mode: u32) bool {
        var result = self.remoteCall(server_id, .{ .sftp_stat = .{ .path = path } }) catch return false;
        defer result.deinit(self.allocator, false);
        if (result.code != .ok) return false;
        var parsed = std.json.parseFromSlice(SftpStatWire, self.allocator, result.data, .{ .ignore_unknown_fields = true }) catch return false;
        defer parsed.deinit();
        var mode_buf: [9]u8 = undefined;
        return parsed.value.ok and std.mem.eql(u8, parsed.value.entry.kind, "file") and std.mem.eql(u8, parsed.value.entry.mode, expectedModeText(mode & 0o777, &mode_buf));
    }

    fn writeRemoteFile(self: *Registry, server_id: []const u8, path: []const u8, data: []const u8, mode: u32, sensitive: bool) !void {
        var write_result = try self.remoteCall(server_id, .{ .sftp_write = .{ .path = path, .data = data, .sensitive = sensitive } });
        defer write_result.deinit(self.allocator, false);
        if (write_result.code != .ok) return error.RemoteWriteFailed;
        var chmod_result = try self.remoteCall(server_id, .{ .sftp_chmod = .{ .path = path, .mode = mode } });
        defer chmod_result.deinit(self.allocator, false);
        if (chmod_result.code != .ok) return error.RemoteChmodFailed;
        const readback = (try self.readRemoteFile(server_id, path, @max(data.len, 1))) orelse return error.RemoteReadFailed;
        defer {
            if (sensitive) std.crypto.secureZero(u8, readback);
            self.allocator.free(readback);
        }
        if (!std.mem.eql(u8, readback, data)) return error.RemoteReadFailed;
        if (!self.remoteFileHasMode(server_id, path, mode)) return error.RemoteModeFailed;
    }

    fn ensureRemoteDirectory(self: *Registry, server_id: []const u8, path: []const u8, mode: u32) !void {
        const quoted = try shellquote.quote(self.allocator, path);
        defer self.allocator.free(quoted);
        const command = try std.fmt.allocPrint(self.allocator, "umask 077; mkdir -p {s} && chmod {o} {s}", .{ quoted, mode & 0o7777, quoted });
        defer self.allocator.free(command);
        var result = try self.execRemote(server_id, command, null, "prepare backup state directory", 64 * 1024, 20, false);
        defer result.deinit(self.allocator, false);
        if (result.code != .ok or result.exit != 0) return error.RemoteMkdirFailed;
    }

    fn crontabReconciliationFailure(self: *Registry, kind: CleanupTaskKind, err: anyerror, message: []const u8, step: []const u8, path: []const u8) Completion {
        return self.reconciliationFailure(
            kind,
            if (err == error.CrontabPermissionDenied) .permission_denied else .transport_error,
            message,
            step,
            path,
        );
    }

    fn readRemoteCrontab(self: *Registry, server_id: []const u8, crontab_path: []const u8) ![]u8 {
        const quoted = try shellquote.quote(self.allocator, crontab_path);
        defer self.allocator.free(quoted);
        const command = try std.fmt.allocPrint(
            self.allocator,
            "umask 077; ERR=\"${{TMPDIR:-/tmp}}/.oars-crontab-read-$$\"; {s} -l 2>\"$ERR\"; RC=$?; if [ \"$RC\" -eq 0 ]; then rm -f \"$ERR\"; exit 0; fi; if grep -Eiq 'no crontab|does not exist' \"$ERR\"; then rm -f \"$ERR\"; exit 0; fi; if grep -Eiq 'permission denied|access denied|not allowed|not permitted' \"$ERR\"; then rm -f \"$ERR\"; exit 77; fi; cat \"$ERR\" >&2; rm -f \"$ERR\"; exit \"$RC\"",
            .{quoted},
        );
        defer self.allocator.free(command);
        var result = try self.execRemote(server_id, command, null, "read crontab for backup transaction", 256 * 1024, 20, false);
        defer result.deinit(self.allocator, false);
        if (result.code != .ok) return error.CrontabReadFailed;
        if (result.exit == 77) return error.CrontabPermissionDenied;
        if (result.exit != 0) return error.CrontabReadFailed;
        return try self.allocator.dupe(u8, result.data);
    }

    fn installRemoteCrontab(self: *Registry, server_id: []const u8, crontab_path: []const u8, content: []const u8) !void {
        const quoted = try shellquote.quote(self.allocator, crontab_path);
        defer self.allocator.free(quoted);
        const command = try std.fmt.allocPrint(self.allocator, "{s} -", .{quoted});
        defer self.allocator.free(command);
        var result = try self.execRemote(server_id, command, content, "install backup crontab block", 256 * 1024, 20, false);
        defer result.deinit(self.allocator, false);
        if (result.code != .ok or result.exit != 0) return error.CrontabInstallFailed;
    }

    fn configPath(allocator: std.mem.Allocator, basis: ScheduleBasis) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/.config/oars/rclone.conf", .{basis.home});
    }

    fn jobStatePath(allocator: std.mem.Allocator, basis: ScheduleBasis, job_id: []const u8) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/.local/state/oars/backups/{s}", .{ basis.home, job_id });
    }

    fn scheduleDisableCompletion(self: *Registry, io: std.Io, work: *const OperationWork, planned: SavePlanPayload, now_ms: i64) Completion {
        const previous = planned.previous_job orelse return self.completionFailure(.conflict, "former scheduled job snapshot is missing", false, "validate_plan");
        const basis = planned.schedule_basis orelse return self.completionFailure(.session_not_ready, "schedule plan has no frozen runtime facts", false, "validate_plan");
        const current_crontab = self.readRemoteCrontab(work.server_id, basis.crontab_path) catch |err| return self.crontabReconciliationFailure(.reconcile_save, err, "could not re-read crontab while disabling schedule", "apply_remote", basis.crontab_path);
        defer self.allocator.free(current_crontab);
        const edited = crontabRemove(self.allocator, basis.crontab, previous.id) catch return self.completionFailure(.conflict, "frozen crontab marker block is malformed", false, "apply_remote");
        defer self.allocator.free(edited.content);
        var current_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(current_crontab, &current_hash, .{});
        if (!std.mem.eql(u8, &current_hash, &basis.crontab_sha256) and !std.mem.eql(u8, current_crontab, edited.content)) {
            return self.completionFailure(.conflict, "crontab changed after planning", false, "apply_remote");
        }
        if (!std.mem.eql(u8, current_crontab, edited.content)) {
            self.installRemoteCrontab(work.server_id, basis.crontab_path, edited.content) catch return self.reconciliationFailure(.reconcile_save, .cleanup_failed, "could not remove the former scheduled crontab block", "apply_remote", basis.crontab_path);
            const cron_readback = self.readRemoteCrontab(work.server_id, basis.crontab_path) catch |err| return self.crontabReconciliationFailure(.reconcile_save, err, "crontab removal could not be verified", "apply_remote", basis.crontab_path);
            defer self.allocator.free(cron_readback);
            if (!std.mem.eql(u8, cron_readback, edited.content)) return self.reconciliationFailure(.reconcile_save, .conflict, "crontab removal readback differs", "apply_remote", basis.crontab_path);
        }

        const job_dir = jobStatePath(self.allocator, basis, previous.id) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not build former schedule state path", "apply_remote", "");
        defer self.allocator.free(job_dir);
        const exact_names = [_][]const u8{ "run.sh", "meta.json", "next_due" };
        for (exact_names) |name| {
            const path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ job_dir, name }) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not build former schedule artifact path", "apply_remote", job_dir);
            defer self.allocator.free(path);
            if (!self.removeRemoteFile(work.server_id, path)) return self.reconciliationFailure(.reconcile_save, .cleanup_failed, "former scheduled artifact could not be removed and verified absent", "apply_remote", path);
        }

        const config_path = configPath(self.allocator, basis) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not build scheduled config path", "apply_remote", "");
        defer self.allocator.free(config_path);
        const old_config_opt = self.readRemoteFileSensitive(work.server_id, config_path, 256 * 1024) catch return self.reconciliationFailure(.reconcile_save, .cleanup_failed, "could not read scheduled config while disabling", "apply_remote", config_path);
        if (old_config_opt) |old_config| {
            defer secureFree(self.allocator, old_config);
            const remote_name = remoteName(self.allocator, previous.id) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not build former config section", "apply_remote", config_path);
            defer self.allocator.free(remote_name);
            const without = configRemoveSection(self.allocator, old_config, remote_name) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not remove former config section", "apply_remote", config_path);
            defer secureFree(self.allocator, without);
            if (std.mem.trim(u8, without, " \t\r\n").len == 0) {
                if (!self.removeRemoteFile(work.server_id, config_path)) return self.reconciliationFailure(.reconcile_save, .cleanup_failed, "scheduled config could not be removed and verified absent", "apply_remote", config_path);
            } else {
                self.writeRemoteFile(work.server_id, config_path, without, 0o600, true) catch return self.reconciliationFailure(.reconcile_save, .cleanup_failed, "scheduled config update or mode verification failed", "apply_remote", config_path);
            }
        }

        var saved = self.jobs.savePlanned(io, planned.job, planned.expected_revision, false, now_ms * std.time.ns_per_ms) catch |err| return self.reconciliationFailure(.reconcile_save, .store_corrupt, @errorName(err), "persist_local", self.jobs.path);
        defer saved.deinit(self.allocator);
        self.upsertCachedJob(&saved) catch return self.reconciliationFailure(.reconcile_save, .store_corrupt, "saved job could not be published to the coordinator cache", "persist_local", self.jobs.path);
        return .{ .state = .done, .result_json = std.fmt.allocPrint(self.allocator, "{{\"job_id\":\"{s}\"}}", .{saved.id}) catch null, .committed = true };
    }

    fn scheduleSaveCompletion(self: *Registry, io: std.Io, work: *const OperationWork, planned: SavePlanPayload, now_ms: i64) Completion {
        const basis = planned.schedule_basis orelse return self.completionFailure(.session_not_ready, "schedule plan has no frozen runtime facts", false, "validate_plan");
        if (basis.rclone_path.len == 0) return self.completionFailure(.rclone_missing, "rclone is not available", false, "validate_plan");
        if (basis.crontab_path.len == 0) return self.completionFailure(.cron_missing, "crontab is not available", false, "validate_plan");
        const current_crontab = self.readRemoteCrontab(work.server_id, basis.crontab_path) catch |err| return self.crontabReconciliationFailure(.reconcile_save, err, "could not re-read crontab", "apply_remote", basis.crontab_path);
        defer self.allocator.free(current_crontab);
        var current_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(current_crontab, &current_hash, .{});

        const transfer = Transfer.fromJsonName(planned.job.transfer) orelse return self.completionFailure(.invalid_job, "invalid planned transfer", false, "validate_plan");
        if (transfer == .sync and !work.sync_advance_approved) return self.completionFailure(.invalid_payload, "scheduled sync requires exact job-name advance approval", false, "validate_plan");
        const job = Job{
            .id = planned.job.id orelse work.job_id,
            .server_id = planned.job.server_id,
            .name = planned.job.name,
            .source_path = planned.job.source_path,
            .destination = planned.job.destination,
            .transfer = transfer,
            .schedule = planned.job.schedule,
            .revision = (planned.expected_revision orelse 0) + 1,
        };
        const config_path = configPath(self.allocator, basis) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not build schedule config path", "apply_remote", "");
        defer self.allocator.free(config_path);
        const job_dir = jobStatePath(self.allocator, basis, job.id) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not build schedule state path", "apply_remote", "");
        defer self.allocator.free(job_dir);
        const runs_dir = std.fmt.allocPrint(self.allocator, "{s}/runs", .{job_dir}) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not build runs path", "apply_remote", job_dir);
        defer self.allocator.free(runs_dir);

        const remote_name = remoteName(self.allocator, job.id) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not build remote name", "apply_remote", job_dir);
        defer self.allocator.free(remote_name);
        const credentials = work.credentials;
        const section = remoteConfigSection(self.allocator, &job, remote_name, if (credentials) |value| value.access_key else null, if (credentials) |value| value.secret_key else null) catch return self.reconciliationFailure(.reconcile_save, .invalid_credentials, "could not build scheduled rclone config", "apply_remote", config_path);
        defer secureFree(self.allocator, section);
        const old_config_opt = self.readRemoteFileSensitive(work.server_id, config_path, 256 * 1024) catch return self.reconciliationFailure(.reconcile_save, .transport_error, "could not read scheduled rclone config", "apply_remote", config_path);
        const old_config = old_config_opt orelse self.allocator.dupe(u8, "") catch return self.reconciliationFailure(.reconcile_save, .internal, "out of memory", "apply_remote", config_path);
        defer secureFree(self.allocator, old_config);
        const merged_config = configMergeSection(self.allocator, old_config, remote_name, section) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not merge scheduled rclone config", "apply_remote", config_path);
        defer secureFree(self.allocator, merged_config);

        const wrapper = scheduledWrapper(self.allocator, &job, basis, config_path, job_dir) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not generate scheduled wrapper", "apply_remote", job_dir);
        defer self.allocator.free(wrapper);
        const wrapper_path = std.fmt.allocPrint(self.allocator, "{s}/run.sh", .{job_dir}) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not build wrapper path", "apply_remote", job_dir);
        defer self.allocator.free(wrapper_path);
        const meta_path = std.fmt.allocPrint(self.allocator, "{s}/meta.json", .{job_dir}) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not build metadata path", "apply_remote", job_dir);
        defer self.allocator.free(meta_path);
        var wrapper_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(wrapper, &wrapper_digest, .{});
        const wrapper_hex = std.fmt.bytesToHex(wrapper_digest, .lower);
        const cron_expr = if (std.mem.eql(u8, job.schedule.mode, "custom")) job.schedule.expr else "* * * * *";
        const quoted_wrapper = shellquote.quote(self.allocator, wrapper_path) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not quote wrapper path", "apply_remote", wrapper_path);
        defer self.allocator.free(quoted_wrapper);
        const cron_line = std.fmt.allocPrint(self.allocator, "{s} /bin/sh {s}", .{ cron_expr, quoted_wrapper }) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not build cron line", "apply_remote", basis.crontab_path);
        defer self.allocator.free(cron_line);
        const crontab_edit = crontabAdd(self.allocator, basis.crontab, job.id, cron_line) catch return self.completionFailure(.conflict, "frozen crontab contains duplicate or malformed Oars markers", false, "apply_remote");
        defer self.allocator.free(crontab_edit.content);
        if (!std.mem.eql(u8, &current_hash, &basis.crontab_sha256) and !std.mem.eql(u8, current_crontab, crontab_edit.content)) return self.completionFailure(.conflict, "crontab changed after planning", false, "apply_remote");
        var block_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(crontab_edit.content, &block_digest, .{});
        const block_hex = std.fmt.bytesToHex(block_digest, .lower);
        const meta = std.fmt.allocPrint(self.allocator, "{{\"v\":1,\"job_id\":\"{s}\",\"job_revision\":{d},\"schedule\":\"{s}\",\"source\":\"remote source\",\"destination\":\"s3:{s}\",\"config_section\":\"{s}\",\"wrapper_sha256\":\"{s}\",\"crontab_sha256\":\"{s}\",\"next_due_epoch\":{d},\"sync_advance_approved\":{s},\"retained_runs\":20,\"max_log_bytes\":1048576}}", .{ job.id, job.revision, job.schedule.mode, job.destination.bucket, remote_name, wrapper_hex, block_hex, job.schedule.anchor_epoch_sec, if (job.transfer == .sync) "true" else "false" }) catch return self.reconciliationFailure(.reconcile_save, .internal, "could not generate schedule metadata", "apply_remote", job_dir);
        defer self.allocator.free(meta);

        // No remote mutation is admitted until the frozen crontab is either
        // still current or already equals this operation's exact desired table.
        self.ensureRemoteDirectory(work.server_id, std.fs.path.dirname(config_path) orelse basis.home, 0o700) catch return self.reconciliationFailure(.reconcile_save, .transport_error, "could not prepare remote config directory", "apply_remote", config_path);
        self.ensureRemoteDirectory(work.server_id, runs_dir, 0o700) catch return self.reconciliationFailure(.reconcile_save, .transport_error, "could not prepare remote schedule directory", "apply_remote", runs_dir);
        self.writeRemoteFile(work.server_id, config_path, merged_config, 0o600, true) catch return self.reconciliationFailure(.reconcile_save, .cleanup_failed, "scheduled config write, readback, or mode verification failed", "apply_remote", config_path);
        self.writeRemoteFile(work.server_id, wrapper_path, wrapper, 0o700, false) catch return self.reconciliationFailure(.reconcile_save, .cleanup_failed, "could not write or verify scheduled wrapper", "apply_remote", wrapper_path);
        self.writeRemoteFile(work.server_id, meta_path, meta, 0o600, false) catch return self.reconciliationFailure(.reconcile_save, .cleanup_failed, "could not write or verify scheduled metadata", "apply_remote", meta_path);
        if (!std.mem.eql(u8, current_crontab, crontab_edit.content)) {
            self.installRemoteCrontab(work.server_id, basis.crontab_path, crontab_edit.content) catch return self.reconciliationFailure(.reconcile_save, .cleanup_failed, "remote artifacts were written but crontab installation failed", "apply_remote", basis.crontab_path);
        }
        const readback = self.readRemoteCrontab(work.server_id, basis.crontab_path) catch |err| return self.crontabReconciliationFailure(.reconcile_save, err, "crontab was installed but readback failed", "apply_remote", basis.crontab_path);
        defer self.allocator.free(readback);
        if (!std.mem.eql(u8, readback, crontab_edit.content)) return self.reconciliationFailure(.reconcile_save, .conflict, "crontab readback differs from the reviewed table", "apply_remote", basis.crontab_path);

        var saved = self.jobs.savePlanned(io, planned.job, planned.expected_revision, planned.expected_revision == null, now_ms * std.time.ns_per_ms) catch |err| return self.reconciliationFailure(.reconcile_save, .store_corrupt, @errorName(err), "persist_local", self.jobs.path);
        defer saved.deinit(self.allocator);
        self.upsertCachedJob(&saved) catch return self.reconciliationFailure(.reconcile_save, .store_corrupt, "saved job could not be published to the coordinator cache", "persist_local", self.jobs.path);
        return .{ .state = .done, .result_json = std.fmt.allocPrint(self.allocator, "{{\"job_id\":\"{s}\"}}", .{saved.id}) catch null, .committed = true };
    }

    fn saveCompletion(self: *Registry, io: std.Io, work: *const OperationWork, now_ms: i64) Completion {
        var parsed = std.json.parseFromSlice(SavePlanPayload, self.allocator, work.payload_json, .{}) catch {
            return .{ .state = .failed, .failure = BackupFailure.init(self.allocator, .internal, "saved backup plan is unreadable", false, "validate_plan") catch null };
        };
        defer parsed.deinit();
        if (work.remote_required) {
            if (parsed.value.job.schedule.enabled) return self.scheduleSaveCompletion(io, work, parsed.value, now_ms);
            return self.scheduleDisableCompletion(io, work, parsed.value, now_ms);
        }
        var saved = self.jobs.savePlanned(io, parsed.value.job, parsed.value.expected_revision, parsed.value.expected_revision == null, now_ms * std.time.ns_per_ms) catch |err| {
            const code: FailureCode = switch (err) {
                error.RevConflict => .conflict,
                error.StoreCorrupt => .store_corrupt,
                error.UnknownId => .not_found,
                else => .invalid_job,
            };
            return .{ .state = .failed, .failure = BackupFailure.init(self.allocator, code, @errorName(err), code == .store_corrupt, "persist_local") catch null };
        };
        defer saved.deinit(self.allocator);
        self.upsertCachedJob(&saved) catch return .{ .state = .failed, .failure = BackupFailure.init(self.allocator, .store_corrupt, "saved job could not be published to the coordinator cache", true, "persist_local") catch null };
        const result = std.fmt.allocPrint(self.allocator, "{{\"job_id\":\"{s}\"}}", .{saved.id}) catch null;
        return .{ .state = .done, .result_json = result, .committed = true };
    }

    fn deleteCompletion(self: *Registry, io: std.Io, work: *const OperationWork) Completion {
        var parsed = std.json.parseFromSlice(DeletePlanPayload, self.allocator, work.payload_json, .{}) catch {
            return .{ .state = .failed, .failure = BackupFailure.init(self.allocator, .internal, "saved delete plan is unreadable", false, "validate_plan") catch null };
        };
        defer parsed.deinit();
        var current = (self.jobs.find(io, parsed.value.job_id) catch {
            return .{ .state = .failed, .failure = BackupFailure.init(self.allocator, .store_corrupt, "job registry could not be read during delete reconciliation", true, "validate_plan") catch null };
        }) orelse {
            return .{ .state = .failed, .failure = BackupFailure.init(self.allocator, .not_found, "job no longer exists", false, "validate_plan") catch null };
        };
        defer current.deinit(self.allocator);
        if (!std.mem.eql(u8, current.server_id, parsed.value.server_id) or current.revision != parsed.value.expected_revision or !std.mem.eql(u8, current.name, parsed.value.job_name)) {
            return .{ .state = .failed, .failure = BackupFailure.init(self.allocator, .conflict, "job changed after delete planning", false, "validate_plan") catch null };
        }
        if (work.remote_required) {
            const basis = parsed.value.schedule_basis orelse return self.completionFailure(.session_not_ready, "delete plan has no frozen runtime facts", false, "remove_remote");
            const current_crontab = self.readRemoteCrontab(work.server_id, basis.crontab_path) catch |err| return self.crontabReconciliationFailure(.reconcile_delete, err, "could not re-read crontab", "remove_remote", basis.crontab_path);
            defer self.allocator.free(current_crontab);
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(current_crontab, &digest, .{});
            const edited = crontabRemove(self.allocator, basis.crontab, current.id) catch return self.completionFailure(.conflict, "frozen crontab marker block is malformed", false, "remove_remote");
            defer self.allocator.free(edited.content);
            if (!std.mem.eql(u8, &digest, &basis.crontab_sha256) and !std.mem.eql(u8, current_crontab, edited.content)) return self.completionFailure(.conflict, "crontab changed after delete planning", false, "remove_remote");
            if (!std.mem.eql(u8, current_crontab, edited.content)) {
                self.installRemoteCrontab(work.server_id, basis.crontab_path, edited.content) catch return self.reconciliationFailure(.reconcile_delete, .cleanup_failed, "could not remove the scheduled crontab block", "remove_remote", basis.crontab_path);
            }
            const cron_readback = self.readRemoteCrontab(work.server_id, basis.crontab_path) catch |err| return self.crontabReconciliationFailure(.reconcile_delete, err, "crontab removal could not be verified", "remove_remote", basis.crontab_path);
            defer self.allocator.free(cron_readback);
            if (!std.mem.eql(u8, cron_readback, edited.content)) return self.reconciliationFailure(.reconcile_delete, .conflict, "crontab removal readback differs", "remove_remote", basis.crontab_path);

            const job_dir = jobStatePath(self.allocator, basis, current.id) catch return self.reconciliationFailure(.reconcile_delete, .internal, "could not build remote job path", "remove_remote", "");
            defer self.allocator.free(job_dir);
            const runs_dir = std.fmt.allocPrint(self.allocator, "{s}/runs", .{job_dir}) catch return self.reconciliationFailure(.reconcile_delete, .internal, "could not build remote runs path", "remove_remote", job_dir);
            defer self.allocator.free(runs_dir);
            const names = self.listRemoteNames(work.server_id, runs_dir) catch return self.reconciliationFailure(.reconcile_delete, .cleanup_failed, "could not enumerate scheduled run artifacts", "remove_remote", runs_dir);
            defer {
                for (names) |name| self.allocator.free(name);
                self.allocator.free(names);
            }
            for (names) |name| {
                if (!validStagedName(name)) return self.reconciliationFailure(.reconcile_delete, .cleanup_failed, "unknown staged file blocks safe schedule deletion", "remove_remote", runs_dir);
                const path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ runs_dir, name }) catch return self.reconciliationFailure(.reconcile_delete, .internal, "out of memory", "remove_remote", runs_dir);
                defer self.allocator.free(path);
                if (!self.removeRemoteFile(work.server_id, path)) return self.reconciliationFailure(.reconcile_delete, .cleanup_failed, "scheduled run artifact could not be removed and verified absent", "remove_remote", path);
            }
            const exact_names = [_][]const u8{ "run.sh", "meta.json", "next_due", ".lock" };
            for (exact_names) |name| {
                const path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ job_dir, name }) catch return self.reconciliationFailure(.reconcile_delete, .internal, "out of memory", "remove_remote", job_dir);
                defer self.allocator.free(path);
                if (!self.removeRemoteFile(work.server_id, path) and !std.mem.eql(u8, name, ".lock")) return self.reconciliationFailure(.reconcile_delete, .cleanup_failed, "scheduled artifact cleanup was incomplete", "remove_remote", path);
            }
            if (!self.removeRemoteFile(work.server_id, runs_dir)) return self.reconciliationFailure(.reconcile_delete, .cleanup_failed, "scheduled runs directory could not be removed and verified absent", "remove_remote", runs_dir);
            if (!self.removeRemoteFile(work.server_id, job_dir)) return self.reconciliationFailure(.reconcile_delete, .cleanup_failed, "scheduled state directory could not be removed and verified absent", "remove_remote", job_dir);

            const config_path = configPath(self.allocator, basis) catch return self.reconciliationFailure(.reconcile_delete, .internal, "could not build config path", "remove_remote", "");
            defer self.allocator.free(config_path);
            const config_opt = self.readRemoteFileSensitive(work.server_id, config_path, 256 * 1024) catch return self.reconciliationFailure(.reconcile_delete, .cleanup_failed, "scheduled config could not be read", "remove_remote", config_path);
            if (config_opt) |config_bytes| {
                defer secureFree(self.allocator, config_bytes);
                const remote_name = remoteName(self.allocator, current.id) catch return self.reconciliationFailure(.reconcile_delete, .internal, "could not build config section", "remove_remote", config_path);
                defer self.allocator.free(remote_name);
                const without = configRemoveSection(self.allocator, config_bytes, remote_name) catch return self.reconciliationFailure(.reconcile_delete, .internal, "could not remove config section", "remove_remote", config_path);
                defer secureFree(self.allocator, without);
                if (std.mem.trim(u8, without, " \t\r\n").len == 0) {
                    if (!self.removeRemoteFile(work.server_id, config_path)) return self.reconciliationFailure(.reconcile_delete, .cleanup_failed, "scheduled config could not be removed and verified absent", "remove_remote", config_path);
                } else {
                    self.writeRemoteFile(work.server_id, config_path, without, 0o600, true) catch return self.reconciliationFailure(.reconcile_delete, .cleanup_failed, "scheduled config update or mode verification failed", "remove_remote", config_path);
                }
            }
        }
        const deleted = self.jobs.delete(io, parsed.value.job_id) catch {
            if (work.remote_required) return self.reconciliationFailure(.reconcile_delete, .store_corrupt, "remote schedule was removed but the local job registry could not be updated", "persist_local", self.jobs.path);
            return .{ .state = .failed, .failure = BackupFailure.init(self.allocator, .store_corrupt, "job registry could not be updated", true, "persist_local") catch null };
        };
        if (!deleted) return .{ .state = .failed, .failure = BackupFailure.init(self.allocator, .not_found, "job no longer exists", false, "persist_local") catch null };
        self.removeCachedJob(parsed.value.job_id);
        return .{ .state = .done, .result_json = std.fmt.allocPrint(self.allocator, "{{\"job_id\":\"{s}\"}}", .{parsed.value.job_id}) catch null, .committed = true };
    }

    fn cleanupCompletion(self: *Registry, io: std.Io, work: *const OperationWork, now_ms: i64) Completion {
        const task = work.cleanup_task orelse return self.completionFailure(.internal, "retained cleanup task is missing", false, "cleanup");
        switch (task.kind) {
            .reconcile_save => {
                var completion = self.saveCompletion(io, work, now_ms);
                if (completion.state != .done and completion.cleanup_task == null) completion.cleanup_task = task.clone(self.allocator) catch null;
                return completion;
            },
            .reconcile_delete => {
                var completion = self.deleteCompletion(io, work);
                if (completion.state != .done and completion.cleanup_task == null) completion.cleanup_task = task.clone(self.allocator) catch null;
                return completion;
            },
            .test_sentinel => {
                const job = task.job orelse {
                    var missing = self.completionFailure(.internal, "retained cleanup adapter identity is missing", false, "cleanup");
                    missing.state = .partial;
                    missing.cleanup_task = task.clone(self.allocator) catch null;
                    missing.result_json = self.cleanupRequiredResult(work.job_id, false);
                    return missing;
                };
                const needs_credentials = task.remote_object.len > 0 and job.destination.credential_mode == .access_key;
                if (needs_credentials and work.credentials == null) {
                    var missing = self.completionFailure(.invalid_credentials, "fresh credentials are required to retry exact cleanup", false, "cleanup");
                    missing.state = .partial;
                    missing.cleanup_task = task.clone(self.allocator) catch null;
                    missing.result_json = self.cleanupRequiredResult(work.job_id, true);
                    return missing;
                }
                var config: ?[]u8 = null;
                defer if (config) |bytes| secureFree(self.allocator, bytes);
                if (task.remote_object.len > 0) {
                    const remote_name = remoteName(self.allocator, job.id) catch {
                        var invalid = self.completionFailure(.internal, "could not rebuild the cleanup adapter identity", false, "cleanup");
                        invalid.state = .partial;
                        invalid.cleanup_task = task.clone(self.allocator) catch null;
                        return invalid;
                    };
                    defer self.allocator.free(remote_name);
                    const credentials = work.credentials;
                    config = remoteConfigSection(self.allocator, &job, remote_name, if (credentials) |value| value.access_key else null, if (credentials) |value| value.secret_key else null) catch {
                        var invalid = self.completionFailure(.invalid_credentials, "fresh credentials could not rebuild the cleanup adapter", false, "cleanup");
                        invalid.state = .partial;
                        invalid.cleanup_task = task.clone(self.allocator) catch null;
                        invalid.result_json = self.cleanupRequiredResult(work.job_id, needs_credentials);
                        return invalid;
                    };
                }
                var sentinel_ok = task.remote_object.len == 0;
                if (task.remote_object.len > 0) {
                    if (self.writeRemoteFile(work.server_id, task.config_path, config.?, 0o600, true)) |_| {
                        var probed_rclone: ?[]u8 = null;
                        defer if (probed_rclone) |path| self.allocator.free(path);
                        const rclone_path = if (task.rclone_path.len > 0)
                            task.rclone_path
                        else path: {
                            var probe = self.execRemote(work.server_id, "command -v rclone", null, "probe rclone path for exact backup cleanup", 4096, 10, false) catch break :path "";
                            defer probe.deinit(self.allocator, false);
                            if (self.remoteResultFailure(&probe, "cleanup") != null) break :path "";
                            const trimmed = std.mem.trim(u8, probe.data, " \t\r\n");
                            if (trimmed.len == 0 or trimmed[0] != '/') break :path "";
                            probed_rclone = self.allocator.dupe(u8, trimmed) catch break :path "";
                            break :path probed_rclone.?;
                        };
                        const quoted_config = shellquote.quote(self.allocator, task.config_path) catch "";
                        defer if (quoted_config.len > 0) self.allocator.free(quoted_config);
                        const quoted_rclone = shellquote.quote(self.allocator, rclone_path) catch "";
                        defer if (quoted_rclone.len > 0) self.allocator.free(quoted_rclone);
                        const quoted_exact = shellquote.quote(self.allocator, task.exact_destination) catch "";
                        defer if (quoted_exact.len > 0) self.allocator.free(quoted_exact);
                        if (rclone_path.len > 0 and quoted_config.len > 0 and quoted_rclone.len > 0 and quoted_exact.len > 0) {
                            const delete_command = std.fmt.allocPrint(self.allocator, "{s} deletefile {s} --config {s} --ask-password=false", .{ quoted_rclone, quoted_exact, quoted_config }) catch null;
                            defer if (delete_command) |command| self.allocator.free(command);
                            const verify_command = std.fmt.allocPrint(self.allocator, "{s} lsf {s} --config {s} --ask-password=false", .{ quoted_rclone, quoted_exact, quoted_config }) catch null;
                            defer if (verify_command) |command| self.allocator.free(command);
                            if (delete_command != null and verify_command != null) {
                                const cleaned = self.cleanupExactSentinel(work.server_id, delete_command.?, verify_command.?);
                                sentinel_ok = cleaned.absent;
                            }
                        }
                    } else |_| {}
                }
                const config_ok = self.removeRemoteFileDuringShutdown(work.server_id, task.config_path);
                if (sentinel_ok and config_ok) return .{ .state = .done, .result_json = std.fmt.allocPrint(self.allocator, "{{\"cleanup\":\"complete\",\"remote_object\":\"{s}\"}}", .{task.remote_object}) catch null, .committed = true };
                var completion = self.completionFailure(.cleanup_failed, "retained connection-test cleanup is still incomplete", true, "cleanup_verify");
                completion.state = .partial;
                if (completion.failure) |*failure| {
                    if (!config_ok) failure.path = dupOrLiteral(self.allocator, task.config_path) catch "";
                    if (!sentinel_ok) failure.remote_object = dupOrLiteral(self.allocator, task.remote_object) catch "";
                }
                completion.cleanup_task = task.clone(self.allocator) catch null;
                completion.result_json = self.cleanupRequiredResult(work.job_id, needs_credentials);
                return completion;
            },
        }
    }

    fn installCompletion(self: *Registry, work: *const OperationWork) Completion {
        var parsed = std.json.parseFromSlice(InstallPlanPayload, self.allocator, work.payload_json, .{}) catch return self.completionFailure(.internal, "saved install plan is unreadable", false, "install");
        defer parsed.deinit();
        if (parsed.value.manual or parsed.value.command.len == 0) return self.unsupportedCompletion("install", "automatic installation is unsupported for this unverified target; use the manual plan");
        const verified_target = std.mem.eql(u8, parsed.value.target, "alpine") or std.mem.eql(u8, parsed.value.target, "debian") or std.mem.eql(u8, parsed.value.target, "ubuntu");
        if (!verified_target) return self.unsupportedCompletion("install", "install plan target is not a frozen Alpine/Debian adapter");
        var result = self.execRemote(work.server_id, parsed.value.command, null, "install backup runtime dependency", 256 * 1024, 10 * 60, false) catch |err| return self.remoteFailure(err, "install");
        defer result.deinit(self.allocator, false);
        if (result.code != .ok) return self.completionFailure(.transport_error, if (result.message.len > 0) result.message else "installation transport failed", true, "install");
        if (result.exit != 0) {
            return .{
                .state = .partial,
                .failure = BackupFailure.init(self.allocator, .cleanup_failed, "the verified install command failed after possible partial package-manager effects", true, "install") catch null,
                .result_json = std.fmt.allocPrint(self.allocator, "{{\"target\":\"{s}\",\"what\":\"{s}\",\"partial_effects\":true}}", .{ parsed.value.target, parsed.value.what }) catch null,
            };
        }
        return .{ .state = .done, .result_json = std.fmt.allocPrint(self.allocator, "{{\"target\":\"{s}\",\"what\":\"{s}\",\"partial_effects\":false}}", .{ parsed.value.target, parsed.value.what }) catch null, .committed = true };
    }

    fn executeWork(self: *Registry, io: std.Io, work: *const OperationWork, now_ms: i64) Completion {
        return switch (work.kind) {
            .save => self.saveCompletion(io, work, now_ms),
            .delete => self.deleteCompletion(io, work),
            .refresh => self.refreshCompletion(work, now_ms),
            .@"test" => self.testCompletion(work, now_ms),
            .install => self.installCompletion(work),
            .cleanup => self.cleanupCompletion(io, work, now_ms),
        };
    }

    fn completeWork(self: *Registry, id: []const u8, completion: *Completion, now_ms: i64) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.ops.items) |op| {
            if (!std.mem.eql(u8, op.id, id) or op.state.terminal()) continue;
            // A late cancel request cannot erase failed/partial reconciliation
            // evidence produced by work that was already admitted remotely.
            op.state = completion.state;
            if (op.failure) |*old| old.deinit(self.allocator);
            op.failure = completion.failure;
            completion.failure = null;
            if (op.result_json) |old| self.allocator.free(old);
            op.result_json = completion.result_json;
            completion.result_json = null;
            if (op.cleanup_task) |*old| old.deinit(self.allocator);
            op.cleanup_task = completion.cleanup_task;
            completion.cleanup_task = null;
            op.finished_at_ms = now_ms;
            op.touched_at_ms = now_ms;
            self.finishStepsLocked(op, op.state);
            if (op.failure) |failure| {
                for (op.steps.items) |*step| {
                    if (step.state == .failed or step.state == .canceled) {
                        step.failure = failure.clone(self.allocator) catch null;
                        break;
                    }
                }
            }
            // Operation credentials end at every terminal transition. A retry
            // must be re-admitted with fresh bounded credentials when needed.
            self.clearCredentialsLocked(op);
            self.markJournalDirtyLocked();
            return;
        }
    }

    fn replaceRunText(self: *Registry, field: *[]const u8, value: []const u8) void {
        if (field.*.len > 0) self.allocator.free(field.*);
        field.* = dupOrLiteral(self.allocator, value) catch "";
    }

    fn setRunState(self: *Registry, run: *LiveRun, status: RunStatus, phase: []const u8) void {
        self.runs.lock();
        defer self.runs.unlock();
        run.record.status = status;
        self.replaceRunText(&run.phase, phase);
    }

    fn runWantsCancel(self: *Registry, run: *LiveRun) bool {
        self.runs.lock();
        defer self.runs.unlock();
        return run.cancel_requested;
    }

    fn appendLiveLog(self: *Registry, run: *LiveRun, bytes: []const u8) void {
        const cap = 4 * 1024 * 1024;
        self.runs.lock();
        defer self.runs.unlock();
        if (bytes.len >= cap) {
            run.log_start += run.live_log.items.len + bytes.len - cap;
            run.live_log.clearRetainingCapacity();
            run.live_log.appendSlice(self.allocator, bytes[bytes.len - cap ..]) catch {};
        } else {
            const excess = run.live_log.items.len + bytes.len -| cap;
            if (excess > 0) {
                std.mem.copyForwards(u8, run.live_log.items[0 .. run.live_log.items.len - excess], run.live_log.items[excess..]);
                run.live_log.items.len -= excess;
                run.log_start += excess;
            }
            run.live_log.appendSlice(self.allocator, bytes) catch {};
        }
        const parsed = lastStatsFromLog(self.allocator, run.live_log.items);
        run.record.bytes_done = parsed.stats.bytes_done;
        run.record.bytes_total = parsed.stats.bytes_total;
        run.record.files_done = parsed.stats.files_done;
        run.record.files_total = parsed.stats.files_total;
        run.speed_bps = parsed.stats.speed_bps;
        run.eta_sec = parsed.stats.eta_sec;
    }

    const CancelEscalation = struct {
        term_attempted: bool = false,
        kill_attempted: bool = false,
        term_deadline_ns: i128 = 0,
        kill_deadline_ns: i128 = 0,

        fn begin(self: *CancelEscalation, now_ns: i128) void {
            self.term_attempted = true;
            self.term_deadline_ns = now_ns + 2 * std.time.ns_per_s;
        }

        fn shouldKill(self: CancelEscalation, now_ns: i128) bool {
            // Channel EOF is not proof that every member of the remote
            // process group exited. Only an explicit absence probe may
            // suppress KILL after the TERM deadline.
            return self.term_attempted and !self.kill_attempted and now_ns >= self.term_deadline_ns;
        }

        fn killed(self: *CancelEscalation, now_ns: i128) void {
            self.kill_attempted = true;
            self.kill_deadline_ns = now_ns + 2 * std.time.ns_per_s;
        }

        fn postKillExpired(self: CancelEscalation, now_ns: i128) bool {
            return self.kill_attempted and now_ns >= self.kill_deadline_ns;
        }
    };

    fn signalProcessGroup(self: *Registry, server_id: []const u8, pgid: []const u8, signal: []const u8) bool {
        if (!validProcessGroupId(pgid)) return false;
        const command = std.fmt.allocPrint(self.allocator, "kill -{s} -{s}", .{ signal, pgid }) catch return false;
        defer self.allocator.free(command);
        var result = self.execRemoteCleanup(server_id, command, null, "signal backup process group", 64 * 1024, 10, false) catch return false;
        defer result.deinit(self.allocator, false);
        return result.code == .ok and result.exit != null and result.exit.? == 0;
    }

    fn processGroupAbsent(self: *Registry, server_id: []const u8, pgid: []const u8) bool {
        if (!validProcessGroupId(pgid)) return false;
        const command = std.fmt.allocPrint(self.allocator, "groups=$(ps -eo pgid= 2>/dev/null) || {{ printf '__OARS_UNKNOWN__\\n'; exit 2; }}; for g in $groups; do if [ \"$g\" = '{s}' ]; then printf '__OARS_PRESENT__\\n'; exit 0; fi; done; printf '__OARS_ABSENT__\\n'", .{pgid}) catch return false;
        defer self.allocator.free(command);
        var result = self.execRemoteCleanup(server_id, command, null, "verify backup process group absence", 64 * 1024, 10, false) catch return false;
        defer result.deinit(self.allocator, false);
        return result.code == .ok and result.exit != null and result.exit.? == 0 and std.mem.eql(u8, std.mem.trim(u8, result.data, " \t\r\n"), "__OARS_ABSENT__");
    }

    fn terminateProcessGroup(self: *Registry, server_id: []const u8, pgid: []const u8, term_grace_ns: i128, kill_grace_ns: i128) bool {
        const io = self.io orelse return false;
        _ = self.signalProcessGroup(server_id, pgid, "TERM");
        var deadline = std.Io.Timestamp.now(io, .real).nanoseconds + term_grace_ns;
        while (true) {
            if (self.processGroupAbsent(server_id, pgid)) return true;
            if (std.Io.Timestamp.now(io, .real).nanoseconds >= deadline) break;
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(50), .awake) catch break;
        }

        // A failed TERM request or an exited stream is not evidence that the
        // remote group is gone. KILL is always attempted after the grace
        // window, then absence is explicitly verified within another bound.
        _ = self.signalProcessGroup(server_id, pgid, "KILL");
        deadline = std.Io.Timestamp.now(io, .real).nanoseconds + kill_grace_ns;
        while (true) {
            if (self.processGroupAbsent(server_id, pgid)) return true;
            if (std.Io.Timestamp.now(io, .real).nanoseconds >= deadline) break;
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(50), .awake) catch break;
        }
        return false;
    }

    fn validProcessGroupId(pgid: []const u8) bool {
        if (pgid.len == 0 or pgid.len > 20) return false;
        for (pgid) |ch| if (!std.ascii.isDigit(ch)) return false;
        return true;
    }

    fn cleanupLiveRunArtifacts(self: *Registry, run: *LiveRun) ?[]const u8 {
        var leftover: ?[]const u8 = null;
        if (run.temp_config.len > 0 and !self.removeRemoteFileDuringShutdown(run.record.server_id, run.temp_config)) leftover = run.temp_config;
        if (run.state_dir_path.len > 0) {
            const pgid_path = std.fmt.allocPrint(self.allocator, "{s}/pgid", .{run.state_dir_path}) catch {
                if (leftover == null) leftover = run.state_dir_path;
                return leftover;
            };
            defer self.allocator.free(pgid_path);
            const pgid_removed = self.removeRemoteFileDuringShutdown(run.record.server_id, pgid_path);
            const state_removed = pgid_removed and self.removeRemoteFileDuringShutdown(run.record.server_id, run.state_dir_path);
            if (!state_removed and leftover == null) leftover = run.state_dir_path;
        }
        return leftover;
    }

    fn failLiveRun(self: *Registry, run: *LiveRun, code: FailureCode, message: []const u8, phase: []const u8, status: RunStatus) void {
        const leftover = self.cleanupLiveRunArtifacts(run);
        var failure = if (leftover == null)
            BackupFailure.init(self.allocator, code, message, code == .transport_error or code == .interrupted, phase) catch null
        else
            BackupFailure.init(self.allocator, .cleanup_failed, "manual backup failed and exact temporary cleanup could not be verified", true, "cleanup") catch null;
        if (leftover) |path| {
            if (failure) |*value| value.path = dupOrLiteral(self.allocator, path) catch "";
        }
        self.finishLiveRun(self.io.?, run, status, leftover == null, failure);
    }

    fn finishLiveRun(self: *Registry, io: std.Io, run: *LiveRun, status: RunStatus, cleanup_ok: bool, failure: ?BackupFailure) void {
        self.runs.lock();
        run.outcome_status = status;
        run.record.status = if (cleanup_ok) status else .partial;
        run.record.finished_at_ns = @intCast(std.Io.Timestamp.now(io, .real).nanoseconds);
        self.replaceRunText(&run.phase, "finished");
        self.replaceRunText(&run.cleanup_state, if (cleanup_ok) "complete" else "failed");
        if (run.failure) |*old| old.deinit(self.allocator);
        run.failure = failure;
        var persistence_ok = true;
        run.record.trimLog(self.allocator, run.live_log.items) catch {
            persistence_ok = false;
        };
        if (run.failure) |value| {
            if (run.record.@"error") |old| self.allocator.free(old);
            run.record.@"error" = dupOrLiteral(self.allocator, value.message) catch null;
            run.record.error_code = value.code;
            run.record.error_retryable = value.retryable;
        }
        if (run.credentials) |*credentials| credentials.deinit(self.allocator);
        run.credentials = null;
        var history_record: ?RunRecord = HistoryStore.cloneRun(self.allocator, run.record) catch null;
        if (history_record == null) persistence_ok = false;
        self.runs.unlock();

        if (history_record) |*record| {
            self.history.append(io, record, run.record.finished_at_ns) catch {
                persistence_ok = false;
            };
            if (persistence_ok) self.upsertCachedHistory(record) catch {
                persistence_ok = false;
            };
            record.deinit(self.allocator);
        }

        self.runs.lock();
        if (!persistence_ok and (run.record.status == .success or run.record.status == .no_changes)) {
            run.record.status = .partial;
            if (run.failure) |*old| old.deinit(self.allocator);
            run.failure = BackupFailure.init(self.allocator, .store_corrupt, "manual backup completed remotely but durable history persistence failed", true, "persist_local") catch null;
            if (run.record.@"error") |old| self.allocator.free(old);
            run.record.@"error" = dupOrLiteral(self.allocator, "manual backup completed remotely but durable history persistence failed") catch null;
            run.record.error_code = .store_corrupt;
            run.record.error_retryable = true;
        }
        run.finalized = true;
        self.runs.unlock();
    }

    fn executeManualRun(self: *Registry, io: std.Io, run: *LiveRun) void {
        if (run.cleanup_retry) {
            const leftover = self.cleanupLiveRunArtifacts(run);
            if (leftover) |path| {
                var failure = BackupFailure.init(self.allocator, .cleanup_failed, "manual backup temporary cleanup retry could not be verified", true, "cleanup") catch null;
                if (failure) |*value| value.path = dupOrLiteral(self.allocator, path) catch "";
                return self.finishLiveRun(io, run, run.outcome_status, false, failure);
            }
            self.runs.lock();
            run.cleanup_retry = false;
            self.runs.unlock();
            const restored_failure: ?BackupFailure = switch (run.outcome_status) {
                .canceled => BackupFailure.init(self.allocator, .canceled, "backup run canceled and cleanup is complete", false, "cancel") catch null,
                .interrupted => BackupFailure.init(self.allocator, .interrupted, "backup run was interrupted; retained cleanup is now complete", true, "running") catch null,
                .failed => BackupFailure.init(self.allocator, .capability_failed, "backup run failed; retained cleanup is now complete", true, "running") catch null,
                else => null,
            };
            return self.finishLiveRun(io, run, run.outcome_status, true, restored_failure);
        }
        if (self.runWantsCancel(run)) {
            const failure = BackupFailure.init(self.allocator, .canceled, "backup run canceled before remote execution", false, "cancel") catch null;
            return self.finishLiveRun(io, run, .canceled, true, failure);
        }
        const job = &(run.job orelse return self.failLiveRun(run, .internal, "run lost its job snapshot", "prepare", .failed));
        var probe = self.execRemote(job.server_id, runtime_probe_command, null, "probe manual backup runtime", 256 * 1024, 20, false) catch |err| return self.failLiveRun(run, switch (err) {
            error.NotConnected => .not_connected,
            error.SessionNotReady => .session_not_ready,
            error.Interrupted => .interrupted,
            error.OutOfMemory => .internal,
        }, @errorName(err), "prepare", if (err == error.Interrupted) .interrupted else .failed);
        defer probe.deinit(self.allocator, false);
        if (probe.code != .ok or probe.exit != 0) return self.failLiveRun(run, .transport_error, "manual runtime probe failed", "prepare", .failed);
        var facts = parseRuntimeFacts(self.allocator, probe.data, @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_ms))) catch return self.failLiveRun(run, .unsupported_target, "runtime facts are invalid", "prepare", .failed);
        defer facts.deinit(self.allocator);
        if (facts.rclone_path.len == 0) return self.failLiveRun(run, .rclone_missing, "rclone is not installed", "prepare", .failed);
        if (!facts.process_groups) return self.failLiveRun(run, .unsupported_target, "verified process groups are unavailable", "prepare", .failed);

        const quoted_source = shellquote.quote(self.allocator, job.source_path) catch return self.failLiveRun(run, .internal, "could not quote source", "prepare", .failed);
        defer self.allocator.free(quoted_source);
        const source_command = std.fmt.allocPrint(self.allocator, "if [ ! -e {s} ]; then exit 44; fi; if [ ! -r {s} ]; then exit 45; fi", .{ quoted_source, quoted_source }) catch return self.failLiveRun(run, .internal, "could not build source check", "prepare", .failed);
        defer self.allocator.free(source_command);
        var source_result = self.execRemote(job.server_id, source_command, null, "check backup source readability", 64 * 1024, 10, false) catch return self.failLiveRun(run, .transport_error, "source check failed", "prepare", .failed);
        defer source_result.deinit(self.allocator, false);
        if (source_result.exit == 44) return self.failLiveRun(run, .source_missing, "backup source does not exist", "prepare", .failed);
        if (source_result.exit == 45) return self.failLiveRun(run, .source_unreadable, "backup source is not readable", "prepare", .failed);
        if (source_result.code != .ok or source_result.exit != 0) return self.failLiveRun(run, .transport_error, "source check failed", "prepare", .failed);

        const state_path = std.fmt.allocPrint(self.allocator, "{s}/.local/state/oars/backups/.manual/{s}", .{ facts.home, run.record.id }) catch return self.failLiveRun(run, .internal, "could not build manual state path", "prepare", .failed);
        defer self.allocator.free(state_path);
        const config_path = std.fmt.allocPrint(self.allocator, "{s}/rclone.conf", .{state_path}) catch return self.failLiveRun(run, .internal, "could not build manual config path", "prepare", .failed);
        defer self.allocator.free(config_path);
        const pgid_path = std.fmt.allocPrint(self.allocator, "{s}/pgid", .{state_path}) catch return self.failLiveRun(run, .internal, "could not build process-group identity path", "prepare", .failed);
        defer self.allocator.free(pgid_path);
        self.runs.lock();
        self.replaceRunText(&run.temp_config, config_path);
        self.replaceRunText(&run.state_dir_path, state_path);
        self.runs.unlock();
        self.ensureRemoteDirectory(job.server_id, state_path, 0o700) catch return self.failLiveRun(run, .transport_error, "could not create manual state directory", "prepare", .failed);
        const remote_name = remoteName(self.allocator, job.id) catch return self.failLiveRun(run, .internal, "could not build remote name", "prepare", .failed);
        defer self.allocator.free(remote_name);
        const config = remoteConfigSection(self.allocator, job, remote_name, if (run.credentials) |value| value.access_key else null, if (run.credentials) |value| value.secret_key else null) catch return self.failLiveRun(run, .invalid_credentials, "could not build manual config", "prepare", .failed);
        defer secureFree(self.allocator, config);
        // The exact cleanup paths were recorded above before this worker-owned
        // SFTP write was admitted. writeRemoteFile verifies bytes and mode 0600.
        self.writeRemoteFile(job.server_id, config_path, config, 0o600, true) catch return self.failLiveRun(run, .transport_error, "could not write and verify manual config", "prepare", .failed);
        self.runs.lock();
        if (run.credentials) |*credentials| credentials.deinit(self.allocator);
        run.credentials = null;
        self.runs.unlock();

        const destination = destinationArg(self.allocator, job, remote_name) catch return self.failLiveRun(run, .internal, "could not build destination", "prepare", .failed);
        defer self.allocator.free(destination);
        const quoted_rclone = shellquote.quote(self.allocator, facts.rclone_path) catch return self.failLiveRun(run, .internal, "could not quote rclone", "prepare", .failed);
        defer self.allocator.free(quoted_rclone);
        const quoted_destination = shellquote.quote(self.allocator, destination) catch return self.failLiveRun(run, .internal, "could not quote destination", "prepare", .failed);
        defer self.allocator.free(quoted_destination);
        const quoted_config = shellquote.quote(self.allocator, config_path) catch return self.failLiveRun(run, .internal, "could not quote config path", "prepare", .failed);
        defer self.allocator.free(quoted_config);
        const quoted_pgid_path = shellquote.quote(self.allocator, pgid_path) catch return self.failLiveRun(run, .internal, "could not quote process-group identity path", "prepare", .failed);
        defer self.allocator.free(quoted_pgid_path);
        const inner = std.fmt.allocPrint(self.allocator, "umask 077; printf '%s\\n' \"$$\" > {s}; printf '__OARS_PGID__%s\\n' \"$$\"; exec {s} {s} {s} {s} --config {s} --use-json-log --stats 1s --stats-log-level NOTICE --ask-password=false 2>&1", .{ quoted_pgid_path, quoted_rclone, job.transfer.jsonName(), quoted_source, quoted_destination, quoted_config }) catch return self.failLiveRun(run, .internal, "could not build rclone command", "prepare", .failed);
        defer self.allocator.free(inner);
        const quoted_inner = shellquote.quote(self.allocator, inner) catch return self.failLiveRun(run, .internal, "could not quote run wrapper", "prepare", .failed);
        defer self.allocator.free(quoted_inner);
        const command = std.fmt.allocPrint(self.allocator, "exec setsid /bin/sh -c {s}", .{quoted_inner}) catch return self.failLiveRun(run, .internal, "could not build process-group command", "prepare", .failed);
        defer self.allocator.free(command);
        const process = self.allocator.create(sessions.BackupProcess) catch return self.failLiveRun(run, .internal, "out of memory", "prepare", .failed);
        process.* = .{ .allocator = self.allocator };
        const adapter = self.remoteAdapter() orelse {
            self.allocator.destroy(process);
            return self.failLiveRun(run, .not_connected, "session disconnected", "prepare", .failed);
        };
        adapter.start(job.server_id, command, null, process) catch {
            self.allocator.destroy(process);
            return self.failLiveRun(run, .session_not_ready, "manual run could not be queued", "prepare", .failed);
        };
        self.runs.lock();
        run.process = process;
        self.runs.unlock();

        var identity: std.ArrayList(u8) = .empty;
        defer identity.deinit(self.allocator);
        var identity_done = false;
        var final_exit: ?i32 = null;
        var disconnected = false;
        var process_done = false;
        var cancel_verified = false;
        const process_started_ns = std.Io.Timestamp.now(io, .real).nanoseconds;
        const identity_deadline_ns = process_started_ns + 10 * std.time.ns_per_s;
        const run_deadline_ns = process_started_ns + 24 * std.time.ns_per_hour;
        var next_identity_probe_ns = process_started_ns;
        var timed_out = false;
        while (true) {
            var snapshot = process.snapshot(self.allocator, run.process_cursor, 256 * 1024) catch {
                self.failLiveRun(run, .internal, "could not sample backup stream", "running", .failed);
                return;
            };
            defer snapshot.deinit(self.allocator);
            run.process_cursor = snapshot.cursor;
            final_exit = snapshot.exit;
            disconnected = snapshot.disconnected;
            process_done = snapshot.done;
            var log_bytes = snapshot.data;
            if (!identity_done and log_bytes.len > 0) {
                const newline = std.mem.indexOfScalar(u8, log_bytes, '\n');
                if (newline) |index| {
                    identity.appendSlice(self.allocator, log_bytes[0..index]) catch {};
                    const prefix = "__OARS_PGID__";
                    if (!std.mem.startsWith(u8, identity.items, prefix)) return self.failLiveRun(run, .unsupported_target, "process-group identity was not reported", "prepare", .failed);
                    const pgid = identity.items[prefix.len..];
                    if (!validProcessGroupId(pgid)) return self.failLiveRun(run, .unsupported_target, "process-group identity is invalid", "prepare", .failed);
                    self.runs.lock();
                    self.replaceRunText(&run.pgid, pgid);
                    run.record.status = .running;
                    self.replaceRunText(&run.phase, "running");
                    self.runs.unlock();
                    identity_done = true;
                    log_bytes = log_bytes[index + 1 ..];
                } else {
                    identity.appendSlice(self.allocator, log_bytes) catch {};
                    log_bytes = log_bytes[log_bytes.len..];
                }
            }
            if (identity_done and log_bytes.len > 0) self.appendLiveLog(run, log_bytes);

            const now_ns = std.Io.Timestamp.now(io, .real).nanoseconds;
            if (now_ns >= run_deadline_ns) {
                timed_out = true;
                self.runs.lock();
                run.cancel_requested = true;
                self.runs.unlock();
            }
            const wants_cancel = self.runWantsCancel(run) or self.stop.load(.acquire);
            if (wants_cancel and !identity_done and now_ns >= next_identity_probe_ns) {
                next_identity_probe_ns = now_ns + 100 * std.time.ns_per_ms;
                if (self.readRemoteFileDuringShutdown(job.server_id, pgid_path, 64)) |pgid_opt| {
                    if (pgid_opt) |pgid_bytes| {
                        defer self.allocator.free(pgid_bytes);
                        const pgid = std.mem.trim(u8, pgid_bytes, " \t\r\n");
                        if (validProcessGroupId(pgid)) {
                            self.runs.lock();
                            self.replaceRunText(&run.pgid, pgid);
                            self.runs.unlock();
                            identity_done = true;
                        }
                    }
                } else |_| {}
            }
            if (wants_cancel and identity_done) {
                cancel_verified = self.terminateProcessGroup(job.server_id, run.pgid, 2 * std.time.ns_per_s, 2 * std.time.ns_per_s);
                break;
            }
            if (snapshot.done and !wants_cancel) break;
            if (wants_cancel and !identity_done and now_ns >= identity_deadline_ns) break;
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(50), .awake) catch break;
        }

        const leftover = self.cleanupLiveRunArtifacts(run);
        const cleanup_ok = leftover == null;
        var terminal_status: RunStatus = .failed;
        var terminal_failure: ?BackupFailure = null;
        if (timed_out and cancel_verified) {
            terminal_status = .failed;
            terminal_failure = BackupFailure.init(self.allocator, .timeout, "backup run exceeded its bounded execution deadline and the process group was removed", true, "running") catch null;
        } else if (self.runWantsCancel(run) and cancel_verified) {
            terminal_status = .canceled;
            terminal_failure = BackupFailure.init(self.allocator, .canceled, "backup run canceled and process group verified absent", false, "cancel") catch null;
        } else if (self.runWantsCancel(run) or disconnected or self.stop.load(.acquire)) {
            terminal_status = .interrupted;
            terminal_failure = BackupFailure.init(self.allocator, .interrupted, "backup transport or cancellation ended before process-group absence was verified", true, "running") catch null;
        } else if (final_exit == 0) {
            terminal_status = if (run.record.files_done == 0) .no_changes else .success;
        } else {
            terminal_status = .failed;
            terminal_failure = BackupFailure.init(self.allocator, .capability_failed, "rclone exited unsuccessfully", true, "running") catch null;
        }
        if (leftover) |path| {
            if (terminal_failure) |*old| old.deinit(self.allocator);
            terminal_failure = BackupFailure.init(self.allocator, .cleanup_failed, "manual backup temporary config/state cleanup could not be verified", true, "cleanup") catch null;
            if (terminal_failure) |*failure| failure.path = dupOrLiteral(self.allocator, path) catch "";
        }
        self.runs.lock();
        run.process = null;
        run.cancel_verified = cancel_verified;
        self.runs.unlock();
        if (process_done or process.abandon()) {
            process.data.deinit(self.allocator);
            self.allocator.destroy(process);
        }
        self.finishLiveRun(io, run, terminal_status, cleanup_ok, terminal_failure);
    }

    fn claimQueuedRun(self: *Registry) ?*LiveRun {
        self.runs.lock();
        defer self.runs.unlock();
        for (self.runs.list.items) |run| {
            if (run.record.status != .queued and run.record.status != .cancel_requested) continue;
            // Remote work may start only after the admission audit has been
            // durably acknowledged. The coordinator owns that transition.
            if (!run.admission_reported) continue;
            if (!run.cancel_requested) run.record.status = .preparing;
            self.replaceRunText(&run.phase, "preparing");
            return run;
        }
        return null;
    }

    fn failQueuedForShutdown(self: *Registry, now_ms: i64) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.ops.items) |op| {
            if (op.state != .queued) continue;
            op.state = .failed;
            op.finished_at_ms = now_ms;
            op.touched_at_ms = now_ms;
            if (op.failure) |*old| old.deinit(self.allocator);
            op.failure = BackupFailure.init(self.allocator, .interrupted, "backup coordinator stopped before operation execution", true, "shutdown") catch null;
            self.finishStepsLocked(op, .failed);
            self.clearCredentialsLocked(op);
            self.markJournalDirtyLocked();
        }
    }

    fn failQueuedInternal(self: *Registry, now_ms: i64) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.ops.items) |op| {
            if (op.state != .queued) continue;
            op.state = .failed;
            op.finished_at_ms = now_ms;
            op.touched_at_ms = now_ms;
            op.failure = BackupFailure.init(self.allocator, .internal, "coordinator could not allocate operation work", true, "coordinator") catch null;
            self.finishStepsLocked(op, .failed);
            self.clearCredentialsLocked(op);
            self.markJournalDirtyLocked();
            return;
        }
    }

    fn manualRunnerMain(self: *Registry) void {
        const io = self.io orelse return;
        while (true) {
            if (self.claimQueuedRun()) |run| {
                self.executeManualRun(io, run);
                continue;
            }
            if (self.stop.load(.acquire)) break;
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(coordinator_idle_ms), .awake) catch return;
        }
    }

    fn coordinatorMain(self: *Registry) void {
        const io = self.io orelse return;
        self.loadStoreCaches(io) catch {};
        while (true) {
            const before_events_ms: i64 = @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_ms));
            self.persistOperationJournal(io) catch {
                self.operationJournalFailed(before_events_ms);
                std.Io.sleep(io, std.Io.Duration.fromMilliseconds(coordinator_idle_ms), .awake) catch return;
                continue;
            };
            self.drainEvents();
            const now_ms: i64 = @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_ms));
            if (self.stop.load(.acquire)) {
                self.failQueuedForShutdown(now_ms);
                self.persistOperationJournal(io) catch self.operationJournalFailed(now_ms);
                self.drainEvents();
                break;
            }
            const maybe_work = self.claimNextWork(now_ms) catch {
                self.failQueuedInternal(now_ms);
                continue;
            };
            if (maybe_work) |work_value| {
                var work = work_value;
                self.persistOperationJournal(io) catch {
                    self.operationJournalFailed(now_ms);
                    work.deinit(self.allocator);
                    continue;
                };
                var completion = self.executeWork(io, &work, now_ms);
                self.completeWork(work.operation_id, &completion, @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_ms)));
                completion.deinit(self.allocator);
                work.deinit(self.allocator);
                continue;
            }
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(coordinator_idle_ms), .awake) catch return;
        }
    }
};

// --- unit tests ------------------------------------------------------------

test "shipping job validation rejects legacy destinations and credential modes" {
    const base = JobInput{
        .id = "bk-1",
        .server_id = "s1",
        .name = "daily-website",
        .source_path = "/var/www/html",
        .destination = .{ .provider = "aws", .bucket = "acme-backups", .region = "us-east-1" },
        .transfer = "sync",
    };
    try validate(base);
    try std.testing.expectError(error.MissingName, validate(.{ .id = "bk-1", .server_id = "s1", .name = " ", .source_path = "/x", .destination = base.destination }));
    try std.testing.expectError(error.InvalidSource, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "relative/path", .destination = base.destination }));
    try std.testing.expectError(error.InvalidProvider, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = .{ .provider = "gcs", .bucket = "b" } }));
    try std.testing.expectError(error.InvalidBucket, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = .{ .provider = "aws", .bucket = "bad bucket" } }));
    try std.testing.expectError(error.InvalidEndpoint, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = .{ .provider = "minio", .bucket = "b" } }));
    try std.testing.expectError(error.InvalidStorageClass, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = .{ .provider = "minio", .bucket = "b", .endpoint = "http://127.0.0.1:9000", .storage_class = "glacier" } }));
    try std.testing.expectError(error.IamRequiresAws, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = .{ .provider = "minio", .bucket = "b", .endpoint = "http://127.0.0.1:9000", .credential_mode = .aws_runtime } }));
    try std.testing.expectError(error.InvalidTransfer, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = base.destination, .transfer = "mirror" }));
    try std.testing.expectError(error.InvalidCronExpr, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = base.destination, .schedule = .{ .mode = "custom", .expr = "not cron" } }));
    try std.testing.expectError(error.InvalidDestination, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = .{ .type = "local" } }));
}

test "credential keys reject empty oversized NUL CR and LF values" {
    try std.testing.expect(!validCredentials(""));
    try std.testing.expect(!validCredentials("bad\x00key"));
    try std.testing.expect(!validCredentials("bad\rkey"));
    try std.testing.expect(!validCredentials("bad\nkey"));
    try std.testing.expect(!validCredentials("x" ** (max_credentials_len + 1)));
    try std.testing.expect(validCredentials("actual-key"));
}

test "cron expression grammar" {
    try std.testing.expect(validCronExpr("0 2 * * *"));
    try std.testing.expect(validCronExpr("*/5 * * * *"));
    try std.testing.expect(validCronExpr("0 */6 * * *"));
    try std.testing.expect(validCronExpr("15,45 9-17 * * 1-5"));
    try std.testing.expect(validCronExpr("0 0 */2 * 0"));
    try std.testing.expect(validCronExpr("0 0 * * 7"));
    try std.testing.expect(validCronExpr("0\t2\t*\t*\t*")); // tabs as separators
    try std.testing.expect(validCronExpr("1-5/2 * * * *")); // range steps
    try std.testing.expect(validCronExpr("*/2 * * * *"));
    try std.testing.expect(validCronExpr("1,2,3 * * * *"));
    try std.testing.expect(!validCronExpr("60 * * * *"));
    try std.testing.expect(!validCronExpr("* 24 * * *"));
    try std.testing.expect(!validCronExpr("* * 0 * *"));
    try std.testing.expect(!validCronExpr("* * * 13 *"));
    try std.testing.expect(!validCronExpr("* * * * 8"));
    try std.testing.expect(!validCronExpr("0 2 * *"));
    try std.testing.expect(!validCronExpr("0 2 * * * *"));
    try std.testing.expect(!validCronExpr("@daily"));
    try std.testing.expect(!validCronExpr(""));
    try std.testing.expect(!validCronExpr("0 2 * * %")); // % is newline to cron
    try std.testing.expect(!validCronExpr("0 2 * * *\n"));
    try std.testing.expect(!validCronExpr("1-5/0 * * * *"));
    const hours = try intervalToCronExpr(std.testing.allocator, "hours", 4);
    defer std.testing.allocator.free(hours);
    try std.testing.expectEqualStrings("0 */4 * * *", hours);
    const days = try intervalToCronExpr(std.testing.allocator, "days", 2);
    defer std.testing.allocator.free(days);
    try std.testing.expectEqualStrings("0 0 */2 * *", days);
    try std.testing.expectError(error.InvalidSchedule, intervalToCronExpr(std.testing.allocator, "hours", 48));
    try std.testing.expectError(error.InvalidSchedule, intervalToCronExpr(std.testing.allocator, "days", 60));
}

test "crontab add/remove round trip with id markers" {
    const allocator = std.testing.allocator;
    const empty = "";
    const add1 = try crontabAdd(allocator, empty, "bk-1", "0 2 * * * /bin/sh ~/.local/state/oars/backups/bk-1/run.sh");
    defer allocator.free(add1.content);
    try std.testing.expect(add1.changed);
    try std.testing.expect(std.mem.indexOf(u8, add1.content, "# oars:job:bk-1") != null);
    try std.testing.expect(std.mem.endsWith(u8, add1.content, "\n"));

    // Existing markers are updated in place rather than silently ignored.
    const add2 = try crontabAdd(allocator, add1.content, "bk-1", "0 2 * * * /bin/sh /home/test/.local/state/oars/backups/bk-1/run.sh");
    defer allocator.free(add2.content);
    try std.testing.expect(add2.changed);
    try std.testing.expect(std.mem.indexOf(u8, add2.content, "/home/test/.local/state/oars/backups/bk-1/run.sh") != null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, add2.content, "# oars:job:bk-1"));

    // A second job appends cleanly.
    const add3 = try crontabAdd(allocator, add1.content, "bk-2", "0 3 * * * /bin/sh /home/test/.local/state/oars/backups/bk-2/run.sh");
    defer allocator.free(add3.content);
    try std.testing.expect(std.mem.count(u8, add3.content, "# oars:job:") == 2);

    // Remove bk-1: marker + command line both go.
    const rem1 = try crontabRemove(allocator, add3.content, "bk-1");
    defer allocator.free(rem1.content);
    try std.testing.expect(rem1.changed);
    try std.testing.expect(std.mem.indexOf(u8, rem1.content, "# oars:job:bk-1") == null);
    try std.testing.expect(std.mem.indexOf(u8, rem1.content, "bk-1/run.sh") == null);
    try std.testing.expect(std.mem.indexOf(u8, rem1.content, "# oars:job:bk-2") != null);

    // Removing again is a no-op.
    const rem2 = try crontabRemove(allocator, rem1.content, "bk-1");
    defer allocator.free(rem2.content);
    try std.testing.expect(!rem2.changed);

    // Non-job lines survive untouched.
    const other_job = "# my other job\n0 9 * * * /usr/bin/thing\n";
    const with_other = try std.mem.concat(allocator, u8, &.{ other_job, add1.content });
    defer allocator.free(with_other);
    const rem3 = try crontabRemove(allocator, with_other, "bk-1");
    defer allocator.free(rem3.content);
    try std.testing.expect(std.mem.indexOf(u8, rem3.content, "/usr/bin/thing") != null);
    try std.testing.expect(std.mem.indexOf(u8, rem3.content, "my other job") != null);
}

test "cron percent escaping" {
    const allocator = std.testing.allocator;
    const escaped = try escapePercent(allocator, "run.sh --flag=100%");
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("run.sh --flag=100\\%", escaped);
}

test "rclone config provider matrix and credential modes" {
    const allocator = std.testing.allocator;
    var job = Job{
        .id = "bk-1",
        .server_id = "s1",
        .name = "daily",
        .source_path = "/var/www",
        .destination = .{ .provider = "minio", .bucket = "acme", .endpoint = "http://127.0.0.1:9000" },
    };
    const section = try remoteConfigSection(allocator, &job, "oars-bk-1", "AKID", "SECRET");
    defer secureFree(allocator, section);
    try std.testing.expectEqualStrings("[oars-bk-1]\ntype = s3\nprovider = Minio\naccess_key_id = AKID\nsecret_access_key = SECRET\nendpoint = http://127.0.0.1:9000\n", section);

    job.destination = .{ .provider = "aws", .bucket = "acme", .region = "us-east-1", .credential_mode = .aws_runtime };
    const iam_section = try remoteConfigSection(allocator, &job, "oars-bk-2", null, null);
    defer secureFree(allocator, iam_section);
    try std.testing.expect(std.mem.indexOf(u8, iam_section, "env_auth = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, iam_section, "access_key_id") == null);
    try std.testing.expectError(error.InvalidCredentials, remoteConfigSection(allocator, &job, "oars-bk-2", "AKID", "SECRET"));

    job.destination = .{ .provider = "b2_s3", .bucket = "acme", .endpoint = "https://s3.us-west.example" };
    const b2_section = try remoteConfigSection(allocator, &job, "oars-b2", "AKID", "SECRET");
    defer secureFree(allocator, b2_section);
    try std.testing.expect(std.mem.indexOf(u8, b2_section, "provider = Other") != null);

    job.destination = .{ .provider = "r2", .bucket = "acme", .endpoint = "https://account.r2.cloudflarestorage.com" };
    const r2_section = try remoteConfigSection(allocator, &job, "oars-r2", "AKID", "SECRET");
    defer secureFree(allocator, r2_section);
    try std.testing.expectEqualStrings("[oars-r2]\ntype = s3\nprovider = Cloudflare\naccess_key_id = AKID\nsecret_access_key = SECRET\nendpoint = https://account.r2.cloudflarestorage.com\nregion = auto\n", r2_section);

    job.destination = .{ .provider = "wasabi", .bucket = "acme", .endpoint = "https://s3.us-west-1.wasabisys.com", .region = "us-west-1" };
    const wasabi_section = try remoteConfigSection(allocator, &job, "oars-wasabi", "AKID", "SECRET");
    defer secureFree(allocator, wasabi_section);
    try std.testing.expectEqualStrings("[oars-wasabi]\ntype = s3\nprovider = Wasabi\naccess_key_id = AKID\nsecret_access_key = SECRET\nendpoint = https://s3.us-west-1.wasabisys.com\nregion = us-west-1\n", wasabi_section);

    job.destination = .{ .provider = "minio", .bucket = "acme", .endpoint = "https://minio.example.test", .region = "us-east-1" };
    const minio_section = try remoteConfigSection(allocator, &job, "oars-minio", "AKID", "SECRET");
    defer secureFree(allocator, minio_section);
    try std.testing.expectEqualStrings("[oars-minio]\ntype = s3\nprovider = Minio\naccess_key_id = AKID\nsecret_access_key = SECRET\nendpoint = https://minio.example.test\nregion = us-east-1\n", minio_section);

    job.destination = .{ .provider = "spaces", .bucket = "acme", .endpoint = "https://nyc3.digitaloceanspaces.com", .region = "nyc3" };
    const spaces_section = try remoteConfigSection(allocator, &job, "oars-spaces", "AKID", "SECRET");
    defer secureFree(allocator, spaces_section);
    try std.testing.expectEqualStrings("[oars-spaces]\ntype = s3\nprovider = DigitalOcean\naccess_key_id = AKID\nsecret_access_key = SECRET\nendpoint = https://nyc3.digitaloceanspaces.com\nregion = nyc3\n", spaces_section);
}

test "scheduled wrapper freezes a versioned paired bounded staging protocol" {
    const allocator = std.testing.allocator;
    const job = Job{
        .id = "bk-wrapper",
        .server_id = "server-1",
        .name = "nightly",
        .source_path = "/srv/data with spaces",
        .destination = .{ .provider = "aws", .bucket = "backups", .prefix = "nightly", .region = "us-east-1", .credential_mode = .aws_runtime },
        .transfer = .copy,
        .schedule = .{ .mode = "interval", .enabled = true, .every = 6, .unit = "hours", .anchor_epoch_sec = 1_700_000_000 },
        .revision = 7,
    };
    const basis = ScheduleBasis{
        .home = "/home/oars",
        .rclone_path = "/usr/bin/rclone",
        .crontab_path = "/usr/bin/crontab",
        .timezone = "UTC",
        .target = "alpine",
        .privilege = "root",
        .process_groups = true,
        .crontab = "",
        .crontab_sha256 = [_]u8{0} ** 32,
    };
    const wrapper = try scheduledWrapper(allocator, &job, basis, "/home/oars/.config/oars/rclone.conf", "/home/oars/.local/state/oars/backups/bk-wrapper");
    defer allocator.free(wrapper);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "# version=3") != null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "\"v\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "'/usr/bin/rclone' copy '/srv/data with spaces'") != null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "--use-json-log --stats 1s --stats-log-level NOTICE") != null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "source_missing") != null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "source_unreadable") != null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, ": > \"$RUNS/$RID.log\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "rm -f \"$OLD\" \"$BASE.log\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "1048576") != null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "access_key") == null);
    try std.testing.expect(std.mem.indexOf(u8, wrapper, "secret_key") == null);
}

test "config merge replaces only the job's section" {
    const allocator = std.testing.allocator;
    const existing =
        "# header comment\n" ++
        "[other]\ntype = s3\nprovider = AWS\n" ++
        "[oars-bk-1]\ntype = s3\nprovider = Minio\naccess_key_id = OLD\n";
    const merged = try configMergeSection(allocator, existing, "oars-bk-1", "[oars-bk-1]\ntype = s3\nprovider = Minio\naccess_key_id = NEW\n");
    defer allocator.free(merged);
    try std.testing.expect(std.mem.indexOf(u8, merged, "access_key_id = NEW") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged, "access_key_id = OLD") == null);
    try std.testing.expect(std.mem.indexOf(u8, merged, "[other]") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged, "# header comment") != null);
    const appended = try configMergeSection(allocator, existing, "oars-bk-2", "[oars-bk-2]\ntype = s3\n");
    defer allocator.free(appended);
    try std.testing.expect(std.mem.indexOf(u8, appended, "[oars-bk-2]") != null);
    try std.testing.expect(std.mem.indexOf(u8, appended, "access_key_id = OLD") != null);
}

test "json log stats parsing (top-level and nested)" {
    const allocator = std.testing.allocator;
    // Modern rclone: stats fields top-level.
    const modern = "{\"bytes\":1234,\"checks\":2,\"elapsedTime\":1.5,\"errors\":0,\"eta\":42,\"fatalError\":false,\"retryError\":false,\"speed\":8192,\"totalBytes\":9999,\"transfers\":7,\"transferTime\":1.2,\"level\":\"info\",\"msg\":\"Transferred: 7 / 7, 1.234 KiB / 9.765 KiB, 12%\",\"time\":\"2024-01-01T00:00:00Z\"}";
    switch (parseJsonLogLine(allocator, modern)) {
        .stats => |s| {
            try std.testing.expectEqual(@as(u64, 1234), s.bytes_done);
            try std.testing.expectEqual(@as(u64, 9999), s.bytes_total);
            try std.testing.expectEqual(@as(u64, 7), s.files_done);
            try std.testing.expectEqual(@as(u64, 8192), s.speed_bps);
            try std.testing.expectEqual(@as(i64, 42), s.eta_sec);
        },
        else => return error.TestUnexpectedResult,
    }
    // Older rclone: nested stats object.
    const nested = "{\"stats\":{\"bytes\":555,\"totalBytes\":1000,\"transfers\":3,\"speed\":100,\"eta\":9},\"level\":\"info\",\"msg\":\"...\"}";
    switch (parseJsonLogLine(allocator, nested)) {
        .stats => |s| {
            try std.testing.expectEqual(@as(u64, 555), s.bytes_done);
            try std.testing.expectEqual(@as(u64, 3), s.files_done);
        },
        else => return error.TestUnexpectedResult,
    }
    // Error lines surface the message.
    switch (parseJsonLogLine(allocator, "{\"level\":\"error\",\"msg\":\"AccessDenied: Access Denied\",\"time\":\"...\"}")) {
        .@"error" => |msg| try std.testing.expectEqualStrings("AccessDenied: Access Denied", msg),
        else => return error.TestUnexpectedResult,
    }
    // Non-JSON and unrelated lines are ignored.
    try std.testing.expect(parseJsonLogLine(allocator, "not json") == .other);
    try std.testing.expect(parseJsonLogLine(allocator, "{\"level\":\"info\",\"msg\":\"Sending request\"}") == .other);
}

test "lastStatsFromLog returns the final stats and error" {
    const allocator = std.testing.allocator;
    const log =
        "{\"bytes\":1,\"transfers\":0,\"level\":\"info\"}\n" ++
        "{\"bytes\":100,\"transfers\":5,\"level\":\"info\"}\n" ++
        "{\"level\":\"error\",\"msg\":\"boom\"}\n";
    const result = lastStatsFromLog(allocator, log);
    try std.testing.expectEqual(@as(u64, 100), result.stats.bytes_done);
    try std.testing.expectEqual(@as(u64, 5), result.stats.files_done);
    try std.testing.expectEqualStrings("boom", result.@"error");
}

test "store parent directory sync uses a sync-capable handle" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: [8]u8 = undefined;
    try std.Io.randomSecure(io, &nonce);
    const nonce_hex = std.fmt.bytesToHex(nonce, .lower);
    var dir_buf: [160]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-store-parent-sync-{s}", .{nonce_hex});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var path_buf: [200]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/state.json", .{dir});

    try writeStoreAtomically(allocator, io, path, "{\"ok\":true}");
    const content = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64));
    defer allocator.free(content);
    try std.testing.expectEqualStrings("{\"ok\":true}", content);
}

test "history store appends, prunes, and lists newest first" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [160]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-backup-itest-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var path_buf: [200]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/backup_runs.json", .{dir});
    var store = HistoryStore{ .allocator = allocator, .path = path };

    const day_ns: i64 = 86_400_000_000_000;
    const now_ns: i64 = 1_800_000_000_000_000_000; // ~2027

    var run1 = RunRecord{
        .id = "run-1",
        .job_id = "bk-1",
        .server_id = "s1",
        .status = .success,
        .started_at_ns = now_ns - day_ns,
        .finished_at_ns = now_ns - day_ns + 100,
        .files_done = 3,
    };
    try store.append(io, &run1, now_ns);
    var run2 = RunRecord{
        .id = "run-2",
        .job_id = "bk-1",
        .server_id = "s1",
        .status = .no_changes,
        .started_at_ns = now_ns - 2 * day_ns,
    };
    try store.append(io, &run2, now_ns);
    var run3 = RunRecord{
        .id = "run-3",
        .job_id = "bk-2",
        .server_id = "s1",
        .status = .failed,
        .started_at_ns = now_ns - 3 * day_ns,
        .@"error" = "boom",
    };
    try store.append(io, &run3, now_ns);

    // Idempotent: the same run id is not duplicated.
    try store.append(io, &run1, now_ns);

    const bk1 = try store.listForJob(io, "bk-1", 10);
    defer {
        for (bk1) |*r| r.deinit(allocator);
        allocator.free(bk1);
    }
    try std.testing.expectEqual(@as(usize, 2), bk1.len);
    try std.testing.expectEqualStrings("run-2", bk1[0].id); // newest appended first
    try std.testing.expectEqualStrings("run-1", bk1[1].id);

    const bk2 = try store.listForJob(io, "bk-2", 10);
    defer {
        for (bk2) |*r| r.deinit(allocator);
        allocator.free(bk2);
    }
    try std.testing.expectEqual(@as(usize, 1), bk2.len);
    try std.testing.expectEqualStrings("failed", bk2[0].status.jsonName());
    try std.testing.expectEqualStrings("boom", bk2[0].@"error".?);

    // Retention: a run older than 90 days is pruned on the next append.
    var old = RunRecord{
        .id = "run-old",
        .job_id = "bk-1",
        .server_id = "s1",
        .status = .success,
        .started_at_ns = now_ns - 91 * day_ns, // outside the window
    };
    try store.append(io, &old, now_ns);
    var fresh = RunRecord{
        .id = "run-fresh",
        .job_id = "bk-1",
        .server_id = "s1",
        .status = .success,
        .started_at_ns = now_ns - 60 * 1_000_000_000, // a minute ago
    };
    try store.append(io, &fresh, now_ns);
    const after = try store.listForJob(io, "bk-1", 100);
    defer {
        for (after) |*r| r.deinit(allocator);
        allocator.free(after);
    }
    try std.testing.expectEqual(@as(usize, 3), after.len);
    for (after) |*r| {
        try std.testing.expect(std.mem.indexOf(u8, r.id, "run-old") == null);
    }
}

test "run log trimming caps at the history budget" {
    const allocator = std.testing.allocator;
    var run = RunRecord{
        .id = try allocator.dupe(u8, "run-1"),
        .job_id = try allocator.dupe(u8, "bk-1"),
        .server_id = try allocator.dupe(u8, "s1"),
        .source = try allocator.dupe(u8, "manual"),
    };
    defer run.deinit(allocator);
    const big = "x" ** (history_log_cap + 100);
    try run.trimLog(allocator, big);
    try std.testing.expectEqual(@as(usize, history_log_cap), run.log.?.len);
    try std.testing.expectEqualStrings("x" ** 100, run.log.?[0..100]);
}

test "job store round trip: save, edit, list, delete, id generation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [160]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-backup-store-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var path_buf: [200]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/backups.json", .{dir});
    var store = JobStore{ .allocator = allocator, .path = path };
    const stale_tmp = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(stale_tmp);
    try std.Io.Dir.cwd().createDirPath(io, dir);
    {
        var stale = try std.Io.Dir.cwd().createFile(io, stale_tmp, .{});
        defer stale.close(io);
        try stale.writeStreamingAll(io, "stale-temp-must-not-be-reused");
    }

    const input = JobInput{
        .id = null,
        .server_id = "s1",
        .name = "daily-website",
        .source_path = "/var/www/html",
        .destination = .{ .type = "s3", .provider = "minio", .bucket = "acme", .endpoint = "http://127.0.0.1:9000" },
        .transfer = "sync",
    };
    var saved = try store.save(io, input, null, 1000);
    defer saved.deinit(allocator);
    const encoded = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024));
    defer allocator.free(encoded);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"version\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"jobs\"") != null);
    const stale_content = try std.Io.Dir.cwd().readFileAlloc(io, stale_tmp, allocator, .limited(1024));
    defer allocator.free(stale_content);
    try std.testing.expectEqualStrings("stale-temp-must-not-be-reused", stale_content);
    var durable_file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer durable_file.close(io);
    const durable_stat = try durable_file.stat(io);
    try std.testing.expectEqual(@as(u32, 0), durable_stat.permissions.toMode() & 0o077);
    try std.testing.expect(std.mem.startsWith(u8, saved.id, "bk-"));
    try std.testing.expectEqualStrings("daily-website", saved.name);
    try std.testing.expectEqualStrings("sync", saved.transfer.jsonName());

    // Edit preserves the id and created_at.
    var edited_input = input;
    edited_input.id = saved.id;
    edited_input.name = "daily-www";
    var edited = try store.save(io, edited_input, saved.revision, 2000);
    defer edited.deinit(allocator);
    try std.testing.expectEqualStrings(saved.id, edited.id);
    try std.testing.expectEqualStrings("daily-www", edited.name);
    try std.testing.expectEqual(@as(i64, 1000), edited.created_at_ns);
    try std.testing.expectEqual(@as(i64, 2000), edited.updated_at_ns);

    try std.testing.expectError(error.RevConflict, store.save(io, edited_input, saved.revision, 3000));

    // The local store contains no credentials; remote admission owns that gate.
    var sched_iam = input;
    sched_iam.schedule = .{ .mode = "custom", .expr = "0 2 * * *", .enabled = true };
    sched_iam.destination = .{ .provider = "aws", .bucket = "acme", .region = "us-east-1", .credential_mode = .aws_runtime };
    var iam_saved = try store.save(io, sched_iam, null, 3000);
    iam_saved.deinit(allocator);

    const listed = try store.listForServer(io, "s1");
    defer {
        for (listed) |*j| j.deinit(allocator);
        allocator.free(listed);
    }
    try std.testing.expectEqual(@as(usize, 2), listed.len);
    const other_server = try store.listForServer(io, "s2");
    defer {
        for (other_server) |*j| j.deinit(allocator);
        allocator.free(other_server);
    }
    try std.testing.expectEqual(@as(usize, 0), other_server.len);

    try std.testing.expect((try store.delete(io, saved.id)) == true);
    try std.testing.expect((try store.delete(io, saved.id)) == false);
    const after = try store.listForServer(io, "s1");
    defer {
        for (after) |*j| j.deinit(allocator);
        allocator.free(after);
    }
    try std.testing.expectEqual(@as(usize, 1), after.len);
}

test "job store migrates legacy credential and interval fields internally" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [160]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-backup-migrate-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    try std.Io.Dir.cwd().createDirPath(io, dir);
    var path_buf: [220]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/backups.json", .{dir});
    const legacy = "[{\"id\":\"bk-old\",\"server_id\":\"s1\",\"name\":\"old\",\"source_path\":\"/srv\",\"destination\":{\"type\":\"s3\",\"provider\":\"aws\",\"bucket\":\"bucket\",\"prefix\":\"\",\"endpoint\":\"\",\"region\":\"us-east-1\",\"use_iam\":true,\"storage_class\":\"standard\"},\"transfer\":\"copy\",\"schedule\":{\"mode\":\"interval\",\"interval_unit\":\"hours\",\"interval_every\":12,\"expr\":\"\",\"enabled\":true},\"revision\":1,\"created_at_ns\":1000,\"updated_at_ns\":2000}]";
    {
        var file = try std.Io.Dir.cwd().createFile(io, path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, legacy);
    }
    var store = JobStore{ .allocator = allocator, .path = path };
    var loaded = try store.loadParsed(io);
    defer loaded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), loaded.parsed.value.jobs.len);
    try std.testing.expectEqual(CredentialMode.aws_runtime, loaded.parsed.value.jobs[0].destination.credential_mode);
    try std.testing.expectEqualStrings("", loaded.parsed.value.jobs[0].destination.storage_class);
    try std.testing.expectEqual(@as(u32, 12), loaded.parsed.value.jobs[0].schedule.every);
    try std.testing.expectEqualStrings("hours", loaded.parsed.value.jobs[0].schedule.unit);
    const migrated = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(64 * 1024));
    defer allocator.free(migrated);
    try std.testing.expect(std.mem.indexOf(u8, migrated, "credential_mode") != null);
    try std.testing.expect(std.mem.indexOf(u8, migrated, "use_iam") == null);
    try std.testing.expect(std.mem.indexOf(u8, migrated, "\"version\": 1") != null);
}

test "backup stores migrate bare arrays into versioned bounded envelopes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [180]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-backup-envelope-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    try std.Io.Dir.cwd().createDirPath(io, dir);

    var jobs_path_buf: [240]u8 = undefined;
    const jobs_path = try std.fmt.bufPrint(&jobs_path_buf, "{s}/backups.json", .{dir});
    const bare_job = "[{\"id\":\"bk-current\",\"server_id\":\"s1\",\"name\":\"current\",\"source_path\":\"/srv\",\"destination\":{\"type\":\"s3\",\"provider\":\"aws\",\"bucket\":\"bucket\",\"prefix\":\"\",\"endpoint\":\"\",\"region\":\"us-east-1\",\"credential_mode\":\"aws_runtime\",\"storage_class\":\"\"},\"transfer\":\"copy\",\"schedule\":{\"mode\":\"manual\",\"enabled\":false,\"every\":24,\"unit\":\"hours\",\"anchor_epoch_sec\":0,\"expr\":\"\"},\"revision\":1,\"created_at_ns\":1000,\"updated_at_ns\":2000}]";
    {
        var file = try std.Io.Dir.cwd().createFile(io, jobs_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, bare_job);
    }
    var jobs = JobStore{ .allocator = allocator, .path = jobs_path };
    var loaded_jobs = try jobs.loadParsed(io);
    defer loaded_jobs.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), loaded_jobs.parsed.value.jobs.len);

    var history_path_buf: [240]u8 = undefined;
    const history_path = try std.fmt.bufPrint(&history_path_buf, "{s}/backup_runs.json", .{dir});
    const bare_history = "[{\"id\":\"run-current\",\"job_id\":\"bk-current\",\"server_id\":\"s1\",\"source\":\"scheduled\",\"status\":\"success\",\"started_at_ns\":1000,\"finished_at_ns\":2000}]";
    {
        var file = try std.Io.Dir.cwd().createFile(io, history_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, bare_history);
    }
    var history = HistoryStore{ .allocator = allocator, .path = history_path };
    var loaded_history = try history.loadParsed(io);
    defer loaded_history.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), loaded_history.parsed.value.runs.len);

    const jobs_encoded = try std.Io.Dir.cwd().readFileAlloc(io, jobs_path, allocator, .limited(64 * 1024));
    defer allocator.free(jobs_encoded);
    const history_encoded = try std.Io.Dir.cwd().readFileAlloc(io, history_path, allocator, .limited(64 * 1024));
    defer allocator.free(history_encoded);
    try std.testing.expect(std.mem.indexOf(u8, jobs_encoded, "\"version\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_encoded, "\"version\": 1") != null);
}

test "backup stores quarantine unsupported schemas and reject record-count overflow" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [180]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-backup-schema-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    try std.Io.Dir.cwd().createDirPath(io, dir);
    var jobs_path_buf: [240]u8 = undefined;
    const jobs_path = try std.fmt.bufPrint(&jobs_path_buf, "{s}/backups.json", .{dir});
    {
        var file = try std.Io.Dir.cwd().createFile(io, jobs_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, "{\"version\":2,\"jobs\":[]}");
    }
    var jobs = JobStore{ .allocator = allocator, .path = jobs_path };
    defer jobs.deinitRecovery();
    var loaded_jobs = try jobs.loadParsed(io);
    defer loaded_jobs.deinit(allocator);
    try std.testing.expect(loaded_jobs.recovered);
    try std.testing.expect(loaded_jobs.quarantined != null);

    var history_path_buf: [240]u8 = undefined;
    const history_path = try std.fmt.bufPrint(&history_path_buf, "{s}/backup_runs.json", .{dir});
    {
        var file = try std.Io.Dir.cwd().createFile(io, history_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, "{\"version\":2,\"runs\":[]}");
    }
    var history = HistoryStore{ .allocator = allocator, .path = history_path };
    defer history.deinitRecovery();
    var loaded_history = try history.loadParsed(io);
    defer loaded_history.deinit(allocator);
    try std.testing.expect(loaded_history.recovered);
    try std.testing.expect(loaded_history.quarantined != null);

    const oversized_jobs = try allocator.alloc(Job, max_job_store_records + 1);
    defer allocator.free(oversized_jobs);
    try std.testing.expect(!JobStore.validJobDocument(.{ .version = backup_store_version, .jobs = oversized_jobs }));
    const oversized_runs = try allocator.alloc(RunRecord, max_runs + 1);
    defer allocator.free(oversized_runs);
    try std.testing.expect(!HistoryStore.validHistoryDocument(.{ .version = backup_store_version, .runs = oversized_runs }));
}

test "operation journal restores identity and converts uncertain work to cleanup-only recovery" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [192]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-backup-op-journal-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var jobs_buf: [256]u8 = undefined;
    var history_buf: [256]u8 = undefined;
    const jobs_path = try std.fmt.bufPrint(&jobs_buf, "{s}/jobs.json", .{dir});
    const history_path = try std.fmt.bufPrint(&history_buf, "{s}/runs.json", .{dir});

    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    defer payload_writer.deinit();
    try std.json.Stringify.value(SavePlanPayload{
        .job = .{
            .id = "bk-journal",
            .server_id = "server-journal",
            .name = "journal",
            .source_path = "/srv/journal",
            .destination = .{ .provider = "aws", .bucket = "bucket", .region = "us-east-1", .credential_mode = .aws_runtime },
            .transfer = "copy",
        },
    }, .{}, &payload_writer.writer);

    var first = Registry.init(allocator, jobs_path, history_path);
    first.io = io;
    defer first.deinit();
    try first.loadStoreCaches(io);
    const plan = try testBackupPlan(allocator, .save, "plan-journal", payload_writer.writer.buffered(), true);
    allocator.free(plan.server_id);
    plan.server_id = try allocator.dupe(u8, "server-journal");
    allocator.free(plan.job_id);
    plan.job_id = try allocator.dupe(u8, "bk-journal");
    try first.registerPlan(plan);
    var receipt = try first.admitOperation(.{ .operation_id = "op-journal", .kind = .save, .plan_id = "plan-journal" }, 10);
    defer receipt.receipt.deinit(allocator);
    lockSpin(&first.mutex);
    first.ops.items[0].admission_reported = true;
    first.mutex.unlock();
    var work = (try first.claimNextWork(11)).?;
    defer work.deinit(allocator);
    try first.persistOperationJournal(io);

    var second = Registry.init(allocator, jobs_path, history_path);
    second.io = io;
    defer second.deinit();
    try second.loadStoreCaches(io);
    var retained = (try second.existingReceipt("op-journal", .save, "plan-journal")).?;
    defer retained.deinit(allocator);
    try std.testing.expectEqualStrings("op-journal", retained.operation_id);
    var snapshot = (try second.operationSnapshot("op-journal")).?;
    try std.testing.expectEqual(OperationState.partial, snapshot.state);
    try std.testing.expectEqual(FailureCode.interrupted, snapshot.failure.?.code);
    snapshot.deinit(allocator);
    try std.testing.expectEqual(Registry.CancelOperationResult.accepted, second.cancelOperation("op-journal", null, 12));
    snapshot = (try second.operationSnapshot("op-journal")).?;
    defer snapshot.deinit(allocator);
    try std.testing.expectEqual(OperationKind.cleanup, snapshot.kind);
    try std.testing.expectEqual(OperationState.queued, snapshot.state);

    const journal_path = try operationJournalPath(allocator, history_path);
    defer allocator.free(journal_path);
    var journal_file = try std.Io.Dir.cwd().openFile(io, journal_path, .{});
    defer journal_file.close(io);
    const journal_stat = try journal_file.stat(io);
    try std.testing.expectEqual(@as(u32, 0), journal_stat.permissions.toMode() & 0o077);
}

test "live runs registry: one manual run per server, eviction" {
    const allocator = std.testing.allocator;
    var runs = Runs{ .allocator = allocator };
    defer runs.deinit();
    var run = try runs.start("bk-1", "s1", "manual", 1000);
    try std.testing.expect(runs.runningForServer("s1") == run);
    try std.testing.expect(runs.runningForServer("s2") == null);
    try std.testing.expect(runs.byId(run.record.id) == run);
    run.finalized = true;
    try std.testing.expect(runs.runningForServer("s1") == null);
}

const TestOperationObserver = struct {
    admitted: std.atomic.Value(u32) = .init(0),
    terminal: std.atomic.Value(u32) = .init(0),

    fn notify(context: *anyopaque, event: *const OperationEvent) bool {
        const self: *TestOperationObserver = @ptrCast(@alignCast(context));
        if (event.admitted) {
            _ = self.admitted.fetchAdd(1, .monotonic);
        } else {
            _ = self.terminal.fetchAdd(1, .monotonic);
        }
        return true;
    }
};

fn testBackupPlan(allocator: std.mem.Allocator, kind: PlanKind, id: []const u8, payload_json: []const u8, remote_required: bool) !*BackupPlan {
    const plan = try allocator.create(BackupPlan);
    plan.* = .{ .id = "", .kind = kind, .expires_at_ms = std.math.maxInt(i64), .remote_required = remote_required };
    errdefer {
        plan.deinit(allocator);
        allocator.destroy(plan);
    }
    plan.id = try allocator.dupe(u8, id);
    plan.server_id = try allocator.dupe(u8, "s1");
    plan.job_id = try allocator.dupe(u8, "bk-fixed");
    plan.job_name = try allocator.dupe(u8, "daily");
    plan.payload_json = try allocator.dupe(u8, payload_json);
    return plan;
}

test "registry snapshots remain owned after registry teardown" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, "/tmp/oars-unused-jobs.json", "/tmp/oars-unused-runs.json");
    const plan = try testBackupPlan(allocator, .save, "plan-owned", "{}", false);
    try registry.registerPlan(plan);
    var snapshot = (try registry.planSnapshot("plan-owned", 1)).?;
    registry.deinit();
    defer snapshot.deinit(allocator);
    try std.testing.expectEqualStrings("plan-owned", snapshot.id);
    try std.testing.expectEqualStrings("bk-fixed", snapshot.job_id);
}

test "coordinator persists local saves and fails remote work without an adapter" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [160]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-backup-coordinator-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var jobs_buf: [220]u8 = undefined;
    var runs_buf: [220]u8 = undefined;
    const jobs_path = try std.fmt.bufPrint(&jobs_buf, "{s}/backups.json", .{dir});
    const runs_path = try std.fmt.bufPrint(&runs_buf, "{s}/runs.json", .{dir});
    var registry = Registry.init(allocator, jobs_path, runs_path);
    defer registry.deinit();
    var observer = TestOperationObserver{};
    registry.setObserver(.{ .context = &observer, .notify = TestOperationObserver.notify });
    try registry.ensureStarted(io);
    try registry.ensureStarted(io);

    var payload_writer: std.Io.Writer.Allocating = .init(allocator);
    defer payload_writer.deinit();
    const planned = SavePlanPayload{
        .job = .{
            .id = "bk-fixed",
            .server_id = "s1",
            .name = "daily",
            .source_path = "/srv/data",
            .destination = .{ .provider = "minio", .bucket = "backups", .endpoint = "http://127.0.0.1:9000" },
            .schedule = .{ .mode = "manual", .enabled = false },
        },
    };
    try std.json.Stringify.value(planned, .{}, &payload_writer.writer);
    const save_plan = try testBackupPlan(allocator, .save, "plan-save", payload_writer.writer.buffered(), false);
    try registry.registerPlan(save_plan);
    var save_admission = try registry.admitOperation(.{ .operation_id = "op-save", .kind = .save, .plan_id = "plan-save" }, 1);
    defer save_admission.receipt.deinit(allocator);

    var save_done = false;
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        var snapshot = (try registry.operationSnapshot("op-save")).?;
        defer snapshot.deinit(allocator);
        if (snapshot.state.terminal()) {
            try std.testing.expectEqual(OperationState.done, snapshot.state);
            try std.testing.expect(snapshot.result_json != null);
            save_done = true;
            break;
        }
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(2), .awake) catch {};
    }
    try std.testing.expect(save_done);
    var stored = (try registry.jobs.find(io, "bk-fixed")).?;
    defer stored.deinit(allocator);
    try std.testing.expectEqualStrings("daily", stored.name);

    const remote_plan = try testBackupPlan(allocator, .@"test", "plan-test", payload_writer.writer.buffered(), true);
    try registry.registerPlan(remote_plan);
    var remote_admission = try registry.admitOperation(.{
        .operation_id = "op-test",
        .kind = .@"test",
        .plan_id = "plan-test",
        .credentials = .{ .access_key = "actual-access", .secret_key = "actual-secret" },
    }, 2);
    defer remote_admission.receipt.deinit(allocator);

    var remote_failed = false;
    attempts = 0;
    while (attempts < 100) : (attempts += 1) {
        var snapshot = (try registry.operationSnapshot("op-test")).?;
        defer snapshot.deinit(allocator);
        try std.testing.expect(snapshot.state != .done);
        if (snapshot.state.terminal()) {
            try std.testing.expectEqual(OperationState.failed, snapshot.state);
            try std.testing.expectEqual(FailureCode.not_connected, snapshot.failure.?.code);
            try std.testing.expectEqual(StepState.failed, snapshot.steps[0].state);
            try std.testing.expectEqual(StepState.skipped, snapshot.steps[1].state);
            remote_failed = true;
            break;
        }
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(2), .awake) catch {};
    }
    try std.testing.expect(remote_failed);
    attempts = 0;
    while (attempts < 100 and observer.terminal.load(.acquire) < 2) : (attempts += 1) {
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(2), .awake) catch {};
    }
    try std.testing.expectEqual(@as(u32, 2), observer.admitted.load(.acquire));
    try std.testing.expectEqual(@as(u32, 2), observer.terminal.load(.acquire));
}

const TestRemoteRequestKind = enum {
    exec,
    stat,
    list,
    read,
    write,
    mkdir,
    chmod,
    remove,
    rename,
};

const TestRemoteStep = struct {
    kind: TestRemoteRequestKind,
    needle: []const u8 = "",
    code: sessions.BackupOutcomeCode = .ok,
    exit: ?i32 = 0,
    data: []const u8 = "",
    message: []const u8 = "",
    read_last_write: bool = false,
};

const TestRemote = struct {
    allocator: std.mem.Allocator,
    steps: []const TestRemoteStep,
    index: usize = 0,
    mismatch: bool = false,
    last_write: []u8 = &.{},

    fn deinit(self: *TestRemote) void {
        if (self.last_write.len > 0) secureFree(self.allocator, self.last_write);
    }

    fn submit(context: *anyopaque, _: []const u8, request: sessions.BackupRequest, outcome: *sessions.BackupOutcome) anyerror!void {
        const self: *TestRemote = @ptrCast(@alignCast(context));
        if (self.index >= self.steps.len) {
            self.mismatch = true;
            outcome.set(.internal, null, -1, false, "", "unexpected backup request");
            return;
        }
        const step = self.steps[self.index];
        self.index += 1;
        var kind: TestRemoteRequestKind = undefined;
        var target: []const u8 = "";
        switch (request) {
            .exec => |value| {
                kind = .exec;
                target = value.command;
            },
            .sftp_stat => |value| {
                kind = .stat;
                target = value.path;
            },
            .sftp_list => |value| {
                kind = .list;
                target = value.path;
            },
            .sftp_read => |value| {
                kind = .read;
                target = value.path;
            },
            .sftp_write => |value| {
                kind = .write;
                target = value.path;
                if (self.last_write.len > 0) secureFree(self.allocator, self.last_write);
                self.last_write = try self.allocator.dupe(u8, value.data);
            },
            .sftp_mkdir => |value| {
                kind = .mkdir;
                target = value.path;
            },
            .sftp_chmod => |value| {
                kind = .chmod;
                target = value.path;
            },
            .sftp_remove => |value| {
                kind = .remove;
                target = value.path;
            },
            .sftp_rename => |value| {
                kind = .rename;
                target = value.from;
            },
        }
        if (kind != step.kind or (step.needle.len > 0 and std.mem.indexOf(u8, target, step.needle) == null)) self.mismatch = true;
        if (step.read_last_write) {
            const b64 = try self.allocator.alloc(u8, std.base64.standard.Encoder.calcSize(self.last_write.len));
            defer self.allocator.free(b64);
            _ = std.base64.standard.Encoder.encode(b64, self.last_write);
            const json_bytes = try std.fmt.allocPrint(self.allocator, "{{\"ok\":true,\"base64\":\"{s}\",\"eof\":true}}", .{b64});
            defer self.allocator.free(json_bytes);
            outcome.set(step.code, step.exit, -1, false, json_bytes, step.message);
            return;
        }
        outcome.set(step.code, step.exit, -1, false, step.data, step.message);
    }

    fn start(_: *anyopaque, _: []const u8, _: []const u8, _: ?[]const u8, process: *sessions.BackupProcess) anyerror!void {
        process.complete(0, false, "");
    }

    fn adapter(self: *TestRemote) RemoteAdapter {
        return .{ .context = self, .submit_fn = submit, .start_fn = start };
    }
};

fn testConnectionPayload(allocator: std.mem.Allocator) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer writer.deinit();
    try std.json.Stringify.value(SavePlanPayload{
        .job = .{
            .id = "bk-fixed",
            .server_id = "s1",
            .name = "daily",
            .source_path = "/srv/data",
            .destination = .{ .provider = "minio", .bucket = "backups", .prefix = "prefix", .endpoint = "http://127.0.0.1:9000" },
            .transfer = "copy",
            .schedule = .{ .mode = "manual", .enabled = false },
        },
    }, .{}, &writer.writer);
    return writer.toOwnedSlice();
}

test "capability proofs bind destination auth and transfer but not source or schedule" {
    const base = JobInput{
        .server_id = "s1",
        .name = "daily",
        .source_path = "/srv/a",
        .destination = .{ .provider = "minio", .bucket = "backups", .prefix = "prefix", .endpoint = "http://127.0.0.1:9000" },
        .transfer = "copy",
        .schedule = .{ .mode = "manual", .enabled = false },
    };
    var source_only = base;
    source_only.source_path = "/srv/b";
    source_only.schedule = .{ .mode = "custom", .enabled = true, .expr = "0 2 * * *" };
    try std.testing.expectEqualSlices(u8, &capabilityBinding(base), &capabilityBinding(source_only));
    var transfer_changed = base;
    transfer_changed.transfer = "sync";
    try std.testing.expect(!std.mem.eql(u8, &capabilityBinding(base), &capabilityBinding(transfer_changed)));
    var destination_changed = base;
    destination_changed.destination.bucket = "other";
    try std.testing.expect(!std.mem.eql(u8, &capabilityBinding(base), &capabilityBinding(destination_changed)));
}

test "secret file writes require worker stat mode 0600" {
    const steps = [_]TestRemoteStep{
        .{ .kind = .write, .needle = "/tmp/secret" },
        .{ .kind = .chmod, .needle = "/tmp/secret" },
        .{ .kind = .read, .needle = "/tmp/secret", .exit = null, .read_last_write = true },
        .{ .kind = .stat, .needle = "/tmp/secret", .exit = null, .data = "{\"ok\":true,\"entry\":{\"kind\":\"file\",\"mode\":\"rw-r--r--\"}}" },
    };
    var remote = TestRemote{ .allocator = std.testing.allocator, .steps = &steps };
    defer remote.deinit();
    var registry = Registry.init(std.testing.allocator, "/tmp/oars-unused-mode-jobs", "/tmp/oars-unused-mode-runs");
    defer registry.deinit();
    registry.io = std.testing.io;
    registry.setRemoteAdapter(remote.adapter());
    try std.testing.expectError(error.RemoteModeFailed, registry.writeRemoteFile("s1", "/tmp/secret", "secret", 0o600, true));
    try std.testing.expect(!remote.mismatch);
    try std.testing.expectEqual(steps.len, remote.index);
}

test "connection test cleans admitted partial sentinel and reports exact leftovers" {
    const steps = [_]TestRemoteStep{
        .{ .kind = .exec, .needle = "command -v rclone", .data = "/usr/bin/rclone\n" },
        .{ .kind = .write, .needle = "/tmp/.oars-op-test-cleanup.conf", .exit = null },
        .{ .kind = .chmod, .needle = "/tmp/.oars-op-test-cleanup.conf", .exit = null },
        .{ .kind = .read, .needle = "/tmp/.oars-op-test-cleanup.conf", .exit = null, .read_last_write = true },
        .{ .kind = .stat, .needle = "/tmp/.oars-op-test-cleanup.conf", .exit = null, .data = "{\"ok\":true,\"entry\":{\"kind\":\"file\",\"mode\":\"rw-------\"}}" },
        .{ .kind = .exec, .needle = "oars-bk-fixed:backups/prefix" },
        .{ .kind = .exec, .needle = "rcat 'oars-bk-fixed:backups/prefix/sentinel-exact'", .code = .timeout, .exit = null, .message = "timed out after partial write" },
        .{ .kind = .exec, .needle = "deletefile 'oars-bk-fixed:backups/prefix/sentinel-exact'", .code = .transport, .exit = null, .message = "delete failed" },
        .{ .kind = .exec, .needle = "lsf 'oars-bk-fixed:backups/prefix/sentinel-exact'", .data = "still-present\n" },
        .{ .kind = .remove, .needle = "/tmp/.oars-op-test-cleanup.conf", .exit = null },
        .{ .kind = .stat, .needle = "/tmp/.oars-op-test-cleanup.conf", .code = .not_found, .exit = null },
    };
    var remote = TestRemote{ .allocator = std.testing.allocator, .steps = &steps };
    defer remote.deinit();
    var registry = Registry.init(std.testing.allocator, "/tmp/oars-unused-test-jobs", "/tmp/oars-unused-test-runs");
    defer registry.deinit();
    registry.io = std.testing.io;
    registry.setRemoteAdapter(remote.adapter());
    const payload = try testConnectionPayload(std.testing.allocator);
    defer std.testing.allocator.free(payload);
    var work = OperationWork{
        .operation_id = "op-test-cleanup",
        .kind = .@"test",
        .server_id = "s1",
        .job_id = "bk-fixed",
        .payload_json = payload,
        .remote_object = "prefix/sentinel-exact",
        .remote_required = true,
        .credentials = try OwnedCredentials.init(std.testing.allocator, .{ .access_key = "access", .secret_key = "secret" }),
    };
    defer if (work.credentials) |*credentials| credentials.deinit(std.testing.allocator);
    var completion = registry.testCompletion(&work, 100);
    defer completion.deinit(std.testing.allocator);
    try std.testing.expectEqual(OperationState.partial, completion.state);
    try std.testing.expectEqual(FailureCode.cleanup_failed, completion.failure.?.code);
    try std.testing.expectEqualStrings("prefix/sentinel-exact", completion.failure.?.remote_object);
    try std.testing.expect(completion.cleanup_task != null);
    try std.testing.expect(!remote.mismatch);
    try std.testing.expectEqual(steps.len, remote.index);
}

test "partial secret config write cannot skip exact cleanup failure evidence" {
    const steps = [_]TestRemoteStep{
        .{ .kind = .exec, .needle = "command -v rclone", .data = "/usr/bin/rclone\n" },
        .{ .kind = .write, .needle = "/tmp/.oars-op-config-cleanup.conf", .code = .timeout, .exit = null, .message = "partial write" },
        .{ .kind = .remove, .needle = "/tmp/.oars-op-config-cleanup.conf", .code = .transport, .exit = null, .message = "remove failed" },
    };
    var remote = TestRemote{ .allocator = std.testing.allocator, .steps = &steps };
    defer remote.deinit();
    var registry = Registry.init(std.testing.allocator, "/tmp/oars-unused-partial-jobs", "/tmp/oars-unused-partial-runs");
    defer registry.deinit();
    registry.io = std.testing.io;
    registry.setRemoteAdapter(remote.adapter());
    const payload = try testConnectionPayload(std.testing.allocator);
    defer std.testing.allocator.free(payload);
    var work = OperationWork{
        .operation_id = "op-config-cleanup",
        .kind = .@"test",
        .server_id = "s1",
        .job_id = "bk-fixed",
        .payload_json = payload,
        .remote_object = "prefix/sentinel-exact",
        .remote_required = true,
        .credentials = try OwnedCredentials.init(std.testing.allocator, .{ .access_key = "access", .secret_key = "secret" }),
    };
    defer if (work.credentials) |*credentials| credentials.deinit(std.testing.allocator);
    var completion = registry.testCompletion(&work, 100);
    defer completion.deinit(std.testing.allocator);
    try std.testing.expectEqual(OperationState.partial, completion.state);
    try std.testing.expectEqual(FailureCode.cleanup_failed, completion.failure.?.code);
    try std.testing.expectEqualStrings("/tmp/.oars-op-config-cleanup.conf", completion.failure.?.path);
    try std.testing.expect(!remote.mismatch);
    try std.testing.expectEqual(steps.len, remote.index);
}

test "scheduled save rejects crontab conflicts before any remote write" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const frozen_crontab = "";
    var frozen_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(frozen_crontab, &frozen_hash, .{});
    var writer: std.Io.Writer.Allocating = .init(allocator);
    defer writer.deinit();
    try std.json.Stringify.value(SavePlanPayload{
        .job = .{
            .id = "bk-transaction",
            .server_id = "s1",
            .name = "scheduled",
            .source_path = "/srv/data",
            .destination = .{ .provider = "aws", .bucket = "backups", .region = "us-east-1", .credential_mode = .aws_runtime },
            .transfer = "copy",
            .schedule = .{ .mode = "custom", .enabled = true, .expr = "0 2 * * *" },
        },
        .schedule_basis = .{
            .home = "/home/test",
            .rclone_path = "/usr/bin/rclone",
            .crontab_path = "/usr/bin/crontab",
            .timezone = "UTC",
            .target = "linux",
            .privilege = "user",
            .process_groups = true,
            .crontab = frozen_crontab,
            .crontab_sha256 = frozen_hash,
        },
    }, .{}, &writer.writer);
    const steps = [_]TestRemoteStep{
        .{ .kind = .exec, .needle = " -l", .data = "# unrelated external change\n" },
        .{ .kind = .read, .needle = "/home/test/.config/oars/rclone.conf", .code = .not_found, .exit = null },
    };
    var remote = TestRemote{ .allocator = allocator, .steps = &steps };
    defer remote.deinit();
    var registry = Registry.init(allocator, "/tmp/oars-unused-transaction-jobs", "/tmp/oars-unused-transaction-runs");
    defer registry.deinit();
    registry.io = io;
    registry.setRemoteAdapter(remote.adapter());
    const work = OperationWork{
        .operation_id = "op-transaction",
        .kind = .save,
        .server_id = "s1",
        .job_id = "bk-transaction",
        .payload_json = writer.writer.buffered(),
        .remote_object = "",
        .remote_required = true,
    };
    var completion = registry.saveCompletion(io, &work, 100);
    defer completion.deinit(allocator);
    try std.testing.expectEqual(OperationState.failed, completion.state);
    try std.testing.expectEqual(FailureCode.conflict, completion.failure.?.code);
    try std.testing.expect(completion.cleanup_task == null);
    try std.testing.expectEqual(steps.len, remote.index);
    try std.testing.expect(!remote.mismatch);
}

test "operationCancel retries a retained cleanup operation without erasing partial evidence" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, "/tmp/oars-unused-cleanup-jobs", "/tmp/oars-unused-cleanup-runs");
    defer registry.deinit();
    registry.io = std.testing.io;
    const plan = try testBackupPlan(allocator, .@"test", "plan-cleanup", "{}", true);
    try registry.registerPlan(plan);
    const other_plan = try testBackupPlan(allocator, .install, "plan-other", "{}", true);
    try registry.registerPlan(other_plan);
    var admission = try registry.admitOperation(.{ .operation_id = "op-cleanup", .kind = .@"test", .plan_id = "plan-cleanup" }, 1);
    defer admission.receipt.deinit(allocator);
    lockSpin(&registry.mutex);
    registry.ops.items[0].admission_reported = true;
    registry.mutex.unlock();
    var claimed = (try registry.claimNextWork(2)).?;
    claimed.deinit(allocator);
    var partial = Completion{
        .state = .partial,
        .failure = try BackupFailure.init(allocator, .cleanup_failed, "leftover", true, "cleanup"),
        .cleanup_task = .{
            .kind = .test_sentinel,
            .config_path = try allocator.dupe(u8, "/tmp/exact-leftover"),
            .job = try cloneJobOwned(allocator, .{
                .id = "bk-fixed",
                .server_id = "s1",
                .name = "daily",
                .source_path = "/srv/data",
                .destination = .{ .provider = "aws", .bucket = "backups", .region = "us-east-1", .credential_mode = .aws_runtime },
            }),
        },
    };
    partial.failure.?.path = try allocator.dupe(u8, "/tmp/exact-leftover");
    registry.completeWork("op-cleanup", &partial, 3);
    partial.deinit(allocator);

    var other = try registry.admitOperation(.{ .operation_id = "op-other", .kind = .install, .plan_id = "plan-other" }, 4);
    defer other.receipt.deinit(allocator);
    try std.testing.expectEqual(Registry.CancelOperationResult.busy, registry.cancelOperation("op-cleanup", null, 5));
    try std.testing.expectEqual(Registry.CancelOperationResult.accepted, registry.cancelOperation("op-other", null, 6));
    try std.testing.expectEqual(Registry.CancelOperationResult.accepted, registry.cancelOperation("op-cleanup", null, 7));
    var queued = (try registry.operationSnapshot("op-cleanup")).?;
    try std.testing.expectEqual(OperationKind.cleanup, queued.kind);
    try std.testing.expectEqual(OperationState.queued, queued.state);
    try std.testing.expectEqual(FailureCode.cleanup_failed, queued.failure.?.code);
    queued.deinit(allocator);

    lockSpin(&registry.mutex);
    for (registry.ops.items) |op| {
        if (std.mem.eql(u8, op.id, "op-cleanup")) op.admission_reported = true;
    }
    registry.mutex.unlock();

    const steps = [_]TestRemoteStep{
        .{ .kind = .remove, .needle = "/tmp/exact-leftover", .exit = null },
        .{ .kind = .stat, .needle = "/tmp/exact-leftover", .code = .not_found, .exit = null },
    };
    var remote = TestRemote{ .allocator = allocator, .steps = &steps };
    defer remote.deinit();
    registry.setRemoteAdapter(remote.adapter());
    var cleanup_work = (try registry.claimNextWork(8)).?;
    var completion = registry.executeWork(std.testing.io, &cleanup_work, 9);
    registry.completeWork("op-cleanup", &completion, 10);
    completion.deinit(allocator);
    cleanup_work.deinit(allocator);
    var done = (try registry.operationSnapshot("op-cleanup")).?;
    defer done.deinit(allocator);
    try std.testing.expectEqual(OperationKind.cleanup, done.kind);
    try std.testing.expectEqual(OperationState.done, done.state);
    try std.testing.expect(!remote.mismatch);
}

test "cancel escalation reaches KILL after failed TERM and has a post-KILL deadline" {
    var escalation: Registry.CancelEscalation = .{};
    escalation.begin(100);
    try std.testing.expect(!escalation.shouldKill(100 + std.time.ns_per_s));
    try std.testing.expect(escalation.shouldKill(100 + 2 * std.time.ns_per_s));
    try std.testing.expect(escalation.shouldKill(100 + 2 * std.time.ns_per_s));
    escalation.killed(100 + 2 * std.time.ns_per_s);
    try std.testing.expect(!escalation.postKillExpired(100 + 3 * std.time.ns_per_s));
    try std.testing.expect(escalation.postKillExpired(100 + 4 * std.time.ns_per_s));
}

test "process group absence requires a successful explicit absence marker" {
    const steps = [_]TestRemoteStep{
        .{ .kind = .exec, .needle = "__OARS_ABSENT__", .code = .ok, .exit = 1 },
        .{ .kind = .exec, .needle = "__OARS_ABSENT__", .code = .ok, .exit = 0, .data = "__OARS_ABSENT__\n" },
    };
    var remote = TestRemote{ .allocator = std.testing.allocator, .steps = &steps };
    defer remote.deinit();
    var registry = Registry.init(std.testing.allocator, "/tmp/oars-unused-probe-jobs", "/tmp/oars-unused-probe-runs");
    defer registry.deinit();
    registry.io = std.testing.io;
    registry.setRemoteAdapter(remote.adapter());
    try std.testing.expect(!registry.processGroupAbsent("s1", "123"));
    try std.testing.expect(registry.processGroupAbsent("s1", "123"));
    try std.testing.expect(!remote.mismatch);
}

test "disconnect cancellation performs TERM then KILL then explicit absence" {
    const steps = [_]TestRemoteStep{
        .{ .kind = .exec, .needle = "kill -TERM -123", .code = .ok, .exit = 1 },
        .{ .kind = .exec, .needle = "__OARS_ABSENT__", .code = .ok, .exit = 0, .data = "__OARS_PRESENT__\n" },
        .{ .kind = .exec, .needle = "kill -KILL -123", .code = .ok, .exit = 0 },
        .{ .kind = .exec, .needle = "__OARS_ABSENT__", .code = .ok, .exit = 0, .data = "__OARS_ABSENT__\n" },
    };
    var remote = TestRemote{ .allocator = std.testing.allocator, .steps = &steps };
    defer remote.deinit();
    var registry = Registry.init(std.testing.allocator, "/tmp/oars-unused-terminate-jobs", "/tmp/oars-unused-terminate-runs");
    defer registry.deinit();
    registry.io = std.testing.io;
    registry.setRemoteAdapter(remote.adapter());
    try std.testing.expect(registry.terminateProcessGroup("s1", "123", 0, 0));
    try std.testing.expectEqual(steps.len, remote.index);
    try std.testing.expect(!remote.mismatch);
}

test "successful manual run becomes store_corrupt partial when history persistence fails" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [192]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-backup-history-fail-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    try std.Io.Dir.cwd().createDirPath(io, dir);
    var history_buf: [256]u8 = undefined;
    const history_path = try std.fmt.bufPrint(&history_buf, "{s}/history-as-directory", .{dir});
    try std.Io.Dir.cwd().createDirPath(io, history_path);
    var registry = Registry.init(allocator, "/tmp/oars-unused-history-jobs", history_path);
    defer registry.deinit();
    registry.io = io;
    registry.runs.lock();
    const run = try registry.runs.startEx("run-history-fail", "bk-fixed", "s1", "manual", 1);
    registry.runs.unlock();
    registry.finishLiveRun(io, run, .success, true, null);
    registry.runs.lock();
    defer registry.runs.unlock();
    try std.testing.expectEqual(RunStatus.partial, run.record.status);
    try std.testing.expectEqual(FailureCode.store_corrupt, run.failure.?.code);
    try std.testing.expect(run.finalized);
}

const AuditRetryObserver = struct {
    terminal_ok: bool = false,

    fn operation(_: *anyopaque, _: *const OperationEvent) bool {
        return true;
    }

    fn run(context: *anyopaque, event: *const RunEvent) bool {
        const self: *AuditRetryObserver = @ptrCast(@alignCast(context));
        return event.admitted or self.terminal_ok;
    }
};

test "terminal audit is acknowledged only after durable observer success" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [192]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-backup-audit-fail-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var history_buf: [256]u8 = undefined;
    const history_path = try std.fmt.bufPrint(&history_buf, "{s}/history.json", .{dir});
    var registry = Registry.init(allocator, "/tmp/oars-unused-audit-jobs", history_path);
    defer registry.deinit();
    registry.io = io;
    var observer = AuditRetryObserver{};
    registry.setObserver(.{ .context = &observer, .notify = AuditRetryObserver.operation, .notify_run = AuditRetryObserver.run });
    registry.runs.lock();
    const run = try registry.runs.startEx("run-audit-fail", "bk-fixed", "s1", "manual", 1);
    run.admission_reported = true;
    registry.runs.unlock();
    registry.finishLiveRun(io, run, .success, true, null);
    registry.drainEvents();
    registry.runs.lock();
    try std.testing.expectEqual(RunStatus.partial, run.record.status);
    try std.testing.expectEqual(FailureCode.store_corrupt, run.failure.?.code);
    try std.testing.expect(!run.terminal_reported);
    registry.runs.unlock();
    observer.terminal_ok = true;
    registry.drainEvents();
    registry.runs.lock();
    defer registry.runs.unlock();
    try std.testing.expect(run.terminal_reported);
}

test "manual execution cannot start before durable admission audit" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [192]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-backup-admission-gate-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var jobs_buf: [256]u8 = undefined;
    var history_buf: [256]u8 = undefined;
    const jobs_path = try std.fmt.bufPrint(&jobs_buf, "{s}/jobs.json", .{dir});
    const history_path = try std.fmt.bufPrint(&history_buf, "{s}/history.json", .{dir});
    var registry = Registry.init(allocator, jobs_path, history_path);
    registry.io = io;
    defer registry.deinit();
    try registry.loadStoreCaches(io);
    const job = Job{
        .id = "bk-audited",
        .server_id = "server-audited",
        .name = "audited",
        .source_path = "/srv/audited",
        .destination = .{ .provider = "aws", .bucket = "bucket", .region = "us-east-1", .credential_mode = .aws_runtime },
    };
    var receipt = try registry.admitRun("op-audited", &job, null, 1);
    defer receipt.deinit(allocator);

    try std.testing.expect(registry.claimQueuedRun() == null);
    registry.runs.lock();
    const run = registry.runs.byId(receipt.run_id).?;
    run.admission_reported = true;
    registry.runs.unlock();
    try std.testing.expect(registry.claimQueuedRun() != null);
}

test "registry read snapshots never reopen stores on the caller thread" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [192]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-backup-cache-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var jobs_buf: [256]u8 = undefined;
    var history_buf: [256]u8 = undefined;
    const jobs_path = try std.fmt.bufPrint(&jobs_buf, "{s}/jobs.json", .{dir});
    const history_path = try std.fmt.bufPrint(&history_buf, "{s}/runs.json", .{dir});
    var store = JobStore{ .allocator = allocator, .path = jobs_path };
    defer store.deinitRecovery();
    var saved = try store.savePlanned(io, .{
        .id = "bk-cached",
        .server_id = "server-cache",
        .name = "cached",
        .source_path = "/srv/cached",
        .destination = .{ .provider = "aws", .bucket = "bucket", .region = "us-east-1", .credential_mode = .aws_runtime },
    }, null, true, 1);
    saved.deinit(allocator);

    var registry = Registry.init(allocator, jobs_path, history_path);
    registry.io = io;
    defer registry.deinit();
    try std.testing.expectError(error.StoreNotReady, registry.jobSnapshot("bk-cached"));
    try registry.loadStoreCaches(io);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = jobs_path, .data = "not-json" });
    var cached = (try registry.jobSnapshot("bk-cached")).?;
    defer cached.deinit(allocator);
    try std.testing.expectEqualStrings("cached", cached.name);
}

const ShutdownObserver = struct {
    admitted_runs: std.atomic.Value(u32) = .init(0),
    terminal_runs: std.atomic.Value(u32) = .init(0),

    fn operation(_: *anyopaque, _: *const OperationEvent) bool {
        return true;
    }

    fn run(context: *anyopaque, event: *const RunEvent) bool {
        const self: *ShutdownObserver = @ptrCast(@alignCast(context));
        if (event.admitted) {
            _ = self.admitted_runs.fetchAdd(1, .monotonic);
        } else {
            _ = self.terminal_runs.fetchAdd(1, .monotonic);
        }
        return true;
    }
};

test "coordinator shutdown finalizes queued runs through the cancel path" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [192]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-backup-shutdown-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var jobs_buf: [256]u8 = undefined;
    var history_buf: [256]u8 = undefined;
    const jobs_path = try std.fmt.bufPrint(&jobs_buf, "{s}/jobs.json", .{dir});
    const history_path = try std.fmt.bufPrint(&history_buf, "{s}/history.json", .{dir});
    var registry = Registry.init(allocator, jobs_path, history_path);
    var observer = ShutdownObserver{};
    registry.setObserver(.{ .context = &observer, .notify = ShutdownObserver.operation, .notify_run = ShutdownObserver.run });
    try registry.ensureStarted(io);
    while (true) {
        var health = try registry.storeHealthSnapshot();
        defer health.deinit(allocator);
        if (health.ready) break;
        if (health.failed) return error.TestUnexpectedResult;
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    const job = Job{
        .id = "bk-shutdown",
        .server_id = "s1",
        .name = "shutdown",
        .source_path = "/srv/data",
        .destination = .{ .provider = "aws", .bucket = "backups", .region = "us-east-1", .credential_mode = .aws_runtime },
    };
    var receipt = try registry.admitRun("op-shutdown", &job, null, 1);
    receipt.deinit(allocator);
    registry.deinit();
    try std.testing.expectEqual(@as(u32, 1), observer.admitted_runs.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1), observer.terminal_runs.load(.acquire));
}

test "cancel re-admits a partial manual run as exact cleanup-only work" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buf: [192]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/oars-backup-manual-cleanup-{d}", .{std.Io.Timestamp.now(io, .real).nanoseconds});
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    var jobs_buf: [256]u8 = undefined;
    var history_buf: [256]u8 = undefined;
    var registry = Registry.init(
        allocator,
        try std.fmt.bufPrint(&jobs_buf, "{s}/jobs.json", .{dir}),
        try std.fmt.bufPrint(&history_buf, "{s}/runs.json", .{dir}),
    );
    registry.io = io;
    defer registry.deinit();
    try registry.loadStoreCaches(io);
    const job = Job{
        .id = "bk-cleanup-run",
        .server_id = "s1",
        .name = "cleanup",
        .source_path = "/srv/data",
        .destination = .{ .provider = "aws", .bucket = "backups", .region = "us-east-1", .credential_mode = .aws_runtime },
    };
    var receipt = try registry.admitRun("op-cleanup-run", &job, null, 1);
    defer receipt.deinit(allocator);
    registry.runs.lock();
    const run = registry.runs.byId(receipt.run_id).?;
    run.record.status = .partial;
    run.outcome_status = .success;
    run.finalized = true;
    run.admission_reported = true;
    run.terminal_reported = true;
    registry.replaceRunText(&run.cleanup_state, "failed");
    registry.replaceRunText(&run.temp_config, "/tmp/exact-config");
    registry.replaceRunText(&run.state_dir_path, "/tmp/exact-state");
    registry.runs.unlock();

    try std.testing.expect(registry.cancelRun(receipt.run_id));
    registry.runs.lock();
    defer registry.runs.unlock();
    try std.testing.expect(run.cleanup_retry);
    try std.testing.expectEqual(RunStatus.queued, run.record.status);
    try std.testing.expect(!run.admission_reported);
    try std.testing.expect(!run.terminal_reported);
    try std.testing.expectEqualStrings("cleanup_retry_queued", run.phase);
}

test "manual cleanup removes config, process id, and empty state directory in order" {
    const allocator = std.testing.allocator;
    const steps = [_]TestRemoteStep{
        .{ .kind = .remove, .needle = "/tmp/exact-state/rclone.conf" },
        .{ .kind = .stat, .needle = "/tmp/exact-state/rclone.conf", .code = .not_found, .exit = null },
        .{ .kind = .remove, .needle = "/tmp/exact-state/pgid" },
        .{ .kind = .stat, .needle = "/tmp/exact-state/pgid", .code = .not_found, .exit = null },
        .{ .kind = .remove, .needle = "/tmp/exact-state" },
        .{ .kind = .stat, .needle = "/tmp/exact-state", .code = .not_found, .exit = null },
    };
    var remote = TestRemote{ .allocator = allocator, .steps = &steps };
    defer remote.deinit();
    var registry = Registry.init(allocator, "/tmp/oars-unused-manual-cleanup-jobs", "/tmp/oars-unused-manual-cleanup-runs");
    defer registry.deinit();
    registry.io = std.testing.io;
    registry.setRemoteAdapter(remote.adapter());
    registry.runs.lock();
    const run = try registry.runs.startEx("run-manual-cleanup", "bk-fixed", "s1", "manual", 1);
    registry.replaceRunText(&run.temp_config, "/tmp/exact-state/rclone.conf");
    registry.replaceRunText(&run.state_dir_path, "/tmp/exact-state");
    registry.runs.unlock();

    try std.testing.expect(registry.cleanupLiveRunArtifacts(run) == null);
    try std.testing.expectEqual(steps.len, remote.index);
    try std.testing.expect(!remote.mismatch);
}
