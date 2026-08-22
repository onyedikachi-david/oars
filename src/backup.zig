//! Spec 10: backups — the job model + stores (no secrets), rclone remote
//! config generation, crontab add/remove with `# oars:job:<id>` markers,
//! JSON-log `stats` parsing, the sentinel capability-test plan, and the
//! run record state machine. Pure logic + registries; the bridge handlers
//! drive the execs/SFTP writes.
//!
//! Secret rules (spec 10 §8): bucket credentials live in Keychain
//! (`backup:<job_id>`) and never in jobs.json, run history, or audit.
//! The dedicated remote config for unattended schedules is the only
//! server-side secret copy (mode 0600, reversible obscuring disclosure).

const std = @import("std");

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
pub const max_credentials_len: usize = 4096;
pub const history_retention_ns: i64 = history_retention_days * 86_400_000_000_000;

/// Bounds for NEXT-SPEC §Exact bounds — centralize here.
pub fn validId(id: []const u8) bool {
    if (id.len == 0 or id.len > max_id_len) return false;
    for (id) |ch| {
        if (ch == 0 or ch < 0x20 or ch == 0x7f) return false;
        if (ch == '/' or ch == '\\' or ch == '"' or ch == '\'' or ch == '`' or ch == '$' or ch == '\n' or ch == '\r') return false;
    }
    return true;
}

pub fn validCredentials(s: []const u8) bool {
    if (s.len == 0 or s.len > max_credentials_len) return false;
    for (s) |ch| if (ch == 0 or ch == '\n' or ch == '\r') return false;
    return true;
}

/// "prefix" normalization: strip one leading/trailing `/`, reject empties
/// that become empty only due to slashes, keep interior.
pub fn normalizePrefix(allocator: std.mem.Allocator, prefix: []const u8) ![]u8 {
    var s = std.mem.trim(u8, prefix, " \t\r\n");
    if (s.len > 0 and s[0] == '/') s = s[1..];
    if (s.len > 0 and s[s.len - 1] == '/') s = s[0 .. s.len - 1];
    return allocator.dupe(u8, s);
}

/// Random job/run id like "bk-<16 hex>" using secure RNG.
pub fn randomJobId(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    var bytes: [8]u8 = undefined;
    try std.Io.randomSecure(io, &bytes);
    const hex = std.fmt.bytesToHex(bytes, .lower);
    return std.fmt.allocPrint(allocator, "bk-{s}", .{hex});
}

pub fn randomRunId(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    var bytes: [8]u8 = undefined;
    try std.Io.randomSecure(io, &bytes);
    const hex = std.fmt.bytesToHex(bytes, .lower);
    return std.fmt.allocPrint(allocator, "run-{s}", .{hex});
}

// --- providers -------------------------------------------------------------

pub const Provider = enum(u8) {
    aws,
    r2,
    b2,
    wasabi,
    minio,
    spaces,

    pub fn jsonName(self: Provider) []const u8 {
        return @tagName(self);
    }

    pub fn fromJsonName(name: []const u8) ?Provider {
        if (std.mem.eql(u8, name, "aws")) return .aws;
        if (std.mem.eql(u8, name, "r2")) return .r2;
        if (std.mem.eql(u8, name, "b2")) return .b2;
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
            .b2 => "Other",
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

pub const Destination = struct {
    type: []const u8 = "s3", // "s3" | "local" (local = Oars+; modeled, execution deferred)
    provider: []const u8 = "aws",
    bucket: []const u8 = "",
    prefix: []const u8 = "",
    endpoint: []const u8 = "",
    region: []const u8 = "",
    use_iam: bool = false,
    storage_class: []const u8 = "standard",
};

pub const Schedule = struct {
    mode: []const u8 = "manual", // manual | interval | custom
    interval_unit: []const u8 = "hours", // hours | days (interval mode)
    interval_every: u32 = 24,
    expr: []const u8 = "",
    enabled: bool = false,
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
        if (self.schedule.interval_unit.len > 0) allocator.free(self.schedule.interval_unit);
        if (self.schedule.expr.len > 0) allocator.free(self.schedule.expr);
    }
};

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
    expected_revision: ?u64 = null,
};

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
};

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

pub fn validate(input: JobInput, schedule_credentials: ?[]const u8) SaveError!void {
    // Generated ids are validated at admission; edits verify revision/server.
    if (input.id) |jid| if (!validId(jid)) return error.InvalidId;
    if (input.expected_revision) |_| {} // validated in JobStore.save (optimistic concurrency)
    const name = std.mem.trim(u8, input.name, " \t\r\n");
    if (name.len == 0) return error.MissingName;
    if (name.len > max_job_name_len or hasControlChars(name)) return error.InvalidName;
    if (input.server_id.len == 0) return error.MissingServer;
    if (!validId(input.server_id)) return error.InvalidId;
    const source = std.mem.trim(u8, input.source_path, " \t\r\n");
    if (source.len == 0) return error.MissingSource;
    if (source.len > max_source_path_len or hasControlChars(source) or source[0] != '/') return error.InvalidSource;

    if (std.mem.eql(u8, input.destination.type, "local")) {
        // Oars+ destination: modeled and validated, execution deferred.
        return;
    }
    if (!std.mem.eql(u8, input.destination.type, "s3")) return error.InvalidDestination;
    const provider = Provider.fromJsonName(input.destination.provider) orelse return error.InvalidProvider;
    if (!validBucketName(input.destination.bucket)) return error.InvalidBucket;
    // Prefix: allow empty, else reject controls, NUL, and overlong after trim.
    {
        const p = std.mem.trim(u8, input.destination.prefix, " \t\r\n");
        if (p.len > max_prefix_len or hasControlChars(p)) return error.InvalidDestination;
        if (std.mem.indexOfScalar(u8, p, 0) != null) return error.InvalidDestination;
    }
    // Endpoint: adapter-owned requirement; plain http only for MinIO test adapter.
    if (provider.needsEndpoint()) {
        if (!validEndpoint(input.destination.endpoint)) return error.InvalidEndpoint;
        if (std.mem.startsWith(u8, input.destination.endpoint, "http://") and provider != .minio) return error.InvalidEndpoint;
    } else if (input.destination.endpoint.len > 0) {
        if (!validEndpoint(input.destination.endpoint)) return error.InvalidEndpoint;
    }
    if (provider.needsRegion() and !validRegion(input.destination.region)) return error.InvalidRegion;
    if (!provider.supportsStorageClass(input.destination.storage_class)) return error.InvalidStorageClass;
    if (input.destination.use_iam and provider != .aws) return error.IamRequiresAws;

    // Credentials shape when present (INI injection guard): non-empty, bounded, no CR/LF/NUL.
    if (schedule_credentials) |creds| {
        if (creds.len == 0) return error.InvalidCredentials;
        if (creds.len > max_credentials_len) return error.InvalidCredentials;
        if (std.mem.indexOfScalar(u8, creds, 0) != null or std.mem.indexOfScalar(u8, creds, '\n') != null or std.mem.indexOfScalar(u8, creds, '\r') != null) return error.InvalidCredentials;
    }

    if (Transfer.fromJsonName(input.transfer) == null) return error.InvalidTransfer;

    const mode = input.schedule.mode;
    if (!std.mem.eql(u8, mode, "manual") and !std.mem.eql(u8, mode, "interval") and !std.mem.eql(u8, mode, "custom")) return error.InvalidSchedule;
    if (std.mem.eql(u8, mode, "interval")) {
        if (!std.mem.eql(u8, input.schedule.interval_unit, "hours") and !std.mem.eql(u8, input.schedule.interval_unit, "days")) return error.InvalidSchedule;
        if (input.schedule.interval_every == 0) return error.InvalidSchedule;
        // Bounds per NEXT-SPEC §Exact bounds
        if (std.mem.eql(u8, input.schedule.interval_unit, "hours") and input.schedule.interval_every > 168) return error.InvalidSchedule;
        if (std.mem.eql(u8, input.schedule.interval_unit, "days") and input.schedule.interval_every > 365) return error.InvalidSchedule;
    }
    if (std.mem.eql(u8, mode, "custom")) {
        if (!validCronExpr(input.schedule.expr)) return error.InvalidCronExpr;
    }
    if (input.schedule.enabled and !std.mem.eql(u8, mode, "manual")) {
        if (!input.destination.use_iam and schedule_credentials == null) return error.EnabledScheduleNeedsCredentials;
    }
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
    return std.fmt.allocPrint(allocator, "# oars:job:{s}", .{job_id});
}

/// Adds the job's crontab lines. Idempotent: a table that already carries
/// the marker is returned unchanged. Ensures a trailing newline.
pub fn crontabAdd(allocator: std.mem.Allocator, existing: []const u8, job_id: []const u8, line: []const u8) !struct { content: []u8, changed: bool } {
    const marker = try crontabMarker(allocator, job_id);
    defer allocator.free(marker);
    if (std.mem.indexOf(u8, existing, marker) != null) {
        return .{ .content = try allocator.dupe(u8, existing), .changed = false };
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator); // safe after toOwnedSlice (list empties)
    try out.appendSlice(allocator, existing);
    if (existing.len > 0 and existing[existing.len - 1] != '\n') try out.append(allocator, '\n');
    try out.appendSlice(allocator, marker);
    try out.append(allocator, '\n');
    try out.appendSlice(allocator, line);
    try out.append(allocator, '\n');
    return .{ .content = try out.toOwnedSlice(allocator), .changed = true };
}

/// Removes the job's marker line and the command line that follows it.
pub fn crontabRemove(allocator: std.mem.Allocator, existing: []const u8, job_id: []const u8) !struct { content: []u8, changed: bool } {
    const marker = try crontabMarker(allocator, job_id);
    defer allocator.free(marker);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator); // safe after toOwnedSlice (list empties)
    var changed = false;
    var lines = std.mem.splitScalar(u8, existing, '\n');
    var skip_next = false;
    while (lines.next()) |line| {
        if (skip_next) {
            skip_next = false;
            changed = true;
            continue;
        }
        if (std.mem.eql(u8, std.mem.trim(u8, line, "\r"), marker)) {
            skip_next = true;
            changed = true;
            continue;
        }
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
    }
    if (!changed) return .{ .content = try allocator.dupe(u8, existing), .changed = false };
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
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    {
        const part = try std.fmt.allocPrint(allocator, "[{s}]\ntype = s3\nprovider = {s}\n", .{ remote, provider.rcloneName() });
        defer allocator.free(part);
        try out.appendSlice(allocator, part);
    }
    if (job.destination.use_iam) {
        if (provider != .aws) return error.IamRequiresAws;
        try out.appendSlice(allocator, "env_auth = true\n");
        try out.appendSlice(allocator, "access_key_id = \nsecret_access_key = \n");
    } else {
        // Validate credential shape to prevent INI injection (CR/LF/NUL).
        if (access_key) |k| if (std.mem.indexOfScalar(u8, k, '\n') != null or std.mem.indexOfScalar(u8, k, '\r') != null or std.mem.indexOfScalar(u8, k, 0) != null) return error.InvalidDestination;
        if (secret_key) |k| if (std.mem.indexOfScalar(u8, k, '\n') != null or std.mem.indexOfScalar(u8, k, '\r') != null or std.mem.indexOfScalar(u8, k, 0) != null) return error.InvalidDestination;
        const part = try std.fmt.allocPrint(allocator, "access_key_id = {s}\nsecret_access_key = {s}\n", .{ access_key orelse "", secret_key orelse "" });
        defer allocator.free(part);
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
pub const wrapper_version: u32 = 2;

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
    running,
    success,
    failed,
    no_changes,
    interrupted,

    pub fn jsonName(self: RunStatus) []const u8 {
        return switch (self) {
            .running => "running",
            .success => "success",
            .failed => "failed",
            .no_changes => "no_changes",
            .interrupted => "interrupted",
        };
    }
};

/// A completed or in-flight run (manual or imported-scheduled).
pub const RunRecord = struct {
    id: []const u8,
    job_id: []const u8,
    server_id: []const u8,
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
    log: ?[]const u8 = null,

    pub fn deinit(self: *RunRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.job_id);
        allocator.free(self.server_id);
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

pub const HistoryStore = struct {
    allocator: std.mem.Allocator = undefined,
    path: []const u8 = "",
    mutex: std.atomic.Mutex = .unlocked,

    pub const Loaded = struct {
        parsed: std.json.Parsed([]RunRecord),
        content: ?[]u8,
        quarantined: ?[]const u8 = null,

        pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
            self.parsed.deinit();
            if (self.content) |c| allocator.free(c);
            if (self.quarantined) |q| allocator.free(q);
        }
    };

    pub fn loadParsed(self: *HistoryStore, io: std.Io) !Loaded {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.loadParsedLocked(io);
    }

    fn loadParsedLocked(self: *HistoryStore, io: std.Io) !Loaded {
        const cwd = std.Io.Dir.cwd();
        const content = cwd.readFileAlloc(io, self.path, self.allocator, .limited(32 * 1024 * 1024)) catch return emptyLoaded(self.allocator);
        const parsed = std.json.parseFromSlice([]RunRecord, self.allocator, content, .{}) catch {
            self.allocator.free(content);
            var loaded = try emptyLoaded(self.allocator);
            loaded.quarantined = self.quarantine(io) catch null;
            return loaded;
        };
        return .{ .parsed = parsed, .content = content };
    }

    fn emptyLoaded(allocator: std.mem.Allocator) !Loaded {
        return .{
            .parsed = try std.json.parseFromSlice([]RunRecord, allocator, "[]", .{}),
            .content = null,
        };
    }

    fn quarantine(self: *HistoryStore, io: std.Io) !?[]const u8 {
        const now = std.Io.Timestamp.now(io, .real).nanoseconds;
        var buf: [512]u8 = undefined;
        const dir = std.fs.path.dirname(self.path) orelse return null;
        const base = std.fs.path.basename(self.path);
        const new_path = try std.fmt.bufPrint(&buf, "{s}/{s}.corrupt-{d}", .{ dir, base, now });
        std.Io.Dir.renameAbsolute(self.path, new_path, io) catch return null;
        return try self.allocator.dupe(u8, new_path);
    }

    fn saveLocked(self: *HistoryStore, io: std.Io, runs: []const RunRecord) !void {
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(self.path)) |dir| {
            cwd.createDirPath(io, dir) catch |err| {
                std.debug.print("saveLocked createDirPath {s} failed: {s}\n", .{ dir, @errorName(err) });
                return err;
            };
        }
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        std.json.Stringify.value(runs, .{ .whitespace = .indent_2 }, &out.writer) catch return error.SerializeFailed;
        var tmp_buf: [4096]u8 = undefined;
        const tmp = std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{self.path}) catch return error.SerializeFailed;
        {
            var file = try cwd.createFile(io, tmp, .{});
            defer file.close(io);
            file.setPermissions(io, .fromMode(0o600)) catch {};
            try file.writeStreamingAll(io, out.writer.buffered());
            try file.sync(io);
        }
        try std.Io.Dir.renameAbsolute(tmp, self.path, io);
        // Ensure the file is owner-only after the rename.
        if (cwd.openFile(io, self.path, .{ .mode = .read_write })) |*f| {
            var file = f.*;
            defer file.close(io);
            if (file.stat(io)) |stat| {
                if (stat.permissions.toMode() & 0o077 != 0) file.setPermissions(io, .fromMode(0o600)) catch {};
            } else |_| {}
        } else |_| {}
    }

    /// Appends a completed run; prunes records older than the retention
    /// window and caps the store (spec 10 §7). Idempotent by run id.
    pub fn append(self: *HistoryStore, io: std.Io, run: *const RunRecord, now_ns: i64) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        for (loaded.parsed.value) |existing| {
            if (std.mem.eql(u8, existing.id, run.id)) return; // already imported
        }
        var list: std.ArrayList(RunRecord) = .empty;
        defer {
            for (list.items) |*r| r.deinit(self.allocator);
            list.deinit(self.allocator);
        }
        for (loaded.parsed.value) |existing| {
            if (existing.started_at_ns < now_ns - history_retention_days * 86_400_000_000_000) continue;
            try list.append(self.allocator, try cloneRun(self.allocator, existing));
        }
        try list.append(self.allocator, try cloneRun(self.allocator, run.*));
        while (list.items.len > max_runs) {
            var oldest: usize = 0;
            for (list.items, 0..) |*r, i| {
                if (r.started_at_ns < list.items[oldest].started_at_ns) oldest = i;
            }
            var removed = list.orderedRemove(oldest);
            removed.deinit(self.allocator);
        }
        self.saveLocked(io, list.items) catch return error.SerializeFailed;
    }

    /// Newest-first owned copies for one job, capped by `limit`.
    pub fn listForJob(self: *HistoryStore, io: std.Io, job_id: []const u8, limit: usize) ![]RunRecord {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        var out: std.ArrayList(RunRecord) = .empty;
        errdefer {
            for (out.items) |*r| r.deinit(self.allocator);
            out.deinit(self.allocator);
        }
        var i = loaded.parsed.value.len;
        while (i > 0) {
            i -= 1;
            const existing = loaded.parsed.value[i];
            if (!std.mem.eql(u8, existing.job_id, job_id)) continue;
            if (out.items.len >= limit) break;
            try out.append(self.allocator, try cloneRun(self.allocator, existing));
        }
        return out.toOwnedSlice(self.allocator);
    }

    fn cloneRun(allocator: std.mem.Allocator, run: RunRecord) !RunRecord {
        return .{
            .id = try allocator.dupe(u8, run.id),
            .job_id = try allocator.dupe(u8, run.job_id),
            .server_id = try allocator.dupe(u8, run.server_id),
            .source = try allocator.dupe(u8, run.source),
            .status = run.status,
            .started_at_ns = run.started_at_ns,
            .finished_at_ns = run.finished_at_ns,
            .bytes_done = run.bytes_done,
            .bytes_total = run.bytes_total,
            .files_done = run.files_done,
            .files_total = run.files_total,
            .@"error" = if (run.@"error") |e| try allocator.dupe(u8, e) else null,
            .log = if (run.log) |l| try allocator.dupe(u8, l) else null,
        };
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// --- job store -------------------------------------------------------------

pub const JobStore = struct {
    allocator: std.mem.Allocator = undefined,
    path: []const u8 = "",
    /// Monotonic id generator for new jobs (in-memory only).
    next_id: u32 = 1,
    mutex: std.atomic.Mutex = .unlocked,

    pub const Loaded = struct {
        parsed: std.json.Parsed([]Job),
        content: ?[]u8,
        quarantined: ?[]const u8 = null,

        pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
            self.parsed.deinit();
            if (self.content) |c| allocator.free(c);
            if (self.quarantined) |q| allocator.free(q);
        }
    };

    pub fn loadParsed(self: *JobStore, io: std.Io) !Loaded {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.loadParsedLocked(io);
    }

    fn loadParsedLocked(self: *JobStore, io: std.Io) !Loaded {
        const cwd = std.Io.Dir.cwd();
        const content = cwd.readFileAlloc(io, self.path, self.allocator, .limited(16 * 1024 * 1024)) catch return emptyLoaded(self.allocator);
        const parsed = std.json.parseFromSlice([]Job, self.allocator, content, .{}) catch {
            self.allocator.free(content);
            var loaded = try emptyLoaded(self.allocator);
            loaded.quarantined = self.quarantine(io) catch null;
            return loaded;
        };
        return .{ .parsed = parsed, .content = content };
    }

    fn emptyLoaded(allocator: std.mem.Allocator) !Loaded {
        return .{
            .parsed = try std.json.parseFromSlice([]Job, allocator, "[]", .{}),
            .content = null,
        };
    }

    fn quarantine(self: *JobStore, io: std.Io) !?[]const u8 {
        const now = std.Io.Timestamp.now(io, .real).nanoseconds;
        var buf: [512]u8 = undefined;
        const dir = std.fs.path.dirname(self.path) orelse return null;
        const base = std.fs.path.basename(self.path);
        const new_path = try std.fmt.bufPrint(&buf, "{s}/{s}.corrupt-{d}", .{ dir, base, now });
        std.Io.Dir.renameAbsolute(self.path, new_path, io) catch return null;
        return try self.allocator.dupe(u8, new_path);
    }

    fn saveLocked(self: *JobStore, io: std.Io, jobs: []const Job) !void {
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(self.path)) |dir| try cwd.createDirPath(io, dir);
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        std.json.Stringify.value(jobs, .{ .whitespace = .indent_2 }, &out.writer) catch return error.SerializeFailed;
        var tmp_buf: [4096]u8 = undefined;
        const tmp = std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{self.path}) catch return error.SerializeFailed;
        {
            var file = try cwd.createFile(io, tmp, .{});
            defer file.close(io);
            file.setPermissions(io, .fromMode(0o600)) catch {};
            try file.writeStreamingAll(io, out.writer.buffered());
            try file.sync(io);
        }
        try std.Io.Dir.renameAbsolute(tmp, self.path, io);
        if (cwd.openFile(io, self.path, .{ .mode = .read_write })) |*f| {
            var file = f.*;
            defer file.close(io);
            if (file.stat(io)) |stat| {
                if (stat.permissions.toMode() & 0o077 != 0) file.setPermissions(io, .fromMode(0o600)) catch {};
            } else |_| {}
        } else |_| {}
    }

    /// Upserts a job (secrets never persisted). `schedule_credentials`
    /// gates unattended schedules. Returns an owned copy.
    /// Enforces: random IDs (no reuse on restart), 128/server, immutable
    /// server_id, optimistic revision check when expected_revision is set.
    pub fn save(self: *JobStore, io: std.Io, input: JobInput, schedule_credentials: ?[]const u8, now_ns: i64) SaveError!Job {
        try validate(input, schedule_credentials);
        if (input.id) |jid| if (!validId(jid)) return error.InvalidId;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);

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
                for (loaded.parsed.value) |j| if (std.mem.eql(u8, j.id, cand)) {
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
            for (loaded.parsed.value) |j| {
                if (std.mem.eql(u8, j.id, id)) {
                    is_edit = true;
                    existing_job = j;
                    break;
                }
            }
            if (!is_edit) return error.UnknownId;
            // Immutable server_id.
            if (!std.mem.eql(u8, existing_job.?.server_id, input.server_id)) return error.ImmutableServerId;
            // Optimistic concurrency.
            if (input.expected_revision) |exp| {
                if (existing_job.?.revision != exp) return error.RevConflict;
            }
        }
        // Per-server cap (only for new jobs).
        if (!is_edit) {
            var count: usize = 0;
            for (loaded.parsed.value) |j| {
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
        for (loaded.parsed.value) |j| {
            if (is_edit and std.mem.eql(u8, j.id, id)) continue;
            try list.append(self.allocator, try cloneJob(self.allocator, j));
        }
        try list.append(self.allocator, try cloneJob(self.allocator, saved));
        self.saveLocked(io, list.items) catch return error.SerializeFailed;
        return saved;
    }

    /// Owned copies of every job on a server.
    pub fn listForServer(self: *JobStore, io: std.Io, server_id: []const u8) ![]Job {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        var out: std.ArrayList(Job) = .empty;
        errdefer {
            for (out.items) |*j| j.deinit(self.allocator);
            out.deinit(self.allocator);
        }
        for (loaded.parsed.value) |j| {
            if (std.mem.eql(u8, j.server_id, server_id)) {
                try out.append(self.allocator, try cloneJob(self.allocator, j));
            }
        }
        return out.toOwnedSlice(self.allocator);
    }

    /// Owned copy of one job, or null.
    pub fn find(self: *JobStore, io: std.Io, job_id: []const u8) !?Job {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        for (loaded.parsed.value) |j| {
            if (std.mem.eql(u8, j.id, job_id)) return try cloneJob(self.allocator, j);
        }
        return null;
    }

    pub fn delete(self: *JobStore, io: std.Io, job_id: []const u8) SaveError!bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        var found = false;
        var list: std.ArrayList(Job) = .empty;
        defer {
            for (list.items) |*j| j.deinit(self.allocator);
            list.deinit(self.allocator);
        }
        for (loaded.parsed.value) |j| {
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
            .use_iam = d.use_iam,
            .storage_class = try dupOrLiteral(allocator, d.storage_class),
        };
    }

    fn dupSchedule(allocator: std.mem.Allocator, s: Schedule) !Schedule {
        return .{
            .mode = try dupOrLiteral(allocator, s.mode),
            .interval_unit = try dupOrLiteral(allocator, s.interval_unit),
            .interval_every = s.interval_every,
            .expr = try dupOrLiteral(allocator, s.expr),
            .enabled = s.enabled,
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
    /// The exec channel on the server session (null once finalized).
    channel: ?u32 = null,
    /// Temp config path (deleted at finalize).
    temp_config: []const u8 = "",
    /// Latest stats snapshot for the poll response.
    speed_bps: u64 = 0,
    eta_sec: i64 = 0,
    finalized: bool = false,

    pub fn deinit(self: *LiveRun, allocator: std.mem.Allocator) void {
        self.record.deinit(allocator);
        if (self.temp_config.len > 0) allocator.free(self.temp_config);
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
            if (r.record.status == .running and std.mem.eql(u8, r.record.server_id, server_id)) return r;
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
            if (r.finalized) completed += 1;
        }
        var i: usize = 0;
        while (completed > max_completed and i < self.list.items.len) {
            const r = self.list.items[i];
            if (r.finalized) {
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

/// Handler-owned registry: job store, run history, and live runs.
pub const Registry = struct {
    allocator: std.mem.Allocator,
    jobs: JobStore = .{},
    history: HistoryStore = .{},
    runs: Runs = .{},

    pub fn init(allocator: std.mem.Allocator, jobs_path: []const u8, history_path: []const u8) Registry {
        return .{
            .allocator = allocator,
            .jobs = .{ .allocator = allocator, .path = jobs_path },
            .history = .{ .allocator = allocator, .path = history_path },
            .runs = .{ .allocator = allocator },
        };
    }

    pub fn deinit(self: *Registry) void {
        self.runs.deinit();
    }
};

// --- unit tests ------------------------------------------------------------

test "job validation matrix" {
    const base = JobInput{
        .id = "bk-1",
        .server_id = "s1",
        .name = "daily-website",
        .source_path = "/var/www/html",
        .destination = .{ .type = "s3", .provider = "aws", .bucket = "acme-backups", .region = "us-east-1" },
        .transfer = "sync",
    };
    try validate(base, null);
    try std.testing.expectError(error.MissingName, validate(.{ .id = "bk-1", .server_id = "s1", .name = " ", .source_path = "/x", .destination = base.destination }, null));
    try std.testing.expectError(error.InvalidSource, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "relative/path", .destination = base.destination }, null));
    try std.testing.expectError(error.InvalidSource, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x\x01", .destination = base.destination }, null));
    try std.testing.expectError(error.InvalidProvider, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = .{ .type = "s3", .provider = "gcs", .bucket = "b" } }, null));
    try std.testing.expectError(error.InvalidBucket, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = .{ .type = "s3", .provider = "aws", .bucket = "bad bucket" } }, null));
    // MinIO needs an endpoint; AWS needs a region.
    try std.testing.expectError(error.InvalidEndpoint, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = .{ .type = "s3", .provider = "minio", .bucket = "b" } }, null));
    try std.testing.expectError(error.InvalidRegion, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = .{ .type = "s3", .provider = "aws", .bucket = "b" } }, null));
    try std.testing.expectError(error.InvalidStorageClass, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = .{ .type = "s3", .provider = "minio", .bucket = "b", .endpoint = "http://127.0.0.1:9000", .storage_class = "glacier" } }, null));
    try std.testing.expectError(error.IamRequiresAws, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = .{ .type = "s3", .provider = "minio", .bucket = "b", .endpoint = "http://127.0.0.1:9000", .use_iam = true } }, null));
    try std.testing.expectError(error.InvalidTransfer, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = base.destination, .transfer = "mirror" }, null));
    try std.testing.expectError(error.InvalidCronExpr, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = base.destination, .schedule = .{ .mode = "custom", .expr = "not cron" } }, null));
    try std.testing.expectError(error.EnabledScheduleNeedsCredentials, validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = base.destination, .schedule = .{ .mode = "custom", .expr = "0 2 * * *", .enabled = true } }, null));
    // IAM schedules need no credentials.
    var iam = base;
    iam.destination.use_iam = true;
    iam.schedule = .{ .mode = "custom", .expr = "0 2 * * *", .enabled = true };
    try validate(iam, null);
    // Local destinations are modeled (Oars+ execution deferred).
    try validate(.{ .id = "bk-1", .server_id = "s1", .name = "x", .source_path = "/x", .destination = .{ .type = "local" } }, null);
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

    // Idempotent: re-adding does not duplicate.
    const add2 = try crontabAdd(allocator, add1.content, "bk-1", "0 2 * * * /bin/sh x");
    defer allocator.free(add2.content);
    try std.testing.expect(!add2.changed);
    try std.testing.expectEqualStrings(add1.content, add2.content);

    // A second job appends cleanly.
    const add3 = try crontabAdd(allocator, add1.content, "bk-2", "0 3 * * * /bin/sh y");
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

test "rclone config section generation" {
    const allocator = std.testing.allocator;
    var job = Job{
        .id = try allocator.dupe(u8, "bk-1"),
        .server_id = try allocator.dupe(u8, "s1"),
        .name = try allocator.dupe(u8, "daily"),
        .source_path = try allocator.dupe(u8, "/var/www"),
        .destination = .{
            .type = try allocator.dupe(u8, "s3"),
            .provider = try allocator.dupe(u8, "minio"),
            .bucket = try allocator.dupe(u8, "acme"),
            .prefix = "",
            .endpoint = try allocator.dupe(u8, "http://127.0.0.1:9000"),
            .region = "",
            .storage_class = try allocator.dupe(u8, "standard"),
        },
        .schedule = .{
            .mode = try allocator.dupe(u8, "manual"),
            .interval_unit = try allocator.dupe(u8, "hours"),
            .expr = "",
        },
    };
    defer job.deinit(allocator);
    const section = try remoteConfigSection(allocator, &job, "oars-bk-1", "AKID", "SECRET");
    defer allocator.free(section);
    // "standard" is the provider default — omitted from config.
    const expected =
        "[oars-bk-1]\ntype = s3\nprovider = Minio\naccess_key_id = AKID\nsecret_access_key = SECRET\nendpoint = http://127.0.0.1:9000\n";
    try std.testing.expectEqualStrings(expected, section);
    var gl_job = Job{
        .id = try allocator.dupe(u8, "bk-gl"),
        .server_id = try allocator.dupe(u8, "s1"),
        .name = try allocator.dupe(u8, "daily"),
        .source_path = try allocator.dupe(u8, "/var/www"),
        .destination = .{
            .type = try allocator.dupe(u8, "s3"),
            .provider = try allocator.dupe(u8, "aws"),
            .bucket = try allocator.dupe(u8, "acme"),
            .prefix = "",
            .endpoint = "",
            .region = try allocator.dupe(u8, "us-east-1"),
            .storage_class = try allocator.dupe(u8, "glacier"),
        },
        .schedule = .{ .mode = try allocator.dupe(u8, "manual"), .interval_unit = try allocator.dupe(u8, "hours"), .expr = "" },
    };
    defer gl_job.deinit(allocator);
    const gl_section = try remoteConfigSection(allocator, &gl_job, "oars-bk-gl", "AKID", "SECRET");
    defer allocator.free(gl_section);
    try std.testing.expect(std.mem.indexOf(u8, gl_section, "storage_class = GLACIER") != null);

    // IAM: no key material at all.
    var iam_job = Job{
        .id = try allocator.dupe(u8, "bk-2"),
        .server_id = try allocator.dupe(u8, "s1"),
        .name = try allocator.dupe(u8, "daily"),
        .source_path = try allocator.dupe(u8, "/var/www"),
        .destination = .{
            .type = try allocator.dupe(u8, "s3"),
            .provider = try allocator.dupe(u8, "aws"),
            .bucket = try allocator.dupe(u8, "acme"),
            .prefix = "",
            .endpoint = "",
            .region = try allocator.dupe(u8, "us-east-1"),
            .use_iam = true,
            .storage_class = try allocator.dupe(u8, "standard"),
        },
        .schedule = .{
            .mode = try allocator.dupe(u8, "manual"),
            .interval_unit = try allocator.dupe(u8, "hours"),
            .expr = "",
        },
    };
    defer iam_job.deinit(allocator);
    const iam_section = try remoteConfigSection(allocator, &iam_job, "oars-bk-2", null, null);
    defer allocator.free(iam_section);
    try std.testing.expect(std.mem.indexOf(u8, iam_section, "env_auth = true") != null);
    try std.testing.expect(std.mem.indexOf(u8, iam_section, "access_key_id = \n") != null);
    try std.testing.expect(std.mem.indexOf(u8, iam_section, "provider = AWS") != null);
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
    try std.testing.expect(std.mem.startsWith(u8, saved.id, "bk-"));
    try std.testing.expectEqualStrings("daily-website", saved.name);
    try std.testing.expectEqualStrings("sync", saved.transfer.jsonName());

    // Edit preserves the id and created_at.
    var edited_input = input;
    edited_input.id = saved.id;
    edited_input.name = "daily-www";
    var edited = try store.save(io, edited_input, null, 2000);
    defer edited.deinit(allocator);
    try std.testing.expectEqualStrings(saved.id, edited.id);
    try std.testing.expectEqualStrings("daily-www", edited.name);
    try std.testing.expectEqual(@as(i64, 1000), edited.created_at_ns);
    try std.testing.expectEqual(@as(i64, 2000), edited.updated_at_ns);

    // Enabled unattended schedules demand credentials (unless IAM).
    var sched_input = input;
    sched_input.schedule = .{ .mode = "custom", .expr = "0 2 * * *", .enabled = true };
    try std.testing.expectError(error.EnabledScheduleNeedsCredentials, store.save(io, sched_input, null, 3000));
    var sched_iam = sched_input;
    sched_iam.destination = .{ .type = "s3", .provider = "aws", .bucket = "acme", .region = "us-east-1", .use_iam = true };
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
