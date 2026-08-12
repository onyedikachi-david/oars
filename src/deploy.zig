//! One-click deployment (spec 07): the App model + persistent store
//! (`apps.json`), the step planner (app type → command templates), the
//! run state machine, secret masking for captured output, and the run
//! history store (`deploy_runs.json`).
//!
//! The bridge handlers drive the pipeline with the session worker's exec
//! path and the SFTP writer (`.env`, PM2 ecosystem, nginx config) — no
//! extra threads; steps advance while the frontend polls (spec 07 §6).
//! This module is pure logic — no libssh2, no network.

const std = @import("std");
const shellquote = @import("shellquote.zig");

pub const max_env_vars: usize = 128;
pub const max_env_value_bytes: usize = 64 * 1024;
pub const max_domains: usize = 16;
pub const max_commands_bytes: usize = 4096;
pub const max_app_name_len: usize = 100;
pub const max_history_runs: usize = 200;
pub const history_list_limit: usize = 10;
/// History retention: 30 days (age prune runs on append, before the
/// record-count cap — NEXT-SPEC "App model and store").
pub const history_retention_ms: i64 = 30 * 24 * 60 * 60 * 1000;
/// Output kept per run in the history store (spec 07 §7).
pub const history_output_cap: usize = 200 * 1024;
/// Product capacity limits (NEXT-SPEC "Authoritative Bridge Contract") —
/// Oars capacity decisions, not limits of the external tools. Run/preflight
/// admission is enforced by the bridge; store limits by the store.
pub const max_apps_total: usize = 500;
pub const max_apps_per_server: usize = 100;
pub const max_active_runs_total: usize = 8;
pub const max_uncommitted_preflights: usize = 32;

pub const Transport = enum(u8) {
    https,
    ssh,
    /// Integration-test-only transport for local Git fixtures. Product
    /// saves reject it (NEXT-SPEC: `file://` stays behind an
    /// integration-test-only path).
    file,

    pub fn fromJsonName(name: []const u8) ?Transport {
        if (std.mem.eql(u8, name, "https")) return .https;
        if (std.mem.eql(u8, name, "ssh")) return .ssh;
        if (std.mem.eql(u8, name, "file")) return .file;
        return null;
    }
};

pub const AppType = enum(u8) {
    node,
    react,
    next,
    static,

    pub fn fromJsonName(name: []const u8) ?AppType {
        if (std.mem.eql(u8, name, "node")) return .node;
        if (std.mem.eql(u8, name, "react")) return .react;
        if (std.mem.eql(u8, name, "next")) return .next;
        if (std.mem.eql(u8, name, "static")) return .static;
        return null;
    }
};

/// Package-manager selection (NEXT-SPEC "Runtime and repository adapters"):
/// `auto` derives the manager from the repository lockfiles at preflight
/// time; an explicit choice is honored and conflicting lockfiles explained.
pub const PackageManager = enum(u8) {
    auto,
    npm,
    pnpm,
    yarn,

    pub fn fromJsonName(name: []const u8) ?PackageManager {
        if (std.mem.eql(u8, name, "auto")) return .auto;
        if (std.mem.eql(u8, name, "npm")) return .npm;
        if (std.mem.eql(u8, name, "pnpm")) return .pnpm;
        if (std.mem.eql(u8, name, "yarn")) return .yarn;
        return null;
    }

    pub fn jsonName(self: PackageManager) []const u8 {
        return @tagName(self);
    }
};

// --- Phase 3 runtime & repo adapters (NEXT-SPEC § Runtime and repository adapters) ------
pub fn resolveInstallCommand(allocator: std.mem.Allocator, app: *const App) ![]u8 {
    if (app.runtime.install.len > 0) return allocator.dupe(u8, app.runtime.install);
    return switch (app.runtime.package_manager) {
        .npm => allocator.dupe(u8, "npm ci"),
        .pnpm => allocator.dupe(u8, "pnpm install --frozen-lockfile"),
        .yarn => allocator.dupe(u8, "yarn install --immutable"),
        .auto => allocator.dupe(u8, "npm ci"),
    };
}

pub fn detectedLockfileName(pm: PackageManager) ?[]const u8 {
    return switch (pm) {
        .npm => "package-lock.json",
        .pnpm => "pnpm-lock.yaml",
        .yarn => "yarn.lock",
        .auto => null,
    };
}

pub fn validateLockfiles(present: struct { npm: bool, pnpm: bool, yarn: bool }, selected: PackageManager) !void {
    const n: usize = @as(usize, @intFromBool(present.npm)) + @as(usize, @intFromBool(present.pnpm)) + @as(usize, @intFromBool(present.yarn));
    if (n > 1 and selected == .auto) return error.ConflictingLockfiles;
}

pub const NodeRelease = struct {
    version: []const u8,
    major: u8,
    lts: bool,
    sha256: []const u8 = "",
    url: []const u8 = "",
    arch: []const u8 = "x64",
    libc: []const u8 = "glibc",
};

fn semverGt(a: []const u8, b: []const u8) bool {
    var ai = std.mem.splitScalar(u8, a, '.');
    var bi = std.mem.splitScalar(u8, b, '.');
    while (true) {
        const an = ai.next();
        const bn = bi.next();
        if (an == null and bn == null) return false;
        const av = if (an) |v| std.fmt.parseInt(u32, v, 10) catch 0 else 0;
        const bv = if (bn) |v| std.fmt.parseInt(u32, v, 10) catch 0 else 0;
        if (av != bv) return av > bv;
        if (an == null or bn == null) return an != null;
    }
}
pub fn resolveNodeRelease(releases: []const NodeRelease, major: u8) ?NodeRelease {
    var best: ?NodeRelease = null;
    for (releases) |r| {
        if (r.major != major or !r.lts) continue;
        if (best == null or semverGt(r.version, best.?.version)) best = r;
    }
    return best;
}

pub fn deployKeyDir(allocator: std.mem.Allocator, app_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "~/.config/oars/deploy/{s}", .{app_id});
}
pub fn deployKeyPath(allocator: std.mem.Allocator, app_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "~/.config/oars/deploy/{s}/id_ed25519", .{app_id});
}
pub fn knownHostsPath(allocator: std.mem.Allocator, app_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "~/.config/oars/deploy/{s}/known_hosts", .{app_id});
}
pub fn gitSshCommand(allocator: std.mem.Allocator, app_id: []const u8, key_path: []const u8, known_hosts: []const u8) ![]u8 {
    _ = app_id;
    return std.fmt.allocPrint(allocator, "ssh -i {s} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={s}", .{ key_path, known_hosts });
}

pub fn verifySha256(expected_hex: []const u8, actual_hex: []const u8) !void {
    if (expected_hex.len == 0 or actual_hex.len == 0) return error.ChecksumMissing;
    // constant-time-ish hex compare (case-insensitive)
    if (expected_hex.len != actual_hex.len) return error.ChecksumMismatch;
    for (expected_hex, actual_hex) |a, b| if (std.ascii.toLower(a) != std.ascii.toLower(b)) return error.ChecksumMismatch;
}
pub const OsAdapter = enum { debian, ubuntu, unknown };
pub fn osAdapter(os_release: []const u8) OsAdapter {
    if (std.mem.indexOf(u8, os_release, "ID=debian") != null) return .debian;
    if (std.mem.indexOf(u8, os_release, "ID=ubuntu") != null) return .ubuntu;
    return .unknown;
}
pub fn isSupportedArch(arch: []const u8) bool {
    return std.mem.eql(u8, arch, "x64") or std.mem.eql(u8, arch, "arm64");
}
pub fn isGlibc(libc: []const u8) bool {
    return std.mem.eql(u8, libc, "glibc");
}

/// One unguessable Linux process-group-controller token. Run and step IDs
/// are deliberately absent because the control filename is a capability.
pub fn cancelToken(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    var random: [24]u8 = undefined;
    try std.Io.randomSecure(io, &random);
    const hex = std.fmt.bytesToHex(random, .lower);
    return allocator.dupe(u8, &hex);
}
pub fn controlFilePath(allocator: std.mem.Allocator, token: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}.ctl", .{token});
}
pub fn wrapWithProcessGroup(allocator: std.mem.Allocator, command: []const u8, token: []const u8, control_path: []const u8) ![]u8 {
    const qc = try shellquote.quote(allocator, command);
    defer allocator.free(qc);
    const qp = try shellquote.quote(allocator, control_path);
    defer allocator.free(qp);
    const qt = try shellquote.quote(allocator, token);
    defer allocator.free(qt);
    return std.fmt.allocPrint(allocator, "REL={s}; TOK={s}; CMD={s}; BASE=\"${{XDG_RUNTIME_DIR:-$HOME/.cache}}/oars/control\"; umask 077; mkdir -p \"$BASE\" && chmod 700 \"$BASE\" || exit 125; CTRL=\"$BASE/$REL\"; export CTRL TOK CMD; : | setsid sh -c 'set -C; : > \"$CTRL\" || exit 125; PID=$$; PGID=$(ps -o pgid= -p \"$PID\" | tr -d \" \t\"); START=$(awk \"{{print \\$22}}\" /proc/\"$PID\"/stat 2>/dev/null) || exit 125; printf \"token=%s\\npid=%s\\npgid=%s\\nstart=%s\\nuid=%s\\n\" \"$TOK\" \"$PID\" \"$PGID\" \"$START\" \"$(id -u)\" > \"$CTRL\"; chmod 600 \"$CTRL\"; exec sh -c \"$CMD\"'", .{ qp, qt, qc });
}
pub fn cancelCommand(allocator: std.mem.Allocator, control_path: []const u8, token: []const u8) ![]u8 {
    const qp = try shellquote.quote(allocator, control_path);
    defer allocator.free(qp);
    const qt = try shellquote.quote(allocator, token);
    defer allocator.free(qt);
    return std.fmt.allocPrint(allocator, "REL={s}; TOK={s}; BASE=\"${{XDG_RUNTIME_DIR:-$HOME/.cache}}/oars/control\"; CTRL=\"$BASE/$REL\"; [ -f \"$CTRL\" ] || exit 1; [ \"$(stat -c %u \"$CTRL\" 2>/dev/null)\" = \"$(id -u)\" ] || exit 1; [ \"$(sed -n 's/^token=//p' \"$CTRL\")\" = \"$TOK\" ] || exit 1; PID=$(sed -n 's/^pid=//p' \"$CTRL\"); PGID=$(sed -n 's/^pgid=//p' \"$CTRL\"); START=$(sed -n 's/^start=//p' \"$CTRL\"); UID0=$(sed -n 's/^uid=//p' \"$CTRL\"); [ \"$UID0\" = \"$(id -u)\" ] && [ -n \"$PID\" ] && [ -n \"$PGID\" ] && [ -n \"$START\" ] || exit 1; [ \"$(stat -c %u /proc/\"$PID\" 2>/dev/null)\" = \"$UID0\" ] || exit 1; [ \"$(awk '{{print $22}}' /proc/\"$PID\"/stat 2>/dev/null)\" = \"$START\" ] || exit 1; kill -TERM -- -\"$PGID\" 2>/dev/null || exit 1; N=0; while kill -0 -- -\"$PGID\" 2>/dev/null && [ \"$N\" -lt 20 ]; do sleep 0.1; N=$((N+1)); done; if kill -0 -- -\"$PGID\" 2>/dev/null; then kill -KILL -- -\"$PGID\" 2>/dev/null || exit 1; sleep 0.2; fi; kill -0 -- -\"$PGID\" 2>/dev/null && exit 1; rm -f \"$CTRL\"; echo ok", .{ qp, qt });
}
pub const FrozenCommit = struct { branch: []const u8, sha: []const u8 };
pub fn frozenCommitForBranch(branch: []const u8, commits: []const FrozenCommit) ?[]const u8 {
    for (commits) |c| if (std.mem.eql(u8, c.branch, branch)) return c.sha;
    return null;
}

pub const Environment = enum(u8) {
    development,
    staging,
    production,

    pub fn fromJsonName(name: []const u8) ?Environment {
        if (std.mem.eql(u8, name, "development")) return .development;
        if (std.mem.eql(u8, name, "staging")) return .staging;
        if (std.mem.eql(u8, name, "production")) return .production;
        return null;
    }
};

/// One environment row. Secret values never enter the JSON store (spec
/// 07 §5: Keychain holds them; `has_value` records that a value exists).
pub const EnvVar = struct {
    name: []const u8,
    secret: bool = true,
    /// Non-secret values only; secret rows keep this empty.
    value: []const u8 = "",
    has_value: bool = false,
};

pub const Repo = struct {
    url: []const u8,
    transport: Transport,
    branch: []const u8 = "main",
};

pub const Runtime = struct {
    /// The supported Node production line (major, e.g. "22"). Format-checked
    /// here; the support check resolves current release data at preflight.
    node_version: []const u8 = "",
    type: AppType = .node,
    package_manager: PackageManager = .auto,
    /// Shell-code override for the install step; empty = the planner derives
    /// the frozen command from the lockfile + selected manager.
    install: []const u8 = "",
    /// Shell-code override for the build step; empty = derived by app type.
    build: []const u8 = "",
    /// Structured process entry (node/next): a path relative to `folder`.
    entry: []const u8 = "",
    /// Documented PM2 argument string for the entry.
    args: []const u8 = "",
    /// Shell-code start override (labeled as such in the plan); when set it
    /// wins over entry/args and runs through one documented shell.
    start_command: []const u8 = "",
    /// Static output folder relative to `folder` (react/static; required).
    build_folder: []const u8 = "",
};

pub const App = struct {
    id: []const u8,
    server_id: []const u8,
    name: []const u8,
    environment: Environment = .production,
    folder: []const u8,
    repo: Repo,
    runtime: Runtime,
    env_vars: []const EnvVar = &.{},
    domains: []const []const u8 = &.{},
    ssl: bool = false,
    email: []const u8 = "",
    app_port: u16 = 3000,
    /// Monotonic metadata revision: 1 on create, +1 on every save. The
    /// preflight freezes it and commit rejects a changed app.
    revision: u64 = 0,
    /// Wire timestamps are integer milliseconds (NEXT-SPEC bridge contract).
    created_at_ms: i64 = 0,
    updated_at_ms: i64 = 0,
};

/// Wire shape of `oars.deploy.apps.save` (id optional = create).
pub const AppInput = struct {
    id: ?[]const u8 = null,
    server_id: []const u8,
    name: []const u8,
    environment: []const u8 = "production",
    folder: []const u8,
    repo: RepoInput,
    runtime: RuntimeInput,
    env_vars: []const EnvVar = &.{},
    domains: []const []const u8 = &.{},
    ssl: bool = false,
    email: []const u8 = "",
    app_port: u16 = 3000,
};

pub const RepoInput = struct {
    url: []const u8,
    transport: []const u8,
    branch: []const u8 = "main",
};

pub const RuntimeInput = struct {
    node_version: []const u8 = "",
    type: []const u8 = "node",
    package_manager: []const u8 = "auto",
    install: []const u8 = "",
    build: []const u8 = "",
    entry: []const u8 = "",
    args: []const u8 = "",
    start_command: []const u8 = "",
    build_folder: []const u8 = "",
};

pub const SaveError = error{
    MissingId,
    MissingServer,
    ServerMismatch,
    MissingName,
    InvalidName,
    MissingFolder,
    InvalidFolder,
    InvalidRepo,
    InvalidTransport,
    UnsupportedTransport,
    InvalidBranch,
    InvalidNodeVersion,
    InvalidAppType,
    InvalidPackageManager,
    InvalidCommand,
    MissingEntry,
    InvalidEntry,
    MissingBuildFolder,
    InvalidBuildFolder,
    InvalidEnvVar,
    DuplicateEnvVar,
    TooManyEnvVars,
    InvalidDomain,
    TooManyDomains,
    DuplicateDomain,
    EmailRequired,
    InvalidEmail,
    InvalidPort,
    TooManyApps,
    SerializeFailed,
    StoreCorrupt,
    OutOfMemory,
};

pub fn validName(name: []const u8) bool {
    if (name.len == 0) return false;
    const first = name[0];
    if (!((first >= 'a' and first <= 'z') or (first >= 'A' and first <= 'Z') or first == '_')) return false;
    for (name[1..]) |ch| {
        if (!((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '_')) return false;
    }
    return true;
}

fn hasControlChars(s: []const u8) bool {
    for (s) |ch| {
        if (ch == 0 or ch < 0x20 or ch == 0x7f) return true;
    }
    return false;
}

/// Validates a hostname: labels of letters/digits/hyphens, no leading or
/// trailing hyphen, no empty labels, no control characters, ≤ 253 bytes.
pub fn validDomain(domain: []const u8) bool {
    if (domain.len == 0 or domain.len > 253 or hasControlChars(domain)) return false;
    var it = std.mem.splitScalar(u8, domain, '.');
    var labels: usize = 0;
    while (it.next()) |label| {
        labels += 1;
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |ch| {
            if (!((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '-')) return false;
        }
    }
    return labels >= 2;
}

/// Env values go into a server-side `.env` and a PM2 ecosystem file —
/// newlines would break both formats (spec 07 §6).
fn envValueUsable(value: []const u8) bool {
    return value.len <= max_env_value_bytes and std.mem.indexOfAny(u8, value, "\r\n") == null;
}

/// A Node major is 1–3 ASCII digits. Which lines are *supported* is a
/// preflight decision made from current release data — never a constant
/// baked into validation (NEXT-SPEC: majors must not be hard-coded).
fn validNodeMajor(v: []const u8) bool {
    if (v.len == 0 or v.len > 3) return false;
    for (v) |ch| {
        if (ch < '0' or ch > '9') return false;
    }
    return true;
}

/// Entry and build-folder paths live inside the app folder: relative, no
/// empty/dot/dotdot segments, no control characters (NEXT-SPEC: reject
/// traversal before nginx or PM2 ever see the path; the symlink-escape
/// check is a preflight remote fact).
pub fn validRelativePath(path: []const u8) bool {
    if (path.len == 0 or path.len > 512 or hasControlChars(path)) return false;
    if (path[0] == '/' or path[path.len - 1] == '/') return false;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".") or std.mem.eql(u8, seg, "..")) return false;
    }
    return true;
}

/// HTTPS carries public repositories only: no credentials in the URL
/// (NEXT-SPEC "Repository identity" — never accept or persist an HTTPS
/// token in the repository URL).
fn validHttpsRepo(url: []const u8) bool {
    const rest = url["https://".len..];
    if (rest.len == 0) return false;
    const authority_end = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const authority = rest[0..authority_end];
    return std.mem.indexOfScalar(u8, authority, '@') == null;
}

pub fn validate(input: AppInput, allow_test_transports: bool) SaveError!void {
    const name = std.mem.trim(u8, input.name, " \t\r\n");
    if (name.len == 0) return error.MissingName;
    if (name.len > max_app_name_len or hasControlChars(name)) return error.InvalidName;
    const folder = std.mem.trim(u8, input.folder, " \t\r\n");
    if (folder.len == 0) return error.MissingFolder;
    if (folder[0] != '/' or folder[folder.len - 1] == '/' or hasControlChars(folder)) return error.InvalidFolder;
    const transport = Transport.fromJsonName(input.repo.transport) orelse return error.InvalidTransport;
    const url = std.mem.trim(u8, input.repo.url, " \t\r\n");
    if (url.len == 0 or url.len > 2048 or hasControlChars(url)) return error.InvalidRepo;
    const ok_url = switch (transport) {
        .https => std.mem.startsWith(u8, url, "https://") and validHttpsRepo(url),
        .ssh => std.mem.startsWith(u8, url, "git@") or std.mem.startsWith(u8, url, "ssh://"),
        .file => allow_test_transports and std.mem.startsWith(u8, url, "file://"),
    };
    if (!ok_url) {
        if (transport == .file or std.mem.startsWith(u8, url, "http://")) return error.UnsupportedTransport;
        return error.InvalidRepo;
    }
    const branch = std.mem.trim(u8, input.repo.branch, " \t\r\n");
    if (branch.len == 0 or branch.len > 200 or hasControlChars(branch)) return error.InvalidBranch;
    if (!validNodeMajor(input.runtime.node_version)) return error.InvalidNodeVersion;
    const app_type = AppType.fromJsonName(input.runtime.type) orelse return error.InvalidAppType;
    if (PackageManager.fromJsonName(input.runtime.package_manager) == null) return error.InvalidPackageManager;
    const commands = [_][]const u8{ input.runtime.install, input.runtime.build, input.runtime.start_command, input.runtime.args };
    for (commands) |cmd| {
        if (cmd.len > max_commands_bytes or hasControlChars(cmd)) return error.InvalidCommand;
    }
    switch (app_type) {
        .node, .next => {
            if (input.runtime.entry.len == 0 and input.runtime.start_command.len == 0) return error.MissingEntry;
            if (input.app_port == 0) return error.InvalidPort;
        },
        .react, .static => {
            if (input.runtime.build_folder.len == 0) return error.MissingBuildFolder;
        },
    }
    if (input.runtime.entry.len > 0 and !validRelativePath(input.runtime.entry)) return error.InvalidEntry;
    if (input.runtime.build_folder.len > 0 and !validRelativePath(input.runtime.build_folder)) return error.InvalidBuildFolder;
    if (input.env_vars.len > max_env_vars) return error.TooManyEnvVars;
    for (input.env_vars, 0..) |v, i| {
        if (!validName(v.name)) return error.InvalidEnvVar;
        if (!v.secret) {
            if (!envValueUsable(v.value)) return error.InvalidEnvVar;
        }
        for (input.env_vars[0..i]) |prev| {
            if (std.mem.eql(u8, prev.name, v.name)) return error.DuplicateEnvVar;
        }
    }
    if (input.domains.len > max_domains) return error.TooManyDomains;
    for (input.domains, 0..) |d, i| {
        if (!validDomain(d)) return error.InvalidDomain;
        for (input.domains[0..i]) |previous| {
            if (std.ascii.eqlIgnoreCase(previous, d)) return error.DuplicateDomain;
        }
    }
    if (input.ssl) {
        const email = std.mem.trim(u8, input.email, " \t\r\n");
        if (email.len == 0) return error.EmailRequired;
        if (email.len > 254 or std.mem.indexOfScalar(u8, email, '@') == null) return error.InvalidEmail;
    }
}

pub fn clone(allocator: std.mem.Allocator, src: App) SaveError!App {
    var out = App{
        .id = try allocator.dupe(u8, src.id),
        .server_id = try allocator.dupe(u8, src.server_id),
        .name = try allocator.dupe(u8, src.name),
        .environment = src.environment,
        .folder = try allocator.dupe(u8, src.folder),
        .repo = .{
            .url = try allocator.dupe(u8, src.repo.url),
            .transport = src.repo.transport,
            .branch = try allocator.dupe(u8, src.repo.branch),
        },
        .runtime = .{
            .node_version = try allocator.dupe(u8, src.runtime.node_version),
            .type = src.runtime.type,
            .package_manager = src.runtime.package_manager,
            .install = try allocator.dupe(u8, src.runtime.install),
            .build = try allocator.dupe(u8, src.runtime.build),
            .entry = try allocator.dupe(u8, src.runtime.entry),
            .args = try allocator.dupe(u8, src.runtime.args),
            .start_command = try allocator.dupe(u8, src.runtime.start_command),
            .build_folder = try allocator.dupe(u8, src.runtime.build_folder),
        },
        .domains = &.{},
        .email = try allocator.dupe(u8, src.email),
        .ssl = src.ssl,
        .app_port = src.app_port,
        .revision = src.revision,
        .created_at_ms = src.created_at_ms,
        .updated_at_ms = src.updated_at_ms,
    };
    errdefer deinit(allocator, &out);
    if (src.env_vars.len > 0) {
        const buf = try allocator.alloc(EnvVar, src.env_vars.len);
        for (src.env_vars, 0..) |v, i| {
            buf[i] = .{
                .name = try allocator.dupe(u8, v.name),
                .secret = v.secret,
                .value = try allocator.dupe(u8, v.value),
                .has_value = v.has_value,
            };
        }
        out.env_vars = buf;
    }
    if (src.domains.len > 0) {
        const buf = try allocator.alloc([]const u8, src.domains.len);
        for (src.domains, 0..) |d, i| {
            buf[i] = try allocator.dupe(u8, d);
        }
        out.domains = buf;
    }
    return out;
}

pub fn deinit(allocator: std.mem.Allocator, app: *App) void {
    allocator.free(app.id);
    allocator.free(app.server_id);
    allocator.free(app.name);
    allocator.free(app.folder);
    allocator.free(app.repo.url);
    allocator.free(app.repo.branch);
    allocator.free(app.runtime.node_version);
    allocator.free(app.runtime.install);
    allocator.free(app.runtime.build);
    allocator.free(app.runtime.entry);
    allocator.free(app.runtime.args);
    allocator.free(app.runtime.start_command);
    allocator.free(app.runtime.build_folder);
    for (app.env_vars) |v| {
        allocator.free(v.name);
        allocator.free(v.value);
    }
    allocator.free(app.env_vars);
    for (app.domains) |d| allocator.free(d);
    allocator.free(app.domains);
    allocator.free(app.email);
}

/// The app-free alias avoids the `deinit` name collision inside `Run`.
const appDeinit = deinit;

// --- apps store -----------------------------------------------------------

/// Persistent app registry: `apps.json`, 0600, rewritten wholesale on each
/// mutation via temp-file + sync + rename; corrupt files are quarantined
/// (mirrors the servers store). `test_transports` admits the `file://`
/// repo transport for local Git fixtures — integration rigs only.
pub const AppStore = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    test_transports: bool = false,
    mutex: std.atomic.Mutex = .unlocked,

    pub const Loaded = struct {
        parsed: std.json.Parsed([]App),
        content: ?[]u8,
        quarantined: ?[]const u8 = null,

        pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
            self.parsed.deinit();
            if (self.content) |c| allocator.free(c);
            if (self.quarantined) |q| allocator.free(q);
        }
    };

    pub fn loadParsed(self: *AppStore, io: std.Io) !Loaded {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.loadParsedLocked(io);
    }

    fn loadParsedLocked(self: *AppStore, io: std.Io) !Loaded {
        const cwd = std.Io.Dir.cwd();
        const content = cwd.readFileAlloc(io, self.path, self.allocator, .limited(16 * 1024 * 1024)) catch return emptyLoaded(self.allocator);
        const parsed = std.json.parseFromSlice([]App, self.allocator, content, .{}) catch {
            self.allocator.free(content);
            var loaded = try emptyLoaded(self.allocator);
            loaded.quarantined = self.quarantine(io) catch null;
            return loaded;
        };
        return .{ .parsed = parsed, .content = content };
    }

    fn emptyLoaded(allocator: std.mem.Allocator) !Loaded {
        return .{
            .parsed = try std.json.parseFromSlice([]App, allocator, "[]", .{}),
            .content = null,
        };
    }

    fn quarantine(self: *AppStore, io: std.Io) !?[]const u8 {
        const now = std.Io.Timestamp.now(io, .real).nanoseconds;
        var buf: [512]u8 = undefined;
        const dir = std.fs.path.dirname(self.path) orelse return null;
        const base = std.fs.path.basename(self.path);
        const new_path = try std.fmt.bufPrint(&buf, "{s}/{s}.corrupt-{d}", .{ dir, base, now });
        std.Io.Dir.renameAbsolute(self.path, new_path, io) catch return null;
        return try self.allocator.dupe(u8, new_path);
    }

    /// Atomic write: serialize → sibling temp file (0600) → sync → rename
    /// over the destination. A crash mid-write leaves either the old file
    /// or the new one, never a torn file.
    fn saveLocked(self: *AppStore, io: std.Io, apps: []const App) !void {
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(self.path)) |dir| try cwd.createDirPath(io, dir);
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        std.json.Stringify.value(apps, .{ .whitespace = .indent_2 }, &out.writer) catch return error.SerializeFailed;
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
        self.tightenPermissions(io);
    }

    fn tightenPermissions(self: *AppStore, io: std.Io) void {
        const cwd = std.Io.Dir.cwd();
        var file = cwd.openFile(io, self.path, .{ .mode = .read_write }) catch return;
        defer file.close(io);
        const stat = file.stat(io) catch return;
        if (stat.permissions.toMode() & 0o077 != 0) file.setPermissions(io, .fromMode(0o600)) catch {};
    }

    /// Builds an owned App from validated input (trims applied; secret env
    /// values never stored — spec 07 §5). Caller deinits.
    fn fromInput(allocator: std.mem.Allocator, input: AppInput, now_ms: i64) SaveError!App {
        var saved = App{
            .id = try allocator.dupe(u8, input.id.?),
            .server_id = try allocator.dupe(u8, input.server_id),
            .name = try allocator.dupe(u8, std.mem.trim(u8, input.name, " \t\r\n")),
            .environment = Environment.fromJsonName(input.environment) orelse .production,
            .folder = try allocator.dupe(u8, std.mem.trim(u8, input.folder, " \t\r\n")),
            .repo = .{
                .url = try allocator.dupe(u8, std.mem.trim(u8, input.repo.url, " \t\r\n")),
                .transport = Transport.fromJsonName(input.repo.transport).?,
                .branch = try allocator.dupe(u8, std.mem.trim(u8, input.repo.branch, " \t\r\n")),
            },
            .runtime = .{
                .node_version = try allocator.dupe(u8, input.runtime.node_version),
                .type = AppType.fromJsonName(input.runtime.type).?,
                .package_manager = PackageManager.fromJsonName(input.runtime.package_manager).?,
                .install = try allocator.dupe(u8, input.runtime.install),
                .build = try allocator.dupe(u8, input.runtime.build),
                .entry = try allocator.dupe(u8, input.runtime.entry),
                .args = try allocator.dupe(u8, input.runtime.args),
                .start_command = try allocator.dupe(u8, input.runtime.start_command),
                .build_folder = try allocator.dupe(u8, input.runtime.build_folder),
            },
            .email = try allocator.dupe(u8, std.mem.trim(u8, input.email, " \t\r\n")),
            .ssl = input.ssl,
            .app_port = input.app_port,
            .revision = 1,
            .created_at_ms = now_ms,
            .updated_at_ms = now_ms,
        };
        errdefer deinit(allocator, &saved);
        saved.env_vars = try dupEnvVars(allocator, input.env_vars);
        saved.domains = try dupDomains(allocator, input.domains);
        return saved;
    }

    /// Upserts an app by id; edits preserve created_at_ms and bump the
    /// monotonic revision. Secret env rows never store a value (spec 07
    /// §5). Create-time capacity limits reject before any write. Returns
    /// an owned copy.
    pub fn saveApp(self: *AppStore, io: std.Io, input: AppInput, now_ms: i64) SaveError!App {
        try validate(input, self.test_transports);
        const id = input.id orelse return error.MissingId;
        if (input.server_id.len == 0) return error.MissingServer;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);

        var existing: ?App = null;
        defer {
            if (existing) |*e| deinit(self.allocator, e);
        }
        var total: usize = 0;
        var on_server: usize = 0;
        for (loaded.parsed.value) |a| {
            if (std.mem.eql(u8, a.id, id)) {
                existing = try clone(self.allocator, a);
            } else {
                // The app being replaced does not count against the caps.
                total += 1;
                if (std.mem.eql(u8, a.server_id, input.server_id)) on_server += 1;
            }
        }
        if (existing == null and (total >= max_apps_total or on_server >= max_apps_per_server))
            return error.TooManyApps;
        if (existing) |current| {
            if (!std.mem.eql(u8, current.server_id, input.server_id)) return error.ServerMismatch;
        }

        var saved = try fromInput(self.allocator, input, now_ms);
        errdefer deinit(self.allocator, &saved);
        if (existing) |e| {
            saved.created_at_ms = e.created_at_ms;
            saved.revision = e.revision + 1;
            // The client cannot mint or clear a Keychain-existence claim.
            // Preserve it for unchanged secret rows; a separate bridge
            // command confirms Keychain writes and removals.
            for (@constCast(saved.env_vars)) |*row| {
                if (!row.secret) continue;
                row.has_value = false;
                for (e.env_vars) |old| {
                    if (old.secret and std.mem.eql(u8, old.name, row.name)) {
                        row.has_value = old.has_value;
                        break;
                    }
                }
            }
        } else {
            for (@constCast(saved.env_vars)) |*row| {
                if (row.secret) row.has_value = false;
            }
        }

        // Persist with this app placed (edit) or added.
        var list: std.ArrayList(App) = .empty;
        defer {
            for (list.items) |*a| deinit(self.allocator, a);
            list.deinit(self.allocator);
        }
        for (loaded.parsed.value) |a| {
            if (std.mem.eql(u8, a.id, id)) continue; // replaced by `saved`
            try list.append(self.allocator, try clone(self.allocator, a));
        }
        try list.append(self.allocator, try clone(self.allocator, saved));
        self.saveLocked(io, list.items) catch return error.SerializeFailed;
        return saved;
    }

    fn dupEnvVars(allocator: std.mem.Allocator, vars: []const EnvVar) SaveError![]EnvVar {
        const buf = try allocator.alloc(EnvVar, vars.len);
        for (vars, 0..) |v, i| {
            buf[i] = .{
                .name = try allocator.dupe(u8, v.name),
                .secret = v.secret,
                .value = if (v.secret) "" else try allocator.dupe(u8, v.value),
                // Secret rows never store a value; the flag survives edits.
                .has_value = if (v.secret) v.has_value else v.value.len > 0,
            };
        }
        return buf;
    }

    fn dupDomains(allocator: std.mem.Allocator, domains: []const []const u8) SaveError![]const []const u8 {
        const buf = try allocator.alloc([]const u8, domains.len);
        for (domains, 0..) |d, i| {
            buf[i] = try allocator.dupe(u8, d);
        }
        return buf;
    }

    /// Confirms Keychain writes only after the credential operation succeeds.
    /// This is the sole path that changes a secret row's existence flag.
    pub fn setSecretPresence(self: *AppStore, io: std.Io, id: []const u8, names: []const []const u8, present: bool, now_ms: i64) SaveError!App {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        var list: std.ArrayList(App) = .empty;
        defer {
            for (list.items) |*app| deinit(self.allocator, app);
            list.deinit(self.allocator);
        }
        var result: ?App = null;
        errdefer if (result) |*app| deinit(self.allocator, app);
        for (loaded.parsed.value) |source| {
            var app = try clone(self.allocator, source);
            if (std.mem.eql(u8, app.id, id)) {
                for (@constCast(app.env_vars)) |*row| {
                    if (!row.secret) continue;
                    for (names) |name| {
                        if (std.mem.eql(u8, row.name, name)) row.has_value = present;
                    }
                }
                app.revision += 1;
                app.updated_at_ms = now_ms;
                result = try clone(self.allocator, app);
            }
            try list.append(self.allocator, app);
        }
        const saved = result orelse return error.MissingId;
        self.saveLocked(io, list.items) catch return error.SerializeFailed;
        return saved;
    }

    pub fn delete(self: *AppStore, io: std.Io, id: []const u8) SaveError!bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        var found = false;
        var list: std.ArrayList(App) = .empty;
        defer {
            for (list.items) |*a| deinit(self.allocator, a);
            list.deinit(self.allocator);
        }
        for (loaded.parsed.value) |a| {
            if (std.mem.eql(u8, a.id, id)) {
                found = true;
                continue;
            }
            try list.append(self.allocator, try clone(self.allocator, a));
        }
        if (found) self.saveLocked(io, list.items) catch return error.SerializeFailed;
        return found;
    }

    /// Returns an owned deep copy of the app with `id`, or null.
    pub fn find(self: *AppStore, io: std.Io, id: []const u8) SaveError!?App {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        for (loaded.parsed.value) |a| {
            if (std.mem.eql(u8, a.id, id)) return try clone(self.allocator, a);
        }
        return null;
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// --- step planner -----------------------------------------------------------

pub const StepId = enum(u8) {
    clone,
    install,
    build,
    pm2,
    nginx,
    certbot,

    pub fn jsonName(self: StepId) []const u8 {
        return @tagName(self);
    }
};

pub const step_labels = [_][]const u8{
    "Clone repository",
    "Install dependencies",
    "Build application",
    "Start with PM2",
    "Configure Nginx",
    "Issue SSL certificate",
};

/// One planned step: the id/label and the exact command string (owned).
pub const PlanStep = struct {
    id: StepId,
    label: []const u8,
    /// Empty = the step is skipped (no command configured).
    command: []u8,

    pub fn deinit(self: *PlanStep, allocator: std.mem.Allocator) void {
        allocator.free(self.command);
    }
};

fn appendQuoted(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    const quoted = try shellquote.quote(allocator, value);
    defer allocator.free(quoted);
    try list.appendSlice(allocator, quoted);
}

fn appendCmd(list: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    try list.appendSlice(allocator, text);
}

fn addStep(list: *std.ArrayList(PlanStep), allocator: std.mem.Allocator, id: StepId, command: []const u8) !void {
    try list.append(allocator, .{
        .id = id,
        .label = step_labels[@intFromEnum(id)],
        .command = try allocator.dupe(u8, command),
    });
}

/// Builds the six-step plan (spec 07 §6). The clone step doubles as the
/// interruption recheck: an existing folder must be the same repo, with no
/// locally modified tracked files (Oars-managed untracked files — `.env`,
/// the PM2 ecosystem file — are ignored; git itself refuses a pull that
/// would overwrite an untracked file), and fast-forwardable — a mismatched
/// or modified folder stops with a diff summary rather than being reset
/// (spec 07 §10).
pub fn buildPlan(allocator: std.mem.Allocator, app: *const App) SaveError![]PlanStep {
    var steps: std.ArrayList(PlanStep) = .empty;
    errdefer {
        for (steps.items) |*s| s.deinit(allocator);
        steps.deinit(allocator);
    }

    // 1. clone / pull.
    {
        var cmd: std.ArrayList(u8) = .empty;
        defer cmd.deinit(allocator);
        try appendCmd(&cmd, allocator, "if [ -d ");
        try appendQuoted(&cmd, allocator, app.folder);
        try appendCmd(&cmd, allocator, "/.git ]; then git -C ");
        try appendQuoted(&cmd, allocator, app.folder);
        try appendCmd(&cmd, allocator, " status --porcelain --untracked-files=no | grep -q . && { echo 'deploy folder has modified tracked files; refusing to overwrite'; exit 1; }; git -C ");
        try appendQuoted(&cmd, allocator, app.folder);
        try appendCmd(&cmd, allocator, " remote get-url origin | grep -Fqx ");
        try appendQuoted(&cmd, allocator, app.repo.url);
        try appendCmd(&cmd, allocator, " || { echo 'existing folder is a different repository'; exit 1; }; git -C ");
        try appendQuoted(&cmd, allocator, app.folder);
        try appendCmd(&cmd, allocator, " pull --ff-only; else git clone --branch ");
        try appendQuoted(&cmd, allocator, app.repo.branch);
        try appendCmd(&cmd, allocator, " ");
        try appendQuoted(&cmd, allocator, app.repo.url);
        try appendCmd(&cmd, allocator, " ");
        try appendQuoted(&cmd, allocator, app.folder);
        try appendCmd(&cmd, allocator, "; fi");
        try addStep(&steps, allocator, .clone, cmd.items);
    }

    // 2. install — derived when app.runtime.install is empty: the selected
    // package manager's frozen install. User overrides are shell code and are
    // kept verbatim (NEXT-SPEC § Core Design / Package managers). No muted fallbacks.
    {
        const derived = try resolveInstallCommand(allocator, app);
        defer allocator.free(derived);
        if (derived.len > 0) {
            var cmd: std.ArrayList(u8) = .empty;
            defer cmd.deinit(allocator);
            try appendCmd(&cmd, allocator, "cd ");
            try appendQuoted(&cmd, allocator, app.folder);
            try appendCmd(&cmd, allocator, " && ");
            try appendCmd(&cmd, allocator, derived);
            try addStep(&steps, allocator, .install, cmd.items);
        } else try addStep(&steps, allocator, .install, "");
    }

    // 3. build — NODE_OPTIONS heap hint for node-family builds.
    if (app.runtime.build.len > 0) {
        var cmd: std.ArrayList(u8) = .empty;
        defer cmd.deinit(allocator);
        try appendCmd(&cmd, allocator, "cd ");
        try appendQuoted(&cmd, allocator, app.folder);
        try appendCmd(&cmd, allocator, " && NODE_OPTIONS=--max-old-space-size=4096 ");
        try appendCmd(&cmd, allocator, app.runtime.build);
        try addStep(&steps, allocator, .build, cmd.items);
    } else {
        try addStep(&steps, allocator, .build, "");
    }

    // 4. pm2 — the handler writes the ecosystem file before the step.
    // Node/Next apps run under PM2; react/static are served as files by
    // nginx and have no process step (NEXT-SPEC plan-by-type table).
    switch (app.runtime.type) {
        .node, .next => {
            const eco_path = try pm2EcosystemPath(allocator, app.folder);
            defer allocator.free(eco_path);
            const proc = try pm2ProcessName(allocator, app.id);
            defer allocator.free(proc);
            var cmd: std.ArrayList(u8) = .empty;
            defer cmd.deinit(allocator);
            try appendCmd(&cmd, allocator, "pm2 startOrReload ");
            try appendQuoted(&cmd, allocator, eco_path);
            try appendCmd(&cmd, allocator, " --only ");
            try appendQuoted(&cmd, allocator, proc);
            try addStep(&steps, allocator, .pm2, cmd.items);
        },
        .react, .static => try addStep(&steps, allocator, .pm2, ""),
    }

    // 5. nginx — the handler writes the candidate site config to an
    // Oars-owned temp first; privileged install happens via sudo -n. The
    // command below validates the candidate then enables + reloads with
    // rollback on failure (spec: save old + link state, install, nginx -t,
    // reload, restore on failure). The exact shell is the guarded-reload
    // contract; the handler's pre-write is the transactional source.
    {
        const avail = try nginxAvailablePath(allocator, app.id);
        defer allocator.free(avail);
        const enabled = try nginxEnabledPath(allocator, app.id);
        defer allocator.free(enabled);
        // Staged path the bridge writes before the step: <folder>/.oars-nginx.<id>
        const staged = try std.fmt.allocPrint(allocator, "{s}/.oars-nginx.{s}", .{ app.folder, app.id });
        defer allocator.free(staged);
        var cmd: std.ArrayList(u8) = .empty;
        defer cmd.deinit(allocator);
        // Save old file/link state, install staged candidate with 0644, enable, test, reload; restore on failure.
        try appendCmd(&cmd, allocator, "as_root() { if [ \"$(id -u)\" = 0 ]; then \"$@\"; else sudo -n \"$@\"; fi; }; STAGED=");
        try appendQuoted(&cmd, allocator, staged);
        try appendCmd(&cmd, allocator, "; AVAIL=");
        try appendQuoted(&cmd, allocator, avail);
        try appendCmd(&cmd, allocator, "; ENABLED=");
        try appendQuoted(&cmd, allocator, enabled);
        try appendCmd(&cmd, allocator, "; MARKER=");
        const marker = try nginxOwnershipMarker(allocator, app.id);
        defer allocator.free(marker);
        try appendQuoted(&cmd, allocator, marker);
        try appendCmd(&cmd, allocator, "; if [ -f \"$AVAIL\" ] && ! head -n 1 \"$AVAIL\" | grep -Fx -- \"$MARKER\" >/dev/null; then echo 'nginx site ownership changed since preflight'; exit 1; fi; BACKUP=$(mktemp); LINK_WAS=0; [ -L \"$ENABLED\" ] && LINK_WAS=1; [ -f \"$AVAIL\" ] && as_root cp -a \"$AVAIL\" \"$BACKUP\" 2>/dev/null || true; ");
        try appendCmd(&cmd, allocator, "as_root install -m 0644 \"$STAGED\" \"$AVAIL\" || { echo 'nginx: install of staged site failed (no privilege)'; exit 1; }; ");
        try appendCmd(&cmd, allocator, "as_root ln -sfn \"$AVAIL\" \"$ENABLED\" || exit 1; ");
        try appendCmd(&cmd, allocator, "if ! as_root nginx -t 2>&1; then echo 'nginx -t failed -- restoring'; [ -s \"$BACKUP\" ] && as_root install -m 0644 \"$BACKUP\" \"$AVAIL\" || as_root rm -f \"$AVAIL\"; if [ \"$LINK_WAS\" = \"1\" ]; then as_root ln -sfn \"$AVAIL\" \"$ENABLED\"; else as_root rm -f \"$ENABLED\"; fi; as_root nginx -t 2>&1; exit 1; fi; ");
        try appendCmd(&cmd, allocator, "as_root nginx -s reload 2>&1 || { echo 'nginx reload failed -- restoring'; [ -s \"$BACKUP\" ] && as_root install -m 0644 \"$BACKUP\" \"$AVAIL\" || as_root rm -f \"$AVAIL\"; if [ \"$LINK_WAS\" = \"1\" ]; then as_root ln -sfn \"$AVAIL\" \"$ENABLED\"; else as_root rm -f \"$ENABLED\"; fi; as_root nginx -t 2>&1; as_root nginx -s reload 2>&1; exit 1; }; rm -f \"$BACKUP\" \"$STAGED\"");
        try addStep(&steps, allocator, .nginx, cmd.items);
    }

    // 6. certbot — only when SSL is on; DNS pre-check first (spec 07 §6:
    // fail early before a doomed http-01; certbot remains final authority).
    if (app.ssl and app.domains.len > 0) {
        var cmd: std.ArrayList(u8) = .empty;
        defer cmd.deinit(allocator);
        try appendCmd(&cmd, allocator, "command -v dig >/dev/null || { echo 'dig is required for the DNS pre-check'; exit 1; }; for d in");
        for (app.domains) |d| try appendQuoted(&cmd, allocator, d);
        try appendCmd(&cmd, allocator, "; do dig +short A \"$d\" | grep -q . || dig +short AAAA \"$d\" | grep -q . || { echo \"no DNS record for $d\"; exit 1; }; done; as_root() { if [ \"$(id -u)\" = 0 ]; then \"$@\"; else sudo -n \"$@\"; fi; }; as_root certbot --nginx");
        for (app.domains) |d| {
            try appendCmd(&cmd, allocator, " -d ");
            try appendQuoted(&cmd, allocator, d);
        }
        try appendCmd(&cmd, allocator, " --non-interactive --agree-tos -m ");
        try appendQuoted(&cmd, allocator, app.email);
        try addStep(&steps, allocator, .certbot, cmd.items);
    } else {
        try addStep(&steps, allocator, .certbot, "");
    }

    return steps.toOwnedSlice(allocator);
}

pub fn nginxAvailableDir() []const u8 {
    return "/etc/nginx/sites-available";
}

pub fn nginxEnabledDir() []const u8 {
    return "/etc/nginx/sites-enabled";
}

pub fn nginxAvailablePath(allocator: std.mem.Allocator, app_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "/etc/nginx/sites-available/{s}", .{app_id});
}

pub fn nginxEnabledPath(allocator: std.mem.Allocator, app_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "/etc/nginx/sites-enabled/{s}", .{app_id});
}

/// `<folder>/.oars-pm2.json` — the PM2 ecosystem file location.
pub fn pm2EcosystemPath(allocator: std.mem.Allocator, folder: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/.oars-pm2.json", .{folder});
}

/// The Oars-owned PM2 process name: stable, collision-proof, and identifies
/// the process as managed by this app (NEXT-SPEC ownership IDs).
pub fn pm2ProcessName(allocator: std.mem.Allocator, app_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "oars-{s}", .{app_id});
}

/// The `.env` location: `<folder>/.env` (spec 07 §6).
pub fn envFilePath(allocator: std.mem.Allocator, folder: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/.env", .{folder});
}

pub const FileMode = enum(u32) { secret = 0o600, nginx_site = 0o644 };
pub fn requiredMode(kind: enum { deploy_key, known_hosts, env_file, pm2_ecosystem, nginx_site }) u32 {
    return switch (kind) {
        .deploy_key, .known_hosts, .env_file, .pm2_ecosystem => 0o600,
        .nginx_site => 0o644,
    };
}
/// The Oars ownership marker the collision check reads (first line of generated nginx site).
pub fn nginxOwnershipMarker(allocator: std.mem.Allocator, app_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "# oars:app={s} schema=1", .{app_id});
}
/// True when content starts with an Oars nginx marker (any app id).
pub fn hasNginxOwnershipMarker(content: []const u8) bool {
    return std.mem.startsWith(u8, content, "# oars:app=");
}
/// The nginx site config content for an app (spec 07 §13 + NEXT-SPEC
/// plan-by-type table): node/next reverse-proxy to the app port; react SPA
/// serves the build folder with the history-api fallback; static serves
/// files only. The first line is the Oars ownership marker the preflight
/// collision check reads.
pub fn nginxConfig(allocator: std.mem.Allocator, app: *const App) ![]u8 {
    var server_names: std.ArrayList(u8) = .empty;
    defer server_names.deinit(allocator);
    if (app.domains.len == 0) {
        try server_names.appendSlice(allocator, "_");
    } else {
        for (app.domains, 0..) |d, i| {
            if (i > 0) try server_names.appendSlice(allocator, " ");
            try server_names.appendSlice(allocator, d);
        }
    }
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    switch (app.runtime.type) {
        .node, .next => {
            try body.appendSlice(allocator, "    location / {\n        proxy_pass http://127.0.0.1:");
            var port_buf: [8]u8 = undefined;
            const port = std.fmt.bufPrint(&port_buf, "{d}", .{app.app_port}) catch unreachable;
            try body.appendSlice(allocator, port);
            try body.appendSlice(allocator,
                \\;
                \\        proxy_set_header Host $host;
                \\        proxy_set_header X-Real-IP $remote_addr;
                \\        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                \\        proxy_set_header X-Forwarded-Proto $scheme;
                \\    }
            );
        },
        .react, .static => {
            const root = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ app.folder, app.runtime.build_folder });
            defer allocator.free(root);
            try body.appendSlice(allocator, "    root ");
            try body.appendSlice(allocator, root);
            try body.appendSlice(allocator, ";\n    location / {\n        try_files $uri $uri/ ");
            try body.appendSlice(allocator, if (app.runtime.type == .react) "/index.html" else "=404");
            try body.appendSlice(allocator, ";\n    }");
        },
    }
    return std.fmt.allocPrint(allocator,
        \\# oars:app={s} schema=1
        \\server {{
        \\    listen 80;
        \\    server_name {s};
        \\{s}
        \\}}
        \\
    , .{ app.id, server_names.items, body.items });
}

/// `.env` content: one `NAME=value` line per env var (all values, secret
/// values included — they live on the server, never in Oars config).
pub fn envFile(allocator: std.mem.Allocator, app: *const App, values: []const SecretValue) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (app.env_vars) |v| {
        const value = if (v.secret) blk: {
            const found = findSecret(values, v.name) orelse continue;
            break :blk found.value;
        } else v.value;
        try out.appendSlice(allocator, v.name);
        try out.appendSlice(allocator, "=");
        try out.appendSlice(allocator, value);
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

/// The PM2 ecosystem file content (spec 07 §6 + NEXT-SPEC: structured
/// name, cwd, script, args, env, and Oars ownership). The structured
/// entry/args pair is the normal path; a shell-code start override runs as
/// `/bin/sh -c <command>` with a JSON args array — Oars never splits an
/// arbitrary start command on whitespace to invent fields.
pub fn ecosystemFile(allocator: std.mem.Allocator, app: *const App, values: []const SecretValue) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const proc = try pm2ProcessName(allocator, app.id);
    defer allocator.free(proc);
    try out.appendSlice(allocator, "{\"apps\":[{\n  \"name\": ");
    try writeJsonString(&out, allocator, proc);
    try out.appendSlice(allocator, ",\n  \"cwd\": ");
    try writeJsonString(&out, allocator, app.folder);
    if (app.runtime.start_command.len > 0) {
        try out.appendSlice(allocator, ",\n  \"script\": \"/bin/sh\",\n  \"args\": [\"-c\", ");
        try writeJsonString(&out, allocator, app.runtime.start_command);
        try out.appendSlice(allocator, "],\n  \"interpreter\": \"none\"");
    } else {
        try out.appendSlice(allocator, ",\n  \"script\": ");
        try writeJsonString(&out, allocator, app.runtime.entry);
        try out.appendSlice(allocator, ",\n  \"args\": ");
        try writeJsonString(&out, allocator, app.runtime.args);
    }
    try out.appendSlice(allocator, ",\n  \"env\": {");
    var first = true;
    for (app.env_vars) |v| {
        const value = if (v.secret) blk: {
            const found = findSecret(values, v.name) orelse continue;
            break :blk found.value;
        } else v.value;
        if (!first) try out.append(allocator, ',');
        first = false;
        try writeJsonString(&out, allocator, v.name);
        try out.appendSlice(allocator, ": ");
        try writeJsonString(&out, allocator, value);
    }
    try out.appendSlice(allocator, "}\n}]}\n");
    return out.toOwnedSlice(allocator);
}

pub fn ecosystemFileForInterpreter(allocator: std.mem.Allocator, app: *const App, values: []const SecretValue, interpreter: []const u8) ![]u8 {
    const base = try ecosystemFile(allocator, app, values);
    defer allocator.free(base);
    if (app.runtime.start_command.len > 0 or interpreter.len == 0) return allocator.dupe(u8, base);
    const needle = "\n  \"cwd\":";
    const at = std.mem.indexOf(u8, base, needle) orelse return allocator.dupe(u8, base);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, base[0..at]);
    try out.appendSlice(allocator, "\n  \"interpreter\": ");
    try writeJsonString(&out, allocator, interpreter);
    try out.append(allocator, ',');
    try out.appendSlice(allocator, base[at..]);
    return out.toOwnedSlice(allocator);
}

/// Minimal JSON string writer (duplicated from json.zig to keep deploy.zig
/// standalone — the ecosystem file must be valid JSON on the server).
fn writeJsonString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try out.append(allocator, '"');
    for (value) |ch| {
        switch (ch) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => {
                if (ch < 0x20) {
                    try out.appendSlice(allocator, "\\u");
                    const hex = "0123456789abcdef";
                    var buf: [4]u8 = undefined;
                    buf[0] = '0';
                    buf[1] = '0';
                    buf[2] = hex[(ch >> 4) & 0xf];
                    buf[3] = hex[ch & 0xf];
                    try out.appendSlice(allocator, &buf);
                } else {
                    try out.append(allocator, ch);
                }
            },
        }
    }
    try out.append(allocator, '"');
}

// --- runs ------------------------------------------------------------------

// Bridge contract (NEXT-SPEC): run + per-step state must be identical to
// the spec vocabulary — back-compat with bridge.ts relies on these names.
pub const StepState = enum(u8) {
    pending,
    running,
    cancel_requested,
    canceled,
    success,
    failed,
    skipped,

    pub fn jsonName(self: StepState) []const u8 {
        return @tagName(self);
    }
};

pub const RunStatus = enum(u8) {
    queued,
    running,
    cancel_requested,
    canceled,
    done,
    failed,
    interrupted,

    pub fn jsonName(self: RunStatus) []const u8 {
        return @tagName(self);
    }
};

pub const Step = struct {
    cancel_token: ?[]const u8 = null,
    cancel_ctrl: ?[]const u8 = null,
    id: StepId,
    label: []const u8,
    /// Owned; empty = skipped.
    command: []u8,
    state: StepState = .pending,
    channel: ?u32 = null,
    prepare_channel: ?u32 = null,
    prepared: bool = false,
    /// Worker-owned verifier channel used by cancellation. The bridge poll
    /// consumes it asynchronously, so cancel never blocks the UI thread.
    cancel_channel: ?u32 = null,
    exit: ?i32 = null,
    /// Static error text only (mirrors the transfer registries).
    @"error": []const u8 = "",
    /// Internal reads use one absolute cursor. Masked chunks keep their raw
    /// cursor bounds so every deployment view can read the same deltas after
    /// the SSH channel is closed without exposing a secret or draining
    /// another view.
    capture_cursor: u64 = 0,
    output_floor: u64 = 0,
    output_bytes: usize = 0,
    output_chunks: std.ArrayList(OutputChunk) = .empty,
    /// Raw bytes withheld at the end of the latest SSH delta. Keeping at
    /// most max-secret-length minus one lets the next delta mask a secret
    /// that crosses the channel boundary. These bytes are never serialized.
    redaction_pending: std.ArrayList(u8) = .empty,
    redaction_pending_start: u64 = 0,
    stream_eof: bool = false,
    termination_verified: bool = false,

    pub fn deinit(self: *Step, allocator: std.mem.Allocator) void {
        allocator.free(self.command);
        allocator.free(self.label);
        if (self.cancel_token) |t| allocator.free(t);
        if (self.cancel_ctrl) |c| allocator.free(c);
        for (self.output_chunks.items) |*chunk| chunk.deinit(allocator);
        self.output_chunks.deinit(allocator);
        std.crypto.secureZero(u8, self.redaction_pending.items);
        self.redaction_pending.deinit(allocator);
    }
};

pub const OutputChunk = struct {
    start: u64,
    end: u64,
    data: []u8,

    fn deinit(self: *OutputChunk, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

/// One secret value for this run: protected memory, freed at run teardown,
/// never serialized (spec 07 §5/§8).
pub const SecretValue = struct {
    name: []const u8,
    value: []const u8,
};

fn findSecret(values: []const SecretValue, name: []const u8) ?*const SecretValue {
    for (values) |*v| {
        if (std.mem.eql(u8, v.name, name)) return v;
    }
    return null;
}

pub const Run = struct {
    id: u32,
    server_id: []const u8,
    app_id: []const u8,
    app_name: []const u8,
    /// The app snapshot this run deploys (owned; cloned at start). The
    /// config files (`.env`, PM2 ecosystem, nginx site) are built from it
    /// on the server, so mid-run app edits never affect a running plan.
    app: App,
    /// `.env` is written before install or build, whichever runs first
    /// (spec 07 §6) — once per run.
    env_written: bool = false,
    steps: std.ArrayList(Step) = .empty,
    step_index: usize = 0,
    cancel_requested: bool = false,
    canceled: bool = false,
    status: RunStatus = .queued,
    /// What initiated the run: "deploy" (first) or "update" (re-deploy).
    action: []const u8 = "",
    /// The deployed commit when the clone step has proven it (owned).
    commit: []const u8 = "",
    /// Exact patch release resolved by preflight, including the leading `v`.
    node_release: []const u8 = "",
    /// Absolute Node interpreter path frozen from the preflight user's home.
    node_interpreter: []const u8 = "",
    /// Wire timestamps are integer milliseconds (NEXT-SPEC bridge contract).
    started_at_ms: i64 = 0,
    finished_at_ms: ?i64 = null,
    /// Secret values for the `.env` and ecosystem writes. These buffers are
    /// cleared as soon as the last secret-bearing remote write succeeds.
    secrets: std.ArrayList(SecretValue) = .empty,
    /// Independent copies kept only for output redaction. A zeroed write
    /// buffer must never disable masking for output that arrives later.
    redactions: std.ArrayList(SecretValue) = .empty,
    secrets_cleared: bool = false,
    /// Masked output accumulated for history (bounded; per-step cursor).
    output: std.ArrayList(u8) = .empty,
    output_cursor: u64 = 0,
    output_truncated: bool = false,

    pub fn deinit(self: *Run, allocator: std.mem.Allocator) void {
        allocator.free(self.server_id);
        allocator.free(self.app_id);
        allocator.free(self.app_name);
        allocator.free(self.action);
        allocator.free(self.commit);
        allocator.free(self.node_release);
        allocator.free(self.node_interpreter);
        // `deinit` would resolve to this method; use the app-free alias.
        appDeinit(allocator, &self.app);
        for (self.steps.items) |*s| s.deinit(allocator);
        self.steps.deinit(allocator);
        for (self.secrets.items) |*s| {
            std.crypto.secureZero(u8, @constCast(s.value));
            allocator.free(s.name);
            allocator.free(s.value);
        }
        self.secrets.deinit(allocator);
        for (self.redactions.items) |*s| {
            std.crypto.secureZero(u8, @constCast(s.value));
            allocator.free(s.name);
            allocator.free(s.value);
        }
        self.redactions.deinit(allocator);
        self.output.deinit(allocator);
    }

    /// Zeros owned secret buffers early (after the last required remote
    /// secret-bearing write) while keeping the masked redaction buffers
    /// alive at the Run boundary if masking must continue.
    pub fn zeroSecrets(self: *Run) void {
        if (self.secrets_cleared) return;
        for (self.secrets.items) |*s| std.crypto.secureZero(u8, @constCast(s.value));
        self.secrets_cleared = true;
    }

    pub fn currentStep(self: *Run) ?*Step {
        if (self.step_index >= self.steps.items.len) return null;
        return &self.steps.items[self.step_index];
    }

    fn appendMaskedChunk(self: *Run, allocator: std.mem.Allocator, step: *Step, masked: []u8, start: u64, end: u64) void {
        if (masked.len == 0) {
            allocator.free(masked);
            return;
        }
        if (!self.output_truncated) {
            const room = history_output_cap -| self.output.items.len;
            if (masked.len >= room) {
                self.output.appendSlice(allocator, masked[0..room]) catch {};
                self.output_truncated = true;
            } else {
                self.output.appendSlice(allocator, masked) catch {};
            }
        }

        step.output_chunks.append(allocator, .{ .start = start, .end = end, .data = masked }) catch {
            allocator.free(masked);
            return;
        };
        step.output_bytes += masked.len;
        while (step.output_bytes > history_output_cap and step.output_chunks.items.len > 1) {
            var removed = step.output_chunks.orderedRemove(0);
            step.output_bytes -= removed.data.len;
            removed.deinit(allocator);
        }
        step.output_floor = step.output_chunks.items[0].start;
    }

    /// Captures one internal channel delta. The trailing overlap is withheld
    /// until the next delta, so a known secret split between two SSH polls is
    /// replaced before any part enters a view or the retained history.
    pub fn captureOutput(self: *Run, allocator: std.mem.Allocator, step: *Step, data: []const u8, start: u64, end: u64, eof: bool) void {
        _ = end;
        if (step.redaction_pending.items.len == 0) {
            step.redaction_pending_start = start;
        } else {
            const expected = step.redaction_pending_start + step.redaction_pending.items.len;
            if (start != expected) {
                // A channel retention gap makes cross-boundary reconstruction
                // impossible. Drop the raw overlap instead of risking a
                // partial secret in retained output.
                std.crypto.secureZero(u8, step.redaction_pending.items);
                step.redaction_pending.clearRetainingCapacity();
                step.redaction_pending_start = start;
                self.output_truncated = true;
            }
        }
        step.redaction_pending.appendSlice(allocator, data) catch return;

        var max_secret_len: usize = 0;
        for (self.redactions.items) |secret| max_secret_len = @max(max_secret_len, secret.value.len);
        const keep = if (eof or max_secret_len == 0) 0 else max_secret_len - 1;
        const safe_end = step.redaction_pending.items.len -| keep;
        if (safe_end == 0) return;

        var masked: std.ArrayList(u8) = .empty;
        defer masked.deinit(allocator);
        var pos: usize = 0;
        while (pos < safe_end) {
            var best_len: usize = 0;
            for (self.redactions.items) |secret| {
                if (secret.value.len == 0 or secret.value.len <= best_len) continue;
                if (secret.value.len > step.redaction_pending.items.len - pos) continue;
                if (std.mem.eql(u8, step.redaction_pending.items[pos .. pos + secret.value.len], secret.value)) best_len = secret.value.len;
            }
            if (best_len > 0) {
                masked.appendSlice(allocator, "***") catch return;
                pos += best_len;
            } else {
                masked.append(allocator, step.redaction_pending.items[pos]) catch return;
                pos += 1;
            }
        }

        const chunk_start = step.redaction_pending_start;
        const chunk_end = chunk_start + pos;
        const remaining = step.redaction_pending.items.len - pos;
        std.mem.copyForwards(u8, step.redaction_pending.items[0..remaining], step.redaction_pending.items[pos..]);
        std.crypto.secureZero(u8, step.redaction_pending.items[remaining..]);
        step.redaction_pending.items.len = remaining;
        step.redaction_pending_start = chunk_end;
        self.appendMaskedChunk(allocator, step, masked.toOwnedSlice(allocator) catch return, chunk_start, chunk_end);
    }

    /// Terminal transitions can occur without channel EOF after a disconnect.
    /// Discard withheld raw fragments before the run enters retained history.
    pub fn discardOutputTails(self: *Run) void {
        for (self.steps.items) |*step| {
            std.crypto.secureZero(u8, step.redaction_pending.items);
            step.redaction_pending.clearRetainingCapacity();
        }
    }
};

/// Replaces every occurrence of a secret value with `***` (longest values
/// first so a shorter value never masks inside a longer one).
pub fn maskSecrets(allocator: std.mem.Allocator, data: []const u8, secrets: []const SecretValue) ![]u8 {
    var ordered: std.ArrayList(*const SecretValue) = .empty;
    defer ordered.deinit(allocator);
    for (secrets) |*s| try ordered.append(allocator, s);
    std.mem.sort(*const SecretValue, ordered.items, {}, struct {
        fn lessThan(_: void, a: *const SecretValue, b: *const SecretValue) bool {
            return a.value.len > b.value.len;
        }
    }.lessThan);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var pos: usize = 0;
    while (pos < data.len) {
        var best: ?usize = null; // index into ordered of the longest match at pos
        var best_len: usize = 0;
        for (ordered.items, 0..) |s, i| {
            if (s.value.len == 0 or s.value.len > data.len - pos) continue;
            if (s.value.len <= best_len) continue;
            if (std.mem.eql(u8, data[pos .. pos + s.value.len], s.value)) {
                best = i;
                best_len = s.value.len;
            }
        }
        if (best) |i| {
            try out.appendSlice(allocator, "***");
            pos += ordered.items[i].value.len;
        } else {
            try out.append(allocator, data[pos]);
            pos += 1;
        }
    }
    return out.toOwnedSlice(allocator);
}

/// Registry of live runs (bounded completed history). Main-thread access
/// (bridge handlers), guarded by a spinlock.
pub const Runs = struct {
    allocator: std.mem.Allocator = undefined,
    mutex: std.atomic.Mutex = .unlocked,
    list: std.ArrayList(Run) = .empty,
    next_id: u32 = 1,
    const max_completed: usize = 32;

    pub fn lock(self: *Runs) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    pub fn unlock(self: *Runs) void {
        self.mutex.unlock();
    }

    pub fn deinit(self: *Runs) void {
        for (self.list.items) |*r| r.deinit(self.allocator);
        self.list.deinit(self.allocator);
    }

    /// Registers a run with the planned steps and the run's secret values
    /// (all duplicated). Returns the run id. Caller holds the registry lock.
    pub fn start(
        self: *Runs,
        server_id: []const u8,
        app: *const App,
        plan: []const PlanStep,
        secret_values: []const SecretValue,
        action: []const u8,
        commit: []const u8,
        node_release: []const u8,
        node_interpreter: []const u8,
        io: std.Io,
        now_ms: i64,
    ) !u32 {
        var run = Run{
            .id = self.next_id,
            .server_id = try self.allocator.dupe(u8, server_id),
            .app_id = try self.allocator.dupe(u8, app.id),
            .app_name = try self.allocator.dupe(u8, app.name),
            .app = try clone(self.allocator, app.*),
            .action = try self.allocator.dupe(u8, action),
            .commit = try self.allocator.dupe(u8, commit),
            .node_release = try self.allocator.dupe(u8, node_release),
            .node_interpreter = try self.allocator.dupe(u8, node_interpreter),
            .started_at_ms = now_ms,
        };
        errdefer run.deinit(self.allocator);
        self.next_id +%= 1;
        for (plan) |*ps| {
            const tok = cancelToken(self.allocator, io) catch null;
            const ctrl = if (tok) |t| controlFilePath(self.allocator, t) catch null else null;
            if (tok != null and ctrl == null) {
                if (tok) |t| self.allocator.free(t);
            }
            try run.steps.append(self.allocator, .{
                .cancel_token = tok,
                .cancel_ctrl = ctrl,
                .id = ps.id,
                .label = try self.allocator.dupe(u8, ps.label),
                .command = try self.allocator.dupe(u8, ps.command),
            });
        }
        for (secret_values) |*s| {
            try run.secrets.append(self.allocator, .{
                .name = try self.allocator.dupe(u8, s.name),
                .value = try self.allocator.dupe(u8, s.value),
            });
            try run.redactions.append(self.allocator, .{
                .name = try self.allocator.dupe(u8, s.name),
                .value = try self.allocator.dupe(u8, s.value),
            });
        }
        self.list.append(self.allocator, run) catch return error.OutOfMemory;
        return run.id;
    }

    /// Caller holds the lock.
    pub fn get(self: *Runs, id: u32) ?*Run {
        for (self.list.items) |*r| {
            if (r.id == id) return r;
        }
        return null;
    }

    /// Drops finished runs beyond the bounded history (oldest first).
    pub fn evictFinished(self: *Runs) void {
        var finished: usize = 0;
        for (self.list.items) |*r| {
            if (r.status == .done or r.status == .failed or r.status == .canceled or r.status == .interrupted) finished += 1;
        }
        var i: usize = 0;
        while (i < self.list.items.len and finished > max_completed) {
            const r = &self.list.items[i];
            const terminal = r.status == .done or r.status == .failed or r.status == .canceled or r.status == .interrupted;
            if (terminal) {
                var evicted = self.list.orderedRemove(i);
                evicted.deinit(self.allocator);
                finished -= 1;
            } else {
                i += 1;
            }
        }
    }
};

// --- history ---------------------------------------------------------------

pub const HistoryStep = struct {
    id: StepId,
    state: StepState,
    exit: ?i32 = null,
    @"error": []const u8 = "",
};

pub const HistoryRecord = struct {
    id: u32,
    server_id: []const u8,
    app_id: []const u8,
    status: RunStatus,
    /// What initiated the run: "deploy" (first) or "update" (re-deploy).
    action: []const u8 = "",
    /// The deployed commit when known (empty before the clone step lands).
    commit: []const u8 = "",
    /// Integer milliseconds (NEXT-SPEC wire contract).
    started_at_ms: i64,
    finished_at_ms: ?i64 = null,
    steps: []HistoryStep = &.{},
    /// Masked output, trimmed to `history_output_cap`.
    output: []const u8 = "",
    truncated: bool = false,
};

/// Run history: `deploy_runs.json`, capped at `max_history_runs` records
/// (30-day retention is a display concern; the cap bounds the file).
pub const HistoryStore = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    mutex: std.atomic.Mutex = .unlocked,

    /// The parsed records reference the file buffer, so the buffer is kept
    /// alive alongside the parse (mirrors the apps store).
    pub const Loaded = struct {
        parsed: std.json.Parsed([]HistoryRecord),
        content: ?[]u8,

        pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
            self.parsed.deinit();
            if (self.content) |c| allocator.free(c);
        }
    };

    pub fn loadParsed(self: *HistoryStore, io: std.Io) !Loaded {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.loadParsedLocked(io);
    }

    fn loadParsedLocked(self: *HistoryStore, io: std.Io) !Loaded {
        const cwd = std.Io.Dir.cwd();
        const content = cwd.readFileAlloc(io, self.path, self.allocator, .limited(max_history_runs * (history_output_cap + 4096))) catch return emptyLoaded(self.allocator);
        const parsed = std.json.parseFromSlice([]HistoryRecord, self.allocator, content, .{}) catch return emptyLoaded(self.allocator);
        return .{ .parsed = parsed, .content = content };
    }

    fn emptyLoaded(allocator: std.mem.Allocator) !Loaded {
        return .{
            .parsed = try std.json.parseFromSlice([]HistoryRecord, allocator, "[]", .{}),
            .content = null,
        };
    }

    /// Appends a record for `run`, trimming output to the history cap, then
    /// prunes: first records older than `history_retention_ms`, then the
    /// oldest beyond `max_history_runs` (NEXT-SPEC retention order). Pruning
    /// compares timestamps, not append order.
    pub fn append(self: *HistoryStore, io: std.Io, run: *Run, now_ms: i64) void {
        run.discardOutputTails();
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return;
        defer loaded.deinit(self.allocator);
        var list: std.ArrayList(HistoryRecord) = .empty;
        defer {
            for (list.items) |*r| freeRecord(self.allocator, r);
            list.deinit(self.allocator);
        }
        // The parsed records reference the file buffer; duplicate the ones
        // we keep. Age-prune anything older than the cutoff first.
        const cutoff = now_ms - history_retention_ms;
        for (loaded.parsed.value) |rec| {
            if (rec.started_at_ms < cutoff) continue;
            list.append(self.allocator, dupRecord(self.allocator, rec) catch return) catch return;
        }
        // Count-prune the oldest by start time to make room for the new record.
        while (list.items.len > max_history_runs - 1) {
            var oldest: usize = 0;
            for (list.items[1..], 1..) |r, i| {
                if (r.started_at_ms < list.items[oldest].started_at_ms) oldest = i;
            }
            var victim = list.orderedRemove(oldest);
            freeRecord(self.allocator, &victim);
        }
        const steps = self.allocator.alloc(HistoryStep, run.steps.items.len) catch return;
        errdefer self.allocator.free(steps);
        for (run.steps.items, 0..) |s, i| {
            steps[i] = .{
                .id = s.id,
                .state = s.state,
                .exit = s.exit,
                .@"error" = self.allocator.dupe(u8, s.@"error") catch return,
            };
        }
        const server_id = self.allocator.dupe(u8, run.server_id) catch return;
        errdefer self.allocator.free(server_id);
        const app_id = self.allocator.dupe(u8, run.app_id) catch return;
        errdefer self.allocator.free(app_id);
        const action = self.allocator.dupe(u8, run.action) catch return;
        errdefer self.allocator.free(action);
        const commit = self.allocator.dupe(u8, run.commit) catch return;
        errdefer self.allocator.free(commit);
        const output = self.allocator.dupe(u8, run.output.items) catch return;
        errdefer self.allocator.free(output);
        list.append(self.allocator, .{
            .id = run.id,
            .server_id = server_id,
            .app_id = app_id,
            .status = run.status,
            .action = action,
            .commit = commit,
            .started_at_ms = run.started_at_ms,
            .finished_at_ms = run.finished_at_ms,
            .steps = steps,
            .output = output,
            .truncated = run.output_truncated,
        }) catch return;
        self.saveLocked(io, list.items) catch {};
    }

    fn freeRecord(allocator: std.mem.Allocator, r: *HistoryRecord) void {
        allocator.free(r.server_id);
        allocator.free(r.app_id);
        allocator.free(r.action);
        allocator.free(r.commit);
        for (r.steps) |*s| {
            allocator.free(s.@"error");
        }
        allocator.free(r.steps);
        allocator.free(r.output);
    }

    fn dupRecord(allocator: std.mem.Allocator, rec: HistoryRecord) !HistoryRecord {
        var out = HistoryRecord{
            .id = rec.id,
            .server_id = try allocator.dupe(u8, rec.server_id),
            .app_id = try allocator.dupe(u8, rec.app_id),
            .status = rec.status,
            .action = try allocator.dupe(u8, rec.action),
            .commit = try allocator.dupe(u8, rec.commit),
            .started_at_ms = rec.started_at_ms,
            .finished_at_ms = rec.finished_at_ms,
            .output = try allocator.dupe(u8, rec.output),
            .truncated = rec.truncated,
        };
        errdefer {
            allocator.free(out.server_id);
            allocator.free(out.app_id);
            allocator.free(out.action);
            allocator.free(out.commit);
            allocator.free(out.output);
        }
        out.steps = try allocator.alloc(HistoryStep, rec.steps.len);
        for (rec.steps, 0..) |s, i| {
            out.steps[i] = .{
                .id = s.id,
                .state = s.state,
                .exit = s.exit,
                .@"error" = try allocator.dupe(u8, s.@"error"),
            };
        }
        return out;
    }

    /// Atomic write (temp + sync + rename) — same pattern as the apps
    /// store; a torn history file must never destroy the record of what
    /// ran.
    fn saveLocked(self: *HistoryStore, io: std.Io, records: []const HistoryRecord) !void {
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(self.path)) |dir| try cwd.createDirPath(io, dir);
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        std.json.Stringify.value(records, .{ .whitespace = .indent_2 }, &out.writer) catch return error.SerializeFailed;
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
    }
};

// --- tests -----------------------------------------------------------------

const testing = std.testing;

fn testApp(allocator: std.mem.Allocator, id: []const u8) !App {
    return clone(allocator, .{
        .id = id,
        .server_id = "s1",
        .name = "storefront",
        .environment = .production,
        .folder = "/home/ubuntu/storefront",
        .repo = .{ .url = "git@github.com:you/storefront.git", .transport = .ssh, .branch = "main" },
        .runtime = .{
            .node_version = "22",
            .type = .next,
            .package_manager = .npm,
            .install = "npm ci",
            .build = "npm run build",
            .entry = "node_modules/next/dist/bin/next",
            .args = "start -p 3000",
            .build_folder = ".next",
        },
        .env_vars = &.{
            .{ .name = "NODE_ENV", .secret = false, .value = "production", .has_value = true },
            .{ .name = "DATABASE_URL", .secret = true, .has_value = true },
        },
        .domains = &.{"storefront.dev"},
        .ssl = true,
        .email = "ops@storefront.dev",
        .app_port = 3000,
        .revision = 1,
        .created_at_ms = 1,
        .updated_at_ms = 1,
    });
}

fn testStorePaths(buf: *TestPaths, name: []const u8) []const u8 {
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    buf.dir = std.fmt.bufPrint(&buf.dir_buf, "oars-{s}-{d}", .{ name, now }) catch unreachable;
    return std.fmt.bufPrint(&buf.path_buf, "/tmp/{s}/apps.json", .{buf.dir}) catch unreachable;
}

const TestPaths = struct {
    dir_buf: [128]u8 = undefined,
    path_buf: [512]u8 = undefined,
    dir: []const u8 = "",
};

test "apps store round trip preserves secret flags and never stores values" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    var paths: TestPaths = .{};
    const path = testStorePaths(&paths, "apps-test");
    defer std.Io.Dir.cwd().deleteTree(io, paths.dir) catch {};
    var store = AppStore{ .allocator = allocator, .path = path };

    var created = try store.saveApp(io, .{
        .id = "a1",
        .server_id = "s1",
        .name = "storefront",
        .folder = "/home/ubuntu/storefront",
        .repo = .{ .url = "git@github.com:you/storefront.git", .transport = "ssh", .branch = "main" },
        .runtime = .{ .node_version = "22", .type = "next", .package_manager = "npm", .install = "npm ci", .build = "npm run build", .entry = "server.js" },
        .env_vars = &.{
            .{ .name = "NODE_ENV", .secret = false, .value = "production" },
            .{ .name = "DATABASE_URL", .secret = true, .has_value = true },
        },
        .domains = &.{"storefront.dev"},
        .ssl = true,
        .email = "ops@storefront.dev",
        .app_port = 3000,
    }, 1_000);
    defer deinit(allocator, &created);
    try testing.expectEqualStrings("storefront", created.name);
    try testing.expectEqual(@as(usize, 2), created.env_vars.len);
    try testing.expect(created.env_vars[1].secret);
    try testing.expect(!created.env_vars[1].has_value);
    try testing.expectEqualStrings("", created.env_vars[1].value); // never stored
    try testing.expectEqual(@as(u64, 1), created.revision);
    try testing.expectEqual(@as(i64, 1_000), created.created_at_ms);
    try testing.expectEqual(@as(i64, 1_000), created.updated_at_ms);

    // The secret value sent at save time must NOT persist either.
    var loaded = try store.loadParsed(io);
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), loaded.parsed.value.len);
    try testing.expectEqualStrings("", loaded.parsed.value[0].env_vars[1].value);
    try testing.expect(std.mem.indexOf(u8, loaded.content.?, "postgres://secret") == null);

    // The atomic write leaves no temp file behind and lands 0600.
    {
        var tmp_buf: [520]u8 = undefined;
        const tmp = try std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path});
        try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(io, tmp, .{}));
        const stat = try std.Io.Dir.cwd().statFile(io, path, .{});
        try testing.expectEqual(@as(u16, 0), stat.permissions.toMode() & 0o077);
    }

    // An edit preserves created_at_ms and bumps the revision.
    var edited = try store.saveApp(io, .{
        .id = "a1",
        .server_id = "s1",
        .name = "storefront-v2",
        .folder = "/home/ubuntu/storefront",
        .repo = .{ .url = "git@github.com:you/storefront.git", .transport = "ssh", .branch = "main" },
        .runtime = .{ .node_version = "24", .type = "next", .package_manager = "pnpm", .install = "pnpm install --frozen-lockfile", .build = "pnpm build", .entry = "server.js" },
        .env_vars = &.{.{ .name = "DATABASE_URL", .secret = true, .has_value = true }},
        .app_port = 3001,
    }, 2_000);
    defer deinit(allocator, &edited);
    try testing.expectEqual(@as(u64, 2), edited.revision);
    try testing.expectEqual(@as(i64, 1_000), edited.created_at_ms);
    try testing.expectEqual(@as(i64, 2_000), edited.updated_at_ms);
    try testing.expectEqual(PackageManager.pnpm, edited.runtime.package_manager);

    var found = (try store.find(io, "a1")) orelse return error.TestUnexpectedResult;
    defer deinit(allocator, &found);
    try testing.expectEqual(@as(u16, 3001), found.app_port);

    try testing.expect(try store.delete(io, "a1"));
    try testing.expect((try store.find(io, "a1")) == null);
}

test "app validation rejects bad input and unsupported transports" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    var paths: TestPaths = .{};
    const path = testStorePaths(&paths, "apps-valid");
    defer std.Io.Dir.cwd().deleteTree(io, paths.dir) catch {};
    var store = AppStore{ .allocator = allocator, .path = path };
    const now: i64 = 1;

    try testing.expectError(error.MissingName, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = " ", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" } }, now));
    try testing.expectError(error.InvalidFolder, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "relative", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" } }, now));
    try testing.expectError(error.InvalidFolder, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x/", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" } }, now));
    try testing.expectError(error.InvalidTransport, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ftp" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" } }, now));
    try testing.expectError(error.InvalidRepo, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "rm -rf /", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" } }, now));
    // Plain HTTP and file:// are not product transports; HTTPS with an
    // embedded token is refused (never persist credentials in the URL).
    try testing.expectError(error.UnsupportedTransport, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "http://github.com/you/x.git", .transport = "https" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" } }, now));
    try testing.expectError(error.UnsupportedTransport, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "file:///srv/x.git", .transport = "file" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" } }, now));
    try testing.expectError(error.InvalidRepo, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "https://ghp_secret@github.com/you/x.git", .transport = "https" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" } }, now));
    // Node major is format-only here; support is a preflight decision.
    try testing.expectError(error.InvalidNodeVersion, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "lts", .type = "node", .entry = "server.js" } }, now));
    try testing.expectError(error.InvalidPackageManager, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .package_manager = "gradle", .entry = "server.js" } }, now));
    // Node apps need a process entry and a port; react/static need a
    // safe build folder.
    try testing.expectError(error.MissingEntry, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node" } }, now));
    try testing.expectError(error.InvalidPort, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" }, .app_port = 0 }, now));
    try testing.expectError(error.MissingBuildFolder, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "react" } }, now));
    try testing.expectError(error.InvalidBuildFolder, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "static", .build_folder = "../escape" } }, now));
    try testing.expectError(error.InvalidEntry, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "/etc/passwd" } }, now));
    try testing.expectError(error.InvalidEnvVar, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" }, .env_vars = &.{.{ .name = "BAD NAME", .secret = false, .value = "v" }} }, now));
    try testing.expectError(error.InvalidEnvVar, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" }, .env_vars = &.{.{ .name = "A", .secret = false, .value = "a\nb" }} }, now));
    try testing.expectError(error.DuplicateEnvVar, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" }, .env_vars = &.{ .{ .name = "A", .secret = false, .value = "1" }, .{ .name = "A", .secret = false, .value = "2" } } }, now));
    try testing.expectError(error.InvalidDomain, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" }, .domains = &.{"-bad.example"} }, now));
    try testing.expectError(error.EmailRequired, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" }, .domains = &.{"storefront.dev"}, .ssl = true, .email = "" }, now));

    // The test-only constructor admits local file:// fixtures.
    var test_store = AppStore{ .allocator = allocator, .path = path, .test_transports = true };
    var fixture_app = try test_store.saveApp(io, .{ .id = "fx", .server_id = "s1", .name = "fixture", .folder = "/srv/fx", .repo = .{ .url = "file:///srv/fx.git", .transport = "file" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" } }, now);
    defer deinit(allocator, &fixture_app);
    try testing.expectEqual(Transport.file, fixture_app.repo.transport);
}

test "app store enforces the per-server and total capacity limits" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    var paths: TestPaths = .{};
    const path = testStorePaths(&paths, "apps-limit");
    defer std.Io.Dir.cwd().deleteTree(io, paths.dir) catch {};
    var store = AppStore{ .allocator = allocator, .path = path };
    const now: i64 = 1;

    var i: usize = 0;
    while (i < max_apps_per_server) : (i += 1) {
        var id_buf: [16]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "app-{d}", .{i});
        var saved = try store.saveApp(io, .{ .id = id, .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" } }, now);
        deinit(allocator, &saved);
    }
    // The 101st app on this server is rejected; another server still has room.
    try testing.expectError(error.TooManyApps, store.saveApp(io, .{ .id = "over", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" } }, now));
    var other = try store.saveApp(io, .{ .id = "other", .server_id = "s2", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" } }, now);
    defer deinit(allocator, &other);
    // Editing an existing app at the cap still works.
    var edited = try store.saveApp(io, .{ .id = "app-0", .server_id = "s1", .name = "renamed", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node", .entry = "server.js" } }, now);
    defer deinit(allocator, &edited);
    try testing.expectEqualStrings("renamed", edited.name);
}

test "corrupt apps store is quarantined and reported" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    var paths: TestPaths = .{};
    const path = testStorePaths(&paths, "apps-corrupt");
    defer std.Io.Dir.cwd().deleteTree(io, paths.dir) catch {};
    var store = AppStore{ .allocator = allocator, .path = path };
    if (std.fs.path.dirname(path)) |dir| try std.Io.Dir.cwd().createDirPath(io, dir);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "{not json" });

    var loaded = try store.loadParsed(io);
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), loaded.parsed.value.len);
    try testing.expect(loaded.quarantined != null);
}

test "step planner builds the six-step plan with quoted values" {
    const allocator = testing.allocator;
    var app = try testApp(allocator, "a1");
    defer deinit(allocator, &app);

    const plan = try buildPlan(allocator, &app);
    defer {
        for (plan) |*s| s.deinit(allocator);
        allocator.free(plan);
    }
    try testing.expectEqual(@as(usize, 6), plan.len);
    try testing.expectEqual(StepId.clone, plan[0].id);
    // The fresh-folder clone path.
    try testing.expect(std.mem.indexOf(u8, plan[0].command, "git clone --branch 'main' 'git@github.com:you/storefront.git' '/home/ubuntu/storefront'") != null);
    // The recheck path (dirty + remote identity + ff-only pull).
    try testing.expect(std.mem.indexOf(u8, plan[0].command, "status --porcelain") != null);
    try testing.expect(std.mem.indexOf(u8, plan[0].command, "remote get-url origin") != null);
    try testing.expect(std.mem.indexOf(u8, plan[0].command, "pull --ff-only") != null);
    // Derived frozen install for the selected manager, no silent fallback.
    try testing.expect(std.mem.indexOf(u8, plan[1].command, "npm ci") != null);
    try testing.expect(std.mem.indexOf(u8, plan[1].command, "|| npm install") == null);
    // NODE_OPTIONS heap hint for node-family builds.
    try testing.expect(std.mem.indexOf(u8, plan[2].command, "NODE_OPTIONS=--max-old-space-size=4096 npm run build") != null);
    // pm2 scoped to the Oars-owned process name.
    try testing.expect(std.mem.indexOf(u8, plan[3].command, "pm2 startOrReload '/home/ubuntu/storefront/.oars-pm2.json' --only 'oars-a1'") != null);
    // nginx test + symlink + reload.
    try testing.expect(std.mem.indexOf(u8, plan[4].command, "nginx -t") != null);
    try testing.expect(std.mem.indexOf(u8, plan[4].command, "install -m 0644") != null);
    try testing.expect(std.mem.indexOf(u8, plan[4].command, "nginx -t") != null);
    try testing.expect(std.mem.indexOf(u8, plan[4].command, "BACKUP") != null);
    try testing.expect(std.mem.indexOf(u8, plan[4].command, "nginx -s reload") != null);
    // certbot with DNS pre-check, one -d per domain, user email only.
    try testing.expect(std.mem.indexOf(u8, plan[5].command, "dig +short A") != null);
    try testing.expect(std.mem.indexOf(u8, plan[5].command, "certbot --nginx -d 'storefront.dev' --non-interactive --agree-tos -m 'ops@storefront.dev'") != null);
}

test "ssl-off apps skip certbot but keep nginx" {
    const allocator = testing.allocator;
    var app = try testApp(allocator, "a2");
    defer deinit(allocator, &app);
    app.ssl = false;

    const plan = try buildPlan(allocator, &app);
    defer {
        for (plan) |*s| s.deinit(allocator);
        allocator.free(plan);
    }
    try testing.expectEqual(@as(usize, 6), plan.len);
    try testing.expectEqualStrings("", plan[5].command); // certbot skipped
    try testing.expect(std.mem.indexOf(u8, plan[4].command, "nginx -t") != null); // nginx still runs
}

test "react and static apps skip pm2" {
    const allocator = testing.allocator;
    var app = try testApp(allocator, "a2s");
    defer deinit(allocator, &app);
    app.runtime.type = .react;
    const plan = try buildPlan(allocator, &app);
    defer {
        for (plan) |*s| s.deinit(allocator);
        allocator.free(plan);
    }
    try testing.expectEqualStrings("", plan[3].command); // no process step
}

test "nginx config and ecosystem files are well-formed per app type" {
    const allocator = testing.allocator;
    var app = try testApp(allocator, "a3");
    defer deinit(allocator, &app);

    // Node/Next: reverse proxy with the ownership marker.
    const config = try nginxConfig(allocator, &app);
    defer allocator.free(config);
    try testing.expect(std.mem.indexOf(u8, config, "# oars:app=a3 schema=1") != null);
    try testing.expect(std.mem.indexOf(u8, config, "server_name storefront.dev;") != null);
    try testing.expect(std.mem.indexOf(u8, config, "proxy_pass http://127.0.0.1:3000;") != null);

    // Structured entry/args land verbatim; the Oars-owned name is used.
    const secrets = [_]SecretValue{.{ .name = "DATABASE_URL", .value = "postgres://secret" }};
    const eco = try ecosystemFile(allocator, &app, &secrets);
    defer allocator.free(eco);
    try testing.expect(std.mem.indexOf(u8, eco, "\"name\": \"oars-a3\"") != null);
    try testing.expect(std.mem.indexOf(u8, eco, "\"script\": \"node_modules/next/dist/bin/next\"") != null);
    try testing.expect(std.mem.indexOf(u8, eco, "\"args\": \"start -p 3000\"") != null);
    try testing.expect(std.mem.indexOf(u8, eco, "postgres://secret") != null); // on the server file, yes
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, eco, .{});
    defer parsed.deinit();
    try testing.expect(parsed.value != .null);

    // A shell-code start override runs through /bin/sh as an args array.
    var sh_app = try testApp(allocator, "a3sh");
    defer deinit(allocator, &sh_app);
    allocator.free(sh_app.runtime.start_command);
    sh_app.runtime.start_command = try allocator.dupe(u8, "exec node server.js --prod");
    const sh_eco = try ecosystemFile(allocator, &sh_app, &secrets);
    defer allocator.free(sh_eco);
    try testing.expect(std.mem.indexOf(u8, sh_eco, "\"script\": \"/bin/sh\"") != null);
    try testing.expect(std.mem.indexOf(u8, sh_eco, "\"args\": [\"-c\", \"exec node server.js --prod\"]") != null);
    const sh_parsed = try std.json.parseFromSlice(std.json.Value, allocator, sh_eco, .{});
    defer sh_parsed.deinit();

    // React SPA: served from the build folder with the history fallback.
    var react_app = try testApp(allocator, "a3r");
    defer deinit(allocator, &react_app);
    react_app.runtime.type = .react;
    allocator.free(react_app.runtime.build_folder);
    react_app.runtime.build_folder = try allocator.dupe(u8, "dist");
    const react_config = try nginxConfig(allocator, &react_app);
    defer allocator.free(react_config);
    try testing.expect(std.mem.indexOf(u8, react_config, "root /home/ubuntu/storefront/dist;") != null);
    try testing.expect(std.mem.indexOf(u8, react_config, "try_files $uri $uri/ /index.html;") != null);
    try testing.expect(std.mem.indexOf(u8, react_config, "proxy_pass") == null);

    // Static: no fallback, plain 404.
    var static_app = try testApp(allocator, "a3t");
    defer deinit(allocator, &static_app);
    static_app.runtime.type = .static;
    allocator.free(static_app.runtime.build_folder);
    static_app.runtime.build_folder = try allocator.dupe(u8, "public");
    const static_config = try nginxConfig(allocator, &static_app);
    defer allocator.free(static_config);
    try testing.expect(std.mem.indexOf(u8, static_config, "try_files $uri $uri/ =404;") != null);

    const env = try envFile(allocator, &app, &secrets);
    defer allocator.free(env);
    try testing.expect(std.mem.indexOf(u8, env, "NODE_ENV=production\n") != null);
    try testing.expect(std.mem.indexOf(u8, env, "DATABASE_URL=postgres://secret\n") != null);
}

test "maskSecrets replaces values longest-first and leaves non-secrets" {
    const allocator = testing.allocator;
    const secrets = [_]SecretValue{
        .{ .name = "A", .value = "short" },
        .{ .name = "B", .value = "shortvalue" },
    };
    const masked = try maskSecrets(allocator, "before shortvalue after short end", &secrets);
    defer allocator.free(masked);
    try testing.expectEqualStrings("before *** after *** end", masked);

    const no_match = try maskSecrets(allocator, "nothing here", &secrets);
    defer allocator.free(no_match);
    try testing.expectEqualStrings("nothing here", no_match);
}

test "maskSecrets handles overlapping and empty values" {
    const allocator = testing.allocator;
    // A shorter value must never mask inside a longer overlapping one.
    const overlapping = [_]SecretValue{
        .{ .name = "A", .value = "abc" },
        .{ .name = "B", .value = "abcdef" },
    };
    const masked = try maskSecrets(allocator, "x abcdef y abc z", &overlapping);
    defer allocator.free(masked);
    try testing.expectEqualStrings("x *** y *** z", masked);

    // Empty values mask nothing and never loop.
    const with_empty = [_]SecretValue{
        .{ .name = "EMPTY", .value = "" },
        .{ .name = "REAL", .value = "token123" },
    };
    const masked2 = try maskSecrets(allocator, "token123 and token123", &with_empty);
    defer allocator.free(masked2);
    try testing.expectEqualStrings("*** and ***", masked2);
}

// --- Phase 3: runtime & repo adapters -----------------------------------------------
test "resolveInstallCommand selects frozen installs and honors overrides" {
    const a = std.testing.allocator;
    var app = try testApp(a, "pm-a");
    defer deinit(a, &app);
    a.free(app.runtime.install);
    app.runtime.install = try a.dupe(u8, "");
    app.runtime.package_manager = .npm;
    const npm = try resolveInstallCommand(a, &app);
    defer a.free(npm);
    try std.testing.expectEqualStrings("npm ci", npm);
    a.free(app.runtime.install);
    app.runtime.install = try a.dupe(u8, "");
    app.runtime.package_manager = .pnpm;
    const pnpm = try resolveInstallCommand(a, &app);
    defer a.free(pnpm);
    try std.testing.expectEqualStrings("pnpm install --frozen-lockfile", pnpm);
    app.runtime.package_manager = .yarn;
    const yarn = try resolveInstallCommand(a, &app);
    defer a.free(yarn);
    try std.testing.expectEqualStrings("yarn install --immutable", yarn);
    // explicit override wins
    a.free(app.runtime.install);
    app.runtime.install = try a.dupe(u8, "make install");
    const over = try resolveInstallCommand(a, &app);
    defer a.free(over);
    try std.testing.expectEqualStrings("make install", over);
}

test "conflicting lockfiles are a blocker unless manager is explicit" {
    try std.testing.expectError(error.ConflictingLockfiles, validateLockfiles(.{ .npm = true, .pnpm = true, .yarn = false }, .auto));
    try validateLockfiles(.{ .npm = true, .pnpm = true, .yarn = false }, .npm);
    try validateLockfiles(.{ .npm = false, .pnpm = false, .yarn = false }, .auto);
}

test "Node resolver keeps only Active/Maintenance LTS and freezes highest patch" {
    const rels = [_]NodeRelease{
        .{ .version = "22.9.0", .major = 22, .lts = true },
        .{ .version = "22.11.0", .major = 22, .lts = true },
        .{ .version = "23.0.0", .major = 23, .lts = false },
        .{ .version = "24.1.0", .major = 24, .lts = true },
    };
    const v22 = resolveNodeRelease(&rels, 22).?;
    try std.testing.expectEqualStrings("22.11.0", v22.version);
    try std.testing.expect(resolveNodeRelease(&rels, 23) == null);
}

test "SSH identity uses per-app known_hosts and strict checking" {
    const a = std.testing.allocator;
    const kh = try knownHostsPath(a, "a1");
    defer a.free(kh);
    try std.testing.expect(std.mem.indexOf(u8, kh, ".config/oars/deploy") != null);
    const key = try deployKeyPath(a, "a1");
    defer a.free(key);
    const cmd = try gitSshCommand(a, "a1", key, kh);
    defer a.free(cmd);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "StrictHostKeyChecking=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "IdentitiesOnly=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "StrictHostKeyChecking=no") == null);
}

test "planner: file modes, ownership, and type-split PM2" {
    try std.testing.expectEqual(@as(u32, 0o600), requiredMode(.deploy_key));
    try std.testing.expectEqual(@as(u32, 0o600), requiredMode(.known_hosts));
    try std.testing.expectEqual(@as(u32, 0o600), requiredMode(.env_file));
    try std.testing.expectEqual(@as(u32, 0o600), requiredMode(.pm2_ecosystem));
    try std.testing.expectEqual(@as(u32, 0o644), requiredMode(.nginx_site));
    const a = std.testing.allocator;
    const m = try nginxOwnershipMarker(a, "a1");
    defer a.free(m);
    try std.testing.expect(std.mem.startsWith(u8, m, "# oars:app=a1"));
    try std.testing.expect(hasNginxOwnershipMarker("# oars:app=x schema=1\nfoo"));
    try std.testing.expect(!hasNginxOwnershipMarker("server {}\n"));
    // react/static have no PM2 command (nginx root + try_files split already covered by nginxConfig)
    var react = try testApp(a, "r1");
    defer deinit(a, &react);
    react.runtime.type = .react;
    a.free(react.runtime.build_folder);
    react.runtime.build_folder = try a.dupe(u8, "dist");
    const rp = try buildPlan(a, &react);
    defer {
        for (rp) |*st| st.deinit(a);
        a.free(rp);
    }
    try std.testing.expectEqualStrings("", rp[3].command); // PM2 skipped for SPA/static
    const ncfg = try nginxConfig(a, &react);
    defer a.free(ncfg);
    try std.testing.expect(std.mem.indexOf(u8, ncfg, "try_files $uri $uri/ /index.html") != null);
    var stat = try testApp(a, "s1");
    defer deinit(a, &stat);
    stat.runtime.type = .static;
    a.free(stat.runtime.build_folder);
    stat.runtime.build_folder = try a.dupe(u8, "out");
    const sp = try buildPlan(a, &stat);
    defer {
        for (sp) |*st| st.deinit(a);
        a.free(sp);
    }
    try std.testing.expectEqualStrings("", sp[3].command);
    const scfg = try nginxConfig(a, &stat);
    defer a.free(scfg);
    try std.testing.expect(std.mem.indexOf(u8, scfg, "try_files $uri $uri/ =404") != null);
    // node keeps PM2
    var node = try testApp(a, "n1");
    defer deinit(a, &node);
    const np = try buildPlan(a, &node);
    defer {
        for (np) |*st| st.deinit(a);
        a.free(np);
    }
    try std.testing.expect(np[3].command.len > 0);
}

test "verifySha256 rejects mismatched checksums" {
    try verifySha256("abc123", "abc123");
    try std.testing.expectError(error.ChecksumMismatch, verifySha256("abc123", "abc124"));
    try std.testing.expectError(error.ChecksumMissing, verifySha256("", "abc"));
}

test "Debian/Ubuntu adapter data, arch/libc guards, and frozen commit" {
    try std.testing.expectEqual(OsAdapter.debian, osAdapter("ID=debian\nVERSION=12"));
    try std.testing.expectEqual(OsAdapter.ubuntu, osAdapter("ID=ubuntu\nVERSION=22.04"));
    try std.testing.expectEqual(OsAdapter.unknown, osAdapter("ID=alpine"));
    try std.testing.expect(isSupportedArch("x64"));
    try std.testing.expect(isSupportedArch("arm64"));
    try std.testing.expect(!isSupportedArch("mips"));
    try std.testing.expect(isGlibc("glibc"));
    try std.testing.expect(!isGlibc("musl"));
    const commits = [_]FrozenCommit{ .{ .branch = "main", .sha = "abc" }, .{ .branch = "dev", .sha = "def" } };
    try std.testing.expectEqualStrings("abc", frozenCommitForBranch("main", &commits).?);
    try std.testing.expect(frozenCommitForBranch("missing", &commits) == null);
}

test "cancel wrapper and cancel command are safe and bound to token" {
    const allocator = testing.allocator;
    const tok = try cancelToken(allocator, std.testing.io);
    defer allocator.free(tok);
    const ctrl = try controlFilePath(allocator, tok);
    defer allocator.free(ctrl);
    try testing.expect(std.mem.indexOf(u8, ctrl, tok) != null);
    const wrapped = try wrapWithProcessGroup(allocator, "git clone https://example.com/x.git", tok, ctrl);
    defer allocator.free(wrapped);
    try testing.expect(std.mem.indexOf(u8, wrapped, "setsid") != null);
    try testing.expect(std.mem.indexOf(u8, wrapped, ": | setsid") != null);
    const cmd = try cancelCommand(allocator, ctrl, tok);
    defer allocator.free(cmd);
    try testing.expect(std.mem.indexOf(u8, cmd, "kill -TERM") != null);
    try testing.expect(std.mem.indexOf(u8, cmd, "kill -KILL") != null);
    try testing.expect(std.mem.indexOf(u8, cmd, "kill -0") != null);
}
test "run capture masks output and truncates at the history cap" {
    const allocator = testing.allocator;
    var app = try testApp(allocator, "a4");
    defer deinit(allocator, &app);
    const plan = try buildPlan(allocator, &app);
    defer {
        for (plan) |*s| s.deinit(allocator);
        allocator.free(plan);
    }
    const secrets = [_]SecretValue{.{ .name = "DATABASE_URL", .value = "postgres://secret" }};
    var runs = Runs{ .allocator = allocator };
    defer runs.deinit();
    const id = try runs.start("s1", &app, plan, &secrets, "deploy", "abc123", "v22.17.1", "/home/deploy/.local/share/oars/node/v22.17.1/bin/node", std.testing.io, 1);
    const run = runs.get(id).?;
    try testing.expectEqualStrings("deploy", run.action);
    try testing.expectEqualStrings("abc123", run.commit);
    const data = "connecting to postgres://secret now";
    run.captureOutput(allocator, &run.steps.items[0], data, 0, data.len, true);
    try testing.expect(std.mem.indexOf(u8, run.output.items, "postgres://secret") == null);
    try testing.expect(std.mem.indexOf(u8, run.output.items, "connecting to *** now") != null);
    try testing.expect(std.mem.indexOf(u8, run.steps.items[0].output_chunks.items[0].data, "postgres://secret") == null);
}

test "run capture masks a secret split across SSH poll deltas" {
    const allocator = testing.allocator;
    var app = try testApp(allocator, "a5");
    defer deinit(allocator, &app);
    const plan = try buildPlan(allocator, &app);
    defer {
        for (plan) |*s| s.deinit(allocator);
        allocator.free(plan);
    }
    const secrets = [_]SecretValue{.{ .name = "TOKEN", .value = "split-secret" }};
    var runs = Runs{ .allocator = allocator };
    defer runs.deinit();
    const id = try runs.start("s1", &app, plan, &secrets, "deploy", "abc123", "v22.17.1", "/node", std.testing.io, 1);
    const run = runs.get(id).?;
    const first = "before split-";
    run.captureOutput(allocator, &run.steps.items[0], first, 0, first.len, false);
    try testing.expect(std.mem.indexOf(u8, run.output.items, "split-") == null);
    const second = "secret after";
    run.captureOutput(allocator, &run.steps.items[0], second, first.len, first.len + second.len, true);
    try testing.expectEqualStrings("before *** after", run.output.items);
    try testing.expect(std.mem.indexOf(u8, run.output.items, "split-secret") == null);
}

test "history store persists masked records, prunes by age, then by count" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    var paths: TestPaths = .{};
    _ = testStorePaths(&paths, "deploy-hist");
    var hist_path_buf: [520]u8 = undefined;
    const hist_path = try std.fmt.bufPrint(&hist_path_buf, "/tmp/{s}/deploy_runs.json", .{paths.dir});
    defer std.Io.Dir.cwd().deleteTree(io, paths.dir) catch {};
    var store = HistoryStore{ .allocator = allocator, .path = hist_path };

    var hist_app = try testApp(allocator, "a1");
    defer deinit(allocator, &hist_app);
    const now: i64 = 1_800_000_000_000;
    var run = Run{
        .id = 7,
        .server_id = try allocator.dupe(u8, "s1"),
        .app_id = try allocator.dupe(u8, "a1"),
        .app_name = try allocator.dupe(u8, "x"),
        .app = try clone(allocator, hist_app),
        .action = try allocator.dupe(u8, "update"),
        .commit = try allocator.dupe(u8, "abc123"),
        .status = .done,
        .started_at_ms = now - 1_000,
        .finished_at_ms = now,
    };
    defer run.deinit(allocator);
    try run.output.appendSlice(allocator, "hello");
    try run.steps.append(allocator, .{ .id = .clone, .label = try allocator.dupe(u8, "Clone repository"), .command = try allocator.dupe(u8, "git clone x") });
    run.steps.items[0].state = .success;
    store.append(io, &run, now);

    var loaded = try store.loadParsed(io);
    try testing.expectEqual(@as(usize, 1), loaded.parsed.value.len);
    try testing.expectEqualStrings("s1", loaded.parsed.value[0].server_id);
    try testing.expectEqualStrings("update", loaded.parsed.value[0].action);
    try testing.expectEqualStrings("abc123", loaded.parsed.value[0].commit);
    try testing.expectEqualStrings("hello", loaded.parsed.value[0].output);
    try testing.expectEqual(@as(usize, 1), loaded.parsed.value[0].steps.len);
    try testing.expectEqual(StepState.success, loaded.parsed.value[0].steps[0].state);
    loaded.deinit(allocator);

    // An aged-out stored record is pruned on the next append. Write the old
    // record directly so the test controls its timestamp exactly.
    {
        var old_run = Run{
            .id = 1,
            .server_id = try allocator.dupe(u8, "s1"),
            .app_id = try allocator.dupe(u8, "a1"),
            .app_name = try allocator.dupe(u8, "x"),
            .app = try clone(allocator, hist_app),
            .action = try allocator.dupe(u8, "deploy"),
            .commit = try allocator.dupe(u8, ""),
            .status = .done,
            .started_at_ms = now - history_retention_ms - 1,
            .finished_at_ms = now - history_retention_ms,
        };
        defer old_run.deinit(allocator);
        store.append(io, &old_run, now - history_retention_ms - 1);
        // The old record is in the store (it was current when written).
        var check = try store.loadParsed(io);
        try testing.expectEqual(@as(usize, 2), check.parsed.value.len);
        check.deinit(allocator);
        // A fresh append at `now` prunes the aged record first.
        var newer = Run{
            .id = 8,
            .server_id = try allocator.dupe(u8, "s1"),
            .app_id = try allocator.dupe(u8, "a1"),
            .app_name = try allocator.dupe(u8, "x"),
            .app = try clone(allocator, hist_app),
            .action = try allocator.dupe(u8, "deploy"),
            .commit = try allocator.dupe(u8, ""),
            .status = .done,
            .started_at_ms = now - 500,
            .finished_at_ms = now,
        };
        defer newer.deinit(allocator);
        store.append(io, &newer, now);
        var after = try store.loadParsed(io);
        defer after.deinit(allocator);
        try testing.expectEqual(@as(usize, 2), after.parsed.value.len);
        for (after.parsed.value) |rec| {
            try testing.expect(rec.started_at_ms >= now - history_retention_ms);
        }
    }
}
