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

pub const supported_node_versions = [_][]const u8{ "22", "24" };
pub const max_env_vars: usize = 128;
pub const max_env_value_bytes: usize = 64 * 1024;
pub const max_domains: usize = 16;
pub const max_commands_bytes: usize = 4096;
pub const max_app_name_len: usize = 100;
pub const max_history_runs: usize = 200;
pub const history_list_limit: usize = 10;
/// Output kept per run in the history store (spec 07 §7).
pub const history_output_cap: usize = 200 * 1024;

pub const Transport = enum(u8) {
    https,
    ssh,
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
    node_version: []const u8 = "22",
    type: AppType = .node,
    install: []const u8 = "",
    build: []const u8 = "",
    start: []const u8 = "",
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
    created_at: i64 = 0,
    updated_at: i64 = 0,
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
    node_version: []const u8 = "22",
    type: []const u8 = "node",
    install: []const u8 = "",
    build: []const u8 = "",
    start: []const u8 = "",
    build_folder: []const u8 = "",
};

pub const SaveError = error{
    MissingId,
    MissingServer,
    MissingName,
    InvalidName,
    MissingFolder,
    InvalidFolder,
    InvalidRepo,
    InvalidTransport,
    InvalidBranch,
    InvalidNodeVersion,
    InvalidAppType,
    InvalidCommand,
    InvalidEnvVar,
    DuplicateEnvVar,
    TooManyEnvVars,
    InvalidDomain,
    TooManyDomains,
    EmailRequired,
    InvalidEmail,
    InvalidPort,
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

pub fn validate(input: AppInput) SaveError!void {
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
        .https => std.mem.startsWith(u8, url, "https://") or std.mem.startsWith(u8, url, "http://"),
        .ssh => std.mem.startsWith(u8, url, "git@") or std.mem.startsWith(u8, url, "ssh://"),
        .file => std.mem.startsWith(u8, url, "file://"),
    };
    if (!ok_url) return error.InvalidRepo;
    const branch = std.mem.trim(u8, input.repo.branch, " \t\r\n");
    if (branch.len == 0 or branch.len > 200 or hasControlChars(branch)) return error.InvalidBranch;
    var node_ok = false;
    for (supported_node_versions) |v| {
        if (std.mem.eql(u8, input.runtime.node_version, v)) node_ok = true;
    }
    if (!node_ok) return error.InvalidNodeVersion;
    if (AppType.fromJsonName(input.runtime.type) == null) return error.InvalidAppType;
    const commands = [_][]const u8{ input.runtime.install, input.runtime.build, input.runtime.start };
    for (commands) |cmd| {
        if (cmd.len > max_commands_bytes or hasControlChars(cmd)) return error.InvalidCommand;
    }
    if (input.runtime.build_folder.len > 512 or hasControlChars(input.runtime.build_folder)) return error.InvalidCommand;
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
    for (input.domains) |d| {
        if (!validDomain(d)) return error.InvalidDomain;
    }
    if (input.ssl) {
        const email = std.mem.trim(u8, input.email, " \t\r\n");
        if (email.len == 0) return error.EmailRequired;
        if (email.len > 254 or std.mem.indexOfScalar(u8, email, '@') == null) return error.InvalidEmail;
    }
    if (input.app_port == 0) return error.InvalidPort;
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
            .install = try allocator.dupe(u8, src.runtime.install),
            .build = try allocator.dupe(u8, src.runtime.build),
            .start = try allocator.dupe(u8, src.runtime.start),
            .build_folder = try allocator.dupe(u8, src.runtime.build_folder),
        },
        .domains = &.{},
        .email = try allocator.dupe(u8, src.email),
        .ssl = src.ssl,
        .app_port = src.app_port,
        .created_at = src.created_at,
        .updated_at = src.updated_at,
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
    allocator.free(app.runtime.start);
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
/// mutation; corrupt files are quarantined (mirrors the servers store).
pub const AppStore = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
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

    fn saveLocked(self: *AppStore, io: std.Io, apps: []const App) !void {
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(self.path)) |dir| try cwd.createDirPath(io, dir);
        self.tightenPermissions(io);
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        std.json.Stringify.value(apps, .{ .whitespace = .indent_2 }, &out.writer) catch return error.SerializeFailed;
        var file = try cwd.createFile(io, self.path, .{});
        defer file.close(io);
        if (file.stat(io)) |stat| {
            if (stat.permissions.toMode() & 0o077 != 0) file.setPermissions(io, .fromMode(0o600)) catch {};
        } else |_| {}
        try file.writeStreamingAll(io, out.writer.buffered());
        try file.sync(io);
    }

    fn tightenPermissions(self: *AppStore, io: std.Io) void {
        const cwd = std.Io.Dir.cwd();
        var file = cwd.openFile(io, self.path, .{ .mode = .read_write }) catch return;
        defer file.close(io);
        const stat = file.stat(io) catch return;
        if (stat.permissions.toMode() & 0o077 != 0) file.setPermissions(io, .fromMode(0o600)) catch {};
    }

    /// Upserts an app by id; edits preserve created_at. Secret env rows
    /// never store a value (spec 07 §5). Returns an owned copy.
    pub fn saveApp(self: *AppStore, io: std.Io, input: AppInput, now_ns: i128) SaveError!App {
        try validate(input);
        const id = input.id orelse return error.MissingId;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);

        var existing: ?App = null;
        defer {
            if (existing) |*e| deinit(self.allocator, e);
        }
        var is_edit = false;
        for (loaded.parsed.value) |a| {
            if (std.mem.eql(u8, a.id, id)) {
                existing = try clone(self.allocator, a);
                is_edit = true;
                break;
            }
        }

        var saved: App = undefined;
        errdefer deinit(self.allocator, &saved);
        if (existing) |e| {
            saved = try clone(self.allocator, e);
            self.allocator.free(saved.name);
            saved.name = try self.allocator.dupe(u8, std.mem.trim(u8, input.name, " \t\r\n"));
            self.allocator.free(saved.folder);
            saved.folder = try self.allocator.dupe(u8, std.mem.trim(u8, input.folder, " \t\r\n"));
            self.allocator.free(saved.repo.url);
            saved.repo.url = try self.allocator.dupe(u8, std.mem.trim(u8, input.repo.url, " \t\r\n"));
            saved.repo.transport = Transport.fromJsonName(input.repo.transport).?;
            self.allocator.free(saved.repo.branch);
            saved.repo.branch = try self.allocator.dupe(u8, std.mem.trim(u8, input.repo.branch, " \t\r\n"));
            self.allocator.free(saved.runtime.node_version);
            saved.runtime.node_version = try self.allocator.dupe(u8, input.runtime.node_version);
            saved.runtime.type = AppType.fromJsonName(input.runtime.type).?;
            self.allocator.free(saved.runtime.install);
            saved.runtime.install = try self.allocator.dupe(u8, input.runtime.install);
            self.allocator.free(saved.runtime.build);
            saved.runtime.build = try self.allocator.dupe(u8, input.runtime.build);
            self.allocator.free(saved.runtime.start);
            saved.runtime.start = try self.allocator.dupe(u8, input.runtime.start);
            self.allocator.free(saved.runtime.build_folder);
            saved.runtime.build_folder = try self.allocator.dupe(u8, input.runtime.build_folder);
            saved.environment = Environment.fromJsonName(input.environment) orelse .production;
            for (saved.env_vars) |v| {
                self.allocator.free(v.name);
                self.allocator.free(v.value);
            }
            self.allocator.free(saved.env_vars);
            saved.env_vars = try dupEnvVars(self.allocator, input.env_vars);
            for (saved.domains) |d| self.allocator.free(d);
            self.allocator.free(saved.domains);
            saved.domains = try dupDomains(self.allocator, input.domains);
            self.allocator.free(saved.email);
            saved.email = try self.allocator.dupe(u8, std.mem.trim(u8, input.email, " \t\r\n"));
            saved.ssl = input.ssl;
            saved.app_port = input.app_port;
            saved.updated_at = @intCast(now_ns);
        } else {
            saved = .{
                .id = try self.allocator.dupe(u8, id),
                .server_id = try self.allocator.dupe(u8, input.server_id),
                .name = try self.allocator.dupe(u8, std.mem.trim(u8, input.name, " \t\r\n")),
                .environment = Environment.fromJsonName(input.environment) orelse .production,
                .folder = try self.allocator.dupe(u8, std.mem.trim(u8, input.folder, " \t\r\n")),
                .repo = .{
                    .url = try self.allocator.dupe(u8, std.mem.trim(u8, input.repo.url, " \t\r\n")),
                    .transport = Transport.fromJsonName(input.repo.transport).?,
                    .branch = try self.allocator.dupe(u8, std.mem.trim(u8, input.repo.branch, " \t\r\n")),
                },
                .runtime = .{
                    .node_version = try self.allocator.dupe(u8, input.runtime.node_version),
                    .type = AppType.fromJsonName(input.runtime.type).?,
                    .install = try self.allocator.dupe(u8, input.runtime.install),
                    .build = try self.allocator.dupe(u8, input.runtime.build),
                    .start = try self.allocator.dupe(u8, input.runtime.start),
                    .build_folder = try self.allocator.dupe(u8, input.runtime.build_folder),
                },
                .email = try self.allocator.dupe(u8, std.mem.trim(u8, input.email, " \t\r\n")),
                .ssl = input.ssl,
                .app_port = input.app_port,
                .created_at = @intCast(now_ns),
                .updated_at = @intCast(now_ns),
            };
            errdefer deinit(self.allocator, &saved);
            if (input.server_id.len == 0) return error.MissingServer;
            saved.env_vars = try dupEnvVars(self.allocator, input.env_vars);
            saved.domains = try dupDomains(self.allocator, input.domains);
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

    // 2. install — lockfile-specific frozen command; the chosen command's
    // failure fails the step (no silent `|| npm install` fallback).
    if (app.runtime.install.len > 0) {
        var cmd: std.ArrayList(u8) = .empty;
        defer cmd.deinit(allocator);
        try appendCmd(&cmd, allocator, "cd ");
        try appendQuoted(&cmd, allocator, app.folder);
        try appendCmd(&cmd, allocator, " && if [ -f pnpm-lock.yaml ]; then ");
        try appendCmd(&cmd, allocator, app.runtime.install);
        try appendCmd(&cmd, allocator, "; elif [ -f yarn.lock ]; then ");
        try appendCmd(&cmd, allocator, app.runtime.install);
        try appendCmd(&cmd, allocator, "; elif [ -f package-lock.json ]; then ");
        try appendCmd(&cmd, allocator, app.runtime.install);
        try appendCmd(&cmd, allocator, "; else ");
        try appendCmd(&cmd, allocator, app.runtime.install);
        try appendCmd(&cmd, allocator, "; fi");
        try addStep(&steps, allocator, .install, cmd.items);
    } else {
        try addStep(&steps, allocator, .install, "");
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
    if (app.runtime.start.len > 0) {
        const eco_path = try pm2EcosystemPath(allocator, app.folder);
        defer allocator.free(eco_path);
        var cmd: std.ArrayList(u8) = .empty;
        defer cmd.deinit(allocator);
        try appendCmd(&cmd, allocator, "pm2 startOrReload ");
        try appendQuoted(&cmd, allocator, eco_path);
        try appendCmd(&cmd, allocator, " --only ");
        try appendQuoted(&cmd, allocator, app.name);
        try addStep(&steps, allocator, .pm2, cmd.items);
    } else {
        try addStep(&steps, allocator, .pm2, "");
    }

    // 5. nginx — the handler writes the site config before the step.
    {
        const avail = try nginxAvailablePath(allocator, app.id);
        defer allocator.free(avail);
        const enabled = try nginxEnabledPath(allocator, app.id);
        defer allocator.free(enabled);
        var cmd: std.ArrayList(u8) = .empty;
        defer cmd.deinit(allocator);
        try appendCmd(&cmd, allocator, "mkdir -p ");
        try appendQuoted(&cmd, allocator, nginxAvailableDir());
        try appendCmd(&cmd, allocator, " ");
        try appendQuoted(&cmd, allocator, nginxEnabledDir());
        try appendCmd(&cmd, allocator, " && nginx -t && ln -sfn ");
        try appendQuoted(&cmd, allocator, avail);
        try appendCmd(&cmd, allocator, " ");
        try appendQuoted(&cmd, allocator, enabled);
        try appendCmd(&cmd, allocator, " && nginx -s reload");
        try addStep(&steps, allocator, .nginx, cmd.items);
    }

    // 6. certbot — only when SSL is on; DNS pre-check first (spec 07 §6:
    // fail early before a doomed http-01; certbot remains final authority).
    if (app.ssl and app.domains.len > 0) {
        var cmd: std.ArrayList(u8) = .empty;
        defer cmd.deinit(allocator);
        try appendCmd(&cmd, allocator, "command -v dig >/dev/null || { echo 'dig is required for the DNS pre-check'; exit 1; }; for d in");
        for (app.domains) |d| try appendQuoted(&cmd, allocator, d);
        try appendCmd(&cmd, allocator, "; do dig +short A \"$d\" | grep -q . || dig +short AAAA \"$d\" | grep -q . || { echo \"no DNS record for $d\"; exit 1; }; done; certbot --nginx");
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

/// The `.env` location: `<folder>/.env` (spec 07 §6).
pub fn envFilePath(allocator: std.mem.Allocator, folder: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/.env", .{folder});
}

/// The nginx site config content for an app (spec 07 §13: proxy_pass to
/// the local app port; `_` server_name when no domains).
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
    return std.fmt.allocPrint(allocator,
        \\server {{
        \\    listen 80;
        \\    server_name {s};
        \\    location / {{
        \\        proxy_pass http://127.0.0.1:{d};
        \\        proxy_set_header Host $host;
        \\        proxy_set_header X-Real-IP $remote_addr;
        \\        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        \\        proxy_set_header X-Forwarded-Proto $scheme;
        \\    }}
        \\}}
        \\
    , .{ server_names.items, app.app_port });
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

/// The PM2 ecosystem file content (spec 07 §6: explicit cwd, script, args,
/// environment, and app name). The start command is split on whitespace:
/// the first token is the script, the rest are args (user-authored).
pub fn ecosystemFile(allocator: std.mem.Allocator, app: *const App, values: []const SecretValue) ![]u8 {
    var script: []const u8 = app.runtime.start;
    var args: []const u8 = "";
    var split = std.mem.splitScalar(u8, std.mem.trim(u8, app.runtime.start, " \t\r\n"), ' ');
    if (split.next()) |first| {
        script = first;
        args = split.rest();
    }
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"apps\":[{\"name\":");
    try writeJsonString(&out, allocator, app.name);
    try out.appendSlice(allocator, ",\"cwd\":");
    try writeJsonString(&out, allocator, app.folder);
    try out.appendSlice(allocator, ",\"script\":");
    try writeJsonString(&out, allocator, script);
    try out.appendSlice(allocator, ",\"args\":");
    try writeJsonString(&out, allocator, args);
    try out.appendSlice(allocator, ",\"env\":{");
    for (app.env_vars, 0..) |v, i| {
        const value = if (v.secret) blk: {
            const found = findSecret(values, v.name) orelse continue;
            break :blk found.value;
        } else v.value;
        if (i > 0) try out.append(allocator, ',');
        try writeJsonString(&out, allocator, v.name);
        try out.append(allocator, ':');
        try writeJsonString(&out, allocator, value);
    }
    try out.appendSlice(allocator, "}}]}");
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
                    buf[0] = hex[(ch >> 4) & 0xf];
                    buf[1] = hex[ch & 0xf];
                    buf[2] = '0';
                    buf[3] = '0';
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

pub const StepState = enum(u8) {
    pending,
    running,
    success,
    failed,
    canceled,

    pub fn jsonName(self: StepState) []const u8 {
        return @tagName(self);
    }
};

pub const RunStatus = enum(u8) {
    queued,
    running,
    done,
    failed,
    canceled,
    interrupted,

    pub fn jsonName(self: RunStatus) []const u8 {
        return @tagName(self);
    }
};

pub const Step = struct {
    id: StepId,
    label: []const u8,
    /// Owned; empty = skipped.
    command: []u8,
    state: StepState = .pending,
    channel: ?u32 = null,
    exit: ?i32 = null,
    /// Static error text only (mirrors the transfer registries).
    @"error": []const u8 = "",

    pub fn deinit(self: *Step, allocator: std.mem.Allocator) void {
        allocator.free(self.command);
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
    canceled: bool = false,
    status: RunStatus = .queued,
    started_at: i64 = 0,
    finished_at: ?i64 = null,
    /// Secret values for the `.env`/ecosystem writes and output masking.
    secrets: std.ArrayList(SecretValue) = .empty,
    /// Masked output accumulated for history (bounded; per-step cursor).
    output: std.ArrayList(u8) = .empty,
    output_cursor: u64 = 0,
    output_truncated: bool = false,

    pub fn deinit(self: *Run, allocator: std.mem.Allocator) void {
        allocator.free(self.server_id);
        allocator.free(self.app_id);
        allocator.free(self.app_name);
        // `deinit` would resolve to this method; use the app-free alias.
        appDeinit(allocator, &self.app);
        for (self.steps.items) |*s| s.deinit(allocator);
        self.steps.deinit(allocator);
        for (self.secrets.items) |*s| {
            allocator.free(s.name);
            allocator.free(s.value);
        }
        self.secrets.deinit(allocator);
        self.output.deinit(allocator);
    }

    pub fn currentStep(self: *Run) ?*Step {
        if (self.step_index >= self.steps.items.len) return null;
        return &self.steps.items[self.step_index];
    }

    /// Appends masked step data to the history output (bounded).
    pub fn captureOutput(self: *Run, allocator: std.mem.Allocator, data: []const u8) void {
        if (self.output_truncated) return;
        const masked = maskSecrets(allocator, data, self.secrets.items) catch return;
        defer allocator.free(masked);
        const room = history_output_cap -| self.output.items.len;
        if (masked.len >= room) {
            self.output.appendSlice(allocator, masked[0..room]) catch {};
            self.output_truncated = true;
        } else {
            self.output.appendSlice(allocator, masked) catch {};
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
    /// (all duplicated). Returns the run id.
    pub fn start(
        self: *Runs,
        server_id: []const u8,
        app: *const App,
        plan: []const PlanStep,
        secret_values: []const SecretValue,
        now_ns: i64,
    ) !u32 {
        var run = Run{
            .id = self.next_id,
            .server_id = try self.allocator.dupe(u8, server_id),
            .app_id = try self.allocator.dupe(u8, app.id),
            .app_name = try self.allocator.dupe(u8, app.name),
            .app = try clone(self.allocator, app.*),
            .started_at = now_ns,
        };
        errdefer run.deinit(self.allocator);
        self.next_id +%= 1;
        for (plan) |*ps| {
            try run.steps.append(self.allocator, .{
                .id = ps.id,
                .label = ps.label,
                .command = try self.allocator.dupe(u8, ps.command),
            });
        }
        for (secret_values) |*s| {
            try run.secrets.append(self.allocator, .{
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
    started_at: i64,
    finished_at: ?i64 = null,
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

    /// Appends a record for `run`, trimming output to the history cap, and
    /// prunes beyond `max_history_runs` (oldest first).
    pub fn append(self: *HistoryStore, io: std.Io, run: *const Run) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return;
        defer loaded.deinit(self.allocator);
        var list: std.ArrayList(HistoryRecord) = .empty;
        defer {
            for (list.items) |*r| {
                self.allocator.free(r.server_id);
                self.allocator.free(r.app_id);
                for (r.steps) |*s| {
                    self.allocator.free(s.@"error");
                }
                self.allocator.free(r.steps);
                self.allocator.free(r.output);
            }
            list.deinit(self.allocator);
        }
        // The parsed records reference the file buffer; duplicate the ones
        // we keep (the newest `max_history_runs - 1` plus the new record).
        const keep_from = loaded.parsed.value.len -| (max_history_runs - 1);
        for (loaded.parsed.value[keep_from..]) |rec| {
            list.append(self.allocator, dupRecord(self.allocator, rec) catch return) catch return;
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
        const output = self.allocator.dupe(u8, run.output.items) catch return;
        errdefer self.allocator.free(output);
        list.append(self.allocator, .{
            .id = run.id,
            .server_id = server_id,
            .app_id = app_id,
            .status = run.status,
            .started_at = run.started_at,
            .finished_at = run.finished_at,
            .steps = steps,
            .output = output,
            .truncated = run.output_truncated,
        }) catch return;
        self.saveLocked(io, list.items) catch {};
    }

    fn dupRecord(allocator: std.mem.Allocator, rec: HistoryRecord) !HistoryRecord {
        var out = HistoryRecord{
            .id = rec.id,
            .server_id = try allocator.dupe(u8, rec.server_id),
            .app_id = try allocator.dupe(u8, rec.app_id),
            .status = rec.status,
            .started_at = rec.started_at,
            .finished_at = rec.finished_at,
            .output = try allocator.dupe(u8, rec.output),
            .truncated = rec.truncated,
        };
        errdefer {
            allocator.free(out.server_id);
            allocator.free(out.app_id);
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

    fn saveLocked(self: *HistoryStore, io: std.Io, records: []const HistoryRecord) !void {
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(self.path)) |dir| try cwd.createDirPath(io, dir);
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        std.json.Stringify.value(records, .{ .whitespace = .indent_2 }, &out.writer) catch return error.SerializeFailed;
        var file = try cwd.createFile(io, self.path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, out.writer.buffered());
        try file.sync(io);
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
            .install = "npm ci",
            .build = "npm run build",
            .start = "npm start",
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
        .created_at = 1,
        .updated_at = 1,
    });
}

test "apps store round trip preserves secret flags and never stores values" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [128]u8 = undefined;
    const dir_name = try std.fmt.bufPrint(&dir_buf, "oars-apps-test-{d}", .{now});
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/{s}/apps.json", .{dir_name});
    defer std.Io.Dir.cwd().deleteTree(io, dir_name) catch {};
    var store = AppStore{ .allocator = allocator, .path = path };

    var created = try store.saveApp(io, .{
        .id = "a1",
        .server_id = "s1",
        .name = "storefront",
        .folder = "/home/ubuntu/storefront",
        .repo = .{ .url = "git@github.com:you/storefront.git", .transport = "ssh", .branch = "main" },
        .runtime = .{ .node_version = "22", .type = "next", .install = "npm ci", .build = "npm run build", .start = "npm start" },
        .env_vars = &.{
            .{ .name = "NODE_ENV", .secret = false, .value = "production" },
            .{ .name = "DATABASE_URL", .secret = true, .has_value = true },
        },
        .domains = &.{"storefront.dev"},
        .ssl = true,
        .email = "ops@storefront.dev",
        .app_port = 3000,
    }, now);
    defer deinit(allocator, &created);
    try testing.expectEqualStrings("storefront", created.name);
    try testing.expectEqual(@as(usize, 2), created.env_vars.len);
    try testing.expect(created.env_vars[1].secret);
    try testing.expect(created.env_vars[1].has_value);
    try testing.expectEqualStrings("", created.env_vars[1].value); // never stored

    // The secret value sent at save time must NOT persist either.
    var loaded = try store.loadParsed(io);
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), loaded.parsed.value.len);
    try testing.expectEqualStrings("", loaded.parsed.value[0].env_vars[1].value);
    try testing.expect(std.mem.indexOf(u8, loaded.content.?, "postgres://secret") == null);

    var found = (try store.find(io, "a1")) orelse return error.TestUnexpectedResult;
    defer deinit(allocator, &found);
    try testing.expectEqual(@as(u16, 3000), found.app_port);

    try testing.expect(try store.delete(io, "a1"));
    try testing.expect((try store.find(io, "a1")) == null);
}

test "app validation rejects bad transports, folders, vars, domains, and versions" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [128]u8 = undefined;
    const dir_name = try std.fmt.bufPrint(&dir_buf, "oars-apps-valid-{d}", .{now});
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/{s}/apps.json", .{dir_name});
    defer std.Io.Dir.cwd().deleteTree(io, dir_name) catch {};
    var store = AppStore{ .allocator = allocator, .path = path };

    const base = AppInput{
        .id = "a",
        .server_id = "s1",
        .name = "x",
        .folder = "/srv/x",
        .repo = .{ .url = "git@github.com:you/x.git", .transport = "ssh" },
        .runtime = .{ .node_version = "22", .type = "node" },
    };
    try testing.expectError(error.MissingName, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = " ", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node" } }, now));
    try testing.expectError(error.InvalidFolder, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "relative", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node" } }, now));
    try testing.expectError(error.InvalidFolder, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x/", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node" } }, now));
    try testing.expectError(error.InvalidTransport, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ftp" }, .runtime = .{ .node_version = "22", .type = "node" } }, now));
    try testing.expectError(error.InvalidRepo, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "rm -rf /", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node" } }, now));
    try testing.expectError(error.InvalidNodeVersion, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "18", .type = "node" } }, now));
    try testing.expectError(error.InvalidEnvVar, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node" }, .env_vars = &.{.{ .name = "BAD NAME", .secret = false, .value = "v" }} }, now));
    try testing.expectError(error.InvalidEnvVar, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node" }, .env_vars = &.{.{ .name = "A", .secret = false, .value = "a\nb" }} }, now));
    try testing.expectError(error.InvalidDomain, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node" }, .domains = &.{"-bad.example"} }, now));
    try testing.expectError(error.EmailRequired, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node" }, .domains = &.{"storefront.dev"}, .ssl = true, .email = "" }, now));
    try testing.expectError(error.InvalidPort, store.saveApp(io, .{ .id = "a", .server_id = "s1", .name = "x", .folder = "/srv/x", .repo = .{ .url = "git@h:y.git", .transport = "ssh" }, .runtime = .{ .node_version = "22", .type = "node" }, .app_port = 0 }, now));
    _ = base;
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
    // Lockfile chain with no silent fallback.
    try testing.expect(std.mem.indexOf(u8, plan[1].command, "if [ -f pnpm-lock.yaml ]; then") != null);
    try testing.expect(std.mem.indexOf(u8, plan[1].command, "elif [ -f package-lock.json ]; then") != null);
    try testing.expect(std.mem.indexOf(u8, plan[1].command, "|| npm install") == null);
    // NODE_OPTIONS heap hint for node-family builds.
    try testing.expect(std.mem.indexOf(u8, plan[2].command, "NODE_OPTIONS=--max-old-space-size=4096 npm run build") != null);
    // pm2 scoped to the app.
    try testing.expect(std.mem.indexOf(u8, plan[3].command, "pm2 startOrReload '/home/ubuntu/storefront/.oars-pm2.json' --only 'storefront'") != null);
    // nginx test + symlink + reload.
    try testing.expect(std.mem.indexOf(u8, plan[4].command, "nginx -t") != null);
    try testing.expect(std.mem.indexOf(u8, plan[4].command, "ln -sfn '/etc/nginx/sites-available/a1' '/etc/nginx/sites-enabled/a1'") != null);
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

test "nginx config and ecosystem files are well-formed" {
    const allocator = testing.allocator;
    var app = try testApp(allocator, "a3");
    defer deinit(allocator, &app);

    const config = try nginxConfig(allocator, &app);
    defer allocator.free(config);
    try testing.expect(std.mem.indexOf(u8, config, "server_name storefront.dev;") != null);
    try testing.expect(std.mem.indexOf(u8, config, "proxy_pass http://127.0.0.1:3000;") != null);

    const secrets = [_]SecretValue{.{ .name = "DATABASE_URL", .value = "postgres://secret" }};
    const eco = try ecosystemFile(allocator, &app, &secrets);
    defer allocator.free(eco);
    try testing.expect(std.mem.indexOf(u8, eco, "\"script\":\"npm\"") != null);
    try testing.expect(std.mem.indexOf(u8, eco, "\"args\":\"start\"") != null);
    try testing.expect(std.mem.indexOf(u8, eco, "postgres://secret") != null); // on the server file, yes
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, eco, .{});
    defer parsed.deinit();
    try testing.expect(parsed.value != .null);

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
    const id = try runs.start("s1", &app, plan, &secrets, 1);
    const run = runs.get(id).?;
    run.captureOutput(allocator, "connecting to postgres://secret now");
    try testing.expect(std.mem.indexOf(u8, run.output.items, "postgres://secret") == null);
    try testing.expect(std.mem.indexOf(u8, run.output.items, "connecting to *** now") != null);
}

test "history store persists masked records and prunes the cap" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [128]u8 = undefined;
    const dir_name = try std.fmt.bufPrint(&dir_buf, "oars-deploy-hist-{d}", .{now});
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/{s}/deploy_runs.json", .{dir_name});
    defer std.Io.Dir.cwd().deleteTree(io, dir_name) catch {};
    var store = HistoryStore{ .allocator = allocator, .path = path };

    var hist_app = try testApp(allocator, "a1");
    defer deinit(allocator, &hist_app);
    var run = Run{
        .id = 7,
        .server_id = try allocator.dupe(u8, "s1"),
        .app_id = try allocator.dupe(u8, "a1"),
        .app_name = try allocator.dupe(u8, "x"),
        .app = try clone(allocator, hist_app),
        .status = .done,
        .started_at = 1,
        .finished_at = 2,
    };
    defer run.deinit(allocator);
    try run.output.appendSlice(allocator, "hello");
    try run.steps.append(allocator, .{ .id = .clone, .label = "Clone repository", .command = try allocator.dupe(u8, "git clone x") });
    run.steps.items[0].state = .success;
    store.append(io, &run);

    var loaded = try store.loadParsed(io);
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), loaded.parsed.value.len);
    try testing.expectEqualStrings("s1", loaded.parsed.value[0].server_id);
    try testing.expectEqualStrings("hello", loaded.parsed.value[0].output);
    try testing.expectEqual(@as(usize, 1), loaded.parsed.value[0].steps.len);
    try testing.expectEqual(StepState.success, loaded.parsed.value[0].steps[0].state);
}
