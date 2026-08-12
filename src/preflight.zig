//! Spec 07 preflight: the read-only preparation phase (NEXT-SPEC "Preflight
//! engine"). A preflight gathers remote facts through fixed-string,
//! read-only probe commands driven by the session worker, derives blockers,
//! warnings, required approvals, and the exact frozen mutation plan, and
//! freezes everything behind an expiring, memory-only token. The deploy run
//! commits this plan verbatim — it never replans from live state.
//!
//! This module is pure logic plus probe-command templates: no libssh2, no
//! network. The bridge drives the probes through the session worker's exec
//! path; nothing here blocks the bridge main thread.

const std = @import("std");
const deploy = @import("deploy.zig");
const shellquote = @import("shellquote.zig");

pub const preflight_ttl_ms: i64 = 10 * 60 * 1000;
pub const max_probe_output: usize = 64 * 1024;
pub const probe_timeout_ns: i128 = 45 * std.time.ns_per_s;

// --- facts -----------------------------------------------------------------

pub const Privilege = enum(u8) {
    root,
    sudo,
    none,
    unknown,

    pub fn jsonName(self: Privilege) []const u8 {
        return @tagName(self);
    }
};

pub const ToolState = struct {
    path: []const u8 = "",
    version: []const u8 = "",
};

pub const Tools = struct {
    git: ToolState = .{},
    curl: ToolState = .{},
    wget: ToolState = .{},
    tar: ToolState = .{},
    xz: ToolState = .{},
    sha256sum: ToolState = .{},
    readlink: ToolState = .{},
    ss: ToolState = .{},
    node: ToolState = .{},
    npm: ToolState = .{},
    corepack: ToolState = .{},
    pm2: ToolState = .{},
    nginx: ToolState = .{},
    certbot: ToolState = .{},
    dig: ToolState = .{},
};

pub const RepoFacts = struct {
    folder_exists: bool = false,
    is_git: bool = false,
    origin: []const u8 = "",
    branch: []const u8 = "",
    dirty_files: []const u8 = "",
    head: []const u8 = "",
    /// Exact commit the remote branch resolves to ("" when unverified).
    remote_commit: []const u8 = "",
    repo_accessible: bool = false,
    deploy_key_present: bool = false,
    known_hosts_present: bool = false,
    /// Discovery data from ssh-keyscan — not identity proof by itself.
    scanned_host_keys: []const u8 = "",
    /// SHA-256 fingerprints derived from the discovery keys. The user must
    /// compare these with a trusted source before first use.
    scanned_host_fingerprints: []const u8 = "",
    lockfiles: []const u8 = "",
    package_manager_field: []const u8 = "",
};

pub const PortFacts = struct {
    app_port_in_use: bool = false,
    port_probe_ran: bool = false,
    /// absent | ours | foreign (ownership marker decides).
    nginx_site: []const u8 = "absent",
    /// SHA-256 of the existing sites-available file, or empty when absent.
    nginx_site_sha256: []const u8 = "",
    /// absent | linked | present (a non-symlink file is always foreign).
    nginx_enabled: []const u8 = "",
    pm2_process_present: bool = false,
    /// free | nginx | foreign | unknown.
    http_listener: []const u8 = "unknown",
    https_listener: []const u8 = "unknown",
    dns: []const u8 = "",
    local_addresses: []const u8 = "",
};

pub const Facts = struct {
    os_id: []const u8 = "",
    os_version: []const u8 = "",
    os_pretty: []const u8 = "",
    arch: []const u8 = "",
    libc: []const u8 = "",
    uid: []const u8 = "",
    user: []const u8 = "",
    home: []const u8 = "",
    privilege: Privilege = .unknown,
    disk_free_kb: u64 = 0,
    tools: Tools = .{},
    repo: RepoFacts = .{},
    ports: PortFacts = .{},
    node_version: []const u8 = "",
    node_archive: []const u8 = "",
    node_sha256: []const u8 = "",
    node_url: []const u8 = "",
    node_lts: []const u8 = "",
    pm2_version: []const u8 = "",
    pm2_integrity: []const u8 = "",
};

// --- issues / approvals ------------------------------------------------------

pub const Issue = struct {
    id: []const u8,
    message: []const u8,

    pub fn deinit(self: *Issue, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.message);
    }
};

pub const Approval = struct {
    id: []const u8,
    label: []const u8,
    detail: []const u8,

    pub fn deinit(self: *Approval, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.label);
        allocator.free(self.detail);
    }
};

// --- planned steps -----------------------------------------------------------

pub const MutationClass = enum(u8) {
    files,
    packages,
    service,
    process,
    certificate,

    pub fn jsonName(self: MutationClass) []const u8 {
        return @tagName(self);
    }
};

pub const FileWrite = struct {
    path: []const u8,
    mode: u32,
    /// Redacted preview — secret values never appear here.
    preview: []const u8,

    pub fn deinit(self: *FileWrite, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.preview);
    }
};

/// One frozen plan step: the exact redacted command, the files it writes,
/// the prior-state guards the run rechecks, and the rollback description.
pub const PreflightStep = struct {
    id: []const u8,
    label: []const u8,
    class: MutationClass,
    skipped: bool = false,
    skip_reason: []const u8 = "",
    command: []const u8,
    file_writes: []FileWrite = &.{},
    guards: []const []const u8 = &.{},
    rollback: []const u8 = "",

    pub fn deinit(self: *PreflightStep, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.label);
        allocator.free(self.command);
        allocator.free(self.skip_reason);
        for (self.file_writes) |*w| w.deinit(allocator);
        allocator.free(self.file_writes);
        for (self.guards) |g| allocator.free(g);
        allocator.free(self.guards);
        allocator.free(self.rollback);
    }
};

// --- probes ------------------------------------------------------------------

pub const ProbeId = enum(u8) {
    system,
    tools,
    repo,
    ports,
    runtime,

    pub fn jsonName(self: ProbeId) []const u8 {
        return @tagName(self);
    }
};

pub const probe_count = 5;

/// The remote deploy-key directory for an app (server side, under the
/// connected user's home — never a system path).
pub fn deployKeyDir(allocator: std.mem.Allocator, app_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "$HOME/.config/oars/deploy/{s}", .{app_id});
}

/// The git host for an SSH/HTTPS repo URL ("" when unparseable).
/// `git@host:path` and `ssh://[user@]host[:port]/path` and
/// `https://host/path` are the accepted shapes (spec 07 §5).
pub fn repoHost(allocator: std.mem.Allocator, url: []const u8) ![]const u8 {
    if (std.mem.startsWith(u8, url, "git@")) {
        const rest = url[4..];
        const colon = std.mem.indexOfScalar(u8, rest, ':') orelse return allocator.dupe(u8, "");
        return allocator.dupe(u8, rest[0..colon]);
    }
    if (std.mem.indexOf(u8, url, "://")) |scheme_end| {
        var rest = url[scheme_end + 3 ..];
        if (std.mem.indexOfScalar(u8, rest, '@')) |at| rest = rest[at + 1 ..];
        var end = rest.len;
        if (std.mem.indexOfScalar(u8, rest, '/')) |slash| end = slash;
        if (std.mem.indexOfScalar(u8, rest[0..end], ':')) |colon| end = colon;
        return allocator.dupe(u8, rest[0..end]);
    }
    return allocator.dupe(u8, "");
}

pub fn repoPort(url: []const u8) ?u16 {
    if (!std.mem.startsWith(u8, url, "ssh://")) return null;
    var authority = url["ssh://".len..];
    if (std.mem.indexOfScalar(u8, authority, '/')) |slash| authority = authority[0..slash];
    if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| authority = authority[at + 1 ..];
    const colon = std.mem.lastIndexOfScalar(u8, authority, ':') orelse return null;
    if (colon + 1 >= authority.len) return null;
    return std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch null;
}

pub fn sshKeyscanTarget(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    const host = try repoHost(allocator, url);
    defer allocator.free(host);
    const q_host = try shellquote.quote(allocator, host);
    defer allocator.free(q_host);
    if (repoPort(url)) |port| return std.fmt.allocPrint(allocator, "-p {d} {s}", .{ port, q_host });
    return allocator.dupe(u8, q_host);
}

/// Builds the five managed-state-safe probe commands for an app. Every dynamic
/// value is shell-quoted. A fresh repository uses a removed-on-exit temporary
/// clone to inspect lockfiles; probes never change the app folder, packages,
/// keys, configuration, processes, or services.
pub fn buildProbes(allocator: std.mem.Allocator, app: *const deploy.App) ![probe_count][]u8 {
    var out: [probe_count][]u8 = undefined;
    var built: usize = 0;
    errdefer for (out[0..built]) |p| allocator.free(p);

    const folder = try shellquote.quote(allocator, app.folder);
    defer allocator.free(folder);
    const url = try shellquote.quote(allocator, app.repo.url);
    defer allocator.free(url);
    const branch = try shellquote.quote(allocator, app.repo.branch);
    defer allocator.free(branch);
    const key_dir = try deployKeyDir(allocator, app.id);
    defer allocator.free(key_dir);
    const q_key = try shellquote.quote(allocator, key_dir);
    defer allocator.free(q_key);
    // The key path embeds "$HOME" — quoting must not freeze it. Build the
    // shell expression as "$HOME"/.config/... with the app id quoted.
    var key_expr: std.ArrayList(u8) = .empty;
    defer key_expr.deinit(allocator);
    try key_expr.appendSlice(allocator, "\"$HOME\"/.config/oars/deploy/");
    const q_id = try shellquote.quote(allocator, app.id);
    defer allocator.free(q_id);
    try key_expr.appendSlice(allocator, q_id);
    const scan_target = try sshKeyscanTarget(allocator, app.repo.url);
    defer allocator.free(scan_target);
    const avail = try deploy.nginxAvailablePath(allocator, app.id);
    defer allocator.free(avail);
    const q_avail = try shellquote.quote(allocator, avail);
    defer allocator.free(q_avail);
    const enabled = try deploy.nginxEnabledPath(allocator, app.id);
    defer allocator.free(enabled);
    const q_enabled = try shellquote.quote(allocator, enabled);
    defer allocator.free(q_enabled);
    const proc = try deploy.pm2ProcessName(allocator, app.id);
    defer allocator.free(proc);
    const q_proc = try shellquote.quote(allocator, proc);
    defer allocator.free(q_proc);

    out[0] = try std.fmt.allocPrint(allocator,
        \\echo '@os'; sed -n '1,16p' /etc/os-release 2>/dev/null;
        \\echo '@arch'; uname -m;
        \\echo '@libc'; {{ ldd --version 2>&1 || true; }} | head -1;
        \\echo '@uid'; id -u;
        \\echo '@user'; id -un;
        \\echo '@home'; printf '%s\n' "$HOME";
        \\echo '@priv'; if [ "$(id -u)" = "0" ]; then echo root; elif sudo -n true 2>/dev/null; then echo sudo; else echo none; fi;
        \\echo '@disk'; df -k "$HOME" 2>/dev/null | tail -1
    , .{});
    built += 1;

    out[1] = try std.fmt.allocPrint(allocator,
        \\for t in git curl wget tar xz sha256sum readlink ss node npm corepack pm2 nginx certbot dig; do printf '%s=' "$t"; command -v "$t" 2>/dev/null || echo; done;
        \\echo '@ver';
        \\printf 'node='; node --version 2>/dev/null || echo;
        \\printf 'npm='; npm --version 2>/dev/null || echo;
        \\printf 'pm2='; pm2 --version 2>/dev/null || echo;
        \\printf 'nginx='; nginx -v 2>&1 | head -1;
        \\printf 'certbot='; certbot --version 2>/dev/null | head -1 || echo;
        \\printf 'git='; git --version 2>/dev/null | awk '{{print $3}}'
    , .{});
    built += 1;

    out[2] = try std.fmt.allocPrint(allocator,
        \\echo '@exists'; [ -d {s} ] && echo yes || echo no;
        \\echo '@gitdir'; [ -d {s}/.git ] && echo yes || echo no;
        \\if [ -d {s}/.git ]; then
        \\echo '@origin'; git -C {s} remote get-url origin 2>/dev/null;
        \\echo '@branch'; git -C {s} rev-parse --abbrev-ref HEAD 2>/dev/null;
        \\echo '@dirty'; git -C {s} status --porcelain --untracked-files=no 2>/dev/null;
        \\echo '@head'; git -C {s} rev-parse HEAD 2>/dev/null;
        \\fi;
        \\echo '@key'; K={s}/id_ed25519; [ -f "$K" ] && echo present || echo missing;
        \\echo '@knownhosts'; KH={s}/known_hosts; [ -f "$KH" ] && echo present || echo missing;
        \\echo '@remote'; if [ -f "$K" ]; then GIT_SSH_COMMAND="ssh -i \"$K\" -o IdentitiesOnly=yes -o UserKnownHostsFile=\"$KH\" -o StrictHostKeyChecking=yes -o ConnectTimeout=8" git ls-remote {s} refs/heads/{s} 2>&1 | head -2; else git ls-remote {s} refs/heads/{s} 2>&1 | head -2; fi;
        \\HOST_KEYS=$(ssh-keyscan -T 5 {s} 2>/dev/null | head -8); echo '@hostkeys'; printf '%s\n' "$HOST_KEYS";
        \\echo '@hostfingerprints'; if [ -n "$HOST_KEYS" ] && command -v ssh-keygen >/dev/null 2>&1; then printf '%s\n' "$HOST_KEYS" | ssh-keygen -E sha256 -lf - 2>/dev/null; fi;
        \\echo '@lockfiles'; if [ -d {s} ]; then for f in package-lock.json npm-shrinkwrap.json pnpm-lock.yaml yarn.lock; do [ -f {s}/"$f" ] && sha256sum {s}/"$f" | awk -v n="$f" '{{print $1"  "n}}'; done; grep -m1 '"packageManager"' {s}/package.json 2>/dev/null;
        \\else SCRATCH=$(mktemp -d "${{TMPDIR:-/tmp}}/oars-preflight.XXXXXX") || exit 7; trap 'rm -rf "$SCRATCH"' EXIT HUP INT TERM; if [ -f "$K" ]; then GIT_SSH_COMMAND="ssh -i \"$K\" -o IdentitiesOnly=yes -o UserKnownHostsFile=\"$KH\" -o StrictHostKeyChecking=yes -o ConnectTimeout=8" git clone --quiet --no-checkout --filter=blob:none --depth 1 --branch {s} {s} "$SCRATCH/repo"; else git clone --quiet --no-checkout --filter=blob:none --depth 1 --branch {s} {s} "$SCRATCH/repo"; fi; if [ "$?" = 0 ]; then for f in package-lock.json npm-shrinkwrap.json pnpm-lock.yaml yarn.lock; do git -C "$SCRATCH/repo" cat-file -e "HEAD:$f" 2>/dev/null && git -C "$SCRATCH/repo" show "HEAD:$f" | sha256sum | awk -v n="$f" '{{print $1"  "n}}'; done; git -C "$SCRATCH/repo" show HEAD:package.json 2>/dev/null | grep -m1 '"packageManager"'; fi; rm -rf "$SCRATCH"; trap - EXIT HUP INT TERM; fi
    , .{ folder, folder, folder, folder, folder, folder, folder, key_expr.items, key_expr.items, url, branch, url, branch, scan_target, folder, folder, folder, folder, branch, url, branch, url });
    built += 1;

    var domains: std.ArrayList(u8) = .empty;
    defer domains.deinit(allocator);
    for (app.domains) |d| {
        try domains.appendSlice(allocator, "printf '== %s\\n' ");
        const q_label = try shellquote.quote(allocator, d);
        defer allocator.free(q_label);
        try domains.appendSlice(allocator, q_label);
        try domains.appendSlice(allocator, "; { dig +short A ");
        const qd = try shellquote.quote(allocator, d);
        defer allocator.free(qd);
        try domains.appendSlice(allocator, qd);
        try domains.appendSlice(allocator, " 2>/dev/null; dig +short AAAA ");
        const qd2 = try shellquote.quote(allocator, d);
        defer allocator.free(qd2);
        try domains.appendSlice(allocator, qd2);
        try domains.appendSlice(allocator, " 2>/dev/null; } | sort -u;\n");
    }

    out[3] = try std.fmt.allocPrint(allocator,
        \\echo '@port'; if command -v ss >/dev/null 2>&1; then ss -ltn 2>/dev/null | grep -qE ':{d}([[:space:]]|$)' && echo inuse || echo free; else echo unknown; fi;
        \\echo '@webports'; if command -v ss >/dev/null 2>&1; then if [ "$(id -u)" = 0 ]; then WEB=$(ss -ltnp 2>/dev/null); elif sudo -n true 2>/dev/null; then WEB=$(sudo -n ss -ltnp 2>/dev/null); else WEB=$(ss -ltnp 2>/dev/null); fi; for P in 80 443; do LINE=$(printf '%s\n' "$WEB" | awk -v p=":$P" '$4 ~ (p "$") {{print}}'); if [ -z "$LINE" ]; then STATE=free; elif printf '%s\n' "$LINE" | grep -q 'nginx'; then STATE=nginx; else STATE=foreign; fi; printf '%s=%s\n' "$P" "$STATE"; done; else printf '80=unknown\n443=unknown\n'; fi;
        \\echo '@site'; if [ -f {s} ]; then head -1 {s}; else echo absent; fi;
        \\echo '@sitehash'; if [ -f {s} ]; then sha256sum {s} | awk '{{print $1}}'; fi;
        \\echo '@enabled'; if [ -L {s} ]; then echo linked; elif [ -e {s} ]; then echo present; else echo absent; fi;
        \\echo '@pm2proc'; if command -v pm2 >/dev/null 2>&1; then pm2 jlist 2>/dev/null | grep -F {s} >/dev/null 2>&1 && echo present || echo absent; else echo nopm2; fi;
        \\echo '@dns';
        \\{s}echo '@addrs'; hostname -I 2>/dev/null | head -1
    , .{ app.app_port, q_avail, q_avail, q_avail, q_avail, q_enabled, q_enabled, q_proc, domains.items });
    built += 1;

    const q_major = try shellquote.quote(allocator, app.runtime.node_version);
    defer allocator.free(q_major);
    out[4] = try std.fmt.allocPrint(allocator,
        \\echo '@node'; MAJOR={s}; case "$(uname -m)" in x86_64) A=x64;; aarch64) A=arm64;; *) exit 2;; esac;
        \\fetch() {{ if command -v curl >/dev/null 2>&1; then curl -fsSL --max-time 20 "$1"; elif command -v wget >/dev/null 2>&1; then wget -qO- --timeout=20 "$1"; else return 127; fi; }};
        \\BASE="https://nodejs.org/dist/latest-v${{MAJOR}}.x"; SUMS=$(fetch "$BASE/SHASUMS256.txt") || exit 3;
        \\INDEX=$(fetch https://nodejs.org/dist/index.json) || exit 3; RELEASE=$(printf '%s\n' "$INDEX" | grep -m1 "\\\"version\\\":\\\"v${{MAJOR}}\\."); LTS=$(printf '%s\n' "$RELEASE" | sed -n 's/.*"lts":[[:space:]]*\\([^,}}]*\\).*/\\1/p');
        \\LINE=$(printf '%s\n' "$SUMS" | awk -v a="$A" '$2 ~ ("^node-v[0-9.]+-linux-" a "\\.tar\\.xz$") {{ print; exit }}'); [ -n "$LINE" ] || exit 4;
        \\SHA=$(printf '%s\n' "$LINE" | awk '{{print $1}}'); FILE=$(printf '%s\n' "$LINE" | awk '{{print $2}}'); VER=${{FILE#node-}}; VER=${{VER%-linux-*}};
        \\printf 'version=%s\narchive=%s\nsha256=%s\nurl=https://nodejs.org/dist/%s/%s\nlts=%s\n' "$VER" "$FILE" "$SHA" "$VER" "$FILE" "$LTS";
        \\echo '@pm2'; META=$(fetch https://registry.npmjs.org/pm2/latest) || exit 5;
        \\PM2_VER=$(printf '%s' "$META" | sed -n 's/.*"_id":"pm2@\([^"]*\)".*/\1/p'); PM2_INTEGRITY=$(printf '%s' "$META" | sed -n 's/.*"integrity":"\([^"]*\)".*/\1/p'); [ -n "$PM2_VER" ] && [ -n "$PM2_INTEGRITY" ] || exit 6;
        \\printf 'version=%s\nintegrity=%s\n' "$PM2_VER" "$PM2_INTEGRITY"
    , .{q_major});
    built += 1;

    return out;
}

// --- probe output parsing ----------------------------------------------------

/// Splits probe output into named sections. Lines starting with `@` open a
/// section; everything up to the next marker is the section body.
pub const Sections = struct {
    entries: std.ArrayList(Entry) = .empty,

    pub const Entry = struct {
        name: []const u8,
        body: []const u8,
    };

    pub fn get(self: *const Sections, name: []const u8) []const u8 {
        for (self.entries.items) |e| {
            if (std.mem.eql(u8, e.name, name)) return std.mem.trim(u8, e.body, "\r\n");
        }
        return "";
    }

    pub fn deinit(self: *Sections, allocator: std.mem.Allocator) void {
        for (self.entries.items) |*e| {
            allocator.free(e.name);
            allocator.free(e.body);
        }
        self.entries.deinit(allocator);
    }
};

pub fn parseSections(allocator: std.mem.Allocator, output: []const u8) !Sections {
    var out: Sections = .{};
    errdefer out.deinit(allocator);
    var name: ?[]const u8 = null;
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    var it = std.mem.splitScalar(u8, output, '\n');
    while (it.next()) |line| {
        if (line.len > 1 and line[0] == '@') {
            if (name) |n| {
                try out.entries.append(allocator, .{ .name = try allocator.dupe(u8, n), .body = try allocator.dupe(u8, body.items) });
                body.clearRetainingCapacity();
            }
            name = line[1..];
        } else if (name != null) {
            try body.appendSlice(allocator, line);
            try body.append(allocator, '\n');
        }
    }
    if (name) |n| {
        try out.entries.append(allocator, .{ .name = try allocator.dupe(u8, n), .body = try allocator.dupe(u8, body.items) });
    }
    return out;
}

/// os-release KEY=value lines (values may be quoted).
fn osReleaseValue(body: []const u8, key: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, body, '\n');
    while (it.next()) |line| {
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        if (!std.mem.eql(u8, line[0..eq], key)) continue;
        var v = line[eq + 1 ..];
        if (v.len >= 2 and v[0] == '"' and v[v.len - 1] == '"') v = v[1 .. v.len - 1];
        return std.mem.trim(u8, v, " \t\r");
    }
    return "";
}

/// The first line of `ldd --version` names the libc family.
pub fn libcFamily(ldd_line: []const u8) []const u8 {
    if (std.ascii.indexOfIgnoreCase(ldd_line, "musl") != null) return "musl";
    if (std.ascii.indexOfIgnoreCase(ldd_line, "glibc") != null or std.ascii.indexOfIgnoreCase(ldd_line, "gnu libc") != null) return "glibc";
    return "unknown";
}

pub fn parseSystem(allocator: std.mem.Allocator, output: []const u8, facts: *Facts) !void {
    var sections = try parseSections(allocator, output);
    defer sections.deinit(allocator);
    const os = sections.get("os");
    facts.os_id = try allocator.dupe(u8, osReleaseValue(os, "ID"));
    facts.os_version = try allocator.dupe(u8, osReleaseValue(os, "VERSION_ID"));
    facts.os_pretty = try allocator.dupe(u8, osReleaseValue(os, "PRETTY_NAME"));
    facts.arch = try allocator.dupe(u8, sections.get("arch"));
    facts.libc = try allocator.dupe(u8, libcFamily(sections.get("libc")));
    facts.uid = try allocator.dupe(u8, sections.get("uid"));
    facts.user = try allocator.dupe(u8, sections.get("user"));
    facts.home = try allocator.dupe(u8, sections.get("home"));
    const priv = sections.get("priv");
    facts.privilege = if (std.mem.eql(u8, priv, "root")) .root else if (std.mem.eql(u8, priv, "sudo")) .sudo else if (std.mem.eql(u8, priv, "none")) Privilege.none else .unknown;
    const disk = sections.get("disk");
    var it = std.mem.tokenizeAny(u8, disk, " \t");
    var col: usize = 0;
    while (it.next()) |tok| : (col += 1) {
        if (col == 3) {
            facts.disk_free_kb = std.fmt.parseInt(u64, tok, 10) catch 0;
            break;
        }
    }
}

pub fn parseTools(allocator: std.mem.Allocator, output: []const u8, facts: *Facts) !void {
    var sections = try parseSections(allocator, output);
    defer sections.deinit(allocator);
    // Section-less first block: `name=path` lines until `@ver`.
    var it = std.mem.splitScalar(u8, output, '\n');
    while (it.next()) |line| {
        if (line.len > 0 and line[0] == '@') break;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const name = line[0..eq];
        const path = std.mem.trim(u8, line[eq + 1 ..], " \t\r");
        try setTool(allocator, &facts.tools, name, path, "");
    }
    const vers = sections.get("ver");
    var vit = std.mem.splitScalar(u8, vers, '\n');
    while (vit.next()) |line| {
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const name = line[0..eq];
        const version = std.mem.trim(u8, line[eq + 1 ..], " \t\r");
        if (version.len == 0) continue;
        try setTool(allocator, &facts.tools, name, "", version);
    }
}

fn setTool(allocator: std.mem.Allocator, tools: *Tools, name: []const u8, path: []const u8, version: []const u8) !void {
    const slot: *ToolState = blk: {
        if (std.mem.eql(u8, name, "git")) break :blk &tools.git;
        if (std.mem.eql(u8, name, "curl")) break :blk &tools.curl;
        if (std.mem.eql(u8, name, "wget")) break :blk &tools.wget;
        if (std.mem.eql(u8, name, "tar")) break :blk &tools.tar;
        if (std.mem.eql(u8, name, "xz")) break :blk &tools.xz;
        if (std.mem.eql(u8, name, "sha256sum")) break :blk &tools.sha256sum;
        if (std.mem.eql(u8, name, "readlink")) break :blk &tools.readlink;
        if (std.mem.eql(u8, name, "ss")) break :blk &tools.ss;
        if (std.mem.eql(u8, name, "node")) break :blk &tools.node;
        if (std.mem.eql(u8, name, "npm")) break :blk &tools.npm;
        if (std.mem.eql(u8, name, "corepack")) break :blk &tools.corepack;
        if (std.mem.eql(u8, name, "pm2")) break :blk &tools.pm2;
        if (std.mem.eql(u8, name, "nginx")) break :blk &tools.nginx;
        if (std.mem.eql(u8, name, "certbot")) break :blk &tools.certbot;
        if (std.mem.eql(u8, name, "dig")) break :blk &tools.dig;
        return;
    };
    if (path.len > 0 and slot.path.len == 0) slot.path = try allocator.dupe(u8, path);
    if (version.len > 0 and slot.version.len == 0) slot.version = try allocator.dupe(u8, version);
}

pub fn parseRepo(allocator: std.mem.Allocator, output: []const u8, facts: *Facts) !void {
    var sections = try parseSections(allocator, output);
    defer sections.deinit(allocator);
    facts.repo.folder_exists = std.mem.eql(u8, sections.get("exists"), "yes");
    facts.repo.is_git = std.mem.eql(u8, sections.get("gitdir"), "yes");
    facts.repo.origin = try allocator.dupe(u8, sections.get("origin"));
    facts.repo.branch = try allocator.dupe(u8, sections.get("branch"));
    facts.repo.dirty_files = try allocator.dupe(u8, sections.get("dirty"));
    facts.repo.head = try allocator.dupe(u8, sections.get("head"));
    facts.repo.deploy_key_present = std.mem.eql(u8, sections.get("key"), "present");
    facts.repo.known_hosts_present = std.mem.eql(u8, sections.get("knownhosts"), "present");
    facts.repo.scanned_host_keys = try allocator.dupe(u8, sections.get("hostkeys"));
    facts.repo.scanned_host_fingerprints = try allocator.dupe(u8, sections.get("hostfingerprints"));
    facts.repo.lockfiles = try allocator.dupe(u8, sections.get("lockfiles"));
    // ls-remote prints `<sha>\trefs/heads/<branch>` on success, an error
    // line otherwise.
    const remote = sections.get("remote");
    if (remote.len > 0) {
        var it = std.mem.splitScalar(u8, remote, '\n');
        if (it.next()) |line| {
            if (std.mem.indexOf(u8, line, "refs/heads/") != null) {
                var tok = std.mem.tokenizeAny(u8, line, " \t");
                if (tok.next()) |sha| {
                    if (sha.len == 40 or sha.len == 64) {
                        facts.repo.remote_commit = try allocator.dupe(u8, sha);
                        facts.repo.repo_accessible = true;
                    }
                }
            }
        }
    }
    // The packageManager metadata line shares the lockfiles section body.
    const locks = sections.get("lockfiles");
    var lit = std.mem.splitScalar(u8, locks, '\n');
    while (lit.next()) |line| {
        if (std.mem.indexOf(u8, line, "\"packageManager\"") != null) {
            facts.repo.package_manager_field = try allocator.dupe(u8, std.mem.trim(u8, line, " \t\r"));
        }
    }
}

pub fn parsePorts(allocator: std.mem.Allocator, output: []const u8, facts: *Facts) !void {
    var sections = try parseSections(allocator, output);
    defer sections.deinit(allocator);
    const port = sections.get("port");
    facts.ports.port_probe_ran = !std.mem.eql(u8, port, "unknown");
    facts.ports.app_port_in_use = std.mem.eql(u8, port, "inuse");
    var wit = std.mem.splitScalar(u8, sections.get("webports"), '\n');
    while (wit.next()) |line| {
        if (std.mem.startsWith(u8, line, "80=")) facts.ports.http_listener = listenerState(line[3..]);
        if (std.mem.startsWith(u8, line, "443=")) facts.ports.https_listener = listenerState(line[4..]);
    }
    const site = sections.get("site");
    if (std.mem.eql(u8, site, "absent")) {
        facts.ports.nginx_site = "absent";
    } else if (std.mem.startsWith(u8, site, "# oars:app=")) {
        facts.ports.nginx_site = "ours";
    } else {
        facts.ports.nginx_site = "foreign";
    }
    facts.ports.nginx_site_sha256 = try allocator.dupe(u8, sections.get("sitehash"));
    const enabled = sections.get("enabled");
    if (std.mem.eql(u8, enabled, "linked") or std.mem.eql(u8, enabled, "present") or std.mem.eql(u8, enabled, "absent")) {
        facts.ports.nginx_enabled = try allocator.dupe(u8, enabled);
    }
    facts.ports.pm2_process_present = std.mem.eql(u8, sections.get("pm2proc"), "present");
    facts.ports.dns = try allocator.dupe(u8, sections.get("dns"));
    facts.ports.local_addresses = try allocator.dupe(u8, sections.get("addrs"));
}

pub fn parseRuntime(allocator: std.mem.Allocator, output: []const u8, facts: *Facts) !void {
    var sections = try parseSections(allocator, output);
    defer sections.deinit(allocator);
    const node = sections.get("node");
    var it = std.mem.splitScalar(u8, node, '\n');
    while (it.next()) |line| {
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = line[0..eq];
        const value = std.mem.trim(u8, line[eq + 1 ..], " \t\r");
        if (std.mem.eql(u8, key, "version")) facts.node_version = try allocator.dupe(u8, value) else if (std.mem.eql(u8, key, "archive")) facts.node_archive = try allocator.dupe(u8, value) else if (std.mem.eql(u8, key, "sha256")) facts.node_sha256 = try allocator.dupe(u8, value) else if (std.mem.eql(u8, key, "url")) facts.node_url = try allocator.dupe(u8, value) else if (std.mem.eql(u8, key, "lts")) facts.node_lts = try allocator.dupe(u8, value);
    }
    const pm2 = sections.get("pm2");
    var pit = std.mem.splitScalar(u8, pm2, '\n');
    while (pit.next()) |line| {
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = line[0..eq];
        const value = std.mem.trim(u8, line[eq + 1 ..], " \t\r");
        if (std.mem.eql(u8, key, "version")) facts.pm2_version = try allocator.dupe(u8, value) else if (std.mem.eql(u8, key, "integrity")) facts.pm2_integrity = try allocator.dupe(u8, value);
    }
}

fn listenerState(value: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, value, " \t\r");
    inline for (.{ "free", "nginx", "foreign" }) |state| {
        if (std.mem.eql(u8, trimmed, state)) return state;
    }
    return "unknown";
}

// --- the preflight record ----------------------------------------------------

/// Worker completion cell for one read-only probe. The bridge can abandon a
/// canceled preflight while the session worker retains final-free ownership.
pub const ProbeOutcome = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    done: bool = false,
    ok: bool = false,
    abandoned: bool = false,
    exit: ?i32 = null,
    msg_buf: [512]u8 = undefined,
    msg_len: usize = 0,
    data: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) ProbeOutcome {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ProbeOutcome) void {
        self.data.deinit(self.allocator);
    }

    pub fn set(self: *ProbeOutcome, exit: ?i32, data: []const u8, msg: []const u8) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        if (data.len > 0) self.data.appendSlice(self.allocator, data) catch {};
        const n = @min(msg.len, self.msg_buf.len - 1);
        @memcpy(self.msg_buf[0..n], msg[0..n]);
        self.msg_len = n;
        self.exit = exit;
        self.ok = exit != null and exit.? == 0;
        self.done = true;
        const free = self.abandoned;
        self.mutex.unlock();
        if (free) {
            self.data.deinit(self.allocator);
            self.allocator.destroy(self);
        }
    }

    pub fn abandon(self: *ProbeOutcome) bool {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        defer self.mutex.unlock();
        self.abandoned = true;
        return self.done;
    }

    pub fn isDone(self: *ProbeOutcome) bool {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        defer self.mutex.unlock();
        return self.done;
    }

    pub fn message(self: *ProbeOutcome) []const u8 {
        return self.msg_buf[0..self.msg_len];
    }
};

pub const Status = enum(u8) {
    gathering,
    ready,
    blocked,
    failed,

    pub fn jsonName(self: Status) []const u8 {
        return @tagName(self);
    }
};

pub const Preflight = struct {
    id: u32,
    server_id: []const u8,
    app_id: []const u8,
    /// The app snapshot frozen at preflight time; commit deploys this, not
    /// whatever the store holds later.
    app: deploy.App,
    app_revision: u64,
    status: Status = .gathering,
    /// "deploy" (fresh folder) or "update" (existing matching checkout).
    action: []const u8 = "",
    error_text: []const u8 = "",
    probe_index: usize = 0,
    channel: ?u32 = null,
    cursor: u64 = 0,
    probe_started_ns: i128 = 0,
    outputs: [probe_count][]u8 = .{ &.{}, &.{}, &.{}, &.{}, &.{} },
    /// Worker-owned read-only probe results. A canceled record abandons
    /// unfinished outcomes so the session worker performs the final free.
    probe_outcomes: [probe_count]?*ProbeOutcome = .{ null, null, null, null, null },
    output_truncated: bool = false,
    facts: Facts = .{},
    blockers: std.ArrayList(Issue) = .empty,
    warnings: std.ArrayList(Issue) = .empty,
    approvals: std.ArrayList(Approval) = .empty,
    steps: std.ArrayList(PreflightStep) = .empty,
    /// Exact approved commands. Commit transfers this plan to the run and
    /// never calls the planner again.
    plan: []deploy.PlanStep = &.{},
    /// Redacted config previews (env names masked, pm2, nginx).
    env_preview: []const u8 = "",
    pm2_preview: []const u8 = "",
    nginx_preview: []const u8 = "",
    target_fingerprint: u64 = 0,
    created_at_ms: i64,
    expires_at_ms: i64,

    pub fn deinit(self: *Preflight, allocator: std.mem.Allocator) void {
        allocator.free(self.server_id);
        allocator.free(self.app_id);
        deploy.deinit(allocator, &self.app);
        allocator.free(self.action);
        allocator.free(self.error_text);
        for (self.outputs) |o| {
            if (o.len > 0) allocator.free(o);
        }
        for (&self.probe_outcomes) |*slot| {
            if (slot.*) |outcome| {
                slot.* = null;
                if (outcome.abandon()) {
                    outcome.deinit();
                    allocator.destroy(outcome);
                }
            }
        }
        freeFacts(allocator, &self.facts);
        for (self.blockers.items) |*b| b.deinit(allocator);
        self.blockers.deinit(allocator);
        for (self.warnings.items) |*w| w.deinit(allocator);
        self.warnings.deinit(allocator);
        for (self.approvals.items) |*a| a.deinit(allocator);
        self.approvals.deinit(allocator);
        for (self.steps.items) |*s| s.deinit(allocator);
        self.steps.deinit(allocator);
        for (self.plan) |*step| {
            allocator.free(step.label);
            step.deinit(allocator);
        }
        allocator.free(self.plan);
        if (self.env_preview.len > 0) allocator.free(self.env_preview);
        if (self.pm2_preview.len > 0) allocator.free(self.pm2_preview);
        if (self.nginx_preview.len > 0) allocator.free(self.nginx_preview);
    }
};

/// Frees every owned fact string (the parsers allocate into `facts`).
pub fn freeFacts(allocator: std.mem.Allocator, f: *Facts) void {
    for ([_][]const u8{ f.os_id, f.os_version, f.os_pretty, f.arch, f.libc, f.uid, f.user, f.home, f.node_version, f.node_archive, f.node_sha256, f.node_url, f.node_lts, f.pm2_version, f.pm2_integrity }) |s| {
        if (s.len > 0) allocator.free(s);
    }
    inline for (@typeInfo(Tools).@"struct".fields) |field| {
        const t = &@field(f.tools, field.name);
        if (t.path.len > 0) allocator.free(t.path);
        if (t.version.len > 0) allocator.free(t.version);
    }
    for ([_][]const u8{ f.repo.origin, f.repo.branch, f.repo.dirty_files, f.repo.head, f.repo.remote_commit, f.repo.scanned_host_keys, f.repo.scanned_host_fingerprints, f.repo.lockfiles, f.repo.package_manager_field }) |s| {
        if (s.len > 0) allocator.free(s);
    }
    if (f.ports.nginx_enabled.len > 0) allocator.free(f.ports.nginx_enabled);
    for ([_][]const u8{ f.ports.nginx_site_sha256, f.ports.dns, f.ports.local_addresses }) |s| {
        if (s.len > 0) allocator.free(s);
    }
    f.* = .{};
}

/// Bounded, memory-only registry of preflights. Main-thread access only
/// (bridge handlers serialize), guarded by a spinlock. Evicted on commit,
/// cancel, expiry, server disconnect, and shutdown.
pub const Preflights = struct {
    allocator: std.mem.Allocator = undefined,
    mutex: std.atomic.Mutex = .unlocked,
    list: std.ArrayList(Preflight) = .empty,
    next_id: u32 = 1,

    pub fn lock(self: *Preflights) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    pub fn unlock(self: *Preflights) void {
        self.mutex.unlock();
    }

    pub fn deinit(self: *Preflights) void {
        for (self.list.items) |*p| p.deinit(self.allocator);
        self.list.deinit(self.allocator);
    }

    /// Adopts the record (ownership transfers on success) and returns its
    /// id. On error the caller keeps ownership. Caller holds the lock.
    pub fn add(self: *Preflights, p: Preflight) !u32 {
        if (self.list.items.len >= deploy.max_uncommitted_preflights) return error.TooManyPreflights;
        var adopted = p;
        adopted.id = self.next_id;
        self.next_id +%= 1;
        try self.list.append(self.allocator, adopted);
        return adopted.id;
    }

    /// Removes a completed preflight and transfers its frozen plan. The
    /// remaining snapshots are freed immediately. Caller holds the lock.
    pub fn takePlan(self: *Preflights, id: u32) []deploy.PlanStep {
        for (self.list.items, 0..) |*p, i| {
            if (p.id != id) continue;
            const plan = p.plan;
            p.plan = &.{};
            var removed = self.list.orderedRemove(i);
            removed.plan = &.{};
            removed.deinit(self.allocator);
            return plan;
        }
        return &.{};
    }

    /// Caller holds the lock.
    pub fn get(self: *Preflights, id: u32) ?*Preflight {
        for (self.list.items) |*p| {
            if (p.id == id) return p;
        }
        return null;
    }

    /// Removes and frees the record. Caller holds the lock.
    pub fn remove(self: *Preflights, id: u32) bool {
        for (self.list.items, 0..) |*p, i| {
            if (p.id == id) {
                var removed = self.list.orderedRemove(i);
                removed.deinit(self.allocator);
                return true;
            }
        }
        return false;
    }

    /// Drops every preflight for a disconnected server. Caller holds the lock.
    pub fn removeServer(self: *Preflights, server_id: []const u8) void {
        var i: usize = 0;
        while (i < self.list.items.len) {
            if (std.mem.eql(u8, self.list.items[i].server_id, server_id)) {
                var removed = self.list.orderedRemove(i);
                removed.deinit(self.allocator);
            } else {
                i += 1;
            }
        }
    }

    /// Drops expired records. Caller holds the lock.
    pub fn expire(self: *Preflights, now_ms: i64) void {
        var i: usize = 0;
        while (i < self.list.items.len) {
            if (now_ms >= self.list.items[i].expires_at_ms) {
                var p = self.list.orderedRemove(i);
                p.deinit(self.allocator);
            } else {
                i += 1;
            }
        }
    }
};

/// A diagnostic hash over the remote facts shown during preflight. The frozen
/// commands enforce the relevant repository, lockfile, Nginx, and DNS guards
/// again when the mutating run starts.
pub fn targetFingerprint(facts: *const Facts, app: *const deploy.App) u64 {
    var hasher = std.hash.Wyhash.init(0x0a15);
    hasher.update(app.folder);
    hasher.update(facts.os_id);
    hasher.update(facts.os_version);
    hasher.update(facts.arch);
    hasher.update(facts.libc);
    hasher.update(facts.user);
    hasher.update(facts.home);
    hasher.update(facts.privilege.jsonName());
    hasher.update(facts.repo.origin);
    hasher.update(facts.repo.branch);
    hasher.update(facts.repo.head);
    hasher.update(facts.repo.remote_commit);
    hasher.update(facts.repo.dirty_files);
    hasher.update(if (facts.repo.folder_exists) "1" else "0");
    hasher.update(if (facts.repo.is_git) "1" else "0");
    hasher.update(if (facts.repo.deploy_key_present) "1" else "0");
    hasher.update(facts.repo.scanned_host_fingerprints);
    hasher.update(facts.repo.lockfiles);
    hasher.update(facts.node_version);
    hasher.update(facts.node_archive);
    hasher.update(facts.node_sha256);
    hasher.update(facts.node_lts);
    hasher.update(facts.node_url);
    hasher.update(facts.pm2_version);
    hasher.update(facts.pm2_integrity);
    hasher.update(facts.ports.nginx_site);
    hasher.update(facts.ports.nginx_site_sha256);
    hasher.update(facts.ports.nginx_enabled);
    hasher.update(if (facts.ports.app_port_in_use) "1" else "0");
    hasher.update(if (facts.ports.pm2_process_present) "1" else "0");
    hasher.update(facts.ports.http_listener);
    hasher.update(facts.ports.https_listener);
    return hasher.final();
}

// --- OS adapter (Debian/Ubuntu, glibc, x64/arm64 — the tested v1 target) ----

/// GitHub's published SSH known-hosts entries (GitHub docs: "GitHub's SSH
/// key fingerprints", cited in docs/research/spec-07-current-state.md). A
/// scanned key matching one of these lines is verified; anything else is
/// discovery data and needs independent user confirmation.
pub const github_known_hosts = [_][]const u8{
    "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
    "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
    "github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNd/XA5TKA1U2NzM5iN7ZRJqM0uA=",
};

pub fn githubHostKeysMatch(scanned: []const u8) bool {
    for (github_known_hosts) |entry| {
        if (std.mem.indexOf(u8, scanned, entry) != null) return true;
    }
    return false;
}

/// The v1 OS adapter: supported releases and the exact apt package for each
/// required tool. Node.js and PM2 are deliberately absent — Node comes from
/// the official release archive and PM2 from the frozen package manager,
/// never from a guessed distribution package.
pub fn supportedOsRelease(os_id: []const u8, version_id: []const u8) bool {
    if (std.mem.eql(u8, os_id, "ubuntu")) {
        for ([_][]const u8{ "22.04", "24.04" }) |v| {
            if (std.mem.eql(u8, version_id, v)) return true;
        }
        return false;
    }
    if (std.mem.eql(u8, os_id, "debian")) {
        for ([_][]const u8{ "12", "13" }) |v| {
            if (std.mem.eql(u8, version_id, v)) return true;
        }
        return false;
    }
    return false;
}

/// Tool name → apt package name for the adapter (null = not apt-managed).
pub fn aptPackage(tool: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, tool, "git")) return "git";
    if (std.mem.eql(u8, tool, "curl")) return "curl";
    if (std.mem.eql(u8, tool, "wget")) return "wget";
    if (std.mem.eql(u8, tool, "tar")) return "tar";
    if (std.mem.eql(u8, tool, "xz")) return "xz-utils";
    if (std.mem.eql(u8, tool, "sha256sum")) return "coreutils";
    if (std.mem.eql(u8, tool, "readlink")) return "coreutils";
    if (std.mem.eql(u8, tool, "ss")) return "iproute2";
    if (std.mem.eql(u8, tool, "nginx")) return "nginx";
    if (std.mem.eql(u8, tool, "certbot")) return "certbot";
    if (std.mem.eql(u8, tool, "dig")) return "dnsutils";
    return null;
}

pub fn supportedArch(arch: []const u8) bool {
    return std.mem.eql(u8, arch, "x86_64") or std.mem.eql(u8, arch, "aarch64");
}

// --- derivation: facts → blockers / warnings / approvals / plan -------------

fn addIssue(allocator: std.mem.Allocator, list: *std.ArrayList(Issue), id: []const u8, message: []const u8) !void {
    try list.append(allocator, .{
        .id = try allocator.dupe(u8, id),
        .message = try allocator.dupe(u8, message),
    });
}

fn addApproval(allocator: std.mem.Allocator, list: *std.ArrayList(Approval), id: []const u8, label: []const u8, detail: []const u8) !void {
    for (list.items) |a| {
        if (std.mem.eql(u8, a.id, id)) return; // one entry per approval id
    }
    try list.append(allocator, .{
        .id = try allocator.dupe(u8, id),
        .label = try allocator.dupe(u8, label),
        .detail = try allocator.dupe(u8, detail),
    });
}

/// The answers for one domain inside the `@dns` section body.
fn dnsAnswers(dns: []const u8, domain: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, dns, '\n');
    var active = false;
    var start: usize = 0;
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, "== ")) {
            if (active) return dns[start..@intCast(line.ptr - dns.ptr)];
            active = std.mem.eql(u8, line[3..], domain);
            if (active) start = @intCast(line.ptr - dns.ptr);
        }
    }
    if (!active) return "";
    return dns[start..];
}

fn isPrivateAddress(addr: []const u8) bool {
    return std.mem.startsWith(u8, addr, "10.") or std.mem.startsWith(u8, addr, "192.168.") or std.mem.startsWith(u8, addr, "172.16.") or std.mem.startsWith(u8, addr, "172.17.") or std.mem.startsWith(u8, addr, "172.18.") or std.mem.startsWith(u8, addr, "172.19.") or std.mem.startsWith(u8, addr, "172.2") or std.mem.startsWith(u8, addr, "172.30.") or std.mem.startsWith(u8, addr, "172.31.") or std.mem.startsWith(u8, addr, "127.") or std.mem.startsWith(u8, addr, "169.254.");
}

fn replacePlanCommand(allocator: std.mem.Allocator, step: *deploy.PlanStep, command: []const u8) !void {
    allocator.free(step.command);
    step.command = try allocator.dupe(u8, command);
}

fn missingSystemPackages(allocator: std.mem.Allocator, app: *const deploy.App, f: *const Facts) ![]u8 {
    var packages: std.ArrayList(u8) = .empty;
    errdefer packages.deinit(allocator);
    const names = .{ "git", "tar", "xz", "sha256sum", "ss", "nginx", "dig" };
    const states = .{ f.tools.git, f.tools.tar, f.tools.xz, f.tools.sha256sum, f.tools.ss, f.tools.nginx, f.tools.dig };
    inline for (names, states) |name, state| {
        if (state.path.len == 0) {
            if (aptPackage(name)) |pkg| {
                if (packages.items.len > 0) try packages.append(allocator, ' ');
                try packages.appendSlice(allocator, pkg);
            }
        }
    }
    if (f.tools.curl.path.len == 0 and f.tools.wget.path.len == 0) {
        if (packages.items.len > 0) try packages.append(allocator, ' ');
        try packages.appendSlice(allocator, "curl");
    }
    if (app.ssl and f.tools.certbot.path.len == 0) {
        if (packages.items.len > 0) try packages.append(allocator, ' ');
        try packages.appendSlice(allocator, "certbot");
    }
    if ((app.runtime.type == .react or app.runtime.type == .static) and f.tools.readlink.path.len == 0 and std.mem.indexOf(u8, packages.items, "coreutils") == null) {
        if (packages.items.len > 0) try packages.append(allocator, ' ');
        try packages.appendSlice(allocator, "coreutils");
    }
    return packages.toOwnedSlice(allocator);
}

fn exactCloneCommand(allocator: std.mem.Allocator, app: *const deploy.App, facts: *const Facts) ![]u8 {
    const folder = try shellquote.quote(allocator, app.folder);
    defer allocator.free(folder);
    const url = try shellquote.quote(allocator, app.repo.url);
    defer allocator.free(url);
    const branch = try shellquote.quote(allocator, app.repo.branch);
    defer allocator.free(branch);
    const commit = try shellquote.quote(allocator, facts.repo.remote_commit);
    defer allocator.free(commit);
    var prefix: std.ArrayList(u8) = .empty;
    defer prefix.deinit(allocator);
    const packages = try missingSystemPackages(allocator, app, facts);
    defer allocator.free(packages);
    if (packages.len > 0) {
        try prefix.appendSlice(allocator, "as_root() { if [ \"$(id -u)\" = 0 ]; then \"$@\"; else sudo -n \"$@\"; fi; }; export DEBIAN_FRONTEND=noninteractive; as_root apt-get install -y ");
        try prefix.appendSlice(allocator, packages);
        try prefix.appendSlice(allocator, " || exit 1; ");
    }
    if (app.repo.transport == .ssh) {
        const id = try shellquote.quote(allocator, app.id);
        defer allocator.free(id);
        const keys = try shellquote.quote(allocator, facts.repo.scanned_host_keys);
        defer allocator.free(keys);
        try prefix.appendSlice(allocator, "APP_ID=");
        try prefix.appendSlice(allocator, id);
        try prefix.appendSlice(allocator, "; KEY_DIR=\"$HOME/.config/oars/deploy/$APP_ID\"; mkdir -p \"$KEY_DIR\" && chmod 700 \"$KEY_DIR\"; KEY=\"$KEY_DIR/id_ed25519\"; KH=\"$KEY_DIR/known_hosts\"; [ -f \"$KEY\" ] || { echo 'deploy key is missing'; exit 1; }; if [ ! -s \"$KH\" ]; then printf '%s\\n' ");
        try prefix.appendSlice(allocator, keys);
        try prefix.appendSlice(allocator, " > \"$KH\" && chmod 600 \"$KH\"; fi; export GIT_SSH_COMMAND=\"ssh -i $KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KH\"; ");
    }
    return std.fmt.allocPrint(
        allocator,
        "{s}URL={s}; BRANCH={s}; COMMIT={s}; REMOTE=$(git ls-remote \"$URL\" \"refs/heads/$BRANCH\" | awk 'NR==1{{print $1}}'); [ \"$REMOTE\" = \"$COMMIT\" ] || {{ echo 'repository changed since preflight'; exit 1; }}; if [ -d {s}/.git ]; then git -C {s} status --porcelain --untracked-files=no | grep -q . && {{ echo 'deploy folder has modified tracked files'; exit 1; }}; [ \"$(git -C {s} remote get-url origin)\" = \"$URL\" ] || {{ echo 'existing folder is a different repository'; exit 1; }}; git -C {s} fetch --depth 1 origin \"$BRANCH\" || exit 1; [ \"$(git -C {s} rev-parse FETCH_HEAD)\" = \"$COMMIT\" ] || {{ echo 'fetched commit differs from preflight'; exit 1; }}; git -C {s} merge-base --is-ancestor HEAD \"$COMMIT\" || {{ echo 'server checkout is not a fast-forward ancestor'; exit 1; }}; git -C {s} checkout --detach \"$COMMIT\"; else git clone --no-checkout --depth 1 --branch \"$BRANCH\" \"$URL\" {s} || exit 1; [ \"$(git -C {s} rev-parse HEAD)\" = \"$COMMIT\" ] || {{ echo 'cloned commit differs from preflight'; exit 1; }}; git -C {s} checkout --detach \"$COMMIT\"; fi",
        .{ prefix.items, url, branch, commit, folder, folder, folder, folder, folder, folder, folder, folder, folder, folder },
    );
}

fn exactInstallCommand(allocator: std.mem.Allocator, app: *const deploy.App, facts: *const Facts) ![]u8 {
    const folder = try shellquote.quote(allocator, app.folder);
    defer allocator.free(folder);
    const version = try shellquote.quote(allocator, facts.node_version);
    defer allocator.free(version);
    const archive = try shellquote.quote(allocator, facts.node_archive);
    defer allocator.free(archive);
    const sha = try shellquote.quote(allocator, facts.node_sha256);
    defer allocator.free(sha);
    const url = try shellquote.quote(allocator, facts.node_url);
    defer allocator.free(url);
    const expected_locks = try shellquote.quote(allocator, facts.repo.lockfiles);
    defer allocator.free(expected_locks);
    const has_npm = std.mem.indexOf(u8, facts.repo.lockfiles, "package-lock.json") != null or std.mem.indexOf(u8, facts.repo.lockfiles, "npm-shrinkwrap.json") != null;
    const has_pnpm = std.mem.indexOf(u8, facts.repo.lockfiles, "pnpm-lock.yaml") != null;
    const has_yarn = std.mem.indexOf(u8, facts.repo.lockfiles, "yarn.lock") != null;
    const selected: deploy.PackageManager = if (app.runtime.package_manager != .auto)
        app.runtime.package_manager
    else if (has_pnpm)
        .pnpm
    else if (has_yarn)
        .yarn
    else
        .npm;
    const install = if (app.runtime.install.len > 0)
        app.runtime.install
    else switch (selected) {
        .npm => if (has_npm) "npm ci" else "npm install",
        .pnpm => if (has_pnpm) "pnpm install --frozen-lockfile" else "pnpm install --no-frozen-lockfile",
        .yarn => if (has_yarn) "yarn install --immutable" else "yarn install",
        .auto => unreachable,
    };
    const q_install = try shellquote.quote(allocator, install);
    defer allocator.free(q_install);
    const pm2_version = try shellquote.quote(allocator, facts.pm2_version);
    defer allocator.free(pm2_version);
    const pm2_integrity = try shellquote.quote(allocator, facts.pm2_integrity);
    defer allocator.free(pm2_integrity);
    const install_pm2 = app.runtime.type == .node or app.runtime.type == .next;
    const needs_corepack = selected == .pnpm or selected == .yarn;
    return std.fmt.allocPrint(
        allocator,
        "VER={s}; FILE={s}; SHA={s}; URL={s}; EXPECTED_LOCKS={s}; PM2_VER={s}; PM2_INTEGRITY={s}; CURRENT_LOCKS=$(for f in package-lock.json npm-shrinkwrap.json pnpm-lock.yaml yarn.lock; do [ -f {s}/\"$f\" ] && sha256sum {s}/\"$f\" | awk -v n=\"$f\" '{{print $1\"  \"n}}'; done; grep -m1 '\"packageManager\"' {s}/package.json 2>/dev/null); [ \"$CURRENT_LOCKS\" = \"$EXPECTED_LOCKS\" ] || {{ echo 'lockfiles changed since preflight'; exit 1; }}; ROOT=\"$HOME/.local/share/oars/node\"; DEST=\"$ROOT/$VER\"; CACHE=\"$HOME/.cache/oars/node/$FILE\"; if [ ! -x \"$DEST/bin/node\" ]; then mkdir -p \"$ROOT\" \"$(dirname \"$CACHE\")\"; if command -v curl >/dev/null 2>&1; then curl -fsSL --max-time 120 \"$URL\" -o \"$CACHE.part\"; else wget -qO \"$CACHE.part\" --timeout=120 \"$URL\"; fi; printf '%s  %s\\n' \"$SHA\" \"$CACHE.part\" | sha256sum -c - && mv \"$CACHE.part\" \"$CACHE\" || exit 1; TMP=\"$DEST.oars.$$\"; rm -rf \"$TMP\"; mkdir -p \"$TMP\"; tar -xJf \"$CACHE\" --strip-components=1 -C \"$TMP\" && mv \"$TMP\" \"$DEST\" || exit 1; fi; PM2_ROOT=\"$HOME/.local/share/oars/pm2/$PM2_VER\"; {s} {s} export PATH=\"$DEST/bin:$PM2_ROOT/bin:$PATH\"; cd {s} && sh -c {s}",
        .{ version, archive, sha, url, expected_locks, pm2_version, pm2_integrity, folder, folder, folder, if (install_pm2) "if [ ! -x \"$PM2_ROOT/bin/pm2\" ]; then ACTUAL_INTEGRITY=$(\"$DEST/bin/npm\" view \"pm2@$PM2_VER\" dist.integrity); [ \"$ACTUAL_INTEGRITY\" = \"$PM2_INTEGRITY\" ] || { echo 'PM2 release changed since preflight'; exit 1; }; \"$DEST/bin/npm\" install --global --prefix \"$PM2_ROOT\" \"pm2@$PM2_VER\" || exit 1; fi;" else "", if (needs_corepack) "[ -x \"$DEST/bin/corepack\" ] || { echo 'the reviewed Node release does not include Corepack'; exit 1; }; \"$DEST/bin/corepack\" enable --install-directory \"$DEST/bin\" || exit 1;" else "", folder, q_install },
    );
}

fn prefixNodePath(allocator: std.mem.Allocator, command: []const u8, version: []const u8, pm2_version: []const u8) ![]u8 {
    if (command.len == 0) return allocator.dupe(u8, "");
    const qv = try shellquote.quote(allocator, version);
    defer allocator.free(qv);
    const qp = try shellquote.quote(allocator, pm2_version);
    defer allocator.free(qp);
    return std.fmt.allocPrint(allocator, "VER={s}; PM2_VER={s}; export PATH=\"$HOME/.local/share/oars/node/$VER/bin:$HOME/.local/share/oars/pm2/$PM2_VER/bin:$PATH\"; {s}", .{ qv, qp, command });
}

fn guardNginxCommand(allocator: std.mem.Allocator, app: *const deploy.App, facts: *const Facts, command: []const u8) ![]u8 {
    if (command.len == 0) return allocator.dupe(u8, "");
    const path = try deploy.nginxAvailablePath(allocator, app.id);
    defer allocator.free(path);
    const q_path = try shellquote.quote(allocator, path);
    defer allocator.free(q_path);
    const q_hash = try shellquote.quote(allocator, facts.ports.nginx_site_sha256);
    defer allocator.free(q_hash);
    var root_guard: []const u8 = "";
    var owned_root_guard: ?[]u8 = null;
    defer if (owned_root_guard) |guard| allocator.free(guard);
    if (app.runtime.type == .react or app.runtime.type == .static) {
        const root_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ app.folder, app.runtime.build_folder });
        defer allocator.free(root_path);
        const q_app = try shellquote.quote(allocator, app.folder);
        defer allocator.free(q_app);
        const q_root = try shellquote.quote(allocator, root_path);
        defer allocator.free(q_root);
        owned_root_guard = try std.fmt.allocPrint(allocator, "APP_ROOT={s}; BUILD_ROOT={s}; REAL_APP=$(readlink -f \"$APP_ROOT\") || exit 1; REAL_BUILD=$(readlink -f \"$BUILD_ROOT\") || exit 1; case \"$REAL_BUILD/\" in \"$REAL_APP/\"*) ;; *) echo 'build folder escapes the application folder'; exit 1;; esac; ", .{ q_app, q_root });
        root_guard = owned_root_guard.?;
    }
    return std.fmt.allocPrint(
        allocator,
        "{s}EXPECTED_SITE_SHA={s}; GUARDED_SITE={s}; if [ -n \"$EXPECTED_SITE_SHA\" ]; then [ -f \"$GUARDED_SITE\" ] && [ \"$(sha256sum \"$GUARDED_SITE\" | awk '{{print $1}}')\" = \"$EXPECTED_SITE_SHA\" ] || {{ echo 'nginx site changed since preflight'; exit 1; }}; else [ ! -e \"$GUARDED_SITE\" ] || {{ echo 'nginx site appeared since preflight'; exit 1; }}; fi; {s}",
        .{ root_guard, q_hash, q_path, command },
    );
}

fn guardDnsCommand(allocator: std.mem.Allocator, app: *const deploy.App, facts: *const Facts, command: []const u8) ![]u8 {
    if (command.len == 0) return allocator.dupe(u8, "");
    const expected = try shellquote.quote(allocator, facts.ports.dns);
    defer allocator.free(expected);
    var probe: std.ArrayList(u8) = .empty;
    defer probe.deinit(allocator);
    for (app.domains) |domain| {
        const q_domain = try shellquote.quote(allocator, domain);
        defer allocator.free(q_domain);
        try probe.appendSlice(allocator, "printf '== %s\\n' ");
        try probe.appendSlice(allocator, q_domain);
        try probe.appendSlice(allocator, "; { dig +short A ");
        try probe.appendSlice(allocator, q_domain);
        try probe.appendSlice(allocator, " 2>/dev/null; dig +short AAAA ");
        try probe.appendSlice(allocator, q_domain);
        try probe.appendSlice(allocator, " 2>/dev/null; } | sort -u; ");
    }
    return std.fmt.allocPrint(
        allocator,
        "EXPECTED_DNS={s}; CURRENT_DNS=$({s}); [ \"$CURRENT_DNS\" = \"$EXPECTED_DNS\" ] || {{ echo 'DNS answers changed since preflight'; exit 1; }}; {s}",
        .{ expected, probe.items, command },
    );
}

/// Derives blockers, warnings, approvals, the frozen plan, config previews,
/// and the guard fingerprint from the gathered facts. Pure: all remote
/// evidence is already in `p.facts`.
pub fn derive(allocator: std.mem.Allocator, p: *Preflight) !void {
    const f = &p.facts;
    const app = &p.app;

    // deploy vs update: an existing matching checkout makes this an update.
    const origin_matches = f.repo.is_git and std.mem.eql(u8, f.repo.origin, app.repo.url);
    p.action = try allocator.dupe(u8, if (origin_matches) "update" else "deploy");

    // --- blockers ---
    if (!supportedOsRelease(f.os_id, f.os_version)) {
        var buf: [160]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "unsupported OS ({s} {s}); v1 supports Ubuntu 22.04/24.04 and Debian 12/13 — install dependencies manually", .{ f.os_pretty, f.os_version }) catch "unsupported OS";
        try addIssue(allocator, &p.blockers, "unsupported_os", msg);
    }
    if (!supportedArch(f.arch)) try addIssue(allocator, &p.blockers, "unsupported_arch", "unsupported CPU architecture (v1 supports x86_64 and aarch64)");
    if (!std.mem.eql(u8, f.libc, "glibc")) try addIssue(allocator, &p.blockers, "unsupported_libc", "unsupported libc (the official Node archives target glibc)");
    if (f.privilege == .none or f.privilege == .unknown) try addIssue(allocator, &p.blockers, "missing_privilege", "nginx and system changes need root or passwordless sudo (sudo -n)");

    if (f.repo.is_git) {
        if (!origin_matches) try addIssue(allocator, &p.blockers, "mismatched_checkout", "the folder contains a different repository (origin does not match)");
        if (f.repo.dirty_files.len > 0) try addIssue(allocator, &p.blockers, "dirty_checkout", "the checkout has local modifications; commit or revert them on the server first");
        if (f.repo.branch.len > 0 and !std.mem.eql(u8, f.repo.branch, app.repo.branch)) {
            var buf: [220]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "the checkout is on branch {s}; the run switches to {s}", .{ f.repo.branch, app.repo.branch }) catch "branch differs";
            try addIssue(allocator, &p.warnings, "branch_switch", msg);
        }
    } else if (f.repo.folder_exists) {
        try addIssue(allocator, &p.blockers, "folder_collision", "the folder exists but is not this repository; Oars never overwrites unknown files");
    }

    if (!f.repo.repo_accessible) {
        if (app.repo.transport == .ssh and !f.repo.deploy_key_present) {
            try addIssue(allocator, &p.blockers, "missing_deploy_key", "create this app's deploy key and add its public key to the repository before deployment");
        } else {
            try addIssue(allocator, &p.blockers, "repo_unreachable", "the repository is not reachable with the configured transport and branch");
        }
    }

    if (app.repo.transport == .ssh) {
        const host = try repoHost(allocator, app.repo.url);
        defer allocator.free(host);
        if (std.mem.eql(u8, host, "github.com")) {
            if (!githubHostKeysMatch(f.repo.scanned_host_keys)) try addIssue(allocator, &p.blockers, "unverifiable_host", "github.com's host key does not match GitHub's published entries");
        } else if (f.repo.scanned_host_keys.len == 0) {
            try addIssue(allocator, &p.blockers, "unverifiable_host", "no SSH host key could be discovered for the git host");
        } else if (f.repo.scanned_host_fingerprints.len == 0) {
            try addIssue(allocator, &p.blockers, "unverifiable_host", "the SSH host-key fingerprint could not be calculated; install the OpenSSH client and run preflight again");
        } else if (!f.repo.known_hosts_present) {
            const detail = try std.fmt.allocPrint(allocator, "compare this SHA-256 fingerprint with a trusted source for {s} before approval:\n{s}", .{ host, f.repo.scanned_host_fingerprints });
            defer allocator.free(detail);
            try addApproval(allocator, &p.approvals, "git-host-key", "Trust this git host key", detail);
        }
    }

    if (f.ports.app_port_in_use and !f.ports.pm2_process_present and (app.runtime.type == .node or app.runtime.type == .next)) {
        try addIssue(allocator, &p.blockers, "port_occupied", "the app port is already in use by another process");
    }
    if (!f.ports.port_probe_ran) try addIssue(allocator, &p.blockers, "port_probe_unavailable", "the server does not provide ss, so Oars cannot check listener conflicts; install iproute2 and run preflight again");
    if (std.mem.eql(u8, f.ports.http_listener, "unknown") or (app.ssl and std.mem.eql(u8, f.ports.https_listener, "unknown"))) try addIssue(allocator, &p.blockers, "listener_probe_incomplete", "Oars could not classify the required web listeners; check ss permissions and run preflight again");
    if (std.mem.eql(u8, f.ports.http_listener, "foreign")) try addIssue(allocator, &p.blockers, "http_port_occupied", "port 80 is owned by a process other than nginx");
    if (app.ssl and std.mem.eql(u8, f.ports.https_listener, "foreign")) try addIssue(allocator, &p.blockers, "https_port_occupied", "port 443 is owned by a process other than nginx");
    if (f.ports.app_port_in_use and f.ports.pm2_process_present) {
        try addIssue(allocator, &p.warnings, "existing_service", "an Oars-managed process already serves this app and is replaced safely");
    }
    if (std.mem.eql(u8, f.ports.nginx_site, "foreign")) {
        try addIssue(allocator, &p.blockers, "nginx_collision", "a non-Oars nginx site already uses this name; remove or rename it manually");
    }
    if (std.mem.eql(u8, f.ports.nginx_site, "ours")) {
        try addApproval(allocator, &p.approvals, "replace-nginx", "Replace the Oars-managed nginx site", "the existing Oars site file is replaced with the reviewed config");
    }
    if (f.ports.pm2_process_present and (app.runtime.type == .react or app.runtime.type == .static)) {
        try addApproval(allocator, &p.approvals, "remove-process", "Remove the old managed process", "the app now serves static files; the previous PM2 process is deleted");
    }

    // Lockfiles → manager decision and frozen-install guarantees.
    const has_npm_lock = std.mem.indexOf(u8, f.repo.lockfiles, "package-lock.json") != null or std.mem.indexOf(u8, f.repo.lockfiles, "npm-shrinkwrap.json") != null;
    const has_pnpm_lock = std.mem.indexOf(u8, f.repo.lockfiles, "pnpm-lock.yaml") != null;
    const has_yarn_lock = std.mem.indexOf(u8, f.repo.lockfiles, "yarn.lock") != null;
    const lock_count: usize = @as(usize, @intFromBool(has_npm_lock)) + @intFromBool(has_pnpm_lock) + @intFromBool(has_yarn_lock);
    if (lock_count > 1) {
        if (app.runtime.package_manager == .auto) {
            try addIssue(allocator, &p.blockers, "conflicting_lockfiles", "several package-manager lockfiles exist; select the package manager explicitly");
        } else {
            try addIssue(allocator, &p.warnings, "ignored_lockfiles", "lockfiles of other package managers are present and ignored");
        }
    }
    if (lock_count == 0 and f.repo.is_git) {
        try addIssue(allocator, &p.warnings, "no_lockfile", "no lockfile: the dependency tree is not frozen");
    }

    // Missing system tools → one system-packages approval with exact names.
    const packages = try missingSystemPackages(allocator, app, f);
    defer allocator.free(packages);
    if (packages.len > 0) {
        var buf: [256]u8 = undefined;
        const detail = std.fmt.bufPrint(&buf, "install with the system package manager: {s}", .{packages}) catch "install missing system packages";
        try addApproval(allocator, &p.approvals, "system-packages", "Install system packages", detail);
    }
    try addApproval(allocator, &p.approvals, "install-node", "Use the reviewed Node release", "install the exact official Node archive under the connected user's home if it is not already present");
    if (app.runtime.type == .node or app.runtime.type == .next) {
        try addApproval(allocator, &p.approvals, "install-pm2", "Use the reviewed PM2 release", "install the exact integrity-checked PM2 release under the connected user's home if it is not already present");
    }
    try addIssue(allocator, &p.warnings, "user_local_runtime", "the reviewed Node.js and PM2 releases use the connected user's home and never replace system-wide runtimes");
    if (f.node_version.len == 0 or f.node_archive.len == 0 or f.node_sha256.len != 64 or f.node_url.len == 0) {
        try addIssue(allocator, &p.blockers, "node_release_unavailable", "the selected Node release or its official SHA-256 manifest could not be resolved");
    } else {
        var prefix_buf: [16]u8 = undefined;
        const expected_prefix = std.fmt.bufPrint(&prefix_buf, "v{s}.", .{app.runtime.node_version}) catch "";
        if (!std.mem.startsWith(u8, f.node_version, expected_prefix) or f.node_lts.len == 0 or std.mem.eql(u8, f.node_lts, "false")) {
            try addIssue(allocator, &p.blockers, "unsupported_node_line", "the selected Node major is not a current production LTS line");
        }
    }
    if ((app.runtime.type == .node or app.runtime.type == .next) and (f.pm2_version.len == 0 or f.pm2_integrity.len == 0)) {
        try addIssue(allocator, &p.blockers, "pm2_release_unavailable", "the current PM2 release metadata could not be resolved from the npm registry");
    }

    // DNS per domain: no answers = blocker; answers that do not meet the
    // local addresses = NAT warning (Oars cannot prove public ingress).
    for (app.domains) |d| {
        const answers = dnsAnswers(f.ports.dns, d);
        var has_answer = false;
        var ait = std.mem.splitScalar(u8, answers, '\n');
        while (ait.next()) |line| {
            const t = std.mem.trim(u8, line, " \t\r");
            if (t.len > 0 and !std.mem.startsWith(u8, t, "==")) has_answer = true;
        }
        if (!has_answer) {
            var buf: [280]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "{s} has no A or AAAA record", .{d}) catch "missing DNS record";
            try addIssue(allocator, &p.blockers, "wrong_dns", msg);
            continue;
        }
        var meets_local = false;
        var lit = std.mem.splitScalar(u8, answers, '\n');
        while (lit.next()) |line| {
            const t = std.mem.trim(u8, line, " \t\r");
            if (t.len == 0 or std.mem.startsWith(u8, t, "==")) continue;
            if (std.mem.indexOf(u8, f.ports.local_addresses, t) != null) meets_local = true;
        }
        if (!meets_local) {
            var buf: [300]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "{s} does not resolve to an address this server shows; behind NAT, public port 80 must reach this server — Oars cannot prove ingress", .{d}) catch "DNS does not meet local addresses";
            try addIssue(allocator, &p.warnings, "nat_unproven", msg);
        }
    }
    if (app.ssl and app.domains.len > 0) {
        try addIssue(allocator, &p.warnings, "http01_boundary", "certbot proves domain control over public port 80; Oars cannot test inbound reachability from the server itself");
    }

    // Command overrides are shell code and shown as such.
    if (app.runtime.install.len > 0 or app.runtime.build.len > 0 or app.runtime.start_command.len > 0) {
        try addIssue(allocator, &p.warnings, "command_overrides", "custom install/build/start shell commands are in use and run exactly as written");
    }

    // A blocked result must remain inspectable. Do not manufacture an
    // executable plan when a required commit, key, tool, or runtime artifact
    // could not be proved by the read-only probes.
    if (p.blockers.items.len > 0) {
        p.target_fingerprint = targetFingerprint(f, app);
        p.status = .blocked;
        return;
    }

    // --- the frozen plan (exact commands + config snapshots) ---
    const plan = try deploy.buildPlan(allocator, app);
    defer {
        for (plan) |*s| s.deinit(allocator);
        allocator.free(plan);
    }
    const frozen = try allocator.alloc(deploy.PlanStep, plan.len);
    var frozen_built: usize = 0;
    errdefer {
        for (frozen[0..frozen_built]) |*s| s.deinit(allocator);
        allocator.free(frozen);
    }
    for (plan, 0..) |*ps, i| {
        frozen[i] = .{
            .id = ps.id,
            .label = try allocator.dupe(u8, ps.label),
            .command = try allocator.dupe(u8, ps.command),
        };
        frozen_built += 1;
    }
    if (f.repo.remote_commit.len == 0) return error.RepositoryCommitMissing;
    const clone_command = try exactCloneCommand(allocator, app, f);
    defer allocator.free(clone_command);
    try replacePlanCommand(allocator, &frozen[@intFromEnum(deploy.StepId.clone)], clone_command);
    const install_command = try exactInstallCommand(allocator, app, f);
    defer allocator.free(install_command);
    try replacePlanCommand(allocator, &frozen[@intFromEnum(deploy.StepId.install)], install_command);
    inline for ([_]deploy.StepId{ .build, .pm2 }) |step_id| {
        const idx = @intFromEnum(step_id);
        const command = try prefixNodePath(allocator, frozen[idx].command, f.node_version, f.pm2_version);
        defer allocator.free(command);
        try replacePlanCommand(allocator, &frozen[idx], command);
    }
    const nginx_index = @intFromEnum(deploy.StepId.nginx);
    const nginx_command = try guardNginxCommand(allocator, app, f, frozen[nginx_index].command);
    defer allocator.free(nginx_command);
    try replacePlanCommand(allocator, &frozen[nginx_index], nginx_command);
    const certbot_index = @intFromEnum(deploy.StepId.certbot);
    const certbot_command = try guardDnsCommand(allocator, app, f, frozen[certbot_index].command);
    defer allocator.free(certbot_command);
    try replacePlanCommand(allocator, &frozen[certbot_index], certbot_command);
    p.plan = frozen;
    const classes = [_]MutationClass{ .files, .files, .files, .process, .service, .certificate };
    const guard_texts = [_][]const u8{
        "folder state is unchanged (origin, branch, clean worktree, same remote commit)",
        "lockfiles are unchanged",
        "",
        "no foreign process owns this process name",
        "any existing site file is still Oars-owned and unchanged",
        "DNS answers are unchanged",
    };
    const rollback_texts = [_][]const u8{
        "git leaves the checkout untouched on a failed clone or non-fast-forward",
        "a failed frozen install leaves node_modules partial; the next run reinstalls",
        "a failed build leaves the running service and files untouched",
        "a failed startOrReload keeps the previous process generation",
        "the prior site file and enabled link are restored and nginx revalidated",
        "the backed-up Oars nginx config is restored and reloaded",
    };
    const skip_reasons = [_][]const u8{ "", "", "", "static app — nginx serves files, no process", "", "SSL is disabled" };
    for (p.plan, 0..) |*ps, i| {
        const skipped = ps.command.len == 0;
        var step = PreflightStep{
            .id = try allocator.dupe(u8, ps.id.jsonName()),
            .label = try allocator.dupe(u8, ps.label),
            .class = classes[i],
            .skipped = skipped,
            .skip_reason = try allocator.dupe(u8, if (skipped) skip_reasons[i] else ""),
            .command = try allocator.dupe(u8, ps.command),
            .rollback = try allocator.dupe(u8, rollback_texts[i]),
        };
        errdefer step.deinit(allocator);
        if (guard_texts[i].len > 0) {
            const guards = try allocator.alloc([]const u8, 1);
            guards[0] = try allocator.dupe(u8, guard_texts[i]);
            step.file_writes = &.{};
            step.guards = guards;
        }
        try p.steps.append(allocator, step);
    }

    // Config snapshots with secrets masked (the preflight never sees values).
    p.nginx_preview = try deploy.nginxConfig(allocator, app);
    var mask: std.ArrayList(deploy.SecretValue) = .empty;
    defer mask.deinit(allocator);
    var env_names: std.ArrayList(u8) = .empty;
    defer env_names.deinit(allocator);
    for (app.env_vars) |v| {
        if (v.secret) try mask.append(allocator, .{ .name = v.name, .value = "***" });
        try env_names.appendSlice(allocator, v.name);
        try env_names.appendSlice(allocator, if (v.secret) "=***\n" else "=");
        if (!v.secret) try env_names.appendSlice(allocator, v.value);
        if (!v.secret) try env_names.append(allocator, '\n');
    }
    p.env_preview = try allocator.dupe(u8, env_names.items);
    if (app.runtime.type == .node or app.runtime.type == .next) {
        const interpreter = try std.fmt.allocPrint(allocator, "{s}/.local/share/oars/node/{s}/bin/node", .{ f.home, f.node_version });
        defer allocator.free(interpreter);
        p.pm2_preview = try deploy.ecosystemFileForInterpreter(allocator, app, mask.items, interpreter);
    } else {
        p.pm2_preview = try allocator.dupe(u8, "");
    }

    p.target_fingerprint = targetFingerprint(f, app);
    p.status = if (p.blockers.items.len > 0) .blocked else .ready;
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test "section parser splits marker-delimited output" {
    const allocator = testing.allocator;
    var sections = try parseSections(allocator, "@os\nID=ubuntu\nVERSION_ID=\"24.04\"\n@arch\nx86_64\n@libc\nldd (Ubuntu GLIBC 2.39-0ubuntu8) 2.39\n");
    defer sections.deinit(allocator);
    try testing.expectEqualStrings("ID=ubuntu\nVERSION_ID=\"24.04\"", sections.get("os"));
    try testing.expectEqualStrings("x86_64", sections.get("arch"));
    try testing.expectEqualStrings("", sections.get("missing"));
}

test "system parser derives os, arch, libc, user, privilege, disk" {
    const allocator = testing.allocator;
    var facts = Facts{};
    defer freeFacts(allocator, &facts);
    try parseSystem(allocator,
        \\@os
        \\PRETTY_NAME="Ubuntu 24.04.2 LTS"
        \\NAME="Ubuntu"
        \\VERSION_ID="24.04"
        \\VERSION="24.04.2 LTS (Noble Numbat)"
        \\ID=ubuntu
        \\ID_LIKE=debian
        \\@arch
        \\aarch64
        \\@libc
        \\ldd (Ubuntu GLIBC 2.39-0ubuntu8.3) 2.39
        \\@uid
        \\1000
        \\@user
        \\deploy
        \\@home
        \\/home/deploy
        \\@priv
        \\sudo
        \\@disk
        \\/dev/sda1  51606140  10509888  38491448  22% /
    , &facts);
    try testing.expectEqualStrings("ubuntu", facts.os_id);
    try testing.expectEqualStrings("24.04", facts.os_version);
    try testing.expectEqualStrings("Ubuntu 24.04.2 LTS", facts.os_pretty);
    try testing.expectEqualStrings("aarch64", facts.arch);
    try testing.expectEqualStrings("glibc", facts.libc);
    try testing.expectEqualStrings("deploy", facts.user);
    try testing.expectEqual(Privilege.sudo, facts.privilege);
    try testing.expectEqual(@as(u64, 38491448), facts.disk_free_kb);
}

test "libc family detection" {
    try testing.expectEqualStrings("glibc", libcFamily("ldd (Ubuntu GLIBC 2.39-0ubuntu8.3) 2.39"));
    try testing.expectEqualStrings("musl", libcFamily("musl libc (aarch64) Version 1.2.5"));
    try testing.expectEqualStrings("unknown", libcFamily(""));
}

test "tools parser records paths and versions" {
    const allocator = testing.allocator;
    var facts = Facts{};
    defer freeFacts(allocator, &facts);
    try parseTools(allocator,
        \\git=/usr/bin/git
        \\curl=/usr/bin/curl
        \\wget=
        \\tar=/bin/tar
        \\sha256sum=/usr/bin/sha256sum
        \\ss=/usr/bin/ss
        \\node=
        \\npm=
        \\corepack=
        \\pm2=
        \\nginx=
        \\certbot=
        \\dig=/usr/bin/dig
        \\@ver
        \\git=2.43.0
        \\nginx=nginx version: nginx/1.24.0
    , &facts);
    try testing.expectEqualStrings("/usr/bin/git", facts.tools.git.path);
    try testing.expectEqualStrings("2.43.0", facts.tools.git.version);
    try testing.expectEqualStrings("", facts.tools.node.path);
    try testing.expectEqualStrings("/usr/bin/dig", facts.tools.dig.path);
}

test "repo parser extracts checkout state and the frozen remote commit" {
    const allocator = testing.allocator;
    var facts = Facts{};
    defer freeFacts(allocator, &facts);
    try parseRepo(allocator,
        \\@exists
        \\yes
        \\@gitdir
        \\yes
        \\@origin
        \\git@github.com:you/storefront.git
        \\@branch
        \\main
        \\@dirty
        \\ M server.js
        \\@head
        \\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        \\@key
        \\present
        \\@knownhosts
        \\missing
        \\@remote
        \\bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/heads/main
        \\@hostkeys
        \\github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
        \\@hostfingerprints
        \\256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com (ED25519)
        \\@lockfiles
        \\package-lock.json
        \\  "packageManager": "npm@11.1.0",
    , &facts);
    try testing.expect(facts.repo.folder_exists);
    try testing.expect(facts.repo.is_git);
    try testing.expectEqualStrings("git@github.com:you/storefront.git", facts.repo.origin);
    try testing.expectEqualStrings(" M server.js", facts.repo.dirty_files);
    try testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", facts.repo.head);
    try testing.expectEqualStrings("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", facts.repo.remote_commit);
    try testing.expect(facts.repo.repo_accessible);
    try testing.expect(facts.repo.deploy_key_present);
    try testing.expect(!facts.repo.known_hosts_present);
    try testing.expect(std.mem.indexOf(u8, facts.repo.scanned_host_keys, "ssh-ed25519") != null);
    try testing.expect(std.mem.indexOf(u8, facts.repo.scanned_host_fingerprints, "SHA256:+DiY3") != null);
    try testing.expect(std.mem.indexOf(u8, facts.repo.package_manager_field, "npm@11.1.0") != null);
}

test "runtime parser records the reviewed LTS release and PM2 integrity" {
    const allocator = testing.allocator;
    var facts = Facts{};
    defer freeFacts(allocator, &facts);
    try parseRuntime(allocator,
        \\@node
        \\version=v24.13.0
        \\archive=node-v24.13.0-linux-x64.tar.xz
        \\sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        \\url=https://nodejs.org/dist/v24.13.0/node-v24.13.0-linux-x64.tar.xz
        \\lts=Krypton
        \\@pm2
        \\version=7.0.3
        \\integrity=sha512-reviewed
    , &facts);
    try testing.expectEqualStrings("v24.13.0", facts.node_version);
    try testing.expectEqualStrings("Krypton", facts.node_lts);
    try testing.expectEqualStrings("7.0.3", facts.pm2_version);
    try testing.expectEqualStrings("sha512-reviewed", facts.pm2_integrity);
}

test "ports parser reads site ownership, port state, and dns" {
    const allocator = testing.allocator;
    var facts = Facts{};
    defer freeFacts(allocator, &facts);
    try parsePorts(allocator,
        \\@port
        \\inuse
        \\@webports
        \\80=nginx
        \\443=foreign
        \\@site
        \\# oars:app=a1 schema=1
        \\@sitehash
        \\0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        \\@enabled
        \\linked
        \\@pm2proc
        \\present
        \\@dns
        \\== storefront.dev
        \\203.0.113.10
        \\@addrs
        \\203.0.113.10 10.0.0.2
    , &facts);
    try testing.expect(facts.ports.app_port_in_use);
    try testing.expectEqualStrings("nginx", facts.ports.http_listener);
    try testing.expectEqualStrings("foreign", facts.ports.https_listener);
    try testing.expectEqualStrings("ours", facts.ports.nginx_site);
    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", facts.ports.nginx_site_sha256);
    try testing.expectEqualStrings("linked", facts.ports.nginx_enabled);
    try testing.expect(facts.ports.pm2_process_present);
    try testing.expect(std.mem.indexOf(u8, facts.ports.dns, "203.0.113.10") != null);
}

test "repo host extraction covers git@, ssh://, and https URLs" {
    const allocator = testing.allocator;
    const a = try repoHost(allocator, "git@github.com:you/x.git");
    defer allocator.free(a);
    try testing.expectEqualStrings("github.com", a);
    const b = try repoHost(allocator, "ssh://git@git.example.com:2222/you/x.git");
    defer allocator.free(b);
    try testing.expectEqualStrings("git.example.com", b);
    try testing.expectEqual(@as(?u16, 2222), repoPort("ssh://git@git.example.com:2222/you/x.git"));
    const scan = try sshKeyscanTarget(allocator, "ssh://git@git.example.com:2222/you/x.git");
    defer allocator.free(scan);
    try testing.expectEqualStrings("-p 2222 'git.example.com'", scan);
    const c = try repoHost(allocator, "https://github.com/you/x.git");
    defer allocator.free(c);
    try testing.expectEqualStrings("github.com", c);
}

test "derive freezes a ready deployment at the reviewed commit and releases" {
    const allocator = testing.allocator;
    const app = try deploy.clone(allocator, .{
        .id = "shop",
        .server_id = "s1",
        .name = "Storefront",
        .folder = "/home/deploy/storefront",
        .repo = .{ .url = "https://example.com/acme/storefront.git", .transport = .https, .branch = "main" },
        .runtime = .{ .node_version = "24", .type = .next, .package_manager = .npm, .build = "npm run build", .entry = "node_modules/next/dist/bin/next", .args = "start" },
        .app_port = 3000,
        .revision = 3,
    });
    var p = Preflight{
        .id = 1,
        .server_id = try allocator.dupe(u8, "s1"),
        .app_id = try allocator.dupe(u8, "shop"),
        .app = app,
        .app_revision = 3,
        .created_at_ms = 1000,
        .expires_at_ms = 1000 + preflight_ttl_ms,
    };
    defer p.deinit(allocator);

    try parseSystem(allocator,
        \\@os
        \\ID=ubuntu
        \\VERSION_ID="24.04"
        \\PRETTY_NAME="Ubuntu 24.04 LTS"
        \\@arch
        \\x86_64
        \\@libc
        \\ldd (Ubuntu GLIBC 2.39) 2.39
        \\@uid
        \\0
        \\@user
        \\deploy
        \\@home
        \\/home/deploy
        \\@priv
        \\root
        \\@disk
        \\/dev/vda1 1000000 1000 999000 1% /home
    , &p.facts);
    try parseTools(allocator,
        \\git=/usr/bin/git
        \\curl=/usr/bin/curl
        \\wget=
        \\tar=/usr/bin/tar
        \\xz=/usr/bin/xz
        \\sha256sum=/usr/bin/sha256sum
        \\readlink=/usr/bin/readlink
        \\ss=/usr/bin/ss
        \\node=
        \\npm=
        \\corepack=
        \\pm2=
        \\nginx=/usr/sbin/nginx
        \\certbot=
        \\dig=/usr/bin/dig
        \\@ver
        \\git=2.43.0
    , &p.facts);
    try parseRepo(allocator,
        \\@exists
        \\yes
        \\@gitdir
        \\yes
        \\@origin
        \\https://example.com/acme/storefront.git
        \\@branch
        \\main
        \\@dirty
        \\@head
        \\1111111111111111111111111111111111111111
        \\@key
        \\missing
        \\@knownhosts
        \\missing
        \\@remote
        \\2222222222222222222222222222222222222222 refs/heads/main
        \\@hostkeys
        \\@hostfingerprints
        \\@lockfiles
        \\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /home/deploy/storefront/package-lock.json
        \\  "packageManager": "npm@11.1.0",
    , &p.facts);
    try parsePorts(allocator,
        \\@port
        \\free
        \\@webports
        \\80=free
        \\443=free
        \\@site
        \\absent
        \\@sitehash
        \\@enabled
        \\absent
        \\@pm2proc
        \\absent
        \\@dns
        \\@addrs
        \\203.0.113.10
    , &p.facts);
    try parseRuntime(allocator,
        \\@node
        \\version=v24.13.0
        \\archive=node-v24.13.0-linux-x64.tar.xz
        \\sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        \\url=https://nodejs.org/dist/v24.13.0/node-v24.13.0-linux-x64.tar.xz
        \\lts=Krypton
        \\@pm2
        \\version=7.0.3
        \\integrity=sha512-reviewed
    , &p.facts);

    try derive(allocator, &p);
    try testing.expectEqual(Status.ready, p.status);
    try testing.expectEqual(@as(usize, 0), p.blockers.items.len);
    try testing.expectEqual(@as(usize, 6), p.plan.len);
    try testing.expect(std.mem.indexOf(u8, p.plan[@intFromEnum(deploy.StepId.clone)].command, "2222222222222222222222222222222222222222") != null);
    try testing.expect(std.mem.indexOf(u8, p.plan[@intFromEnum(deploy.StepId.clone)].command, "checkout --detach") != null);
    try testing.expect(std.mem.indexOf(u8, p.plan[@intFromEnum(deploy.StepId.install)].command, "npm ci") != null);
    try testing.expect(std.mem.indexOf(u8, p.plan[@intFromEnum(deploy.StepId.install)].command, "sha512-reviewed") != null);
}

test "static nginx step rejects a build-folder symlink escape at run time" {
    const allocator = testing.allocator;
    var app = try deploy.clone(allocator, .{
        .id = "site",
        .server_id = "s1",
        .name = "Site",
        .folder = "/home/deploy/site",
        .repo = .{ .url = "https://example.com/site.git", .transport = .https, .branch = "main" },
        .runtime = .{ .node_version = "24", .type = .static, .build_folder = "public" },
    });
    defer deploy.deinit(allocator, &app);
    const guarded = try guardNginxCommand(allocator, &app, &.{}, "echo install-nginx");
    defer allocator.free(guarded);
    try testing.expect(std.mem.indexOf(u8, guarded, "readlink -f") != null);
    try testing.expect(std.mem.indexOf(u8, guarded, "build folder escapes the application folder") != null);
    try testing.expect(std.mem.indexOf(u8, guarded, "echo install-nginx") != null);
}

test "probe commands do not change managed state and quote every dynamic value" {
    const allocator = testing.allocator;
    var app = try deploy.clone(allocator, .{
        .id = "a'1",
        .server_id = "s1",
        .name = "storefront",
        .folder = "/home/ubuntu/my app",
        .repo = .{ .url = "git@github.com:you/storefront.git", .transport = .ssh, .branch = "main" },
        .runtime = .{ .node_version = "22", .type = .node, .entry = "server.js" },
        .domains = &.{"storefront.dev"},
        .app_port = 3000,
    });
    defer deploy.deinit(allocator, &app);
    const probes = try buildProbes(allocator, &app);
    defer for (probes) |p| allocator.free(p);

    const banned = [_][]const u8{ "git pull", "git fetch", "git checkout", "git reset", "git clean", "npm install", "npm ci", "pnpm install", "yarn install", "apt ", "apt-get", "dpkg", "pm2 start", "pm2 delete", "pm2 save", "pm2 resurrect", "nginx -s", "systemctl", "service ", "certbot --nginx", "certbot certonly", "certbot renew", "ssh-keygen -t", "useradd", "usermod", "groupadd", "mount", "umount", "; dd ", "mkfs", "> /", ">>/", "sudo tee", "crontab", "snap ", "curl |", "wget |" };
    for (probes) |probe| {
        for (banned) |verb| {
            try testing.expect(std.mem.indexOf(u8, probe, verb) == null);
        }
    }
    // The folder with the space is quoted in each probe that uses it. System,
    // tool, and Node metadata probes intentionally do not contain app paths.
    try testing.expect(std.mem.indexOf(u8, probes[2], "git -C '/home/ubuntu/my app'") != null);
    try testing.expect(std.mem.indexOf(u8, probes[2], "oars-preflight.XXXXXX") != null);
    try testing.expect(std.mem.indexOf(u8, probes[2], "rm -rf \"$SCRATCH\"") != null);
    try testing.expect(std.mem.indexOf(u8, probes[2], "git clone") != null);
    try testing.expect(std.mem.indexOf(u8, probes[2], "ssh-keygen -E sha256 -lf -") != null);
    try testing.expect(std.mem.indexOf(u8, probes[3], "'/home/ubuntu/my app'") == null);
    try testing.expect(std.mem.indexOf(u8, probes[4], "dist/index.json") != null);
    try testing.expect(std.mem.indexOf(u8, probes[4], "lts=%s") != null);
}

test "preflights registry enforces the cap, expiry, and server eviction" {
    const allocator = testing.allocator;
    var registry = Preflights{ .allocator = allocator };
    defer registry.deinit();
    registry.lock();
    defer registry.unlock();

    var i: usize = 0;
    while (i < deploy.max_uncommitted_preflights) : (i += 1) {
        const app = try deploy.clone(allocator, .{
            .id = "a1",
            .server_id = if (i == 0) "s-other" else "s1",
            .name = "x",
            .folder = "/srv/x",
            .repo = .{ .url = "git@h:y.git", .transport = .ssh, .branch = "main" },
            .runtime = .{ .node_version = "22", .type = .node, .entry = "server.js" },
        });
        const id = try registry.add(.{
            .id = 0,
            .server_id = try allocator.dupe(u8, if (i == 0) "s-other" else "s1"),
            .app_id = try allocator.dupe(u8, "a1"),
            .app = app,
            .app_revision = 1,
            .created_at_ms = 1000,
            .expires_at_ms = 1000 + preflight_ttl_ms,
        });
        try testing.expect(id > 0);
    }
    // The 33rd preflight is rejected.
    const over_app = try deploy.clone(allocator, .{
        .id = "a1",
        .server_id = "s1",
        .name = "x",
        .folder = "/srv/x",
        .repo = .{ .url = "git@h:y.git", .transport = .ssh, .branch = "main" },
        .runtime = .{ .node_version = "22", .type = .node, .entry = "server.js" },
    });
    var over = Preflight{
        .id = 0,
        .server_id = try allocator.dupe(u8, "s1"),
        .app_id = try allocator.dupe(u8, "a1"),
        .app = over_app,
        .app_revision = 1,
        .created_at_ms = 1000,
        .expires_at_ms = 1000 + preflight_ttl_ms,
    };
    try testing.expectError(error.TooManyPreflights, registry.add(over));
    over.deinit(allocator);

    // Server eviction drops only that server's records.
    registry.removeServer("s1");
    try testing.expectEqual(@as(usize, 1), registry.list.items.len);

    // Expiry drops the rest once the TTL passes.
    registry.expire(1000 + preflight_ttl_ms);
    try testing.expectEqual(@as(usize, 0), registry.list.items.len);
}

test "target fingerprint is stable and sensitive to guarded facts" {
    const allocator = testing.allocator;
    var app = try deploy.clone(allocator, .{
        .id = "a1",
        .server_id = "s1",
        .name = "x",
        .folder = "/srv/x",
        .repo = .{ .url = "git@h:y.git", .transport = .ssh, .branch = "main" },
        .runtime = .{ .node_version = "22", .type = .node, .entry = "server.js" },
    });
    defer deploy.deinit(allocator, &app);
    var facts = Facts{};
    facts.os_id = "ubuntu";
    facts.repo.head = "aaaa";
    facts.repo.remote_commit = "bbbb";
    const base = targetFingerprint(&facts, &app);
    const same = targetFingerprint(&facts, &app);
    try testing.expectEqual(base, same);
    facts.repo.remote_commit = "cccc";
    try testing.expect(targetFingerprint(&facts, &app) != base);
    facts.repo.remote_commit = "bbbb";
    facts.ports.app_port_in_use = true;
    try testing.expect(targetFingerprint(&facts, &app) != base);
}
