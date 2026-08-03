//! Script library (spec 06): the Script model, the persistent store
//! (`scripts.json` in the app data directory), and the shell-aware
//! `{{variable}}` template expansion.
//!
//! The expansion contract (spec 06 §5): each placeholder must occupy a
//! shell word by itself. Placeholders inside quotes, command substitutions,
//! parameter expansions, comments, redirection targets, assignments, or at
//! command-name position are rejected before expansion; every accepted
//! placeholder is replaced with a single-quoted shell literal. The script
//! body is user-authored code; this rule only prevents a variable VALUE
//! from adding shell syntax.
//!
//! This module is pure logic — no libssh2, no network, no sessions.

const std = @import("std");
const shellquote = @import("shellquote.zig");

pub const max_body_bytes: usize = 64 * 1024;
pub const max_scripts: usize = 1000;
/// The store file is a plain array of scripts; the read cap is the worst
/// case the save validation permits.
pub const max_store_bytes: usize = max_body_bytes * max_scripts;
pub const max_variables: usize = 64;
pub const max_name_len: usize = 200;
pub const max_description_len: usize = 4096;
pub const max_tag_len: usize = 64;
pub const max_tags: usize = 32;
pub const max_color_len: usize = 16;

/// One run-time variable definition (spec 06 §7). `secret_default` only
/// marks the editor's input mode; run-time secrets come in the run payload.
pub const Variable = struct {
    name: []const u8,
    label: []const u8 = "",
    secret_default: bool = false,
};

/// A stored script. String fields point into whichever allocation owns the
/// containing parse; use `clone`/`deinit` for owned copies.
pub const Script = struct {
    id: []const u8,
    name: []const u8,
    description: []const u8 = "",
    tags: []const []const u8 = &.{},
    color: []const u8 = "",
    body: []const u8,
    variables: []const Variable = &.{},
    created_at: i64 = 0,
    updated_at: i64 = 0,
    run_count: u64 = 0,
    last_run_at: ?i64 = null,
};

/// The wire shape of `oars.scripts.save`. The handler generates the id for
/// creates (`servers.makeId`); the store upserts by id.
pub const ScriptInput = struct {
    id: ?[]const u8 = null,
    name: []const u8,
    description: []const u8 = "",
    tags: []const []const u8 = &.{},
    color: []const u8 = "",
    body: []const u8,
    variables: []const Variable = &.{},
};

pub const SaveError = error{
    MissingId,
    MissingName,
    InvalidName,
    NameTooLong,
    EmptyBody,
    BodyTooLarge,
    InvalidTag,
    TooManyTags,
    InvalidColor,
    InvalidVariable,
    DuplicateVariable,
    TooManyVariables,
    TooManyScripts,
    SerializeFailed,
    StoreCorrupt,
    OutOfMemory,
};

/// Deep-copies a script (all strings duplicated). Caller owns the result.
pub fn clone(allocator: std.mem.Allocator, src: Script) SaveError!Script {
    var out = Script{
        .id = try allocator.dupe(u8, src.id),
        .name = try allocator.dupe(u8, src.name),
        .description = try allocator.dupe(u8, src.description),
        .color = try allocator.dupe(u8, src.color),
        .body = try allocator.dupe(u8, src.body),
        .created_at = src.created_at,
        .updated_at = src.updated_at,
        .run_count = src.run_count,
        .last_run_at = src.last_run_at,
    };
    errdefer deinit(allocator, &out);
    if (src.tags.len > 0) {
        const buf = try allocator.alloc([]const u8, src.tags.len);
        for (src.tags, 0..) |tag, i| {
            buf[i] = try allocator.dupe(u8, tag);
        }
        out.tags = buf;
    }
    if (src.variables.len > 0) {
        const buf = try allocator.alloc(Variable, src.variables.len);
        for (src.variables, 0..) |v, i| {
            buf[i] = .{
                .name = try allocator.dupe(u8, v.name),
                .label = try allocator.dupe(u8, v.label),
                .secret_default = v.secret_default,
            };
        }
        out.variables = buf;
    }
    return out;
}

pub fn deinit(allocator: std.mem.Allocator, script: *Script) void {
    allocator.free(script.id);
    allocator.free(script.name);
    allocator.free(script.description);
    allocator.free(script.color);
    allocator.free(script.body);
    for (script.tags) |tag| allocator.free(tag);
    allocator.free(script.tags);
    for (script.variables) |v| {
        allocator.free(v.name);
        allocator.free(v.label);
    }
    allocator.free(script.variables);
}

/// Variable-name charset: `[A-Za-z_][A-Za-z0-9_]*` — the same rule the
/// template lexer applies to placeholders.
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

/// Validates a save payload (the name is trimmed before storage).
pub fn validate(input: ScriptInput) SaveError!void {
    const name = std.mem.trim(u8, input.name, " \t\r\n");
    if (name.len == 0) return error.MissingName;
    if (name.len > max_name_len) return error.NameTooLong;
    if (hasControlChars(name)) return error.InvalidName;
    if (input.body.len == 0) return error.EmptyBody;
    if (input.body.len > max_body_bytes) return error.BodyTooLarge;
    if (hasControlChars(input.description) or input.description.len > max_description_len) return error.InvalidName;
    if (input.tags.len > max_tags) return error.TooManyTags;
    for (input.tags) |tag| {
        if (tag.len == 0 or tag.len > max_tag_len or hasControlChars(tag)) return error.InvalidTag;
    }
    if (input.color.len > max_color_len or hasControlChars(input.color)) return error.InvalidColor;
    if (input.color.len > 0 and input.color[0] != '#') return error.InvalidColor;
    if (input.variables.len > max_variables) return error.TooManyVariables;
    for (input.variables, 0..) |v, i| {
        if (!validName(v.name)) return error.InvalidVariable;
        if (v.label.len > max_name_len or hasControlChars(v.label)) return error.InvalidVariable;
        for (input.variables[0..i]) |prev| {
            if (std.mem.eql(u8, prev.name, v.name)) return error.DuplicateVariable;
        }
    }
}

// --- store ----------------------------------------------------------------

/// Persistent script library: `scripts.json`, 0600, rewritten wholesale on
/// each mutation (mirrors the servers store). A corrupt file is moved aside
/// under a timestamped name, never silently replaced.
pub const Store = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    mutex: std.atomic.Mutex = .unlocked,

    pub const Loaded = struct {
        parsed: std.json.Parsed([]Script),
        content: ?[]u8,
        quarantined: ?[]const u8 = null,

        pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
            self.parsed.deinit();
            if (self.content) |c| allocator.free(c);
            if (self.quarantined) |q| allocator.free(q);
        }
    };

    pub fn loadParsed(self: *Store, io: std.Io) !Loaded {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.loadParsedLocked(io);
    }

    fn loadParsedLocked(self: *Store, io: std.Io) !Loaded {
        const cwd = std.Io.Dir.cwd();
        const content = cwd.readFileAlloc(io, self.path, self.allocator, .limited(max_store_bytes)) catch return emptyLoaded(self.allocator);
        const parsed = std.json.parseFromSlice([]Script, self.allocator, content, .{}) catch {
            self.allocator.free(content);
            var loaded = try emptyLoaded(self.allocator);
            loaded.quarantined = self.quarantine(io) catch null;
            return loaded;
        };
        return .{ .parsed = parsed, .content = content };
    }

    fn emptyLoaded(allocator: std.mem.Allocator) !Loaded {
        return .{
            .parsed = try std.json.parseFromSlice([]Script, allocator, "[]", .{}),
            .content = null,
        };
    }

    fn quarantine(self: *Store, io: std.Io) !?[]const u8 {
        const now = std.Io.Timestamp.now(io, .real).nanoseconds;
        var buf: [512]u8 = undefined;
        const dir = std.fs.path.dirname(self.path) orelse return null;
        const base = std.fs.path.basename(self.path);
        const new_path = try std.fmt.bufPrint(&buf, "{s}/{s}.corrupt-{d}", .{ dir, base, now });
        std.Io.Dir.renameAbsolute(self.path, new_path, io) catch return null;
        return try self.allocator.dupe(u8, new_path);
    }

    fn saveLocked(self: *Store, io: std.Io, scripts: []const Script) !void {
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(self.path)) |dir| try cwd.createDirPath(io, dir);
        self.tightenPermissions(io);
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        std.json.Stringify.value(scripts, .{ .whitespace = .indent_2 }, &out.writer) catch return error.SerializeFailed;
        var file = try cwd.createFile(io, self.path, .{});
        defer file.close(io);
        if (file.stat(io)) |stat| {
            if (stat.permissions.toMode() & 0o077 != 0) file.setPermissions(io, .fromMode(0o600)) catch {};
        } else |_| {}
        try file.writeStreamingAll(io, out.writer.buffered());
        try file.sync(io);
    }

    fn tightenPermissions(self: *Store, io: std.Io) void {
        const cwd = std.Io.Dir.cwd();
        var file = cwd.openFile(io, self.path, .{ .mode = .read_write }) catch return;
        defer file.close(io);
        const stat = file.stat(io) catch return;
        if (stat.permissions.toMode() & 0o077 != 0) file.setPermissions(io, .fromMode(0o600)) catch {};
    }

    /// Upserts a script by id (the handler generates ids for creates).
    /// Edits preserve `created_at`, `run_count`, and `last_run_at`. Returns
    /// an owned deep copy of the saved script; caller frees with `deinit`.
    pub fn saveScript(self: *Store, io: std.Io, input: ScriptInput, now_ns: i128) SaveError!Script {
        try validate(input);
        const id = input.id orelse return error.MissingId;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);

        var existing: ?Script = null;
        defer {
            if (existing) |*e| deinit(self.allocator, e);
        }
        var is_edit = false;
        for (loaded.parsed.value) |s| {
            if (std.mem.eql(u8, s.id, id)) {
                existing = try clone(self.allocator, s);
                is_edit = true;
                break;
            }
        }
        if (!is_edit and loaded.parsed.value.len >= max_scripts) return error.TooManyScripts;

        const name = std.mem.trim(u8, input.name, " \t\r\n");
        var saved: Script = undefined;
        errdefer deinit(self.allocator, &saved);
        if (existing) |e| {
            saved = try clone(self.allocator, e);
            {
                self.allocator.free(saved.name);
                saved.name = try self.allocator.dupe(u8, name);
                self.allocator.free(saved.description);
                saved.description = try self.allocator.dupe(u8, input.description);
                self.allocator.free(saved.color);
                saved.color = try self.allocator.dupe(u8, input.color);
                self.allocator.free(saved.body);
                saved.body = try self.allocator.dupe(u8, input.body);
                for (saved.tags) |t| self.allocator.free(t);
                self.allocator.free(saved.tags);
                if (input.tags.len > 0) {
                    const buf = try self.allocator.alloc([]const u8, input.tags.len);
                    for (input.tags, 0..) |tag, i| buf[i] = try self.allocator.dupe(u8, tag);
                    saved.tags = buf;
                } else {
                    saved.tags = &.{};
                }
                for (saved.variables) |v| {
                    self.allocator.free(v.name);
                    self.allocator.free(v.label);
                }
                self.allocator.free(saved.variables);
                if (input.variables.len > 0) {
                    const buf = try self.allocator.alloc(Variable, input.variables.len);
                    for (input.variables, 0..) |v, i| {
                        buf[i] = .{
                            .name = try self.allocator.dupe(u8, v.name),
                            .label = try self.allocator.dupe(u8, v.label),
                            .secret_default = v.secret_default,
                        };
                    }
                    saved.variables = buf;
                } else {
                    saved.variables = &.{};
                }
            }
            saved.updated_at = @intCast(now_ns);
        } else {
            saved = .{
                .id = try self.allocator.dupe(u8, id),
                .name = try self.allocator.dupe(u8, name),
                .description = try self.allocator.dupe(u8, input.description),
                .color = try self.allocator.dupe(u8, input.color),
                .body = try self.allocator.dupe(u8, input.body),
                .created_at = @intCast(now_ns),
                .updated_at = @intCast(now_ns),
            };
            if (input.tags.len > 0) {
                const buf = try self.allocator.alloc([]const u8, input.tags.len);
                for (input.tags, 0..) |tag, i| buf[i] = try self.allocator.dupe(u8, tag);
                saved.tags = buf;
            }
            if (input.variables.len > 0) {
                const buf = try self.allocator.alloc(Variable, input.variables.len);
                for (input.variables, 0..) |v, i| {
                    buf[i] = .{
                        .name = try self.allocator.dupe(u8, v.name),
                        .label = try self.allocator.dupe(u8, v.label),
                        .secret_default = v.secret_default,
                    };
                }
                saved.variables = buf;
            }
        }

        // Persist the whole list with this script placed (edit) or added.
        var list: std.ArrayList(Script) = .empty;
        defer {
            for (list.items) |*s| deinit(self.allocator, s);
            list.deinit(self.allocator);
        }
        for (loaded.parsed.value) |s| {
            if (std.mem.eql(u8, s.id, id)) continue; // replaced by `saved`
            try list.append(self.allocator, try clone(self.allocator, s));
        }
        // The edited or fresh script always lands in the list (the loop
        // above skipped the old copy of an edit).
        try list.append(self.allocator, try clone(self.allocator, saved));
        self.saveLocked(io, list.items) catch return error.SerializeFailed;
        return saved;
    }

    /// Deletes a script; returns whether it existed.
    pub fn delete(self: *Store, io: std.Io, id: []const u8) SaveError!bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        var found = false;
        var list: std.ArrayList(Script) = .empty;
        defer {
            for (list.items) |*s| deinit(self.allocator, s);
            list.deinit(self.allocator);
        }
        for (loaded.parsed.value) |existing| {
            if (std.mem.eql(u8, existing.id, id)) {
                found = true;
                continue;
            }
            try list.append(self.allocator, try clone(self.allocator, existing));
        }
        if (found) self.saveLocked(io, list.items) catch return error.SerializeFailed;
        return found;
    }

    /// Returns an owned deep copy of the script with `id`, or null.
    pub fn find(self: *Store, io: std.Io, id: []const u8) SaveError!?Script {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        for (loaded.parsed.value) |existing| {
            if (std.mem.eql(u8, existing.id, id)) return try clone(self.allocator, existing);
        }
        return null;
    }

    /// Bumps `run_count` and `last_run_at` (spec 06 §7). No-op when the
    /// script is gone.
    pub fn touchRun(self: *Store, io: std.Io, id: []const u8, now_ns: i128) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return;
        defer loaded.deinit(self.allocator);
        var changed = false;
        var list: std.ArrayList(Script) = .empty;
        defer {
            for (list.items) |*s| deinit(self.allocator, s);
            list.deinit(self.allocator);
        }
        for (loaded.parsed.value) |existing| {
            var item = clone(self.allocator, existing) catch return;
            if (std.mem.eql(u8, existing.id, id)) {
                item.run_count +|= 1;
                item.last_run_at = @intCast(now_ns);
                changed = true;
            }
            list.append(self.allocator, item) catch return;
        }
        if (changed) self.saveLocked(io, list.items) catch {};
    }
};

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// --- template expansion ------------------------------------------------------

pub const RunVar = struct {
    name: []const u8,
    value: []const u8,
    secret: bool = false,
};

pub const ExpandError = error{
    UnterminatedPlaceholder,
    InvalidPlaceholderName,
    AmbiguousPlaceholder,
    MissingVariable,
    MultilineValue,
    TooManyVariables,
    OutOfMemory,
};

/// One resolved placeholder, in first-use order.
pub const NameInfo = struct {
    /// Owned.
    name: []const u8,
    secret: bool,
};

pub const Expansion = struct {
    /// Owned expanded command (values single-quoted).
    command: []u8,
    /// Owned copy of the command with secret values masked as `***`
    /// (for audit; spec 06 §8).
    redacted: []u8,
    /// Owned variable names in first-use order (deduped) + secret flags.
    names: []NameInfo,

    pub fn deinit(self: *Expansion, allocator: std.mem.Allocator) void {
        allocator.free(self.command);
        allocator.free(self.redacted);
        for (self.names) |n| allocator.free(n.name);
        allocator.free(self.names);
    }
};

/// Shell-syntax characters a placeholder must not TOUCH (spec 06 §5:
/// "placeholders inside quotes, redirections, command names, assignments,
/// or shell syntax are rejected"). Whitespace and ordinary word characters
/// may border a placeholder — the spec's own example body is
/// `tail -f /var/log/{{service}}/error.log`, where the quoted value merges
/// into a path word. The characters after `}}` that would change the word's
/// parse are a subset (`=`, quotes, expansions, braces).
fn isSyntax(ch: u8) bool {
    return switch (ch) {
        ';', '&', '|', '(', ')', '>', '<', '=', '\'', '"', '`', '$', '#', '\\', '{', '}' => true,
        else => false,
    };
}

/// Characters that must not follow a placeholder: they would splice the
/// substituted word into an assignment or quoting context.
fn isBadAfter(ch: u8) bool {
    return switch (ch) {
        '=', '\'', '"', '`', '$', '\\', '{', '}' => true,
        else => false,
    };
}

const VarRef = struct {
    /// Slice into the body.
    name: []const u8,
    /// Position of the opening `{{`.
    pos: usize,
    /// One past the closing `}}`.
    end: usize,
};

/// Shell-aware scan for `{{name}}` placeholders. Rejects every ambiguous
/// context (spec 06 §5) and returns the refs in body order.
fn scanBody(allocator: std.mem.Allocator, body: []const u8) ExpandError![]VarRef {
    var refs: std.ArrayList(VarRef) = .empty;
    errdefer refs.deinit(allocator);
    var squote = false;
    var dquote = false;
    var dquote_esc = false;
    var backtick = false;
    var comment = false;
    var subst_depth: usize = 0; // $(...) and ${...}
    var word_start = true;
    var at_command = true;
    var i: usize = 0;
    while (i < body.len) {
        const ch = body[i];
        // A placeholder in ANY non-executing or quoting context is rejected
        // (spec 06 §5) rather than silently skipped: the UI's variable table
        // must match what actually executes.
        const placeholder_here = ch == '{' and i + 1 < body.len and body[i + 1] == '{';
        if (comment) {
            if (placeholder_here) return error.AmbiguousPlaceholder;
            if (ch == '\n') {
                comment = false;
                word_start = true;
                at_command = true;
            }
            i += 1;
            continue;
        }
        if (squote) {
            if (placeholder_here) return error.AmbiguousPlaceholder;
            if (ch == '\'') squote = false;
            i += 1;
            continue;
        }
        if (dquote) {
            if (placeholder_here) return error.AmbiguousPlaceholder;
            if (dquote_esc) {
                dquote_esc = false;
            } else if (ch == '\\') {
                dquote_esc = true;
            } else if (ch == '"') {
                dquote = false;
            }
            i += 1;
            continue;
        }
        if (backtick) {
            if (placeholder_here) return error.AmbiguousPlaceholder;
            if (ch == '`') backtick = false;
            i += 1;
            continue;
        }
        if (subst_depth > 0) {
            if (placeholder_here) return error.AmbiguousPlaceholder;
            if (ch == '$' and i + 1 < body.len and (body[i + 1] == '(' or body[i + 1] == '{')) {
                subst_depth += 1;
                i += 2;
            } else if (ch == '(') {
                subst_depth += 1;
                i += 1;
            } else if (ch == ')' or ch == '}') {
                subst_depth -= 1;
                i += 1;
            } else {
                i += 1;
            }
            continue;
        }
        switch (ch) {
            ' ', '\t', '\r' => {
                word_start = true;
                i += 1;
            },
            '\n' => {
                word_start = true;
                at_command = true;
                i += 1;
            },
            ';', '&', '|', '(', ')' => {
                word_start = true;
                at_command = true;
                i += 1;
            },
            '>', '<' => {
                word_start = true;
                at_command = true;
                i += 1;
            },
            '\'', '"', '`', '\\' => {
                // Quote toggles below; a top-level backslash (line
                // continuation) is a boundary.
                switch (ch) {
                    '\'' => squote = true,
                    '"' => dquote = true,
                    '`' => backtick = true,
                    else => {},
                }
                word_start = true;
                i += 1;
            },
            '$' => {
                if (i + 1 < body.len and (body[i + 1] == '(' or body[i + 1] == '{')) {
                    subst_depth += 1;
                    i += 2;
                } else {
                    word_start = true;
                    i += 1;
                }
            },
            '#' => {
                if (word_start) {
                    comment = true;
                    i += 1;
                } else {
                    word_start = false;
                    i += 1;
                }
            },
            '{' => {
                if (i + 1 < body.len and body[i + 1] == '{') {
                    if (at_command) return error.AmbiguousPlaceholder;
                    if (i > 0 and isSyntax(body[i - 1])) return error.AmbiguousPlaceholder;
                    const close = std.mem.indexOfPos(u8, body, i + 2, "}}") orelse return error.UnterminatedPlaceholder;
                    const name = body[i + 2 .. close];
                    if (!validName(name)) return error.InvalidPlaceholderName;
                    if (close + 2 < body.len and isBadAfter(body[close + 2])) return error.AmbiguousPlaceholder;
                    refs.append(allocator, .{ .name = name, .pos = i, .end = close + 2 }) catch return error.OutOfMemory;
                    if (refs.items.len > max_variables) return error.TooManyVariables;
                    i = close + 2;
                    word_start = true;
                } else {
                    word_start = true;
                    i += 1;
                }
            },
            '}' => {
                word_start = true;
                i += 1;
            },
            else => {
                word_start = false;
                at_command = false;
                i += 1;
            },
        }
    }
    return refs.toOwnedSlice(allocator);
}

fn findVar(vars: []const RunVar, name: []const u8) ?*const RunVar {
    for (vars) |*v| {
        if (std.mem.eql(u8, v.name, name)) return v;
    }
    return null;
}

/// Appends the single-quoted form of `value` to `list`.
fn appendQuoted(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    const quoted = try shellquote.quote(allocator, value);
    defer allocator.free(quoted);
    try list.appendSlice(allocator, quoted);
}

/// Expands the template. Every referenced variable must be present (no
/// partial substitution); multiline values are rejected (v1). Values are
/// single-quoted; secret values are masked with `***` in `redacted`.
/// On `error.MissingVariable`, `missing_out` (if given) receives the name
/// (a slice into `body`).
pub fn expandTemplate(
    allocator: std.mem.Allocator,
    body: []const u8,
    vars: []const RunVar,
    missing_out: ?*[]const u8,
) ExpandError!Expansion {
    const refs = try scanBody(allocator, body);
    defer allocator.free(refs);

    // Presence + multiline checks first: no partial substitution.
    for (refs) |ref| {
        const v = findVar(vars, ref.name) orelse {
            if (missing_out) |m| m.* = ref.name;
            return error.MissingVariable;
        };
        if (std.mem.indexOfAny(u8, v.value, "\r\n") != null) return error.MultilineValue;
    }

    var cmd: std.ArrayList(u8) = .empty;
    defer cmd.deinit(allocator);
    var red: std.ArrayList(u8) = .empty;
    defer red.deinit(allocator);
    var names: std.ArrayList(NameInfo) = .empty;
    defer names.deinit(allocator);

    var seg: usize = 0;
    for (refs) |ref| {
        const v = findVar(vars, ref.name).?;
        cmd.appendSlice(allocator, body[seg..ref.pos]) catch return error.OutOfMemory;
        red.appendSlice(allocator, body[seg..ref.pos]) catch return error.OutOfMemory;
        try appendQuoted(&cmd, allocator, v.value);
        if (v.secret) {
            red.appendSlice(allocator, "***") catch return error.OutOfMemory;
        } else {
            try appendQuoted(&red, allocator, v.value);
        }
        var seen = false;
        for (names.items) |n| {
            if (std.mem.eql(u8, n.name, ref.name)) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            const owned = allocator.dupe(u8, ref.name) catch return error.OutOfMemory;
            names.append(allocator, .{ .name = owned, .secret = v.secret }) catch {
                allocator.free(owned);
                return error.OutOfMemory;
            };
        }
        seg = ref.end;
    }
    cmd.appendSlice(allocator, body[seg..]) catch return error.OutOfMemory;
    red.appendSlice(allocator, body[seg..]) catch return error.OutOfMemory;

    return .{
        .command = cmd.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .redacted = red.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .names = names.toOwnedSlice(allocator) catch return error.OutOfMemory,
    };
}

// --- tests -----------------------------------------------------------------

const testing = std.testing;

test "store round trip: save, find, edit preserves history, delete" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [128]u8 = undefined;
    const dir_name = try std.fmt.bufPrint(&dir_buf, "oars-scripts-test-{d}", .{now});
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/{s}/scripts.json", .{dir_name});
    defer std.Io.Dir.cwd().deleteTree(io, dir_name) catch {};

    var store = Store{ .allocator = allocator, .path = path };

    // Create.
    var created = try store.saveScript(io, .{
        .id = "sc1",
        .name = "tail errors",
        .description = "tail the error log",
        .tags = &.{ "logs", "diagnostics" },
        .color = "#ff6b6b",
        .body = "tail -f /var/log/{{service}}/error.log",
        .variables = &.{.{ .name = "service", .label = "Service name" }},
    }, now);
    defer deinit(allocator, &created);
    try testing.expectEqualStrings("tail errors", created.name);
    try testing.expect(created.created_at == created.updated_at);
    try testing.expectEqual(@as(u64, 0), created.run_count);

    // Find.
    var found = (try store.find(io, created.id)) orelse return error.TestUnexpectedResult;
    defer deinit(allocator, &found);
    try testing.expectEqualStrings("tail -f /var/log/{{service}}/error.log", found.body);
    try testing.expectEqual(@as(usize, 1), found.variables.len);
    try testing.expectEqualStrings("service", found.variables[0].name);
    try testing.expectEqualStrings("logs", found.tags[0]);

    // Edit preserves created_at and run stats; updates the body.
    var edited = try store.saveScript(io, .{
        .id = "sc1",
        .name = "tail errors v2",
        .body = "tail -n 200 /var/log/{{service}}/error.log",
        .variables = &.{.{ .name = "service", .label = "Service" }},
    }, now + 1);
    defer deinit(allocator, &edited);
    try testing.expectEqual(created.created_at, edited.created_at);
    try testing.expectEqualStrings("tail errors v2", edited.name);
    try testing.expect(std.mem.indexOf(u8, edited.body, "-n 200") != null);
    try testing.expectEqual(@as(usize, 0), edited.tags.len);

    // run_count bump.
    store.touchRun(io, "sc1", now + 2);
    var after_run = (try store.find(io, "sc1")) orelse return error.TestUnexpectedResult;
    defer deinit(allocator, &after_run);
    try testing.expectEqual(@as(u64, 1), after_run.run_count);
    try testing.expect(after_run.last_run_at != null);

    // Delete.
    try testing.expect(try store.delete(io, "sc1"));
    try testing.expect(!(try store.delete(io, "sc1")));
    try testing.expect((try store.find(io, "sc1")) == null);
}

test "save validation rejects bad payloads" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [128]u8 = undefined;
    const dir_name = try std.fmt.bufPrint(&dir_buf, "oars-scripts-valid-{d}", .{now});
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/{s}/scripts.json", .{dir_name});
    defer std.Io.Dir.cwd().deleteTree(io, dir_name) catch {};
    var store = Store{ .allocator = allocator, .path = path };

    try testing.expectError(error.MissingId, store.saveScript(io, .{ .name = "x", .body = "y" }, now));
    try testing.expectError(error.MissingName, store.saveScript(io, .{ .id = "a", .name = "  ", .body = "x" }, now));
    try testing.expectError(error.EmptyBody, store.saveScript(io, .{ .id = "a", .name = "ok", .body = "" }, now));

    var big: [max_body_bytes + 1]u8 = undefined;
    @memset(&big, 'a');
    try testing.expectError(error.BodyTooLarge, store.saveScript(io, .{ .id = "a", .name = "ok", .body = &big }, now));

    try testing.expectError(
        error.InvalidVariable,
        store.saveScript(io, .{ .id = "a", .name = "ok", .body = "x", .variables = &.{.{ .name = "bad-name" }} }, now),
    );
    try testing.expectError(
        error.DuplicateVariable,
        store.saveScript(io, .{ .id = "a", .name = "ok", .body = "x", .variables = &.{ .{ .name = "a" }, .{ .name = "a" } } }, now),
    );
    try testing.expectError(error.InvalidTag, store.saveScript(io, .{ .id = "a", .name = "ok", .body = "x", .tags = &.{"bad\x01tag"} }, now));
}

test "corrupt store file is quarantined, not replaced silently" {
    const allocator = testing.allocator;
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    var dir_buf: [128]u8 = undefined;
    const dir_name = try std.fmt.bufPrint(&dir_buf, "oars-scripts-quar-{d}", .{now});
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/{s}/scripts.json", .{dir_name});
    defer std.Io.Dir.cwd().deleteTree(io, dir_name) catch {};
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, std.fs.path.dirname(path).?);
    try cwd.writeFile(io, .{ .sub_path = path, .data = "{corrupt" });
    var store = Store{ .allocator = allocator, .path = path };

    var loaded = try store.loadParsed(io);
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), loaded.parsed.value.len);
    try testing.expect(loaded.quarantined != null);
    // The damage is visible: the corrupt file was moved aside.
    try cwd.access(io, loaded.quarantined.?, .{});
}

test "template expansion accepts whole-word placeholders" {
    const allocator = testing.allocator;
    const vars = [_]RunVar{
        .{ .name = "service", .value = "nginx" },
        .{ .name = "msg", .value = "hello world" },
    };
    var exp = try expandTemplate(allocator, "tail -f /var/log/{{service}}/error.log", &vars, null);
    defer exp.deinit(allocator);
    try testing.expectEqualStrings("tail -f /var/log/'nginx'/error.log", exp.command);
    try testing.expectEqual(@as(usize, 1), exp.names.len);
    try testing.expectEqualStrings("service", exp.names[0].name);

    var exp2 = try expandTemplate(allocator, "echo {{msg}}; echo {{msg}}", &vars, null);
    defer exp2.deinit(allocator);
    try testing.expectEqualStrings("echo 'hello world'; echo 'hello world'", exp2.command);
    try testing.expectEqual(@as(usize, 1), exp2.names.len); // deduped

    // Empty value becomes an empty quoted word.
    const empty_vars = [_]RunVar{.{ .name = "x", .value = "" }};
    var exp3 = try expandTemplate(allocator, "touch {{x}}", &empty_vars, null);
    defer exp3.deinit(allocator);
    try testing.expectEqualStrings("touch ''", exp3.command);
}

test "injection values stay literal inside single quotes" {
    const allocator = testing.allocator;
    const vars = [_]RunVar{
        .{ .name = "x", .value = "$(rm -rf /); echo pwned; touch /tmp/oars-pwned" },
    };
    var exp = try expandTemplate(allocator, "echo {{x}}", &vars, null);
    defer exp.deinit(allocator);
    try testing.expectEqualStrings("echo '$(rm -rf /); echo pwned; touch /tmp/oars-pwned'", exp.command);
    try testing.expect(std.mem.indexOf(u8, exp.command, "';") == null); // no unquoted splice
}

test "template lexer rejects ambiguous contexts" {
    const allocator = testing.allocator;
    const vars = [_]RunVar{.{ .name = "x", .value = "v" }};

    // Mid-word placeholders are legal: the quoted value merges into the
    // word (the spec's own example is `/var/log/{{service}}/error.log`).
    var mid = try expandTemplate(allocator, "echo {{x}}y; ech{{x}}o hi", &vars, null);
    defer mid.deinit(allocator);
    try testing.expectEqualStrings("echo 'v'y; ech'v'o hi", mid.command);
    // Assignment.
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "a={{x}}", &vars, null));
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "echo {{x}}=y", &vars, null));
    // Command-name position.
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "{{x}} --flag", &vars, null));
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "echo a; {{x}}", &vars, null));
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "echo a && {{x}}", &vars, null));
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "echo a | {{x}}", &vars, null));
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "( {{x}} )", &vars, null));
    // Redirection target.
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "echo hi > {{x}}", &vars, null));
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "cat < {{x}}", &vars, null));
    // Inside quotes and substitutions.
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "echo '{{x}}'", &vars, null));
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "echo \"{{x}}\"", &vars, null));
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "echo `{{x}}`", &vars, null));
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "echo $({{x}})", &vars, null));
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "echo ${a{{x}}}", &vars, null));
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "echo $'{{x}}'", &vars, null));
    // In a comment.
    try testing.expectError(error.AmbiguousPlaceholder, expandTemplate(allocator, "echo hi # {{x}}", &vars, null));
    // Unterminated / invalid names.
    try testing.expectError(error.UnterminatedPlaceholder, expandTemplate(allocator, "echo {{x", &vars, null));
    try testing.expectError(error.InvalidPlaceholderName, expandTemplate(allocator, "echo {{bad-name}}", &vars, null));
    try testing.expectError(error.InvalidPlaceholderName, expandTemplate(allocator, "echo {{x y}}", &vars, null));
    // Braces that are not placeholders pass through.
    var exp = try expandTemplate(allocator, "echo {a,b}", &vars, null);
    defer exp.deinit(allocator);
    try testing.expectEqualStrings("echo {a,b}", exp.command);
}

test "missing variables and multiline values are refused before substitution" {
    const allocator = testing.allocator;
    const vars = [_]RunVar{.{ .name = "a", .value = "1" }};
    var missing: []const u8 = undefined;
    try testing.expectError(error.MissingVariable, expandTemplate(allocator, "echo {{a}} {{b}}", &vars, &missing));
    try testing.expectEqualStrings("b", missing);

    const multiline = [_]RunVar{.{ .name = "x", .value = "a\nb" }};
    try testing.expectError(error.MultilineValue, expandTemplate(allocator, "echo {{x}}", &multiline, null));
}

test "secret values are masked in the redacted command" {
    const allocator = testing.allocator;
    const vars = [_]RunVar{
        .{ .name = "user", .value = "alice" },
        .{ .name = "pass", .value = "s3cret", .secret = true },
    };
    var exp = try expandTemplate(allocator, "mysql -u {{user}} --password {{pass}}", &vars, null);
    defer exp.deinit(allocator);
    try testing.expectEqualStrings("mysql -u 'alice' --password 's3cret'", exp.command);
    try testing.expectEqualStrings("mysql -u 'alice' --password ***", exp.redacted);
    try testing.expectEqual(@as(usize, 2), exp.names.len);
    try testing.expect(!exp.names[0].secret);
    try testing.expect(exp.names[1].secret);
}
