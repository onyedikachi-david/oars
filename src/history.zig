//! Spec 15: command history + audit journals.
//!
//! Two bounded JSON Lines journals in the app data directory:
//!   history.jsonl — committed interactive + app-initiated commands
//!     (searchable, replayable, redacted at write time), capped at 2,000.
//!   audit.jsonl — one record per mutating product action, capped at 5,000.
//!
//! Both are local, clearable logs — not tamper-proof records (spec 15 §2
//! non-goals). Appends are O(1) between compactions; the in-memory index is
//! authoritative for reads (spec 15 §9: list queries never re-parse the
//! whole journal). Redaction is applied at write time with the secrets the
//! operation knew; the store's own pass masks narrow, named fields such as
//! `PASSWORD=…`, `TOKEN=…`, `--password …`, and URL passwords — never a
//! blanket `-p` (spec 15 §8).

const std = @import("std");
const json = @import("json.zig");

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

pub const history_cap: usize = 2_000;
pub const audit_cap: usize = 5_000;

/// Longest stored command (spec 15 §10). Longer commands are truncated
/// at write time; the executed text is never affected.
pub const command_cap: usize = 4 * 1024;
/// Longest stored output snippet (first two lines of output).
pub const snippet_cap: usize = 512;

/// The redaction marker rendered in place of a masked value.
pub const mask = "\u{2022}\u{2022}\u{2022}\u{2022}";

// --- redaction -------------------------------------------------------------

/// Named fields whose value is a secret (spec 15 §8: narrow, named — the
/// list must not grow a blanket `-p`).
const secret_names = [_][]const u8{
    "password",       "passwd",       "pwd",           "passphrase",
    "token",          "secret",       "api-key",       "apikey",
    "api_key",        "access-key",   "access_key",    "secret-key",
    "secret_key",     "auth-token",   "auth_token",    "session-token",
    "session_token",  "client-secret", "client_secret", "private-key",
    "private_key",    "consumer-secret", "consumer_secret",
    "signing-key",    "signing_key",  "encryption-key", "encryption_key",
};

fn eqIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

fn nameIsSecret(name: []const u8) bool {
    for (secret_names) |candidate| {
        if (eqIgnoreCase(name, candidate)) return true;
    }
    return false;
}

fn isWordChar(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '-';
}

fn isNameStart(ch: u8) bool {
    return std.ascii.isAlphabetic(ch) or ch == '_';
}

/// One past the end of the value token starting at `start`: up to
/// unquoted whitespace, or past the closing quote when the value begins
/// with a quote (the whole quoted token is masked).
fn valueEnd(command: []const u8, start: usize) usize {
    const ch = command[start];
    if (ch == '\'' or ch == '"') {
        var j = start + 1;
        while (j < command.len) : (j += 1) {
            if (command[j] == ch) return j + 1;
        }
        return command.len;
    }
    var j = start;
    while (j < command.len and command[j] != ' ' and command[j] != '\t' and command[j] != '\n' and command[j] != '\r') j += 1;
    return j;
}

/// One past the password in `scheme://user:pass@…`, or null when the text
/// after `://` has no `user:pass@` userinfo (no colon, empty password, or
/// whitespace/`/` inside the userinfo span).
fn urlPasswordEnd(command: []const u8, after_scheme: usize) ?usize {
    var k = after_scheme + 3; // past "://"
    var colon: ?usize = null;
    while (k < command.len) : (k += 1) {
        const ch = command[k];
        if (ch == ' ' or ch == '\t' or ch == '/' or ch == '\n' or ch == '\r') return null;
        if (ch == '@') {
            const c = colon orelse return null;
            if (c + 1 >= k) return null; // empty password
            return k + 1;
        }
        if (ch == ':' and colon == null) colon = k;
    }
    return null;
}

pub const Redacted = struct {
    /// Owned masked text.
    text: []u8,
    /// True when at least one span was masked.
    redacted: bool,
};

/// Exact-value pass: masks every occurrence of each secret value
/// (longest match wins at each position, so `abc` is not half-masked by
/// `ab`). Used for text the operation's own secrets may have flowed into
/// — commands AND output snippets (spec 15 §8: secrets known to the
/// operation are absent from stored text).
pub fn exactMask(allocator: std.mem.Allocator, text: []const u8, secrets: []const []const u8) !Redacted {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var masked = false;
    var i: usize = 0;
    while (i < text.len) {
        var best_len: usize = 0;
        for (secrets) |s| {
            if (s.len == 0 or s.len <= best_len) continue;
            if (i + s.len <= text.len and std.mem.eql(u8, text[i .. i + s.len], s)) best_len = s.len;
        }
        if (best_len > 0) {
            try out.appendSlice(allocator, mask);
            masked = true;
            i += best_len;
        } else {
            try out.append(allocator, text[i]);
            i += 1;
        }
    }
    return .{ .text = try out.toOwnedSlice(allocator), .redacted = masked };
}

/// Narrow named-field pass (spec 15 §8): `PASSWORD=…`, `TOKEN=…`,
/// `--password …`, URL userinfo — never a blanket `-p`. This is the
/// store's second pass; exact values are masked first by `exactMask`.
pub fn patternMask(allocator: std.mem.Allocator, command: []const u8) !Redacted {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var masked = false;
    var i: usize = 0;
    const n = command.len;
    while (i < n) {
        const ch = command[i];
        if (ch == '-' and i + 2 < n and command[i + 1] == '-') {
            // Long option: --name value | --name=value.
            var j = i + 2;
            while (j < n and isWordChar(command[j])) j += 1;
            if (j > i + 2 and nameIsSecret(command[i + 2 .. j])) {
                var value_start: ?usize = null;
                if (j < n and command[j] == '=') {
                    value_start = j + 1;
                } else if (j < n and (command[j] == ' ' or command[j] == '\t')) {
                    var k = j;
                    while (k < n and (command[k] == ' ' or command[k] == '\t')) k += 1;
                    value_start = k;
                }
                if (value_start) |vs| {
                    if (vs < n) {
                        const vend = valueEnd(command, vs);
                        try out.appendSlice(allocator, command[i..vs]);
                        try out.appendSlice(allocator, mask);
                        masked = true;
                        i = vend;
                        continue;
                    }
                }
            }
            try out.append(allocator, ch);
            i += 1;
            continue;
        }
        if (isNameStart(ch) and (i == 0 or !isWordChar(command[i - 1]))) {
            // Assignment: NAME=value at a word boundary.
            var j = i;
            while (j < n and (std.ascii.isAlphanumeric(command[j]) or command[j] == '_')) j += 1;
            if (j < n and command[j] == '=' and nameIsSecret(command[i..j])) {
                const vs = j + 1;
                if (vs < n) {
                    const vend = valueEnd(command, vs);
                    try out.appendSlice(allocator, command[i..vs]);
                    try out.appendSlice(allocator, mask);
                    masked = true;
                    i = vend;
                    continue;
                }
            }
        }
        if (ch == ':' and i + 2 < n and command[i + 1] == '/' and command[i + 2] == '/') {
            // URL userinfo: keep `scheme://user:`, mask the password. The
            // '@' is left for the next iteration (i = pend - 1).
            if (urlPasswordEnd(command, i)) |pend| {
                var k = i + 3;
                while (k < pend and command[k] != ':') k += 1;
                if (k < pend) {
                    try out.appendSlice(allocator, command[i .. k + 1]);
                    try out.appendSlice(allocator, mask);
                    masked = true;
                    i = pend - 1;
                    continue;
                }
            }
        }
        try out.append(allocator, ch);
        i += 1;
    }
    return .{ .text = try out.toOwnedSlice(allocator), .redacted = masked };
}

/// Redaction for stored command text: exact secret values first (the
/// operation's known secrets), then the narrow named-field pass. Output
/// snippets get `exactMask` only — patterns describe command syntax, not
/// program output.
pub fn redact(allocator: std.mem.Allocator, command: []const u8, secrets: []const []const u8) !Redacted {
    if (secrets.len == 0) return patternMask(allocator, command);
    const exact = try exactMask(allocator, command, secrets);
    defer allocator.free(exact.text);
    var pattern = try patternMask(allocator, exact.text);
    pattern.redacted = pattern.redacted or exact.redacted;
    return pattern;
}

// --- journal file helpers --------------------------------------------------

/// Appends one JSON line to a journal: O(1) positional write + fsync so a
/// recorded entry survives a crash (spec 15 §13).
fn appendLine(io: std.Io, path: []const u8, line: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |dir| try cwd.createDirPath(io, dir);
    var file = try cwd.createFile(io, path, .{ .truncate = false });
    defer file.close(io);
    const end = (try file.stat(io)).size;
    try file.writePositionalAll(io, line, end);
    try file.sync(io);
}

/// Atomically rewrites a journal (temp + rename) with the caller's lines.
fn rewriteJournal(io: std.Io, path: []const u8, lines: []const []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |dir| try cwd.createDirPath(io, dir);
    var tmp_buf: [2048]u8 = undefined;
    const tmp = std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path}) catch return error.PathTooLong;
    var file = try cwd.createFile(io, tmp, .{});
    defer file.close(io);
    for (lines) |line| try file.writeStreamingAll(io, line);
    try file.sync(io);
    std.Io.Dir.renameAbsolute(tmp, path, io) catch return error.RenameFailed;
}

// --- history ---------------------------------------------------------------

pub const HistoryEntry = struct {
    /// Assigned by the store ("h-<n>"); `""` when passing into `record`.
    id: []const u8,
    /// Operation identity for dedupe (create/update by the same op).
    operation_id: []const u8,
    ts: i64,
    server_id: []const u8,
    /// `exec | script | deploy | backup | monitor | access | …`
    kind: []const u8,
    /// Redacted at write time.
    command: []const u8,
    exit: ?i32,
    duration_ms: ?i64,
    output_snippet: []const u8,
    redacted: bool,

    pub fn deinit(self: *HistoryEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.operation_id);
        allocator.free(self.server_id);
        allocator.free(self.kind);
        allocator.free(self.command);
        allocator.free(self.output_snippet);
    }
};

fn writeHistoryLine(w: *std.Io.Writer, e: *const HistoryEntry) !void {
    try w.writeAll("{\"id\":");
    try json.writeJsonString(w, e.id);
    try w.writeAll(",\"operation_id\":");
    try json.writeJsonString(w, e.operation_id);
    try w.print(",\"ts\":{d},\"server_id\":", .{e.ts});
    try json.writeJsonString(w, e.server_id);
    try w.writeAll(",\"kind\":");
    try json.writeJsonString(w, e.kind);
    try w.writeAll(",\"command\":");
    try json.writeJsonString(w, e.command);
    try w.writeAll(",\"exit\":");
    if (e.exit) |exit| {
        try w.print("{d}", .{exit});
    } else {
        try w.writeAll("null");
    }
    try w.writeAll(",\"duration_ms\":");
    if (e.duration_ms) |ms| {
        try w.print("{d}", .{ms});
    } else {
        try w.writeAll("null");
    }
    try w.writeAll(",\"output_snippet\":");
    try json.writeJsonString(w, e.output_snippet);
    try w.writeAll(",\"redacted\":");
    try w.writeAll(if (e.redacted) "true" else "false");
    try w.writeAll("}\n");
}

pub const HistoryStore = struct {
    allocator: std.mem.Allocator,
    /// Full path to history.jsonl.
    path: []const u8,
    /// Ring cap (kept a field so tests can shrink it; production uses
    /// `history_cap`).
    cap: usize = history_cap,
    mutex: std.atomic.Mutex = .unlocked,
    /// Owned entries in write order (newest appended last).
    entries: std.ArrayList(HistoryEntry) = .empty,
    loaded: bool = false,
    next_id: u64 = 1,

    pub fn deinit(self: *HistoryStore) void {
        for (self.entries.items) |*e| e.deinit(self.allocator);
        self.entries.deinit(self.allocator);
    }

    fn ensureLoadedLocked(self: *HistoryStore, io: std.Io) !void {
        if (self.loaded) return;
        try self.loadFile(io);
        self.loaded = true;
    }

    /// Creates or updates the record for `operation_id`. The journal gets
    /// one line per write; the newest line per operation_id wins on load
    /// (spec 15 §10 duplicate capture). `entry.id` is ignored (assigned).
    pub fn record(self: *HistoryStore, io: std.Io, entry_in: HistoryEntry) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.ensureLoadedLocked(io);
        var entry = try self.dupeNewId(entry_in);
        errdefer entry.deinit(self.allocator);
        try self.upsert(entry);
        var line_buf: [32 * 1024]u8 = undefined;
        var w = std.Io.Writer.fixed(&line_buf);
        try writeHistoryLine(&w, &entry);
        appendLine(io, self.path, w.buffered()) catch {};
        self.compactLocked(io);
    }

    fn dupeNewId(self: *HistoryStore, src: HistoryEntry) !HistoryEntry {
        var id_buf: [64]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buf, "h-{d}", .{self.next_id}) catch unreachable;
        self.next_id += 1;
        const command = if (src.command.len > command_cap) src.command[0..command_cap] else src.command;
        const snippet = if (src.output_snippet.len > snippet_cap) src.output_snippet[0..snippet_cap] else src.output_snippet;
        var out = HistoryEntry{
            .id = try self.allocator.dupe(u8, id),
            .operation_id = try self.allocator.dupe(u8, src.operation_id),
            .ts = src.ts,
            .server_id = try self.allocator.dupe(u8, src.server_id),
            .kind = try self.allocator.dupe(u8, src.kind),
            .command = try self.allocator.dupe(u8, command),
            .exit = src.exit,
            .duration_ms = src.duration_ms,
            .output_snippet = try self.allocator.dupe(u8, snippet),
            .redacted = src.redacted,
        };
        errdefer out.deinit(self.allocator);
        return out;
    }

    /// Removes any prior record with the same operation_id (the latest
    /// write wins), then appends at the end.
    fn upsert(self: *HistoryStore, entry: HistoryEntry) !void {
        var k: usize = self.entries.items.len;
        while (k > 0) {
            k -= 1;
            const e = &self.entries.items[k];
            if (e.operation_id.len > 0 and std.mem.eql(u8, e.operation_id, entry.operation_id)) {
                var old = self.entries.orderedRemove(k);
                old.deinit(self.allocator);
                break;
            }
        }
        try self.entries.append(self.allocator, entry);
    }

    fn compactLocked(self: *HistoryStore, io: std.Io) void {
        if (self.entries.items.len <= self.cap) return;
        const drop = self.entries.items.len - self.cap;
        for (self.entries.items[0..drop]) |*e| e.deinit(self.allocator);
        var i: usize = 0;
        while (i < drop) : (i += 1) _ = self.entries.orderedRemove(0);
        // Atomic rewrite of the retained tail; a failed rewrite leaves the
        // on-disk journal larger than the cap until the next success — the
        // in-memory index stays capped, so reads are always bounded.
        var lines: std.ArrayList([]const u8) = .empty;
        defer lines.deinit(self.allocator);
        for (self.entries.items) |*e| {
            var buf: [32 * 1024]u8 = undefined;
            var w = std.Io.Writer.fixed(&buf);
            writeHistoryLine(&w, e) catch return;
            const owned = self.allocator.dupe(u8, w.buffered()) catch return;
            lines.append(self.allocator, owned) catch {
                self.allocator.free(owned);
                return;
            };
        }
        defer for (lines.items) |l| self.allocator.free(l);
        rewriteJournal(io, self.path, lines.items) catch {};
    }

    fn loadFile(self: *HistoryStore, io: std.Io) !void {
        for (self.entries.items) |*e| e.deinit(self.allocator);
        self.entries.clearRetainingCapacity();
        const content = std.Io.Dir.cwd().readFileAlloc(io, self.path, self.allocator, .limited(64 * 1024 * 1024)) catch return;
        defer self.allocator.free(content);
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (line.len == 0 or line[0] != '{') continue;
            var parsed = std.json.parseFromSlice(HistoryEntry, self.allocator, line, .{ .allocate = .alloc_always }) catch continue;
            defer parsed.deinit();
            const e = parsed.value;
            var entry = HistoryEntry{
                .id = try self.allocator.dupe(u8, e.id),
                .operation_id = try self.allocator.dupe(u8, e.operation_id),
                .ts = e.ts,
                .server_id = try self.allocator.dupe(u8, e.server_id),
                .kind = try self.allocator.dupe(u8, e.kind),
                .command = try self.allocator.dupe(u8, e.command),
                .exit = e.exit,
                .duration_ms = e.duration_ms,
                .output_snippet = try self.allocator.dupe(u8, e.output_snippet),
                .redacted = e.redacted,
            };
            errdefer entry.deinit(self.allocator);
            var k: usize = self.entries.items.len;
            while (k > 0) {
                k -= 1;
                const prev = &self.entries.items[k];
                if (prev.operation_id.len > 0 and std.mem.eql(u8, prev.operation_id, entry.operation_id)) {
                    var old = self.entries.orderedRemove(k);
                    old.deinit(self.allocator);
                    break;
                }
            }
            try self.entries.append(self.allocator, entry);
            if (idNumber(entry.id)) |num| {
                if (num >= self.next_id) self.next_id = num + 1;
            }
        }
    }

    fn dupeEntry(self: *HistoryStore, src: *const HistoryEntry) !HistoryEntry {
        return .{
            .id = try self.allocator.dupe(u8, src.id),
            .operation_id = try self.allocator.dupe(u8, src.operation_id),
            .ts = src.ts,
            .server_id = try self.allocator.dupe(u8, src.server_id),
            .kind = try self.allocator.dupe(u8, src.kind),
            .command = try self.allocator.dupe(u8, src.command),
            .exit = src.exit,
            .duration_ms = src.duration_ms,
            .output_snippet = try self.allocator.dupe(u8, src.output_snippet),
            .redacted = src.redacted,
        };
    }

    /// Owned entries, newest first, filtered by server and/or text,
    /// capped at `limit`. `q` matches the command, kind, or server id
    /// (case-insensitive substring).
    pub fn list(self: *HistoryStore, io: std.Io, server_id: ?[]const u8, q: ?[]const u8, limit: usize) ![]HistoryEntry {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.ensureLoadedLocked(io);
        var out: std.ArrayList(HistoryEntry) = .empty;
        errdefer {
            for (out.items) |*e| e.deinit(self.allocator);
            out.deinit(self.allocator);
        }
        var i: usize = self.entries.items.len;
        while (i > 0) {
            i -= 1;
            const e = &self.entries.items[i];
            if (server_id) |sid| {
                if (!std.mem.eql(u8, e.server_id, sid)) continue;
            }
            if (q) |query| {
                if (!containsIgnoreCase(e.command, query) and
                    !containsIgnoreCase(e.kind, query) and
                    !containsIgnoreCase(e.server_id, query)) continue;
            }
            try out.append(self.allocator, try self.dupeEntry(e));
            if (out.items.len >= limit) break;
        }
        return out.toOwnedSlice(self.allocator);
    }

    /// Owned entry by id, or null.
    pub fn get(self: *HistoryStore, io: std.Io, id: []const u8) !?HistoryEntry {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.ensureLoadedLocked(io);
        var i: usize = self.entries.items.len;
        while (i > 0) {
            i -= 1;
            if (std.mem.eql(u8, self.entries.items[i].id, id)) {
                return try self.dupeEntry(&self.entries.items[i]);
            }
        }
        return null;
    }
};

fn idNumber(id: []const u8) ?u64 {
    const dash = std.mem.indexOfScalar(u8, id, '-') orelse return null;
    return std.fmt.parseInt(u64, id[dash + 1 ..], 10) catch null;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (eqIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

// --- audit -----------------------------------------------------------------

pub const AuditEntry = struct {
    /// Assigned by the store ("aud-<n>").
    id: []const u8,
    operation_id: []const u8,
    ts: i64,
    /// Action type, e.g. `deploy.run`, `access.offboard`, `sshkeys.revoke`.
    type: []const u8,
    /// The affected target (usually a server id; `-` for app-level).
    target: []const u8,
    /// JSON array of the redacted command strings ("" when not applicable).
    commands: []const u8,
    /// `ok | failed | canceled` ("" when the action has no result yet).
    result: []const u8,
    detail: []const u8,

    pub fn deinit(self: *AuditEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.operation_id);
        allocator.free(self.type);
        allocator.free(self.target);
        allocator.free(self.commands);
        allocator.free(self.result);
        allocator.free(self.detail);
    }
};

fn writeAuditLine(w: *std.Io.Writer, e: *const AuditEntry) !void {
    try w.writeAll("{\"id\":");
    try json.writeJsonString(w, e.id);
    try w.writeAll(",\"operation_id\":");
    try json.writeJsonString(w, e.operation_id);
    try w.print(",\"ts\":{d},\"type\":", .{e.ts});
    try json.writeJsonString(w, e.type);
    try w.writeAll(",\"target\":");
    try json.writeJsonString(w, e.target);
    try w.writeAll(",\"commands\":");
    try json.writeJsonString(w, e.commands);
    try w.writeAll(",\"result\":");
    try json.writeJsonString(w, e.result);
    try w.writeAll(",\"detail\":");
    try json.writeJsonString(w, e.detail);
    try w.writeAll("}\n");
}

/// Disk shape for reads: the pre-spec-15 `action`/`server_id` field names
/// are accepted so journals written by earlier builds still load.
const DiskAudit = struct {
    id: ?[]const u8 = null,
    operation_id: ?[]const u8 = null,
    ts: i64 = 0,
    type: ?[]const u8 = null,
    action: ?[]const u8 = null,
    target: ?[]const u8 = null,
    server_id: ?[]const u8 = null,
    commands: ?[]const u8 = null,
    result: ?[]const u8 = null,
    detail: ?[]const u8 = null,
};

pub const AuditStore = struct {
    allocator: std.mem.Allocator,
    /// Full path to audit.jsonl.
    path: []const u8,
    /// Ring cap (field so tests can shrink it; production uses `audit_cap`).
    cap: usize = audit_cap,
    mutex: std.atomic.Mutex = .unlocked,
    entries: std.ArrayList(AuditEntry) = .empty,
    loaded: bool = false,
    next_id: u64 = 1,

    pub fn deinit(self: *AuditStore) void {
        for (self.entries.items) |*e| e.deinit(self.allocator);
        self.entries.deinit(self.allocator);
    }

    fn ensureLoadedLocked(self: *AuditStore, io: std.Io) !void {
        if (self.loaded) return;
        try self.loadFile(io);
        self.loaded = true;
    }

    /// Simple append (the shape every mutating action uses today): the
    /// store generates the id; operation_id/commands/result stay empty.
    pub fn append(self: *AuditStore, io: std.Io, action_type: []const u8, target: []const u8, detail: []const u8) !void {
        try self.appendFull(io, "", action_type, target, "", "", detail);
    }

    /// Full append with an operation_id (links the audit row to a history
    /// operation), a redacted command list, and a result.
    pub fn appendFull(self: *AuditStore, io: std.Io, operation_id: []const u8, action_type: []const u8, target: []const u8, commands: []const u8, result: []const u8, detail: []const u8) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.ensureLoadedLocked(io);
        var id_buf: [64]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buf, "aud-{d}", .{self.next_id}) catch unreachable;
        self.next_id += 1;
        var entry = AuditEntry{
            .id = try self.allocator.dupe(u8, id),
            .operation_id = try self.allocator.dupe(u8, operation_id),
            .ts = @intCast(std.Io.Timestamp.now(io, .real).nanoseconds),
            .type = try self.allocator.dupe(u8, action_type),
            .target = try self.allocator.dupe(u8, target),
            .commands = try self.allocator.dupe(u8, commands),
            .result = try self.allocator.dupe(u8, result),
            .detail = try self.allocator.dupe(u8, detail),
        };
        errdefer entry.deinit(self.allocator);
        try self.entries.append(self.allocator, entry);
        var line_buf: [16 * 1024]u8 = undefined;
        var w = std.Io.Writer.fixed(&line_buf);
        try writeAuditLine(&w, &entry);
        appendLine(io, self.path, w.buffered()) catch {};
        self.compactLocked(io);
    }

    fn compactLocked(self: *AuditStore, io: std.Io) void {
        if (self.entries.items.len <= self.cap) return;
        const drop = self.entries.items.len - self.cap;
        for (self.entries.items[0..drop]) |*e| e.deinit(self.allocator);
        var i: usize = 0;
        while (i < drop) : (i += 1) _ = self.entries.orderedRemove(0);
        var lines: std.ArrayList([]const u8) = .empty;
        defer lines.deinit(self.allocator);
        for (self.entries.items) |*e| {
            var buf: [16 * 1024]u8 = undefined;
            var w = std.Io.Writer.fixed(&buf);
            writeAuditLine(&w, e) catch return;
            const owned = self.allocator.dupe(u8, w.buffered()) catch return;
            lines.append(self.allocator, owned) catch {
                self.allocator.free(owned);
                return;
            };
        }
        defer for (lines.items) |l| self.allocator.free(l);
        rewriteJournal(io, self.path, lines.items) catch {};
    }

    fn loadFile(self: *AuditStore, io: std.Io) !void {
        for (self.entries.items) |*e| e.deinit(self.allocator);
        self.entries.clearRetainingCapacity();
        const content = std.Io.Dir.cwd().readFileAlloc(io, self.path, self.allocator, .limited(128 * 1024 * 1024)) catch return;
        defer self.allocator.free(content);
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (line.len == 0 or line[0] != '{') continue;
            var parsed = std.json.parseFromSlice(DiskAudit, self.allocator, line, .{ .allocate = .alloc_always }) catch continue;
            defer parsed.deinit();
            const d = parsed.value;
            const action_type = d.type orelse d.action orelse continue;
            const target = d.target orelse d.server_id orelse "";
            var entry = AuditEntry{
                .id = try self.allocator.dupe(u8, d.id orelse "aud-0"),
                .operation_id = try self.allocator.dupe(u8, d.operation_id orelse ""),
                .ts = d.ts,
                .type = try self.allocator.dupe(u8, action_type),
                .target = try self.allocator.dupe(u8, target),
                .commands = try self.allocator.dupe(u8, d.commands orelse ""),
                .result = try self.allocator.dupe(u8, d.result orelse ""),
                .detail = try self.allocator.dupe(u8, d.detail orelse ""),
            };
            errdefer entry.deinit(self.allocator);
            try self.entries.append(self.allocator, entry);
            if (idNumber(entry.id)) |num| {
                if (num >= self.next_id) self.next_id = num + 1;
            }
        }
    }

    fn dupeEntry(self: *AuditStore, src: *const AuditEntry) !AuditEntry {
        return .{
            .id = try self.allocator.dupe(u8, src.id),
            .operation_id = try self.allocator.dupe(u8, src.operation_id),
            .ts = src.ts,
            .type = try self.allocator.dupe(u8, src.type),
            .target = try self.allocator.dupe(u8, src.target),
            .commands = try self.allocator.dupe(u8, src.commands),
            .result = try self.allocator.dupe(u8, src.result),
            .detail = try self.allocator.dupe(u8, src.detail),
        };
    }

    /// Minimal read (kept for `oars.ai.history` and spec-12 assertions):
    /// one target's entries of one type, newest first, capped.
    pub fn read(self: *AuditStore, io: std.Io, target: []const u8, action_type: ?[]const u8, limit: usize) ![]AuditEntry {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.ensureLoadedLocked(io);
        var out: std.ArrayList(AuditEntry) = .empty;
        errdefer {
            for (out.items) |*e| e.deinit(self.allocator);
            out.deinit(self.allocator);
        }
        var i: usize = self.entries.items.len;
        while (i > 0) {
            i -= 1;
            const e = &self.entries.items[i];
            if (!std.mem.eql(u8, e.target, target)) continue;
            if (action_type) |t| {
                if (!std.mem.eql(u8, e.type, t)) continue;
            }
            try out.append(self.allocator, try self.dupeEntry(e));
            if (out.items.len >= limit) break;
        }
        return out.toOwnedSlice(self.allocator);
    }

    /// Full read for `oars.audit.list`: newest first, filtered by type
    /// (exact) and/or text (case-insensitive over type/target/detail/
    /// commands), capped.
    pub fn list(self: *AuditStore, io: std.Io, q: ?[]const u8, action_type: ?[]const u8, limit: usize) ![]AuditEntry {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.ensureLoadedLocked(io);
        var out: std.ArrayList(AuditEntry) = .empty;
        errdefer {
            for (out.items) |*e| e.deinit(self.allocator);
            out.deinit(self.allocator);
        }
        var i: usize = self.entries.items.len;
        while (i > 0) {
            i -= 1;
            const e = &self.entries.items[i];
            if (action_type) |t| {
                if (!std.mem.eql(u8, e.type, t)) continue;
            }
            if (q) |query| {
                if (!containsIgnoreCase(e.type, query) and
                    !containsIgnoreCase(e.target, query) and
                    !containsIgnoreCase(e.detail, query) and
                    !containsIgnoreCase(e.commands, query)) continue;
            }
            try out.append(self.allocator, try self.dupeEntry(e));
            if (out.items.len >= limit) break;
        }
        return out.toOwnedSlice(self.allocator);
    }

    /// Truncates the journal (type-to-confirm is the handler's job).
    pub fn clear(self: *AuditStore, io: std.Io) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.ensureLoadedLocked(io);
        for (self.entries.items) |*e| e.deinit(self.allocator);
        self.entries.clearRetainingCapacity();
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(self.path)) |dir| try cwd.createDirPath(io, dir);
        var file = try cwd.createFile(io, self.path, .{ .truncate = true });
        defer file.close(io);
        try file.sync(io);
    }
};

// --- tests -----------------------------------------------------------------

fn testPath(comptime tag: []const u8, path_buf: *[512]u8) ![]const u8 {
    const io = std.testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    const dir_name = try std.fmt.bufPrint(path_buf[0..128], "oars-h-{s}-{d}", .{ tag, now });
    const path = try std.fmt.bufPrint(path_buf[128..], "/tmp/{s}/journal.jsonl", .{dir_name});
    return path;
}

fn testCleanup(path: []const u8) void {
    const io = std.testing.io;
    const dir = std.fs.path.dirname(path) orelse return;
    const base = std.fs.path.basename(dir);
    std.Io.Dir.cwd().deleteTree(io, base) catch {};
}

test "exactMask masks known secret values in commands and snippets" {
    const allocator = std.testing.allocator;
    const secrets = [_][]const u8{ "hunter2", "ab" };
    // Longest match wins: "ab" alone must not half-mask "hunter2"'s "h".
    const out = try exactMask(allocator, "echo hunter2 && echo ab", &secrets);
    defer allocator.free(out.text);
    try std.testing.expectEqualStrings("echo \u{2022}\u{2022}\u{2022}\u{2022} && echo \u{2022}\u{2022}\u{2022}\u{2022}", out.text);
    try std.testing.expect(out.redacted);

    // A snippet that echoes the secret is masked; unrelated text stays.
    const snippet = try exactMask(allocator, "supersecret-value\nok", &.{"supersecret-value"});
    defer allocator.free(snippet.text);
    try std.testing.expectEqualStrings("\u{2022}\u{2022}\u{2022}\u{2022}\nok", snippet.text);
    try std.testing.expect(snippet.redacted);

    // No secrets → identity, nothing masked.
    const none = try exactMask(allocator, "plain text", &.{});
    defer allocator.free(none.text);
    try std.testing.expectEqualStrings("plain text", none.text);
    try std.testing.expect(!none.redacted);
}

test "redaction masks named fields but not blanket -p or lookalikes" {
    const allocator = std.testing.allocator;
    const cases = [_]struct { in: []const u8, want: []const u8, masked: bool }{
        .{ .in = "export PASSWORD=hunter2", .want = "export PASSWORD=\u{2022}\u{2022}\u{2022}\u{2022}", .masked = true },
        .{ .in = "TOKEN=abc123 run", .want = "TOKEN=\u{2022}\u{2022}\u{2022}\u{2022} run", .masked = true },
        .{ .in = "curl --password hunter2 -L url", .want = "curl --password \u{2022}\u{2022}\u{2022}\u{2022} -L url", .masked = true },
        .{ .in = "curl --password=hunter2 -L url", .want = "curl --password=\u{2022}\u{2022}\u{2022}\u{2022} -L url", .masked = true },
        .{ .in = "psql postgres://app:dbpass@db:5432/prod", .want = "psql postgres://app:\u{2022}\u{2022}\u{2022}\u{2022}@db:5432/prod", .masked = true },
        .{ .in = "cmd --api-key 'k-123' x", .want = "cmd --api-key \u{2022}\u{2022}\u{2022}\u{2022} x", .masked = true },
        .{ .in = "grep -p pattern file", .want = "grep -p pattern file", .masked = false },
        .{ .in = "ssh -i key.pem host", .want = "ssh -i key.pem host", .masked = false },
        .{ .in = "openssl rsa -in key.pem -passin pass:sekret", .want = "openssl rsa -in key.pem -passin pass:sekret", .masked = false },
        .{ .in = "export MYPASSWORD=visible", .want = "export MYPASSWORD=visible", .masked = false },
        .{ .in = "git push origin main", .want = "git push origin main", .masked = false },
    };
    for (cases) |c| {
        const out = try redact(allocator, c.in, &.{});
        defer allocator.free(out.text);
        try std.testing.expectEqualStrings(c.want, out.text);
        try std.testing.expectEqual(c.masked, out.redacted);
    }
}

test "redaction keeps quotes and mid-word values intact" {
    const allocator = std.testing.allocator;
    const out = try redact(allocator, "export PASSWORD='quoted value' && echo done", &.{});
    defer allocator.free(out.text);
    try std.testing.expectEqualStrings("export PASSWORD=\u{2022}\u{2022}\u{2022}\u{2022} && echo done", out.text);
    try std.testing.expect(out.redacted);

    // A password adjacent to other text is masked only as the value.
    const out2 = try redact(allocator, "PASSWORD=x TOKEN=", &.{});
    defer allocator.free(out2.text);
    try std.testing.expectEqualStrings("PASSWORD=\u{2022}\u{2022}\u{2022}\u{2022} TOKEN=", out2.text);
}

test "history record, update by operation_id, and list filters" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var path_buf: [512]u8 = undefined;
    const path = try testPath("record", &path_buf);
    defer testCleanup(path);

    var store = HistoryStore{ .allocator = allocator, .path = path };
    defer store.deinit();

    try store.record(io, .{ .id = "", .operation_id = "exec-1", .ts = 1, .server_id = "s1", .kind = "exec", .command = "ls -la", .exit = 0, .duration_ms = 12, .output_snippet = "total 8", .redacted = false });
    try store.record(io, .{ .id = "", .operation_id = "exec-2", .ts = 2, .server_id = "s2", .kind = "script", .command = "df -h", .exit = 1, .duration_ms = null, .output_snippet = "", .redacted = false });

    const all = try store.list(io, null, null, 10);
    defer {
        for (all) |*e| e.deinit(allocator);
        allocator.free(all);
    }
    try std.testing.expectEqual(@as(usize, 2), all.len);
    try std.testing.expectEqualStrings("exec-2", all[0].operation_id); // newest first
    try std.testing.expectEqualStrings("df -h", all[0].command);
    try std.testing.expectEqual(@as(?i32, 1), all[0].exit);
    try std.testing.expectEqualStrings("s1", all[1].server_id);
    try std.testing.expect(std.mem.startsWith(u8, all[0].id, "h-"));

    // Update by operation_id: one record, latest fields, moved newest.
    try store.record(io, .{ .id = "", .operation_id = "exec-1", .ts = 3, .server_id = "s1", .kind = "exec", .command = "ls -la", .exit = 0, .duration_ms = 14, .output_snippet = "total 8", .redacted = false });
    const after = try store.list(io, null, null, 10);
    defer {
        for (after) |*e| e.deinit(allocator);
        allocator.free(after);
    }
    try std.testing.expectEqual(@as(usize, 2), after.len);
    try std.testing.expectEqual(@as(?i64, 14), after[0].duration_ms);
    try std.testing.expectEqualStrings("exec-1", after[0].operation_id);

    // Filters: server, text (case-insensitive), limit.
    const s1 = try store.list(io, "s1", null, 10);
    defer {
        for (s1) |*e| e.deinit(allocator);
        allocator.free(s1);
    }
    try std.testing.expectEqual(@as(usize, 1), s1.len);
    const q = try store.list(io, null, "DF -H", 10);
    defer {
        for (q) |*e| e.deinit(allocator);
        allocator.free(q);
    }
    try std.testing.expectEqual(@as(usize, 1), q.len);
    const capped = try store.list(io, null, null, 1);
    defer {
        for (capped) |*e| e.deinit(allocator);
        allocator.free(capped);
    }
    try std.testing.expectEqual(@as(usize, 1), capped.len);
}

test "history persists across store instances and dedupes by operation_id on load" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var path_buf: [512]u8 = undefined;
    const path = try testPath("persist", &path_buf);
    defer testCleanup(path);

    {
        var store = HistoryStore{ .allocator = allocator, .path = path };
        defer store.deinit();
        try store.record(io, .{ .id = "", .operation_id = "exec-1", .ts = 1, .server_id = "s1", .kind = "exec", .command = "a", .exit = 0, .duration_ms = 1, .output_snippet = "", .redacted = false });
        try store.record(io, .{ .id = "", .operation_id = "exec-2", .ts = 2, .server_id = "s1", .kind = "exec", .command = "b", .exit = 0, .duration_ms = 1, .output_snippet = "", .redacted = false });
    }
    {
        // A new instance reloads both and keeps assigning fresh ids.
        var store = HistoryStore{ .allocator = allocator, .path = path };
        defer store.deinit();
        const all = try store.list(io, null, null, 10);
        defer {
            for (all) |*e| e.deinit(allocator);
            allocator.free(all);
        }
        try std.testing.expectEqual(@as(usize, 2), all.len);
        try store.record(io, .{ .id = "", .operation_id = "exec-1", .ts = 9, .server_id = "s1", .kind = "exec", .command = "a-updated", .exit = 0, .duration_ms = 1, .output_snippet = "", .redacted = false });
        const after = try store.list(io, null, null, 10);
        defer {
            for (after) |*e| e.deinit(allocator);
            allocator.free(after);
        }
        try std.testing.expectEqual(@as(usize, 2), after.len);
        try std.testing.expectEqualStrings("a-updated", after[0].command);
    }
    {
        // The journal's two exec-1 lines collapse to the newest on load.
        var store = HistoryStore{ .allocator = allocator, .path = path };
        defer store.deinit();
        const all = try store.list(io, null, null, 10);
        defer {
            for (all) |*e| e.deinit(allocator);
            allocator.free(all);
        }
        try std.testing.expectEqual(@as(usize, 2), all.len);
        try std.testing.expectEqualStrings("a-updated", all[0].command);
    }
}

test "history ring compaction keeps the newest entries and rewrites the journal" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var path_buf: [512]u8 = undefined;
    const path = try testPath("compact", &path_buf);
    defer testCleanup(path);

    var store = HistoryStore{ .allocator = allocator, .path = path, .cap = 3 };
    defer store.deinit();
    var i: usize = 0;
    while (i < 7) : (i += 1) {
        var cmd_buf: [32]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "cmd-{d}", .{i}) catch unreachable;
        try store.record(io, .{ .id = "", .operation_id = "", .ts = @intCast(i), .server_id = "s1", .kind = "exec", .command = cmd, .exit = 0, .duration_ms = 1, .output_snippet = "", .redacted = false });
    }
    const all = try store.list(io, null, null, 100);
    defer {
        for (all) |*e| e.deinit(allocator);
        allocator.free(all);
    }
    try std.testing.expectEqual(@as(usize, 3), all.len);
    try std.testing.expectEqualStrings("cmd-6", all[0].command);
    try std.testing.expectEqualStrings("cmd-4", all[2].command);
}

test "audit append, read filter, list filter, and clear" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var path_buf: [512]u8 = undefined;
    const path = try testPath("audit", &path_buf);
    defer testCleanup(path);

    var store = AuditStore{ .allocator = allocator, .path = path };
    defer store.deinit();
    try store.append(io, "ssh.exec", "s1", "cmd=du");
    try store.append(io, "ssh.exec", "s2", "cmd=whoami");
    try store.append(io, "ssh.exec", "s1", "cmd=ls -la");
    try store.appendFull(io, "op-9", "ai.provider.set", "s1", "[]", "ok", "adapter=openai_compatible");

    // Legacy minimal read: one target's type, newest first.
    const runs = try store.read(io, "s1", "ssh.exec", 10);
    defer {
        for (runs) |*e| e.deinit(allocator);
        allocator.free(runs);
    }
    try std.testing.expectEqual(@as(usize, 2), runs.len);
    try std.testing.expectEqualStrings("cmd=ls -la", runs[0].detail);
    try std.testing.expectEqualStrings("", runs[1].operation_id); // plain append, no op id

    // Full list with type + text filters.
    const all = try store.list(io, null, null, 10);
    defer {
        for (all) |*e| e.deinit(allocator);
        allocator.free(all);
    }
    try std.testing.expectEqual(@as(usize, 4), all.len);
    try std.testing.expectEqualStrings("ai.provider.set", all[0].type);
    try std.testing.expectEqualStrings("s1", all[1].target); // ssh.exec ls -la
    try std.testing.expectEqualStrings("s2", all[2].target);

    const typed = try store.list(io, null, "ssh.exec", 10);
    defer {
        for (typed) |*e| e.deinit(allocator);
        allocator.free(typed);
    }
    try std.testing.expectEqual(@as(usize, 3), typed.len);

    const queried = try store.list(io, "whoami", null, 10);
    defer {
        for (queried) |*e| e.deinit(allocator);
        allocator.free(queried);
    }
    try std.testing.expectEqual(@as(usize, 1), queried.len);

    // Clear truncates; reads come back empty; the file is empty.
    try store.clear(io);
    const empty = try store.list(io, null, null, 10);
    defer allocator.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
    const content = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024));
    defer allocator.free(content);
    try std.testing.expectEqual(@as(usize, 0), content.len);
}

test "audit loads pre-spec-15 action/server_id journal lines" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var path_buf: [512]u8 = undefined;
    const path = try testPath("legacy", &path_buf);
    defer testCleanup(path);

    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |dir| try cwd.createDirPath(io, dir);
    var file = try cwd.createFile(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, "{\"ts\":1,\"action\":\"monitor.clean_disk\",\"server_id\":\"s1\",\"detail\":\"plan=apt\"}\n");

    var store = AuditStore{ .allocator = allocator, .path = path };
    defer store.deinit();
    const all = try store.list(io, null, null, 10);
    defer {
        for (all) |*e| e.deinit(allocator);
        allocator.free(all);
    }
    try std.testing.expectEqual(@as(usize, 1), all.len);
    try std.testing.expectEqualStrings("monitor.clean_disk", all[0].type);
    try std.testing.expectEqualStrings("s1", all[0].target);
    try std.testing.expectEqualStrings("plan=apt", all[0].detail);
}

test "audit ring compaction keeps the newest entries" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var path_buf: [512]u8 = undefined;
    const path = try testPath("acompact", &path_buf);
    defer testCleanup(path);

    var store = AuditStore{ .allocator = allocator, .path = path, .cap = 4 };
    defer store.deinit();
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        var detail_buf: [32]u8 = undefined;
        const detail = std.fmt.bufPrint(&detail_buf, "n={d}", .{i}) catch unreachable;
        try store.append(io, "t", "s1", detail);
    }
    const all = try store.list(io, null, null, 100);
    defer {
        for (all) |*e| e.deinit(allocator);
        allocator.free(all);
    }
    try std.testing.expectEqual(@as(usize, 4), all.len);
    try std.testing.expectEqualStrings("n=5", all[0].detail);
    try std.testing.expectEqualStrings("n=2", all[3].detail);
}
