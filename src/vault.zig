//! Spec 17: vault export/import.
//!
//! Two formats:
//! - **Encrypted vault** (`.oarsvault`): the JSON payload is sealed with
//!   AES-256-GCM under a PBKDF2-HMAC-SHA256 key (600,000 iterations,
//!   random 16-byte salt per file, random 12-byte nonce). The header —
//!   magic, version, KDF parameters, salt, nonce, ciphertext length — is
//!   the GCM additional authenticated data, so tampering with any of it
//!   fails the same atomic auth check as a wrong password.
//! - **Plain JSON**: the payload as-is. Configuration sections only;
//!   history, audit, deploy runs, and backup runs are refused in plain
//!   mode (best-effort redaction cannot prove arbitrary text is clean —
//!   spec 17 §8).
//!
//! Import never writes before the whole file is authenticated and parsed
//! (spec 17 §6): decrypt → validate → preview → confirm → atomic
//! write-back per store. Imported ids merge by id (existing → update,
//! new → add); credential-binding conflicts (a server whose endpoint or
//! auth method changed, an app/backup job whose server or destination
//! changed) can never update in place — the preview lists them and the
//! confirm step decides keep-local vs import-as-new.

const std = @import("std");
const crypto = @import("crypto.zig");

pub const magic = "OARSVAULT";
pub const version: u8 = 1;
pub const kdf_id_pbkdf2_sha256: u8 = 1;
/// OWASP Password Storage Cheat Sheet (2026): PBKDF2-HMAC-SHA256 with
/// 600,000 iterations (spec 17 §13).
pub const kdf_iterations: u32 = 600_000;
pub const salt_len = 16;
pub const nonce_len = 12;
pub const tag_len = 16;
/// V1 import cap: authenticate before parsing without unbounded memory.
pub const max_file_bytes: usize = 50 * 1024 * 1024;
/// Spec 17 §4.1: enforced minimum vault password length.
pub const min_password_len = 12;

/// One export source: a store file whose content becomes a payload
/// section. `jsonl` sections (history/audit) are converted to JSON
/// arrays.
pub const Section = struct {
    name: []const u8,
    path: []const u8,
    jsonl: bool = false,
};

pub const PayloadError = error{
    UnsupportedVersion,
    NotAVault,
    TooLarge,
    InvalidJson,
    DuplicateId,
    RecordWithoutId,
    PasswordTooShort,
    KdfFailed,
    SealFailed,
    /// The vault/store file could not be written (disk, path, rename).
    WriteFailed,
    /// GCM auth failed: wrong password, tampered header, or corrupted
    /// ciphertext — one explicit error (spec 17 §10).
    AuthFailed,
    OutOfMemory,
    FileMissing,
};

/// The parsed payload: version + per-section JSON values (owned).
pub const Payload = struct {
    version: u32,
    exported_at: i64,
    sections: std.StringArrayHashMapUnmanaged(std.json.Value),

    pub fn deinit(self: *Payload, allocator: std.mem.Allocator) void {
        var it = self.sections.iterator();
        while (it.next()) |e| {
            allocator.free(e.key_ptr.*);
            freeValue(allocator, &e.value_ptr.*);
        }
        self.sections.deinit(allocator);
    }
};

/// A validation or conflict report for one section of the preview.
pub const SectionReport = struct {
    /// Owned.
    name: []const u8,
    incoming: usize,
    new: usize,
    updated: usize,
    /// Credential-binding conflicts: `section:id` + a human reason.
    /// Owned entries.
    conflicts: std.ArrayList(Conflict),

    pub fn deinit(self: *SectionReport, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        for (self.conflicts.items) |*c| c.deinit(allocator);
        self.conflicts.deinit(allocator);
    }
};

pub const Conflict = struct {
    /// Owned compound key `section:id`.
    key: []const u8,
    /// Owned reason (endpoint/auth/server/destination changed).
    reason: []const u8,

    pub fn deinit(self: *Conflict, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        allocator.free(self.reason);
    }
};

pub const Preview = struct {
    reports: std.ArrayList(SectionReport),
    /// Owned `section:message` pairs for records that cannot import at
    /// all (missing id, broken via chain after merge).
    errors: std.ArrayList(Conflict),

    pub fn deinit(self: *Preview, allocator: std.mem.Allocator) void {
        for (self.reports.items) |*r| r.deinit(allocator);
        self.reports.deinit(allocator);
        for (self.errors.items) |*c| c.deinit(allocator);
        self.errors.deinit(allocator);
    }
};

pub const ImportOptions = struct {
    /// `section:id` keys to keep local (skip the incoming record).
    keep_local: []const []const u8 = &.{},
    /// `section:id` keys to import under a fresh id.
    import_as_new: []const []const u8 = &.{},
};

pub const ImportResult = struct {
    /// Owned `section: message` lines describing what happened.
    notes: std.ArrayList([]const u8),

    pub fn deinit(self: *ImportResult, allocator: std.mem.Allocator) void {
        for (self.notes.items) |n| allocator.free(n);
        self.notes.deinit(allocator);
    }
};

// --- file helpers -----------------------------------------------------------

fn readSmallFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8, cap: usize) PayloadError![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(cap)) catch |err| {
        return switch (err) {
            error.FileTooBig => error.TooLarge,
            else => error.FileMissing,
        };
    };
}

/// Atomic write (temp + rename), the established store pattern.
fn writeAtomic(io: std.Io, path: []const u8, data: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |dir| try cwd.createDirPath(io, dir);
    var tmp_buf: [2048]u8 = undefined;
    const tmp = std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path}) catch return error.PathTooLong;
    var file = try cwd.createFile(io, tmp, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, data);
    try file.sync(io);
    std.Io.Dir.renameAbsolute(tmp, path, io) catch return error.RenameFailed;
}

// --- payload build / parse ---------------------------------------------------

/// Reads the requested sections and assembles the payload document.
pub fn buildPayload(io: std.Io, allocator: std.mem.Allocator, sections: []const Section) PayloadError!Payload {
    var payload = Payload{
        .version = version,
        .exported_at = @intCast(std.Io.Timestamp.now(io, .real).nanoseconds),
        .sections = std.StringArrayHashMapUnmanaged(std.json.Value).empty,
    };
    errdefer payload.deinit(allocator);
    for (sections) |section| {
        var raw: []u8 = undefined;
        if (readSmallFile(io, allocator, section.path, max_file_bytes)) |content| {
            raw = content;
        } else |_| {
            raw = try allocator.dupe(u8, "[]");
        }
        defer allocator.free(raw);
        var text: []const u8 = raw;
        var converted: ?[]u8 = null;
        if (section.jsonl) {
            const conv = try jsonlToArray(allocator, raw);
            text = conv;
            converted = conv;
        }
        defer if (converted) |c| allocator.free(c);
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{ .allocate = .alloc_always, .max_value_len = max_file_bytes }) catch {
            return error.InvalidJson;
        };
        defer parsed.deinit();
        if (parsed.value == .array) {
            try validateNoDuplicateIds(allocator, &parsed.value);
        }
        // Deep-copy into the payload: the parse tree dies with `parsed`.
        var copy = try cloneValue(allocator, &parsed.value);
        errdefer freeValue(allocator, &copy);
        try payload.sections.put(allocator, try allocator.dupe(u8, section.name), copy);
    }
    return payload;
}

/// Converts a JSONL document into a JSON array text.
fn jsonlToArray(allocator: std.mem.Allocator, raw: []const u8) PayloadError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var owned = false;
    errdefer if (!owned) out.deinit(allocator);
    try out.append(allocator, '[');
    var first = true;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] != '{') continue;
        if (!first) try out.append(allocator, ',');
        first = false;
        try out.appendSlice(allocator, line);
    }
    try out.append(allocator, ']');
    const slice = try out.toOwnedSlice(allocator);
    owned = true;
    return slice;
}

/// Rejects duplicate `id` values inside one array section (spec 17 §10:
/// Oars does not guess which duplicate is newer).
fn validateNoDuplicateIds(allocator: std.mem.Allocator, value: *const std.json.Value) PayloadError!void {
    if (value.* != .array) return;
    var seen = std.StringHashMap(void).init(allocator);
    defer {
        var it = seen.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        seen.deinit();
    }
    for (value.array.items) |*item| {
        const id = recordId(allocator, item) orelse return error.RecordWithoutId;
        // `contains` would miss the just-allocated `id` free on duplicate;
        // use `getOrPut` ownership pattern.
        const gop = try seen.getOrPut(id);
        if (gop.found_existing) {
            allocator.free(id);
            return error.DuplicateId;
        }
        // `id` is now owned by the map; do not free here.
    }
}

/// The record's `id` string (allocated) or null when absent/not a string.
fn recordId(allocator: std.mem.Allocator, record: *const std.json.Value) ?[]const u8 {
    if (record.* != .object) return null;
    const v = record.object.get("id") orelse return null;
    if (v != .string) return null;
    return allocator.dupe(u8, v.string) catch null;
}

fn cloneValue(allocator: std.mem.Allocator, value: *const std.json.Value) !std.json.Value {
    return switch (value.*) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .integer => |i| .{ .integer = i },
        .float => |f| .{ .float = f },
        .number_string => |s| .{ .number_string = try allocator.dupe(u8, s) },
        .string => |s| .{ .string = try allocator.dupe(u8, s) },
        .array => |arr| blk: {
            var out = std.json.Array.init(allocator);
            errdefer out.deinit();
            for (arr.items) |*item| {
                var copy = try cloneValue(allocator, item);
                out.append(copy) catch {
                    freeValue(allocator, &copy);
                    return error.OutOfMemory;
                };
            }
            break :blk .{ .array = out };
        },
        .object => |obj| blk: {
            var out = std.json.ObjectMap.empty;
            errdefer out.deinit(allocator);
            var it = obj.iterator();
            while (it.next()) |entry| {
                var copy = try cloneValue(allocator, entry.value_ptr);
                out.put(allocator, try allocator.dupe(u8, entry.key_ptr.*), copy) catch {
                    allocator.free(entry.key_ptr.*);
                    freeValue(allocator, &copy);
                    return error.OutOfMemory;
                };
            }
            break :blk .{ .object = out };
        },
    };
}

fn freeValue(allocator: std.mem.Allocator, value: *std.json.Value) void {
    switch (value.*) {
        .null, .bool, .integer, .float => {},
        .number_string => |str| allocator.free(str),
        .string => |str| allocator.free(str),
        .array => |*arr| {
            for (arr.items) |*item| freeValue(allocator, item);
            arr.deinit();
        },
        .object => |*obj| {
            var it = obj.iterator();
            while (it.next()) |e| {
                allocator.free(e.key_ptr.*);
                freeValue(allocator, @constCast(e.value_ptr));
            }
            obj.deinit(allocator);
        },
    }
}

/// Serializes the payload document. Section names are store-owned
/// constants, so they are written raw (no escaping needed).
pub fn serializePayload(allocator: std.mem.Allocator, payload: *const Payload) ![]u8 {
    var scratch: std.ArrayList(u8) = .empty;
    var aw = std.Io.Writer.Allocating.fromArrayList(allocator, &scratch);
    defer aw.deinit();
    const w = &aw.writer;
    try w.print("{{\"version\":{d},\"exported_at\":{d},\"sections\":{{", .{ payload.version, payload.exported_at });
    var first = true;
    var it = payload.sections.iterator();
    while (it.next()) |e| {
        if (!first) try w.writeAll(",");
        first = false;
        try w.writeAll("\"");
        try w.writeAll(e.key_ptr.*);
        try w.writeAll("\":");
        try std.json.Stringify.value(e.value_ptr.*, .{}, w);
    }
    try w.writeAll("}}");
    var list = aw.toArrayList();
    return list.toOwnedSlice(allocator);
}

/// Parses a payload document (import side — always re-validated; the
/// file may be hand-crafted).
pub fn parsePayload(allocator: std.mem.Allocator, text: []const u8) PayloadError!Payload {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{ .allocate = .alloc_always, .max_value_len = max_file_bytes }) catch return error.InvalidJson;
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return error.InvalidJson;
    const version_v = root.object.get("version") orelse return error.InvalidJson;
    if (version_v != .integer or version_v.integer != version) return error.UnsupportedVersion;
    var payload = Payload{
        .version = version,
        .exported_at = if (root.object.get("exported_at")) |ts| if (ts == .integer) ts.integer else 0 else 0,
        .sections = std.StringArrayHashMapUnmanaged(std.json.Value).empty,
    };
    errdefer payload.deinit(allocator);
    const sections_v = root.object.get("sections") orelse return error.InvalidJson;
    if (sections_v != .object) return error.InvalidJson;
    var it = sections_v.object.iterator();
    while (it.next()) |entry| {
        var copy = try cloneValue(allocator, entry.value_ptr);
        errdefer freeValue(allocator, &copy);
        if (copy == .array) {
            try validateNoDuplicateIds(allocator, &copy);
        }
        try payload.sections.put(allocator, try allocator.dupe(u8, entry.key_ptr.*), copy);
    }
    return payload;
}

// --- vault file format ------------------------------------------------------

/// Writes the encrypted vault file: magic, version, KDF parameters,
/// salt, nonce, ciphertext length, ciphertext, tag. Everything before
/// the ciphertext is the GCM AAD.
pub fn writeVaultFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8, password: []const u8, plaintext: []const u8) PayloadError!void {
    if (password.len < min_password_len) return error.PasswordTooShort;
    var salt: [salt_len]u8 = undefined;
    std.Io.random(io, &salt);
    var nonce: [nonce_len]u8 = undefined;
    std.Io.random(io, &nonce);
    var key: [crypto.key_len]u8 = undefined;
    crypto.pbkdf2Sha256(password, &salt, kdf_iterations, &key) catch return error.KdfFailed;
    defer std.crypto.secureZero(u8, &key);

    // Header layout (fixed offsets, big-endian numbers).
    const header_len = 9 + 1 + 1 + 4 + 1 + salt_len + 1 + nonce_len + 8;
    var header: [header_len]u8 = undefined;
    @memcpy(header[0..9], magic);
    header[9] = version;
    header[10] = kdf_id_pbkdf2_sha256;
    std.mem.writeInt(u32, header[11..15], kdf_iterations, .big);
    header[15] = salt_len;
    @memcpy(header[16 .. 16 + salt_len], &salt);
    header[16 + salt_len] = nonce_len;
    @memcpy(header[17 + salt_len .. 17 + salt_len + nonce_len], &nonce);
    std.mem.writeInt(u64, header[17 + salt_len + nonce_len ..][0..8], plaintext.len, .big);

    const ciphertext: []u8 = try allocator.alloc(u8, plaintext.len);
    defer allocator.free(ciphertext);
    var tag: [tag_len]u8 = undefined;
    crypto.gcmSeal(&key, &nonce, &header, plaintext, ciphertext, &tag) catch return error.SealFailed;

    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |dir| cwd.createDirPath(io, dir) catch return error.WriteFailed;
    var file = cwd.createFile(io, path, .{}) catch return error.WriteFailed;
    defer file.close(io);
    file.writeStreamingAll(io, &header) catch return error.WriteFailed;
    file.writeStreamingAll(io, ciphertext) catch return error.WriteFailed;
    file.writeStreamingAll(io, &tag) catch return error.WriteFailed;
    file.sync(io) catch return error.WriteFailed;
}

/// Reads and authenticates a vault file, returning the plaintext
/// payload JSON. Wrong password, tampered header, and corrupted
/// ciphertext all surface as `error.AuthFailed` — one honest error.
pub fn readVaultFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8, password: []const u8) PayloadError![]u8 {
    const content = readSmallFile(io, allocator, path, max_file_bytes) catch return error.FileMissing;
    defer allocator.free(content);
    const header_len = 17 + salt_len + nonce_len + 8;
    if (content.len < header_len + tag_len) return error.NotAVault;
    if (!std.mem.eql(u8, content[0..9], magic)) return error.NotAVault;
    if (content[9] != version) return error.UnsupportedVersion;
    if (content[10] != kdf_id_pbkdf2_sha256) return error.UnsupportedVersion;
    const iterations = std.mem.readInt(u32, content[11..15], .big);
    if (content[15] != salt_len or content[16 + salt_len] != nonce_len) return error.NotAVault;
    var salt: [salt_len]u8 = undefined;
    @memcpy(&salt, content[16 .. 16 + salt_len]);
    var nonce: [nonce_len]u8 = undefined;
    @memcpy(&nonce, content[17 + salt_len .. 17 + salt_len + nonce_len]);
    const ct_len = std.mem.readInt(u64, content[17 + salt_len + nonce_len ..][0..8], .big);
    if (ct_len > content.len - header_len - tag_len) return error.NotAVault;
    const ct = content[header_len .. header_len + @as(usize, @intCast(ct_len))];
    const tag = content[header_len + @as(usize, @intCast(ct_len)) .. header_len + @as(usize, @intCast(ct_len)) + tag_len];

    var key: [crypto.key_len]u8 = undefined;
    crypto.pbkdf2Sha256(password, &salt, iterations, &key) catch return error.KdfFailed;
    defer std.crypto.secureZero(u8, &key);

    const plaintext = try allocator.alloc(u8, ct.len);
    errdefer allocator.free(plaintext);
    var tag_arr: [tag_len]u8 = undefined;
    @memcpy(&tag_arr, tag);
    crypto.gcmOpen(&key, &nonce, content[0..header_len], ct, &tag_arr, plaintext) catch return error.AuthFailed;
    return plaintext;
}

// --- import preview / apply -------------------------------------------------

/// Identity fields that bind an id to a destination (spec 17 §6): an
/// imported record whose identity differs cannot update in place — it
/// would silently inherit the local Keychain credential.
fn identityConflict(allocator: std.mem.Allocator, section: []const u8, local: *const std.json.Value, incoming: *const std.json.Value) ?[]const u8 {
    if (std.mem.eql(u8, section, "servers")) {
        const host_eq = stringFieldEqual(local, incoming, "host");
        const port_eq = numberFieldEqual(local, incoming, "port");
        const user_eq = stringFieldEqual(local, incoming, "user");
        const auth_eq = stringFieldEqual(local, incoming, "auth_method");
        if (!host_eq or !port_eq or !user_eq or !auth_eq) {
            return allocator.dupe(u8, "endpoint or auth method changed") catch null;
        }
    } else if (std.mem.eql(u8, section, "apps")) {
        if (!stringFieldEqual(local, incoming, "server_id")) {
            return allocator.dupe(u8, "target server changed") catch null;
        }
    } else if (std.mem.eql(u8, section, "backup_jobs")) {
        if (!stringFieldEqual(local, incoming, "server_id")) {
            return allocator.dupe(u8, "target server changed") catch null;
        }
        if (incoming.object.get("destination")) |dest| {
            if (local.object.get("destination")) |ldest| {
                if (dest == .object and ldest == .object) {
                    if (!stringFieldEqual(&ldest, &dest, "bucket") or !stringFieldEqual(&ldest, &dest, "endpoint")) {
                        return allocator.dupe(u8, "destination changed") catch null;
                    }
                }
            }
        }
    }
    return null;
}

fn stringFieldEqual(a: *const std.json.Value, b: *const std.json.Value, field: []const u8) bool {
    if (a.* != .object or b.* != .object) return false;
    const av = a.object.get(field);
    const bv = b.object.get(field);
    if (av == null and bv == null) return true;
    if (av == null or bv == null) return false;
    if (av.? != .string or bv.? != .string) return false;
    return std.mem.eql(u8, av.?.string, bv.?.string);
}

fn numberFieldEqual(a: *const std.json.Value, b: *const std.json.Value, field: []const u8) bool {
    if (a.* != .object or b.* != .object) return false;
    const av = a.object.get(field);
    const bv = b.object.get(field);
    if (av == null and bv == null) return true;
    if (av == null or bv == null) return false;
    if (av.? != .integer or bv.? != .integer) return false;
    return av.?.integer == bv.?.integer;
}

/// Loads the local section content (empty array when missing).
fn loadLocalSection(io: std.Io, allocator: std.mem.Allocator, section: *const Section) PayloadError!std.json.Value {
    var raw: []u8 = undefined;
    if (readSmallFile(io, allocator, section.path, max_file_bytes)) |content| {
        raw = content;
    } else |_| {
        return .{ .array = std.json.Array.init(allocator) };
    }
    defer allocator.free(raw);
    var text: []const u8 = raw;
    var converted: ?[]u8 = null;
    if (section.jsonl) {
        const conv = try jsonlToArray(allocator, raw);
        text = conv;
        converted = conv;
    }
    defer if (converted) |c| allocator.free(c);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{ .allocate = .alloc_always, .max_value_len = max_file_bytes }) catch return error.InvalidJson;
    defer parsed.deinit();
    var copy = try cloneValue(allocator, &parsed.value);
    errdefer freeValue(allocator, &copy);
    return copy;
}

/// Dry-run analysis: per-section incoming/new/updated counts plus the
/// credential-binding conflicts. Never writes.
pub fn previewImport(io: std.Io, allocator: std.mem.Allocator, payload: *const Payload, sections: []const Section) PayloadError!Preview {
    var preview = Preview{
        .reports = std.ArrayList(SectionReport).empty,
        .errors = std.ArrayList(Conflict).empty,
    };
    errdefer preview.deinit(allocator);
    for (sections) |*section| {
        const incoming = payload.sections.get(section.name) orelse continue;
        if (incoming != .array) continue; // ai_provider handled separately
        var report = SectionReport{
            .name = try allocator.dupe(u8, section.name),
            .incoming = incoming.array.items.len,
            .new = 0,
            .updated = 0,
            .conflicts = std.ArrayList(Conflict).empty,
        };
        errdefer report.deinit(allocator);
        var local = try loadLocalSection(io, allocator, section);
        defer freeValue(allocator, &local);
        for (incoming.array.items) |*record| {
            const id = recordId(allocator, record) orelse {
                // Missing id: a validation error, never a silent guess.
                const key = try std.fmt.allocPrint(allocator, "{s}: (no id)", .{section.name});
                errdefer allocator.free(key);
                try preview.errors.append(allocator, .{ .key = key, .reason = try allocator.dupe(u8, "record without id") });
                continue;
            };
            defer allocator.free(id);
            var found_local: ?*std.json.Value = null;
            if (local == .array) {
                for (local.array.items) |*l| {
                    const lid = recordId(allocator, l) orelse continue;
                    defer allocator.free(lid);
                    if (std.mem.eql(u8, lid, id)) {
                        found_local = l;
                        break;
                    }
                }
            }
            if (found_local) |l| {
                if (identityConflict(allocator, section.name, l, record)) |reason| {
                    var key_buf: [512]u8 = undefined;
                    const key = std.fmt.bufPrint(&key_buf, "{s}:{s}", .{ section.name, id }) catch unreachable;
                    try report.conflicts.append(allocator, .{
                        .key = try allocator.dupe(u8, key),
                        .reason = reason,
                    });
                } else {
                    report.updated += 1;
                }
            } else {
                report.new += 1;
            }
        }
        try preview.reports.append(allocator, report);
    }
    // ai_provider: single object, replaces the local config on import.
    if (payload.sections.get("ai_provider")) |provider| {
        if (provider == .object) {
            try preview.reports.append(allocator, .{
                .name = try allocator.dupe(u8, "ai_provider"),
                .incoming = 1,
                .new = 1,
                .updated = 0,
                .conflicts = std.ArrayList(Conflict).empty,
            });
        }
    }
    return preview;
}

fn optionHas(options: ImportOptions, key: []const u8, as_new: bool) bool {
    const list: []const []const u8 = if (as_new) options.import_as_new else options.keep_local;
    for (list) |k| {
        if (std.mem.eql(u8, k, key)) return true;
    }
    return false;
}

/// Merges the payload into the local stores and writes each section
/// atomically. Runs only after a preview; unaddressed credential
/// conflicts are skipped (keep local) and reported.
pub fn applyImport(io: std.Io, allocator: std.mem.Allocator, payload: *const Payload, sections: []const Section, options: ImportOptions) PayloadError!ImportResult {
    var result = ImportResult{ .notes = std.ArrayList([]const u8).empty };
    errdefer result.deinit(allocator);
    for (sections) |*section| {
        const incoming = payload.sections.get(section.name) orelse continue;
        if (incoming != .array) continue;
        var local = try loadLocalSection(io, allocator, section);
        defer freeValue(allocator, &local);
        if (local != .array) {
            freeValue(allocator, &local);
            local = .{ .array = std.json.Array.init(allocator) };
        }
        var skipped: usize = 0;
        var as_new_count: usize = 0;
        // old id -> fresh id for records imported as new; references in
        // the merged set (via chains, app/backup targets) follow.
        var id_map: std.StringArrayHashMapUnmanaged([]const u8) = std.StringArrayHashMapUnmanaged([]const u8).empty;
        defer {
            var it = id_map.iterator();
            while (it.next()) |e| {
                allocator.free(e.key_ptr.*);
                allocator.free(e.value_ptr.*);
            }
            id_map.deinit(allocator);
        }
        for (incoming.array.items) |*record| {
            const id = recordId(allocator, record) orelse continue;
            defer allocator.free(id);
            var key_buf: [512]u8 = undefined;
            const key = std.fmt.bufPrint(&key_buf, "{s}:{s}", .{ section.name, id }) catch unreachable;
            var found_idx: ?usize = null;
            for (local.array.items, 0..) |*l, i| {
                const lid = recordId(allocator, l) orelse continue;
                defer allocator.free(lid);
                if (std.mem.eql(u8, lid, id)) {
                    found_idx = i;
                    break;
                }
            }
            if (found_idx) |idx| {
                const local_rec = local.array.items[idx];
                if (identityConflict(allocator, section.name, &local_rec, record)) |reason| {
                    defer allocator.free(reason);
                    if (optionHas(options, key, true)) {
                        // Import under a fresh id; remember the mapping so
                        // references follow (via chains, app targets).
                        var new_id_buf: [128]u8 = undefined;
                        const new_id = std.fmt.bufPrint(&new_id_buf, "imp-{s}-{d}", .{ section.name, as_new_count }) catch unreachable;
                        as_new_count += 1;
                        var copy = try cloneValue(allocator, record);
                        if (copy == .object) {
                            // Remove old "id" entry so its key+value are freed without leaking the replacement key.
                            if (copy.object.fetchOrderedRemove("id")) |kv| {
                                allocator.free(kv.key);
                                var old_val = kv.value;
                                freeValue(allocator, &old_val);
                            }
                            try copy.object.put(allocator, try allocator.dupe(u8, "id"), .{ .string = try allocator.dupe(u8, new_id) });
                            try id_map.put(allocator, try allocator.dupe(u8, id), try allocator.dupe(u8, new_id));
                            try local.array.append(copy);
                        } else {
                            freeValue(allocator, &copy);
                        }
                    } else {
                        skipped += 1; // keep local
                    }
                    continue;
                }
                // Update in place.
                var old = local.array.orderedRemove(idx);
                freeValue(allocator, &old);
                var copy = try cloneValue(allocator, record);
                local.array.insert(idx, copy) catch {
                    freeValue(allocator, &copy);
                    return error.OutOfMemory;
                };
            } else {
                var copy = try cloneValue(allocator, record);
                local.array.append(copy) catch {
                    freeValue(allocator, &copy);
                    return error.OutOfMemory;
                };
            }
        }
        // Rewrite references to import_as_new server ids (via chains).
        if (std.mem.eql(u8, section.name, "servers") and id_map.count() > 0) {
            for (local.array.items) |*rec| {
                if (rec.* == .object) {
                    if (rec.object.get("via_server_id")) |via| {
                        if (via == .string) {
                            if (id_map.get(via.string)) |replacement| {
                                if (rec.object.fetchOrderedRemove("via_server_id")) |kv| {
                                    allocator.free(kv.key);
                                    var old_val = kv.value;
                                    freeValue(allocator, &old_val);
                                }
                                try rec.object.put(allocator, try allocator.dupe(u8, "via_server_id"), .{ .string = try allocator.dupe(u8, replacement) });
                            }
                        }
                    }
                }
            }
        }
        // Serialize + atomic write (JSONL stores get one record per line).
        var scratch: std.ArrayList(u8) = .empty;
        var aw = std.Io.Writer.Allocating.fromArrayList(allocator, &scratch);
        defer aw.deinit();
        if (section.jsonl) {
            for (local.array.items) |*rec| {
                std.json.Stringify.value(rec.*, .{}, &aw.writer) catch return error.OutOfMemory;
                aw.writer.writeAll("\n") catch return error.OutOfMemory;
            }
        } else {
            std.json.Stringify.value(local, .{ .whitespace = .indent_2 }, &aw.writer) catch return error.OutOfMemory;
        }
        var list = aw.toArrayList();
        defer list.deinit(allocator);
        writeAtomic(io, section.path, list.items) catch return error.WriteFailed;
        var note_buf: std.ArrayList(u8) = .empty;
        var naw = std.Io.Writer.Allocating.fromArrayList(allocator, &note_buf);
        defer naw.deinit();
        naw.writer.print("{s}: {d} imported", .{ section.name, incoming.array.items.len }) catch return error.OutOfMemory;
        if (skipped > 0) naw.writer.print(", {d} kept local (credential conflict)", .{skipped}) catch return error.OutOfMemory;
        if (as_new_count > 0) naw.writer.print(", {d} imported as new ids", .{as_new_count}) catch return error.OutOfMemory;
        var nlist = naw.toArrayList();
        defer nlist.deinit(allocator);
        try result.notes.append(allocator, nlist.toOwnedSlice(allocator) catch return error.OutOfMemory);
    }
    // ai_provider: single object replace.
    if (payload.sections.get("ai_provider")) |provider| {
        if (provider == .object) {
            for (sections) |*section| {
                if (!std.mem.eql(u8, section.name, "ai_provider")) continue;
                var scratch: std.ArrayList(u8) = .empty;
                var aw = std.Io.Writer.Allocating.fromArrayList(allocator, &scratch);
                defer aw.deinit();
                std.json.Stringify.value(provider, .{ .whitespace = .indent_2 }, &aw.writer) catch return error.OutOfMemory;
                var list = aw.toArrayList();
                defer list.deinit(allocator);
                writeAtomic(io, section.path, list.items) catch return error.WriteFailed;
                const note = try std.fmt.allocPrint(allocator, "ai_provider: config imported (Keychain keys are never part of a vault)", .{});
                try result.notes.append(allocator, note);
            }
        }
    }
    return result;
}

// --- tests -----------------------------------------------------------------

const testing = std.testing;

fn testPath(comptime tag: []const u8, path_buf: *[512]u8, name: []const u8) ![]const u8 {
    const io = testing.io;
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    const dir_name = try std.fmt.bufPrint(path_buf[0..128], "oars-v-{s}-{d}", .{ tag, now });
    return std.fmt.bufPrint(path_buf[128..], "/tmp/{s}/{s}", .{ dir_name, name });
}

fn testCleanup(path: []const u8) void {
    const io = testing.io;
    const base = std.fs.path.basename(std.fs.path.dirname(path) orelse return);
    std.Io.Dir.cwd().deleteTree(io, base) catch {};
}

test "vault file round trip: seal, read back, wrong password and tamper rejected" {
    const allocator = testing.allocator;
    const io = testing.io;
    var path_buf: [512]u8 = undefined;
    const path = try testPath("roundtrip", &path_buf, "test.oarsvault");
    defer testCleanup(path);

    const payload = "{\"version\":1,\"sections\":{\"servers\":[]}}";
    try writeVaultFile(io, allocator, path, "correct horse battery", payload);
    const plain = try readVaultFile(io, allocator, path, "correct horse battery");
    defer allocator.free(plain);
    try testing.expectEqualStrings(payload, plain);

    // Wrong password fails auth (same error as corruption).
    try testing.expectError(error.AuthFailed, readVaultFile(io, allocator, path, "wrong password!!"));

    // A flipped byte in the salt/ciphertext/tag fails auth (same error
    // as a wrong password). Flipping the version byte is a different
    // error (UnsupportedVersion) — test it separately.
    const content = try readSmallFile(io, allocator, path, max_file_bytes);
    defer allocator.free(content);
    const header_len = 17 + salt_len + nonce_len + 8;
    // Tamper with a ciphertext byte (guaranteed to be inside ct when
    // payload is non-empty) — must be AuthFailed, not UnsupportedVersion.
    {
        var tampered = try allocator.dupe(u8, content);
        defer allocator.free(tampered);
        // Flip a byte after the header (inside ciphertext/tag).
        const off: usize = if (tampered.len > header_len + 5) header_len + 5 else 16;
        tampered[off] ^= 0x01;
        var tp: [512]u8 = undefined;
        const tpath = try testPath("tamper", &tp, "tampered.oarsvault");
        try writeAtomic(io, tpath, tampered);
        try testing.expectError(error.AuthFailed, readVaultFile(io, allocator, tpath, "correct horse battery"));
        testCleanup(tpath);
    }
    // Version tamper is UnsupportedVersion, not AuthFailed.
    {
        var tampered2 = try allocator.dupe(u8, content);
        defer allocator.free(tampered2);
        tampered2[9] ^= 0x01; // version byte
        var tp2: [512]u8 = undefined;
        const tpath2 = try testPath("tamper2", &tp2, "tampered2.oarsvault");
        try writeAtomic(io, tpath2, tampered2);
        try testing.expectError(error.UnsupportedVersion, readVaultFile(io, allocator, tpath2, "correct horse battery"));
        testCleanup(tpath2);
    }

    // Short passwords are refused at export time.
    try testing.expectError(error.PasswordTooShort, writeVaultFile(io, allocator, path, "short", payload));
}

test "two exports with the same password differ in salt and nonce" {
    const allocator = testing.allocator;
    const io = testing.io;
    var path_buf: [512]u8 = undefined;
    const path = try testPath("salt", &path_buf, "salt.oarsvault");
    defer testCleanup(path);
    const payload = "{\"version\":1,\"sections\":{}}";
    try writeVaultFile(io, allocator, path, "correct horse battery", payload);
    const first = try readSmallFile(io, allocator, path, max_file_bytes);
    defer allocator.free(first);
    try writeVaultFile(io, allocator, path, "correct horse battery", payload);
    const second = try readSmallFile(io, allocator, path, max_file_bytes);
    defer allocator.free(second);
    // The salt (bytes 16..32) and nonce (bytes 33..45) are random per file.
    try testing.expect(!std.mem.eql(u8, first[16..32], second[16..32]));
    try testing.expect(!std.mem.eql(u8, first[33..45], second[33..45]));
}

test "buildPayload validates jsonl conversion and duplicate ids" {
    const allocator = testing.allocator;
    const io = testing.io;
    var path_buf: [512]u8 = undefined;
    const hist_path = try testPath("jsonl", &path_buf, "history.jsonl");
    defer testCleanup(hist_path);
    try writeAtomic(io, hist_path, "{\"id\":\"h-1\",\"ts\":1}\n{\"id\":\"h-2\",\"ts\":2}\n");

    var payload = try buildPayload(io, allocator, &.{.{ .name = "history", .path = hist_path, .jsonl = true }});
    defer payload.deinit(allocator);
    const sec = payload.sections.get("history").?;
    try testing.expectEqual(@as(usize, 2), sec.array.items.len);

    // Duplicate ids inside one section are rejected.
    var dup_buf: [512]u8 = undefined;
    const dup_path = try testPath("dup", &dup_buf, "servers.json");
    try writeAtomic(io, dup_path, "[{\"id\":\"s1\"},{\"id\":\"s1\"}]");
    try testing.expectError(error.DuplicateId, buildPayload(io, allocator, &.{.{ .name = "servers", .path = dup_path }}));
}

test "preview reports merge counts and credential-binding conflicts" {
    const allocator = testing.allocator;
    const io = testing.io;
    var path_buf: [512]u8 = undefined;
    const local_path = try testPath("preview", &path_buf, "servers.json");
    defer testCleanup(local_path);
    // Local: s1 (1.1.1.1), s2.
    try writeAtomic(io, local_path, "[{\"id\":\"s1\",\"host\":\"1.1.1.1\",\"port\":22,\"user\":\"root\",\"auth_method\":\"password\"},{\"id\":\"s2\",\"host\":\"2.2.2.2\",\"port\":22,\"user\":\"root\",\"auth_method\":\"password\"}]");

    // Incoming: s1 with a CHANGED host (credential conflict), s2 unchanged, s3 new.
    var payload = try parsePayload(allocator,
        \\{"version":1,"exported_at":0,"sections":{"servers":[{"id":"s1","host":"9.9.9.9","port":22,"user":"root","auth_method":"password"},{"id":"s2","host":"2.2.2.2","port":22,"user":"root","auth_method":"password"},{"id":"s3","host":"3.3.3.3","port":22,"user":"root","auth_method":"password"}]}}
    );
    defer payload.deinit(allocator);

    const sec = Section{ .name = "servers", .path = local_path };
    var preview = try previewImport(io, allocator, &payload, &.{sec});
    defer preview.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), preview.reports.items.len);
    const report = &preview.reports.items[0];
    try testing.expectEqual(@as(usize, 1), report.new);
    try testing.expectEqual(@as(usize, 1), report.updated);
    try testing.expectEqual(@as(usize, 1), report.conflicts.items.len);
    try testing.expectEqualStrings("servers:s1", report.conflicts.items[0].key);
    try testing.expect(std.mem.indexOf(u8, report.conflicts.items[0].reason, "endpoint") != null);

    // Apply with keep-local for s1: s2 updated, s3 added, s1 untouched.
    var result = try applyImport(io, allocator, &payload, &.{sec}, .{
        .keep_local = &.{"servers:s1"},
    });
    defer result.deinit(allocator);
    var local_after = try loadLocalSection(io, allocator, &.{ .name = "servers", .path = local_path });
    defer freeValue(allocator, &local_after);
    try testing.expectEqual(@as(usize, 3), local_after.array.items.len);
    for (local_after.array.items) |*rec| {
        if (std.mem.eql(u8, rec.object.get("id").?.string, "s1")) {
            try testing.expectEqualStrings("1.1.1.1", rec.object.get("host").?.string); // kept local
        }
    }

    // Apply again with import-as-new for s1: a fresh id is used and the
    // old endpoint is NOT overwritten (no silent credential attach).
    var payload2 = try parsePayload(allocator,
        \\{"version":1,"exported_at":0,"sections":{"servers":[{"id":"s1","host":"9.9.9.9","port":22,"user":"root","auth_method":"password","via_server_id":"s2"}]}}
    );
    defer payload2.deinit(allocator);
    var result2 = try applyImport(io, allocator, &payload2, &.{sec}, .{
        .import_as_new = &.{"servers:s1"},
    });
    defer result2.deinit(allocator);
    var local_final = try loadLocalSection(io, allocator, &.{ .name = "servers", .path = local_path });
    defer freeValue(allocator, &local_final);
    try testing.expectEqual(@as(usize, 4), local_final.array.items.len);
    var saw_new = false;
    for (local_final.array.items) |*rec| {
        const id = rec.object.get("id").?.string;
        if (std.mem.startsWith(u8, id, "imp-servers-")) {
            saw_new = true;
            try testing.expectEqualStrings("9.9.9.9", rec.object.get("host").?.string);
        }
    }
    try testing.expect(saw_new);
}
