//! Spec 09: fleet-wide access map — identity registry, scan model,
//! fingerprint-keyed grant matching, mutation jobs, and CSV/JSON export
//! formatting.
//!
//! This module is pure logic + registries. A single access coordinator drives
//! the per-session worker operations; poll handlers only copy snapshots.
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

const identity_store_version: u32 = 1;
const identity_random_bytes: usize = 16;

/// One stored fingerprint binding. Per-fingerprint `shared` is the v1
/// authority (spec NEXT-SPEC § Identity store).
pub const IdentityBinding = struct {
    fingerprint: []const u8,
    shared: bool = false,

    pub fn deinit(self: *IdentityBinding, allocator: std.mem.Allocator) void {
        allocator.free(self.fingerprint);
    }
};

pub const Identity = struct {
    id: []const u8,
    name: []const u8,
    fingerprints: []const []const u8 = &.{},
    /// v1: per-fingerprint authority.
    bindings: []IdentityBinding = &.{},
    /// Legacy top-level mirror (derived from bindings on load/save).
    shared: bool = false,
    /// Integer milliseconds (bridge contract).
    created_at_ms: i64 = 0,
    /// Monotonic revision, 1 on create, +1 on every mutation.
    revision: u64 = 1,
    /// Back-compat alias used internally until callers switch fully to
    /// `created_at_ms`.
    created_at_ns: i64 = 0,

    pub fn deinit(self: *Identity, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        for (self.fingerprints) |fp| allocator.free(fp);
        allocator.free(self.fingerprints);
        for (self.bindings) |*b| b.deinit(allocator);
        allocator.free(self.bindings);
    }

    /// Returns the shared flag for `fingerprint`, consulting bindings first
    /// then the legacy `shared` fallback.
    pub fn bindingShared(self: *const Identity, fingerprint: []const u8) bool {
        for (self.bindings) |b| {
            if (std.mem.eql(u8, b.fingerprint, fingerprint)) return b.shared;
        }
        return self.shared;
    }
};

pub const IdentityInput = struct {
    id: ?[]const u8 = null,
    name: []const u8,
    fingerprints: []const []const u8 = &.{},
    bindings: []const IdentityBindingInput = &.{},
    shared: bool = false,
    expected_revision: ?u64 = null,
};

pub const IdentityBindingInput = struct {
    fingerprint: []const u8,
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
    DuplicateId,
    MissingId,
    UnknownId,
    RevisionConflict,
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
    mutex: std.atomic.Mutex = .unlocked,

    const StoreDoc = struct {
        version: u32 = identity_store_version,
        identities: []Identity = &.{},
    };

    /// Raw doc parsed from disk before normalization (accepts legacy bare
    /// array as well as versioned docs).
    const RawDoc = struct {
        version: ?u32 = null,
        identities: ?[]Identity = null,
    };

    /// One cryptographically random identity id, hex-encoded (32 chars).
    pub fn randomId(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
        var rnd: [identity_random_bytes]u8 = undefined;
        try std.Io.randomSecure(io, &rnd);
        const hex = std.fmt.bytesToHex(rnd, .lower);
        return allocator.dupe(u8, &hex);
    }

    pub const Loaded = struct {
        parsed: std.json.Parsed([]Identity),
        content: ?[]u8,
        quarantined: ?[]const u8 = null,
        /// Present when load recovered from corruption.
        recovery_error: ?[]const u8 = null,

        pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
            self.parsed.deinit();
            if (self.content) |c| allocator.free(c);
            if (self.quarantined) |q| allocator.free(q);
            if (self.recovery_error) |e| allocator.free(e);
        }
    };

    pub fn loadParsed(self: *IdentityStore, io: std.Io) !Loaded {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.loadParsedLocked(io);
    }

    fn normalizeIdentity(allocator: std.mem.Allocator, ident: *Identity) !void {
        // Backfill created_at_ms from legacy created_at_ns.
        if (ident.created_at_ms == 0 and ident.created_at_ns != 0) {
            ident.created_at_ms = @divTrunc(ident.created_at_ns, std.time.ns_per_ms);
        }
        if (ident.created_at_ns == 0 and ident.created_at_ms != 0) {
            ident.created_at_ns = ident.created_at_ms * std.time.ns_per_ms;
        }
        if (ident.revision == 0) ident.revision = 1;
        if (ident.bindings.len == 0 and ident.fingerprints.len > 0) {
            const b = try allocator.alloc(IdentityBinding, ident.fingerprints.len);
            for (ident.fingerprints, 0..) |fp, i| {
                b[i] = .{ .fingerprint = try allocator.dupe(u8, fp), .shared = ident.shared };
            }
            ident.bindings = b;
        } else if (ident.bindings.len > 0 and ident.fingerprints.len == 0) {
            const fps = try allocator.alloc([]const u8, ident.bindings.len);
            for (ident.bindings, 0..) |bd, i| {
                fps[i] = try allocator.dupe(u8, bd.fingerprint);
            }
            ident.fingerprints = fps;
        }
        // Mirror top-level shared for bridge compat (true if any binding is shared).
        var any_shared = false;
        for (ident.bindings) |binding| {
            if (binding.shared) {
                any_shared = true;
                break;
            }
        }
        if (ident.bindings.len > 0) ident.shared = any_shared;
    }

    fn loadParsedLocked(self: *IdentityStore, io: std.Io) !Loaded {
        const cwd = std.Io.Dir.cwd();
        const content = cwd.readFileAlloc(io, self.path, self.allocator, .limited(4 * 1024 * 1024)) catch return emptyLoaded(self.allocator);
        // Try versioned doc first, then bare array (legacy).
        if (std.json.parseFromSlice(StoreDoc, self.allocator, content, .{})) |doc_parsed| {
            var doc = doc_parsed;
            // Duplicate-id detection.
            for (doc.value.identities, 0..) |a, i| {
                for (doc.value.identities[i + 1 ..]) |b| {
                    if (std.mem.eql(u8, a.id, b.id)) {
                        self.allocator.free(content);
                        doc.deinit();
                        return self.recoveredEmpty(io, "duplicate identity id");
                    }
                }
            }
            for (doc.value.identities) |*ident| {
                normalizeIdentity(self.allocator, ident) catch {
                    doc.deinit();
                    self.allocator.free(content);
                    return self.recoveredEmpty(io, "identity registry is unreadable");
                };
            }
            // Re-serialize into a Parsed([]Identity) shape so the rest of the
            // store keeps its current contract.
            const cloned = cloneIdentities(self.allocator, doc.value.identities) catch {
                doc.deinit();
                self.allocator.free(content);
                return self.recoveredEmpty(io, "identity registry is unreadable");
            };
            var out_buf: std.Io.Writer.Allocating = .init(self.allocator);
            const stringify_ok = blk: {
                std.json.Stringify.value(cloned, .{}, &out_buf.writer) catch break :blk false;
                break :blk true;
            };
            for (cloned) |*c| c.deinit(self.allocator);
            self.allocator.free(cloned);
            doc.deinit();
            self.allocator.free(content);
            if (!stringify_ok) {
                out_buf.deinit();
                return self.recoveredEmpty(io, "identity registry is unreadable");
            }
            const owned = out_buf.toOwnedSlice() catch {
                out_buf.deinit();
                return self.recoveredEmpty(io, "identity registry is unreadable");
            };
            defer self.allocator.free(owned);
            const reparsed = std.json.parseFromSlice([]Identity, self.allocator, owned, .{ .allocate = .alloc_always }) catch {
                out_buf.deinit();
                return self.recoveredEmpty(io, "identity registry is unreadable");
            };
            out_buf.deinit();
            return .{ .parsed = reparsed, .content = try self.allocator.dupe(u8, owned) };
        } else |_| {}
        if (std.json.parseFromSlice([]Identity, self.allocator, content, .{})) |parsed| {
            for (parsed.value) |*ident| {
                normalizeIdentity(self.allocator, ident) catch {
                    parsed.deinit();
                    self.allocator.free(content);
                    return self.recoveredEmpty(io, "identity registry is unreadable");
                };
            }
            // Duplicate-id check on legacy array as well.
            for (parsed.value, 0..) |a, i| {
                for (parsed.value[i + 1 ..]) |b| {
                    if (std.mem.eql(u8, a.id, b.id)) {
                        parsed.deinit();
                        self.allocator.free(content);
                        return self.recoveredEmpty(io, "duplicate identity id");
                    }
                }
            }
            return .{ .parsed = parsed, .content = content };
        } else |_| {}
        self.allocator.free(content);
        return self.recoveredEmpty(io, "identity registry is unreadable");
    }

    fn cloneIdentities(allocator: std.mem.Allocator, src: []const Identity) ![]Identity {
        const out = try allocator.alloc(Identity, src.len);
        errdefer allocator.free(out);
        for (src, 0..) |ident, i| {
            out[i] = try cloneIdentity(allocator, ident);
        }
        return out;
    }

    fn emptyLoaded(allocator: std.mem.Allocator) !Loaded {
        return .{
            .parsed = try std.json.parseFromSlice([]Identity, allocator, "[]", .{}),
            .content = null,
        };
    }

    fn recoveredEmpty(self: *IdentityStore, io: std.Io, message: []const u8) !Loaded {
        var loaded = try emptyLoaded(self.allocator);
        errdefer loaded.deinit(self.allocator);
        loaded.quarantined = self.quarantine(io) catch null;
        loaded.recovery_error = try self.allocator.dupe(u8, message);
        return loaded;
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
        const doc = StoreDoc{ .version = identity_store_version, .identities = @constCast(identities) };
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        std.json.Stringify.value(doc, .{ .whitespace = .indent_2 }, &out.writer) catch return error.SerializeFailed;
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

    fn tightenPermissions(self: *IdentityStore, io: std.Io) void {
        const cwd = std.Io.Dir.cwd();
        var file = cwd.openFile(io, self.path, .{ .mode = .read_write }) catch return;
        defer file.close(io);
        const stat = file.stat(io) catch return;
        if (stat.permissions.toMode() & 0o077 != 0) file.setPermissions(io, .fromMode(0o600)) catch {};
    }

    /// Upserts an identity. A fingerprint can belong to at most one person
    /// unless that exact binding is marked shared (spec 09 §5).
    /// Returns an owned copy.
    pub fn save(self: *IdentityStore, io: std.Io, input: IdentityInput, now_ms: i64) IdentitySaveError!Identity {
        const name = std.mem.trim(u8, input.name, " \t\r\n");
        if (name.len == 0) return error.MissingName;
        if (name.len > max_identity_name_len or hasControlChars(name)) return error.InvalidName;
        // Resolve the fingerprint list and per-fingerprint shared flags.
        const fps: []const []const u8 = input.fingerprints;
        const binds: []const IdentityBindingInput = input.bindings;
        if (binds.len > 0) {
            if (fps.len == 0) {
                // Callers that use bindings need not duplicate the list.
            } else if (binds.len != fps.len) return error.InvalidFingerprint;
        }
        const eff_len: usize = if (binds.len > 0) binds.len else fps.len;
        if (eff_len == 0) return error.NoFingerprints;
        if (eff_len > max_identity_fingerprints) return error.TooManyFingerprints;
        // Build the effective fingerprint slice and shared slice.
        var eff_fps_buf: [max_identity_fingerprints][]const u8 = undefined;
        var eff_shared_buf: [max_identity_fingerprints]bool = undefined;
        for (0..eff_len) |i| {
            const fp = if (binds.len > 0) binds[i].fingerprint else fps[i];
            if (!validFingerprint(fp)) return error.InvalidFingerprint;
            eff_fps_buf[i] = fp;
            eff_shared_buf[i] = if (binds.len > 0) binds[i].shared else input.shared;
        }
        for (0..eff_len) |i| {
            for (eff_fps_buf[i + 1 .. eff_len]) |other| {
                if (std.mem.eql(u8, eff_fps_buf[i], other)) return error.DuplicateFingerprint;
            }
        }

        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        if (loaded.recovery_error != null) return error.StoreCorrupt;

        var is_edit = false;
        var existing: ?Identity = null;
        if (input.id) |wanted| {
            for (loaded.parsed.value) |ident| {
                if (std.mem.eql(u8, ident.id, wanted)) {
                    is_edit = true;
                    existing = ident;
                    break;
                }
            }
            if (!is_edit) return error.UnknownId;
            if (input.expected_revision) |rev| {
                if (existing.?.revision != rev) return error.RevisionConflict;
            }
        }

        var id_owned: ?[]u8 = null;
        defer if (id_owned) |b| self.allocator.free(b);
        var id: []const u8 = undefined;
        if (input.id) |i| {
            id = i;
        } else {
            id_owned = randomId(self.allocator, io) catch return error.OutOfMemory;
            id = id_owned.?;
        }

        // Ownership: an unshared binding claimed by another identity is a conflict.
        for (0..eff_len) |i| {
            if (eff_shared_buf[i]) continue;
            const fp = eff_fps_buf[i];
            for (loaded.parsed.value) |ident| {
                if (is_edit and std.mem.eql(u8, ident.id, id)) continue;
                for (ident.bindings) |b| {
                    if (std.mem.eql(u8, fp, b.fingerprint) and !b.shared) return error.FingerprintOwned;
                }
                // Fallback for legacy records without bindings.
                if (ident.bindings.len == 0) {
                    if (ident.shared) continue;
                    for (ident.fingerprints) |other| {
                        if (std.mem.eql(u8, fp, other)) return error.FingerprintOwned;
                    }
                }
            }
        }

        var out_list: std.ArrayList(Identity) = .empty;
        defer {
            for (out_list.items) |*it| it.deinit(self.allocator);
            out_list.deinit(self.allocator);
        }
        var created_at_ms: i64 = now_ms;
        var revision: u64 = 1;
        if (is_edit) {
            created_at_ms = existing.?.created_at_ms;
            if (created_at_ms == 0) created_at_ms = @divTrunc(existing.?.created_at_ns, std.time.ns_per_ms);
            revision = existing.?.revision + 1;
        }
        const id_copy = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(id_copy);
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);
        const fps_copy = try dupFingerprints(self.allocator, eff_fps_buf[0..eff_len]);
        errdefer {
            for (fps_copy) |f| self.allocator.free(f);
            self.allocator.free(fps_copy);
        }
        const bindings_copy = try dupBindings(self.allocator, eff_fps_buf[0..eff_len], eff_shared_buf[0..eff_len]);
        errdefer {
            for (bindings_copy) |*b| b.deinit(self.allocator);
            self.allocator.free(bindings_copy);
        }
        // Legacy shared mirror: true if any binding is shared.
        var any_shared = false;
        for (bindings_copy) |b| {
            if (b.shared) {
                any_shared = true;
                break;
            }
        }
        var saved = Identity{
            .id = id_copy,
            .name = name_copy,
            .fingerprints = fps_copy,
            .bindings = bindings_copy,
            .shared = any_shared,
            .created_at_ms = created_at_ms,
            .created_at_ns = created_at_ms * std.time.ns_per_ms,
            .revision = revision,
        };
        errdefer saved.deinit(self.allocator);
        for (loaded.parsed.value) |ident| {
            if (is_edit and std.mem.eql(u8, ident.id, id)) continue;
            try out_list.append(self.allocator, try cloneIdentity(self.allocator, ident));
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
        if (loaded.recovery_error) |msg| {
            // Surface quarantine path + message to the caller via StoreCorrupt
            // — the bridge maps this to `recovery_error` in the list response.
            _ = msg;
            return error.StoreCorrupt;
        }
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

    /// Like list, but also returns the recovery error when the store was
    /// quarantined (for the identities.list bridge response).
    pub fn listWithRecovery(self: *IdentityStore, io: std.Io) !struct { identities: []Identity, recovery_error: ?[]const u8, quarantined: ?[]const u8 } {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        var out: std.ArrayList(Identity) = .empty;
        errdefer {
            for (out.items) |*it| it.deinit(self.allocator);
            out.deinit(self.allocator);
        }
        for (loaded.parsed.value) |ident| {
            try out.append(self.allocator, try cloneIdentity(self.allocator, ident));
        }
        const ids = try out.toOwnedSlice(self.allocator);
        const rec = if (loaded.recovery_error) |e| try self.allocator.dupe(u8, e) else null;
        const quar = if (loaded.quarantined) |q| try self.allocator.dupe(u8, q) else null;
        return .{ .identities = ids, .recovery_error = rec, .quarantined = quar };
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

    pub fn delete(self: *IdentityStore, io: std.Io, id: []const u8, expected_revision: ?u64) IdentitySaveError!bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = self.loadParsedLocked(io) catch return error.StoreCorrupt;
        defer loaded.deinit(self.allocator);
        if (loaded.recovery_error != null) return error.StoreCorrupt;
        var found: ?Identity = null;
        for (loaded.parsed.value) |ident| {
            if (std.mem.eql(u8, ident.id, id)) {
                found = ident;
                break;
            }
        }
        const target = found orelse return false;
        if (expected_revision) |rev| {
            if (target.revision != rev) return error.RevisionConflict;
        }
        var out_list: std.ArrayList(Identity) = .empty;
        defer {
            for (out_list.items) |*i| i.deinit(self.allocator);
            out_list.deinit(self.allocator);
        }
        for (loaded.parsed.value) |i| {
            if (std.mem.eql(u8, i.id, id)) continue;
            try out_list.append(self.allocator, try cloneIdentity(self.allocator, i));
        }
        self.saveLocked(io, out_list.items) catch return error.SerializeFailed;
        return true;
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

fn dupBindings(allocator: std.mem.Allocator, fps: []const []const u8, shared: []const bool) IdentitySaveError![]IdentityBinding {
    const buf = try allocator.alloc(IdentityBinding, fps.len);
    errdefer allocator.free(buf);
    for (fps, 0..) |fp, i| {
        buf[i] = .{ .fingerprint = try allocator.dupe(u8, fp), .shared = shared[i] };
    }
    return buf;
}

fn cloneIdentity(allocator: std.mem.Allocator, identity: Identity) IdentitySaveError!Identity {
    const fps = try dupFingerprints(allocator, identity.fingerprints);
    errdefer {
        for (fps) |f| allocator.free(f);
        allocator.free(fps);
    }
    var b: []IdentityBinding = &.{};
    if (identity.bindings.len > 0) {
        b = try allocator.alloc(IdentityBinding, identity.bindings.len);
        errdefer allocator.free(b);
        for (identity.bindings, 0..) |bd, i| {
            b[i] = .{ .fingerprint = try allocator.dupe(u8, bd.fingerprint), .shared = bd.shared };
        }
    } else if (fps.len > 0) {
        b = try allocator.alloc(IdentityBinding, fps.len);
        errdefer allocator.free(b);
        for (fps, 0..) |fp, i| {
            b[i] = .{ .fingerprint = try allocator.dupe(u8, fp), .shared = identity.shared };
        }
    }
    return .{
        .id = try allocator.dupe(u8, identity.id),
        .name = try allocator.dupe(u8, identity.name),
        .fingerprints = fps,
        .bindings = b,
        .shared = identity.shared,
        .created_at_ms = identity.created_at_ms,
        .created_at_ns = identity.created_at_ns,
        .revision = identity.revision,
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

/// Sudo vocabulary (spec 09 §13): "full" only from an authoritative sudo
/// policy query; "none" only when sudoers explicitly excludes the account;
/// everything unprovable is "unknown" — never guessed.
pub const sudo_yes = "full";
pub const sudo_no = "none";
pub const sudo_limited = "limited";
pub const sudo_unknown = "unknown";

pub const coverage_complete = "complete";
pub const coverage_partial = "partial";

pub const PendingKind = enum(u8) { none, identity_whoami, identity_id_u, connection_tuple, sudo_probe, sudo_probe_u, enumerate, seed_home, read_sftp, read_sftp_data, read_privileged, sshd_config };
pub const PendingExec = struct {
    kind: PendingKind = .none,
    account_index: usize = 0,
    sudo_user: []const u8 = "",
    sftp_path: []const u8 = "",
    outcome: ?*anyopaque = null,
};
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
/// `source_path` is the exact static file read (NEXT-SPEC § scan facts).
/// `file_sha256` identifies the source file snapshot for mutation guards.
/// `options` preserves authorized_key options.
pub const Grant = struct {
    fingerprint: []const u8,
    user: []const u8,
    sudo: []const u8,
    comment: []const u8,
    line_hash: []const u8,
    source_path: []const u8 = "",
    file_sha256: []const u8 = "",
    options: []const u8 = "",

    pub fn deinit(self: *Grant, allocator: std.mem.Allocator) void {
        allocator.free(self.fingerprint);
        allocator.free(self.user);
        allocator.free(self.sudo);
        allocator.free(self.comment);
        allocator.free(self.line_hash);
        allocator.free(self.source_path);
        allocator.free(self.file_sha256);
        allocator.free(self.options);
    }
};

/// One login account on one server: whether it was read and why not.
pub const AccountScan = struct {
    user: []const u8,
    home: []const u8,
    uid: ?u32 = null,
    /// True for nologin/false-shell accounts: they cannot log in, so no
    /// authorized_keys exists to read (recorded, not counted as partial).
    skipped: bool = false,
    read: bool = false,
    @"error": ?[]const u8 = null,
    sudo: ?[]const u8 = null,
    key_count: usize = 0,
    /// Effective `sshd -T -C` policy has been evaluated for this account.
    policy_evaluated: bool = false,
    pubkey_authentication: ?bool = null,
    static_sources: std.ArrayList([]const u8) = .empty,
    next_source: usize = 0,

    pub fn deinit(self: *AccountScan, allocator: std.mem.Allocator) void {
        allocator.free(self.user);
        allocator.free(self.home);
        if (self.@"error") |s| allocator.free(s);
        if (self.sudo) |s| allocator.free(s);
        for (self.static_sources.items) |source| allocator.free(source);
        self.static_sources.deinit(allocator);
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
    connected_uid: ?u32 = null,
    client_addr: ?[]const u8 = null,
    local_addr: ?[]const u8 = null,
    local_port: ?[]const u8 = null,
    connection_host: ?[]const u8 = null,
    connection_context_valid: bool = false,
    privileged: bool = false,
    /// Sudo status of the connected account on this server.
    sudo: ?[]const u8 = null,
    accounts: std.ArrayList(AccountScan) = .empty,
    /// Next account index to read (read_accounts phase).
    next_account: usize = 0,
    /// Spec 09 worker-ownership: one in-flight worker exec per server.
    /// While non-null the bridge thread must not advance the phase;
    /// the next poll consumes the outcome and resumes.
    pending: ?PendingExec = null,
    /// Chunk accumulator for the one static source currently read through the
    /// owning session worker. The coordinator clears it between sources.
    read_buffer: std.ArrayList(u8) = .empty,
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
        if (self.client_addr) |s| allocator.free(s);
        if (self.local_addr) |s| allocator.free(s);
        if (self.local_port) |s| allocator.free(s);
        if (self.connection_host) |s| allocator.free(s);
        if (self.sudo) |s| allocator.free(s);
        for (self.accounts.items) |*a| a.deinit(allocator);
        self.accounts.deinit(allocator);
        for (self.sources.items) |s| allocator.free(s);
        self.sources.deinit(allocator);
        for (self.grants.items) |*g| g.deinit(allocator);
        self.grants.deinit(allocator);
        self.read_buffer.deinit(allocator);
        if (self.coverage) |c| allocator.free(c);
        if (self.coverage_reason) |r| allocator.free(r);
        if (self.pending) |*pend| {
            if (pend.sudo_user.len > 0) allocator.free(pend.sudo_user);
            if (pend.sftp_path.len > 0) allocator.free(pend.sftp_path);
        }
    }
};

pub const Scan = struct {
    id: []const u8,
    full: bool = false,
    scope: []const u8 = "connected_accounts",
    created_at_ns: i64 = 0,
    /// Refreshed by poll/export. Unfinished scans expire after ten idle minutes.
    last_access_ns: i64 = 0,
    finished_at_ns: i64 = 0,
    canceled: bool = false,
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
    running,
    done,
    conflict,
    canceled,
    @"error",

    pub fn jsonName(self: JobItemState) []const u8 {
        return switch (self) {
            .queued => "queued",
            .running => "running",
            .done => "done",
            .conflict => "conflict",
            .canceled => "canceled",
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
    /// Rotate: fingerprint of `public_key_line`, bound before remote work.
    new_fingerprint: []const u8 = "",
    /// Exact static source file frozen by the scan (NEXT-SPEC § mutation jobs).
    source_path: []const u8 = "",
    /// Whole-file sha256 snapshot for the scanned source.
    file_sha256: []const u8 = "",
    /// NEXT-SPEC operation_id idempotency key for the parent job.
    operation_id: []const u8 = "",
    read_only: bool = false,
    state: JobItemState = .queued,
    @"error": ?[]const u8 = null,

    pub fn deinit(self: *JobItem, allocator: std.mem.Allocator) void {
        allocator.free(self.server_id);
        allocator.free(self.user);
        allocator.free(self.fingerprint);
        allocator.free(self.expected_line_hash);
        allocator.free(self.public_key_line);
        allocator.free(self.new_fingerprint);
        allocator.free(self.source_path);
        allocator.free(self.file_sha256);
        allocator.free(self.operation_id);
        if (self.@"error") |e| allocator.free(e);
    }
};

pub const Job = struct {
    id: []const u8,
    kind: JobKind,
    identity_id: []const u8,
    /// NEXT-SPEC idempotency key for the mutation request.
    operation_id: []const u8 = "",
    created_at_ns: i64 = 0,
    /// Refreshed by job polling. Queued work expires after ten idle minutes.
    last_access_ns: i64 = 0,
    finished_at_ns: i64 = 0,
    items: std.ArrayList(JobItem) = .empty,

    pub fn deinit(self: *Job, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.identity_id);
        allocator.free(self.operation_id);
        for (self.items.items) |*i| i.deinit(allocator);
        self.items.deinit(allocator);
    }

    /// True once every item reached a terminal state.
    pub fn finished(self: *const Job) bool {
        for (self.items.items) |*i| {
            if (i.state == .queued or i.state == .running) return false;
        }
        return true;
    }
};

// --- registry --------------------------------------------------------------

pub const registry_idle_expiry_ns: i64 = 10 * 60 * std.time.ns_per_s;
pub const registry_terminal_retention_ns: i64 = 30 * 60 * std.time.ns_per_s;

pub fn registryDeadlineReached(now_ns: i64, base_ns: i64, ttl_ns: i64) bool {
    return base_ns > 0 and now_ns >= base_ns and now_ns - base_ns >= ttl_ns;
}

/// Handler-owned registries for scans and jobs (main thread only, like the
/// deploy Runs). The identity store is file-backed.
pub const Registry = struct {
    allocator: std.mem.Allocator,
    identities: IdentityStore = .{},
    mutex: std.atomic.Mutex = .unlocked,
    worker_stop: std.atomic.Value(bool) = .init(false),
    worker: ?std.Thread = null,
    worker_context: ?*anyopaque = null,
    scans: std.ArrayList(*Scan) = .empty,
    jobs: std.ArrayList(*Job) = .empty,
    next_scan_id: u32 = 1,
    next_job_id: u32 = 1,
    const max_scans: usize = 8;
    const max_jobs: usize = 32;
    const max_scan_records: usize = max_scans * 2;
    const max_job_records: usize = max_jobs * 2;

    pub fn init(allocator: std.mem.Allocator, identity_path: []const u8) Registry {
        return .{
            .allocator = allocator,
            .identities = .{ .allocator = allocator, .path = identity_path },
        };
    }

    pub fn deinit(self: *Registry) void {
        self.worker_stop.store(true, .release);
        if (self.worker) |thread| thread.join();
        self.worker = null;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
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

    pub fn registerScan(self: *Registry, scan: *Scan) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var active_scans: usize = 0;
        for (self.scans.items) |candidate| {
            var terminal = candidate.canceled;
            if (!terminal) {
                terminal = true;
                for (candidate.servers) |server| if (!server.done and server.phase != .@"error") {
                    terminal = false;
                    break;
                };
            }
            if (!terminal) active_scans += 1;
        }
        if (active_scans >= max_scans) return error.ScanCapacity;
        if (self.scans.items.len >= max_scan_records) {
            var evict: ?usize = null;
            for (self.scans.items, 0..) |candidate, i| {
                var terminal = candidate.canceled;
                if (!terminal) {
                    terminal = true;
                    for (candidate.servers) |server| {
                        if (!server.done and server.phase != .@"error") {
                            terminal = false;
                            break;
                        }
                    }
                }
                if (terminal) {
                    evict = i;
                    break;
                }
            }
            const index = evict orelse return error.ScanCapacity;
            const oldest = self.scans.orderedRemove(index);
            oldest.deinit(self.allocator);
            self.allocator.destroy(oldest);
        }
        try self.scans.append(self.allocator, scan);
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

    pub fn registerJob(self: *Registry, job: *Job) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var active_jobs: usize = 0;
        for (self.jobs.items) |candidate| {
            if (!candidate.finished()) active_jobs += 1;
        }
        if (active_jobs >= max_jobs) return error.JobCapacity;
        if (self.jobs.items.len >= max_job_records) {
            var evict: ?usize = null;
            for (self.jobs.items, 0..) |candidate, i| {
                if (candidate.finished()) {
                    evict = i;
                    break;
                }
            }
            const index = evict orelse return error.JobCapacity;
            const oldest = self.jobs.orderedRemove(index);
            oldest.deinit(self.allocator);
            self.allocator.destroy(oldest);
        }
        try self.jobs.append(self.allocator, job);
    }

    pub fn jobById(self: *Registry, id: []const u8) ?*Job {
        for (self.jobs.items) |j| {
            if (std.mem.eql(u8, j.id, id)) return j;
        }
        return null;
    }
};

// --- pure parsers (unit-tested) --------------------------------------------

/// Parses `LC_ALL=C sudo -n -ll` output into the Spec 09 policy vocabulary.
/// A broad `(ALL) ALL` or `ALL : ALL` rule is full access; another successful
/// rule listing is limited access. Explicit denial is none. Failures are
/// unknown because Oars cannot distinguish policy from missing authority.
pub fn parseSudoList(exit: i32, output: []const u8) []const u8 {
    // Some sudo builds report an explicit denial with exit 0 (Alpine's
    // sudo prints "User X is not allowed to run sudo" and still exits 0
    // for `-l -U` queries) — the message wins over the exit code.
    if (std.mem.indexOf(u8, output, "is not allowed to run sudo") != null) return sudo_no;
    if (std.mem.indexOf(u8, output, "not in the sudoers file") != null) return sudo_no;
    if (exit == 0) {
        if (std.mem.indexOf(u8, output, "(ALL) ALL") != null or
            std.mem.indexOf(u8, output, "(ALL : ALL) ALL") != null or
            std.mem.indexOf(u8, output, "Commands:\n    ALL") != null) return sudo_yes;
        return sudo_limited;
    }
    return sudo_unknown;
}

/// Parses `getent passwd` output into login accounts: NSS-enumerated
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
        _ = fields.next() orelse continue; // uid
        _ = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const shell = fields.next() orelse continue;
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

pub const EffectiveSshdPolicy = struct {
    pubkey_authentication: ?bool = null,
    static_sources: [][]const u8 = &.{},
    warnings: [][]const u8 = &.{},

    pub fn deinit(self: *EffectiveSshdPolicy, allocator: std.mem.Allocator) void {
        for (self.static_sources) |source| allocator.free(source);
        allocator.free(self.static_sources);
        for (self.warnings) |warning| allocator.free(warning);
        allocator.free(self.warnings);
    }
};

const ExpandSourceError = error{ UnsupportedToken, InvalidHome, PathTooLong } || std.mem.Allocator.Error;

/// Expands the tokens documented for `AuthorizedKeysFile` and turns relative
/// paths into exact paths below the account home. Unknown tokens stay a
/// coverage warning; they are never guessed.
pub fn expandAuthorizedKeysPath(
    allocator: std.mem.Allocator,
    raw: []const u8,
    user: []const u8,
    uid: ?u32,
    home: []const u8,
) ExpandSourceError![]u8 {
    if (home.len == 0 or home[0] != '/') return error.InvalidHome;
    var expanded: std.ArrayList(u8) = .empty;
    defer expanded.deinit(allocator);
    var i: usize = 0;
    while (i < raw.len) {
        if (raw[i] != '%') {
            try expanded.append(allocator, raw[i]);
            i += 1;
            continue;
        }
        if (i + 1 >= raw.len) return error.UnsupportedToken;
        switch (raw[i + 1]) {
            '%' => try expanded.append(allocator, '%'),
            'h' => try expanded.appendSlice(allocator, home),
            'u' => try expanded.appendSlice(allocator, user),
            'U' => {
                const account_uid = uid orelse return error.UnsupportedToken;
                var uid_buf: [16]u8 = undefined;
                const text = std.fmt.bufPrint(&uid_buf, "{d}", .{account_uid}) catch return error.PathTooLong;
                try expanded.appendSlice(allocator, text);
            },
            else => return error.UnsupportedToken,
        }
        i += 2;
        if (expanded.items.len > 4096) return error.PathTooLong;
    }
    if (expanded.items.len == 0) return error.InvalidHome;
    if (expanded.items[0] == '/') return expanded.toOwnedSlice(allocator);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ home, expanded.items });
}

fn effectiveWarning(
    allocator: std.mem.Allocator,
    warnings: *std.ArrayList([]const u8),
    key: []const u8,
    value: []const u8,
) !void {
    try warnings.append(allocator, try std.fmt.allocPrint(allocator, "{s} {s}", .{ key, value }));
}

/// Parses the normalized, lower-case output of `sshd -T -C`. The caller
/// supplies the account facts used by documented path-token expansion.
pub fn parseEffectiveSshdPolicy(
    allocator: std.mem.Allocator,
    output: []const u8,
    user: []const u8,
    uid: ?u32,
    home: []const u8,
) !EffectiveSshdPolicy {
    var sources: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (sources.items) |source| allocator.free(source);
        sources.deinit(allocator);
    }
    var warnings: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (warnings.items) |warning| allocator.free(warning);
        warnings.deinit(allocator);
    }
    var pubkey: ?bool = null;
    var saw_authorized_keys_file = false;
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        const split = std.mem.indexOfAny(u8, line, " \t") orelse continue;
        const key = line[0..split];
        const value = std.mem.trim(u8, line[split..], " \t");
        if (std.mem.eql(u8, key, "pubkeyauthentication")) {
            if (std.mem.eql(u8, value, "yes")) pubkey = true else if (std.mem.eql(u8, value, "no")) pubkey = false;
            continue;
        }
        if (std.mem.eql(u8, key, "authorizedkeysfile")) {
            saw_authorized_keys_file = true;
            if (std.mem.eql(u8, value, "none")) continue;
            var paths = std.mem.tokenizeAny(u8, value, " \t");
            while (paths.next()) |path| {
                const expanded = expandAuthorizedKeysPath(allocator, path, user, uid, home) catch |err| {
                    const reason = switch (err) {
                        error.UnsupportedToken => "unsupported AuthorizedKeysFile token",
                        error.InvalidHome => "invalid account home for AuthorizedKeysFile",
                        error.PathTooLong => "AuthorizedKeysFile path is too long",
                        error.OutOfMemory => return error.OutOfMemory,
                    };
                    try effectiveWarning(allocator, &warnings, reason, path);
                    continue;
                };
                var duplicate = false;
                for (sources.items) |existing| if (std.mem.eql(u8, existing, expanded)) {
                    duplicate = true;
                    break;
                };
                if (duplicate) allocator.free(expanded) else try sources.append(allocator, expanded);
            }
            continue;
        }
        const dynamic = std.mem.eql(u8, key, "authorizedkeyscommand") or
            std.mem.eql(u8, key, "authorizedkeysuserca") or
            std.mem.eql(u8, key, "trustedusercakeys") or
            std.mem.eql(u8, key, "authorizedprincipalsfile") or
            std.mem.eql(u8, key, "authorizedprincipalscommand");
        if (dynamic and !std.mem.eql(u8, value, "none")) try effectiveWarning(allocator, &warnings, key, value);
    }
    if (pubkey == null) try effectiveWarning(allocator, &warnings, "pubkeyauthentication", "not reported");
    if (!saw_authorized_keys_file) try effectiveWarning(allocator, &warnings, "authorizedkeysfile", "not reported");
    return .{
        .pubkey_authentication = pubkey,
        .static_sources = try sources.toOwnedSlice(allocator),
        .warnings = try warnings.toOwnedSlice(allocator),
    };
}

pub fn hasCertificateAuthorityOption(options: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, options, ',');
    while (tokens.next()) |raw| {
        const token = std.mem.trim(u8, raw, " \t");
        if (std.mem.eql(u8, token, "cert-authority")) return true;
    }
    return false;
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
    source_path: []const u8 = "",
    file_sha256: []const u8 = "",

    pub fn deinit(self: *PersonGrant, allocator: std.mem.Allocator) void {
        allocator.free(self.fingerprint);
        allocator.free(self.server_id);
        allocator.free(self.server_name);
        allocator.free(self.user);
        allocator.free(self.sudo);
        allocator.free(self.comment);
        allocator.free(self.line_hash);
        allocator.free(self.source_path);
        allocator.free(self.file_sha256);
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
    scan_id: []const u8 = "",
    scope: []const u8 = "connected_accounts",
    created_at_ms: i64 = 0,
    finished_at_ms: ?i64 = null,
    servers: []ServerView = &.{},
    people: []Person = &.{},
    unassigned: []Unassigned = &.{},
    server_count: usize = 0,
    grant_count: usize = 0,
    coverage: []const u8 = coverage_partial,
    sync_errors: []SyncError = &.{},
    source_warnings: []SyncError = &.{},

    pub fn deinit(self: *Map, allocator: std.mem.Allocator) void {
        allocator.free(self.scan_id);
        allocator.free(self.scope);
        for (self.servers) |*server| server.deinit(allocator);
        allocator.free(self.servers);
        for (self.people) |*p| p.deinit(allocator);
        allocator.free(self.people);
        for (self.unassigned) |*u| u.deinit(allocator);
        allocator.free(self.unassigned);
        allocator.free(self.coverage);
        for (self.sync_errors) |*e| e.deinit(allocator);
        allocator.free(self.sync_errors);
        for (self.source_warnings) |*e| e.deinit(allocator);
        allocator.free(self.source_warnings);
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
        .scan_id = try allocator.dupe(u8, if (scans.len > 0) scans[0].id else ""),
        .scope = try allocator.dupe(u8, if (scans.len > 0) scans[0].scope else "connected_accounts"),
        .created_at_ms = if (scans.len > 0) @divTrunc(scans[0].created_at_ns, std.time.ns_per_ms) else 0,
        .finished_at_ms = if (scans.len > 0 and scans[0].finished_at_ns > 0) @divTrunc(scans[0].finished_at_ns, std.time.ns_per_ms) else null,
        .servers = try allocator.alloc(ServerView, 0),
        .people = try allocator.alloc(Person, 0),
        .unassigned = try allocator.alloc(Unassigned, 0),
        .coverage = try allocator.dupe(u8, coverage_partial),
        .sync_errors = try allocator.alloc(SyncError, 0),
        .source_warnings = try allocator.alloc(SyncError, 0),
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
    var warnings: std.ArrayList(SyncError) = .empty;
    errdefer {
        for (warnings.items) |*e| e.deinit(allocator);
        warnings.deinit(allocator);
    }
    var complete = true;
    var server_views: std.ArrayList(ServerView) = .empty;
    errdefer {
        for (server_views.items) |*view| view.deinit(allocator);
        server_views.deinit(allocator);
    }
    for (scans) |scan| {
        for (scan.servers) |*server| {
            try server_views.append(allocator, try serverView(allocator, server));
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
            if (server.coverage_reason) |reason| {
                try warnings.append(allocator, .{
                    .server_id = try allocator.dupe(u8, server.server_id),
                    .reason = try allocator.dupe(u8, reason),
                });
            }
            for (server.grants.items) |*g| {
                try all_grants.append(allocator, .{
                    .fingerprint = try allocator.dupe(u8, g.fingerprint),
                    .server_id = try allocator.dupe(u8, server.server_id),
                    .server_name = try allocator.dupe(u8, server.name),
                    .user = try allocator.dupe(u8, g.user),
                    .sudo = try allocator.dupe(u8, g.sudo),
                    .comment = try allocator.dupe(u8, g.comment),
                    .line_hash = try allocator.dupe(u8, g.line_hash),
                    .source_path = try allocator.dupe(u8, g.source_path),
                    .file_sha256 = try allocator.dupe(u8, g.file_sha256),
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
    allocator.free(map.servers);
    map.servers = try server_views.toOwnedSlice(allocator);
    allocator.free(map.coverage);
    map.coverage = try allocator.dupe(u8, if (complete) coverage_complete else coverage_partial);
    allocator.free(map.sync_errors);
    map.sync_errors = try syncs.toOwnedSlice(allocator);
    allocator.free(map.source_warnings);
    map.source_warnings = try warnings.toOwnedSlice(allocator);
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
        .source_path = try allocator.dupe(u8, g.source_path),
        .file_sha256 = try allocator.dupe(u8, g.file_sha256),
    };
}

// --- export formatting -----------------------------------------------------

/// RFC 4180 CSV: fields containing comma, quote, CR or LF are quoted and
/// embedded quotes doubled; rows end with CRLF.
fn csvField(writer: anytype, field: []const u8) !void {
    // Formula-safe CSV: neutralize spreadsheet formula injection (Excel/Sheets).
    // NEXT-SPEC: treat leading [=+\-@] as formula risks; prefix with a single quote
    // while preserving the original data inside the quoted CSV field.
    const formula_risk = field.len > 0 and switch (field[0]) {
        '=', '+', '-', '@' => true,
        else => false,
    };
    const needs_quote = formula_risk or std.mem.indexOfAny(u8, field, ",\"\r\n") != null;
    if (!needs_quote) {
        try writer.writeAll(field);
        return;
    }
    try writer.writeByte('"');
    if (formula_risk) try writer.writeByte('\'');
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
    try out.writer.writeAll("row_type,scan_id,scope,coverage,identity_id,name,fingerprint,server_id,user,sudo,comment,source_path,line_hash,file_sha256,reason\r\n");
    for (map.people) |*person| {
        for (person.grants) |*g| {
            try out.writer.writeAll("grant,");
            try csvField(&out.writer, map.scan_id);
            try out.writer.writeByte(',');
            try csvField(&out.writer, map.scope);
            try out.writer.writeByte(',');
            try csvField(&out.writer, map.coverage);
            try out.writer.writeByte(',');
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
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.source_path);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.line_hash);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.file_sha256);
            try out.writer.writeAll(",\r\n");
        }
    }
    for (map.unassigned) |*u| {
        for (u.grants) |*g| {
            try out.writer.writeAll("unassigned,");
            try csvField(&out.writer, map.scan_id);
            try out.writer.writeByte(',');
            try csvField(&out.writer, map.scope);
            try out.writer.writeByte(',');
            try csvField(&out.writer, map.coverage);
            try out.writer.writeAll(",,,");
            try csvField(&out.writer, g.fingerprint);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.server_id);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.user);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.sudo);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.comment);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.source_path);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.line_hash);
            try out.writer.writeByte(',');
            try csvField(&out.writer, g.file_sha256);
            try out.writer.writeAll(",\r\n");
        }
    }
    for (map.sync_errors) |*entry| {
        try out.writer.writeAll("sync_error,");
        try csvField(&out.writer, map.scan_id);
        try out.writer.writeByte(',');
        try csvField(&out.writer, map.scope);
        try out.writer.writeByte(',');
        try csvField(&out.writer, map.coverage);
        try out.writer.writeAll(",,,,");
        try csvField(&out.writer, entry.server_id);
        try out.writer.writeAll(",,,,,,,");
        try csvField(&out.writer, entry.reason);
        try out.writer.writeAll("\r\n");
    }
    for (map.source_warnings) |*entry| {
        try out.writer.writeAll("source_warning,");
        try csvField(&out.writer, map.scan_id);
        try out.writer.writeByte(',');
        try csvField(&out.writer, map.scope);
        try out.writer.writeByte(',');
        try csvField(&out.writer, map.coverage);
        try out.writer.writeAll(",,,,");
        try csvField(&out.writer, entry.server_id);
        try out.writer.writeAll(",,,,,,,");
        try csvField(&out.writer, entry.reason);
        try out.writer.writeAll("\r\n");
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
    source_path: []const u8 = "",
    file_sha256: []const u8 = "",

    pub fn deinit(self: *GrantView, allocator: std.mem.Allocator) void {
        allocator.free(self.fingerprint);
        allocator.free(self.user);
        allocator.free(self.sudo);
        allocator.free(self.comment);
        allocator.free(self.line_hash);
        allocator.free(self.source_path);
        allocator.free(self.file_sha256);
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
            .source_path = try allocator.dupe(u8, g.source_path),
            .file_sha256 = try allocator.dupe(u8, g.file_sha256),
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
    scan_id: []const u8 = "",
    state: []const u8 = "scanning",
    scope: []const u8 = "connected_accounts",
    created_at_ms: i64 = 0,
    finished_at_ms: ?i64 = null,
    servers: []ServerView = &.{},
    people: []Person = &.{},
    unassigned: []Unassigned = &.{},
    servers_count: usize = 0,
    grants_count: usize = 0,
    coverage: []const u8 = coverage_partial,
    sync_errors: []SyncError = &.{},
    source_warnings: []SyncError = &.{},

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
        for (self.source_warnings) |*e| e.deinit(allocator);
        allocator.free(self.source_warnings);
    }
};

pub fn exportJson(allocator: std.mem.Allocator, map: *const Map) ![]u8 {
    var payload = PollPayload{
        .scan_id = map.scan_id,
        .state = "done",
        .scope = map.scope,
        .created_at_ms = map.created_at_ms,
        .finished_at_ms = map.finished_at_ms,
        .servers = map.servers,
        .people = map.people,
        .unassigned = map.unassigned,
        .servers_count = map.server_count,
        .grants_count = map.grant_count,
        .coverage = map.coverage,
        .sync_errors = map.sync_errors,
        // `payload` borrows map-owned slices for serialization only.
        .source_warnings = map.source_warnings,
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

    try std.testing.expect((try store.delete(io, bob.id, null)) == true);
    try std.testing.expect((try store.delete(io, bob.id, null)) == false);
}

test "parseSudoList distinguishes yes/no/unknown" {
    try std.testing.expectEqualStrings(sudo_yes, parseSudoList(0, "User root may run the following commands on this host:\n (ALL) ALL\n"));
    try std.testing.expectEqualStrings(sudo_no, parseSudoList(1, "user alice is not in the sudoers file. This incident will be reported."));
    // Alpine's sudo prints the denial with exit 0 for `-l -U` queries.
    try std.testing.expectEqualStrings(sudo_no, parseSudoList(0, "User alice is not allowed to run sudo on b7ac8cc46a82."));
    try std.testing.expectEqualStrings(sudo_limited, parseSudoList(0, "User deploy may run:\n    /usr/bin/systemctl restart app\n"));
    try std.testing.expectEqualStrings(sudo_unknown, parseSudoList(1, "sudo: a password is required"));
    try std.testing.expectEqualStrings(sudo_unknown, parseSudoList(1, "sudo: no tty present and no askpass program specified"));
    try std.testing.expectEqualStrings(sudo_unknown, parseSudoList(127, "sh: sudo: not found"));
    try std.testing.expectEqualStrings(sudo_unknown, parseSudoList(1, ""));
}

test "registry deadlines expire idle and retained records at exact boundaries" {
    const start: i64 = 1_000;
    try std.testing.expect(!registryDeadlineReached(start + registry_idle_expiry_ns - 1, start, registry_idle_expiry_ns));
    try std.testing.expect(registryDeadlineReached(start + registry_idle_expiry_ns, start, registry_idle_expiry_ns));
    try std.testing.expect(registryDeadlineReached(start + registry_terminal_retention_ns, start, registry_terminal_retention_ns));
    try std.testing.expect(!registryDeadlineReached(start - 1, start, registry_idle_expiry_ns));
    try std.testing.expect(!registryDeadlineReached(start + registry_idle_expiry_ns, 0, registry_idle_expiry_ns));
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
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("root", entries[0].name);
    try std.testing.expectEqual(@as(u32, 0), entries[0].uid);
    try std.testing.expectEqualStrings("/root", entries[0].home);
    try std.testing.expectEqualStrings("alice", entries[1].name);
    try std.testing.expectEqual(@as(u32, 1000), entries[1].uid);
    try std.testing.expectEqualStrings("/home/alice", entries[1].home);

    const skipped = try skippedAccounts(allocator, sample);
    defer {
        for (skipped) |n| allocator.free(n);
        allocator.free(skipped);
    }
    try std.testing.expectEqual(@as(usize, 3), skipped.len);
    try std.testing.expectEqualStrings("daemon", skipped[0]);
    try std.testing.expectEqualStrings("carol", skipped[1]);
    try std.testing.expectEqualStrings("dave", skipped[2]);

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
        .scan_id = try allocator.dupe(u8, "scan-test"),
        .scope = try allocator.dupe(u8, "connected_accounts"),
        .servers = try allocator.alloc(ServerView, 0),
        .coverage = try allocator.dupe(u8, coverage_complete),
        .people = try allocator.alloc(Person, 1),
        .unassigned = try allocator.alloc(Unassigned, 0),
        .sync_errors = try allocator.alloc(SyncError, 0),
        .source_warnings = try allocator.alloc(SyncError, 0),
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
        "row_type,scan_id,scope,coverage,identity_id,name,fingerprint,server_id,user,sudo,comment,source_path,line_hash,file_sha256,reason\r\n" ++
        "grant,scan-test,connected_accounts,complete,id-a,Alice,SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,srv-1,root,full,\"has, a comma \"\"and quotes\"\"\",,h,,\r\n";
    try std.testing.expectEqualStrings(expected, csv);
}

test "exportJson serializes the people map" {
    const allocator = std.testing.allocator;
    var map: Map = .{
        .scan_id = try allocator.dupe(u8, "scan-test"),
        .scope = try allocator.dupe(u8, "connected_accounts"),
        .servers = try allocator.alloc(ServerView, 0),
        .coverage = try allocator.dupe(u8, coverage_complete),
        .people = try allocator.alloc(Person, 0),
        .unassigned = try allocator.alloc(Unassigned, 0),
        .sync_errors = try allocator.alloc(SyncError, 0),
        .source_warnings = try allocator.alloc(SyncError, 0),
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

test "effective sshd policy expands every static source and reports dynamic sources" {
    const allocator = std.testing.allocator;
    const output =
        "pubkeyauthentication yes\n" ++
        "authorizedkeysfile .ssh/authorized_keys /etc/ssh/keys/%u/%U %%keys\n" ++
        "authorizedkeyscommand /usr/local/bin/lookup %u\n" ++
        "authorizedkeyscommanduser nobody\n" ++
        "trustedusercakeys /etc/ssh/trusted_ca.pub\n" ++
        "authorizedprincipalsfile none\n";
    var policy = try parseEffectiveSshdPolicy(allocator, output, "alice", 1001, "/home/alice");
    defer policy.deinit(allocator);
    try std.testing.expectEqual(true, policy.pubkey_authentication.?);
    try std.testing.expectEqual(@as(usize, 3), policy.static_sources.len);
    try std.testing.expectEqualStrings("/home/alice/.ssh/authorized_keys", policy.static_sources[0]);
    try std.testing.expectEqualStrings("/etc/ssh/keys/alice/1001", policy.static_sources[1]);
    try std.testing.expectEqualStrings("/home/alice/%keys", policy.static_sources[2]);
    try std.testing.expectEqual(@as(usize, 2), policy.warnings.len);
    try std.testing.expect(std.mem.startsWith(u8, policy.warnings[0], "authorizedkeyscommand "));
    try std.testing.expect(std.mem.startsWith(u8, policy.warnings[1], "trustedusercakeys "));
    try std.testing.expect(hasCertificateAuthorityOption("restrict,cert-authority,command=\"echo no\""));
    try std.testing.expect(!hasCertificateAuthorityOption("restrict,no-port-forwarding"));
}

test "effective sshd policy keeps unsupported path tokens explicit" {
    const allocator = std.testing.allocator;
    var policy = try parseEffectiveSshdPolicy(
        allocator,
        "pubkeyauthentication yes\nauthorizedkeysfile /keys/%f .ssh/authorized_keys\n",
        "root",
        0,
        "/root",
    );
    defer policy.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), policy.static_sources.len);
    try std.testing.expectEqualStrings("/root/.ssh/authorized_keys", policy.static_sources[0]);
    try std.testing.expectEqual(@as(usize, 1), policy.warnings.len);
    try std.testing.expect(std.mem.indexOf(u8, policy.warnings[0], "unsupported") != null);
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
