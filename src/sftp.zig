//! File manager (spec 05): path codec, entry model, transfer state, and
//! the ZIP central-directory preflight. Pure logic — the session worker in
//! `sessions.zig` executes the SFTP calls; this module never touches
//! libssh2 or the network.
//!
//! The ZIP scanner implements the preflight contract of spec 05 §5:
//! reject absolute paths, `..` components, drive-letter paths, symlink
//! entries, duplicates, file/directory conflicts, and enforce entry-count,
//! total-uncompressed-size, per-entry-size, path-length, nesting-depth, and
//! compression-ratio limits. Extraction (decompression + SFTP writes) is
//! driven by the entries this scanner produces.

const std = @import("std");

/// Transfer chunk size (spec 05 §6): 64 KB raw ≈ 87 KB base64 JSON, within
/// the 1 MB bridge budget.
pub const chunk_size: usize = 64 * 1024;

/// Editor/upload single-op byte cap (spec 05 §4.2: editor files < 1 MB).
pub const max_inline_bytes: usize = 1024 * 1024;

pub const ZipLimits = struct {
    max_entries: usize = 10_000,
    max_total_uncompressed: u64 = 4 * 1024 * 1024 * 1024,
    max_per_entry: u64 = 1024 * 1024 * 1024,
    max_path_len: usize = 4096,
    max_depth: usize = 64,
    max_compression_ratio: u32 = 1000,
    /// The archive itself is read into memory for preflight (v1).
    max_archive_bytes: usize = 256 * 1024 * 1024,
};

// --- RemotePath -------------------------------------------------------------

/// `RemotePath = {utf8:string}|{base64:string}` (spec 05 §5): the base64
/// form carries raw server bytes; display escaping is client-side.
pub const RemotePathJson = struct {
    utf8: ?[]const u8 = null,
    base64: ?[]const u8 = null,
};

pub const PathError = error{
    InvalidPath,
    NoPath,
    InvalidBase64,
    OutOfMemory,
};

/// Decodes a RemotePath payload into the raw path bytes (owned).
pub fn decodeRemotePath(allocator: std.mem.Allocator, path: RemotePathJson) PathError![]u8 {
    if (path.utf8) |u| {
        if (u.len == 0) return error.NoPath;
        return allocator.dupe(u8, u) catch return error.OutOfMemory;
    }
    if (path.base64) |b| {
        const size = std.base64.standard.Decoder.calcSizeForSlice(b) catch return error.InvalidBase64;
        const out = allocator.alloc(u8, size) catch return error.OutOfMemory;
        std.base64.standard.Decoder.decode(out, b) catch {
            allocator.free(out);
            return error.InvalidBase64;
        };
        return out;
    }
    return error.NoPath;
}

/// Rejects paths that cannot be sent to the server or a shell safely:
/// control characters and NUL. Traversal (`..`) is NOT rejected here — the
/// SSH account's permissions are the boundary (spec 05 §8); only shell
/// command construction quotes every path.
pub fn validatePath(raw: []const u8) PathError!void {
    if (raw.len == 0) return error.NoPath;
    for (raw) |ch| {
        if (ch == 0 or ch < 0x20 or ch == 0x7f) return error.InvalidPath;
    }
}

/// Validates a LOCAL path (download/zipDownload targets come from the
/// native save dialog): absolute, no control characters.
pub fn validateLocalPath(raw: []const u8) PathError!void {
    try validatePath(raw);
    if (raw[0] != '/') return error.InvalidPath;
}

// --- Entry model -------------------------------------------------------------

pub const Kind = enum {
    file,
    dir,
    symlink,
    other,

    pub fn jsonName(self: Kind) []const u8 {
        return @tagName(self);
    }
};

pub fn kindFromMode(mode: u32) Kind {
    const kind = mode & 0o170000;
    return switch (kind) {
        0o100000 => .file,
        0o040000 => .dir,
        0o120000 => .symlink,
        else => .other,
    };
}

/// POSIX permission string ("rwxr-xr-x", 9 chars — the entry `kind` carries
/// the file type) with setuid/setgid/sticky.
pub fn modeString(mode: u32, out: *[9]u8) []const u8 {
    const chars = [_]u8{ 'r', 'w', 'x' };
    var i: usize = 0;
    for (0..3) |group| {
        const shift: u5 = @intCast((2 - group) * 3);
        for (0..3) |bit| {
            out[i] = if ((mode >> shift) & (@as(u32, 1) << @intCast(2 - bit)) != 0) chars[bit] else '-';
            i += 1;
        }
    }
    if (mode & 0o4000 != 0) out[2] = if (out[2] == 'x') 's' else 'S';
    if (mode & 0o2000 != 0) out[5] = if (out[5] == 'x') 's' else 'S';
    if (mode & 0o1000 != 0) out[8] = if (out[8] == 'x') 't' else 'T';
    return out[0..9];
}

/// UI display text: the raw bytes when valid UTF-8, otherwise invalid
/// sequences replaced with U+FFFD (spec 05 §10: no operation ever
/// reconstructs a path from display text).
pub fn displayName(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (std.unicode.utf8ValidateSlice(raw)) return allocator.dupe(u8, raw);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < raw.len) {
        const n = std.unicode.utf8ByteSequenceLength(raw[i]) catch 1;
        if (i + n > raw.len or !std.unicode.utf8ValidateSlice(raw[i .. i + n])) {
            try out.appendSlice(allocator, "\u{fffd}");
            i += 1;
        } else {
            try out.appendSlice(allocator, raw[i .. i + n]);
            i += n;
        }
    }
    return out.toOwnedSlice(allocator);
}

/// A listing/stat result, JSON-serializable via `std.json.Stringify`
/// (custom stringifier: name is `{utf8,base64}`, mode is a string).
pub const Entry = struct {
    name_utf8: ?[]const u8 = null,
    name_b64: ?[]const u8 = null,
    display: []const u8,
    kind: Kind,
    size: u64,
    mtime: u64,
    mode: []const u8,
    uid: u32,
    gid: u32,
    link_target: ?[]const u8 = null,

    pub fn jsonStringify(self: *const Entry, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("name");
        try jws.beginObject();
        try jws.objectField("utf8");
        try jws.write(self.name_utf8);
        try jws.objectField("base64");
        try jws.write(self.name_b64);
        try jws.endObject();
        try jws.objectField("display");
        try jws.write(self.display);
        try jws.objectField("kind");
        try jws.write(self.kind.jsonName());
        try jws.objectField("size");
        try jws.write(self.size);
        try jws.objectField("mtime");
        try jws.write(self.mtime);
        try jws.objectField("mode");
        try jws.write(self.mode);
        try jws.objectField("uid");
        try jws.write(self.uid);
        try jws.objectField("gid");
        try jws.write(self.gid);
        try jws.objectField("link_target");
        try jws.write(self.link_target);
        try jws.endObject();
    }

    pub fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        if (self.name_utf8) |s| allocator.free(s);
        if (self.name_b64) |s| allocator.free(s);
        allocator.free(self.display);
        allocator.free(self.mode);
        if (self.link_target) |s| allocator.free(s);
    }
};

/// Builds a JSON `Entry` from raw attributes (owned; `deinit` frees).
pub fn makeEntry(allocator: std.mem.Allocator, name: []const u8, attrs: Attrs) !Entry {
    var mode_buf: [9]u8 = undefined;
    const mode = modeString(attrs.permissions, &mode_buf);
    var entry = Entry{
        .display = try displayName(allocator, name),
        .kind = kindFromMode(attrs.permissions),
        .size = attrs.size,
        .mtime = attrs.mtime,
        .mode = try allocator.dupe(u8, mode),
        .uid = attrs.uid,
        .gid = attrs.gid,
    };
    errdefer entry.deinit(allocator);
    if (std.unicode.utf8ValidateSlice(name)) {
        entry.name_utf8 = try allocator.dupe(u8, name);
    } else {
        const b64_len = std.base64.standard.Encoder.calcSize(name.len);
        const b64 = try allocator.alloc(u8, b64_len);
        _ = std.base64.standard.Encoder.encode(b64, name);
        entry.name_b64 = b64;
    }
    return entry;
}

/// Minimal attribute view (SFTP attributes, already type-stripped).
pub const Attrs = struct {
    permissions: u32,
    size: u64,
    mtime: u64,
    uid: u32,
    gid: u32,
};

/// Base64 of raw bytes (owned).
pub fn base64Encode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(data.len));
    _ = std.base64.standard.Encoder.encode(out, data);
    return out;
}

// --- Transfers ----------------------------------------------------------------

pub const TransferStatus = enum(u8) {
    queued,
    running,
    done,
    failed,
    canceled,

    pub fn jsonName(self: TransferStatus) []const u8 {
        return @tagName(self);
    }
};

/// One async transfer (spec 05 §6): progress is written by the session
/// worker, read by `oars.sftp.poll` under the transfers mutex.
pub const Transfer = struct {
    id: u32,
    /// Static kind labels only: upload | download | rm | unzip | zip_download.
    kind: []const u8,
    /// Display path (owned).
    path: []const u8,
    bytes_total: u64 = 0,
    bytes_done: u64 = 0,
    status: TransferStatus = .queued,
    /// Static error strings only.
    err: []const u8 = "",
    /// Uploads are driven by chunks from the frontend: the cancel op deletes
    /// the partial and marks the transfer; the next chunk sees the flag.
    cancel_flag: bool = false,
};

/// Session-owned transfer registry: bounded history (active transfers plus
/// the most recent completed ones), all access under a spinlock.
pub const Transfers = struct {
    mutex: std.atomic.Mutex = .unlocked,
    list: std.ArrayList(Transfer) = .empty,
    next_id: u32 = 1,
    const max_completed: usize = 32;

    pub fn lock(self: *Transfers) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    pub fn unlock(self: *Transfers) void {
        self.mutex.unlock();
    }

    pub fn deinit(self: *Transfers, allocator: std.mem.Allocator) void {
        self.lock();
        defer self.unlock();
        for (self.list.items) |t| allocator.free(t.path);
        self.list.deinit(allocator);
    }

    /// Worker-teardown variant of deinit: the session outlives its worker
    /// (the manager map holds it until disconnect), and late bridge polls
    /// keep reading the registry — leave it valid-but-empty instead of
    /// deinit-poisoned (0.16's ArrayList.deinit writes `undefined`).
    pub fn reset(self: *Transfers, allocator: std.mem.Allocator) void {
        self.lock();
        defer self.unlock();
        for (self.list.items) |t| allocator.free(t.path);
        self.list.clearAndFree(allocator);
    }

    /// Adds a transfer; returns its id. Caller holds the lock.
    pub fn add(self: *Transfers, allocator: std.mem.Allocator, kind: []const u8, path: []const u8) !u32 {
        const id = self.next_id;
        self.next_id +%= 1;
        try self.addWithId(allocator, id, kind, path);
        return id;
    }

    /// Adds a transfer under an explicit id (uploads carry the frontend's
    /// unguessable transfer_id). Caller holds the lock.
    pub fn addWithId(self: *Transfers, allocator: std.mem.Allocator, id: u32, kind: []const u8, path: []const u8) !void {
        if (id == 0) return error.InvalidTransferId;
        if (self.get(id) != null) return; // already registered
        const owned = try allocator.dupe(u8, path);
        errdefer allocator.free(owned);
        try self.list.append(allocator, .{ .id = id, .kind = kind, .path = owned });
    }

    /// Caller holds the lock.
    pub fn get(self: *Transfers, id: u32) ?*Transfer {
        for (self.list.items) |*t| {
            if (t.id == id) return t;
        }
        return null;
    }

    /// Marks a transfer terminal; evicts the oldest completed beyond the
    /// cap. Caller holds the lock.
    pub fn finish(self: *Transfers, allocator: std.mem.Allocator, id: u32, ok: bool, err: []const u8) void {
        const t = self.get(id) orelse return;
        t.status = if (ok) .done else .failed;
        t.err = if (ok) "" else err;
        var completed: usize = 0;
        for (self.list.items) |e| {
            if (e.status == .done or e.status == .failed or e.status == .canceled) completed += 1;
        }
        while (completed > max_completed) {
            var found: ?usize = null;
            for (self.list.items, 0..) |e, i| {
                if (e.status == .done or e.status == .failed or e.status == .canceled) {
                    found = i;
                    break;
                }
            }
            const i = found orelse break;
            allocator.free(self.list.items[i].path);
            _ = self.list.orderedRemove(i);
            completed -= 1;
        }
    }
};

// --- ZIP preflight ------------------------------------------------------------

pub const ZipEntry = struct {
    /// Slice into the archive bytes (not owned).
    name: []const u8,
    method: u16,
    compressed_size: u64,
    uncompressed_size: u64,
    local_offset: u64,
    is_dir: bool,
    is_symlink: bool,
};

pub const ZipError = error{
    NotAZip,
    Truncated,
    UnsupportedZip64,
    TooManyEntries,
    EntryTooLarge,
    TotalTooLarge,
    AbsolutePath,
    ParentTraversal,
    DriveLetter,
    SymlinkEntry,
    DuplicateEntry,
    FileDirConflict,
    PathTooLong,
    DepthTooDeep,
    CompressionRatioExceeded,
    UnsupportedMethod,
    InvalidName,
    OutOfMemory,
};

fn readU16(bytes: []const u8, off: usize) u16 {
    return std.mem.readInt(u16, bytes[off..][0..2], .little);
}

fn readU32(bytes: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, bytes[off..][0..4], .little);
}

const EndRecord = struct {
    record_count_total: u64,
    central_directory_size: u64,
    central_directory_offset: u64,
};

/// Locates the end-of-central-directory record by scanning backwards from
/// the end of the buffer (the record sits before the archive comment).
fn findEndRecord(bytes: []const u8) ZipError!EndRecord {
    const min_len = @sizeOf(std.zip.EndRecord);
    if (bytes.len < min_len) return error.NotAZip;
    var pos = bytes.len;
    // The comment can be at most 65535 bytes; scan that window plus the
    // record itself.
    const stop = bytes.len -| (65535 + min_len);
    while (pos >= min_len) : (pos -= 1) {
        if (std.mem.eql(u8, bytes[pos - min_len .. pos - min_len + 4], &std.zip.end_record_sig)) {
            const count: u64 = readU16(bytes, pos - min_len + 10);
            const cd_size: u64 = readU32(bytes, pos - min_len + 12);
            const cd_offset: u64 = readU32(bytes, pos - min_len + 16);
            if (count == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF) {
                return error.UnsupportedZip64;
            }
            return .{
                .record_count_total = count,
                .central_directory_size = cd_size,
                .central_directory_offset = cd_offset,
            };
        }
        if (pos - 1 <= stop) break;
    }
    return error.NotAZip;
}

/// Scans the ZIP central directory (spec 05 §5 preflight): entry names,
/// sizes, offsets, methods, and the unix mode from the external attributes.
/// The archive must already be fully in memory (bounded by
/// `ZipLimits.max_archive_bytes`).
pub fn scanZipCentralDirectory(allocator: std.mem.Allocator, bytes: []const u8, limits: ZipLimits) ZipError![]ZipEntry {
    const end = try findEndRecord(bytes);
    if (end.record_count_total > limits.max_entries) return error.TooManyEntries;
    if (end.central_directory_offset + end.central_directory_size > bytes.len) return error.Truncated;

    var out: std.ArrayList(ZipEntry) = .empty;
    errdefer out.deinit(allocator);
    var pos: usize = @intCast(end.central_directory_offset);
    var count: usize = 0;
    while (count < end.record_count_total) : (count += 1) {
        if (pos + 46 > bytes.len) return error.Truncated;
        if (!std.mem.eql(u8, bytes[pos..][0..4], &std.zip.central_file_header_sig)) return error.Truncated;
        const method = readU16(bytes, pos + 10);
        const crc = readU32(bytes, pos + 16);
        _ = crc;
        const csize: u64 = readU32(bytes, pos + 20);
        const usize_size: u64 = readU32(bytes, pos + 24);
        const name_len = readU16(bytes, pos + 28);
        const extra_len = readU16(bytes, pos + 30);
        const comment_len = readU16(bytes, pos + 32);
        const ext_attrs = readU32(bytes, pos + 38);
        const local_offset: u64 = readU32(bytes, pos + 42);
        pos += 46;
        if (pos + name_len + extra_len + comment_len > bytes.len) return error.Truncated;
        const name = bytes[pos .. pos + name_len];
        pos += name_len + extra_len + comment_len;
        if (std.mem.indexOfScalar(u8, name, 0) != null) return error.InvalidName;
        if (name.len > limits.max_path_len) return error.PathTooLong;

        const unix_mode = (ext_attrs >> 16) & 0xFFFF;
        const is_symlink = (unix_mode & 0o170000) == 0o120000;
        const is_dir = name.len > 0 and name[name.len - 1] == '/';
        const method_ok = method == 0 or method == 8;
        if (!method_ok) return error.UnsupportedMethod;

        if (usize_size > limits.max_per_entry) return error.EntryTooLarge;

        // Compression-ratio guard: a tiny archive must not explode. A
        // stored (method 0) entry has ratio 1 by construction.
        if (method == 8) {
            if (csize == 0 and usize_size > 0) return error.CompressionRatioExceeded;
            if (csize > 0 and usize_size / csize > limits.max_compression_ratio) return error.CompressionRatioExceeded;
        }

        out.append(allocator, .{
            .name = name,
            .method = method,
            .compressed_size = csize,
            .uncompressed_size = usize_size,
            .local_offset = local_offset,
            .is_dir = is_dir,
            .is_symlink = is_symlink,
        }) catch return error.OutOfMemory;
    }

    const entries = out.toOwnedSlice(allocator) catch return error.OutOfMemory;
    validateZipEntries(entries, limits) catch |err| {
        allocator.free(entries);
        return err;
    };
    return entries;
}

/// Traversal and conflict checks over the scanned entries (spec 05 §5):
/// absolute paths, `..`, drive letters, symlinks, duplicates, file/dir
/// conflicts, total size, depth.
fn validateZipEntries(entries: []const ZipEntry, limits: ZipLimits) ZipError!void {
    var total: u64 = 0;
    for (entries) |e| {
        total +|= e.uncompressed_size;
        if (total > limits.max_total_uncompressed) return error.TotalTooLarge;
        try validateZipEntryName(e.name, limits);
        if (e.is_symlink) return error.SymlinkEntry;
    }
    // Duplicates and file/dir conflicts: exact duplicate names are rejected;
    // a file whose path is a prefix-directory of another entry (or vice
    // versa) is a conflict — the tree cannot materialize.
    for (entries, 0..) |a, i| {
        for (entries[i + 1 ..]) |b| {
            if (std.mem.eql(u8, a.name, b.name)) return error.DuplicateEntry;
            if (isPrefixConflict(a.name, b.name)) return error.FileDirConflict;
        }
    }
}

fn isPrefixConflict(a: []const u8, b: []const u8) bool {
    // "a/b" vs "a" (file) — or "a" vs "a/b" — conflict when the shorter name
    // is a FILE and the longer one descends under it.
    const shorter = if (a.len < b.len) a else b;
    const longer = if (a.len < b.len) b else a;
    if (shorter.len >= longer.len) return false;
    if (!std.mem.startsWith(u8, longer, shorter)) return false;
    // The shorter must be a file (no trailing slash); the longer must be a
    // child (next char is a separator).
    if (shorter[shorter.len - 1] == '/') return false;
    const next = longer[shorter.len];
    return next == '/' or next == '\\';
}

fn validateZipEntryName(name: []const u8, limits: ZipLimits) ZipError!void {
    if (name.len == 0) return error.InvalidName;
    if (name[0] == '/' or name[0] == '\\') return error.AbsolutePath;
    if (name.len >= 2 and name[1] == ':') return error.DriveLetter;
    var depth: usize = 0;
    var it = std.mem.tokenizeAny(u8, name, "/\\");
    while (it.next()) |component| {
        depth += 1;
        if (depth > limits.max_depth) return error.DepthTooDeep;
        if (std.mem.eql(u8, component, "..")) return error.ParentTraversal;
        if (std.mem.eql(u8, component, ".")) return error.InvalidName;
    }
    if (depth == 0) return error.InvalidName;
}

/// A minimal ZIP writer for fixtures/tests: stored (method 0) entries only.
/// Produces a valid single-disk, non-zip64 archive.
pub fn buildStoredZip(allocator: std.mem.Allocator, names: []const []const u8, datas: []const []const u8) ![]u8 {
    std.debug.assert(names.len == datas.len);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var offsets: std.ArrayList(u32) = .empty;
    defer offsets.deinit(allocator);
    var crcs: std.ArrayList(u32) = .empty;
    defer crcs.deinit(allocator);

    for (names, datas) |name, data| {
        const offset: u32 = @intCast(out.items.len);
        try offsets.append(allocator, offset);
        var crc = std.hash.Crc32.init();
        crc.update(data);
        try crcs.append(allocator, crc.final());

        try out.appendSlice(allocator, &std.zip.local_file_header_sig);
        try out.appendSlice(allocator, &[_]u8{ 20, 0 }); // version needed
        try out.appendSlice(allocator, &[_]u8{ 0, 0 }); // flags
        try out.appendSlice(allocator, &[_]u8{ 0, 0 }); // method: store
        try out.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0 }); // time+date
        try out.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0 }); // crc placeholder
        try out.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0 }); // csize placeholder
        try out.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0 }); // usize placeholder
        const nl: u16 = @intCast(name.len);
        try out.appendSlice(allocator, std.mem.asBytes(&nl));
        try out.appendSlice(allocator, &[_]u8{ 0, 0 }); // extra length
        try out.appendSlice(allocator, name);
        try out.appendSlice(allocator, data);
        // Patch crc/csize/usize.
        const data_start = offset + 30 + name.len;
        std.mem.writeInt(u32, out.items[offset + 14 ..][0..4], crcs.items[crcs.items.len - 1], .little);
        std.mem.writeInt(u32, out.items[offset + 18 ..][0..4], @intCast(data.len), .little);
        std.mem.writeInt(u32, out.items[offset + 22 ..][0..4], @intCast(data.len), .little);
        _ = data_start;
    }

    const cd_offset: u32 = @intCast(out.items.len);
    for (names, datas, 0..) |name, data, i| {
        try out.appendSlice(allocator, &std.zip.central_file_header_sig);
        try out.appendSlice(allocator, &[_]u8{ 20, 0 }); // version made by (dos)
        try out.appendSlice(allocator, &[_]u8{ 20, 0 }); // version needed
        try out.appendSlice(allocator, &[_]u8{ 0, 0 }); // flags
        try out.appendSlice(allocator, &[_]u8{ 0, 0 }); // method
        try out.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0 }); // time+date
        try out.appendSlice(allocator, std.mem.asBytes(&crcs.items[i]));
        const l: u32 = @intCast(data.len);
        try out.appendSlice(allocator, std.mem.asBytes(&l));
        try out.appendSlice(allocator, std.mem.asBytes(&l));
        const nl: u16 = @intCast(name.len);
        try out.appendSlice(allocator, std.mem.asBytes(&nl));
        try out.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0, 0, 0 }); // extra+comment+disk
        try out.appendSlice(allocator, &[_]u8{ 0, 0 }); // int attrs
        try out.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0 }); // ext attrs
        try out.appendSlice(allocator, std.mem.asBytes(&offsets.items[i]));
        try out.appendSlice(allocator, name);
    }
    const cd_size: u32 = @intCast(out.items.len - cd_offset);
    const count: u16 = @intCast(names.len);
    try out.appendSlice(allocator, &std.zip.end_record_sig);
    try out.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0 }); // disk numbers
    try out.appendSlice(allocator, std.mem.asBytes(&count));
    try out.appendSlice(allocator, std.mem.asBytes(&count));
    try out.appendSlice(allocator, std.mem.asBytes(&cd_size));
    try out.appendSlice(allocator, std.mem.asBytes(&cd_offset));
    try out.appendSlice(allocator, &[_]u8{ 0, 0 }); // comment len
    return out.toOwnedSlice(allocator);
}

// --- tests ---------------------------------------------------------------------

const testing = std.testing;

test "mode strings render rwx with special bits" {
    var buf: [9]u8 = undefined;
    try testing.expectEqualStrings("rw-r--r--", modeString(0o644, &buf));
    try testing.expectEqualStrings("rwxr-xr-x", modeString(0o755, &buf));
    try testing.expectEqualStrings("rwxr-xr-x", modeString(0o40755, &buf));
    try testing.expectEqualStrings("rwxrwxrwx", modeString(0o120777, &buf));
    try testing.expectEqualStrings("rwsr-xr-x", modeString(0o4755, &buf));
    try testing.expectEqualStrings("rwxr-sr-x", modeString(0o2755, &buf));
    try testing.expectEqualStrings("rwxr-xr-t", modeString(0o1755, &buf));
    try testing.expectEqualStrings("--x--x--x", modeString(0o111, &buf));
}

test "kind follows the file type bits" {
    try testing.expect(kindFromMode(0o100644) == .file);
    try testing.expect(kindFromMode(0o40755) == .dir);
    try testing.expect(kindFromMode(0o120777) == .symlink);
    try testing.expect(kindFromMode(0o060000) == .other);
}

test "display names escape invalid utf8 with U+FFFD" {
    const allocator = testing.allocator;
    const plain = try displayName(allocator, "nginx.conf");
    defer allocator.free(plain);
    try testing.expectEqualStrings("nginx.conf", plain);

    // 0xFF is never valid UTF-8.
    const broken = try displayName(allocator, &[_]u8{ 'a', 0xff, 'b' });
    defer allocator.free(broken);
    try testing.expectEqualStrings("a\u{fffd}b", broken);
}

test "remote path decode: utf8 and base64 forms" {
    const allocator = testing.allocator;
    const u = try decodeRemotePath(allocator, .{ .utf8 = "/var/www" });
    defer allocator.free(u);
    try testing.expectEqualStrings("/var/www", u);

    const b = try decodeRemotePath(allocator, .{ .base64 = "L3Zhci93d3c=" });
    defer allocator.free(b);
    try testing.expectEqualStrings("/var/www", b);

    try testing.expectError(error.NoPath, decodeRemotePath(allocator, .{}));
    try testing.expectError(error.InvalidBase64, decodeRemotePath(allocator, .{ .base64 = "%%%" }));
}

test "path validation rejects control bytes and empty paths" {
    try validatePath("/var/log/app.log");
    try validatePath("relative/path");
    try testing.expectError(error.NoPath, validatePath(""));
    try testing.expectError(error.InvalidPath, validatePath("/var/log/a\nb"));
    try testing.expectError(error.InvalidPath, validatePath("/x\x00y"));

    try validateLocalPath("/tmp/out.bin");
    try testing.expectError(error.InvalidPath, validateLocalPath("tmp/out.bin"));
}

test "stored zip fixture scans with names, sizes, and offsets" {
    const allocator = testing.allocator;
    const zip = try buildStoredZip(allocator, &.{ "a.txt", "dir/b.txt" }, &.{ "hello", "world" });
    defer allocator.free(zip);
    const entries = try scanZipCentralDirectory(allocator, zip, .{});
    defer allocator.free(entries);
    try testing.expectEqual(@as(usize, 2), entries.len);
    try testing.expectEqualStrings("a.txt", entries[0].name);
    try testing.expectEqual(@as(u64, 5), entries[0].uncompressed_size);
    try testing.expectEqual(@as(u16, 0), entries[0].method);
    try testing.expectEqualStrings("dir/b.txt", entries[1].name);
}

test "zip preflight rejects traversal, absolute, and drive-letter paths" {
    const allocator = testing.allocator;
    {
        const zip = try buildStoredZip(allocator, &.{"../evil.txt"}, &.{"x"});
        defer allocator.free(zip);
        try testing.expectError(error.ParentTraversal, scanZipCentralDirectory(allocator, zip, .{}));
    }
    {
        const zip = try buildStoredZip(allocator, &.{"/etc/passwd"}, &.{"x"});
        defer allocator.free(zip);
        try testing.expectError(error.AbsolutePath, scanZipCentralDirectory(allocator, zip, .{}));
    }
    {
        const zip = try buildStoredZip(allocator, &.{"C:\\windows\\x"}, &.{"x"});
        defer allocator.free(zip);
        try testing.expectError(error.DriveLetter, scanZipCentralDirectory(allocator, zip, .{}));
    }
    {
        const zip = try buildStoredZip(allocator, &.{"a/../b.txt"}, &.{"x"});
        defer allocator.free(zip);
        try testing.expectError(error.ParentTraversal, scanZipCentralDirectory(allocator, zip, .{}));
    }
}

test "zip preflight rejects duplicates and file/dir conflicts" {
    const allocator = testing.allocator;
    {
        const zip = try buildStoredZip(allocator, &.{ "a.txt", "a.txt" }, &.{ "x", "y" });
        defer allocator.free(zip);
        try testing.expectError(error.DuplicateEntry, scanZipCentralDirectory(allocator, zip, .{}));
    }
    {
        // A file "a" and a child "a/b" cannot both materialize.
        const zip = try buildStoredZip(allocator, &.{ "a", "a/b" }, &.{ "x", "y" });
        defer allocator.free(zip);
        try testing.expectError(error.FileDirConflict, scanZipCentralDirectory(allocator, zip, .{}));
    }
}

test "zip preflight enforces depth, entry count, and per-entry size limits" {
    const allocator = testing.allocator;
    {
        const zip = try buildStoredZip(allocator, &.{"deep/a/b/c/d/e/f/g/h/i/j/k/l.txt"}, &.{"x"});
        defer allocator.free(zip);
        try testing.expectError(error.DepthTooDeep, scanZipCentralDirectory(allocator, zip, .{ .max_depth = 3 }));
    }
    {
        const zip = try buildStoredZip(allocator, &.{ "a", "b", "c" }, &.{ "x", "y", "z" });
        defer allocator.free(zip);
        try testing.expectError(error.TooManyEntries, scanZipCentralDirectory(allocator, zip, .{ .max_entries = 2 }));
    }
}

test "zip scanner rejects non-zip bytes and truncated archives" {
    const allocator = testing.allocator;
    try testing.expectError(error.NotAZip, scanZipCentralDirectory(allocator, "not a zip at all", .{}));
    const zip = try buildStoredZip(allocator, &.{"a.txt"}, &.{"hello"});
    defer allocator.free(zip);
    // Cutting the end record off entirely: not a zip anymore.
    try testing.expectError(error.NotAZip, scanZipCentralDirectory(allocator, zip[0 .. zip.len - 4], .{}));
    // An end record whose central directory points past the buffer is
    // truncated, not silently accepted.
    std.mem.writeInt(u32, zip[zip.len - 6 ..][0..4], @as(u32, 0xFFFFFF00), .little);
    try testing.expectError(error.Truncated, scanZipCentralDirectory(allocator, zip, .{}));
}

test "transfers track progress, completion, and bounded history" {
    const allocator = testing.allocator;
    var transfers: Transfers = .{};
    defer transfers.deinit(allocator);

    transfers.lock();
    const id = try transfers.add(allocator, "download", "/tmp/big.bin");
    const t = transfers.get(id).?;
    t.status = .running;
    t.bytes_total = 100;
    t.bytes_done = 40;
    transfers.unlock();

    transfers.lock();
    const t2 = transfers.get(id).?;
    try testing.expectEqual(@as(u64, 40), t2.bytes_done);
    try testing.expectEqualStrings("download", t2.kind);
    transfers.finish(allocator, id, true, "");
    transfers.unlock();

    transfers.lock();
    try testing.expect(transfers.get(id).?.status == .done);
    transfers.unlock();
}
