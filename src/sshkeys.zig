//! SSH key management (spec 08): the pure OpenSSH `authorized_keys`
//! parser, the line-preserving writer, fingerprint computation (SHA-256
//! over the base64-decoded wire blob — matches `ssh-keygen -lf`
//! byte-for-byte), and the SSH wire-format decoder that verifies the
//! embedded key type and derives key size only for formats whose
//! structure is understood. No shell, no network.
//!
//! The parser follows the sshd(8) grammar, not whitespace alone: quoted
//! and escaped authorized-key options are scanned until the key-type
//! token, then one base64 key blob, and the rest of the line is the
//! comment. Lines that are empty or start with '#' are preserved by the
//! writer untouched. Malformed lines surface as `parsed:false` rows with
//! the raw line — the list never crashes, and the writer never drops a
//! line it could not parse (except the one explicitly targeted).

const std = @import("std");

/// Reading cap for authorized_keys files (10k-line files are in spec;
/// this bounds memory).
pub const max_keys_file_bytes: usize = 4 * 1024 * 1024;
/// A single line cap: sshd allows long lines; this bounds the parser.
pub const max_key_line_bytes: usize = 64 * 1024;

/// Known key types, in the order sshd(8) documents them. The
/// options-vs-type boundary uses this list; unknown types in the type
/// position are preserved (bits stay null) when the blob validates.
const known_types = [_][]const u8{
    "ssh-ed25519",
    "sk-ssh-ed25519@openssh.com",
    "ssh-rsa",
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-dss",
};

fn isKnownType(tok: []const u8) bool {
    for (known_types) |t| {
        if (std.mem.eql(u8, t, tok)) return true;
    }
    return false;
}

pub const Key = struct {
    /// 0-based line number in the file (the client's stable handle).
    line_index: usize,
    parsed: bool,
    /// The raw line, without the trailing '\n' (any '\r' kept). View
    /// into the file content.
    raw: []const u8,
    options: []const u8 = "",
    key_type: []const u8 = "",
    /// The base64 blob text.
    key: []const u8 = "",
    comment: []const u8 = "",
    /// "SHA256:…" over the decoded blob (owned).
    fingerprint_sha256: []const u8 = "",
    /// Key size only for formats whose structure is understood.
    bits: ?u16 = null,
    /// Hex SHA-256 of the raw line (the revoke/rotate conflict guard).
    line_hash: []const u8 = "",
    /// Static error text for `parsed:false` rows.
    @"error": []const u8 = "",
};

pub const Line = struct {
    /// The raw line bytes, without the trailing '\n' (any '\r' kept).
    raw: []const u8,
    /// Index into `keys` when this line parsed as a key.
    key_index: ?usize = null,
};

pub const ParsedFile = struct {
    lines: []Line,
    keys: []Key,

    pub fn deinit(self: *ParsedFile, allocator: std.mem.Allocator) void {
        for (self.keys) |*k| {
            allocator.free(k.fingerprint_sha256);
            allocator.free(k.line_hash);
        }
        allocator.free(self.keys);
        allocator.free(self.lines);
    }
};

fn isSpace(ch: u8) bool {
    return ch == ' ' or ch == '\t';
}

fn skipSpace(text: []const u8, from: usize) usize {
    var i = from;
    while (i < text.len and isSpace(text[i])) i += 1;
    return i;
}

/// Splits the content into lines (a trailing '\n' does not produce a
/// trailing empty line) and parses each. `content` must stay alive as
/// long as the returned ParsedFile (raw/type/blob/comment are views).
pub fn parse(allocator: std.mem.Allocator, content: []const u8) !ParsedFile {
    var lines: std.ArrayList(Line) = .empty;
    errdefer lines.deinit(allocator);
    var keys: std.ArrayList(Key) = .empty;
    errdefer {
        for (keys.items) |*k| {
            allocator.free(k.fingerprint_sha256);
            allocator.free(k.line_hash);
        }
        keys.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, content, '\n');
    var line_no: usize = 0;
    while (it.next()) |raw_line| : (line_no += 1) {
        const text = std.mem.trimEnd(u8, raw_line, "\r");
        if (text.len == 0 or text[0] == '#') {
            try lines.append(allocator, .{ .raw = raw_line });
            continue;
        }
        var key = try parseKeyLine(allocator, text, line_no);
        errdefer {
            allocator.free(key.fingerprint_sha256);
            allocator.free(key.line_hash);
        }
        key.line_hash = try lineHash(allocator, text);
        try lines.append(allocator, .{ .raw = raw_line, .key_index = keys.items.len });
        try keys.append(allocator, key);
    }
    // A trailing '\n' produces one phantom empty piece; drop it so a
    // file ending in a newline does not round-trip with a doubled one.
    if (content.len > 0 and content[content.len - 1] == '\n' and lines.items.len > 0 and lines.items[lines.items.len - 1].raw.len == 0) {
        _ = lines.pop();
    }
    return .{
        .lines = try lines.toOwnedSlice(allocator),
        .keys = try keys.toOwnedSlice(allocator),
    };
}

/// Parses one non-empty, non-comment line. All string fields are views
/// into `text` except fingerprint_sha256 and line_hash (owned).
fn parseKeyLine(allocator: std.mem.Allocator, text: []const u8, line_index: usize) !Key {
    var key = Key{ .line_index = line_index, .parsed = false, .raw = text };
    if (text.len > max_key_line_bytes) {
        key.@"error" = "line too long";
        return key;
    }

    // The first token: a known key type means no options.
    const first_end = skipSpace(text, 0);
    _ = first_end;
    var tok_start: usize = 0;
    while (tok_start < text.len and isSpace(text[tok_start])) tok_start += 1;
    var tok_end = tok_start;
    while (tok_end < text.len and !isSpace(text[tok_end])) tok_end += 1;
    const first = text[tok_start..tok_end];

    var type_start: usize = undefined;
    if (isKnownType(first)) {
        type_start = tok_start;
    } else {
        // Scan quoted/escaped options until a known key type appears
        // (sshd(8): options are comma-separated, spaces only inside
        // double quotes).
        var i: usize = tok_start;
        var in_quote = false;
        while (i < text.len) : (i += 1) {
            const ch = text[i];
            if (in_quote) {
                if (ch == '\\' and i + 1 < text.len) {
                    i += 1;
                    continue;
                }
                if (ch == '"') in_quote = false;
                continue;
            }
            if (ch == '"') {
                in_quote = true;
                continue;
            }
            if (isSpace(ch)) break;
        }
        if (!in_quote) {
            // The options token sequence ended at whitespace: the next
            // token must be a known type.
            const after = skipSpace(text, i);
            var t2 = after;
            while (t2 < text.len and !isSpace(text[t2])) t2 += 1;
            if (isKnownType(text[after..t2])) {
                key.options = text[0..i];
                type_start = after;
            } else {
                // No options found and the first token is not a known
                // type: treat the first token as an (unknown) type and
                // let the blob validation decide (spec: unknown valid
                // key types are preserved, without an invented bit
                // count).
                key.options = "";
                type_start = tok_start;
            }
        } else {
            // Unterminated quote: the options run to the end of the
            // line — no key type can follow.
            key.@"error" = "unterminated options quote";
            return key;
        }
    }

    var t = type_start;
    while (t < text.len and !isSpace(text[t])) t += 1;
    const key_type = text[type_start..t];
    const blob_start = skipSpace(text, t);
    var b = blob_start;
    while (b < text.len and !isSpace(text[b])) b += 1;
    const blob_text = text[blob_start..b];
    if (blob_text.len == 0) {
        key.@"error" = "missing key blob";
        return key;
    }
    const comment = std.mem.trim(u8, text[b..], " \t\r");

    const decoded = decodeBlob(allocator, blob_text) catch {
        key.@"error" = "invalid base64";
        return key;
    };
    defer allocator.free(decoded);

    // Verify the embedded type matches the text type (spec 08 §5).
    var wire = Wire{ .buf = decoded };
    const embedded = wire.string() orelse {
        key.@"error" = "malformed key blob";
        return key;
    };
    if (!std.mem.eql(u8, embedded, key_type)) {
        key.@"error" = "embedded key type does not match";
        return key;
    }

    key.parsed = true;
    key.key_type = key_type;
    key.key = blob_text;
    key.comment = comment;
    key.bits = deriveBits(key_type, &wire);
    key.fingerprint_sha256 = try fingerprint(allocator, decoded);
    return key;
}

/// Reads the len-prefixed string at the cursor (SSH wire format).
const Wire = struct {
    buf: []const u8,
    pos: usize = 0,

    fn string(w: *Wire) ?[]const u8 {
        if (w.pos + 4 > w.buf.len) return null;
        const len = std.mem.readInt(u32, w.buf[w.pos..][0..4], .big);
        w.pos += 4;
        if (w.pos + len > w.buf.len) return null;
        const s = w.buf[w.pos .. w.pos + len];
        w.pos += len;
        return s;
    }
};

/// Bit length of a key, from its decoded wire blob. Only formats whose
/// structure is understood get a number (spec 08 §5); unknown types stay
/// null rather than inventing a size. The cursor must be positioned
/// after the type string.
fn deriveBits(key_type: []const u8, wire: *Wire) ?u16 {
    if (std.mem.eql(u8, key_type, "ssh-ed25519")) return 256;
    if (std.mem.eql(u8, key_type, "sk-ssh-ed25519@openssh.com")) return 256;
    if (std.mem.eql(u8, key_type, "ecdsa-sha2-nistp256")) return 256;
    if (std.mem.eql(u8, key_type, "ecdsa-sha2-nistp384")) return 384;
    if (std.mem.eql(u8, key_type, "ecdsa-sha2-nistp521")) return 521;
    if (std.mem.eql(u8, key_type, "sk-ecdsa-sha2-nistp256@openssh.com")) return 256;
    if (std.mem.eql(u8, key_type, "ssh-rsa")) {
        // string e, mpint n — the modulus size is the key size.
        _ = wire.string() orelse return null;
        const n = wire.string() orelse return null;
        return mpintBits(n);
    }
    if (std.mem.eql(u8, key_type, "ssh-dss")) {
        // mpint p q g y — p is the prime size.
        const p = wire.string() orelse return null;
        return mpintBits(p);
    }
    return null;
}

fn mpintBits(v: []const u8) ?u16 {
    var i: usize = 0;
    if (v.len > 0 and v[0] == 0) i = 1; // sign pad byte
    if (i >= v.len) return null;
    const first_byte_bits: u6 = @intCast(@as(u16, 8) - @clz(v[i]));
    const total: u64 = @as(u64, @intCast(v.len - i - 1)) * 8 + first_byte_bits;
    if (total == 0 or total > 16384) return null;
    return @intCast(total);
}

/// "SHA256:…" over the full decoded blob (matches `ssh-keygen -lf`).
pub fn fingerprint(allocator: std.mem.Allocator, blob: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(blob, &digest, .{});
    const b64_len = std.base64.standard_no_pad.Encoder.calcSize(digest.len);
    const out = try allocator.alloc(u8, "SHA256:".len + b64_len);
    @memcpy(out[0.."SHA256:".len], "SHA256:");
    _ = std.base64.standard_no_pad.Encoder.encode(out["SHA256:".len..], &digest);
    return out;
}

/// Hex SHA-256 of a raw line (without trailing '\n'/'\r').
pub fn lineHash(allocator: std.mem.Allocator, line: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(line, &digest, .{});
    return std.fmt.allocPrint(allocator, "{x}", .{&digest});
}

/// Hex SHA-256 of a whole file's exact bytes (the whole-file conflict
/// guard every mutation submits; spec 08: an unrelated external edit
/// must not be overwritten silently).
pub fn fileSha256(allocator: std.mem.Allocator, content: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(content, &digest, .{});
    return std.fmt.allocPrint(allocator, "{x}", .{&digest});
}

/// The parsed key with this exact fingerprint in this exact source, or
/// null. Duplicate detection is per source file: the same fingerprint
/// can still be valid in a different account or source (spec 08).
pub fn findByFingerprint(parsed: *const ParsedFile, fingerprint_sha256: []const u8) ?*const Key {
    for (parsed.keys) |*k| {
        if (k.parsed and std.mem.eql(u8, k.fingerprint_sha256, fingerprint_sha256)) return k;
    }
    return null;
}

/// Appends one normalized key line to exact file content (newline
/// guard: a file without a trailing newline gets one first). Pure; the
/// caller owns the atomic write.
pub fn appendLine(allocator: std.mem.Allocator, content: []const u8, line: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    if (content.len > 0) {
        try out.appendSlice(allocator, content);
        if (content[content.len - 1] != '\n') try out.append(allocator, '\n');
    }
    try out.appendSlice(allocator, line);
    try out.append(allocator, '\n');
    return out.toOwnedSlice(allocator);
}

/// Decodes a public-key base64 blob (unpadded standard alphabet — the
/// ssh-keygen output — with a padded fallback, since some tools pad).
/// Errors on any invalid character or length. The returned slice is
/// exactly the decoded bytes.
pub fn decodeBlob(allocator: std.mem.Allocator, text: []const u8) error{ InvalidBase64, OutOfMemory }![]u8 {
    if (text.len == 0 or text.len > 64 * 1024) return error.InvalidBase64;
    if (std.base64.standard_no_pad.Decoder.calcSizeForSlice(text)) |size| {
        const buf = try allocator.alloc(u8, size);
        if (std.base64.standard_no_pad.Decoder.decode(buf, text)) |_| {
            return buf;
        } else |_| {
            // Padded input: the unpadded size over-counts by the padding;
            // decode into the padded decoder's exact size and hand back an
            // exact-sized copy (free must see the allocation size). The
            // scratch buffer is freed when this branch exits.
            defer allocator.free(buf);
            const pad_size = std.base64.standard.Decoder.calcSizeForSlice(text) catch return error.InvalidBase64;
            if (pad_size > size) return error.InvalidBase64;
            std.base64.standard.Decoder.decode(buf[0..pad_size], text) catch return error.InvalidBase64;
            const exact = try allocator.alloc(u8, pad_size);
            @memcpy(exact, buf[0..pad_size]);
            return exact;
        }
    } else |_| {
        const size = std.base64.standard.Decoder.calcSizeForSlice(text) catch return error.InvalidBase64;
        const buf = try allocator.alloc(u8, size);
        errdefer allocator.free(buf);
        std.base64.standard.Decoder.decode(buf, text) catch return error.InvalidBase64;
        return buf;
    }
}

/// Rebuilds the file from the parsed lines, dropping the target line or
/// replacing it with `replacement` (which the caller already normalized
/// to one line). Every other line keeps its exact raw bytes; the result
/// ends with a newline.
pub fn rewrite(allocator: std.mem.Allocator, parsed: *const ParsedFile, target_line: usize, replacement: ?[]const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (parsed.lines, 0..) |line, i| {
        if (i == target_line) {
            if (replacement) |r| {
                try out.appendSlice(allocator, r);
                try out.append(allocator, '\n');
            }
            continue;
        }
        try out.appendSlice(allocator, line.raw);
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

/// Validates pasted public-key text and canonicalizes it to a single
/// line `type blob comment`. Rejects multi-line input and anything the
/// key-line parser rejects. `comment_override` (when non-empty) replaces
/// the pasted comment. Returns the canonical line (owned) plus the
/// fingerprint.
pub fn normalizePublicKey(allocator: std.mem.Allocator, text: []const u8, comment_override: ?[]const u8) !struct { line: []u8, fingerprint_sha256: []u8 } {
    if (std.mem.indexOfScalar(u8, text, '\n') != null or std.mem.indexOfScalar(u8, text, '\r') != null) {
        return error.Multiline;
    }
    const trimmed = std.mem.trim(u8, text, " \t");
    if (trimmed.len == 0 or trimmed.len > max_key_line_bytes) return error.InvalidKey;
    const key = try parseKeyLine(allocator, trimmed, 0);
    defer {
        allocator.free(key.fingerprint_sha256);
        allocator.free(key.line_hash);
    }
    if (!key.parsed) return error.InvalidKey;
    const comment = if (comment_override) |c| blk: {
        const c_trimmed = std.mem.trim(u8, c, " \t");
        break :blk if (c_trimmed.len > 0) c_trimmed else key.comment;
    } else key.comment;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, key.key_type);
    try out.append(allocator, ' ');
    try out.appendSlice(allocator, key.key);
    if (comment.len > 0) {
        try out.append(allocator, ' ');
        try out.appendSlice(allocator, comment);
    }
    return .{ .line = try out.toOwnedSlice(allocator), .fingerprint_sha256 = try allocator.dupe(u8, key.fingerprint_sha256) };
}

// --- tests -----------------------------------------------------------------

const testing = std.testing;

const vector_ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBs5Tnge2MIGi6Zcyo04aosYAQ+iwk4hKYUNpIHkyMQt unit-vector";
const vector_ed25519_fp = "SHA256:IIiiMx8dWbmaEVhH8Oc9GEt16E2UPRuGtQ3itmbNZxs";
const vector_rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxmO6ejIfO+XeLfYjN9QM/sSlagHECPodVIdSm8Qq76UKWvspCEINF5+1gJkU42np3igApZXmU9+sK4ycRnHv12JwELlpwS+gr08Uv13dv+XYdrvXxSyLqAM2DplOysn9jUtfmcEN98/KGAnQpdDoq+EUu4Bvxuo/BLBr0GVsjG+x43HI916EjDqX56f5L/ooTVSYJDHfBC1kgG/m6OFQ5SrcSyudLqpx+0Q86BaAxqQuDQMJxsBpdeFuiK8Km4dUTcXajyBmXNqtH+OfX8VBUPwwilPKHmPmpHU51VWFmW6ZXRz/kdk6VBm0dgEjSRJeMV0/3n3XEqvwQHBO3R6U7 onyedikachi@Davids-MacBook-Air.local";
const vector_ecdsa = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ3PxNGPTFBmBID44I77qx5ZJMgGA37kStEzz+PMe5JzxZlomgoJTIf0cPfMOvjtvSy6BmP6miX+5gZCsAdBy+k= onyedikachi@Davids-MacBook-Air.local";

test "parses a plain key with comment and fingerprint vector" {
    const allocator = testing.allocator;
    var file = try parse(allocator, vector_ed25519);
    defer file.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), file.keys.len);
    const key = file.keys[0];
    try testing.expect(key.parsed);
    try testing.expectEqualStrings("ssh-ed25519", key.key_type);
    try testing.expectEqualStrings("unit-vector", key.comment);
    try testing.expectEqualStrings("", key.options);
    try testing.expectEqual(@as(?u16, 256), key.bits);
    // Matches `ssh-keygen -lf` byte-for-byte (spec 08 acceptance).
    try testing.expectEqualStrings(vector_ed25519_fp, key.fingerprint_sha256);
}

test "rsa and ecdsa bit counts and fingerprints match ssh-keygen" {
    const allocator = testing.allocator;
    var rsa_file = try parse(allocator, vector_rsa);
    defer rsa_file.deinit(allocator);
    const rsa = rsa_file.keys[0];
    try testing.expectEqual(@as(?u16, 2048), rsa.bits);
    try testing.expectEqualStrings("SHA256:el3RAdX7MPz8bGotR4kPQ4XBQTl42+OD1WbuC4jrRtg", rsa.fingerprint_sha256);

    // The ecdsa blob is base64-padded — the decoder must accept it.
    var ecdsa_file = try parse(allocator, vector_ecdsa);
    defer ecdsa_file.deinit(allocator);
    const ecdsa = ecdsa_file.keys[0];
    try testing.expectEqual(@as(?u16, 256), ecdsa.bits);
    try testing.expectEqualStrings("SHA256:NbUAwN6Ia7Cxko9qNAommrTues2r59uNPWa2wv3MCOE", ecdsa.fingerprint_sha256);
}

test "options with quoted spaces and commas parse and preserve exactly" {
    const allocator = testing.allocator;
    const line = "no-port-forwarding,command=\"a b,c\",from=\"1.2.3.4 5.6.7.8\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBs5Tnge2MIGi6Zcyo04aosYAQ+iwk4hKYUNpIHkyMQt hiren@macmini";
    var file = try parse(allocator, line);
    defer file.deinit(allocator);
    const key = file.keys[0];
    try testing.expect(key.parsed);
    try testing.expectEqualStrings("no-port-forwarding,command=\"a b,c\",from=\"1.2.3.4 5.6.7.8\"", key.options);
    try testing.expectEqualStrings("hiren@macmini", key.comment);
}

test "unknown key type with a valid blob is preserved without bits" {
    const allocator = testing.allocator;
    // A future type whose blob embeds its own type string: rebuild the
    // known ed25519 blob with the type renamed.
    const decoded = try decodeBlob(allocator, "AAAAC3NzaC1lZDI1NTE5AAAAIBs5Tnge2MIGi6Zcyo04aosYAQ+iwk4hKYUNpIHkyMQt");
    defer allocator.free(decoded);
    var rebuilt: [128]u8 = undefined;
    const type_name = "ssh-futuretype";
    std.mem.writeInt(u32, rebuilt[0..4], @intCast(type_name.len), .big);
    @memcpy(rebuilt[4 .. 4 + type_name.len], type_name);
    const key_data = decoded[11 + 4 ..]; // skip "ssh-ed25519" + its length
    std.mem.writeInt(u32, rebuilt[4 + type_name.len ..][0..4], @intCast(key_data.len), .big);
    @memcpy(rebuilt[8 + type_name.len ..][0..key_data.len], key_data);
    const blob = try sftpB64(allocator, rebuilt[0 .. 8 + type_name.len + key_data.len]);
    defer allocator.free(blob);
    var line_buf: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&line_buf, "ssh-futuretype {s} comment", .{blob});
    var file = try parse(allocator, line);
    defer file.deinit(allocator);
    const key = file.keys[0];
    try testing.expect(key.parsed);
    try testing.expectEqualStrings("ssh-futuretype", key.key_type);
    try testing.expect(key.bits == null);
    try testing.expect(key.fingerprint_sha256.len > 0);
}

/// Standard base64 with padding (test helper).
fn sftpB64(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(data.len));
    _ = std.base64.standard.Encoder.encode(out, data);
    return out;
}

test "malformed lines surface as parsed:false rows with the raw line" {
    const allocator = testing.allocator;
    var file = try parse(allocator, "ssh-ed25519 not-base64!! comment\njust-a-token\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBs5Tnge2MIGi6Zcyo04aosYAQ+iwk4hKYUNpIHkyMQt x\n");
    defer file.deinit(allocator);
    try testing.expectEqual(@as(usize, 3), file.keys.len);
    try testing.expect(!file.keys[0].parsed);
    try testing.expectEqualStrings("invalid base64", file.keys[0].@"error");
    try testing.expectEqualStrings("ssh-ed25519 not-base64!! comment", file.keys[0].raw);
    try testing.expect(!file.keys[1].parsed);
    try testing.expectEqualStrings("missing key blob", file.keys[1].@"error");
    try testing.expect(file.keys[2].parsed);
}

test "embedded type mismatch is refused" {
    const allocator = testing.allocator;
    var file = try parse(allocator, "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIBs5Tnge2MIGi6Zcyo04aosYAQ+iwk4hKYUNpIHkyMQt x");
    defer file.deinit(allocator);
    const key = file.keys[0];
    try testing.expect(!key.parsed);
    try testing.expectEqualStrings("embedded key type does not match", key.@"error");
}

test "empty lines and comments survive a rewrite; CRLF is preserved" {
    const allocator = testing.allocator;
    const content = "# header comment\r\n\r\n" ++ vector_ed25519 ++ "\r\n" ++ vector_rsa ++ "\r\n";
    var file = try parse(allocator, content);
    defer file.deinit(allocator);
    try testing.expectEqual(@as(usize, 4), file.lines.len);
    try testing.expectEqual(@as(usize, 2), file.keys.len);

    // Revoke the first key: only its line disappears; \r stays on the rest.
    const target = file.keys[0].line_index;
    const rewritten = try rewrite(allocator, &file, target, null);
    defer allocator.free(rewritten);
    try testing.expect(std.mem.indexOf(u8, rewritten, "unit-vector") == null);
    try testing.expect(std.mem.indexOf(u8, rewritten, "# header comment\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, rewritten, "ssh-rsa") != null);
    try testing.expect(std.mem.endsWith(u8, rewritten, "\n"));
}

test "rewrite replaces a line while preserving its neighbors and options" {
    const allocator = testing.allocator;
    const line = "restrict,command=\"internal-sftp -R\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBs5Tnge2MIGi6Zcyo04aosYAQ+iwk4hKYUNpIHkyMQt old-comment";
    var file = try parse(allocator, line ++ "\n");
    defer file.deinit(allocator);
    const replacement = "restrict,command=\"internal-sftp -R\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBs5Tnge2MIGi6Zcyo04aosYAQ+iwk4hKYUNpIHkyMQt new-comment";
    const rewritten = try rewrite(allocator, &file, file.keys[0].line_index, replacement);
    defer allocator.free(rewritten);
    try testing.expect(std.mem.indexOf(u8, rewritten, "new-comment") != null);
    try testing.expect(std.mem.indexOf(u8, rewritten, "old-comment") == null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, rewritten, "\n"));
}

test "line hashes are stable hex and differ across lines" {
    const allocator = testing.allocator;
    const h1 = try lineHash(allocator, "ssh-ed25519 AAAA x");
    defer allocator.free(h1);
    const h2 = try lineHash(allocator, "ssh-ed25519 AAAA y");
    defer allocator.free(h2);
    try testing.expectEqual(@as(usize, 64), h1.len);
    try testing.expect(!std.mem.eql(u8, h1, h2));
    // Known vector: sha256("abc") hex.
    const abc = try lineHash(allocator, "abc");
    defer allocator.free(abc);
    try testing.expectEqualStrings("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", abc);
}

test "normalizePublicKey canonicalizes and rejects multi-line input" {
    const allocator = testing.allocator;
    const normalized = try normalizePublicKey(allocator, "  ssh-ed25519   AAAAC3NzaC1lZDI1NTE5AAAAIBs5Tnge2MIGi6Zcyo04aosYAQ+iwk4hKYUNpIHkyMQt   my comment  ", null);
    defer {
        allocator.free(normalized.line);
        allocator.free(normalized.fingerprint_sha256);
    }
    try testing.expectEqualStrings("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBs5Tnge2MIGi6Zcyo04aosYAQ+iwk4hKYUNpIHkyMQt my comment", normalized.line);
    try testing.expectEqualStrings(vector_ed25519_fp, normalized.fingerprint_sha256);

    // An explicit comment overrides the pasted one.
    const overridden = try normalizePublicKey(allocator, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBs5Tnge2MIGi6Zcyo04aosYAQ+iwk4hKYUNpIHkyMQt old", "new label");
    defer {
        allocator.free(overridden.line);
        allocator.free(overridden.fingerprint_sha256);
    }
    try testing.expectEqualStrings("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBs5Tnge2MIGi6Zcyo04aosYAQ+iwk4hKYUNpIHkyMQt new label", overridden.line);

    try testing.expectError(error.Multiline, normalizePublicKey(allocator, "ssh-ed25519 AAAA\nssh-ed25519 AAAA", null));
    try testing.expectError(error.InvalidKey, normalizePublicKey(allocator, "not a key", null));
}

test "fileSha256 matches the empty-vector and content vectors" {
    const allocator = testing.allocator;
    const empty = try fileSha256(allocator, "");
    defer allocator.free(empty);
    try testing.expectEqualStrings("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", empty);
    const abc = try fileSha256(allocator, "abc");
    defer allocator.free(abc);
    try testing.expectEqualStrings("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", abc);
}

test "findByFingerprint is scoped to the exact parsed source" {
    const allocator = testing.allocator;
    var file = try parse(allocator, vector_ed25519 ++ "\n" ++ vector_rsa);
    defer file.deinit(allocator);
    try testing.expect(findByFingerprint(&file, vector_ed25519_fp) != null);
    try testing.expect(findByFingerprint(&file, "SHA256:nope") == null);
}

test "appendLine guards the trailing newline" {
    const allocator = testing.allocator;
    const line = "ssh-ed25519 AAAA new";
    const from_empty = try appendLine(allocator, "", line);
    defer allocator.free(from_empty);
    try testing.expectEqualStrings("ssh-ed25519 AAAA new\n", from_empty);
    const from_no_nl = try appendLine(allocator, "# comment", line);
    defer allocator.free(from_no_nl);
    try testing.expectEqualStrings("# comment\nssh-ed25519 AAAA new\n", from_no_nl);
    const from_nl = try appendLine(allocator, "# comment\n", line);
    defer allocator.free(from_nl);
    try testing.expectEqualStrings("# comment\nssh-ed25519 AAAA new\n", from_nl);
}
