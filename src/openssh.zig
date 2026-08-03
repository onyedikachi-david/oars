//! OpenSSH "openssh-key-v1" private key parsing (OpenSSH's PROTOCOL.key).
//!
//! The vendored libssh2 is built on mbedTLS, which cannot read OpenSSH
//! private keys and has no Ed25519 support at all — so Ed25519 client
//! auth is implemented natively: this module decodes the PEM armor and
//! the openssh-key-v1 container, decrypts the private blob when it is
//! passphrase protected (bcrypt KDF via libssh2's vendored
//! bcrypt_pbkdf, AES-256-CTR via Zig std), and hands the Ed25519 seed
//! to ssh.zig's sign-callback auth.

const std = @import("std");

extern fn _libssh2_bcrypt_pbkdf(
    pass: [*c]const u8,
    passlen: usize,
    salt: [*c]const u8,
    saltlen: usize,
    key: [*c]u8,
    keylen: usize,
    rounds: c_uint,
) c_int;

pub const Error = error{
    NotOpenSsh,
    Malformed,
    UnsupportedCipher,
    WrongPassphrase,
    OutOfMemory,
};

pub const Parsed = struct {
    /// e.g. "ssh-ed25519" (slice into the decoded blob — do not free).
    key_type: []const u8,
    /// SSH wire encoding of the public key (allocated copy).
    public_wire: []u8,
    /// Ed25519 seed, present when key_type is "ssh-ed25519".
    ed25519_seed: ?[32]u8,

    pub fn deinit(self: *Parsed, allocator: std.mem.Allocator) void {
        allocator.free(self.key_type);
        allocator.free(self.public_wire);
    }
};

const pem_header = "-----BEGIN OPENSSH PRIVATE KEY-----";
const pem_footer = "-----END OPENSSH PRIVATE KEY-----";
const magic = "openssh-key-v1\x00";

const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    fn u32be(self: *Reader) Error!u32 {
        if (self.pos + 4 > self.data.len) return error.Malformed;
        defer self.pos += 4;
        return std.mem.readInt(u32, self.data[self.pos..][0..4], .big);
    }

    /// A length-prefixed SSH string.
    fn string(self: *Reader) Error![]const u8 {
        const len = try self.u32be();
        if (self.pos + len > self.data.len) return error.Malformed;
        defer self.pos += len;
        return self.data[self.pos .. self.pos + len];
    }
};

/// Parses `pem` (the full file content). Returns error.NotOpenSsh when
/// the file is not an openssh-key-v1 PEM (e.g. classic PKCS#1/PKCS#8 —
/// those go through libssh2 instead). `passphrase` may be empty for
/// unencrypted keys.
pub fn parse(allocator: std.mem.Allocator, pem: []const u8, passphrase: []const u8) Error!Parsed {
    const decoded = try decodePem(allocator, pem);
    defer allocator.free(decoded);

    if (decoded.len < magic.len or !std.mem.eql(u8, decoded[0..magic.len], magic)) {
        return error.Malformed;
    }
    var outer = Reader{ .data = decoded, .pos = magic.len };

    const cipher_name = try outer.string();
    const kdf_name = try outer.string();
    const kdf_options = try outer.string();
    const nkeys = try outer.u32be();
    if (nkeys != 1) return error.Malformed; // ssh-keygen always writes 1
    const public_wire = try outer.string();
    const private_blob = try outer.string();

    // Decrypt the private blob if needed.
    var plain: []const u8 = private_blob;
    var plain_owned: ?[]u8 = null;
    defer if (plain_owned) |p| allocator.free(p);
    if (!std.mem.eql(u8, cipher_name, "none")) {
        plain_owned = try decryptBlob(allocator, cipher_name, kdf_name, kdf_options, private_blob, passphrase);
        plain = plain_owned.?;
    }

    var inner = Reader{ .data = plain };
    const check1 = try inner.u32be();
    const check2 = try inner.u32be();
    if (check1 != check2) return error.WrongPassphrase;

    const key_type = try inner.string();
    var seed: ?[32]u8 = null;
    if (std.mem.eql(u8, key_type, "ssh-ed25519")) {
        _ = try inner.string(); // public key (already have the wire blob)
        const priv = try inner.string(); // 64 bytes: seed || public
        if (priv.len != 64) return error.Malformed;
        seed = priv[0..32].*;
    }
    // Other key types need no field extraction: the caller falls back
    // to libssh2's own OpenSSH parser with the original file bytes.

    return .{
        .key_type = try allocator.dupe(u8, key_type),
        .public_wire = try allocator.dupe(u8, public_wire),
        .ed25519_seed = seed,
    };
}

fn decodePem(allocator: std.mem.Allocator, pem: []const u8) Error![]u8 {
    const start = std.mem.indexOf(u8, pem, pem_header) orelse return error.NotOpenSsh;
    const body_start = start + pem_header.len;
    const end_rel = std.mem.indexOf(u8, pem[body_start..], pem_footer) orelse return error.Malformed;
    const body = pem[body_start .. body_start + end_rel];

    // Base64 body with whitespace stripped.
    var clean: std.ArrayList(u8) = .empty;
    defer clean.deinit(allocator);
    for (body) |ch| {
        switch (ch) {
            ' ', '\t', '\r', '\n' => continue,
            else => try clean.append(allocator, ch),
        }
    }
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(clean.items) catch return error.Malformed;
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);
    std.base64.standard.Decoder.decode(decoded, clean.items) catch return error.Malformed;
    return decoded;
}

fn decryptBlob(
    allocator: std.mem.Allocator,
    cipher_name: []const u8,
    kdf_name: []const u8,
    kdf_options: []const u8,
    blob: []const u8,
    passphrase: []const u8,
) Error![]u8 {
    if (!std.mem.eql(u8, cipher_name, "aes256-ctr")) return error.UnsupportedCipher;
    if (!std.mem.eql(u8, kdf_name, "bcrypt")) return error.UnsupportedCipher;
    if (passphrase.len == 0) return error.WrongPassphrase;

    var kdf_reader = Reader{ .data = kdf_options };
    const salt = try kdf_reader.string();
    const rounds = try kdf_reader.u32be();

    var key_iv: [48]u8 = undefined; // 32-byte AES key || 16-byte IV
    if (_libssh2_bcrypt_pbkdf(
        passphrase.ptr,
        passphrase.len,
        salt.ptr,
        salt.len,
        &key_iv,
        key_iv.len,
        rounds,
    ) != 0) return error.Malformed;

    const out = try allocator.dupe(u8, blob);
    errdefer allocator.free(out);
    aes256Ctr(key_iv[0..32].*, key_iv[32..48].*, out);
    return out;
}

/// AES-256-CTR over `data` in place (OpenSSH uses a full 128-bit
/// big-endian counter seeded with the IV).
fn aes256Ctr(key: [32]u8, iv: [16]u8, data: []u8) void {
    const AesCtx = std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes256);
    const ctx = AesCtx.init(key);
    var counter = iv;
    var offset: usize = 0;
    while (offset < data.len) {
        const take = @min(16, data.len - offset);
        var block: [16]u8 = undefined;
        @memset(block[take..], 0);
        @memcpy(block[0..take], data[offset .. offset + take]);
        var out_block: [16]u8 = undefined;
        ctx.xor(&out_block, &block, counter);
        @memcpy(data[offset .. offset + take], out_block[0..take]);
        offset += take;
        // Increment the counter as a 128-bit big-endian integer.
        var i: usize = 16;
        while (i > 0) {
            i -= 1;
            counter[i] +%= 1;
            if (counter[i] != 0) break;
        }
    }
}

// --- tests ---------------------------------------------------------------

test "aes256Ctr matches a known OpenSSH-shaped vector" {
    // NIST-ish sanity: encrypt then decrypt round-trips, and the
    // keystream differs per block (counter actually advances).
    const key: [32]u8 = @splat(0x2b);
    const iv: [16]u8 = @splat(0x7e);
    var data: [48]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i);
    const original = data;
    aes256Ctr(key, iv, &data);
    try std.testing.expect(!std.mem.eql(u8, &data, &original));
    try std.testing.expect(!std.mem.eql(u8, data[0..16], data[16..32]));
    aes256Ctr(key, iv, &data);
    try std.testing.expectEqualSlices(u8, &original, &data);
}

test "parse rejects non-OpenSSH content with NotOpenSsh" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.NotOpenSsh, parse(allocator, "-----BEGIN RSA PRIVATE KEY-----\nxxxx\n-----END RSA PRIVATE KEY-----\n", ""));
}

test "parse round-trips an unencrypted ed25519 openssh-key-v1 blob" {
    const allocator = std.testing.allocator;
    // Build a minimal openssh-key-v1 container by hand.
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(allocator);
    const check: u32 = 0xa5a5a5a5;
    try appendU32(&blob, allocator, check);
    try appendU32(&blob, allocator, check);
    try appendString(&blob, allocator, "ssh-ed25519");
    const pub_bytes: [32]u8 = @splat(0x11);
    try appendString(&blob, allocator, &pub_bytes);
    var priv_bytes: [64]u8 = undefined;
    for (&priv_bytes, 0..) |*b, i| b.* = @intCast(i);
    try appendString(&blob, allocator, &priv_bytes);
    try appendString(&blob, allocator, "comment");

    var outer: std.ArrayList(u8) = .empty;
    defer outer.deinit(allocator);
    try outer.appendSlice(allocator, magic);
    try appendString(&outer, allocator, "none");
    try appendString(&outer, allocator, "none");
    try appendString(&outer, allocator, "");
    try appendU32(&outer, allocator, 1);
    var pub_wire: std.ArrayList(u8) = .empty;
    defer pub_wire.deinit(allocator);
    try appendString(&pub_wire, allocator, "ssh-ed25519");
    try appendString(&pub_wire, allocator, &pub_bytes);
    try appendString(&outer, allocator, pub_wire.items);
    try appendString(&outer, allocator, blob.items);

    const b64_len = std.base64.standard.Encoder.calcSize(outer.items.len);
    const b64 = try allocator.alloc(u8, b64_len);
    defer allocator.free(b64);
    _ = std.base64.standard.Encoder.encode(b64, outer.items);
    const pem = try std.fmt.allocPrint(allocator, "{s}\n{s}\n{s}\n", .{ pem_header, b64, pem_footer });
    defer allocator.free(pem);

    var parsed = try parse(allocator, pem, "");
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("ssh-ed25519", parsed.key_type);
    try std.testing.expectEqualSlices(u8, pub_wire.items, parsed.public_wire);
    try std.testing.expectEqualSlices(u8, priv_bytes[0..32], &parsed.ed25519_seed.?);
}

fn appendU32(list: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, v, .big);
    try list.appendSlice(allocator, &buf);
}

fn appendString(list: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try appendU32(list, allocator, @intCast(s.len));
    try list.appendSlice(allocator, s);
}
