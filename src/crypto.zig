//! Vault cryptography (spec 17 §6): PBKDF2-HMAC-SHA256 key derivation
//! and AES-256-GCM authenticated encryption over the vendored mbedTLS
//! (already linked for libssh2 — no new dependency; build.zig
//! `linkSshStack` puts `third_party/mbedtls/include` on the include
//! path).
//!
//! The GCM tag is the integrity boundary: a wrong password, a tampered
//! header, or a modified ciphertext all fail the same atomic auth
//! check, so callers can report one honest error ("wrong password or
//! corrupt file") and never touch unauthenticated plaintext.

const std = @import("std");

pub const c = @cImport({
    @cInclude("mbedtls/gcm.h");
    @cInclude("mbedtls/pkcs5.h");
    @cInclude("mbedtls/md.h");
});

pub const key_len = 32; // AES-256
pub const nonce_len = 12; // SP 800-38D §8.2 default (96-bit)
pub const tag_len = 16;

pub const Error = error{
    KdfFailed,
    SealFailed,
    /// GCM auth failed: wrong password, tampered header, or corrupted
    /// ciphertext (spec 17 §10 — one explicit error for all three).
    AuthFailed,
};

/// PBKDF2-HMAC-SHA256 (RFC 8018) with `iterations` rounds. `key_out`
/// must be `key_len` bytes.
pub fn pbkdf2Sha256(password: []const u8, salt: []const u8, iterations: u32, key_out: *[key_len]u8) Error!void {
    const rc = c.mbedtls_pkcs5_pbkdf2_hmac_ext(
        c.MBEDTLS_MD_SHA256,
        password.ptr,
        password.len,
        salt.ptr,
        salt.len,
        iterations,
        key_out.len,
        key_out,
    );
    if (rc != 0) return error.KdfFailed;
}

/// AES-256-GCM seal: encrypts `plaintext` into `ciphertext` (same
/// length) and writes the 16-byte auth tag. `aad` is authenticated but
/// not encrypted.
pub fn gcmSeal(key: *const [key_len]u8, nonce: *const [nonce_len]u8, aad: []const u8, plaintext: []const u8, ciphertext: []u8, tag: *[tag_len]u8) Error!void {
    var ctx: c.mbedtls_gcm_context = undefined;
    c.mbedtls_gcm_init(&ctx);
    defer c.mbedtls_gcm_free(&ctx);
    if (c.mbedtls_gcm_setkey(&ctx, c.MBEDTLS_CIPHER_ID_AES, key, key_len * 8) != 0) return error.SealFailed;
    if (c.mbedtls_gcm_crypt_and_tag(
        &ctx,
        c.MBEDTLS_GCM_ENCRYPT,
        plaintext.len,
        nonce,
        nonce_len,
        aad.ptr,
        aad.len,
        plaintext.ptr,
        ciphertext.ptr,
        tag_len,
        tag,
    ) != 0) return error.SealFailed;
}

/// AES-256-GCM open: authenticates `aad` + `ciphertext` against `tag`
/// and decrypts into `plaintext` (same length). Any mismatch fails with
/// `error.AuthFailed` before plaintext is returned.
pub fn gcmOpen(key: *const [key_len]u8, nonce: *const [nonce_len]u8, aad: []const u8, ciphertext: []const u8, tag: *const [tag_len]u8, plaintext: []u8) Error!void {
    var ctx: c.mbedtls_gcm_context = undefined;
    c.mbedtls_gcm_init(&ctx);
    defer c.mbedtls_gcm_free(&ctx);
    if (c.mbedtls_gcm_setkey(&ctx, c.MBEDTLS_CIPHER_ID_AES, key, key_len * 8) != 0) return error.SealFailed;
    if (c.mbedtls_gcm_auth_decrypt(
        &ctx,
        ciphertext.len,
        nonce,
        nonce_len,
        aad.ptr,
        aad.len,
        tag,
        tag_len,
        ciphertext.ptr,
        plaintext.ptr,
    ) != 0) return error.AuthFailed;
}

// --- tests -----------------------------------------------------------------

fn hex(out: []u8, input: []const u8) void {
    std.debug.assert(input.len == out.len * 2);
    for (input, 0..) |ch, i| {
        const v: u8 = switch (ch) {
            '0'...'9' => ch - '0',
            'a'...'f' => ch - 'a' + 10,
            'A'...'F' => ch - 'A' + 10,
            else => unreachable,
        };
        if (i % 2 == 0) out[i / 2] = v << 4 else out[i / 2] |= v;
    }
}

// RFC 7914 §11: PBKDF2-HMAC-SHA256, P="passwd", S="salt", c=1,
// dkLen=64. The expected value was generated with an independent
// implementation (Python hashlib.pbkdf2_hmac) and pinned here.
// Our key_len is 32, so we pin the first 32 bytes (64 hex chars).
test "pbkdf2 matches the RFC 7914 S11 vector" {
    var key: [key_len]u8 = undefined;
    try pbkdf2Sha256("passwd", "salt", 1, &key);
    var want: [32]u8 = undefined;
    hex(&want, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc");
    try std.testing.expectEqualSlices(u8, &want, &key);
}

// NIST SP 800-38D Appendix B Test Case 3 (AES-256-GCM), cross-checked
// against an independent implementation (Zig std crypto): key =
// feffe992…8308 ×2, IV = cafebabefacedbaddecaf888, empty AAD.
test "gcm seal matches the NIST SP 800-38D case 3 vector" {
    var key: [key_len]u8 = undefined;
    hex(&key, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    var nonce: [nonce_len]u8 = undefined;
    hex(&nonce, "cafebabefacedbaddecaf888");
    var pt: [64]u8 = undefined;
    hex(&pt, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    var ct: [64]u8 = undefined;
    var tag: [tag_len]u8 = undefined;
    try gcmSeal(&key, &nonce, "", &pt, &ct, &tag);

    var want_ct: [64]u8 = undefined;
    hex(&want_ct, "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");
    var want_tag: [tag_len]u8 = undefined;
    hex(&want_tag, "b094dac5d93471bdec1a502270e3cc6c");
    try std.testing.expectEqualSlices(u8, &want_ct, &ct);
    try std.testing.expectEqualSlices(u8, &want_tag, &tag);

    // And the same constants open back to the plaintext.
    var opened: [64]u8 = undefined;
    try gcmOpen(&key, &nonce, "", &ct, &tag, &opened);
    try std.testing.expectEqualSlices(u8, &pt, &opened);
}

test "gcm round trip with aad and tamper rejection" {
    var key: [key_len]u8 = undefined;
    @memset(&key, 0x42);
    var nonce: [nonce_len]u8 = undefined;
    @memset(&nonce, 0x24);
    const aad = "OARSVAULT\x01";
    const pt = "the quick brown fox jumps over the lazy dog";

    var ct: [43]u8 = undefined;
    var tag: [tag_len]u8 = undefined;
    try gcmSeal(&key, &nonce, aad, pt, &ct, &tag);

    var opened: [43]u8 = undefined;
    try gcmOpen(&key, &nonce, aad, &ct, &tag, &opened);
    try std.testing.expectEqualStrings(pt, &opened);

    // A flipped tag byte fails auth (wrong password behaves identically).
    var bad_tag = tag;
    bad_tag[0] ^= 0x01;
    try std.testing.expectError(error.AuthFailed, gcmOpen(&key, &nonce, aad, &ct, &bad_tag, &opened));

    // A modified header (aad) fails auth.
    try std.testing.expectError(error.AuthFailed, gcmOpen(&key, &nonce, "OARSVAULT\x02", &ct, &tag, &opened));

    // A modified ciphertext byte fails auth.
    var bad_ct = ct;
    bad_ct[10] ^= 0x80;
    try std.testing.expectError(error.AuthFailed, gcmOpen(&key, &nonce, aad, &bad_ct, &tag, &opened));
}
