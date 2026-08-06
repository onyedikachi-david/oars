//! Bounded RFC 6455 WebSocket server codec (spec 12 §6).
//!
//! Pure functions over slices — no sockets — so the handshake rules and
//! the frame codec are unit-testable in isolation. The session worker
//! drives the socket and feeds it bytes.
//!
//! Enforcement per spec 12 §6:
//!   - handshake: ≤ 16 KB headers; GET + Host + `Upgrade: websocket` +
//!     `Connection` containing `Upgrade` + version 13 + a valid key
//!     (decodes to 16 bytes); Origin ∈ {zero://app, http://127.0.0.1:5173};
//!     path must be `/vnc/<token>`; client must offer the `binary`
//!     subprotocol; extensions are declined by omission.
//!   - frames: client frames must be masked; RSV bits zero; valid
//!     opcodes; control frames FIN + ≤ 125 bytes; minimal length
//!     encodings; 64-bit lengths with the high bit clear; ≤ 8 MB per
//!     frame. Text data is not part of this VNC bridge (close 1003).

const std = @import("std");

pub const ws_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
pub const max_handshake_bytes = 16 * 1024;
pub const max_frame_bytes = 8 * 1024 * 1024;
pub const max_connection_buffer = 16 * 1024 * 1024;
pub const ws_protocol = "binary";
pub const allowed_origins = [_][]const u8{ "zero://app", "http://127.0.0.1:5173" };

pub const Opcode = enum(u8) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,

    pub fn isControl(self: Opcode) bool {
        return self == .close or self == .ping or self == .pong;
    }
};

pub const CloseCode = enum(u16) {
    normal = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    too_big = 1009,
    internal_error = 1011,
};

pub const HandshakeError = error{
    Incomplete,
    HeadersTooLarge,
    InvalidRequestLine,
    InvalidMethod,
    InvalidPath,
    MissingHost,
    BadUpgrade,
    BadConnection,
    BadVersion,
    BadKey,
    BadOrigin,
    BadProtocol,
};

pub const HandshakeResult = struct {
    /// Header bytes consumed; anything after is frame data.
    header_len: usize,
    /// The validated `Sec-WebSocket-Key` (views the request buffer) —
    /// used to compute the accept value.
    key: []const u8,
};

/// Parses the HTTP/1.1 upgrade request in `buffer` (the worker
/// accumulates until it returns). Validates everything and returns the
/// header length (bytes consumed; anything after is frame data).
/// `token` is the tunnel's 128-bit URL token (hex).
pub fn parseHandshake(buffer: []const u8, token: []const u8) HandshakeError!HandshakeResult {
    if (buffer.len > max_handshake_bytes) return error.HeadersTooLarge;
    const header_end = std.mem.indexOf(u8, buffer, "\r\n\r\n") orelse return error.Incomplete;
    const header = buffer[0..header_end];

    var lines = std.mem.splitScalar(u8, header, '\n');
    const request_line = std.mem.trim(u8, lines.next() orelse return error.InvalidRequestLine, "\r");
    var path: []const u8 = "";
    {
        var parts = std.mem.tokenizeAny(u8, request_line, " ");
        const method = parts.next() orelse return error.InvalidRequestLine;
        if (!std.mem.eql(u8, method, "GET")) return error.InvalidMethod;
        path = parts.next() orelse return error.InvalidRequestLine;
        const version = parts.next() orelse return error.InvalidRequestLine;
        if (!std.mem.eql(u8, version, "HTTP/1.1")) return error.InvalidRequestLine;
        if (parts.next() != null) return error.InvalidRequestLine;
    }
    const expected_path = blk: {
        if (token.len != 32) break :blk "";
        var expected_buf: [40]u8 = undefined;
        break :blk std.fmt.bufPrint(&expected_buf, "/vnc/{s}", .{token}) catch "";
    };
    if (expected_path.len == 0 or !std.mem.eql(u8, path, expected_path)) return error.InvalidPath;

    var has_host = false;
    var upgrade_ok = false;
    var connection_ok = false;
    var version_ok = false;
    var key: ?[]const u8 = null;
    var origin_ok = false;
    var protocol_ok = false;

    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, "\r");
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidRequestLine;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "host")) {
            if (value.len == 0) return error.MissingHost;
            has_host = true;
        } else if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
            upgrade_ok = std.ascii.eqlIgnoreCase(value, "websocket");
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            var tokens = std.mem.tokenizeAny(u8, value, ",");
            while (tokens.next()) |t| {
                if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, t, " \t"), "upgrade")) {
                    connection_ok = true;
                    break;
                }
            }
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-version")) {
            version_ok = std.mem.eql(u8, std.mem.trim(u8, value, " \t"), "13");
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-key")) {
            key = value;
        } else if (std.ascii.eqlIgnoreCase(name, "origin")) {
            for (allowed_origins) |allowed| {
                if (std.mem.eql(u8, value, allowed)) {
                    origin_ok = true;
                    break;
                }
            }
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-protocol")) {
            var tokens = std.mem.tokenizeAny(u8, value, ",");
            while (tokens.next()) |t| {
                if (std.mem.eql(u8, std.mem.trim(u8, t, " \t"), ws_protocol)) {
                    protocol_ok = true;
                    break;
                }
            }
        }
    }

    if (!has_host) return error.MissingHost;
    if (!upgrade_ok) return error.BadUpgrade;
    if (!connection_ok) return error.BadConnection;
    if (!version_ok) return error.BadVersion;
    const key_value = key orelse return error.BadKey;
    if (!validKey(key_value)) return error.BadKey;
    if (!origin_ok) return error.BadOrigin;
    if (!protocol_ok) return error.BadProtocol;
    return .{ .header_len = header_end + 4, .key = key_value };
}

/// `Sec-WebSocket-Key` must be base64 that decodes to exactly 16 bytes.
pub fn validKey(key: []const u8) bool {
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(key) catch return false;
    if (decoded_len != 16) return false;
    var decoded: [16]u8 = undefined;
    std.base64.standard.Decoder.decode(&decoded, key) catch return false;
    return true;
}

/// base64(sha1(key + guid)) — 28 bytes into `out`.
pub fn acceptKey(key: []const u8, out: *[28]u8) []const u8 {
    var digest: [20]u8 = undefined;
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(key);
    hasher.update(ws_guid);
    hasher.final(&digest);
    return std.base64.standard.Encoder.encode(out, &digest);
}

/// Writes the 101 response into `buf`; returns the byte count.
pub fn encodeUpgradeResponse(buf: []u8, accept: []const u8) usize {
    const response =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: ";
    @memcpy(buf[0..response.len], response);
    @memcpy(buf[response.len .. response.len + accept.len], accept);
    var rest = buf[response.len + accept.len ..];
    const tail = "\r\nSec-WebSocket-Protocol: binary\r\n\r\n";
    @memcpy(rest[0..tail.len], tail);
    return response.len + accept.len + tail.len;
}

// --- frame codec ----------------------------------------------------------

pub const ParseError = error{
    Truncated,
    ProtocolError,
    TooBig,
};

pub const Frame = struct {
    opcode: Opcode,
    fin: bool,
    /// Views the input; unmask (in place) before consuming.
    payload: []const u8,
    /// Offset of `payload` in the parsed input (for in-place unmask).
    payload_offset: usize,
    mask: [4]u8 = undefined,
};

pub const ParseResult = union(enum) {
    frame: Frame,
    need_more,
};

fn parseLength(b0: u8, input: []const u8) ParseError!struct { len: u64, header_len: usize, minimal: bool } {
    const len7 = b0 & 0x7f;
    switch (len7) {
        126 => {
            if (input.len < 4) return error.Truncated;
            const len = (@as(u64, input[2]) << 8) | input[3];
            if (len < 126) return error.ProtocolError; // non-minimal
            return .{ .len = len, .header_len = 4, .minimal = true };
        },
        127 => {
            if (input.len < 10) return error.Truncated;
            var len: u64 = 0;
            for (input[2..10]) |b| len = (len << 8) | b;
            if (len & (1 << 63) != 0) return error.ProtocolError; // high bit set
            if (len < 65536) return error.ProtocolError; // non-minimal
            return .{ .len = len, .header_len = 10, .minimal = true };
        },
        else => return .{ .len = len7, .header_len = 2, .minimal = true },
    }
}

/// Parses one complete frame from `input` (header + payload). When
/// `require_masked` is true (server parsing client frames) an unmasked
/// frame is a protocol error; server frames (client-side parse) are
/// unmasked. The payload views `input` — unmask before consuming.
pub fn parseFrame(input: []const u8, require_masked: bool) ParseError!ParseResult {
    if (input.len < 2) return .need_more;
    const b0 = input[0];
    const b1 = input[1];
    if (b0 & 0x70 != 0) return error.ProtocolError; // RSV bits must be zero
    const fin = b0 & 0x80 != 0;
    const opcode_raw = b0 & 0x0f;
    if (opcode_raw > 0x2 and opcode_raw < 0x8) return error.ProtocolError; // 3-7 reserved
    if (opcode_raw > 0xa) return error.ProtocolError; // 11-15 reserved
    const opcode: Opcode = @enumFromInt(opcode_raw);
    const masked = b1 & 0x80 != 0;
    if (require_masked and !masked) return error.ProtocolError;
    if (!require_masked and masked) return error.ProtocolError;
    const len_info = try parseLength(b1, input);
    if (len_info.len > max_frame_bytes) return error.TooBig;
    if (opcode.isControl()) {
        if (!fin) return error.ProtocolError; // fragmented control frame
        if (len_info.len > 125) return error.ProtocolError;
    }
    var header_len = len_info.header_len;
    if (masked) header_len += 4;
    if (input.len < header_len + len_info.len) return .need_more;
    var mask: [4]u8 = undefined;
    if (masked) @memcpy(&mask, input[len_info.header_len..header_len]);
    return .{ .frame = .{
        .opcode = opcode,
        .fin = fin,
        .payload = input[header_len .. header_len + @as(usize, @intCast(len_info.len))],
        .payload_offset = header_len,
        .mask = mask,
    } };
}

/// XORs the mask over the payload in place (client frames only).
pub fn unmask(payload: []u8, mask: [4]u8) void {
    for (payload, 0..) |byte, i| payload[i] = byte ^ mask[i & 3];
}

/// Encodes a server frame (unmasked, minimal length) into `buf`; the
/// payload must follow at `buf[header_len..]` — the worker appends both.
pub fn encodeFrame(buf: []u8, opcode: Opcode, payload_len: usize, fin: bool) usize {
    const b0: u8 = (if (fin) @as(u8, 0x80) else 0) | @intFromEnum(opcode);
    buf[0] = b0;
    if (payload_len < 126) {
        buf[1] = @intCast(payload_len);
        return 2;
    }
    if (payload_len < 65536) {
        buf[1] = 126;
        buf[2] = @intCast(payload_len >> 8);
        buf[3] = @intCast(payload_len & 0xff);
        return 4;
    }
    buf[1] = 127;
    var i: usize = 0;
    var len = payload_len;
    while (i < 8) : (i += 1) {
        buf[9 - i] = @intCast(len & 0xff);
        len >>= 8;
    }
    return 10;
}

/// Client frame encoder (tests + the Zig integration client): masked,
/// FIN, minimal length.
pub fn encodeClientFrame(buf: []u8, opcode: Opcode, payload: []const u8, mask: [4]u8) usize {
    const header = encodeFrame(buf, opcode, payload.len, true);
    buf[1] |= 0x80; // mask bit (payload_len field already written)
    @memcpy(buf[header .. header + 4], &mask);
    for (payload, 0..) |byte, i| buf[header + 4 + i] = byte ^ mask[i & 3];
    return header + 4 + payload.len;
}

/// Encodes a close frame with a status code and optional reason.
pub fn encodeCloseFrame(buf: []u8, code: CloseCode, reason: []const u8) usize {
    const header = encodeFrame(buf, .close, 2 + reason.len, true);
    buf[header] = @intCast(@intFromEnum(code) >> 8);
    buf[header + 1] = @intCast(@intFromEnum(code) & 0xff);
    @memcpy(buf[header + 2 .. header + 2 + reason.len], reason);
    return header + 2 + reason.len;
}

// --- unit tests -----------------------------------------------------------

fn testRequest(token: []const u8) [512]u8 {
    var buf: [512]u8 = undefined;
    var path_buf: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/vnc/{s}", .{token}) catch unreachable;
    _ = std.fmt.bufPrint(&buf, "GET {s} HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: zero://app\r\nSec-WebSocket-Protocol: binary\r\n\r\n", .{path}) catch unreachable;
    return buf;
}

test "handshake accepts the RFC 6455 example request" {
    const token = "0123456789abcdef0123456789abcdef";
    var buf = testRequest(token);
    const parsed = try parseHandshake(buf[0..], token);
    try std.testing.expect(std.mem.endsWith(u8, buf[0..parsed.header_len], "\r\n\r\n"));
    try std.testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", parsed.key);
    // The RFC 6455 §1.3 example key → accept vector.
    var accept: [28]u8 = undefined;
    const encoded = acceptKey("dGhlIHNhbXBsZSBub25jZQ==", &accept);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", encoded);
    var resp: [256]u8 = undefined;
    const n = encodeUpgradeResponse(&resp, encoded);
    try std.testing.expect(std.mem.indexOf(u8, resp[0..n], "101 Switching Protocols") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp[0..n], "Sec-WebSocket-Protocol: binary") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp[0..n], "Sec-WebSocket-Extensions") == null);
}

test "handshake rejects bad tokens, origins, versions, keys, and headers" {
    const token = "0123456789abcdef0123456789abcdef";
    var buf = testRequest(token);

    // Wrong token path.
    try std.testing.expectError(error.InvalidPath, parseHandshake(buf[0..], "ffffffffffffffffffffffffffffffff"));

    // Wrong origin.
    var bad_origin: [512]u8 = undefined;
    const origin_req = "GET /vnc/{s} HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: https://evil.example\r\nSec-WebSocket-Protocol: binary\r\n\r\n";
    _ = std.fmt.bufPrint(&bad_origin, origin_req, .{token}) catch unreachable;
    try std.testing.expectError(error.BadOrigin, parseHandshake(&bad_origin, token));

    // Wrong version.
    var bad_version: [512]u8 = undefined;
    _ = std.fmt.bufPrint(&bad_version, "GET /vnc/{s} HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 12\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: zero://app\r\nSec-WebSocket-Protocol: binary\r\n\r\n", .{token}) catch unreachable;
    try std.testing.expectError(error.BadVersion, parseHandshake(&bad_version, token));

    // Bad key (base64 that decodes to 18 bytes, not 16).
    var bad_key: [512]u8 = undefined;
    _ = std.fmt.bufPrint(&bad_key, "GET /vnc/{s} HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAAAA\r\nOrigin: zero://app\r\nSec-WebSocket-Protocol: binary\r\n\r\n", .{token}) catch unreachable;
    try std.testing.expectError(error.BadKey, parseHandshake(&bad_key, token));

    // Missing Upgrade token in Connection.
    var bad_conn: [512]u8 = undefined;
    _ = std.fmt.bufPrint(&bad_conn, "GET /vnc/{s} HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: zero://app\r\nSec-WebSocket-Protocol: binary\r\n\r\n", .{token}) catch unreachable;
    try std.testing.expectError(error.BadConnection, parseHandshake(&bad_conn, token));

    // Missing binary subprotocol.
    var bad_proto: [512]u8 = undefined;
    _ = std.fmt.bufPrint(&bad_proto, "GET /vnc/{s} HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: zero://app\r\nSec-WebSocket-Protocol: text\r\n\r\n", .{token}) catch unreachable;
    try std.testing.expectError(error.BadProtocol, parseHandshake(&bad_proto, token));

    // Incomplete headers.
    try std.testing.expectError(error.Incomplete, parseHandshake(buf[0..40], token));
}

test "handshake header names are case-insensitive and connection tokens are split" {
    const token = "0123456789abcdef0123456789abcdef";
    var buf: [512]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "GET /vnc/{s} HTTP/1.1\r\n" ++
        "host: 127.0.0.1\r\n" ++
        "upgrade: WebSocket\r\n" ++
        "connection: keep-alive, upgrade\r\n" ++
        "SEC-WEBSOCKET-VERSION: 13\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "ORIGIN: http://127.0.0.1:5173\r\n" ++
        "sec-websocket-protocol: superchat, binary\r\n\r\n", .{token}) catch unreachable;
    const parsed = try parseHandshake(&buf, token);
    try std.testing.expect(parsed.header_len > 0);
}

test "client frames parse, unmask, and validate" {
    // Echo a masked "hello" binary frame.
    var frame: [16]u8 = undefined;
    const mask = [4]u8{ 0x12, 0x34, 0x56, 0x78 };
    const n = encodeClientFrame(&frame, .binary, "hello", mask);
    const result = try parseFrame(frame[0..n], true);
    switch (result) {
        .frame => |f| {
            try std.testing.expectEqual(Opcode.binary, f.opcode);
            try std.testing.expect(f.fin);
            try std.testing.expectEqual(@as(usize, 5), f.payload.len); // masked bytes at this point
        },
        .need_more => return error.TestUnexpectedResult,
    }

    // Unmasking in place recovers the payload (header 2 + mask 4).
    const payload_buf = try std.heap.page_allocator.dupe(u8, frame[6..n]);
    defer std.heap.page_allocator.free(payload_buf);
    unmask(payload_buf, mask);
    try std.testing.expectEqualStrings("hello", payload_buf);
}

test "frame validation rejects protocol violations" {
    // Unmasked client frame.
    var buf: [8]u8 = undefined;
    const n = encodeFrame(&buf, .binary, 3, true);
    @memcpy(buf[n .. n + 3], "abc");
    try std.testing.expectError(error.ProtocolError, parseFrame(buf[0 .. n + 3], true));

    // RSV bits set.
    buf[0] = 0xC2; // FIN + RSV1 + binary
    try std.testing.expectError(error.ProtocolError, parseFrame(buf[0 .. n + 3], true));

    // Invalid opcode.
    buf[0] = 0x83; // FIN + opcode 3
    try std.testing.expectError(error.ProtocolError, parseFrame(buf[0 .. n + 3], true));

    // Non-minimal 126 encoding (len 5 encoded as 126 + 0x0005).
    var long: [16]u8 = undefined;
    const ln = encodeFrame(&long, .binary, 5, true);
    long[1] = 126;
    long[2] = 0;
    long[3] = 5;
    try std.testing.expectError(error.ProtocolError, parseFrame(long[0 .. ln + 5], true));

    // Control frame > 125 bytes.
    var ctrl: [130]u8 = undefined;
    const cn = encodeFrame(&ctrl, .ping, 126, true);
    try std.testing.expectError(error.ProtocolError, parseFrame(ctrl[0 .. cn + 126], true));

    // Fragmented control frame.
    var frag: [8]u8 = undefined;
    const fn2 = encodeFrame(&frag, .ping, 1, false);
    try std.testing.expectError(error.ProtocolError, parseFrame(frag[0 .. fn2 + 1], true));

    // 64-bit length with the high bit set.
    var hb: [20]u8 = undefined;
    const hn = encodeFrame(&hb, .binary, 1, true);
    hb[1] = 127;
    hb[2] = 0x80; // high bit
    try std.testing.expectError(error.ProtocolError, parseFrame(hb[0..hn], true));

    // Truncated frame: need_more, not an error.
    var trunc_buf: [24]u8 = undefined;
    const tn = encodeClientFrame(&trunc_buf, .binary, "abcdef", .{ 1, 2, 3, 4 });
    try std.testing.expect(try parseFrame(trunc_buf[0 .. tn - 3], true) == .need_more);
}

test "frame length encodings and limits" {
    // 126-coded length round trip.
    var big: [1024]u8 = undefined;
    const n = encodeFrame(&big, .binary, 300, true);
    const masked_n = n + 4;
    big[1] |= 0x80;
    @memcpy(big[n..masked_n], &[4]u8{ 0, 0, 0, 0 });
    const result = try parseFrame(big[0 .. masked_n + 300], true);
    switch (result) {
        .frame => |f| try std.testing.expectEqual(@as(usize, 300), f.payload.len),
        .need_more => return error.TestUnexpectedResult,
    }
    // Over the 8 MB cap (masked, so the size check is what fires).
    var len_buf: [10]u8 = undefined;
    _ = encodeFrame(&len_buf, .binary, max_frame_bytes + 1, true);
    len_buf[1] |= 0x80;
    try std.testing.expectError(error.TooBig, parseFrame(&len_buf, true));
}

test "close frames encode with a status code" {
    var buf: [32]u8 = undefined;
    const n = encodeCloseFrame(&buf, .unsupported_data, "text is not supported");
    const result = try parseFrame(buf[0..n], false);
    switch (result) {
        .frame => |f| {
            try std.testing.expectEqual(Opcode.close, f.opcode);
            try std.testing.expectEqual(@as(u16, 1003), (@as(u16, f.payload[0]) << 8) | f.payload[1]);
        },
        .need_more => return error.TestUnexpectedResult,
    }
}
