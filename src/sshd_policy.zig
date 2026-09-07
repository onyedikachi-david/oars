//! Shared effective-OpenSSH-policy module (specs 08 and 09): parses the
//! normalized, lower-case output of `sshd -T -C`, expands the documented
//! `AuthorizedKeysFile` tokens into exact static source paths, and
//! classifies dynamic and certificate sources as structured warnings.
//! Pure: no shell, no network, no libssh2.
//!
//! Extracted from access.zig so Spec 08 (per-server SSH management) and
//! Spec 09 (fleet access) evaluate the same effective source model
//! instead of drifting into two interpretations of sshd policy.

const std = @import("std");

/// A non-file key source reported by `sshd -T` (dynamic command output
/// or certificate trust). Owns its strings.
pub const DynamicSource = struct {
    /// The sshd directive, lower-case (e.g. "authorizedkeyscommand").
    key: []const u8,
    /// The configured value (command, path, or user).
    value: []const u8,
    /// "dynamic" for command-sourced keys, "certificate" for CA /
    /// principal trust.
    kind: []const u8,
};

pub const EffectiveSshdPolicy = struct {
    pubkey_authentication: ?bool = null,
    static_sources: [][]const u8 = &.{},
    warnings: [][]const u8 = &.{},
    /// Structured dynamic/certificate sources (spec 08 surfaces these
    /// as non-editable source rows; spec 09 only reads `warnings`).
    dynamic_sources: []DynamicSource = &.{},

    pub fn deinit(self: *EffectiveSshdPolicy, allocator: std.mem.Allocator) void {
        for (self.static_sources) |source| allocator.free(source);
        allocator.free(self.static_sources);
        for (self.warnings) |warning| allocator.free(warning);
        allocator.free(self.warnings);
        for (self.dynamic_sources) |source| {
            allocator.free(source.key);
            allocator.free(source.value);
        }
        allocator.free(self.dynamic_sources);
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

/// The source kind for a dynamic/certificate sshd directive, or null
/// when the directive does not grant key access outside static files.
fn dynamicKind(key: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, key, "authorizedkeyscommand")) return "dynamic";
    if (std.mem.eql(u8, key, "authorizedkeysuserca")) return "certificate";
    if (std.mem.eql(u8, key, "trustedusercakeys")) return "certificate";
    if (std.mem.eql(u8, key, "authorizedprincipalsfile")) return "certificate";
    if (std.mem.eql(u8, key, "authorizedprincipalscommand")) return "certificate";
    return null;
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
    var dynamic: std.ArrayList(DynamicSource) = .empty;
    errdefer {
        for (dynamic.items) |source| {
            allocator.free(source.key);
            allocator.free(source.value);
        }
        dynamic.deinit(allocator);
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
        if (dynamicKind(key)) |kind| {
            if (std.mem.eql(u8, value, "none")) continue;
            try effectiveWarning(allocator, &warnings, key, value);
            try dynamic.append(allocator, .{
                .key = try allocator.dupe(u8, key),
                .value = try allocator.dupe(u8, value),
                .kind = kind,
            });
        }
    }
    if (pubkey == null) try effectiveWarning(allocator, &warnings, "pubkeyauthentication", "not reported");
    if (!saw_authorized_keys_file) try effectiveWarning(allocator, &warnings, "authorizedkeysfile", "not reported");
    return .{
        .pubkey_authentication = pubkey,
        .static_sources = try sources.toOwnedSlice(allocator),
        .warnings = try warnings.toOwnedSlice(allocator),
        .dynamic_sources = try dynamic.toOwnedSlice(allocator),
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

// --- tests -----------------------------------------------------------------

const testing = std.testing;

test "sshdSourcesForcePartial flags dynamic and alternate key sources" {
    try testing.expect(!sshdSourcesForcePartial(&.{}));
    try testing.expect(!sshdSourcesForcePartial(&.{"AuthorizedKeysFile .ssh/authorized_keys"}));
    try testing.expect(!sshdSourcesForcePartial(&.{"AuthorizedKeysFile %h/.ssh/authorized_keys"}));
    try testing.expect(sshdSourcesForcePartial(&.{"AuthorizedKeysFile /etc/ssh/keys/%u"}));
    try testing.expect(sshdSourcesForcePartial(&.{"AuthorizedKeysCommand /usr/bin/keys %u"}));
    try testing.expect(sshdSourcesForcePartial(&.{"AuthorizedKeysCommandUser sshd"}));
    try testing.expect(sshdSourcesForcePartial(&.{"AuthorizedKeysUserCA /etc/ssh/ca.pub"}));
    try testing.expect(!sshdSourcesForcePartial(&.{"PermitRootLogin yes"}));
}

test "effective sshd policy expands every static source and reports dynamic sources" {
    const allocator = testing.allocator;
    const output =
        "pubkeyauthentication yes\n" ++
        "authorizedkeysfile .ssh/authorized_keys /etc/ssh/keys/%u/%U %%keys\n" ++
        "authorizedkeyscommand /usr/local/bin/lookup %u\n" ++
        "authorizedkeyscommanduser nobody\n" ++
        "trustedusercakeys /etc/ssh/trusted_ca.pub\n" ++
        "authorizedprincipalsfile none\n";
    var policy = try parseEffectiveSshdPolicy(allocator, output, "alice", 1001, "/home/alice");
    defer policy.deinit(allocator);
    try testing.expectEqual(true, policy.pubkey_authentication.?);
    try testing.expectEqual(@as(usize, 3), policy.static_sources.len);
    try testing.expectEqualStrings("/home/alice/.ssh/authorized_keys", policy.static_sources[0]);
    try testing.expectEqualStrings("/etc/ssh/keys/alice/1001", policy.static_sources[1]);
    try testing.expectEqualStrings("/home/alice/%keys", policy.static_sources[2]);
    try testing.expectEqual(@as(usize, 2), policy.warnings.len);
    try testing.expect(std.mem.startsWith(u8, policy.warnings[0], "authorizedkeyscommand "));
    try testing.expect(std.mem.startsWith(u8, policy.warnings[1], "trustedusercakeys "));
    try testing.expectEqual(@as(usize, 2), policy.dynamic_sources.len);
    try testing.expectEqualStrings("dynamic", policy.dynamic_sources[0].kind);
    try testing.expectEqualStrings("certificate", policy.dynamic_sources[1].kind);
    try testing.expect(hasCertificateAuthorityOption("restrict,cert-authority,command=\"echo no\""));
    try testing.expect(!hasCertificateAuthorityOption("restrict,no-port-forwarding"));
}

test "effective sshd policy keeps unsupported path tokens explicit" {
    const allocator = testing.allocator;
    var policy = try parseEffectiveSshdPolicy(
        allocator,
        "pubkeyauthentication yes\nauthorizedkeysfile /keys/%f .ssh/authorized_keys\n",
        "root",
        0,
        "/root",
    );
    defer policy.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), policy.static_sources.len);
    try testing.expectEqualStrings("/root/.ssh/authorized_keys", policy.static_sources[0]);
    try testing.expectEqual(@as(usize, 1), policy.warnings.len);
    try testing.expect(std.mem.indexOf(u8, policy.warnings[0], "unsupported") != null);
}

test "authorizedkeysfile none yields no static sources" {
    const allocator = testing.allocator;
    var policy = try parseEffectiveSshdPolicy(allocator, "pubkeyauthentication yes\nauthorizedkeysfile none\n", "root", 0, "/root");
    defer policy.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), policy.static_sources.len);
    try testing.expectEqual(@as(usize, 0), policy.dynamic_sources.len);
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
