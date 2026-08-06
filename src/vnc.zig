//! VNC helpers (spec 12): the probe command + parser and the setup
//! helper's OS-adapter plan. Pure logic over exec output — the bridge
//! handler runs the command and feeds the output here.

const std = @import("std");

pub const probe_command =
    "printf '%%BEGIN_VNC_PROBE%%\\n'; command -v x11vnc >/dev/null 2>&1; echo x11vnc=$?; " ++
    "command -v tigervncserver >/dev/null 2>&1; echo tigervnc=$?; " ++
    "command -v Xvnc >/dev/null 2>&1; echo xvnc=$?; " ++
    "(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || netstat -tln 2>/dev/null || true)";

pub const ListeningPort = struct {
    port: u16,
    /// Process name when the listener reports one (views the output).
    process: []const u8 = "",
};

pub const ProbeResult = struct {
    x11vnc: bool = false,
    tigervnc: bool = false,
    listening: []ListeningPort = &.{},

    pub fn deinit(self: *ProbeResult, allocator: std.mem.Allocator) void {
        if (self.listening.len > 0) allocator.free(self.listening);
    }
};

/// Parses the marker-delimited probe output. `listening` entries with
/// ports 5900-5999, deduplicated, in output order.
pub fn parseProbeOutput(allocator: std.mem.Allocator, text: []const u8) ProbeResult {
    var result: ProbeResult = .{};
    var listening: std.ArrayList(ListeningPort) = .empty;
    errdefer listening.deinit(allocator);
    var seen: [16]u16 = undefined;
    var seen_count: usize = 0;
    var in_section = false;
    var tigervnc_server = false;
    var xvnc = false;

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "%BEGIN_VNC_PROBE%")) {
            in_section = true;
            continue;
        }
        if (!in_section) continue;
        if (std.mem.startsWith(u8, line, "x11vnc=")) {
            result.x11vnc = line["x11vnc=".len..].len == 1 and line["x11vnc=".len..][0] == '0';
        } else if (std.mem.startsWith(u8, line, "tigervnc=")) {
            tigervnc_server = line["tigervnc=".len..].len == 1 and line["tigervnc=".len..][0] == '0';
        } else if (std.mem.startsWith(u8, line, "xvnc=")) {
            xvnc = line["xvnc=".len..].len == 1 and line["xvnc=".len..][0] == '0';
        } else {
            const port = listeningPort(line) orelse continue;
            if (port < 5900 or port > 5999) continue;
            var dup = false;
            for (seen[0..seen_count]) |p| {
                if (p == port) {
                    dup = true;
                    break;
                }
            }
            if (dup) continue;
            if (seen_count < seen.len) {
                seen[seen_count] = port;
                seen_count += 1;
            }
            listening.append(allocator, .{
                .port = port,
                .process = listenerProcess(line),
            }) catch {};
        }
    }
    result.tigervnc = tigervnc_server or xvnc;
    result.listening = listening.toOwnedSlice(allocator) catch &.{};
    return result;
}

/// The listening port from an `ss -tlnp` or `netstat -tln` line: the
/// local address is the 4th whitespace field; the port follows its last
/// colon.
fn listeningPort(line: []const u8) ?u16 {
    var fields = std.mem.tokenizeAny(u8, line, " \t");
    _ = fields.next() orelse return null; // LISTEN / tcp
    _ = fields.next() orelse return null; // 0 / Recv-Q
    _ = fields.next() orelse return null; // 128 / Send-Q
    const local = fields.next() orelse return null;
    const colon = std.mem.lastIndexOfScalar(u8, local, ':') orelse return null;
    return std.fmt.parseInt(u16, local[colon + 1 ..], 10) catch null;
}

/// The listener's process name: `users:(("Xvnc",pid=1234,fd=5))` (ss -p)
/// or the `PID/name` column (`42766/x11vnc`, netstat -p). Empty when the
/// output carries no process info.
fn listenerProcess(line: []const u8) []const u8 {
    const marker = std.mem.indexOf(u8, line, "users:((") orelse {
        // netstat -p: a whitespace field starting with digits followed by
        // `/name` (`1/sshd -D [listener` → `sshd`).
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        while (fields.next()) |field| {
            const slash = std.mem.indexOfScalar(u8, field, '/') orelse continue;
            if (field.len > 0 and field[0] >= '0' and field[0] <= '9') {
                return field[slash + 1 ..];
            }
        }
        return "";
    };
    var rest = line[marker + "users:((".len ..];
    if (rest.len > 0 and rest[0] == '\"') rest = rest[1..];
    const end = std.mem.indexOfScalar(u8, rest, '\"') orelse return "";
    return rest[0..end];
}

pub const SetupPlan = struct {
    /// install | already_installed | manual
    action: []const u8,
    /// The exact exec command (empty for manual/already_installed).
    plan: []const u8,
    /// Suggested start command (the user replaces <vnc-password>).
    hint: []const u8,

    pub fn deinit(self: *SetupPlan, allocator: std.mem.Allocator) void {
        if (self.action.len > 0) allocator.free(self.action);
        if (self.plan.len > 0) allocator.free(self.plan);
        if (self.hint.len > 0) allocator.free(self.hint);
    }
};

/// The tested OS adapter (spec 12 §5): Alpine and Debian/Ubuntu get an
/// exact install command; anything else gets manual guidance. The hint
/// binds VNC to the display's port and always configures a password
/// (spec 12 §8: the setup helper never suggests `-nopw`).
pub fn setupPlan(
    allocator: std.mem.Allocator,
    os_release: []const u8,
    display: u16,
    x11vnc_installed: bool,
) SetupPlan {
    if (x11vnc_installed) {
        return .{
            .action = allocator.dupe(u8, "already_installed") catch "",
            .plan = "",
            .hint = "",
        };
    }
    const alpine = std.mem.indexOf(u8, os_release, "ID=alpine") != null;
    const debian = std.mem.indexOf(u8, os_release, "ID=debian") != null or std.mem.indexOf(u8, os_release, "ID=ubuntu") != null;
    const port = 5900 + display;
    var hint_buf: [512]u8 = undefined;
    const hint = std.fmt.bufPrint(&hint_buf, "Xvfb :{d} -screen 0 1280x800x24 >/dev/null 2>&1 & sleep 1; x11vnc -display :{d} -rfbport {d} -forever -shared -passwd <vnc-password>", .{ display, display, port }) catch "";
    if (alpine) {
        return .{
            .action = allocator.dupe(u8, "install") catch "",
            .plan = allocator.dupe(u8, "apk add --no-cache x11vnc xvfb") catch "",
            .hint = allocator.dupe(u8, hint) catch "",
        };
    }
    if (debian) {
        return .{
            .action = allocator.dupe(u8, "install") catch "",
            .plan = allocator.dupe(u8, "apt-get update && apt-get install -y x11vnc xvfb") catch "",
            .hint = allocator.dupe(u8, hint) catch "",
        };
    }
    return .{
        .action = allocator.dupe(u8, "manual") catch "",
        .plan = "",
        .hint = allocator.dupe(u8, "install x11vnc for your distribution, then start it bound to 127.0.0.1 with a password") catch "",
    };
}

// --- unit tests -----------------------------------------------------------

test "probe output parses booleans and listening ports (ss + netstat)" {
    const allocator = std.testing.allocator;
    const text =
        "unrelated line\n" ++
        "%BEGIN_VNC_PROBE%\n" ++
        "x11vnc=0\n" ++
        "tigervnc=1\n" ++
        "xvnc=0\n" ++
        "LISTEN 0 128 127.0.0.1:5901 0.0.0.0:* users:((\"Xvnc\",pid=1234,fd=5))\n" ++
        "LISTEN 0 128 0.0.0.0:5900 0.0.0.0:* users:((\"x11vnc\",pid=99,fd=6))\n" ++
        "tcp 0 0 0.0.0.0:5902 0.0.0.0:* LISTEN 42766/x11vnc\n" ++
        "tcp 0 0 :::5902 :::* LISTEN 42766/x11vnc\n" ++
        "tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1/sshd -D [listener\n" ++
        "LISTEN 0 128 127.0.0.1:2222 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n";
    var result = parseProbeOutput(allocator, text);
    defer result.deinit(allocator);
    try std.testing.expect(result.x11vnc);
    try std.testing.expect(result.tigervnc); // Xvnc present
    try std.testing.expectEqual(@as(usize, 3), result.listening.len);
    try std.testing.expectEqual(@as(u16, 5901), result.listening[0].port);
    try std.testing.expectEqualStrings("Xvnc", result.listening[0].process);
    try std.testing.expectEqual(@as(u16, 5900), result.listening[1].port);
    try std.testing.expectEqual(@as(u16, 5902), result.listening[2].port);
    // netstat -p reports the process in a `pid/name` field; the duplicate
    // `:::5902` line is deduped away.
    try std.testing.expectEqualStrings("x11vnc", result.listening[2].process);
    // Port 2222 is outside the VNC range and absent (also: the `1/sshd`
    // netstat field on port 22 is out of range).
    for (result.listening) |l| try std.testing.expect(l.port >= 5900 and l.port <= 5999);
}

test "probe output dedupes ports and reports nothing on empty output" {
    const allocator = std.testing.allocator;
    const text =
        "%BEGIN_VNC_PROBE%\n" ++
        "x11vnc=1\n" ++
        "tigervnc=1\n" ++
        "xvnc=1\n" ++
        "LISTEN 0 128 127.0.0.1:5901 0.0.0.0:* users:((\"Xvnc\",pid=1,fd=1))\n" ++
        "LISTEN 0 128 0.0.0.0:5901 0.0.0.0:*\n";
    var result = parseProbeOutput(allocator, text);
    defer result.deinit(allocator);
    try std.testing.expect(!result.x11vnc);
    try std.testing.expect(!result.tigervnc);
    try std.testing.expectEqual(@as(usize, 1), result.listening.len);
}

test "setup plan: alpine gets apk, debian gets apt, unknown gets manual, installed short-circuits" {
    const allocator = std.testing.allocator;
    const alpine_os = "NAME=\"Alpine Linux\"\nID=alpine\n";
    var alpine_plan = setupPlan(allocator, alpine_os, 1, false);
    defer alpine_plan.deinit(allocator);
    try std.testing.expectEqualStrings("install", alpine_plan.action);
    try std.testing.expectEqualStrings("apk add --no-cache x11vnc xvfb", alpine_plan.plan);
    try std.testing.expect(std.mem.indexOf(u8, alpine_plan.hint, "-rfbport 5901") != null);
    try std.testing.expect(std.mem.indexOf(u8, alpine_plan.hint, "-passwd") != null);
    try std.testing.expect(std.mem.indexOf(u8, alpine_plan.hint, "-nopw") == null);

    const debian_os = "PRETTY_NAME=\"Debian GNU/Linux 12\"\nID=debian\n";
    var deb_plan = setupPlan(allocator, debian_os, 0, false);
    defer deb_plan.deinit(allocator);
    try std.testing.expectEqualStrings("apt-get update && apt-get install -y x11vnc xvfb", deb_plan.plan);
    try std.testing.expect(std.mem.indexOf(u8, deb_plan.hint, "-rfbport 5900") != null);

    var unknown_plan = setupPlan(allocator, "ID=nixos\n", 0, false);
    defer unknown_plan.deinit(allocator);
    try std.testing.expectEqualStrings("manual", unknown_plan.action);
    try std.testing.expectEqualStrings("", unknown_plan.plan);

    var installed_plan = setupPlan(allocator, "ID=alpine\n", 0, true);
    defer installed_plan.deinit(allocator);
    try std.testing.expectEqualStrings("already_installed", installed_plan.action);
}
