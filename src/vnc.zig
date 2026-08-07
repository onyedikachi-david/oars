//! VNC helpers (spec 12): the probe command + parser and the setup
//! helper's OS-adapter plan. Pure logic over exec output — the bridge
//! handler runs the command and feeds the output here.

const std = @import("std");

pub fn probeCommand(allocator: std.mem.Allocator, display: u16) ![]u8 {
    if (display > max_setup_display) return error.InvalidDisplay;
    return std.fmt.allocPrint(
        allocator,
        "printf '%%BEGIN_VNC_PROBE%%\\n'; command -v x11vnc >/dev/null 2>&1; echo x11vnc=$?; " ++
            "command -v tigervncserver >/dev/null 2>&1; echo tigervnc=$?; " ++
            "command -v Xvnc >/dev/null 2>&1; echo xvnc=$?; " ++
            "if command -v startxfce4 >/dev/null 2>&1 && command -v dbus-run-session >/dev/null 2>&1 && command -v xprop >/dev/null 2>&1; then xfce_status=0; else xfce_status=1; fi; echo xfce=$xfce_status; " ++
            "command -v gnome-session >/dev/null 2>&1; echo gnome=$?; " ++
            "command -v startplasma-x11 >/dev/null 2>&1; echo plasma=$?; " ++
            "command -v mate-session >/dev/null 2>&1; echo mate=$?; " ++
            "command -v startlxqt >/dev/null 2>&1; echo lxqt=$?; " ++
            "vnc_display=:{d}; xfce_window_present() {{ class=$1; " ++
            "windows=$(DISPLAY=$vnc_display xprop -root _NET_CLIENT_LIST 2>/dev/null | sed -n 's/.*# //p' | tr -d ','); " ++
            "for window in $windows; do DISPLAY=$vnc_display xprop -id $window WM_CLASS 2>/dev/null | grep -Fq $class && return 0; done; return 1; }}; " ++
            "window_manager_present() {{ wm_result=$(DISPLAY=$vnc_display xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null) || return 1; case \"$wm_result\" in *'window id #'*) return 0 ;; *) return 1 ;; esac; }}; " ++
            "wm_window=''; if command -v xprop >/dev/null 2>&1 && window_manager_present; " ++
            "then wm_status=0; wm_window=$(printf '%s\\n' \"$wm_result\" | sed -n 's/.*# //p'); else wm_status=1; fi; echo window_manager_running=$wm_status; " ++
            "if xfce_window_present xfdesktop; then surface_status=0; else surface_status=1; fi; echo desktop_surface_running=$surface_status; " ++
            "if xfce_window_present xfce4-panel; then panel_status=0; else panel_status=1; fi; echo desktop_panel_running=$panel_status; " ++
            "xfce_wm_status=1; if [ -n \"$wm_window\" ] && DISPLAY=$vnc_display xprop -id \"$wm_window\" WM_CLASS 2>/dev/null | grep -Fq xfwm4; then xfce_wm_status=0; fi; " ++
            "desktop_status=1; if [ \"$wm_status\" -eq 0 ]; then if [ \"$xfce_wm_status\" -ne 0 ] || {{ [ \"$surface_status\" -eq 0 ] && [ \"$panel_status\" -eq 0 ]; }}; then desktop_status=0; fi; fi; echo desktop_running=$desktop_status; " ++
            "setup_state=idle; setup_dir=\"$HOME/.local/share/oars/vnc\"; " ++
            "setup_status=\"$setup_dir/setup.status\"; setup_pid=\"$setup_dir/setup.pid\"; " ++
            "if [ -r \"$setup_status\" ]; then IFS= read -r setup_state <\"$setup_status\" || setup_state=idle; fi; " ++
            "if [ \"$setup_state\" = installing ]; then setup_process=''; " ++
            "if [ -r \"$setup_pid\" ]; then IFS= read -r setup_process <\"$setup_pid\" || setup_process=''; fi; " ++
            "case \"$setup_process\" in ''|*[!0-9]*) setup_state=failed ;; *) kill -0 \"$setup_process\" 2>/dev/null || setup_state=failed ;; esac; fi; " ++
            "case \"$setup_state\" in installing|installed|ready|failed) ;; *) setup_state=idle ;; esac; " ++
            "echo setup_state=$setup_state; " ++
            "(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || netstat -tln 2>/dev/null || true)",
        .{display},
    );
}

pub const ListeningPort = struct {
    port: u16,
    /// Process name when the listener reports one (views the output).
    process: []const u8 = "",
};

pub const ProbeResult = struct {
    x11vnc: bool = false,
    tigervnc: bool = false,
    xfce_ready: bool = false,
    desktop_installed: bool = false,
    window_manager_running: bool = false,
    desktop_surface_running: bool = false,
    desktop_panel_running: bool = false,
    desktop_running: bool = false,
    desktop_name: []const u8 = "",
    setup_state: []const u8 = "idle",
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
    var xfce = false;
    var gnome = false;
    var plasma = false;
    var mate = false;
    var lxqt = false;

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
        } else if (std.mem.startsWith(u8, line, "xfce=")) {
            xfce = line["xfce=".len..].len == 1 and line["xfce=".len..][0] == '0';
        } else if (std.mem.startsWith(u8, line, "gnome=")) {
            gnome = line["gnome=".len..].len == 1 and line["gnome=".len..][0] == '0';
        } else if (std.mem.startsWith(u8, line, "plasma=")) {
            plasma = line["plasma=".len..].len == 1 and line["plasma=".len..][0] == '0';
        } else if (std.mem.startsWith(u8, line, "mate=")) {
            mate = line["mate=".len..].len == 1 and line["mate=".len..][0] == '0';
        } else if (std.mem.startsWith(u8, line, "lxqt=")) {
            lxqt = line["lxqt=".len..].len == 1 and line["lxqt=".len..][0] == '0';
        } else if (std.mem.startsWith(u8, line, "desktop_running=")) {
            result.desktop_running = line["desktop_running=".len..].len == 1 and line["desktop_running=".len..][0] == '0';
        } else if (std.mem.startsWith(u8, line, "window_manager_running=")) {
            result.window_manager_running = line["window_manager_running=".len..].len == 1 and line["window_manager_running=".len..][0] == '0';
        } else if (std.mem.startsWith(u8, line, "desktop_surface_running=")) {
            result.desktop_surface_running = line["desktop_surface_running=".len..].len == 1 and line["desktop_surface_running=".len..][0] == '0';
        } else if (std.mem.startsWith(u8, line, "desktop_panel_running=")) {
            result.desktop_panel_running = line["desktop_panel_running=".len..].len == 1 and line["desktop_panel_running=".len..][0] == '0';
        } else if (std.mem.startsWith(u8, line, "setup_state=")) {
            const state = line["setup_state=".len..];
            result.setup_state = if (std.mem.eql(u8, state, "installing"))
                "installing"
            else if (std.mem.eql(u8, state, "installed"))
                "installed"
            else if (std.mem.eql(u8, state, "ready"))
                "ready"
            else if (std.mem.eql(u8, state, "failed"))
                "failed"
            else
                "idle";
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
    result.xfce_ready = xfce;
    result.desktop_installed = xfce or gnome or plasma or mate or lxqt or result.desktop_running;
    result.desktop_name = if (xfce)
        "XFCE"
    else if (gnome)
        "GNOME"
    else if (plasma)
        "KDE Plasma"
    else if (mate)
        "MATE"
    else if (lxqt)
        "LXQt"
    else if (result.desktop_running)
        "Desktop"
    else
        "";
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
    /// install | configure | manual
    action: []const u8,
    /// The exact package-install command (empty for manual/configure).
    plan: []const u8,
    /// Password-free command preview shown in the approval dialog.
    hint: []const u8,
    /// none | install | start | running | manual
    desktop_action: []const u8,
    desktop_name: []const u8,

    pub fn deinit(self: *SetupPlan, allocator: std.mem.Allocator) void {
        if (self.action.len > 0) allocator.free(self.action);
        if (self.plan.len > 0) allocator.free(self.plan);
        if (self.hint.len > 0) allocator.free(self.hint);
        if (self.desktop_action.len > 0) allocator.free(self.desktop_action);
        if (self.desktop_name.len > 0) allocator.free(self.desktop_name);
    }
};

pub const max_setup_display: u16 = 99;

pub fn installStartCommand(allocator: std.mem.Allocator, display: u16, plan: []const u8) ![]u8 {
    if (display > max_setup_display) return error.InvalidDisplay;
    if (plan.len == 0 or std.mem.indexOfAny(u8, plan, "'\r\n") != null) return error.InvalidInstallPlan;
    return std.fmt.allocPrint(
        allocator,
        "set -eu; umask 077; setup_dir=\"$HOME/.local/share/oars/vnc\"; " ++
            "status_file=\"$setup_dir/setup.status\"; log_file=\"$setup_dir/setup.install.log\"; " ++
            "pid_file=\"$setup_dir/setup.pid\"; mkdir -p \"$setup_dir\"; chmod 700 \"$setup_dir\"; " ++
            "if [ -r \"$status_file\" ] && [ -r \"$pid_file\" ]; then state=''; pid=''; " ++
            "IFS= read -r state <\"$status_file\" || state=''; IFS= read -r pid <\"$pid_file\" || pid=''; " ++
            "case \"$pid\" in ''|*[!0-9]*) ;; *) if [ \"$state\" = installing ] && kill -0 \"$pid\" 2>/dev/null; then exit 0; fi ;; esac; fi; " ++
            "printf 'installing\\n' >\"$status_file\"; : >\"$log_file\"; chmod 600 \"$status_file\" \"$log_file\"; " ++
            "setsid sh -c '{s}; code=$?; if [ \"$code\" -eq 0 ]; then printf \"installed\\n\" >\"$1\"; " ++
            "else printf \"failed\\n\" >\"$1\"; fi; exit \"$code\"' sh \"$status_file\" " ++
            "</dev/null >\"$log_file\" 2>&1 & printf '%s\\n' \"$!\" >\"$pid_file\"; chmod 600 \"$pid_file\"",
        .{plan},
    );
}

pub fn installWaitCommand(allocator: std.mem.Allocator, display: u16) ![]u8 {
    if (display > max_setup_display) return error.InvalidDisplay;
    return std.fmt.allocPrint(
        allocator,
        "set -u; setup_dir=\"$HOME/.local/share/oars/vnc\"; status_file=\"$setup_dir/setup.status\"; " ++
            "log_file=\"$setup_dir/setup.install.log\"; pid_file=\"$setup_dir/setup.pid\"; " ++
            "while :; do state=idle; [ ! -r \"$status_file\" ] || IFS= read -r state <\"$status_file\" || state=idle; " ++
            "case \"$state\" in installed|ready) printf 'setup_state=%s\\n' \"$state\"; exit 0 ;; " ++
            "failed) printf 'setup_state=failed\\n'; tail -n 24 \"$log_file\" 2>/dev/null || true; exit 1 ;; " ++
            "installing) pid=''; [ ! -r \"$pid_file\" ] || IFS= read -r pid <\"$pid_file\" || pid=''; " ++
            "case \"$pid\" in ''|*[!0-9]*) alive=0 ;; *) if kill -0 \"$pid\" 2>/dev/null; then alive=1; else alive=0; fi ;; esac; " ++
            "if [ \"$alive\" -eq 0 ]; then printf 'failed\\n' >\"$status_file\"; continue; fi ;; " ++
            "*) printf 'setup state is unavailable\\n'; exit 1 ;; esac; sleep 2; done",
        .{},
    );
}

pub fn setupStateCommand(allocator: std.mem.Allocator, display: u16, state: []const u8) ![]u8 {
    if (display > max_setup_display) return error.InvalidDisplay;
    if (!std.mem.eql(u8, state, "ready") and !std.mem.eql(u8, state, "failed")) return error.InvalidSetupState;
    return std.fmt.allocPrint(
        allocator,
        "set -eu; umask 077; setup_dir=\"$HOME/.local/share/oars/vnc\"; mkdir -p \"$setup_dir\"; chmod 700 \"$setup_dir\"; printf '{s}\\n' >\"$setup_dir/setup.status\"",
        .{state},
    );
}

fn startHint(allocator: std.mem.Allocator, display: u16, start_desktop: bool) []const u8 {
    const port: u32 = 5900 + @as(u32, display);
    if (start_desktop) {
        return std.fmt.allocPrint(
            allocator,
            "x11vnc -storepasswd $HOME/.local/share/oars/vnc/display-{d}.passwd; " ++
                "DISPLAY=:{d} dbus-run-session -- startxfce4; " ++
                "x11vnc -display :{d} -rfbport {d} -localhost -forever -shared " ++
                "-rfbauth $HOME/.local/share/oars/vnc/display-{d}.passwd",
            .{ display, display, display, port, display },
        ) catch "";
    }
    return std.fmt.allocPrint(allocator, "x11vnc -storepasswd $HOME/.local/share/oars/vnc/display-{d}.passwd; x11vnc -display :{d} -rfbport {d} -localhost -forever -shared -rfbauth $HOME/.local/share/oars/vnc/display-{d}.passwd", .{ display, display, port, display }) catch "";
}

fn desktopStartClause(allocator: std.mem.Allocator, display: u16) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "desktop_pid_file=\"$auth_dir/display-{d}.xfce.pid\"; desktop_log=\"$auth_dir/display-{d}.xfce.log\"; " ++
            "component_pid_file=\"$auth_dir/display-{d}.xfce-components.pid\"; runtime_dir=\"$auth_dir/runtime-{d}\"; vnc_display=:{d}; " ++
            "if ! command -v startxfce4 >/dev/null 2>&1 || ! command -v dbus-run-session >/dev/null 2>&1 || ! command -v xprop >/dev/null 2>&1; " ++
            "then printf 'XFCE desktop packages are not installed\\n'; exit 1; fi; " ++
            "xfce_window_present() {{ class=$1; windows=$(DISPLAY=$vnc_display xprop -root _NET_CLIENT_LIST 2>/dev/null | sed -n 's/.*# //p' | tr -d ','); " ++
            "for window in $windows; do DISPLAY=$vnc_display xprop -id $window WM_CLASS 2>/dev/null | grep -Fq $class && return 0; done; return 1; }}; " ++
            "window_manager_present() {{ wm_result=$(DISPLAY=$vnc_display xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null) || return 1; case \"$wm_result\" in *'window id #'*) return 0 ;; *) return 1 ;; esac; }}; " ++
            "xfce_desktop_ready() {{ window_manager_present && xfce_window_present xfdesktop && xfce_window_present xfce4-panel; }}; " ++
            "start_xfce_components() {{ window_manager_present || return 1; wm_window=$(printf '%s\\n' \"$wm_result\" | sed -n 's/.*# //p'); " ++
            "wm_pid=''; [ -z \"$wm_window\" ] || wm_pid=$(DISPLAY=$vnc_display xprop -id \"$wm_window\" _NET_WM_PID 2>/dev/null | sed -n 's/.*= //p'); " ++
            "dbus_address=''; wm_runtime=''; case \"$wm_pid\" in ''|*[!0-9]*) ;; *) if [ -r \"/proc/$wm_pid/environ\" ]; then " ++
            "dbus_address=$(tr '\\0' '\\n' <\"/proc/$wm_pid/environ\" | sed -n 's/^DBUS_SESSION_BUS_ADDRESS=//p'); " ++
            "wm_runtime=$(tr '\\0' '\\n' <\"/proc/$wm_pid/environ\" | sed -n 's/^XDG_RUNTIME_DIR=//p'); fi ;; esac; " ++
            "[ -z \"$wm_runtime\" ] || runtime_dir=$wm_runtime; " ++
            "if [ -n \"$dbus_address\" ]; then setsid env DISPLAY=$vnc_display XDG_RUNTIME_DIR=\"$runtime_dir\" DBUS_SESSION_BUS_ADDRESS=\"$dbus_address\" " ++
            "sh -c 'xfdesktop >>\"$1\" 2>&1 & xfce4-panel >>\"$1\" 2>&1 & wait' sh \"$desktop_log\" </dev/null >/dev/null 2>&1 & " ++
            "else setsid env DISPLAY=$vnc_display XDG_RUNTIME_DIR=\"$runtime_dir\" dbus-run-session -- " ++
            "sh -c 'xfdesktop >>\"$1\" 2>&1 & xfce4-panel >>\"$1\" 2>&1 & wait' sh \"$desktop_log\" </dev/null >/dev/null 2>&1 & fi; " ++
            "printf '%s\\n' \"$!\" >\"$component_pid_file\"; }}; " ++
            "mkdir -p \"$runtime_dir\"; chmod 700 \"$runtime_dir\"; : >\"$desktop_log\"; chmod 600 \"$desktop_log\"; " ++
            "if ! window_manager_present; then " ++
            "if [ -f \"$desktop_pid_file\" ]; then desktop_pid=$(cat \"$desktop_pid_file\" 2>/dev/null || true); " ++
            "case \"$desktop_pid\" in ''|*[!0-9]*) ;; *) if kill -0 \"$desktop_pid\" 2>/dev/null; then kill \"$desktop_pid\" 2>/dev/null || true; sleep 1; fi ;; esac; fi; " ++
            "dbus-uuidgen --ensure >/dev/null 2>&1 || true; " ++
            "setsid env DISPLAY=$vnc_display XDG_RUNTIME_DIR=\"$runtime_dir\" dbus-run-session -- startxfce4 </dev/null >>\"$desktop_log\" 2>&1 & " ++
            "desktop_pid=$!; printf '%s\\n' \"$desktop_pid\" >\"$desktop_pid_file\"; fi; " ++
            "i=0; components_started=0; while ! xfce_desktop_ready && [ \"$i\" -lt 60 ]; do " ++
            "if [ \"$components_started\" -eq 0 ] && [ \"$i\" -ge 10 ] && window_manager_present; then " ++
            "start_xfce_components; components_started=1; fi; sleep 1; i=$((i + 1)); done; " ++
            "if ! xfce_desktop_ready; then printf 'XFCE failed to become usable on display :{d}; missing:'; " ++
            "window_manager_present || printf ' window-manager'; " ++
            "xfce_window_present xfdesktop || printf ' desktop'; xfce_window_present xfce4-panel || printf ' panel'; printf '\\n'; " ++
            "tail -n 24 \"$desktop_log\" 2>/dev/null || true; exit 1; fi; ",
        .{ display, display, display, display, display, display },
    );
}

/// Builds the fixed server-side command. The password arrives through stdin
/// and never appears in this command or in the remote process arguments.
pub fn secureStartCommand(allocator: std.mem.Allocator, display: u16, start_desktop: bool) ![]u8 {
    if (display > max_setup_display) return error.InvalidDisplay;
    const port: u32 = 5900 + @as(u32, display);
    const desktop_clause = if (start_desktop) try desktopStartClause(allocator, display) else "";
    defer if (desktop_clause.len > 0) allocator.free(desktop_clause);
    return std.fmt.allocPrint(
        allocator,
        "set -eu; umask 077; " ++
            "auth_dir=\"$HOME/.local/share/oars/vnc\"; " ++
            "auth_file=\"$auth_dir/display-{d}.passwd\"; pid_file=\"$auth_dir/display-{d}.pid\"; " ++
            "ready_file=\"$auth_dir/display-{d}.ready\"; log_file=\"$auth_dir/display-{d}.log\"; " ++
            "xvfb_pid_file=\"$auth_dir/display-{d}.xvfb.pid\"; xvfb_log=\"$auth_dir/display-{d}.xvfb.log\"; " ++
            "mkdir -p \"$auth_dir\"; chmod 700 \"$auth_dir\"; " ++
            "x11vnc -storepasswd \"$auth_file\" >/dev/null 2>&1; chmod 600 \"$auth_file\"; " ++
            "if [ -f \"$pid_file\" ]; then pid=$(cat \"$pid_file\" 2>/dev/null || true); " ++
            "case \"$pid\" in ''|*[!0-9]*) ;; *) " ++
            "if kill -0 \"$pid\" 2>/dev/null && [ \"$(cat \"/proc/$pid/comm\" 2>/dev/null || true)\" = x11vnc ]; " ++
            "then kill \"$pid\"; sleep 1; fi ;; esac; rm -f \"$pid_file\"; fi; " ++
            "oars_xvfb=0; if [ -f \"$xvfb_pid_file\" ]; then xvfb_pid=$(cat \"$xvfb_pid_file\" 2>/dev/null || true); " ++
            "case \"$xvfb_pid\" in ''|*[!0-9]*) ;; *) if kill -0 \"$xvfb_pid\" 2>/dev/null && " ++
            "[ \"$(cat \"/proc/$xvfb_pid/comm\" 2>/dev/null || true)\" = Xvfb ]; then oars_xvfb=1; fi ;; esac; fi; " ++
            "if [ ! -S /tmp/.X11-unix/X{d} ]; then : >\"$xvfb_log\"; chmod 600 \"$xvfb_log\"; " ++
            "setsid Xvfb :{d} -screen 0 1280x800x24 -nolisten tcp </dev/null >\"$xvfb_log\" 2>&1 & " ++
            "xvfb_pid=$!; printf '%s\\n' \"$xvfb_pid\" >\"$xvfb_pid_file\"; oars_xvfb=1; i=0; " ++
            "while [ ! -S /tmp/.X11-unix/X{d} ] && [ \"$i\" -lt 5 ]; do " ++
            "if ! kill -0 \"$xvfb_pid\" 2>/dev/null; then break; fi; sleep 1; i=$((i + 1)); done; " ++
            "if [ ! -S /tmp/.X11-unix/X{d} ]; then printf 'Xvfb failed to open display :{d}\\n'; " ++
            "tail -n 8 \"$xvfb_log\" 2>/dev/null || true; exit 1; fi; fi; " ++
            "{s}" ++
            "auth_args=''; if [ \"$oars_xvfb\" -eq 0 ]; then auth_args='-auth guess'; fi; " ++
            ": >\"$log_file\"; chmod 600 \"$log_file\"; rm -f \"$ready_file\"; " ++
            "setsid x11vnc -norc -display :{d} $auth_args -rfbport {d} -localhost -forever -shared " ++
            "-rfbauth \"$auth_file\" -flag \"$ready_file\" -o \"$log_file\" </dev/null >/dev/null 2>&1 & " ++
            "pid=$!; printf '%s\\n' \"$pid\" >\"$pid_file\"; i=0; " ++
            "while [ ! -s \"$ready_file\" ] && [ \"$i\" -lt 10 ]; do " ++
            "if ! kill -0 \"$pid\" 2>/dev/null; then break; fi; sleep 1; i=$((i + 1)); done; " ++
            "if [ ! -s \"$ready_file\" ] || ! kill -0 \"$pid\" 2>/dev/null; then " ++
            "printf 'x11vnc failed to open port {d} for display :{d}\\n'; " ++
            "tail -n 12 \"$log_file\" 2>/dev/null || true; kill \"$pid\" 2>/dev/null || true; " ++
            "rm -f \"$pid_file\" \"$ready_file\"; exit 1; fi",
        .{ display, display, display, display, display, display, display, display, display, display, display, desktop_clause, display, port, port, display },
    );
}

/// The tested OS adapter (spec 12 §5): Alpine and Debian/Ubuntu get an exact
/// install command; anything else gets manual guidance. Installed x11vnc can
/// still be configured and restarted with a new password.
pub fn setupPlan(
    allocator: std.mem.Allocator,
    os_release: []const u8,
    display: u16,
    x11vnc_installed: bool,
    xfce_ready: bool,
    desktop_running: bool,
    install_desktop: bool,
) SetupPlan {
    if (display > max_setup_display) {
        return .{
            .action = allocator.dupe(u8, "manual") catch "",
            .plan = "",
            .hint = allocator.dupe(u8, "choose a display between :0 and :99") catch "",
            .desktop_action = allocator.dupe(u8, "manual") catch "",
            .desktop_name = "",
        };
    }
    const os_id = osReleaseValue(os_release, "ID") orelse "";
    const os_like = osReleaseValue(os_release, "ID_LIKE") orelse "";
    const alpine = std.mem.eql(u8, os_id, "alpine") or osReleaseListContains(os_like, "alpine");
    const debian = std.mem.eql(u8, os_id, "debian") or std.mem.eql(u8, os_id, "ubuntu") or osReleaseListContains(os_like, "debian") or osReleaseListContains(os_like, "ubuntu");
    const needs_vnc = !x11vnc_installed;
    const needs_xfce = install_desktop and !desktop_running and !xfce_ready;
    const start_desktop = install_desktop and !desktop_running;
    const hint = startHint(allocator, display, start_desktop);
    defer if (hint.len > 0) allocator.free(hint);
    const desktop_action = if (!install_desktop)
        "none"
    else if (desktop_running)
        "running"
    else if (needs_xfce)
        "install"
    else
        "start";

    if (!needs_vnc and !needs_xfce) {
        return .{
            .action = allocator.dupe(u8, "configure") catch "",
            .plan = "",
            .hint = allocator.dupe(u8, hint) catch "",
            .desktop_action = allocator.dupe(u8, desktop_action) catch "",
            .desktop_name = if (install_desktop) allocator.dupe(u8, "XFCE") catch "" else "",
        };
    }
    if (alpine or debian) {
        const plan = if (alpine)
            if (needs_vnc and needs_xfce)
                "apk add --no-cache x11vnc xvfb xfce4 dbus xprop"
            else if (needs_xfce)
                "apk add --no-cache xfce4 dbus xprop"
            else
                "apk add --no-cache x11vnc xvfb"
        else if (needs_vnc and needs_xfce)
            "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y x11vnc xvfb xfce4 dbus-x11 x11-utils"
        else if (needs_xfce)
            "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y xfce4 dbus-x11 x11-utils"
        else
            "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y x11vnc xvfb";
        return .{
            .action = allocator.dupe(u8, "install") catch "",
            .plan = allocator.dupe(u8, plan) catch "",
            .hint = allocator.dupe(u8, hint) catch "",
            .desktop_action = allocator.dupe(u8, desktop_action) catch "",
            .desktop_name = if (install_desktop) allocator.dupe(u8, "XFCE") catch "" else "",
        };
    }
    return .{
        .action = allocator.dupe(u8, "manual") catch "",
        .plan = "",
        .hint = allocator.dupe(u8, if (install_desktop)
            "install x11vnc, Xvfb, XFCE, D-Bus, and xprop for this distribution; then start XFCE on the selected display and bind x11vnc to remote loopback"
        else
            "install x11vnc for your distribution, then start it bound to remote loopback with a password") catch "",
        .desktop_action = allocator.dupe(u8, "manual") catch "",
        .desktop_name = if (install_desktop) allocator.dupe(u8, "XFCE") catch "" else "",
    };
}

fn osReleaseValue(text: []const u8, key: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        if (!std.mem.eql(u8, line[0..eq], key)) continue;
        var value = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (value.len >= 2 and ((value[0] == '"' and value[value.len - 1] == '"') or (value[0] == '\'' and value[value.len - 1] == '\''))) {
            value = value[1 .. value.len - 1];
        }
        return value;
    }
    return null;
}

fn osReleaseListContains(value: []const u8, needle: []const u8) bool {
    var values = std.mem.tokenizeAny(u8, value, " \t");
    while (values.next()) |item| if (std.mem.eql(u8, item, needle)) return true;
    return false;
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
        "xfce=0\n" ++
        "gnome=1\n" ++
        "plasma=1\n" ++
        "mate=1\n" ++
        "lxqt=1\n" ++
        "window_manager_running=0\n" ++
        "desktop_surface_running=0\n" ++
        "desktop_panel_running=0\n" ++
        "desktop_running=0\n" ++
        "setup_state=installing\n" ++
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
    try std.testing.expect(result.xfce_ready);
    try std.testing.expect(result.desktop_installed);
    try std.testing.expect(result.window_manager_running);
    try std.testing.expect(result.desktop_surface_running);
    try std.testing.expect(result.desktop_panel_running);
    try std.testing.expect(result.desktop_running);
    try std.testing.expectEqualStrings("XFCE", result.desktop_name);
    try std.testing.expectEqualStrings("installing", result.setup_state);
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
        "xfce=1\n" ++
        "gnome=1\n" ++
        "plasma=1\n" ++
        "mate=1\n" ++
        "lxqt=1\n" ++
        "desktop_running=1\n" ++
        "LISTEN 0 128 127.0.0.1:5901 0.0.0.0:* users:((\"Xvnc\",pid=1,fd=1))\n" ++
        "LISTEN 0 128 0.0.0.0:5901 0.0.0.0:*\n";
    var result = parseProbeOutput(allocator, text);
    defer result.deinit(allocator);
    try std.testing.expect(!result.x11vnc);
    try std.testing.expect(!result.tigervnc);
    try std.testing.expect(!result.desktop_installed);
    try std.testing.expect(!result.desktop_running);
    try std.testing.expectEqual(@as(usize, 1), result.listening.len);
}

test "setup plan: supported systems install, unknown is manual, installed configures" {
    const allocator = std.testing.allocator;
    const alpine_os = "NAME=\"Alpine Linux\"\nID=alpine\n";
    var alpine_plan = setupPlan(allocator, alpine_os, 1, false, false, false, false);
    defer alpine_plan.deinit(allocator);
    try std.testing.expectEqualStrings("install", alpine_plan.action);
    try std.testing.expectEqualStrings("apk add --no-cache x11vnc xvfb", alpine_plan.plan);
    try std.testing.expect(std.mem.indexOf(u8, alpine_plan.hint, "-rfbport 5901") != null);
    try std.testing.expect(std.mem.indexOf(u8, alpine_plan.hint, "-storepasswd") != null);
    try std.testing.expect(std.mem.indexOf(u8, alpine_plan.hint, "-localhost") != null);
    try std.testing.expect(std.mem.indexOf(u8, alpine_plan.hint, "-rfbauth") != null);
    try std.testing.expect(std.mem.indexOf(u8, alpine_plan.hint, "-nopw") == null);

    const debian_os = "PRETTY_NAME=\"Debian GNU/Linux 12\"\nID=debian\n";
    var deb_plan = setupPlan(allocator, debian_os, 0, false, false, false, false);
    defer deb_plan.deinit(allocator);
    try std.testing.expectEqualStrings("apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y x11vnc xvfb", deb_plan.plan);
    try std.testing.expect(std.mem.indexOf(u8, deb_plan.hint, "-rfbport 5900") != null);

    var unknown_plan = setupPlan(allocator, "ID=nixos\n", 0, false, false, false, false);
    defer unknown_plan.deinit(allocator);
    try std.testing.expectEqualStrings("manual", unknown_plan.action);
    try std.testing.expectEqualStrings("", unknown_plan.plan);

    var installed_plan = setupPlan(allocator, "ID=alpine\n", 0, true, false, false, false);
    defer installed_plan.deinit(allocator);
    try std.testing.expectEqualStrings("configure", installed_plan.action);
    try std.testing.expectEqualStrings("", installed_plan.plan);
    try std.testing.expect(std.mem.indexOf(u8, installed_plan.hint, "-rfbauth") != null);
}

test "setup plan installs or starts an explicit XFCE desktop" {
    const allocator = std.testing.allocator;
    const ubuntu_os = "NAME=Ubuntu\nID=ubuntu\n";
    var install = setupPlan(allocator, ubuntu_os, 0, true, false, false, true);
    defer install.deinit(allocator);
    try std.testing.expectEqualStrings("install", install.action);
    try std.testing.expectEqualStrings("install", install.desktop_action);
    try std.testing.expectEqualStrings("XFCE", install.desktop_name);
    try std.testing.expect(std.mem.indexOf(u8, install.plan, "xfce4 dbus-x11 x11-utils") != null);
    try std.testing.expect(std.mem.indexOf(u8, install.hint, "startxfce4") != null);

    var start = setupPlan(allocator, ubuntu_os, 0, true, true, false, true);
    defer start.deinit(allocator);
    try std.testing.expectEqualStrings("configure", start.action);
    try std.testing.expectEqualStrings("start", start.desktop_action);
    try std.testing.expectEqualStrings("", start.plan);

    var running = setupPlan(allocator, ubuntu_os, 0, true, false, true, true);
    defer running.deinit(allocator);
    try std.testing.expectEqualStrings("running", running.desktop_action);
    try std.testing.expect(std.mem.indexOf(u8, running.hint, "startxfce4") == null);
}

test "setup plan accepts quoted Ubuntu IDs and Debian-like derivatives" {
    const allocator = std.testing.allocator;
    var quoted = setupPlan(allocator, "NAME=Ubuntu\nID=\"ubuntu\"\n", 1, false, false, false, true);
    defer quoted.deinit(allocator);
    try std.testing.expectEqualStrings("install", quoted.action);
    try std.testing.expect(std.mem.indexOf(u8, quoted.plan, "apt-get") != null);

    var derivative = setupPlan(allocator, "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n", 1, false, false, false, true);
    defer derivative.deinit(allocator);
    try std.testing.expectEqualStrings("install", derivative.action);
    try std.testing.expect(std.mem.indexOf(u8, derivative.plan, "xfce4") != null);
}

test "detached package install lifecycle commands are valid POSIX shell" {
    const allocator = std.testing.allocator;
    const start = try installStartCommand(allocator, 1, "apt-get update && apt-get install -y xfce4");
    defer allocator.free(start);
    const wait = try installWaitCommand(allocator, 1);
    defer allocator.free(wait);
    const ready = try setupStateCommand(allocator, 1, "ready");
    defer allocator.free(ready);
    for ([_][]const u8{ start, wait, ready }) |command| {
        const result = try std.process.run(allocator, std.testing.io, .{ .argv = &.{ "/bin/sh", "-n", "-c", command } });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        if (result.term != .exited or result.term.exited != 0) std.debug.print("VNC install shell error: {s}\n", .{result.stderr});
        try std.testing.expect(result.term == .exited and result.term.exited == 0);
    }
    try std.testing.expectError(error.InvalidInstallPlan, installStartCommand(allocator, 1, "apt-get install 'xfce4'"));
    try std.testing.expectError(error.InvalidSetupState, setupStateCommand(allocator, 1, "installing"));
}

test "secure start command uses stdin auth and loopback only" {
    const command = try secureStartCommand(std.testing.allocator, 1, false);
    defer std.testing.allocator.free(command);
    try std.testing.expect(std.mem.indexOf(u8, command, "x11vnc -storepasswd \"$auth_file\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, command, "-localhost") != null);
    try std.testing.expect(std.mem.indexOf(u8, command, "-rfbauth \"$auth_file\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, command, "-pidfile") == null);
    try std.testing.expect(std.mem.indexOf(u8, command, "-flag \"$ready_file\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, command, "pid=$!") != null);
    try std.testing.expect(std.mem.indexOf(u8, command, "-norc") != null);
    try std.testing.expect(std.mem.indexOf(u8, command, "-passwd ") == null);
    try std.testing.expect(std.mem.indexOf(u8, command, "-rfbport 5901") != null);
    try std.testing.expect(std.mem.indexOf(u8, command, "startxfce4") == null);
    try std.testing.expectError(error.InvalidDisplay, secureStartCommand(std.testing.allocator, 100, false));
}

test "secure start command is valid POSIX shell" {
    const command = try secureStartCommand(std.testing.allocator, 1, true);
    defer std.testing.allocator.free(command);
    try std.testing.expect(std.mem.indexOf(u8, command, "dbus-run-session -- startxfce4") != null);
    try std.testing.expect(std.mem.indexOf(u8, command, "_NET_SUPPORTING_WM_CHECK") != null);
    const result = try std.process.run(std.testing.allocator, std.testing.io, .{
        .argv = &.{ "/bin/sh", "-n", "-c", command },
    });
    defer std.testing.allocator.free(result.stdout);
    defer std.testing.allocator.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) std.debug.print("VNC shell error: {s}\n", .{result.stderr});
    try std.testing.expect(result.term == .exited and result.term.exited == 0);
}

test "desktop-aware probe command is valid POSIX shell" {
    const command = try probeCommand(std.testing.allocator, 1);
    defer std.testing.allocator.free(command);
    try std.testing.expect(std.mem.indexOf(u8, command, "vnc_display=:1") != null);
    try std.testing.expect(std.mem.indexOf(u8, command, "xfce_window_present xfdesktop") != null);
    try std.testing.expect(std.mem.indexOf(u8, command, "xfce_window_present xfce4-panel") != null);
    const result = try std.process.run(std.testing.allocator, std.testing.io, .{
        .argv = &.{ "/bin/sh", "-n", "-c", command },
    });
    defer std.testing.allocator.free(result.stdout);
    defer std.testing.allocator.free(result.stderr);
    try std.testing.expect(result.term == .exited and result.term.exited == 0);
}
