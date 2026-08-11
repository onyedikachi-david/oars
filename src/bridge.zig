//! Bridge command handlers for Oars.
//!
//! All `oars.*` commands are policy-gated by origin (`zero://app` in
//! production, the Vite dev server origin in development). Handlers run
//! on the runtime's main thread and never block on the network; the
//! session manager owns all SSH worker threads.

const std = @import("std");
const native_sdk = @import("native_sdk");
const servers = @import("servers.zig");
const sessions = @import("sessions.zig");
const monitor = @import("monitor.zig");
const history = @import("history.zig");
const json = @import("json.zig");
const logs = @import("logs.zig");
const localfs = @import("localfs.zig");
const shellquote = @import("shellquote.zig");
const sftpmod = @import("sftp.zig");
const scripts = @import("scripts.zig");
const ai = @import("ai.zig");
const vncmod = @import("vnc.zig");
const broadcast = @import("broadcast.zig");
const deploy = @import("deploy.zig");
const sshkeys = @import("sshkeys.zig");
const keygen = @import("keygen.zig");
const access = @import("access.zig");
const backup = @import("backup.zig");
const vault = @import("vault.zig");
const agent = @import("agent.zig");
const ssh = @import("ssh.zig");

pub const allowed_origins = [_][]const u8{ "zero://app", "http://127.0.0.1:5173" };

const handler_count = 103;

pub const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    store: *servers.Store,
    manager: *sessions.Manager,
    audit: *history.AuditStore,
    history: *history.HistoryStore,
    logs: *logs.SourceStore,
    scripts: *scripts.Store,
    apps: *deploy.AppStore,
    deploy_history: *deploy.HistoryStore,
    access: *access.Registry,
    backup: *backup.Registry,
    ai: *ai.Registry,
    handlers: [handler_count]native_sdk.BridgeHandler = undefined,
    policies: [handler_count]native_sdk.BridgeCommandPolicy = undefined,

    pub fn dispatcher(self: *Context) native_sdk.BridgeDispatcher {
        self.handlers = .{
            .{ .name = "oars.servers.list", .context = self, .invoke_fn = handleServersList },
            .{ .name = "oars.servers.save", .context = self, .invoke_fn = handleServersSave },
            .{ .name = "oars.servers.delete", .context = self, .invoke_fn = handleServersDelete },
            .{ .name = "oars.ssh.connect", .context = self, .invoke_fn = handleSshConnect },
            .{ .name = "oars.ssh.disconnect", .context = self, .invoke_fn = handleSshDisconnect },
            .{ .name = "oars.ssh.input", .context = self, .invoke_fn = handleSshInput },
            .{ .name = "oars.ssh.exec", .context = self, .invoke_fn = handleSshExec },
            .{ .name = "oars.ssh.closeChannel", .context = self, .invoke_fn = handleSshCloseChannel },
            .{ .name = "oars.ssh.resize", .context = self, .invoke_fn = handleSshResize },
            .{ .name = "oars.ssh.trust", .context = self, .invoke_fn = handleSshTrust },
            .{ .name = "oars.ssh.retrust", .context = self, .invoke_fn = handleSshRetrust },
            .{ .name = "oars.ssh.poll", .context = self, .invoke_fn = handleSshPoll },
            .{ .name = "oars.monitor.poll", .context = self, .invoke_fn = handleMonitorPoll },
            .{ .name = "oars.monitor.probe", .context = self, .invoke_fn = handleMonitorProbe },
            .{ .name = "oars.monitor.cleanDiskEstimate", .context = self, .invoke_fn = handleMonitorCleanDiskEstimate },
            .{ .name = "oars.monitor.cleanDisk", .context = self, .invoke_fn = handleMonitorCleanDisk },
            .{ .name = "oars.monitor.dropCaches", .context = self, .invoke_fn = handleMonitorDropCaches },
            .{ .name = "oars.logs.scan", .context = self, .invoke_fn = handleLogsScan },
            .{ .name = "oars.logs.read", .context = self, .invoke_fn = handleLogsRead },
            .{ .name = "oars.logs.follow", .context = self, .invoke_fn = handleLogsFollow },
            .{ .name = "oars.logs.clear", .context = self, .invoke_fn = handleLogsClear },
            .{ .name = "oars.logs.addSource", .context = self, .invoke_fn = handleLogsAddSource },
            .{ .name = "oars.local.ls", .context = self, .invoke_fn = handleLocalLs },
            .{ .name = "oars.sftp.ls", .context = self, .invoke_fn = handleSftpLs },
            .{ .name = "oars.sftp.stat", .context = self, .invoke_fn = handleSftpStat },
            .{ .name = "oars.sftp.read", .context = self, .invoke_fn = handleSftpRead },
            .{ .name = "oars.sftp.write", .context = self, .invoke_fn = handleSftpWrite },
            .{ .name = "oars.sftp.save", .context = self, .invoke_fn = handleSftpSave },
            .{ .name = "oars.sftp.download", .context = self, .invoke_fn = handleSftpDownload },
            .{ .name = "oars.sftp.uploadLocal", .context = self, .invoke_fn = handleSftpUploadLocal },
            .{ .name = "oars.sftp.mkdir", .context = self, .invoke_fn = handleSftpMkdir },
            .{ .name = "oars.sftp.rm", .context = self, .invoke_fn = handleSftpRm },
            .{ .name = "oars.sftp.rename", .context = self, .invoke_fn = handleSftpRename },
            .{ .name = "oars.sftp.chmod", .context = self, .invoke_fn = handleSftpChmod },
            .{ .name = "oars.sftp.unzip", .context = self, .invoke_fn = handleSftpUnzip },
            .{ .name = "oars.sftp.zipDownload", .context = self, .invoke_fn = handleSftpZipDownload },
            .{ .name = "oars.sftp.folderSize", .context = self, .invoke_fn = handleSftpFolderSize },
            .{ .name = "oars.sftp.poll", .context = self, .invoke_fn = handleSftpPoll },
            .{ .name = "oars.sftp.cancel", .context = self, .invoke_fn = handleSftpCancel },
            .{ .name = "oars.scripts.list", .context = self, .invoke_fn = handleScriptsList },
            .{ .name = "oars.scripts.validate", .context = self, .invoke_fn = handleScriptsValidate },
            .{ .name = "oars.scripts.save", .context = self, .invoke_fn = handleScriptsSave },
            .{ .name = "oars.scripts.delete", .context = self, .invoke_fn = handleScriptsDelete },
            .{ .name = "oars.scripts.run", .context = self, .invoke_fn = handleScriptsRun },
            .{ .name = "oars.scripts.broadcastPrepare", .context = self, .invoke_fn = handleScriptsBroadcastPrepare },
            .{ .name = "oars.scripts.broadcast", .context = self, .invoke_fn = handleScriptsBroadcast },
            .{ .name = "oars.scripts.broadcastPrepareCancel", .context = self, .invoke_fn = handleScriptsBroadcastPrepareCancel },
            .{ .name = "oars.scripts.broadcastPoll", .context = self, .invoke_fn = handleScriptsBroadcastPoll },
            .{ .name = "oars.scripts.broadcastCancel", .context = self, .invoke_fn = handleScriptsBroadcastCancel },
            .{ .name = "oars.deploy.apps.list", .context = self, .invoke_fn = handleDeployAppsList },
            .{ .name = "oars.deploy.apps.save", .context = self, .invoke_fn = handleDeployAppsSave },
            .{ .name = "oars.deploy.apps.delete", .context = self, .invoke_fn = handleDeployAppsDelete },
            .{ .name = "oars.deploy.run", .context = self, .invoke_fn = handleDeployRun },
            .{ .name = "oars.deploy.poll", .context = self, .invoke_fn = handleDeployPoll },
            .{ .name = "oars.deploy.cancel", .context = self, .invoke_fn = handleDeployCancel },
            .{ .name = "oars.deploy.history", .context = self, .invoke_fn = handleDeployHistory },
            .{ .name = "oars.sshkeys.list", .context = self, .invoke_fn = handleSshKeysList },
            .{ .name = "oars.sshkeys.add", .context = self, .invoke_fn = handleSshKeysAdd },
            .{ .name = "oars.sshkeys.revoke", .context = self, .invoke_fn = handleSshKeysRevoke },
            .{ .name = "oars.sshkeys.rotate", .context = self, .invoke_fn = handleSshKeysRotate },
            .{ .name = "oars.sshkeys.generate", .context = self, .invoke_fn = handleSshKeysGenerate },
            .{ .name = "oars.sshkeys.roles.list", .context = self, .invoke_fn = handleSshKeysRolesList },
            .{ .name = "oars.sshkeys.roles.create", .context = self, .invoke_fn = handleSshKeysRolesCreate },
            .{ .name = "oars.sshkeys.roles.delete", .context = self, .invoke_fn = handleSshKeysRolesDelete },
            .{ .name = "oars.sshkeys.deployKey.generate", .context = self, .invoke_fn = handleSshKeysDeployKeyGenerate },
            .{ .name = "oars.access.scan", .context = self, .invoke_fn = handleAccessScan },
            .{ .name = "oars.access.poll", .context = self, .invoke_fn = handleAccessPoll },
            .{ .name = "oars.access.identities.list", .context = self, .invoke_fn = handleAccessIdentitiesList },
            .{ .name = "oars.access.identities.save", .context = self, .invoke_fn = handleAccessIdentitiesSave },
            .{ .name = "oars.access.identities.delete", .context = self, .invoke_fn = handleAccessIdentitiesDelete },
            .{ .name = "oars.access.offboard", .context = self, .invoke_fn = handleAccessOffboard },
            .{ .name = "oars.access.onboard", .context = self, .invoke_fn = handleAccessOnboard },
            .{ .name = "oars.access.rotate", .context = self, .invoke_fn = handleAccessRotate },
            .{ .name = "oars.access.jobPoll", .context = self, .invoke_fn = handleAccessJobPoll },
            .{ .name = "oars.access.export", .context = self, .invoke_fn = handleAccessExport },
            .{ .name = "oars.backup.jobs.list", .context = self, .invoke_fn = handleBackupJobsList },
            .{ .name = "oars.backup.jobs.save", .context = self, .invoke_fn = handleBackupJobsSave },
            .{ .name = "oars.backup.jobs.delete", .context = self, .invoke_fn = handleBackupJobsDelete },
            .{ .name = "oars.backup.test", .context = self, .invoke_fn = handleBackupTest },
            .{ .name = "oars.backup.run", .context = self, .invoke_fn = handleBackupRun },
            .{ .name = "oars.backup.poll", .context = self, .invoke_fn = handleBackupPoll },
            .{ .name = "oars.backup.history", .context = self, .invoke_fn = handleBackupHistory },
            .{ .name = "oars.backup.install", .context = self, .invoke_fn = handleBackupInstall },
            .{ .name = "oars.backup.cronStatus", .context = self, .invoke_fn = handleBackupCronStatus },
            .{ .name = "oars.ai.context", .context = self, .invoke_fn = handleAiContext },
            .{ .name = "oars.ai.provider.get", .context = self, .invoke_fn = handleAiProviderGet },
            .{ .name = "oars.ai.provider.set", .context = self, .invoke_fn = handleAiProviderSet },
            .{ .name = "oars.ai.history", .context = self, .invoke_fn = handleAiHistory },
            .{ .name = "oars.vnc.start", .context = self, .invoke_fn = handleVncStart },
            .{ .name = "oars.vnc.stop", .context = self, .invoke_fn = handleVncStop },
            .{ .name = "oars.vnc.probe", .context = self, .invoke_fn = handleVncProbe },
            .{ .name = "oars.vnc.setup", .context = self, .invoke_fn = handleVncSetup },
            .{ .name = "oars.vnc.poll", .context = self, .invoke_fn = handleVncPoll },
            .{ .name = "oars.history.record", .context = self, .invoke_fn = handleHistoryRecord },
            .{ .name = "oars.history.list", .context = self, .invoke_fn = handleHistoryList },
            .{ .name = "oars.history.replay", .context = self, .invoke_fn = handleHistoryReplay },
            .{ .name = "oars.audit.list", .context = self, .invoke_fn = handleAuditList },
            .{ .name = "oars.audit.clear", .context = self, .invoke_fn = handleAuditClear },
            .{ .name = "oars.vault.export", .context = self, .invoke_fn = handleVaultExport },
            .{ .name = "oars.vault.import", .context = self, .invoke_fn = handleVaultImport },
            .{ .name = "oars.vault.importConfirm", .context = self, .invoke_fn = handleVaultImportConfirm },
            .{ .name = "oars.agent.list", .context = self, .invoke_fn = handleAgentList },
            .{ .name = "oars.agent.forward", .context = self, .invoke_fn = handleAgentForward },
        };
        self.policies = .{
            .{ .name = "oars.servers.list", .origins = &allowed_origins },
            .{ .name = "oars.servers.save", .origins = &allowed_origins },
            .{ .name = "oars.servers.delete", .origins = &allowed_origins },
            .{ .name = "oars.ssh.connect", .origins = &allowed_origins },
            .{ .name = "oars.ssh.disconnect", .origins = &allowed_origins },
            .{ .name = "oars.ssh.input", .origins = &allowed_origins },
            .{ .name = "oars.ssh.exec", .origins = &allowed_origins },
            .{ .name = "oars.ssh.closeChannel", .origins = &allowed_origins },
            .{ .name = "oars.ssh.resize", .origins = &allowed_origins },
            .{ .name = "oars.ssh.trust", .origins = &allowed_origins },
            .{ .name = "oars.ssh.retrust", .origins = &allowed_origins },
            .{ .name = "oars.ssh.poll", .origins = &allowed_origins },
            .{ .name = "oars.monitor.poll", .origins = &allowed_origins },
            .{ .name = "oars.monitor.probe", .origins = &allowed_origins },
            .{ .name = "oars.monitor.cleanDiskEstimate", .origins = &allowed_origins },
            .{ .name = "oars.monitor.cleanDisk", .origins = &allowed_origins },
            .{ .name = "oars.monitor.dropCaches", .origins = &allowed_origins },
            .{ .name = "oars.logs.scan", .origins = &allowed_origins },
            .{ .name = "oars.logs.read", .origins = &allowed_origins },
            .{ .name = "oars.logs.follow", .origins = &allowed_origins },
            .{ .name = "oars.logs.clear", .origins = &allowed_origins },
            .{ .name = "oars.logs.addSource", .origins = &allowed_origins },
            .{ .name = "oars.local.ls", .origins = &allowed_origins },
            .{ .name = "oars.sftp.ls", .origins = &allowed_origins },
            .{ .name = "oars.sftp.stat", .origins = &allowed_origins },
            .{ .name = "oars.sftp.read", .origins = &allowed_origins },
            .{ .name = "oars.sftp.write", .origins = &allowed_origins },
            .{ .name = "oars.sftp.save", .origins = &allowed_origins },
            .{ .name = "oars.sftp.download", .origins = &allowed_origins },
            .{ .name = "oars.sftp.uploadLocal", .origins = &allowed_origins },
            .{ .name = "oars.sftp.mkdir", .origins = &allowed_origins },
            .{ .name = "oars.sftp.rm", .origins = &allowed_origins },
            .{ .name = "oars.sftp.rename", .origins = &allowed_origins },
            .{ .name = "oars.sftp.chmod", .origins = &allowed_origins },
            .{ .name = "oars.sftp.unzip", .origins = &allowed_origins },
            .{ .name = "oars.sftp.zipDownload", .origins = &allowed_origins },
            .{ .name = "oars.sftp.folderSize", .origins = &allowed_origins },
            .{ .name = "oars.sftp.poll", .origins = &allowed_origins },
            .{ .name = "oars.sftp.cancel", .origins = &allowed_origins },
            .{ .name = "oars.scripts.list", .origins = &allowed_origins },
            .{ .name = "oars.scripts.validate", .origins = &allowed_origins },
            .{ .name = "oars.scripts.save", .origins = &allowed_origins },
            .{ .name = "oars.scripts.delete", .origins = &allowed_origins },
            .{ .name = "oars.scripts.run", .origins = &allowed_origins },
            .{ .name = "oars.scripts.broadcastPrepare", .origins = &allowed_origins },
            .{ .name = "oars.scripts.broadcast", .origins = &allowed_origins },
            .{ .name = "oars.scripts.broadcastPrepareCancel", .origins = &allowed_origins },
            .{ .name = "oars.scripts.broadcastPoll", .origins = &allowed_origins },
            .{ .name = "oars.scripts.broadcastCancel", .origins = &allowed_origins },
            .{ .name = "oars.deploy.apps.list", .origins = &allowed_origins },
            .{ .name = "oars.deploy.apps.save", .origins = &allowed_origins },
            .{ .name = "oars.deploy.apps.delete", .origins = &allowed_origins },
            .{ .name = "oars.deploy.run", .origins = &allowed_origins },
            .{ .name = "oars.deploy.poll", .origins = &allowed_origins },
            .{ .name = "oars.deploy.cancel", .origins = &allowed_origins },
            .{ .name = "oars.deploy.history", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.list", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.add", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.revoke", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.rotate", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.generate", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.roles.list", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.roles.create", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.roles.delete", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.deployKey.generate", .origins = &allowed_origins },
            .{ .name = "oars.access.scan", .origins = &allowed_origins },
            .{ .name = "oars.access.poll", .origins = &allowed_origins },
            .{ .name = "oars.access.identities.list", .origins = &allowed_origins },
            .{ .name = "oars.access.identities.save", .origins = &allowed_origins },
            .{ .name = "oars.access.identities.delete", .origins = &allowed_origins },
            .{ .name = "oars.access.offboard", .origins = &allowed_origins },
            .{ .name = "oars.access.onboard", .origins = &allowed_origins },
            .{ .name = "oars.access.rotate", .origins = &allowed_origins },
            .{ .name = "oars.access.jobPoll", .origins = &allowed_origins },
            .{ .name = "oars.access.export", .origins = &allowed_origins },
            .{ .name = "oars.backup.jobs.list", .origins = &allowed_origins },
            .{ .name = "oars.backup.jobs.save", .origins = &allowed_origins },
            .{ .name = "oars.backup.jobs.delete", .origins = &allowed_origins },
            .{ .name = "oars.backup.test", .origins = &allowed_origins },
            .{ .name = "oars.backup.run", .origins = &allowed_origins },
            .{ .name = "oars.backup.poll", .origins = &allowed_origins },
            .{ .name = "oars.backup.history", .origins = &allowed_origins },
            .{ .name = "oars.backup.install", .origins = &allowed_origins },
            .{ .name = "oars.backup.cronStatus", .origins = &allowed_origins },
            .{ .name = "oars.ai.context", .origins = &allowed_origins },
            .{ .name = "oars.ai.provider.get", .origins = &allowed_origins },
            .{ .name = "oars.ai.provider.set", .origins = &allowed_origins },
            .{ .name = "oars.ai.history", .origins = &allowed_origins },
            .{ .name = "oars.vnc.start", .origins = &allowed_origins },
            .{ .name = "oars.vnc.stop", .origins = &allowed_origins },
            .{ .name = "oars.vnc.probe", .origins = &allowed_origins },
            .{ .name = "oars.vnc.setup", .origins = &allowed_origins },
            .{ .name = "oars.vnc.poll", .origins = &allowed_origins },
            .{ .name = "oars.history.record", .origins = &allowed_origins },
            .{ .name = "oars.history.list", .origins = &allowed_origins },
            .{ .name = "oars.history.replay", .origins = &allowed_origins },
            .{ .name = "oars.audit.list", .origins = &allowed_origins },
            .{ .name = "oars.audit.clear", .origins = &allowed_origins },
            .{ .name = "oars.vault.export", .origins = &allowed_origins },
            .{ .name = "oars.vault.import", .origins = &allowed_origins },
            .{ .name = "oars.vault.importConfirm", .origins = &allowed_origins },
            .{ .name = "oars.agent.list", .origins = &allowed_origins },
            .{ .name = "oars.agent.forward", .origins = &allowed_origins },
        };
        return .{
            .policy = .{ .enabled = true, .commands = &self.policies },
            .registry = .{ .handlers = &self.handlers },
        };
    }
};

fn contextOf(context: *anyopaque) *Context {
    return @ptrCast(@alignCast(context));
}

const HandlerFn = *const fn (context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8;

/// User-facing error result: resolves the invoke with ok:false so the
/// frontend can show a message without a framework-level rejection.
fn respondError(output: []u8, message: []const u8) []const u8 {
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":false,\"error\":") catch return output[0..0];
    json.writeJsonString(&writer, message) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

const ok_json = "{\"ok\":true}";

// --- payload parsing ------------------------------------------------------

fn parsePayload(comptime T: type, allocator: std.mem.Allocator, payload: []const u8) !std.json.Parsed(T) {
    return std.json.parseFromSlice(T, allocator, payload, .{});
}

// --- servers --------------------------------------------------------------

fn handleServersList(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    _ = invocation;
    const self = contextOf(context);
    var loaded = self.store.loadParsed(self.io) catch {
        return "{\"ok\":false,\"error\":\"failed to load servers\"}";
    };
    defer loaded.deinit(self.allocator);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"servers\":") catch return output[0..0];
    std.json.Stringify.value(loaded.parsed.value, .{}, &writer) catch return output[0..0];
    if (loaded.quarantined) |q| {
        var msg_buf: [640]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "servers.json was unreadable and was moved to {s}; the server list starts fresh", .{q}) catch "servers.json was unreadable and was moved aside";
        writer.writeAll(",\"recovery_error\":") catch return output[0..0];
        json.writeJsonString(&writer, msg) catch return output[0..0];
    }
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

const SavePayload = struct {
    id: ?[]const u8 = null,
    name: []const u8,
    host: []const u8,
    port: u16 = 22,
    user: []const u8,
    auth_method: []const u8,
    key_path: ?[]const u8 = null,
    key_has_passphrase: bool = false,
    group: ?[]const u8 = null,
    tags: ?[][]const u8 = null,
    via_server_id: ?[]const u8 = null,
};

fn handleServersSave(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SavePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    const auth_method = servers.AuthMethod.fromJsonName(payload.auth_method) orelse {
        return respondError(output, "unknown auth method");
    };

    // Host names are trimmed; a trailing slash is not part of an SSH host
    // and is rejected rather than silently stripped (spec 01 §10).
    const host = std.mem.trim(u8, payload.host, " \t\r\n");
    if (host.len == 0) return respondError(output, "host is required");
    if (host[host.len - 1] == '/') return respondError(output, "host must not end with '/'");
    if (payload.port == 0) return respondError(output, "port must be between 1 and 65535");

    const key_path = std.mem.trim(u8, payload.key_path orelse "", " \t\r\n");
    if (auth_method == .key) {
        if (key_path.len == 0) {
            return respondError(output, "choose a private key file");
        }
        // Refuse to persist a key path we cannot read (a paste of the
        // whole "ssh -i key host" command line is the classic mistake).
        const expanded = servers.expandHome(self.allocator, key_path, self.manager.home) catch {
            return respondError(output, "out of memory");
        };
        defer self.allocator.free(expanded);
        std.Io.Dir.cwd().access(self.io, expanded, .{}) catch {
            var msg_buf: [512]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "private key file not readable: {s}", .{expanded}) catch "private key file not readable";
            return respondError(output, msg);
        };
    }

    // Tags are normalized (spec 14 §6): trimmed, empties dropped,
    // control characters rejected, deduped case-insensitively with the
    // first-seen casing preserved.
    const tags = servers.normalizeTags(self.allocator, payload.tags) catch |err| {
        return respondError(output, switch (err) {
            error.TagControlChar => "tags cannot contain control characters",
            else => "out of memory",
        });
    };
    defer {
        for (tags) |t| self.allocator.free(t);
        self.allocator.free(tags);
    }

    // Group paths follow the one-level rule (spec 14 §5): ungrouped, one
    // segment, or `parent/child` — at most one '/', no empty segments,
    // no control characters.
    const group = servers.validateGroup(payload.group orelse "") catch |err| {
        return respondError(output, switch (err) {
            error.GroupControlChar => "group names cannot contain control characters",
            error.GroupTooDeep => "groups are limited to one nesting level (parent/child)",
            error.GroupEmptySegment => "group segments cannot be empty",
        });
    };

    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    var owned_id: ?[]const u8 = null;
    defer if (owned_id) |o| self.allocator.free(o);
    const id = payload.id orelse blk: {
        owned_id = servers.makeId(self.allocator, now) catch {
            return respondError(output, "out of memory");
        };
        break :blk owned_id.?;
    };

    // Edits preserve created_at, and keep the trusted host fingerprint
    // only while the endpoint (host+port) is unchanged (spec 01 §5).
    var loaded = self.store.loadParsed(self.io) catch {
        return respondError(output, "failed to load servers");
    };
    defer loaded.deinit(self.allocator);
    var created_at: i64 = @intCast(now);
    var host_fingerprint: ?[]const u8 = null;
    if (payload.id) |pid| {
        for (loaded.parsed.value) |existing| {
            if (std.mem.eql(u8, existing.id, pid)) {
                created_at = existing.created_at;
                if (std.mem.eql(u8, existing.host, host) and existing.port == payload.port) {
                    host_fingerprint = existing.host_fingerprint;
                }
                break;
            }
        }
    }

    const server = servers.Server{
        .id = id,
        .name = payload.name,
        .host = host,
        .port = payload.port,
        .user = payload.user,
        .auth_method = auth_method,
        .key_path = key_path,
        .key_has_passphrase = payload.key_has_passphrase,
        .host_fingerprint = host_fingerprint,
        .group = group,
        .tags = tags,
        .via_server_id = payload.via_server_id,
        .created_at = created_at,
        .updated_at = @intCast(now),
    };

    // Jump chains are validated against the saved set at save time:
    // existing references, no self-links, depth <= 3, no cycles (spec 18).
    servers.validateViaChain(server, loaded.parsed.value) catch |err| {
        return respondError(output, switch (err) {
            error.SelfLink => "a server cannot connect via itself",
            error.MissingVia => "the configured jump host does not exist",
            error.ChainTooDeep => "jump chains are limited to 3 hops",
            error.Cycle => "jump chain contains a cycle",
        });
    };

    self.store.upsert(self.io, server) catch {
        return respondError(output, "failed to save server");
    };

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"server\":") catch return output[0..0];
    writeServer(&writer, server) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn writeServer(writer: anytype, server: servers.Server) !void {
    try writer.writeAll("{\"id\":");
    try json.writeJsonString(writer, server.id);
    try writer.writeAll(",\"name\":");
    try json.writeJsonString(writer, server.name);
    try writer.writeAll(",\"host\":");
    try json.writeJsonString(writer, server.host);
    try writer.print(",\"port\":{d}", .{server.port});
    try writer.writeAll(",\"user\":");
    try json.writeJsonString(writer, server.user);
    try writer.writeAll(",\"auth_method\":");
    try json.writeJsonString(writer, server.auth_method.jsonName());
    try writer.writeAll(",\"key_path\":");
    try json.writeJsonString(writer, server.key_path);
    try writer.print(",\"key_has_passphrase\":{s}", .{if (server.key_has_passphrase) "true" else "false"});
    try writer.writeAll(",\"host_fingerprint\":");
    if (server.host_fingerprint) |fp| {
        try json.writeJsonString(writer, fp);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"group\":");
    try json.writeJsonString(writer, server.group);
    try writer.writeAll(",\"tags\":[");
    for (server.tags, 0..) |tag, i| {
        if (i > 0) try writer.writeByte(',');
        try json.writeJsonString(writer, tag);
    }
    try writer.writeAll("],\"via_server_id\":");
    if (server.via_server_id) |via| {
        try json.writeJsonString(writer, via);
    } else {
        try writer.writeAll("null");
    }
    try writer.print(",\"created_at\":{d},\"updated_at\":{d}}}", .{ server.created_at, server.updated_at });
}

const DeletePayload = struct {
    id: []const u8,
};

fn handleServersDelete(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeletePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.disconnect(parsed.value.id);
    self.store.delete(self.io, parsed.value.id) catch {
        return respondError(output, "failed to delete server");
    };
    return ok_json;
}

// --- ssh ------------------------------------------------------------------

const ConnectPayload = struct {
    server_id: []const u8,
    password: ?[]const u8 = null,
    passphrase: ?[]const u8 = null,
};

fn handleSshConnect(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ConnectPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    const server = self.store.find(self.io, payload.server_id) catch {
        return respondError(output, "failed to load server");
    } orelse {
        return respondError(output, "server not found");
    };
    defer {
        var s = server;
        s.deinit(self.allocator);
    }

    _ = self.manager.connect(server, payload.password, payload.passphrase) catch |err| {
        if (err == error.AlreadyConnected) {
            // Idempotent connect (spec 02 §5): success carrying the live
            // session status, never a text-coupled error.
            if (self.manager.get(server.id)) |existing| {
                var writer = std.Io.Writer.fixed(output);
                writer.print("{{\"ok\":true,\"status\":\"{s}\"}}", .{existing.status.load(.acquire).jsonName()}) catch return output[0..0];
                return writer.buffered();
            }
            return ok_json;
        }
        return respondError(output, "failed to start connection");
    };
    return ok_json;
}

const IdPayload = struct {
    server_id: []const u8,
};

fn handleSshDisconnect(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(IdPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.disconnect(parsed.value.server_id);
    return ok_json;
}

const InputPayload = struct {
    server_id: []const u8,
    data: []const u8,
};

fn handleSshInput(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(InputPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.input(parsed.value.server_id, parsed.value.data) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "input failed",
        });
    };
    return ok_json;
}

const ExecPayload = struct {
    server_id: []const u8,
    command: []const u8,
};

fn handleSshExec(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ExecPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const channel_id = self.manager.execTracked(parsed.value.server_id, parsed.value.command, "exec", null, &.{}) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "exec failed",
        });
    };
    // Spec 11: every executed command is logged; the AI panel's history
    // is the audit-filtered view of these entries. Spec 15 §8: the audit
    // row is redacted the same way as history — secret values never
    // written.
    const redacted_audit = history.redact(self.allocator, parsed.value.command, &.{}) catch {
        return respondError(output, "out of memory");
    };
    defer self.allocator.free(redacted_audit.text);
    var detail_buf: [256]u8 = undefined;
    const cmd = if (redacted_audit.text.len > ai.audit_cmd_cap) redacted_audit.text[0..ai.audit_cmd_cap] else redacted_audit.text;
    const detail = std.fmt.bufPrint(&detail_buf, "cmd={s}", .{cmd}) catch "ssh.exec";
    sshkeysAudit(self, "ssh.exec", parsed.value.server_id, detail);
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel_id}) catch return output[0..0];
    return writer.buffered();
}

const CloseChannelPayload = struct {
    server_id: []const u8,
    channel: u32,
};

/// Explicit channel close (spec 04 follow channels; spec 02 §5): the worker
/// sends EOF, closes the raw channel, and frees the entry.
fn handleSshCloseChannel(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(CloseChannelPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.closeChannel(parsed.value.server_id, parsed.value.channel) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.InvalidChannel => "cannot close the shell channel",
            else => "close failed",
        });
    };
    return ok_json;
}

const ResizePayload = struct {
    server_id: []const u8,
    cols: u16,
    rows: u16,
};

fn handleSshResize(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ResizePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.resize(parsed.value.server_id, parsed.value.cols, parsed.value.rows) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            else => "resize failed",
        });
    };
    return ok_json;
}

const TrustPayload = struct {
    server_id: []const u8,
    accept: bool,
};

fn handleSshTrust(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(TrustPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.trust(parsed.value.server_id, parsed.value.accept) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotPending => "no trust decision pending",
            else => "trust failed",
        });
    };
    return ok_json;
}

const RetrustPayload = struct {
    server_id: []const u8,
    confirm_name: []const u8,
};

/// Clears a stored host identity only after exact profile-name confirmation.
/// The next connection returns to `needs_trust` with the new fingerprint.
fn handleSshRetrust(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(RetrustPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();

    var server = self.store.find(self.io, parsed.value.server_id) catch {
        return respondError(output, "failed to load server");
    } orelse return respondError(output, "server not found");
    defer server.deinit(self.allocator);

    if (!std.mem.eql(u8, parsed.value.confirm_name, server.name)) {
        return respondError(output, "type the connection name exactly to clear the stored host key");
    }
    const old_fingerprint = server.host_fingerprint orelse {
        return respondError(output, "this connection profile has no stored host key");
    };

    self.manager.disconnect(server.id);
    self.allocator.free(old_fingerprint);
    server.host_fingerprint = null;
    server.updated_at = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds);
    self.store.upsert(self.io, server) catch {
        return respondError(output, "failed to clear the stored host key");
    };
    self.audit.append(self.io, "ssh.retrust", server.id, "stored host key cleared after exact name confirmation") catch {};

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"server\":") catch return output[0..0];
    writeServer(&writer, server) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

const PollPayload = struct {
    server_id: []const u8,
    /// Per-channel absolute cursors for the requesting tab (spec 02 §5),
    /// e.g. [{"channel":0,"cursor":1200}].
    cursors: ?[]const PollCursor = null,
    rewind: bool = false,
};

const PollCursor = struct {
    channel: u32,
    cursor: u64,
};

const poll_data_budget: usize = 384 * 1024;
const poll_channel_budget: usize = 256 * 1024;

fn handleSshPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(PollPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();

    const info = self.manager.sessionSnapshot(parsed.value.server_id) catch {
        return "{\"ok\":true,\"status\":\"closed\",\"error\":\"\",\"trust\":{\"pending\":false},\"channels\":[]}";
    };

    // The requesting tab's cursors: channel id -> absolute position.
    var cursors: std.ArrayList(sessions.Cursor) = .empty;
    defer cursors.deinit(self.allocator);
    if (parsed.value.cursors) |incoming| {
        for (incoming) |c| {
            cursors.append(self.allocator, .{ .id = c.channel, .pos = c.cursor }) catch continue;
        }
    }

    const polls = self.manager.pollChannels(
        parsed.value.server_id,
        cursors.items,
        parsed.value.rewind,
        poll_data_budget,
        poll_channel_budget,
    ) catch {
        return "{\"ok\":true,\"status\":\"closed\",\"error\":\"\",\"trust\":{\"pending\":false},\"channels\":[]}";
    };
    defer {
        for (polls) |*p| p.deinit(self.allocator);
        self.allocator.free(polls);
    }

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"status\":") catch return output[0..0];
    json.writeJsonString(&writer, info.status.jsonName()) catch return output[0..0];
    writer.writeAll(",\"error\":") catch return output[0..0];
    json.writeJsonString(&writer, info.@"error") catch return output[0..0];
    writer.writeAll(",\"trust\":{") catch return output[0..0];
    if (info.trust_pending) {
        writer.writeAll("\"pending\":true,\"algorithm\":") catch return output[0..0];
        json.writeJsonString(&writer, info.trust_algorithm) catch return output[0..0];
        writer.writeAll(",\"fingerprint\":") catch return output[0..0];
        json.writeJsonString(&writer, info.trust_fingerprint) catch return output[0..0];
    } else {
        writer.writeAll("\"pending\":false") catch return output[0..0];
    }
    writer.writeAll("},\"channels\":[") catch return output[0..0];

    var first = true;
    for (polls) |ch| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.print("{{\"id\":{d},\"kind\":", .{ch.id}) catch return output[0..0];
        json.writeJsonString(&writer, ch.kind.jsonName()) catch return output[0..0];
        writer.writeAll(",\"command\":") catch return output[0..0];
        json.writeJsonString(&writer, ch.command) catch return output[0..0];
        writer.print(",\"cursor\":{d},\"dropped\":{d},\"pending\":{d},\"eof\":{s},\"exit\":", .{
            ch.cursor, ch.gap, ch.pending, if (ch.eof) "true" else "false",
        }) catch return output[0..0];
        if (ch.exit_status) |status| {
            writer.print("{d}", .{status}) catch return output[0..0];
        } else {
            writer.writeAll("null") catch return output[0..0];
        }
        writer.writeAll(",\"data\":") catch return output[0..0];
        json.writeJsonString(&writer, ch.data) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

// --- VNC (spec 12) ---------------------------------------------------------

const vnc_exec_cap: usize = 256 * 1024;
const vnc_exec_timeout_ns = 20 * std.time.ns_per_s;
const vnc_install_timeout_ns = 30 * std.time.ns_per_min;
const vnc_start_timeout_ns = 5 * std.time.ns_per_s;

const VncStartPayload = struct {
    server_id: []const u8,
    host: ?[]const u8 = null,
    port: ?u16 = null,
};
const VncStopPayload = struct {
    server_id: []const u8,
    tunnel_id: u32,
};
const VncProbePayload = struct {
    server_id: []const u8,
    display: ?u16 = null,
};
const VncSetupPayload = struct {
    server_id: []const u8,
    display: ?u16 = null,
    dry_run: bool = false,
    password: ?[]const u8 = null,
    install_desktop: bool = false,
};
const VncPollPayload = struct {
    server_id: []const u8,
    tunnel_id: u32,
};

fn vncExec(self: *Context, server_id: []const u8, cmd: []const u8) ?sessions.ExecOutcome {
    return self.manager.execWait(server_id, cmd, vnc_exec_cap, vnc_exec_timeout_ns) catch null;
}

fn vncExecWithInput(self: *Context, server_id: []const u8, cmd: []const u8, input: []const u8) ?sessions.ExecOutcome {
    return self.manager.execWaitWithInput(server_id, cmd, input, 64 * 1024, 90 * std.time.ns_per_s) catch null;
}

fn vncCheck(self: *Context, server_id: []const u8, cmd: []const u8) bool {
    var out = vncExec(self, server_id, cmd) orelse return false;
    defer out.output.deinit(self.allocator);
    return !out.limited and out.exit == 0;
}

const VncInstallResult = enum { installed, pending, failed };

fn vncInstall(self: *Context, server_id: []const u8, display: u16, plan: []const u8) VncInstallResult {
    const start_command = vncmod.installStartCommand(self.allocator, display, plan) catch return .failed;
    defer self.allocator.free(start_command);
    var started = vncExec(self, server_id, start_command) orelse return .failed;
    defer started.output.deinit(self.allocator);
    if (started.limited or started.exit != 0) return .failed;

    const wait_command = vncmod.installWaitCommand(self.allocator, display) catch return .failed;
    defer self.allocator.free(wait_command);
    var waited = self.manager.execWait(server_id, wait_command, vnc_exec_cap, vnc_install_timeout_ns) catch return .pending;
    defer waited.output.deinit(self.allocator);
    if (waited.limited) return .pending;
    return if (waited.exit == 0) .installed else .failed;
}

fn vncMarkSetupState(self: *Context, server_id: []const u8, display: u16, state: []const u8) void {
    const command = vncmod.setupStateCommand(self.allocator, display, state) catch return;
    defer self.allocator.free(command);
    var outcome = vncExec(self, server_id, command) orelse return;
    outcome.output.deinit(self.allocator);
}

fn vncSetupFailure(output: []u8, captured: []const u8, timed_out: bool) []const u8 {
    if (timed_out) return respondError(output, "VNC configuration timed out before the server became ready");
    const trimmed = std.mem.trim(u8, captured, " \t\r\n");
    if (trimmed.len == 0) return respondError(output, "VNC configuration failed; the remote command returned no diagnostic output");
    const detail = if (trimmed.len > 1200) trimmed[trimmed.len - 1200 ..] else trimmed;
    var message_buf: [1400]u8 = undefined;
    const message = std.fmt.bufPrint(&message_buf, "VNC configuration failed: {s}", .{detail}) catch
        "VNC configuration failed; inspect the remote x11vnc log";
    return respondError(output, message);
}

fn vncSessionReady(self: *Context, output: []u8, server_id: []const u8) ?[]const u8 {
    const session = self.manager.get(server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    return null;
}

/// Starts the tunnel: a loopback listener plus the direct-tcpip SSH
/// channel. Returns the ephemeral WS port and the URL token (spec 12
/// §5). Defaults: host = the server's own loopback, port = 5900.
fn handleVncStart(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(VncStartPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (vncSessionReady(self, output, payload.server_id)) |err| return err;
    const host = payload.host orelse "127.0.0.1";
    const port = payload.port orelse 5900;

    var token_bytes: [16]u8 = undefined;
    std.Io.random(self.io, &token_bytes);
    var token_buf: [33]u8 = undefined;
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        token_buf[i * 2] = hex[token_bytes[i] >> 4];
        token_buf[i * 2 + 1] = hex[token_bytes[i] & 0xf];
    }
    const token = token_buf[0..32];
    const id = self.manager.nextTunnelId();
    const outcome = self.allocator.create(sessions.TunnelStartOutcome) catch return respondError(output, "out of memory");
    outcome.* = .{ .allocator = self.allocator };
    self.manager.tunnelStart(payload.server_id, id, token, host, port, outcome) catch |err| {
        self.allocator.destroy(outcome);
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "tunnel start failed",
        });
    };
    outcome.wait(self.io, std.Io.Timestamp.now(self.io, .real).nanoseconds + vnc_start_timeout_ns);
    // On a deadline the op keeps the outcome (its eventual set frees it);
    // otherwise it is destroyed after the result is read.
    if (!outcome.isDone() and !outcome.abandon()) return respondError(output, "tunnel start timed out");
    defer self.allocator.destroy(outcome);
    if (!outcome.ok) return respondError(output, outcome.message());

    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"tunnel_id\":{d},\"ws_port\":{d},\"token\":", .{ id, outcome.port }) catch return output[0..0];
    json.writeJsonString(&writer, token) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleVncStop(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(VncStopPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (vncSessionReady(self, output, payload.server_id)) |err| return err;
    self.manager.tunnelStop(payload.server_id, payload.tunnel_id) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            else => "stop failed",
        });
    };
    return ok_json;
}

fn handleVncProbe(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(VncProbePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const server_id = parsed.value.server_id;
    const display = parsed.value.display orelse 0;
    if (vncSessionReady(self, output, server_id)) |err| return err;
    const command = vncmod.probeCommand(self.allocator, display) catch return respondError(output, "display must be between 0 and 99");
    defer self.allocator.free(command);
    var outcome = vncExec(self, server_id, command) orelse return respondError(output, "probe failed");
    defer outcome.output.deinit(self.allocator);
    var result = vncmod.parseProbeOutput(self.allocator, outcome.output.items);
    defer result.deinit(self.allocator);
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"x11vnc\":{s},\"tigervnc\":{s},\"desktop_installed\":{s},\"window_manager_running\":{s},\"desktop_surface_running\":{s},\"desktop_panel_running\":{s},\"desktop_running\":{s},\"desktop_name\":", .{
        if (result.x11vnc) "true" else "false",
        if (result.tigervnc) "true" else "false",
        if (result.desktop_installed) "true" else "false",
        if (result.window_manager_running) "true" else "false",
        if (result.desktop_surface_running) "true" else "false",
        if (result.desktop_panel_running) "true" else "false",
        if (result.desktop_running) "true" else "false",
    }) catch return output[0..0];
    json.writeJsonString(&writer, result.desktop_name) catch return output[0..0];
    writer.writeAll(",\"setup_state\":") catch return output[0..0];
    json.writeJsonString(&writer, result.setup_state) catch return output[0..0];
    writer.writeAll(",\"listening\":[") catch return output[0..0];
    var first = true;
    for (result.listening) |l| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.print("{{\"port\":{d},\"process\":", .{l.port}) catch return output[0..0];
        json.writeJsonString(&writer, l.process) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

/// The setup helper (spec 12 §5): detect the OS, return the tested
/// install plan; `dry_run: false` installs when needed, stores the supplied
/// password through x11vnc stdin, and starts a loopback-only server. The
/// password is never part of a command, process argument, output, or audit.
fn handleVncSetup(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(VncSetupPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (vncSessionReady(self, output, payload.server_id)) |err| return err;
    const display = payload.display orelse 0;
    if (display > vncmod.max_setup_display) return respondError(output, "display must be between 0 and 99");

    var os_out = vncExec(self, payload.server_id, "cat /etc/os-release 2>/dev/null") orelse return respondError(output, "cannot detect the server OS");
    defer os_out.output.deinit(self.allocator);
    const probe_command = vncmod.probeCommand(self.allocator, display) catch return respondError(output, "cannot build the VNC probe command");
    defer self.allocator.free(probe_command);
    var probe_out = vncExec(self, payload.server_id, probe_command) orelse return respondError(output, "cannot inspect the remote desktop");
    defer probe_out.output.deinit(self.allocator);
    var probe = vncmod.parseProbeOutput(self.allocator, probe_out.output.items);
    defer probe.deinit(self.allocator);
    var plan = vncmod.setupPlan(
        self.allocator,
        os_out.output.items,
        display,
        probe.x11vnc,
        probe.xfce_ready,
        probe.desktop_running,
        payload.install_desktop,
    );
    defer plan.deinit(self.allocator);

    if (payload.dry_run or std.mem.eql(u8, plan.action, "manual")) {
        return vncSetupResponse(output, &plan, false);
    }
    const password = payload.password orelse return respondError(output, "enter a VNC password");
    if (password.len == 0 or password.len > 1024) return respondError(output, "VNC password must be between 1 and 1024 bytes");
    if (std.mem.indexOfAny(u8, password, "\r\n") != null) return respondError(output, "VNC password cannot contain a line break");

    if (plan.plan.len > 0) {
        var idc = vncExec(self, payload.server_id, "id -u") orelse return respondError(output, "not connected");
        defer idc.output.deinit(self.allocator);
        if (idc.exit != 0 or !std.mem.eql(u8, std.mem.trim(u8, idc.output.items, " \t\r\n"), "0")) {
            return respondError(output, "installing VNC or desktop packages requires root access on the server");
        }
        switch (vncInstall(self, payload.server_id, display, plan.plan)) {
            .installed => {},
            .pending => return respondError(output, "Package installation is still running on the server. Oars will detect it after reconnect; re-probe this display before retrying."),
            .failed => return respondError(output, "VNC or desktop package installation failed; review the owner-only install log in $HOME/.local/share/oars/vnc"),
        }
    }

    const start_desktop = std.mem.eql(u8, plan.desktop_action, "install") or std.mem.eql(u8, plan.desktop_action, "start");
    const start_command = vncmod.secureStartCommand(self.allocator, display, start_desktop) catch return respondError(output, "cannot build the VNC start command");
    defer self.allocator.free(start_command);
    const input_len = password.len * 2 + 4;
    const password_input = self.allocator.alloc(u8, input_len) catch return respondError(output, "out of memory");
    defer {
        std.crypto.secureZero(u8, password_input);
        self.allocator.free(password_input);
    }
    @memcpy(password_input[0..password.len], password);
    password_input[password.len] = '\n';
    @memcpy(password_input[password.len + 1 .. password.len * 2 + 1], password);
    password_input[input_len - 3] = '\n';
    password_input[input_len - 2] = 'y';
    password_input[input_len - 1] = '\n';
    var started = vncExecWithInput(self, payload.server_id, start_command, password_input) orelse return respondError(output, "VNC configuration failed");
    defer started.output.deinit(self.allocator);
    if (started.limited or started.exit != 0) {
        vncMarkSetupState(self, payload.server_id, display, "failed");
        return vncSetupFailure(output, started.output.items, started.limited);
    }
    vncMarkSetupState(self, payload.server_id, display, "ready");

    var detail_buf: [128]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "display={d} action={s} desktop={s}", .{ display, plan.action, plan.desktop_action }) catch "vnc.setup";
    sshkeysAudit(self, "vnc.setup", payload.server_id, detail);
    return vncSetupResponse(output, &plan, true);
}

fn vncSetupResponse(output: []u8, plan: *const vncmod.SetupPlan, executed: bool) anyerror![]const u8 {
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"action\":") catch return output[0..0];
    json.writeJsonString(&writer, plan.action) catch return output[0..0];
    writer.writeAll(",\"executed\":") catch return output[0..0];
    writer.writeAll(if (executed) "true" else "false") catch return output[0..0];
    writer.writeAll(",\"plan\":") catch return output[0..0];
    json.writeJsonString(&writer, plan.plan) catch return output[0..0];
    writer.writeAll(",\"hint\":") catch return output[0..0];
    json.writeJsonString(&writer, plan.hint) catch return output[0..0];
    writer.writeAll(",\"desktop_action\":") catch return output[0..0];
    json.writeJsonString(&writer, plan.desktop_action) catch return output[0..0];
    writer.writeAll(",\"desktop_name\":") catch return output[0..0];
    json.writeJsonString(&writer, plan.desktop_name) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleVncPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(VncPollPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (vncSessionReady(self, output, payload.server_id)) |err| return err;
    var info: sessions.TunnelPollInfo = .{};
    if (!self.manager.tunnelPoll(payload.server_id, payload.tunnel_id, &info)) {
        return respondError(output, "unknown tunnel");
    }
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"state\":") catch return output[0..0];
    json.writeJsonString(&writer, tunnelStateName(info.state)) catch return output[0..0];
    writer.print(",\"bytes_up\":{d},\"bytes_down\":{d},\"error\":", .{ info.bytes_up, info.bytes_down }) catch return output[0..0];
    json.writeJsonString(&writer, info.error_buf[0..info.error_len]) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn tunnelStateName(state: sessions.TunnelState) []const u8 {
    return switch (state) {
        .listening => "listening",
        .handshake => "handshake",
        .connected => "connected",
        .closing => "closing",
        .closed => "closed",
    };
}

/// Not-ready envelope: the monitor contract has exactly two statuses
/// (spec 03 §10) and the UI shows "waiting for connection".
const monitor_not_ready = "{\"ok\":true,\"status\":\"not_ready\"}";

/// Cached snapshot, refreshed on demand: marks poll activity (the probe
/// liveness heartbeat) and enqueues one probe when the cache is stale and
/// none is running. Never blocks on the network.
fn handleMonitorPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(IdPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();

    const session = self.manager.get(parsed.value.server_id) orelse return monitor_not_ready;
    if (session.status.load(.acquire) != .ready) return monitor_not_ready;

    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    session.monitor_last_poll_ns.store(now, .release);
    // Refresh-if-stale: enqueue one probe when the cache is stale and no
    // probe is already running (spec 03 §6).
    if (now - session.monitor_last_probe_ns.load(.acquire) >= session.monitor_interval_ns and
        !session.monitor_probe_active.load(.acquire))
    {
        session.monitor_force.store(true, .release);
    }

    session.monitor_cache.lock();
    defer session.monitor_cache.unlock();
    const snap = session.monitor_cache.current() orelse &monitor_empty_snapshot;
    var writer = std.Io.Writer.fixed(output);
    // Spec 03 §5: the snapshot fields are the payload, flat with `ok`.
    const payload = .{
        .ok = true,
        .ts = snap.ts,
        .cpu = snap.cpu,
        .mem = snap.mem,
        .disk = snap.disk,
        .processes = snap.processes,
        .probe_error = snap.probe_error,
    };
    std.json.Stringify.value(payload, .{}, &writer) catch return output[0..0];
    return writer.buffered();
}

/// Honest "no sample yet" state: real zeros and an explicit reason, never
/// fabricated gauge values.
const monitor_empty_snapshot = monitor.Snapshot{ .probe_error = "no sample yet" };

/// Manual refresh: enqueues a probe immediately.
fn handleMonitorProbe(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(IdPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    self.manager.monitorForce(parsed.value.server_id, now) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
        });
    };
    return ok_json;
}

/// Read-only preview for a disk plan (spec 03 §6: each plan has its own
/// preview before any cleanup runs). Output streams on the channel.
fn handleMonitorCleanDiskEstimate(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(CleanDiskPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const plan = monitor.DiskPlan.fromJsonName(parsed.value.plan) orelse {
        return respondError(output, "unknown disk plan");
    };
    const channel_id = self.manager.exec(parsed.value.server_id, plan.estimateCommand()) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "estimate failed",
        });
    };
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel_id}) catch return output[0..0];
    return writer.buffered();
}

const CleanDiskPayload = struct {
    server_id: []const u8,
    plan: []const u8,
};

/// Mutating disk cleanup for one fixed plan (spec 03 §6). Approval is the
/// frontend's confirmation; every execution is audited.
fn handleMonitorCleanDisk(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(CleanDiskPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const plan = monitor.DiskPlan.fromJsonName(parsed.value.plan) orelse {
        return respondError(output, "unknown disk plan");
    };
    const channel_id = self.manager.execTracked(parsed.value.server_id, plan.command(), "monitor", null, &.{}) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "cleanup failed",
        });
    };
    var detail_buf: [64]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "plan={s}", .{plan.jsonName()}) catch "plan";
    self.audit.append(self.io, "monitor.clean_disk", parsed.value.server_id, detail) catch {
        return respondError(output, "cleanup ran but the audit entry could not be written");
    };
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel_id}) catch return output[0..0];
    return writer.buffered();
}

const DropCachesPayload = struct {
    server_id: []const u8,
    level: u8 = monitor.drop_cache_default,
};

/// Advanced diagnostics: `sync` then write the selected kernel-documented
/// value to /proc/sys/vm/drop_caches (spec 03 §6). The exact choice and the
/// before snapshot are audited at issue time; the worker records the after
/// snapshot when the forced probe completes.
fn handleMonitorDropCaches(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DropCachesPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const level = parsed.value.level;
    if (level < 1 or level > 3) return respondError(output, "drop-caches level must be 1, 2, or 3");

    const session = self.manager.get(parsed.value.server_id) orelse {
        return respondError(output, "not connected");
    };
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");

    // Before snapshot for the audit record.
    session.monitor_cache.lock();
    const before = if (session.monitor_cache.current()) |s| s.* else monitor.Snapshot{};
    session.monitor_cache.unlock();

    var cmd_buf: [64]u8 = undefined;
    const command = std.fmt.bufPrint(&cmd_buf, monitor.drop_cache_command, .{level}) catch {
        return respondError(output, "invalid drop-caches level");
    };
    const channel_id = self.manager.execTracked(parsed.value.server_id, command, "monitor", null, &.{}) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "drop-caches failed",
        });
    };

    var detail_buf: [512]u8 = undefined;
    const detail = std.fmt.bufPrint(
        &detail_buf,
        "level={d} before_mem_used_bytes={d} before_mem_available_bytes={d}",
        .{ level, before.mem.used_bytes, before.mem.available_bytes },
    ) catch "drop_caches";
    self.audit.append(self.io, "monitor.drop_caches", parsed.value.server_id, detail) catch {
        return respondError(output, "drop-caches ran but the audit entry could not be written");
    };
    session.monitor_drop_pending.store(true, .release);
    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    self.manager.monitorForce(parsed.value.server_id, now) catch {};

    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel_id}) catch return output[0..0];
    return writer.buffered();
}

// --- logs (spec 04) --------------------------------------------------------

const LogsIdPayload = struct {
    server_id: []const u8,
};

const LogsPathPayload = struct {
    server_id: []const u8,
    path: []const u8,
};

const logs_scan_timeout_ns = 15 * std.time.ns_per_s;
const logs_read_timeout_ns = 10 * std.time.ns_per_s;
const logs_clear_wait_ns = 20 * std.time.ns_per_s;
/// Read byte cap: the SDK result buffer is 1 MB and escaped JSON needs
/// headroom, so a full 5,000-line response cannot exceed this (spec 04 §5).
const logs_read_byte_cap: usize = 160 * 1024;
const logs_scan_cmd_cap: usize = 256 * 1024;
const logs_readability_cmd_cap: usize = 128 * 1024;

/// The scan is ONE exec, marker-delimited like the monitor probe:
/// `%BEGIN_DATE%` carries the remote clock (ages are computed against it,
/// never the local workstation clock) and `%BEGIN_SCAN%` carries NUL-
/// delimited records (`path\0size\0mtime\0mode\0`). Markers are emitted
/// with `%%` escapes — busybox printf errors on `%B`-style directives, so
/// a bare `%BEGIN_X%` format prints nothing (verified live); `%%` works on
/// both busybox and GNU. The GNU `find -printf` form and the busybox
/// `-print0` + `stat` fallback are joined with `||` (not `;`): a find
/// without `-printf` fails over instead of emitting two streams. The
/// trailing `printf '\0'` makes an empty tree parse as zero records
/// instead of degrading to the bare-path fallback.
const logs_scan_prefix = "printf '%%BEGIN_DATE%%\\n'; date +%s; printf '%%BEGIN_SCAN%%\\n'; find ";
const logs_scan_middle = " -maxdepth 3 -type f -printf '%p\\0%s\\0%T@\\0%m\\0' 2>/dev/null || find ";
const logs_scan_suffix = " -maxdepth 3 -type f -print0 2>/dev/null | while IFS= read -r -d '' p; do printf '%s\\0' \"$p\"; (stat -c '%s %Y %a' \"$p\" 2>/dev/null || printf '0 0 0\\n') | tr ' \\n' '\\000\\000'; done; printf '\\0'";

const logs_empty_result = logs.ScanResult{};

/// Serializes a scan result. The caller must own `result` (or hold the
/// cache lock) for the duration. Returns an empty slice only on a
/// response-budget failure (the caller turns that into an explicit error).
fn writeScanResult(output: []u8, result: *const logs.ScanResult) []const u8 {
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"sources\":[") catch return output[0..0];
    for (result.entries, 0..) |entry, i| {
        if (i > 0) writer.writeAll(",") catch return output[0..0];
        writer.writeAll("{\"path\":") catch return output[0..0];
        json.writeJsonString(&writer, entry.path) catch return output[0..0];
        writer.writeAll(",\"group\":") catch return output[0..0];
        json.writeJsonString(&writer, entry.group) catch return output[0..0];
        writer.writeAll(",\"name\":") catch return output[0..0];
        json.writeJsonString(&writer, entry.name) catch return output[0..0];
        writer.print(",\"size\":{d},\"mtime_epoch\":{d},\"age_sec\":{d},\"mode\":{d},\"readable\":{s}", .{
            entry.size,                              entry.mtime_epoch, entry.age_sec, entry.mode,
            if (entry.readable) "true" else "false",
        }) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.print("],\"partial\":{s},\"reason\":", .{if (result.partial) "true" else "false"}) catch return output[0..0];
    json.writeJsonString(&writer, result.reason) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

/// Scans documented log locations (spec 04 §5): one exec, cached per
/// session for 60 s; the cache serves repeats without network traffic.
fn handleLogsScan(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(LogsIdPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const server_id = parsed.value.server_id;

    const session = self.manager.get(server_id) orelse {
        return respondError(output, "not connected");
    };
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");

    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;

    // Serve the 60 s cache when fresh (spec 04 §4). The result strings are
    // owned by the cache, so serialization happens under its lock.
    session.logs_cache.lock();
    if (session.logs_cache.fresh(now)) {
        const cached = session.logs_cache.get() orelse &logs_empty_result;
        const written = writeScanResult(output, cached);
        session.logs_cache.unlock();
        return written;
    }
    session.logs_cache.unlock();

    // Fresh scan. Roots = the documented /var/log tree + user-added paths
    // (spec 04 §5: the scan includes user-added sources).
    const added = self.logs.pathsFor(self.io, server_id) catch {
        return respondError(output, "failed to load log sources");
    };
    defer {
        for (added) |p| self.allocator.free(p);
        self.allocator.free(added);
    }

    var roots: std.ArrayList(u8) = .empty;
    defer roots.deinit(self.allocator);
    roots.appendSlice(self.allocator, "'/var/log'") catch {
        return respondError(output, "out of memory");
    };
    for (added) |p| {
        const qlen = shellquote.quotedLen(p);
        if (roots.items.len + qlen + 1 > logs_scan_cmd_cap) break;
        roots.append(self.allocator, ' ') catch {
            return respondError(output, "out of memory");
        };
        var scratch: [64 * 1024]u8 = undefined;
        if (qlen > scratch.len) break;
        roots.appendSlice(self.allocator, shellquote.quoteAppend(&scratch, p)) catch {
            return respondError(output, "out of memory");
        };
    }

    var cmd_buf: [logs_scan_cmd_cap]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "{s}{s}{s}{s}{s}", .{
        logs_scan_prefix, roots.items, logs_scan_middle, roots.items, logs_scan_suffix,
    }) catch {
        return respondError(output, "scan roots too large");
    };

    var outcome = self.manager.execWait(server_id, cmd, logs.max_scan_bytes, logs_scan_timeout_ns) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "scan failed",
        });
    };
    defer outcome.output.deinit(self.allocator);
    if (outcome.limited) return respondError(output, "scan output exceeded the capture cap");
    if (outcome.exit != 0) return respondError(output, "scan command failed");
    if (outcome.output.items.len == 0) return respondError(output, "scan returned no output");

    var result_owned = false;
    var result = logs.parseScanOutput(self.allocator, outcome.output.items) catch {
        return respondError(output, "scan output could not be parsed");
    };
    defer if (!result_owned) result.deinit(self.allocator);

    // Batched readability probe (spec 04 §5: `test -r` per source; only
    // the first max_probe_paths entries, paths that fit the command
    // budget). Unprobed entries stay readable:false — honest, never a lie.
    var probe_buf: [logs_readability_cmd_cap]u8 = undefined;
    var probe_len: usize = 0;
    var probed: usize = 0;
    for (result.entries, 0..) |entry, i| {
        if (i >= logs.max_probe_paths) break;
        const qlen = shellquote.quotedLen(entry.path);
        if (qlen > probe_buf.len or probe_len + qlen + 40 > probe_buf.len) break;
        const head = std.fmt.bufPrint(probe_buf[probe_len..], "test -r ", .{}) catch break;
        probe_len += head.len;
        const q = shellquote.quoteAppend(probe_buf[probe_len..], entry.path);
        probe_len += q.len;
        const tail = std.fmt.bufPrint(probe_buf[probe_len..], " && echo 1 || echo 0; ", .{}) catch break;
        probe_len += tail.len;
        probed += 1;
    }
    if (probed > 0) {
        var probe_outcome = self.manager.execWait(server_id, probe_buf[0..probe_len], 64 * 1024, logs_read_timeout_ns) catch |err| {
            return respondError(output, switch (err) {
                error.NoSession => "not connected",
                error.NotReady => "session not ready",
                else => "readability probe failed",
            });
        };
        defer probe_outcome.output.deinit(self.allocator);
        logs.applyReadability(result.entries[0..probed], probe_outcome.output.items);
    }

    const written = writeScanResult(output, &result);
    if (written.len == 0) return respondError(output, "scan results too large");
    // The cache takes ownership of `result` from here on.
    session.logs_cache.store(self.allocator, result, now);
    result_owned = true;
    return written;
}

const LogsReadPayload = struct {
    server_id: []const u8,
    path: []const u8,
    lines: u32 = 200,
};

const allowed_log_read_lines = [_]u32{ 200, 500, 1000, 5000 };

/// Validates a log path for the path-taking handlers; returns the error
/// response on failure, null on success.
fn validateLogPath(payload_path: []const u8, output: []u8) ?[]const u8 {
    logs.validatePath(payload_path) catch |err| {
        return respondError(output, switch (err) {
            error.RelativePath => "path must be absolute",
            error.InvalidChar => "path contains control characters",
            error.TrailingSlash => "path must not end with '/'",
        });
    };
    return null;
}

/// Reads the last N lines of a log (spec 04 §5: `tail -n <lines>`, lines ∈
/// {200, 500, 1000, 5000}); the byte cap sets `limited` honestly.
fn handleLogsRead(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(LogsReadPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    if (validateLogPath(payload.path, output)) |err_response| return err_response;
    var allowed = false;
    for (allowed_log_read_lines) |l| {
        if (payload.lines == l) {
            allowed = true;
            break;
        }
    }
    if (!allowed) return respondError(output, "line count must be 200, 500, 1000, or 5000");

    var cmd_buf: [64 * 1024]u8 = undefined;
    const qlen = shellquote.quotedLen(payload.path);
    if (qlen > cmd_buf.len or qlen + 32 > cmd_buf.len) return respondError(output, "path too long");
    const head = std.fmt.bufPrint(&cmd_buf, "tail -n {d} ", .{payload.lines}) catch unreachable;
    const q = shellquote.quoteAppend(cmd_buf[head.len..], payload.path);

    var outcome = self.manager.execWait(payload.server_id, cmd_buf[0 .. head.len + q.len], logs_read_byte_cap, logs_read_timeout_ns) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "read failed",
        });
    };
    defer outcome.output.deinit(self.allocator);
    if (outcome.exit != 0) return respondError(output, "file is missing or unreadable");

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"path\":") catch return output[0..0];
    json.writeJsonString(&writer, payload.path) catch return output[0..0];
    const binary = logs.isBinaryContent(outcome.output.items);
    writer.writeAll(",\"binary\":") catch return output[0..0];
    writer.writeAll(if (binary) "true" else "false") catch return output[0..0];
    writer.writeAll(",\"lines\":[") catch return output[0..0];
    // Split on newlines; a trailing newline's empty remainder is not a line,
    // but empty lines in the middle of the file are preserved.
    const text = if (binary) "" else outcome.output.items;
    var start: usize = 0;
    var first = true;
    while (std.mem.indexOfScalarPos(u8, text, start, '\n')) |nl| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        json.writeJsonString(&writer, text[start..nl]) catch return output[0..0];
        start = nl + 1;
    }
    if (start < text.len) {
        if (!first) writer.writeAll(",") catch return output[0..0];
        json.writeJsonString(&writer, text[start..]) catch return output[0..0];
    }
    writer.writeAll("],\"limited\":") catch return output[0..0];
    writer.writeAll(if (outcome.limited) "true" else "false") catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

/// Starts a follow channel (spec 04 §5: `tail -n 100 -F` — name-follow with
/// retry, so normal rotation reopens the new file; verified on both GNU and
/// busybox). Output streams via oars.ssh.poll with kind `log`.
fn handleLogsFollow(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(LogsPathPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    if (validateLogPath(payload.path, output)) |err_response| return err_response;

    var cmd_buf: [64 * 1024]u8 = undefined;
    const qlen = shellquote.quotedLen(payload.path);
    if (qlen > cmd_buf.len or qlen + 32 > cmd_buf.len) return respondError(output, "path too long");
    const head = std.fmt.bufPrint(&cmd_buf, "tail -n 100 -F ", .{}) catch unreachable;
    const q = shellquote.quoteAppend(cmd_buf[head.len..], payload.path);
    const channel_id = self.manager.follow(payload.server_id, cmd_buf[0 .. head.len + q.len]) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "follow failed",
        });
    };
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel_id}) catch return output[0..0];
    return writer.buffered();
}

const LogsClearPayload = struct {
    server_id: []const u8,
    path: []const u8,
    expected: struct {
        size: u64,
        mtime: u64,
        mode: u32,
    },
};

/// Identity-bound truncate (spec 04 §5): the worker SFTP-lstats the path,
/// rejects symlinks/non-regular files, opens WITHOUT truncation, fstats the
/// handle, compares size/mtime/mode against the preview (a mismatch stops
/// with a conflict), and only then sets the size to zero. The audit entry
/// is written by the worker. The handler waits on the outcome with a
/// deadline — the op may not run if the session dies first.
fn handleLogsClear(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(LogsClearPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    if (validateLogPath(payload.path, output)) |err_response| return err_response;

    const outcome = self.allocator.create(sessions.ClearOutcome) catch return respondError(output, "out of memory");
    outcome.* = .{ .allocator = self.allocator };
    self.manager.clearLog(payload.server_id, payload.path, .{
        .size = payload.expected.size,
        .mtime = payload.expected.mtime,
        .mode = payload.expected.mode,
    }, outcome) catch |err| {
        self.allocator.destroy(outcome);
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "clear failed",
        });
    };
    const deadline = std.Io.Timestamp.now(self.io, .real).nanoseconds + logs_clear_wait_ns;
    outcome.wait(self.io, deadline);
    // A clear attempt means the file's identity may have changed, so the
    // 60 s scan cache must not serve the old preview on a re-scan — the
    // spec's rescan-after-conflict flow requires a fresh result.
    if (self.manager.get(payload.server_id)) |session| {
        session.logs_cache.invalidate(self.allocator);
    }
    // On a deadline the op keeps the outcome (its eventual set frees it);
    // otherwise it is destroyed after the result is read.
    if (!outcome.isDone() and !outcome.abandon()) return respondError(output, "timed out waiting for the server");
    defer self.allocator.destroy(outcome);
    if (!outcome.ok) return respondError(output, outcome.message());

    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"before_size\":{d},\"after_size\":{d}}}", .{ outcome.before_size, outcome.after_size }) catch return output[0..0];
    return writer.buffered();
}

/// Persists a user-added log path per server (spec 04 §5). Adding a source
/// invalidates the scan cache so the next scan picks it up.
fn handleLogsAddSource(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(LogsPathPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    const path = std.mem.trim(u8, payload.path, " \t\r\n");
    if (validateLogPath(path, output)) |err_response| return err_response;

    self.logs.addSource(self.io, payload.server_id, path) catch {
        return respondError(output, "failed to save log source");
    };
    if (self.manager.get(payload.server_id)) |session| {
        session.logs_cache.invalidate(self.allocator);
    }
    return ok_json;
}

// --- Local files (spec 05 two-pane browser) ---------------------------------

const LocalLsPayload = struct { path: []const u8 };

fn handleLocalLs(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(LocalLsPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var listing = localfs.list(self.allocator, self.io, parsed.value.path) catch |err| {
        return respondError(output, switch (err) {
            error.InvalidPath => "select an absolute local folder",
            error.FileNotFound => "local folder not found",
            error.AccessDenied => "permission denied for this local folder",
            error.NotDir => "the selected local path is not a folder",
            else => "cannot read this local folder",
        });
    };
    defer listing.deinit(self.allocator);

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"entries\":[") catch return output[0..0];
    for (listing.entries, 0..) |entry, index| {
        if (index > 0) writer.writeByte(',') catch return output[0..0];
        writer.writeAll("{\"name\":") catch return output[0..0];
        json.writeJsonString(&writer, entry.name) catch return output[0..0];
        writer.writeAll(",\"path\":") catch return output[0..0];
        json.writeJsonString(&writer, entry.path) catch return output[0..0];
        writer.writeAll(",\"kind\":") catch return output[0..0];
        json.writeJsonString(&writer, entry.kind.jsonName()) catch return output[0..0];
        writer.print(",\"size\":{d},\"mtime\":{d}}}", .{ entry.size, entry.mtime }) catch return output[0..0];
    }
    writer.print("],\"truncated\":{s}}}", .{if (listing.truncated) "true" else "false"}) catch return output[0..0];
    return writer.buffered();
}

// --- SFTP (spec 05) ----------------------------------------------------------

const sftp_wait_ns = 20 * std.time.ns_per_s;
const sftp_folder_size_timeout_ns = 60 * std.time.ns_per_s;
const sftp_folder_size_cache_ns = 5 * std.time.ns_per_min;
const sftp_folder_size_cmd_cap: usize = 4 * 1024;

const SftpPathPayload = struct {
    server_id: []const u8,
    path: sftpmod.RemotePathJson,
};

const SftpReadPayload = struct {
    server_id: []const u8,
    path: sftpmod.RemotePathJson,
    offset: u64 = 0,
    max: usize = sftpmod.chunk_size,
};

const SftpWritePayload = struct {
    server_id: []const u8,
    path: sftpmod.RemotePathJson,
    offset: u64 = 0,
    base64: []const u8,
    transfer_id: u32,
    total: ?u64 = null,
};

const SftpSavePayload = struct {
    server_id: []const u8,
    path: sftpmod.RemotePathJson,
    base64: []const u8,
    /// Editor conflict preflight (spec 05 §4.2): when any expected field
    /// is present, the worker refuses the save with a "conflict:" error if
    /// the remote file no longer matches the identity the editor opened.
    expected_size: ?u64 = null,
    expected_mtime: ?u64 = null,
    expected_sha256: ?[]const u8 = null,
};

const SftpDownloadPayload = struct {
    server_id: []const u8,
    remote_path: sftpmod.RemotePathJson,
    local_path: []const u8,
};

const SftpUploadLocalPayload = struct {
    server_id: []const u8,
    local_path: []const u8,
    remote_path: sftpmod.RemotePathJson,
};

const SftpRmPayload = struct {
    server_id: []const u8,
    path: sftpmod.RemotePathJson,
    recursive: bool = false,
};

const SftpRenamePayload = struct {
    server_id: []const u8,
    from: sftpmod.RemotePathJson,
    to: sftpmod.RemotePathJson,
};

const SftpChmodPayload = struct {
    server_id: []const u8,
    path: sftpmod.RemotePathJson,
    mode: u32,
};

const SftpUnzipPayload = struct {
    server_id: []const u8,
    zip_path: sftpmod.RemotePathJson,
    dest_dir: ?sftpmod.RemotePathJson = null,
    overwrite: bool = false,
};

const SftpZipDownloadPayload = struct {
    server_id: []const u8,
    paths: []const sftpmod.RemotePathJson,
    local_path: []const u8,
};

const SftpTransferIdPayload = struct {
    server_id: []const u8,
    transfer_id: u32,
};

/// Decodes + validates a RemotePath (spec 05 §5). On failure writes the
/// error response and returns it; on success stores the owned raw bytes in
/// `out_path` and returns null.
fn decodeSftpPathArg(self: *Context, output: []u8, path: sftpmod.RemotePathJson, out_path: *?[]u8) ?[]const u8 {
    const raw = sftpmod.decodeRemotePath(self.allocator, path) catch |err| {
        return respondError(output, switch (err) {
            error.NoPath => "path is required",
            error.InvalidBase64 => "invalid base64 path",
            error.InvalidPath => "path contains control characters",
            error.OutOfMemory => "out of memory",
        });
    };
    sftpmod.validatePath(raw) catch |err| {
        self.allocator.free(raw);
        return respondError(output, switch (err) {
            error.NoPath => "path is required",
            error.InvalidPath => "path contains control characters",
            else => "invalid path",
        });
    };
    out_path.* = raw;
    return null;
}

/// Validates a LOCAL path (the native save dialog result). Returns the
/// error response on failure, null on success.
fn validateSftpLocalPathArg(output: []u8, path: []const u8) ?[]const u8 {
    sftpmod.validateLocalPath(path) catch |err| {
        return respondError(output, switch (err) {
            error.NoPath => "local path is required",
            error.InvalidPath => "local path must be absolute and free of control characters",
            else => "invalid local path",
        });
    };
    return null;
}

/// Decodes a base64 payload (chunk or editor save). On failure writes the
/// error response and returns it; on success stores the owned bytes in
/// `out_data` and returns null.
fn decodeSftpBase64Arg(self: *Context, output: []u8, b64: []const u8, max: usize, out_data: *?[]u8) ?[]const u8 {
    const size = std.base64.standard.Decoder.calcSizeForSlice(b64) catch {
        return respondError(output, "invalid base64");
    };
    if (size > max) return respondError(output, "chunk too large");
    const buf = self.allocator.alloc(u8, size) catch {
        return respondError(output, "out of memory");
    };
    std.base64.standard.Decoder.decode(buf, b64) catch {
        self.allocator.free(buf);
        return respondError(output, "invalid base64");
    };
    out_data.* = buf;
    return null;
}

/// Waits for a synchronous SFTP outcome (bounded), then copies the
/// worker-built JSON into the output buffer and frees it. Takes ownership
/// of the heap outcome: on a deadline the op keeps it (its eventual set
/// frees it — see SftpOutcome's lifetime doc), otherwise it is destroyed
/// here after the result is read.
fn sftpSyncOutcome(self: *Context, output: []u8, outcome: *sessions.SftpOutcome) []const u8 {
    const deadline = std.Io.Timestamp.now(self.io, .real).nanoseconds + sftp_wait_ns;
    outcome.wait(self.io, deadline);
    if (!outcome.isDone() and !outcome.abandon()) return respondError(output, "timed out waiting for the server");
    defer self.allocator.destroy(outcome);
    if (!outcome.ok) return respondError(output, outcome.message());
    const payload_json = outcome.json orelse return respondError(output, "no response payload");
    defer self.allocator.free(payload_json);
    if (payload_json.len > output.len) return respondError(output, "response too large");
    @memcpy(output[0..payload_json.len], payload_json);
    return output[0..payload_json.len];
}

/// Maps queueing errors to user-facing messages.
fn sftpQueueError(output: []u8, err: anyerror) []const u8 {
    return respondError(output, switch (err) {
        error.NoSession => "not connected",
        error.NotReady => "session not ready",
        else => "sftp failed",
    });
}

/// Marks a transfer record failed (queue failure after the record was
/// created, so poll never shows it stuck as queued).
fn sftpFailTransfer(session: *sessions.Session, op_id: u32, msg: []const u8) void {
    session.sftp_transfers.lock();
    if (session.sftp_transfers.get(op_id)) |t| {
        t.status = .failed;
        t.err = msg;
    }
    session.sftp_transfers.unlock();
}

/// `{ok, op_id}` response for async ops.
fn sftpOpIdResponse(output: []u8, op_id: u32) []const u8 {
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"op_id\":{d}}}", .{op_id}) catch return output[0..0];
    return writer.buffered();
}

/// `<dir>/<zip stem>` for Expand-in-place (spec 05 §5: a folder named after
/// the archive appears next to it).
fn sftpDefaultDest(allocator: std.mem.Allocator, zip_path: []const u8) ![]u8 {
    const base = std.fs.path.basename(zip_path);
    var stem = base;
    if (std.mem.lastIndexOfScalar(u8, base, '.')) |dot| {
        if (dot > 0) stem = base[0..dot];
    }
    if (std.fs.path.dirname(zip_path)) |dir| {
        if (dir.len == 0) return allocator.dupe(u8, stem);
        if (std.mem.eql(u8, dir, "/")) return std.fmt.allocPrint(allocator, "/{s}", .{stem});
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, stem });
    }
    return allocator.dupe(u8, stem);
}

fn handleSftpLs(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpPathPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    const outcome = self.allocator.create(sessions.SftpOutcome) catch return respondError(output, "out of memory");
    outcome.* = .{ .allocator = self.allocator };
    self.manager.sftpLs(parsed.value.server_id, path.?, outcome) catch |err| {
        self.allocator.destroy(outcome);
        return sftpQueueError(output, err);
    };
    return sftpSyncOutcome(self, output, outcome);
}

fn handleSftpStat(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpPathPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    const outcome = self.allocator.create(sessions.SftpOutcome) catch return respondError(output, "out of memory");
    outcome.* = .{ .allocator = self.allocator };
    self.manager.sftpStat(parsed.value.server_id, path.?, outcome) catch |err| {
        self.allocator.destroy(outcome);
        return sftpQueueError(output, err);
    };
    return sftpSyncOutcome(self, output, outcome);
}

/// Explicit-offset 64 KB read (spec 05 §5); the worker answers with
/// `{ok, base64, eof}`.
fn handleSftpRead(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpReadPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    if (parsed.value.max == 0 or parsed.value.max > sftpmod.chunk_size) {
        return respondError(output, "max must be between 1 and 65536 bytes");
    }
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    const outcome = self.allocator.create(sessions.SftpOutcome) catch return respondError(output, "out of memory");
    outcome.* = .{ .allocator = self.allocator };
    self.manager.sftpRead(parsed.value.server_id, path.?, parsed.value.offset, parsed.value.max, outcome) catch |err| {
        self.allocator.destroy(outcome);
        return sftpQueueError(output, err);
    };
    return sftpSyncOutcome(self, output, outcome);
}

/// Upload chunk under the frontend's unguessable transfer_id (spec 05 §5):
/// the first chunk registers the transfer, the last chunk no-clobber
/// renames `<path>.partial` into place.
fn handleSftpWrite(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpWritePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.transfer_id == 0) return respondError(output, "invalid transfer id");
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, payload.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    var data: ?[]u8 = null;
    if (decodeSftpBase64Arg(self, output, payload.base64, sftpmod.chunk_size, &data)) |err_response| return err_response;
    defer self.allocator.free(data.?);

    const session = self.manager.get(payload.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    self.manager.sftpStartUpload(session, payload.transfer_id, path.?) catch return respondError(output, "out of memory");
    const total = payload.total orelse (payload.offset +| data.?.len);
    const outcome = self.allocator.create(sessions.SftpOutcome) catch return respondError(output, "out of memory");
    outcome.* = .{ .allocator = self.allocator };
    self.manager.sftpWriteChunk(payload.server_id, path.?, payload.offset, data.?, total, payload.transfer_id, outcome) catch |err| {
        self.allocator.destroy(outcome);
        return sftpQueueError(output, err);
    };
    return sftpSyncOutcome(self, output, outcome);
}

/// Editor save (spec 05 §4.2): temp file + atomic posix-rename on the
/// worker; refusal when the server lacks the extension. An expected
/// identity (size/mtime/sha256) makes the save refuse with a conflict
/// error when the remote file changed since the editor opened it.
fn handleSftpSave(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpSavePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    if (parsed.value.expected_sha256) |h| {
        if (h.len != 64) return respondError(output, "invalid expected hash");
    }
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    var data: ?[]u8 = null;
    if (decodeSftpBase64Arg(self, output, parsed.value.base64, sftpmod.max_inline_bytes, &data)) |err_response| return err_response;
    defer self.allocator.free(data.?);
    const outcome = self.allocator.create(sessions.SftpOutcome) catch return respondError(output, "out of memory");
    outcome.* = .{ .allocator = self.allocator };
    const has_expected = parsed.value.expected_size != null or parsed.value.expected_mtime != null or parsed.value.expected_sha256 != null;
    const expected: ?sessions.SftpExpectedIdentity = if (has_expected) .{
        .size = parsed.value.expected_size,
        .mtime = parsed.value.expected_mtime,
        .sha256 = parsed.value.expected_sha256,
    } else null;
    self.manager.sftpSave(
        parsed.value.server_id,
        path.?,
        data.?,
        expected,
        outcome,
    ) catch |err| {
        self.allocator.destroy(outcome);
        return sftpQueueError(output, err);
    };
    return sftpSyncOutcome(self, output, outcome);
}

/// Remote→local download through the native writer: the core owns the
/// `<local>.partial` file and no-clobber renames it only after success
/// (spec 05 §5). Async — progress rides the transfer record.
fn handleSftpDownload(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpDownloadPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (validateSftpLocalPathArg(output, payload.local_path)) |err_response| return err_response;
    var remote: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, payload.remote_path, &remote)) |err_response| return err_response;
    defer self.allocator.free(remote.?);
    const partial = std.fmt.allocPrint(self.allocator, "{s}.partial", .{payload.local_path}) catch return respondError(output, "out of memory");
    defer self.allocator.free(partial);

    const session = self.manager.get(payload.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    const op_id = self.manager.sftpStartTransfer(session, "download", remote.?) catch return respondError(output, "out of memory");
    self.manager.sftpDownload(payload.server_id, remote.?, partial, payload.local_path, op_id, null) catch |err| {
        sftpFailTransfer(session, op_id, "failed to queue");
        return sftpQueueError(output, err);
    };
    return sftpOpIdResponse(output, op_id);
}

/// Local→remote transfer from a path returned by the native directory
/// picker. The worker reads the file directly; bytes never enter bridge JSON.
fn handleSftpUploadLocal(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpUploadLocalPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    localfs.validateAbsolutePath(payload.local_path) catch return respondError(output, "select an absolute local file");
    var remote: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, payload.remote_path, &remote)) |err_response| return err_response;
    defer self.allocator.free(remote.?);

    const session = self.manager.get(payload.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    const op_id = self.manager.sftpStartTransfer(session, "upload", remote.?) catch return respondError(output, "out of memory");
    self.manager.sftpUploadLocal(payload.server_id, payload.local_path, remote.?, op_id) catch |err| {
        sftpFailTransfer(session, op_id, "failed to queue");
        return sftpQueueError(output, err);
    };
    return sftpOpIdResponse(output, op_id);
}

fn handleSftpMkdir(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpPathPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    const outcome = self.allocator.create(sessions.SftpOutcome) catch return respondError(output, "out of memory");
    outcome.* = .{ .allocator = self.allocator };
    self.manager.sftpMkdir(parsed.value.server_id, path.?, outcome) catch |err| {
        self.allocator.destroy(outcome);
        return sftpQueueError(output, err);
    };
    return sftpSyncOutcome(self, output, outcome);
}

/// Plain delete is synchronous; recursive deletes run as an async transfer
/// with per-entry progress and cancel (spec 05 §5).
fn handleSftpRm(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpRmPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, payload.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);

    if (!payload.recursive) {
        const outcome = self.allocator.create(sessions.SftpOutcome) catch return respondError(output, "out of memory");
        outcome.* = .{ .allocator = self.allocator };
        self.manager.sftpRm(payload.server_id, path.?, false, 0, outcome) catch |err| {
            self.allocator.destroy(outcome);
            return sftpQueueError(output, err);
        };
        return sftpSyncOutcome(self, output, outcome);
    }
    const session = self.manager.get(payload.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    const op_id = self.manager.sftpStartTransfer(session, "rm", path.?) catch return respondError(output, "out of memory");
    // The worker's recursive path never writes an outcome; it signals
    // through the transfer record instead.
    self.manager.sftpRm(payload.server_id, path.?, true, op_id, null) catch |err| {
        sftpFailTransfer(session, op_id, "failed to queue");
        return sftpQueueError(output, err);
    };
    return sftpOpIdResponse(output, op_id);
}

fn handleSftpRename(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpRenamePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var from: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.from, &from)) |err_response| return err_response;
    defer self.allocator.free(from.?);
    var to: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.to, &to)) |err_response| return err_response;
    defer self.allocator.free(to.?);
    const outcome = self.allocator.create(sessions.SftpOutcome) catch return respondError(output, "out of memory");
    outcome.* = .{ .allocator = self.allocator };
    self.manager.sftpRename(parsed.value.server_id, from.?, to.?, outcome) catch |err| {
        self.allocator.destroy(outcome);
        return sftpQueueError(output, err);
    };
    return sftpSyncOutcome(self, output, outcome);
}

fn handleSftpChmod(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpChmodPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.mode & ~@as(u32, 0o7777) != 0) return respondError(output, "invalid mode");
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, payload.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    const outcome = self.allocator.create(sessions.SftpOutcome) catch return respondError(output, "out of memory");
    outcome.* = .{ .allocator = self.allocator };
    self.manager.sftpChmod(payload.server_id, path.?, payload.mode, outcome) catch |err| {
        self.allocator.destroy(outcome);
        return sftpQueueError(output, err);
    };
    return sftpSyncOutcome(self, output, outcome);
}

/// Expand in place (spec 05 §5): central-directory preflight on the worker,
/// overwrite disabled, extraction into `dest_dir` (defaults to a folder
/// named after the archive next to it). Async.
fn handleSftpUnzip(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpUnzipPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.overwrite) return respondError(output, "overwrite is not supported; choose an empty destination");
    var zip_path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, payload.zip_path, &zip_path)) |err_response| return err_response;
    defer self.allocator.free(zip_path.?);
    var dest: ?[]u8 = null;
    if (payload.dest_dir) |d| {
        if (decodeSftpPathArg(self, output, d, &dest)) |err_response| return err_response;
    } else {
        dest = sftpDefaultDest(self.allocator, zip_path.?) catch return respondError(output, "out of memory");
    }
    defer self.allocator.free(dest.?);

    const session = self.manager.get(payload.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    const op_id = self.manager.sftpStartTransfer(session, "unzip", zip_path.?) catch return respondError(output, "out of memory");
    self.manager.sftpUnzip(payload.server_id, zip_path.?, dest.?, op_id, null) catch |err| {
        sftpFailTransfer(session, op_id, "failed to queue");
        return sftpQueueError(output, err);
    };
    return sftpOpIdResponse(output, op_id);
}

/// Remote `zip -r` of the selected paths into a uniquely named staging
/// archive, downloaded through the native writer; the staging archive is
/// removed in success and failure (spec 05 §5). Async.
fn handleSftpZipDownload(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpZipDownloadPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.paths.len == 0) return respondError(output, "no paths");
    if (validateSftpLocalPathArg(output, payload.local_path)) |err_response| return err_response;

    var paths: std.ArrayList([]u8) = .empty;
    defer {
        for (paths.items) |p| self.allocator.free(p);
        paths.deinit(self.allocator);
    }
    for (payload.paths) |rp| {
        var p: ?[]u8 = null;
        if (decodeSftpPathArg(self, output, rp, &p)) |err_response| return err_response;
        paths.append(self.allocator, p.?) catch {
            self.allocator.free(p.?);
            return respondError(output, "out of memory");
        };
    }
    const partial = std.fmt.allocPrint(self.allocator, "{s}.partial", .{payload.local_path}) catch return respondError(output, "out of memory");
    defer self.allocator.free(partial);

    const session = self.manager.get(payload.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    const op_id = self.manager.sftpStartTransfer(session, "zip_download", paths.items[0]) catch return respondError(output, "out of memory");
    self.manager.sftpZipDownload(payload.server_id, paths.items, partial, payload.local_path, op_id, null) catch |err| {
        sftpFailTransfer(session, op_id, "failed to queue");
        return sftpQueueError(output, err);
    };
    return sftpOpIdResponse(output, op_id);
}

/// `du -sb <path>` parsed, cached 5 minutes per path (spec 05 §5).
fn handleSftpFolderSize(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpPathPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var path: ?[]u8 = null;
    if (decodeSftpPathArg(self, output, parsed.value.path, &path)) |err_response| return err_response;
    defer self.allocator.free(path.?);
    const session = self.manager.get(parsed.value.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    if (self.manager.sftpFolderSizeCached(session, path.?, now)) |size| {
        var writer = std.Io.Writer.fixed(output);
        writer.print("{{\"ok\":true,\"size\":{d}}}", .{size}) catch return output[0..0];
        return writer.buffered();
    }

    var cmd_buf: [64 * 1024]u8 = undefined;
    const qlen = shellquote.quotedLen(path.?);
    if (qlen + 16 > cmd_buf.len) return respondError(output, "path too long");
    const head = std.fmt.bufPrint(&cmd_buf, "du -sb ", .{}) catch unreachable;
    const q = shellquote.quoteAppend(cmd_buf[head.len..], path.?);
    var outcome = self.manager.execWait(parsed.value.server_id, cmd_buf[0 .. head.len + q.len], sftp_folder_size_cmd_cap, sftp_folder_size_timeout_ns) catch |err| return sftpQueueError(output, err);
    defer outcome.output.deinit(self.allocator);
    if (outcome.exit != 0 or outcome.output.items.len == 0) return respondError(output, "cannot measure folder size");
    const text = std.mem.trim(u8, outcome.output.items, " \t\r\n");
    const end = std.mem.indexOfAny(u8, text, " \t") orelse text.len;
    const size = std.fmt.parseInt(u64, text[0..end], 10) catch {
        return respondError(output, "cannot parse folder size");
    };
    self.manager.sftpFolderSizeCacheSet(session, path.?, size, now);
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"size\":{d}}}", .{size}) catch return output[0..0];
    return writer.buffered();
}

/// Non-destructive snapshot of active + recent transfers (spec 05 §5): two
/// views can poll without consuming each other's progress.
fn handleSftpPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(IdPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const session = self.manager.get(parsed.value.server_id) orelse {
        return respondError(output, "not connected");
    };
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"transfers\":[") catch return output[0..0];
    session.sftp_transfers.lock();
    defer session.sftp_transfers.unlock();
    var first = true;
    for (session.sftp_transfers.list.items) |t| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.print("{{\"id\":{d},\"kind\":", .{t.id}) catch return output[0..0];
        json.writeJsonString(&writer, t.kind) catch return output[0..0];
        writer.writeAll(",\"path\":") catch return output[0..0];
        json.writeJsonString(&writer, t.path) catch return output[0..0];
        writer.print(",\"bytes\":{d},\"total\":{d},\"status\":", .{ t.bytes_done, t.bytes_total }) catch return output[0..0];
        json.writeJsonString(&writer, t.status.jsonName()) catch return output[0..0];
        writer.writeAll(",\"error\":") catch return output[0..0];
        json.writeJsonString(&writer, t.err) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

/// Cancels an async transfer: the worker cleanup op deletes the upload
/// partial; long-running ops check the flag between entries.
fn handleSftpCancel(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SftpTransferIdPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.sftpCancel(parsed.value.server_id, parsed.value.transfer_id) catch |err| return sftpQueueError(output, err);
    return ok_json;
}

// --- scripts (spec 06) ---------------------------------------------------------

const scripts_run_check_timeout_ns = 30 * std.time.ns_per_s;
const scripts_check_cap: usize = 16 * 1024;
const scripts_poll_data_budget: usize = 256 * 1024;
const scripts_terminal_output_cap: usize = 200_000;

const ScriptsSavePayload = struct {
    script: scripts.ScriptInput,
};

const ScriptsValidatePayload = struct {
    body: []const u8,
};

const ScriptsIdPayload = struct {
    id: []const u8,
};

const ScriptsRunPayload = struct {
    server_id: []const u8,
    script_id: []const u8,
    vars: std.json.Value = .null,
};

const ScriptsBroadcastPayload = struct {
    script_id: []const u8,
    server_ids: []const []const u8,
    vars: std.json.Value = .null,
};

const ScriptsPreviewPayload = struct {
    preview_id: u32,
};

const ScriptsBroadcastPollPayload = struct {
    run_id: u32,
    cursors: std.json.Value = .null,
};

const ScriptsBroadcastCancelPayload = struct {
    run_id: u32,
};

const ScriptWire = struct {
    id: []const u8,
    name: []const u8,
    description: []const u8,
    tags: []const []const u8,
    color: []const u8,
    body: []const u8,
    variables: []const scripts.Variable,
    created_at: i64,
    updated_at: i64,
    run_count: u64,
    last_run_at: ?i64,
};

fn scriptWire(script: scripts.Script) ScriptWire {
    return .{
        .id = script.id,
        .name = script.name,
        .description = script.description,
        .tags = script.tags,
        .color = script.color,
        .body = script.body,
        .variables = script.variables,
        .created_at = @divTrunc(script.created_at, std.time.ns_per_ms),
        .updated_at = @divTrunc(script.updated_at, std.time.ns_per_ms),
        .run_count = script.run_count,
        .last_run_at = if (script.last_run_at) |stamp| @divTrunc(stamp, std.time.ns_per_ms) else null,
    };
}

/// Extracts `{name: {value, secret}}` from the payload. The returned
/// RunVars reference the parsed tree (valid until the parse is freed —
/// expansion happens before that). Returns the error response on failure.
fn scriptsVars(self: *Context, output: []u8, value: std.json.Value, out: *std.ArrayList(scripts.RunVar)) ?[]const u8 {
    if (value == .null) return null; // no variables
    if (value != .object) return respondError(output, "invalid vars payload");
    var it = value.object.iterator();
    while (it.next()) |entry| {
        const v: std.json.Value = entry.value_ptr.*;
        if (v != .object) return respondError(output, "invalid variable value");
        const value_field = v.object.get("value") orelse return respondError(output, "missing variable value");
        if (value_field != .string) return respondError(output, "invalid variable value");
        const secret = if (v.object.get("secret")) |s| s == .bool and s.bool else false;
        out.append(self.allocator, .{ .name = entry.key_ptr.*, .value = value_field.string, .secret = secret }) catch return respondError(output, "out of memory");
    }
    return null;
}

/// Appends one audit entry: script id/name, variable names, and the
/// redacted command (spec 06 §8 — secret values never written). Returns
/// the error response on failure.
fn scriptsAudit(self: *Context, output: []u8, action: []const u8, server_id: []const u8, script_id: []const u8, script_name: []const u8, names: []const scripts.NameInfo, redacted: []const u8) ?[]const u8 {
    var names_buf: std.ArrayList(u8) = .empty;
    defer names_buf.deinit(self.allocator);
    for (names, 0..) |n, i| {
        if (names_buf.items.len >= 256) break;
        if (i > 0) names_buf.append(self.allocator, ',') catch return respondError(output, "out of memory");
        names_buf.appendSlice(self.allocator, n.name) catch return respondError(output, "out of memory");
    }
    const redacted_trim = if (redacted.len > 1000) redacted[0..1000] else redacted;
    var detail_buf: [1800]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "script={s} name={s} vars={s} command={s}", .{ script_id, script_name, names_buf.items, redacted_trim }) catch "scripts.run";
    self.audit.append(self.io, action, server_id, detail) catch return respondError(output, "audit failed");
    return null;
}

/// Enforces the stored `secret_default` as the minimum policy (spec 06
/// §8): a caller may promote a value to secret but must not demote a
/// stored secret — a demoted value could otherwise reach audit or
/// history unmasked. Mutates the parsed RunVars in place.
fn scriptsEnforceSecrets(vars: *std.ArrayList(scripts.RunVar), definitions: []const scripts.Variable) void {
    for (vars.items) |*v| {
        if (v.secret) continue;
        for (definitions) |d| {
            if (std.mem.eql(u8, d.name, v.name) and d.secret_default) {
                v.secret = true;
                break;
            }
        }
    }
}

/// A script with an exact, case-insensitive `destructive` tag requires a
/// second confirmation (spec 06 §4.2). Color alone never marks a script
/// destructive.
fn scriptsDestructive(script: *const scripts.Script) bool {
    for (script.tags) |tag| {
        if (std.ascii.eqlIgnoreCase(tag, "destructive")) return true;
    }
    return false;
}

const LoadedExpansion = struct {
    /// Owned.
    script: scripts.Script,
    /// Owned.
    expansion: scripts.Expansion,

    pub fn deinit(self: *LoadedExpansion, allocator: std.mem.Allocator) void {
        scripts.deinit(allocator, &self.script);
        self.expansion.deinit(allocator);
    }
};

/// Loads the script, parses the payload vars, enforces stored secret
/// policy, and expands the template. No audit, no run state — pure
/// preparation (spec 06 §5: an uncommitted preview writes no audit row
/// and bumps no run count). On failure writes an error response and
/// returns null.
fn scriptsLoadAndExpand(
    self: *Context,
    output: []u8,
    err_response: *[]const u8,
    script_id: []const u8,
    vars: std.json.Value,
) ?LoadedExpansion {
    err_response.* = "";
    var owned_script = self.scripts.find(self.io, script_id) catch {
        err_response.* = respondError(output, "script library is unreadable");
        return null;
    } orelse {
        err_response.* = respondError(output, "script not found");
        return null;
    };

    var var_list: std.ArrayList(scripts.RunVar) = .empty;
    defer var_list.deinit(self.allocator);
    if (scriptsVars(self, output, vars, &var_list)) |resp| {
        scripts.deinit(self.allocator, &owned_script);
        err_response.* = resp;
        return null;
    }
    scriptsEnforceSecrets(&var_list, owned_script.variables);

    var missing: []const u8 = undefined;
    const expansion = scripts.expandTemplate(self.allocator, owned_script.body, var_list.items, &missing) catch |err| {
        // The message bytes are copied into `output` by respondError
        // BEFORE the script (which owns the missing-name slice) is freed.
        err_response.* = respondError(output, switch (err) {
            error.MissingVariable => blk: {
                var buf: [256]u8 = undefined;
                break :blk std.fmt.bufPrint(&buf, "missing variable: {s}", .{missing}) catch "missing variable";
            },
            error.MultilineValue => "multiline variable values are not supported",
            error.UnterminatedPlaceholder => "script contains an unterminated placeholder",
            error.InvalidPlaceholderName => "script contains an invalid placeholder name",
            error.AmbiguousPlaceholder => "a placeholder appears in an ambiguous shell context (quotes, redirection, assignment, or command name)",
            error.TooManyVariables => "script references too many variables",
            error.OutOfMemory => "out of memory",
        });
        scripts.deinit(self.allocator, &owned_script);
        return null;
    };
    return .{ .script = owned_script, .expansion = expansion };
}

fn handleScriptsList(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    _ = invocation;
    var loaded = self.scripts.loadParsed(self.io) catch {
        return "{\"ok\":false,\"error\":\"failed to load scripts\"}";
    };
    defer loaded.deinit(self.allocator);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"scripts\":[") catch return output[0..0];
    for (loaded.parsed.value, 0..) |script, i| {
        if (i > 0) writer.writeAll(",") catch return output[0..0];
        std.json.Stringify.value(scriptWire(script), .{}, &writer) catch return output[0..0];
    }
    writer.writeAll("]") catch return output[0..0];
    if (loaded.quarantined) |q| {
        var msg_buf: [640]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "scripts.json was unreadable and was moved to {s}; the script library starts fresh", .{q}) catch "scripts.json was unreadable and was moved aside";
        writer.writeAll(",\"recovery_error\":") catch return output[0..0];
        json.writeJsonString(&writer, msg) catch return output[0..0];
    }
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

/// Validates every placeholder without saving or executing. The core lexer
/// remains authoritative and scans the complete body before it returns.
fn handleScriptsValidate(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsValidatePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    scripts.validateTemplate(self.allocator, parsed.value.body) catch |err| {
        return switch (err) {
            error.MissingVariable => unreachable,
            error.MultilineValue => respondError(output, "multiline variable values are not supported"),
            error.UnterminatedPlaceholder => respondError(output, "script contains an unterminated placeholder"),
            error.InvalidPlaceholderName => respondError(output, "script contains an invalid placeholder name"),
            error.AmbiguousPlaceholder => respondError(output, "a placeholder appears in an ambiguous shell context (quotes, redirection, assignment, or command name)"),
            error.TooManyVariables => respondError(output, "script references too many variables"),
            error.OutOfMemory => respondError(output, "out of memory"),
        };
    };
    return ok_json;
}

/// Upserts a script (spec 06 §7); ids are generated for creates. The body
/// is capped at 64 KB; variables must match the placeholder name charset.
fn handleScriptsSave(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsSavePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const input = parsed.value.script;
    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    var owned_id: ?[]const u8 = null;
    defer if (owned_id) |o| self.allocator.free(o);
    const id = input.id orelse blk: {
        owned_id = servers.makeId(self.allocator, now) catch return respondError(output, "out of memory");
        break :blk owned_id.?;
    };

    var saved = self.scripts.saveScript(self.io, .{
        .id = id,
        .name = input.name,
        .description = input.description,
        .tags = input.tags,
        .color = input.color,
        .body = input.body,
        .variables = input.variables,
    }, now) catch |err| {
        return respondError(output, switch (err) {
            error.MissingName => "script name is required",
            error.NameTooLong => "script name is too long",
            error.EmptyBody => "script body is required",
            error.BodyTooLarge => "script body must be under 64 KB",
            error.InvalidName => "invalid name or description",
            error.InvalidTag => "invalid tag",
            error.TooManyTags => "too many tags",
            error.InvalidColor => "invalid color",
            error.InvalidVariable => "invalid variable definition",
            error.DuplicateVariable => "duplicate variable",
            error.TooManyVariables => "too many variables",
            error.TooManyScripts => "script library is full",
            error.StoreCorrupt => "script library is unreadable",
            error.SerializeFailed => "failed to save scripts",
            error.OutOfMemory => "out of memory",
            error.MissingId => "missing script id",
        });
    };
    defer scripts.deinit(self.allocator, &saved);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"script\":") catch return output[0..0];
    std.json.Stringify.value(scriptWire(saved), .{}, &writer) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleScriptsDelete(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsIdPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    _ = self.scripts.delete(self.io, parsed.value.id) catch {
        return respondError(output, "failed to delete script");
    };
    return ok_json;
}

/// Runs a script on one server: expand, `bash -n` syntax check on the
/// server, then exec the same `bash -c '<expanded>'` string the check
/// validated (spec 06 §5 — the checked interpreter is the executing
/// interpreter). The channel id carries the output.
fn handleScriptsRun(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsRunPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    var err_response: []const u8 = "";
    var loaded = scriptsLoadAndExpand(self, output, &err_response, payload.script_id, payload.vars) orelse return err_response;
    defer loaded.deinit(self.allocator);
    if (scriptsAudit(self, output, "scripts.run", payload.server_id, loaded.script.id, loaded.script.name, loaded.expansion.names, loaded.expansion.redacted)) |resp| {
        return resp;
    }

    const check_cmd = scripts.checkString(self.allocator, loaded.expansion.command) catch return respondError(output, "out of memory");
    defer self.allocator.free(check_cmd);
    var check = self.manager.execWait(payload.server_id, check_cmd, scripts_check_cap, scripts_run_check_timeout_ns) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "syntax check failed",
        });
    };
    defer check.output.deinit(self.allocator);
    if (check.exit != 0) {
        if (check.exit == 127) return respondError(output, "bash is not available on this server");
        const tail = if (check.output.items.len > 200) check.output.items[check.output.items.len - 200 ..] else check.output.items;
        var msg_buf: [512]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "syntax check failed (exit {d}): {s}", .{ check.exit, tail }) catch "syntax check failed";
        return respondError(output, msg);
    }
    const exec_cmd = scripts.execString(self.allocator, loaded.expansion.command) catch return respondError(output, "out of memory");
    defer self.allocator.free(exec_cmd);
    const redacted_exec = scripts.execString(self.allocator, loaded.expansion.redacted) catch return respondError(output, "out of memory");
    defer self.allocator.free(redacted_exec);
    const redacted_command: ?[]const u8 = if (std.mem.eql(u8, exec_cmd, redacted_exec)) null else redacted_exec;
    const channel = self.manager.execTracked(payload.server_id, exec_cmd, "script", redacted_command, loaded.expansion.secrets) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "run failed",
        });
    };
    self.scripts.touchRun(self.io, payload.script_id, std.Io.Timestamp.now(self.io, .real).nanoseconds);
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel}) catch return output[0..0];
    return writer.buffered();
}

/// Two-phase safe broadcast, step 1 (spec 06 §5): expands once, enforces
/// stored secret policy, dedupes the target list (bounded to 64), freezes
/// the exact exec + check strings, and stores a memory-only preview.
/// Writes NO audit row and bumps NO run count — an uncommitted preview is
/// invisible to history. Secret values never appear in the preview id.
fn handleScriptsBroadcastPrepare(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsBroadcastPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.server_ids.len == 0) return respondError(output, "no servers selected");

    var err_response: []const u8 = "";
    var loaded = scriptsLoadAndExpand(self, output, &err_response, payload.script_id, payload.vars) orelse return err_response;
    defer loaded.deinit(self.allocator);

    // Dedupe once, before anything is audited or started: duplicate
    // selections must not produce duplicate audit rows (spec 06 §10).
    var server_list: std.ArrayList([]const u8) = .empty;
    defer server_list.deinit(self.allocator);
    for (payload.server_ids) |sid| {
        var dup = false;
        for (server_list.items) |seen| {
            if (std.mem.eql(u8, seen, sid)) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        if (server_list.items.len >= broadcast.max_servers_per_broadcast) return respondError(output, "too many servers (max 64 per broadcast)");
        server_list.append(self.allocator, sid) catch return respondError(output, "out of memory");
    }
    if (server_list.items.len == 0) return respondError(output, "no servers selected");

    const exec = scripts.execString(self.allocator, loaded.expansion.command) catch return respondError(output, "out of memory");
    defer self.allocator.free(exec);
    const check = scripts.checkString(self.allocator, loaded.expansion.command) catch return respondError(output, "out of memory");
    defer self.allocator.free(check);
    const redacted = scripts.execString(self.allocator, loaded.expansion.redacted) catch return respondError(output, "out of memory");
    defer self.allocator.free(redacted);
    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;

    var preview = broadcast.previewInit(
        self.allocator,
        loaded.script.id,
        loaded.script.name,
        exec,
        check,
        redacted,
        loaded.expansion.secrets,
        loaded.expansion.names,
        server_list.items,
        scriptsDestructive(&loaded.script),
        now,
    ) catch return respondError(output, "out of memory");
    var adopted = false;
    errdefer if (!adopted) preview.deinit(self.allocator);

    self.manager.previews.lock();
    self.manager.previews.expire(now);
    const preview_id = self.manager.previews.add(preview) catch |err| {
        self.manager.previews.unlock();
        return respondError(output, switch (err) {
            error.TooManyPreviews => "too many prepared broadcasts — commit or cancel one first",
            else => "out of memory",
        });
    };
    self.manager.previews.unlock();
    adopted = true;

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"preview_id\":") catch return output[0..0];
    writer.print("{d}", .{preview_id}) catch return output[0..0];
    writer.writeAll(",\"script_id\":") catch return output[0..0];
    json.writeJsonString(&writer, loaded.script.id) catch return output[0..0];
    writer.writeAll(",\"script_name\":") catch return output[0..0];
    json.writeJsonString(&writer, loaded.script.name) catch return output[0..0];
    writer.writeAll(",\"command\":") catch return output[0..0];
    json.writeJsonString(&writer, exec) catch return output[0..0];
    writer.writeAll(",\"redacted_command\":") catch return output[0..0];
    json.writeJsonString(&writer, redacted) catch return output[0..0];
    writer.writeAll(",\"servers\":[") catch return output[0..0];
    for (server_list.items, 0..) |sid, i| {
        if (i > 0) writer.writeAll(",") catch return output[0..0];
        writer.writeAll("{\"server_id\":") catch return output[0..0];
        json.writeJsonString(&writer, sid) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("],\"destructive\":") catch return output[0..0];
    writer.writeAll(if (scriptsDestructive(&loaded.script)) "true" else "false") catch return output[0..0];
    writer.writeAll(",\"expires_at\":") catch return output[0..0];
    writer.print("{d}}}", .{@divTrunc(now + broadcast.preview_ttl_ns, std.time.ns_per_ms)}) catch return output[0..0];
    return writer.buffered();
}

/// Two-phase safe broadcast, step 2 — commit (spec 06 §5): executes the
/// frozen preview record verbatim, so a script edit between preview and
/// confirm can never change what runs. Audits one row per server, bumps
/// the run count, and admits at most `max_active_runs` broadcasts.
fn handleScriptsBroadcast(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsPreviewPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;

    self.manager.previews.lock();
    defer self.manager.previews.unlock();
    self.manager.previews.expire(now);
    const preview = self.manager.previews.get(parsed.value.preview_id) orelse {
        return respondError(output, "preview expired or unknown — prepare again");
    };

    self.manager.broadcasts.lock();
    const active = self.manager.broadcasts.activeCount();
    self.manager.broadcasts.unlock();
    if (active >= broadcast.max_active_runs) return respondError(output, "too many active broadcasts (max 8)");

    for (preview.servers) |sid| {
        if (scriptsAudit(self, output, "scripts.broadcast", sid, preview.script_id, preview.script_name, preview.names, preview.redacted_command)) |resp| {
            return resp;
        }
    }
    const run_id = self.manager.broadcasts.start(preview.script_id, preview.script_name, preview.command, preview.check_command, preview.redacted_command, preview.secrets, preview.servers) catch |err| {
        return respondError(output, switch (err) {
            error.NoServers => "no servers selected",
            else => "out of memory",
        });
    };
    // touchRun BEFORE removing the preview: `preview` aliases the
    // registry record, and remove() frees it.
    self.scripts.touchRun(self.io, preview.script_id, now);
    _ = self.manager.previews.remove(parsed.value.preview_id);
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"run_id\":{d}}}", .{run_id}) catch return output[0..0];
    return writer.buffered();
}

/// Two-phase safe broadcast, cleanup: drops the prepared record without
/// executing it (spec 06 §5 — records are removed on commit, explicit
/// cancel, expiry, and shutdown).
fn handleScriptsBroadcastPrepareCancel(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsPreviewPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.previews.lock();
    self.manager.previews.expire(std.Io.Timestamp.now(self.io, .real).nanoseconds);
    _ = self.manager.previews.remove(parsed.value.preview_id);
    self.manager.previews.unlock();
    return ok_json;
}

/// The broadcast cursor map value for one server (absolute stream cursor;
/// spec 02 protocol — each view polls with its own cursors).
fn scriptsCursor(cursors: std.json.Value, server_id: []const u8) u64 {
    if (cursors != .object) return 0;
    const v = cursors.object.get(server_id) orelse return 0;
    return switch (v) {
        .integer => |i| if (i < 0) 0 else @intCast(i),
        .float => |f| if (f < 0) 0 else @intFromFloat(f),
        else => 0,
    };
}

fn writeScriptsBroadcastServer(
    writer: *std.Io.Writer,
    server: *const broadcast.ServerState,
    cursor: u64,
    gap: u64,
    eof: bool,
    data: []const u8,
) !void {
    try writer.writeAll("{\"server_id\":");
    try json.writeJsonString(writer, server.server_id);
    try writer.writeAll(",\"status\":");
    try json.writeJsonString(writer, server.status.jsonName());
    try writer.writeAll(",\"exit\":");
    if (server.exit) |exit_v| {
        try writer.print("{d}", .{exit_v});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"error\":");
    try json.writeJsonString(writer, server.err);
    try writer.print(",\"cursor\":{d},\"gap\":{d},\"eof\":{s},\"data\":", .{ cursor, gap, if (eof) "true" else "false" });
    try json.writeJsonString(writer, data);
    try writer.writeAll("}");
}

/// Copies the newest bounded output window before cancellation closes and
/// removes a channel. The absolute range preserves cursor and gap behavior
/// for consumers that poll after cancellation.
fn captureScriptsTerminalOutput(self: *Context, server: *broadcast.ServerState, channel: u32) void {
    const metadata = self.manager.pollChannels(server.server_id, &.{.{ .id = channel, .pos = 0 }}, false, 0, 0) catch return;
    defer {
        for (metadata) |*poll| poll.deinit(self.allocator);
        self.allocator.free(metadata);
    }
    var retained_start: u64 = 0;
    var retained_bytes: u64 = 0;
    for (metadata) |*poll| {
        if (poll.id != channel) continue;
        retained_start = poll.cursor;
        retained_bytes = poll.pending;
        break;
    }
    const desired = retained_start + (retained_bytes -| scripts_terminal_output_cap);
    const snapshots = self.manager.pollChannels(
        server.server_id,
        &.{.{ .id = channel, .pos = desired }},
        false,
        scripts_terminal_output_cap,
        scripts_terminal_output_cap,
    ) catch return;
    defer {
        for (snapshots) |*poll| poll.deinit(self.allocator);
        self.allocator.free(snapshots);
    }
    for (snapshots) |*poll| {
        if (poll.id != channel or poll.data.len == 0) continue;
        const owned = self.allocator.dupe(u8, poll.data) catch return;
        if (server.retained_data.len > 0) self.allocator.free(server.retained_data);
        server.retained_data = owned;
        server.retained_end = poll.cursor;
        server.retained_start = poll.cursor - poll.data.len;
        return;
    }
}

/// Starts queued servers as slots free (enqueuing worker-driven syntax
/// checks — never blocking a bridge call), completes in-flight checks,
/// polls running channels with the caller's cursors, and returns the
/// per-server status/output snapshot (spec 06 §5 — non-destructive:
/// nothing is consumed). Status transitions are applied BEFORE the
/// response serializes each server, so `done:true` and every server
/// result agree in the same response.
fn handleScriptsBroadcastPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsBroadcastPollPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    self.manager.broadcasts.lock();
    const run = self.manager.broadcasts.get(payload.run_id) orelse {
        self.manager.broadcasts.unlock();
        return respondError(output, "unknown run");
    };
    self.manager.broadcasts.unlock();
    // The bridge is single-threaded: no other handler can mutate or evict
    // the run while this one runs, so the pointer stays valid.

    // Start queued servers as slots free (spec 06 §6: at most four at a
    // time — checks included; polling drives the queue). The check runs
    // on the session worker; enqueueing is O(1).
    while (run.running < broadcast.max_concurrent and run.next_to_start < run.servers.items.len and !run.canceled) {
        const idx = run.next_to_start;
        run.next_to_start += 1;
        const server = &run.servers.items[idx];
        if (server.status != .queued) continue;
        const outcome = self.allocator.create(broadcast.ScriptCheckOutcome) catch {
            server.status = .failed;
            server.err = "out of memory";
            continue;
        };
        outcome.* = .{ .allocator = self.allocator };
        self.manager.enqueueSyntaxCheck(server.server_id, run.check_command, scripts_run_check_timeout_ns, outcome) catch {
            self.allocator.destroy(outcome);
            server.status = .skipped;
            server.err = "unreachable";
            continue;
        };
        server.status = .checking;
        server.check_outcome = outcome;
        run.running += 1;
    }

    // Complete in-flight checks: a done check either starts the tracked
    // exec (exit 0) or fails the server with the exact reason.
    for (run.servers.items) |*server| {
        if (server.status != .checking) continue;
        const outcome = server.check_outcome orelse continue;
        if (!outcome.isDone()) continue;
        server.check_outcome = null;
        if (outcome.exit != null and outcome.exit.? == 0) {
            const redacted_command: ?[]const u8 = if (std.mem.eql(u8, run.command, run.redacted_command)) null else run.redacted_command;
            const channel = self.manager.execTracked(server.server_id, run.command, "script", redacted_command, run.secrets) catch {
                self.allocator.destroy(outcome);
                server.status = .failed;
                server.err = "unreachable";
                run.running -= 1;
                continue;
            };
            server.status = .running;
            server.channel = channel;
            self.allocator.destroy(outcome);
        } else {
            // Copy the message before the outcome is freed (it aliases
            // the struct — never return a slice into a freed outcome).
            const check_exit = outcome.exitStatus();
            const err, const err_owned = if (self.allocator.dupe(u8, outcome.message())) |owned|
                .{ owned, true }
            else |_|
                .{ @as([]const u8, "syntax check failed"), false };
            self.allocator.destroy(outcome);
            server.status = .failed;
            server.exit = check_exit;
            server.err = err;
            server.err_owned = err_owned;
            run.running -= 1;
        }
    }

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"run_id\":") catch return output[0..0];
    writer.print("{d}", .{run.id}) catch return output[0..0];
    writer.writeAll(",\"script_name\":") catch return output[0..0];
    json.writeJsonString(&writer, run.script_name) catch return output[0..0];
    writer.print(",\"canceled\":{s}", .{if (run.canceled) "true" else "false"}) catch return output[0..0];

    writer.writeAll(",\"servers\":[") catch return output[0..0];
    var first = true;
    var budget = scripts_poll_data_budget;
    for (run.servers.items) |*server| {
        // Poll the channel and apply the EOF transition BEFORE writing
        // this server's status/exit (the response must agree with the
        // state this poll just observed — spec 06 §5). Successful and
        // nonzero-exit channels remain pollable with another view's cursor.
        var cursor = scriptsCursor(payload.cursors, server.server_id);
        var gap: u64 = 0;
        var eof = switch (server.status) {
            .done, .failed, .canceled, .skipped => true,
            else => false,
        };
        var data: []const u8 = &.{};
        var polls_owned: ?[]sessions.ChannelPoll = null;
        defer if (polls_owned) |polls| {
            for (polls) |*poll| poll.deinit(self.allocator);
            self.allocator.free(polls);
        };

        if (server.channel == null and server.retained_data.len > 0) {
            const read_from = @min(@max(cursor, server.retained_start), server.retained_end);
            gap = server.retained_start -| cursor;
            if (read_from < server.retained_end) {
                const offset: usize = @intCast(read_from - server.retained_start);
                const take = @min(server.retained_data.len - offset, @min(budget, 128 * 1024));
                data = server.retained_data[offset .. offset + take];
                cursor = read_from + take;
                budget -= take;
            } else {
                cursor = read_from;
            }
            eof = true;
        }

        const should_poll = server.channel != null and
            (server.status == .running or server.status == .done or (server.status == .failed and server.exit != null));
        if (should_poll) {
            const channel = server.channel.?;
            const requested_cursor = cursor;
            const polls = self.manager.pollChannels(server.server_id, &.{.{ .id = channel, .pos = requested_cursor }}, false, budget, 128 * 1024) catch {
                const occupied_slot = server.status == .running;
                server.status = .failed;
                server.err = "session lost";
                server.channel = null;
                eof = true;
                if (occupied_slot) run.running -= 1;
                if (!first) writer.writeAll(",") catch return output[0..0];
                first = false;
                writeScriptsBroadcastServer(&writer, server, requested_cursor, 0, true, "") catch return output[0..0];
                continue;
            };
            polls_owned = polls;
            var exit: ?i32 = null;
            for (polls) |*poll| {
                if (poll.id != channel) continue;
                data = poll.data;
                cursor = poll.cursor;
                eof = poll.eof;
                exit = poll.exit_status;
                gap = poll.gap;
            }
            budget = budget -| data.len;
            // Transition exactly once (a done server's later polls skip
            // it). `done` only for exit 0; anything else is `failed` with
            // the exact exit code.
            if (eof and server.status == .running) {
                server.exit = exit;
                if (exit == 0) {
                    server.status = .done;
                } else {
                    server.status = .failed;
                }
                run.running -= 1;
            }
        }
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        // Data aliases `polls_owned`; serialize it before the defer frees it.
        writeScriptsBroadcastServer(&writer, server, cursor, gap, eof, data) catch return output[0..0];
    }
    writer.writeAll("]") catch return output[0..0];

    if (run.allTerminal()) run.finished = true;
    // The done flag must be serialized before eviction can free the run.
    writer.print(",\"done\":{s}}}", .{if (run.finished) "true" else "false"}) catch return output[0..0];
    self.manager.broadcasts.evictFinished();
    return writer.buffered();
}

/// Cancels a broadcast: queued servers never start; checking channels are
/// abandoned (the worker completes and frees the outcome); running
/// channels are closed and reported `canceled` ("cancel requested" —
/// closing a channel does not prove the remote process died; spec 06
/// §10).
fn handleScriptsBroadcastCancel(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(ScriptsBroadcastCancelPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.broadcasts.lock();
    const run = self.manager.broadcasts.get(parsed.value.run_id) orelse {
        self.manager.broadcasts.unlock();
        return respondError(output, "unknown run");
    };
    run.canceled = true;
    for (run.servers.items) |*server| {
        switch (server.status) {
            .queued => server.status = .canceled,
            .checking => {
                // The check op may still complete on the worker; hand the
                // outcome to it (abandon) so its set() frees the struct.
                server.status = .canceled;
                if (server.check_outcome) |oc| {
                    server.check_outcome = null;
                    if (oc.abandon()) self.allocator.destroy(oc);
                }
                run.running -= 1;
            },
            .running => {
                if (server.channel) |ch| {
                    captureScriptsTerminalOutput(self, server, ch);
                    self.manager.closeChannel(server.server_id, ch) catch {};
                }
                server.channel = null;
                server.status = .canceled;
                server.err = "cancel requested";
                run.running -= 1;
            },
            else => {},
        }
    }
    self.manager.broadcasts.unlock();
    return ok_json;
}

// --- tests -----------------------------------------------------------------
// --- one-click deployment (spec 07) ------------------------------------------

const deploy_poll_data_budget: usize = 256 * 1024;
const deploy_file_wait_ns = 20 * std.time.ns_per_s;
const deploy_mkdir_cap: usize = 4 * 1024;

const DeployAppsListPayload = struct { server_id: []const u8 };
const DeployAppsSavePayload = struct { app: deploy.AppInput };
const DeployAppsDeletePayload = struct {
    server_id: []const u8,
    app_id: []const u8,
};
const DeployRunPayload = struct {
    server_id: []const u8,
    app_id: []const u8,
    secret_values: ?[]const deploy.SecretValue = null,
};
const DeployPollPayload = struct {
    run_id: u32,
    cursors: std.json.Value = .null,
};
const DeployCancelPayload = struct { run_id: u32 };
const DeployHistoryPayload = struct {
    server_id: []const u8,
    app_id: []const u8,
    limit: ?usize = null,
};

fn deployTerminal(status: deploy.RunStatus) bool {
    return switch (status) {
        .queued, .running => false,
        else => true,
    };
}

fn deploySaveError(err: anyerror) []const u8 {
    return switch (err) {
        error.MissingId => "missing app id",
        error.MissingServer => "missing server",
        error.MissingName => "app name is required",
        error.InvalidName => "invalid app name",
        error.MissingFolder => "deploy folder is required",
        error.InvalidFolder => "invalid deploy folder",
        error.InvalidRepo => "invalid repository URL",
        error.InvalidTransport => "invalid repository transport",
        error.InvalidBranch => "invalid branch",
        error.InvalidNodeVersion => "unsupported Node.js version (supported: 22, 24)",
        error.InvalidAppType => "invalid app type",
        error.InvalidCommand => "invalid install/build/start command",
        error.InvalidEnvVar => "invalid environment variable",
        error.DuplicateEnvVar => "duplicate environment variable",
        error.TooManyEnvVars => "too many environment variables",
        error.InvalidDomain => "invalid domain",
        error.TooManyDomains => "too many domains",
        error.EmailRequired => "an email is required when SSL is enabled",
        error.InvalidEmail => "invalid certificate email",
        error.InvalidPort => "invalid app port",
        error.SerializeFailed => "failed to save apps",
        error.StoreCorrupt => "app registry is unreadable",
        error.OutOfMemory => "out of memory",
        else => "failed to save app",
    };
}

fn handleDeployAppsList(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeployAppsListPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var loaded = self.apps.loadParsed(self.io) catch {
        return respondError(output, "failed to load apps");
    };
    defer loaded.deinit(self.allocator);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"apps\":[") catch return output[0..0];
    var first = true;
    for (loaded.parsed.value) |a| {
        if (!std.mem.eql(u8, a.server_id, parsed.value.server_id)) continue;
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        std.json.Stringify.value(a, .{}, &writer) catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

/// Upserts an app (spec 07 §5); ids are generated for creates. Secret
/// env values never enter the store (the keychain holds them).
fn handleDeployAppsSave(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeployAppsSavePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var input = parsed.value.app;
    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    var owned_id: ?[]const u8 = null;
    defer if (owned_id) |o| self.allocator.free(o);
    if (input.id == null) {
        owned_id = servers.makeId(self.allocator, now) catch return respondError(output, "out of memory");
        input.id = owned_id;
    }
    var saved = self.apps.saveApp(self.io, input, now) catch |err| {
        return respondError(output, deploySaveError(err));
    };
    defer deploy.deinit(self.allocator, &saved);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"app\":") catch return output[0..0];
    std.json.Stringify.value(saved, .{}, &writer) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleDeployAppsDelete(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeployAppsDeletePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    var owned_opt = self.apps.find(self.io, payload.app_id) catch {
        return respondError(output, "app registry is unreadable");
    };
    defer if (owned_opt) |*a| deploy.deinit(self.allocator, a);
    const app = owned_opt orelse return respondError(output, "app not found");
    if (!std.mem.eql(u8, app.server_id, payload.server_id)) return respondError(output, "app not found on this server");
    _ = self.apps.delete(self.io, payload.app_id) catch {
        return respondError(output, "failed to delete app");
    };
    return ok_json;
}

/// One audit entry per run with the planned command list (spec 07 §8:
/// the Create/Update click is the approval). Commands never contain
/// secret values — env values go to files, not commands. Returns the
/// error response on failure.
fn deployAudit(self: *Context, output: []u8, action: []const u8, server_id: []const u8, app: *const deploy.App, plan: []const deploy.PlanStep) ?[]const u8 {
    var detail_buf: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&detail_buf);
    writer.print("app={s} name={s} folder={s} ssl={s}", .{ app.id, app.name, app.folder, if (app.ssl) "yes" else "no" }) catch return respondError(output, "out of memory");
    for (plan) |*s| {
        writer.print("\n{d}: ", .{@intFromEnum(s.id)}) catch return respondError(output, "out of memory");
        const cmd = if (s.command.len > 600) s.command[0..600] else s.command;
        writer.writeAll(cmd) catch return respondError(output, "out of memory");
        if (writer.buffered().len > 3800) break;
    }
    self.audit.append(self.io, action, server_id, writer.buffered()) catch return respondError(output, "audit failed");
    return null;
}

/// Registers a run and hands the pipeline to the poll handler (spec 07
/// §6: steps execute sequentially, driven by the frontend's polls — no
/// extra threads). Secret values are validated against the declared
/// secret fields and kept only in the run's protected memory.
fn handleDeployRun(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeployRunPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    var owned_opt = self.apps.find(self.io, payload.app_id) catch {
        return respondError(output, "app registry is unreadable");
    };
    defer if (owned_opt) |*a| deploy.deinit(self.allocator, a);
    const app = owned_opt orelse return respondError(output, "app not found");
    if (!std.mem.eql(u8, app.server_id, payload.server_id)) return respondError(output, "app not found on this server");

    var values: std.ArrayList(deploy.SecretValue) = .empty;
    defer values.deinit(self.allocator);
    if (payload.secret_values) |svs| {
        for (svs) |sv| {
            var declared = false;
            for (app.env_vars) |v| {
                if (v.secret and std.mem.eql(u8, v.name, sv.name)) {
                    declared = true;
                    break;
                }
            }
            if (!declared) return respondError(output, "unknown secret variable");
            values.append(self.allocator, sv) catch return respondError(output, "out of memory");
        }
    }

    const session = self.manager.get(payload.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");

    const plan = deploy.buildPlan(self.allocator, &app) catch return respondError(output, "failed to plan the deploy");
    defer {
        for (plan) |*s| s.deinit(self.allocator);
        self.allocator.free(plan);
    }
    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    if (deployAudit(self, output, "deploy.run", payload.server_id, &app, plan)) |resp| return resp;

    const run_id = self.manager.deploys.start(payload.server_id, &app, plan, values.items, @intCast(now)) catch return respondError(output, "out of memory");
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"run_id\":{d}}}", .{run_id}) catch return output[0..0];
    return writer.buffered();
}

/// The caller's absolute cursor for a step channel (spec 02 protocol;
/// each deploy view polls with its own cursors).
fn deployCursor(cursors: std.json.Value, channel: u32) u64 {
    if (cursors != .object) return 0;
    var key_buf: [16]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{d}", .{channel}) catch return 0;
    const v = cursors.object.get(key) orelse return 0;
    return switch (v) {
        .integer => |i| if (i < 0) 0 else @intCast(i),
        .float => |f| if (f < 0) 0 else @intFromFloat(f),
        else => 0,
    };
}

/// Synchronous SFTP write for deploy config files (`.env`, PM2
/// ecosystem, nginx site). Returns a static error message or null
/// (deploy.Step errors are static text by contract).
fn deployWriteFile(self: *Context, server_id: []const u8, path: []const u8, data: []const u8) ?[]const u8 {
    const outcome = self.allocator.create(sessions.SftpOutcome) catch return "out of memory";
    outcome.* = .{ .allocator = self.allocator };
    self.manager.sftpSave(server_id, path, data, null, outcome) catch |err| {
        self.allocator.destroy(outcome);
        return switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "failed to write the file",
        };
    };
    const deadline = std.Io.Timestamp.now(self.io, .real).nanoseconds + deploy_file_wait_ns;
    outcome.wait(self.io, deadline);
    var owned = true;
    defer if (owned) self.allocator.destroy(outcome);
    if (!outcome.isDone() and !outcome.abandon()) {
        owned = false; // the op owns the outcome now; its set frees it
        return "timed out writing the file";
    }
    defer if (outcome.json) |j| self.allocator.free(j);
    if (!outcome.ok) return "failed to write the file";
    return null;
}

/// Writes the config file the next step depends on: `.env` before install
/// (or build, when install is skipped), the PM2 ecosystem file before
/// pm2, the nginx site config before nginx (spec 07 §6). Returns a
/// static error message or null.
fn deployWriteStepFiles(self: *Context, run: *deploy.Run, step: *const deploy.Step) ?[]const u8 {
    switch (step.id) {
        .install, .build => {
            if (run.env_written) return null;
            const path = deploy.envFilePath(self.allocator, run.app.folder) catch return "out of memory";
            defer self.allocator.free(path);
            const content = deploy.envFile(self.allocator, &run.app, run.secrets.items) catch return "out of memory";
            defer self.allocator.free(content);
            if (deployWriteFile(self, run.server_id, path, content)) |msg| return msg;
            run.env_written = true;
            return null;
        },
        .pm2 => {
            const path = deploy.pm2EcosystemPath(self.allocator, run.app.folder) catch return "out of memory";
            defer self.allocator.free(path);
            const content = deploy.ecosystemFile(self.allocator, &run.app, run.secrets.items) catch return "out of memory";
            defer self.allocator.free(content);
            return deployWriteFile(self, run.server_id, path, content);
        },
        .nginx => {
            // The site config needs its directory to exist first; `mkdir
            // -p` is idempotent so the step's own mkdir is harmless.
            const q_avail = shellquote.quote(self.allocator, deploy.nginxAvailableDir()) catch return "out of memory";
            defer self.allocator.free(q_avail);
            const q_enabled = shellquote.quote(self.allocator, deploy.nginxEnabledDir()) catch return "out of memory";
            defer self.allocator.free(q_enabled);
            const mk = std.fmt.allocPrint(self.allocator, "mkdir -p {s} {s}", .{ q_avail, q_enabled }) catch return "out of memory";
            defer self.allocator.free(mk);
            var check = self.manager.execWait(run.server_id, mk, deploy_mkdir_cap, deploy_file_wait_ns) catch return "session lost";
            defer check.output.deinit(self.allocator);
            if (check.exit != 0) return "failed to create the nginx config directory";
            const path = deploy.nginxAvailablePath(self.allocator, run.app.id) catch return "out of memory";
            defer self.allocator.free(path);
            const content = deploy.nginxConfig(self.allocator, &run.app) catch return "out of memory";
            defer self.allocator.free(content);
            return deployWriteFile(self, run.server_id, path, content);
        },
        else => return null,
    }
}

/// Poll-driven step engine: starts the next step on each call, advances
/// on channel EOF, writes each step's config file first, and marks the
/// run done/failed/canceled/interrupted exactly once (appending the
/// history record).
fn deployPollStep(self: *Context, run: *deploy.Run, now_ns: i128) void {
    while (run.currentStep()) |step| {
        if (run.canceled) {
            step.state = .canceled;
            run.status = .canceled;
            run.finished_at = @intCast(now_ns);
            self.deploy_history.append(self.io, run);
            return;
        }
        if (step.channel) |ch| {
            const polls = self.manager.pollChannels(run.server_id, &.{.{ .id = ch, .pos = 0 }}, false, 64 * 1024, 64 * 1024) catch {
                step.@"error" = "session lost";
                step.state = .failed;
                run.status = .interrupted;
                run.finished_at = @intCast(now_ns);
                self.deploy_history.append(self.io, run);
                return;
            };
            defer {
                for (polls) |*poll| poll.deinit(self.allocator);
                self.allocator.free(polls);
            }
            var eof = false;
            var exit: ?i32 = null;
            for (polls) |*poll| {
                if (poll.id != ch) continue;
                eof = poll.eof;
                exit = poll.exit_status;
                run.captureOutput(self.allocator, poll.data);
            }
            if (!eof) return;
            step.exit = exit;
            if (exit != 0) {
                step.state = .failed;
                step.@"error" = "command failed";
                run.status = .failed;
                run.finished_at = @intCast(now_ns);
                self.deploy_history.append(self.io, run);
                return;
            }
            step.state = .success;
            run.step_index += 1;
            continue;
        }
        if (step.command.len == 0) {
            step.state = .success; // skipped step (no command configured)
            run.step_index += 1;
            continue;
        }
        if (deployWriteStepFiles(self, run, step)) |msg| {
            step.state = .failed;
            step.@"error" = msg;
            run.status = .failed;
            run.finished_at = @intCast(now_ns);
            self.deploy_history.append(self.io, run);
            return;
        }
        const channel = self.manager.execTracked(run.server_id, step.command, "deploy", null, &.{}) catch {
            step.@"error" = "session lost";
            step.state = .failed;
            run.status = .interrupted;
            run.finished_at = @intCast(now_ns);
            self.deploy_history.append(self.io, run);
            return;
        };
        if (run.status == .queued) run.status = .running;
        step.channel = channel;
        step.state = .running;
        return;
    }
    if (run.status != .done) {
        run.status = .done;
        run.finished_at = @intCast(now_ns);
        self.deploy_history.append(self.io, run);
    }
}

/// One poll pass: starts/advances steps, then serializes every step with
/// the caller's cursor deltas (masked — secret values never appear in
/// step output; spec 07 §8).
fn handleDeployPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeployPollPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    self.manager.deploys.lock();
    const run = self.manager.deploys.get(payload.run_id) orelse {
        self.manager.deploys.unlock();
        return respondError(output, "unknown run");
    };
    self.manager.deploys.unlock();

    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    if (!deployTerminal(run.status)) {
        const session = self.manager.get(run.server_id);
        if (session == null or session.?.status.load(.acquire) != .ready) {
            // Spec 07 §10: a server lost mid-deploy marks the run
            // `interrupted`; the next run replans from live state.
            if (run.currentStep()) |step| {
                if (step.state == .running or step.state == .pending) {
                    step.@"error" = "session lost";
                    step.state = .failed;
                }
            }
            run.status = .interrupted;
            run.finished_at = @intCast(now);
            self.deploy_history.append(self.io, run);
        } else {
            deployPollStep(self, run, now);
        }
    }

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"run_id\":") catch return output[0..0];
    writer.print("{d}", .{run.id}) catch return output[0..0];
    writer.writeAll(",\"status\":") catch return output[0..0];
    json.writeJsonString(&writer, run.status.jsonName()) catch return output[0..0];
    writer.print(",\"canceled\":{s}", .{if (run.canceled) "true" else "false"}) catch return output[0..0];
    writer.writeAll(",\"steps\":[") catch return output[0..0];

    var first = true;
    var budget = deploy_poll_data_budget;
    for (run.steps.items) |*step| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.writeAll("{\"id\":") catch return output[0..0];
        json.writeJsonString(&writer, step.id.jsonName()) catch return output[0..0];
        writer.writeAll(",\"label\":") catch return output[0..0];
        json.writeJsonString(&writer, step.label) catch return output[0..0];
        writer.writeAll(",\"state\":") catch return output[0..0];
        json.writeJsonString(&writer, step.state.jsonName()) catch return output[0..0];
        if (step.channel) |ch| {
            writer.print(",\"channel\":{d}", .{ch}) catch return output[0..0];
        }
        if (step.exit) |exit| {
            writer.print(",\"exit\":{d}", .{exit}) catch return output[0..0];
        }
        if (step.@"error".len > 0) {
            writer.writeAll(",\"error\":") catch return output[0..0];
            json.writeJsonString(&writer, step.@"error") catch return output[0..0];
        }
        if (step.channel) |ch| {
            const cursor = deployCursor(payload.cursors, ch);
            const polls = self.manager.pollChannels(run.server_id, &.{.{ .id = ch, .pos = cursor }}, false, budget, 128 * 1024) catch {
                // Session lost mid-serialize: report the step as-is; the
                // next poll marks the run interrupted.
                writer.print(",\"cursor\":{d},\"gap\":0,\"eof\":false,\"data\":\"\"", .{cursor}) catch return output[0..0];
                continue;
            };
            var data: []u8 = &.{};
            var new_cursor = cursor;
            var gap: u64 = 0;
            var eof = false;
            for (polls) |*poll| {
                if (poll.id != ch) continue;
                data = poll.data;
                new_cursor = poll.cursor;
                gap = poll.gap;
                eof = poll.eof;
            }
            // Secret values never appear in step output (spec 07 §8).
            const masked = deploy.maskSecrets(self.allocator, data, run.secrets.items) catch data;
            defer if (masked.ptr != data.ptr) self.allocator.free(masked);
            budget = budget -| data.len;
            writer.print(",\"cursor\":{d},\"gap\":{d},\"eof\":{s},\"data\":", .{ new_cursor, gap, if (eof) "true" else "false" }) catch return output[0..0];
            json.writeJsonString(&writer, masked) catch return output[0..0];
            // The data must be serialized before the polls are freed.
            for (polls) |*poll| poll.deinit(self.allocator);
            self.allocator.free(polls);
        }
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]") catch return output[0..0];
    writer.print(",\"done\":{s}}}", .{if (deployTerminal(run.status)) "true" else "false"}) catch return output[0..0];
    self.manager.deploys.evictFinished();
    return writer.buffered();
}

/// Cancels a run: the current channel is closed and the run is reported
/// `canceled` on the next poll ("cancel requested" — closing a channel
/// does not prove the remote process died; spec 07 §4.2).
fn handleDeployCancel(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeployCancelPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.deploys.lock();
    const run = self.manager.deploys.get(parsed.value.run_id) orelse {
        self.manager.deploys.unlock();
        return respondError(output, "unknown run");
    };
    run.canceled = true;
    const server_id = run.server_id;
    if (run.currentStep()) |step| {
        if (step.channel) |ch| self.manager.closeChannel(server_id, ch) catch {};
    }
    self.manager.deploys.unlock();
    self.audit.append(self.io, "deploy.cancel", server_id, "run canceled by the user") catch {};
    return ok_json;
}

/// Run history (spec 07 §7): newest first, filtered by server + app,
/// bounded by the payload limit (default 10). Output is pre-masked.
fn handleDeployHistory(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeployHistoryPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    const cap = @min(payload.limit orelse deploy.history_list_limit, 50);
    var loaded = self.deploy_history.loadParsed(self.io) catch {
        return respondError(output, "failed to load deploy history");
    };
    defer loaded.deinit(self.allocator);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"runs\":[") catch return output[0..0];
    var emitted: usize = 0;
    var i = loaded.parsed.value.len;
    while (i > 0 and emitted < cap) {
        i -= 1;
        const rec = loaded.parsed.value[i];
        if (!std.mem.eql(u8, rec.server_id, payload.server_id) or !std.mem.eql(u8, rec.app_id, payload.app_id)) continue;
        if (emitted > 0) writer.writeAll(",") catch return output[0..0];
        std.json.Stringify.value(rec, .{}, &writer) catch return output[0..0];
        emitted += 1;
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}
// --- SSH key management (spec 08) --------------------------------------------

const sshkeys_read_chunk: usize = 256 * 1024;
const sshkeys_exec_cap: usize = 8 * 1024;
const sshkeys_exec_timeout_ns = 10 * std.time.ns_per_s;
const sshkeys_wait_ns = 20 * std.time.ns_per_s;
const roles_marker_path = "/etc/oars-roles.json";
const deploy_key_name = "oars_deploy";

const SshKeysListPayload = struct {
    server_id: []const u8,
    user: ?[]const u8 = null,
};
const SshKeysAddPayload = struct {
    server_id: []const u8,
    public_key: []const u8,
    comment: ?[]const u8 = null,
    user: ?[]const u8 = null,
};
const SshKeysRevokePayload = struct {
    server_id: []const u8,
    fingerprint: []const u8,
    expected_line_hash: []const u8,
    user: ?[]const u8 = null,
};
const SshKeysRotatePayload = struct {
    server_id: []const u8,
    fingerprint: []const u8,
    expected_line_hash: []const u8,
    new_public_key: []const u8,
    user: ?[]const u8 = null,
};
const SshKeysGeneratePayload = struct {
    destination: []const u8,
    comment: ?[]const u8 = null,
    passphrase: ?[]const u8 = null,
    remember_passphrase: bool = false,
};
const SshKeysRolesListPayload = struct { server_id: []const u8 };
const SshKeysRolesCreatePayload = struct {
    server_id: []const u8,
    name: []const u8,
    read_only: bool = false,
};
const SshKeysRolesDeletePayload = struct {
    server_id: []const u8,
    name: []const u8,
};
const SshKeysDeployKeyPayload = struct { server_id: []const u8 };

fn validRoleName(name: []const u8) bool {
    if (name.len == 0 or name.len > 32) return false;
    const first = name[0];
    if (!((first >= 'a' and first <= 'z') or first == '_')) return false;
    for (name[1..]) |ch| {
        if (!((ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '_' or ch == '-')) return false;
    }
    return true;
}

/// Resolves `<home>/.ssh/authorized_keys` for the connected account or a
/// named role user (spec 08 §5 extension: `user` targets per-user files).
/// Returns the owned path or null with a plain message in `msg`.
fn sshkeysPathMsg(self: *Context, server_id: []const u8, user: ?[]const u8, msg: *[]const u8) ?[]u8 {
    msg.* = "";
    // The home is duplicated while the exec output is alive (the
    // outcome's buffer is freed when this block exits).
    const home: []u8 = if (user) |u| blk: {
        if (!validRoleName(u)) {
            msg.* = "invalid user name";
            return null;
        }
        var cmd_buf: [96]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "getent passwd {s}", .{u}) catch {
            msg.* = "invalid user name";
            return null;
        };
        var check = self.manager.execWait(server_id, cmd, sshkeys_exec_cap, sshkeys_exec_timeout_ns) catch {
            msg.* = "not connected";
            return null;
        };
        defer check.output.deinit(self.allocator);
        if (check.exit != 0) {
            msg.* = "user not found";
            return null;
        }
        // passwd: name:x:uid:gid:gecos:home:shell — the home field is
        // second-to-last even when gecos contains colons.
        var tokens = std.mem.splitScalar(u8, std.mem.trim(u8, check.output.items, " \t\r\n"), ':');
        var all: [16][]const u8 = undefined;
        var n: usize = 0;
        while (tokens.next()) |t| {
            if (n >= all.len) break;
            all[n] = t;
            n += 1;
        }
        if (n < 3) {
            msg.* = "cannot resolve the user's home";
            return null;
        }
        break :blk self.allocator.dupe(u8, all[n - 2]) catch {
            msg.* = "out of memory";
            return null;
        };
    } else blk: {
        var check = self.manager.execWait(server_id, "echo ~", sshkeys_exec_cap, sshkeys_exec_timeout_ns) catch {
            msg.* = "not connected";
            return null;
        };
        defer check.output.deinit(self.allocator);
        const trimmed = std.mem.trim(u8, check.output.items, " \t\r\n");
        if (trimmed.len == 0 or trimmed[0] != '/') {
            msg.* = "cannot resolve the home directory";
            return null;
        }
        break :blk self.allocator.dupe(u8, trimmed) catch {
            msg.* = "out of memory";
            return null;
        };
    };
    defer self.allocator.free(home);
    return std.fmt.allocPrint(self.allocator, "{s}/.ssh/authorized_keys", .{home}) catch {
        msg.* = "out of memory";
        return null;
    };
}

/// Bridge-facing wrapper: failures become JSON error responses.
fn sshkeysPath(self: *Context, output: []u8, server_id: []const u8, user: ?[]const u8, err_response: *[]const u8) ?[]u8 {
    var msg: []const u8 = "";
    const path = sshkeysPathMsg(self, server_id, user, &msg) orelse {
        err_response.* = respondError(output, msg);
        return null;
    };
    return path;
}

/// Synchronous SFTP read of a small file; null when the file is missing
/// (spec 08 §10: missing → empty list/create path). Bounded.
fn sshkeysRead(self: *Context, server_id: []const u8, path: []const u8) ?[]u8 {
    const stat_out = self.allocator.create(sessions.SftpOutcome) catch return null;
    stat_out.* = .{ .allocator = self.allocator };
    self.manager.sftpStat(server_id, path, stat_out) catch {
        self.allocator.destroy(stat_out);
        return null;
    };
    const stat_deadline = std.Io.Timestamp.now(self.io, .real).nanoseconds + sshkeys_wait_ns;
    stat_out.wait(self.io, stat_deadline);
    var stat_owned = true;
    defer if (stat_owned) self.allocator.destroy(stat_out);
    if (!stat_out.isDone() and !stat_out.abandon()) {
        stat_owned = false; // the op owns the outcome now; its set frees it
        return null; // missing
    }
    defer if (stat_out.json) |j| self.allocator.free(j);
    if (!stat_out.ok) return null; // missing

    var content: std.ArrayList(u8) = .empty;
    defer content.deinit(self.allocator);
    var offset: u64 = 0;
    while (true) {
        const read_out = self.allocator.create(sessions.SftpOutcome) catch return null;
        read_out.* = .{ .allocator = self.allocator };
        self.manager.sftpRead(server_id, path, offset, sshkeys_read_chunk, read_out) catch {
            self.allocator.destroy(read_out);
            return null;
        };
        read_out.wait(self.io, stat_deadline);
        var read_owned = true;
        defer if (read_owned) self.allocator.destroy(read_out);
        if (!read_out.isDone() and !read_out.abandon()) {
            read_owned = false;
            return null;
        }
        defer if (read_out.json) |j| self.allocator.free(j);
        if (!read_out.ok) return null;
        const payload = read_out.json orelse return null;
        const parsed = std.json.parseFromSlice(struct {
            ok: bool,
            base64: []const u8 = "",
            eof: bool = false,
        }, self.allocator, payload, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch return null;
        defer parsed.deinit();
        if (!parsed.value.ok) return null;
        const size = std.base64.standard.Decoder.calcSizeForSlice(parsed.value.base64) catch return null;
        if (content.items.len + size > sshkeys.max_keys_file_bytes) return null;
        const decoded = self.allocator.alloc(u8, size) catch return null;
        defer self.allocator.free(decoded);
        std.base64.standard.Decoder.decode(decoded, parsed.value.base64) catch return null;
        content.appendSlice(self.allocator, decoded) catch return null;
        offset += decoded.len;
        if (parsed.value.eof) break;
    }
    return content.toOwnedSlice(self.allocator) catch null;
}

/// Synchronous SFTP save with an optional chmod after the atomic rename
/// (temp + posix-rename — the same editor-save path, spec 05 §4.2) and an
/// optional chown (role-user files are written by the root session and
/// must be readable by the account sshd reads them as). Returns a static
/// error message or null on success.
fn sshkeysWrite(self: *Context, server_id: []const u8, path: []const u8, content: []const u8, mode: ?u32, owner: ?[]const u8, err_buf: []u8) ?[]const u8 {
    const out = self.allocator.create(sessions.SftpOutcome) catch return "out of memory";
    out.* = .{ .allocator = self.allocator };
    self.manager.sftpSave(server_id, path, content, null, out) catch |err| {
        self.allocator.destroy(out);
        return switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "failed to write the file",
        };
    };
    const deadline = std.Io.Timestamp.now(self.io, .real).nanoseconds + sshkeys_wait_ns;
    out.wait(self.io, deadline);
    var out_owned = true;
    defer if (out_owned) self.allocator.destroy(out);
    if (!out.isDone() and !out.abandon()) {
        out_owned = false; // the op owns the outcome now; its set frees it
        return "timed out writing the file";
    }
    defer if (out.json) |j| self.allocator.free(j);
    if (!out.ok) return std.fmt.bufPrint(err_buf, "{s}", .{out.message()}) catch "failed to write the file";
    if (mode) |m| {
        const chmod_out = self.allocator.create(sessions.SftpOutcome) catch return "out of memory";
        chmod_out.* = .{ .allocator = self.allocator };
        self.manager.sftpChmod(server_id, path, m, chmod_out) catch {
            self.allocator.destroy(chmod_out);
            return "failed to set file permissions";
        };
        chmod_out.wait(self.io, deadline);
        var chmod_owned = true;
        defer if (chmod_owned) self.allocator.destroy(chmod_out);
        if (!chmod_out.isDone() and !chmod_out.abandon()) {
            chmod_owned = false;
            return "failed to set file permissions";
        }
        defer if (chmod_out.json) |j| self.allocator.free(j);
        if (!chmod_out.ok) return "failed to set file permissions";
    }
    if (owner) |o| {
        var cmd_buf: [512]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "chown {s} {s}", .{ o, path }) catch return "failed to set file ownership";
        var check = self.manager.execWait(server_id, cmd, sshkeys_exec_cap, sshkeys_exec_timeout_ns) catch return "failed to set file ownership";
        defer check.output.deinit(self.allocator);
        if (check.exit != 0) return "failed to set file ownership";
    }
    return null;
}

/// Ensures `<home>/.ssh` exists with mode 0700 (StrictModes discipline;
/// spec 08 §8). Returns a static error message or null.
fn sshkeysEnsureSshDir(self: *Context, server_id: []const u8, path: []const u8) ?[]const u8 {
    const dir = std.fs.path.dirname(path) orelse return "invalid path";
    const stat_out = self.allocator.create(sessions.SftpOutcome) catch return "out of memory";
    stat_out.* = .{ .allocator = self.allocator };
    self.manager.sftpStat(server_id, dir, stat_out) catch {
        self.allocator.destroy(stat_out);
        return "cannot stat the ssh directory";
    };
    const deadline = std.Io.Timestamp.now(self.io, .real).nanoseconds + sshkeys_wait_ns;
    stat_out.wait(self.io, deadline);
    var stat_owned = true;
    defer if (stat_owned) self.allocator.destroy(stat_out);
    var exists = false;
    if (stat_out.isDone()) {
        exists = stat_out.ok;
    } else if (stat_out.abandon()) {
        exists = stat_out.ok; // completed between isDone and abandon
    } else {
        stat_owned = false; // the op owns the outcome now; its set frees it
    }
    if (stat_owned) {
        if (stat_out.json) |j| self.allocator.free(j);
    }
    if (exists) return null;
    // Missing: create it, then tighten to 0700.
    const mk_out = self.allocator.create(sessions.SftpOutcome) catch return "out of memory";
    mk_out.* = .{ .allocator = self.allocator };
    self.manager.sftpMkdir(server_id, dir, mk_out) catch {
        self.allocator.destroy(mk_out);
        return "failed to create the ssh directory";
    };
    mk_out.wait(self.io, deadline);
    var mk_owned = true;
    defer if (mk_owned) self.allocator.destroy(mk_out);
    if (!mk_out.isDone() and !mk_out.abandon()) {
        mk_owned = false;
        return "failed to create the ssh directory";
    }
    defer if (mk_out.json) |j| self.allocator.free(j);
    if (!mk_out.ok) return "failed to create the ssh directory";
    const chmod_out = self.allocator.create(sessions.SftpOutcome) catch return "out of memory";
    chmod_out.* = .{ .allocator = self.allocator };
    self.manager.sftpChmod(server_id, dir, 0o700, chmod_out) catch {
        self.allocator.destroy(chmod_out);
        return "failed to set the ssh directory permissions";
    };
    chmod_out.wait(self.io, deadline);
    var chmod_owned = true;
    defer if (chmod_owned) self.allocator.destroy(chmod_out);
    if (!chmod_out.isDone() and !chmod_out.abandon()) {
        chmod_owned = false;
        return "failed to set the ssh directory permissions";
    }
    defer if (chmod_out.json) |j| self.allocator.free(j);
    if (!chmod_out.ok) return "failed to set the ssh directory permissions";
    return null;
}

/// The current mode of `path` (from a fresh stat) or 0600 for a missing
/// file — authorized_keys discipline (spec 08 §10).
fn sshkeysMode(self: *Context, server_id: []const u8, path: []const u8) u32 {
    const stat_out = self.allocator.create(sessions.SftpOutcome) catch return 0o600;
    stat_out.* = .{ .allocator = self.allocator };
    self.manager.sftpStat(server_id, path, stat_out) catch {
        self.allocator.destroy(stat_out);
        return 0o600;
    };
    const deadline = std.Io.Timestamp.now(self.io, .real).nanoseconds + sshkeys_wait_ns;
    stat_out.wait(self.io, deadline);
    var stat_owned = true;
    defer if (stat_owned) self.allocator.destroy(stat_out);
    if (!stat_out.isDone() and !stat_out.abandon()) {
        stat_owned = false; // the op owns the outcome now; its set frees it
        return 0o600;
    }
    defer if (stat_out.json) |j| self.allocator.free(j);
    if (!stat_out.ok) return 0o600;
    const parsed = std.json.parseFromSlice(struct {
        ok: bool,
        entry: struct { mode: []const u8 = "" },
    }, self.allocator, stat_out.json.?, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch return 0o600;
    defer parsed.deinit();
    _ = parsed.value.ok;
    // The entry mode is the `ls -l`-style string; 0600 starts with "-rw-------".
    const mode_text = parsed.value.entry.mode;
    if (mode_text.len >= 10) {
        var m: u32 = 0;
        const groups = [_][3]u8{ mode_text[1..4].*, mode_text[4..7].*, mode_text[7..10].* };
        const perms = [_]u8{ 4, 2, 1 };
        for (groups, 0..) |g, gi| {
            for (g, 0..) |ch, pi| {
                if (ch != '-') m |= perms[pi] << @intCast((2 - gi) * 3);
            }
        }
        return m;
    }
    return 0o600;
}

/// Finds the parsed key whose fingerprint and line hash both match the
/// client's expectations (spec 08 §5: a line index is not stable after
/// an external edit — the hash is the conflict guard).
const SshKeysTarget = struct {
    line_index: usize,
    options: []const u8,
};
fn sshkeysFindTarget(parsed: *const sshkeys.ParsedFile, fingerprint: []const u8, expected_hash: []const u8) ?SshKeysTarget {
    for (parsed.keys) |*k| {
        if (!k.parsed) continue;
        if (!std.mem.eql(u8, k.fingerprint_sha256, fingerprint)) continue;
        if (std.mem.eql(u8, k.line_hash, expected_hash)) {
            return .{ .line_index = k.line_index, .options = k.options };
        }
    }
    return null;
}

fn sshkeysAudit(self: *Context, action: []const u8, server_id: []const u8, detail: []const u8) void {
    self.audit.append(self.io, action, server_id, detail) catch {};
}

/// The read-only role's authorized-key options, from the roles marker
/// (recorded at role creation from the server's actual SFTP subsystem).
fn sshkeysRoleOptions(self: *Context, server_id: []const u8, user: []const u8) ?[]const u8 {
    const marker = sshkeysRead(self, server_id, roles_marker_path) orelse return null;
    defer self.allocator.free(marker);
    const parsed = std.json.parseFromSlice([]struct {
        name: []const u8,
        read_only: bool,
        forced_command: []const u8 = "",
    }, self.allocator, marker, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch return null;
    defer parsed.deinit();
    for (parsed.value) |role| {
        if (std.mem.eql(u8, role.name, user) and role.read_only) {
            if (role.forced_command.len == 0) return null;
            var buf: [512]u8 = undefined;
            const options = std.fmt.bufPrint(&buf, "restrict,command=\"{s}\"", .{role.forced_command}) catch return null;
            return self.allocator.dupe(u8, options) catch null;
        }
    }
    return null;
}

fn handleSshKeysList(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SshKeysListPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var err_response: []const u8 = "";
    const path = sshkeysPath(self, output, parsed.value.server_id, parsed.value.user, &err_response) orelse return err_response;
    defer self.allocator.free(path);
    const content = sshkeysRead(self, parsed.value.server_id, path) orelse "";
    defer if (content.len > 0) self.allocator.free(content);
    var file = sshkeys.parse(self.allocator, content) catch {
        return respondError(output, "failed to parse authorized_keys");
    };
    defer file.deinit(self.allocator);

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"keys\":[") catch return output[0..0];
    var first = true;
    for (file.keys) |*k| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.writeAll("{\"line_index\":") catch return output[0..0];
        writer.print("{d}", .{k.line_index}) catch return output[0..0];
        writer.writeAll(",\"parsed\":") catch return output[0..0];
        writer.writeAll(if (k.parsed) "true" else "false") catch return output[0..0];
        if (k.parsed) {
            writer.writeAll(",\"options\":") catch return output[0..0];
            json.writeJsonString(&writer, k.options) catch return output[0..0];
            writer.writeAll(",\"type\":") catch return output[0..0];
            json.writeJsonString(&writer, k.key_type) catch return output[0..0];
            writer.writeAll(",\"key\":") catch return output[0..0];
            json.writeJsonString(&writer, k.key) catch return output[0..0];
            writer.writeAll(",\"comment\":") catch return output[0..0];
            json.writeJsonString(&writer, k.comment) catch return output[0..0];
            writer.writeAll(",\"fingerprint_sha256\":") catch return output[0..0];
            json.writeJsonString(&writer, k.fingerprint_sha256) catch return output[0..0];
            writer.writeAll(",\"bits\":") catch return output[0..0];
            if (k.bits) |b| {
                writer.print("{d}", .{b}) catch return output[0..0];
            } else {
                writer.writeAll("null") catch return output[0..0];
            }
            writer.writeAll(",\"line_hash\":") catch return output[0..0];
            json.writeJsonString(&writer, k.line_hash) catch return output[0..0];
        } else {
            // Malformed lines surface with their raw text (spec 08 §10).
            writer.writeAll(",\"raw\":") catch return output[0..0];
            json.writeJsonString(&writer, k.raw) catch return output[0..0];
            writer.writeAll(",\"error\":") catch return output[0..0];
            json.writeJsonString(&writer, k.@"error") catch return output[0..0];
            writer.writeAll(",\"line_hash\":") catch return output[0..0];
            json.writeJsonString(&writer, k.line_hash) catch return output[0..0];
        }
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

fn handleSshKeysAdd(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SshKeysAddPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    var err_response: []const u8 = "";
    const path = sshkeysPath(self, output, payload.server_id, payload.user, &err_response) orelse return err_response;
    defer self.allocator.free(path);
    if (sshkeysEnsureSshDir(self, payload.server_id, path)) |msg| return respondError(output, msg);

    const normalized = sshkeys.normalizePublicKey(self.allocator, payload.public_key, payload.comment) catch |err| {
        return respondError(output, switch (err) {
            error.Multiline => "public key must be a single line",
            else => "invalid public key",
        });
    };
    defer {
        self.allocator.free(normalized.line);
        self.allocator.free(normalized.fingerprint_sha256);
    }

    // Read-only role keys get the forced-command options automatically.
    var options: ?[]const u8 = null;
    defer if (options) |o| self.allocator.free(o);
    if (payload.user) |u| options = sshkeysRoleOptions(self, payload.server_id, u);

    const content = sshkeysRead(self, payload.server_id, path) orelse "";
    defer if (content.len > 0) self.allocator.free(content);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(self.allocator);
    if (content.len > 0) {
        try out.appendSlice(self.allocator, content);
        if (content[content.len - 1] != '\n') try out.append(self.allocator, '\n'); // newline guard
    }
    if (options) |o| {
        try out.appendSlice(self.allocator, o);
        try out.append(self.allocator, ' ');
    }
    try out.appendSlice(self.allocator, normalized.line);
    try out.append(self.allocator, '\n');

    const mode = sshkeysMode(self, payload.server_id, path);
    var write_err_buf: [256]u8 = undefined;
    if (sshkeysWrite(self, payload.server_id, path, out.items, mode, payload.user, &write_err_buf)) |msg| return respondError(output, msg);

    // Report the new line's index/hash from the written state.
    var written = sshkeys.parse(self.allocator, out.items) catch {
        return respondError(output, "failed to parse the written file");
    };
    defer written.deinit(self.allocator);
    var line_index: usize = 0;
    if (written.keys.len > 0) line_index = written.keys[written.keys.len - 1].line_index;
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "fingerprint={s} user={s}", .{ normalized.fingerprint_sha256, payload.user orelse "-" }) catch "sshkeys.add";
    sshkeysAudit(self, "sshkeys.add", payload.server_id, detail);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"line_index\":") catch return output[0..0];
    writer.print("{d},\"fingerprint\":", .{line_index}) catch return output[0..0];
    json.writeJsonString(&writer, normalized.fingerprint_sha256) catch return output[0..0];
    writer.writeAll(",\"line_hash\":") catch return output[0..0];
    json.writeJsonString(&writer, written.keys[written.keys.len - 1].line_hash) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

/// Loads the file, finds the target key by fingerprint + line hash, and
/// rewrites it (drop or replace). Shared by revoke and rotate. Returns
/// null with a plain message in `msg` on any conflict.
fn sshkeysRewriteCore(
    self: *Context,
    server_id: []const u8,
    path: []const u8,
    fingerprint: []const u8,
    expected_hash: []const u8,
    replacement: ?[]const u8,
    owner: ?[]const u8,
    msg: *[]const u8,
    write_err_buf: []u8,
) ?[]u8 {
    msg.* = "";
    const content = sshkeysRead(self, server_id, path) orelse {
        msg.* = "key not found";
        return null;
    };
    defer self.allocator.free(content);
    var file = sshkeys.parse(self.allocator, content) catch {
        msg.* = "failed to parse authorized_keys";
        return null;
    };
    defer file.deinit(self.allocator);
    const target = sshkeysFindTarget(&file, fingerprint, expected_hash) orelse {
        for (file.keys) |*k| {
            if (k.parsed and std.mem.eql(u8, k.fingerprint_sha256, fingerprint)) {
                msg.* = "authorized_keys changed since the preview; refresh and retry";
                return null;
            }
        }
        msg.* = "key not found";
        return null;
    };
    var new_line: ?[]u8 = null;
    defer if (new_line) |n| self.allocator.free(n);
    if (replacement) |r| {
        if (target.options.len > 0) {
            new_line = std.fmt.allocPrint(self.allocator, "{s} {s}", .{ target.options, r }) catch {
                msg.* = "out of memory";
                return null;
            };
        } else {
            new_line = self.allocator.dupe(u8, r) catch {
                msg.* = "out of memory";
                return null;
            };
        }
    }
    const rewritten = sshkeys.rewrite(self.allocator, &file, target.line_index, new_line) catch {
        msg.* = "out of memory";
        return null;
    };
    errdefer self.allocator.free(rewritten);
    const mode = sshkeysMode(self, server_id, path);
    if (sshkeysWrite(self, server_id, path, rewritten, mode, owner, write_err_buf)) |write_msg| {
        msg.* = write_msg;
        return null;
    }
    return rewritten;
}

/// Bridge-facing wrapper: failures become JSON error responses.
fn sshkeysRewrite(
    self: *Context,
    output: []u8,
    err_response: *[]const u8,
    server_id: []const u8,
    path: []const u8,
    fingerprint: []const u8,
    expected_hash: []const u8,
    replacement: ?[]const u8,
    owner: ?[]const u8,
) ?[]u8 {
    var msg: []const u8 = "";
    // The write error text is formatted into this frame's buffer so it
    // stays valid until respondError copies it (the heap outcome that
    // produced it is destroyed before sshkeysWrite returns).
    var write_err_buf: [256]u8 = undefined;
    const rewritten = sshkeysRewriteCore(self, server_id, path, fingerprint, expected_hash, replacement, owner, &msg, &write_err_buf) orelse {
        err_response.* = respondError(output, msg);
        return null;
    };
    return rewritten;
}

fn handleSshKeysRevoke(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SshKeysRevokePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    var err_response: []const u8 = "";
    const path = sshkeysPath(self, output, payload.server_id, payload.user, &err_response) orelse return err_response;
    defer self.allocator.free(path);
    const rewritten = sshkeysRewrite(self, output, &err_response, payload.server_id, path, payload.fingerprint, payload.expected_line_hash, null, payload.user) orelse return err_response;
    self.allocator.free(rewritten);
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "fingerprint={s} user={s}", .{ payload.fingerprint, payload.user orelse "-" }) catch "sshkeys.revoke";
    sshkeysAudit(self, "sshkeys.revoke", payload.server_id, detail);
    return ok_json;
}

fn handleSshKeysRotate(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SshKeysRotatePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    const normalized = sshkeys.normalizePublicKey(self.allocator, payload.new_public_key, null) catch |err| {
        return respondError(output, switch (err) {
            error.Multiline => "public key must be a single line",
            else => "invalid public key",
        });
    };
    defer {
        self.allocator.free(normalized.line);
        self.allocator.free(normalized.fingerprint_sha256);
    }
    var err_response: []const u8 = "";
    const path = sshkeysPath(self, output, payload.server_id, payload.user, &err_response) orelse return err_response;
    defer self.allocator.free(path);
    const rewritten = sshkeysRewrite(self, output, &err_response, payload.server_id, path, payload.fingerprint, payload.expected_line_hash, normalized.line, payload.user) orelse return err_response;
    self.allocator.free(rewritten);
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "old={s} new={s} user={s}", .{ payload.fingerprint, normalized.fingerprint_sha256, payload.user orelse "-" }) catch "sshkeys.rotate";
    sshkeysAudit(self, "sshkeys.rotate", payload.server_id, detail);
    return ok_json;
}

/// Local key generation (spec 08 §5): ssh-keygen through a private PTY;
/// the passphrase never enters argv, env, or audit text. When
/// `remember_passphrase` is set, the response names the Keychain account
/// (`localkey:<fingerprint>`) the frontend stores the passphrase under.
fn handleSshKeysGenerate(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SshKeysGeneratePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    const generated = keygen.generate(self.io, self.allocator, .{
        .destination = payload.destination,
        .comment = payload.comment,
        .passphrase = payload.passphrase,
    }) catch |err| {
        return respondError(output, switch (err) {
            error.SshKeygenMissing => "ssh-keygen is not available on this machine",
            error.InvalidDestination => "invalid destination path",
            error.DestinationMissing => "the destination folder does not exist",
            error.DestinationExists => "a key already exists at that destination",
            error.PtyFailed, error.SpawnFailed, error.PromptFailed => "ssh-keygen failed during generation",
            error.GenerationFailed => "ssh-keygen failed to generate the key",
            error.VerifyFailed => "the generated key failed verification",
            error.InstallFailed => "failed to install the key pair",
            error.Timeout => "ssh-keygen did not finish in time",
            error.UnexpectedOutput => "ssh-keygen produced unexpected output",
            error.OutOfMemory => "out of memory",
        });
    };
    defer {
        self.allocator.free(generated.public_key);
        self.allocator.free(generated.private_path);
        self.allocator.free(generated.fingerprint_sha256);
    }
    var detail_buf: [512]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "destination={s} type=ed25519 fingerprint={s}", .{ generated.private_path, generated.fingerprint_sha256 }) catch "sshkeys.generate";
    sshkeysAudit(self, "sshkeys.generate", "-", detail);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"public_key\":") catch return output[0..0];
    json.writeJsonString(&writer, generated.public_key) catch return output[0..0];
    writer.writeAll(",\"private_path\":") catch return output[0..0];
    json.writeJsonString(&writer, generated.private_path) catch return output[0..0];
    if (payload.remember_passphrase and payload.passphrase != null and payload.passphrase.?.len > 0) {
        writer.writeAll(",\"keychain_account\":") catch return output[0..0];
        var account_buf: [128]u8 = undefined;
        const account = std.fmt.bufPrint(&account_buf, "localkey:{s}", .{generated.fingerprint_sha256}) catch "";
        json.writeJsonString(&writer, account) catch return output[0..0];
    }
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

// --- roles (spec 08 §4.2) -----------------------------------------------------

/// The roles marker (`/etc/oars-roles.json`): Oars-created role users,
/// with the forced command recorded from the server's SFTP subsystem.
const RolesMarkerEntry = struct {
    name: []const u8,
    read_only: bool,
    forced_command: []const u8 = "",
};

fn sshkeysRolesLoad(self: *Context, server_id: []const u8, out: *std.ArrayList(RolesMarkerEntry)) bool {
    const content = sshkeysRead(self, server_id, roles_marker_path) orelse return true;
    defer self.allocator.free(content);
    if (content.len == 0) return true;
    const parsed = std.json.parseFromSlice([]RolesMarkerEntry, self.allocator, content, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return false;
    defer parsed.deinit();
    for (parsed.value) |r| {
        out.append(self.allocator, .{
            .name = self.allocator.dupe(u8, r.name) catch return false,
            .read_only = r.read_only,
            .forced_command = self.allocator.dupe(u8, r.forced_command) catch return false,
        }) catch return false;
    }
    return true;
}

fn sshkeysRolesSave(self: *Context, server_id: []const u8, roles: *const std.ArrayList(RolesMarkerEntry)) bool {
    var out: std.Io.Writer.Allocating = .init(self.allocator);
    defer out.deinit();
    std.json.Stringify.value(roles.items, .{}, &out.writer) catch return false;
    var err_buf: [256]u8 = undefined;
    return sshkeysWrite(self, server_id, roles_marker_path, out.writer.buffered(), 0o600, null, &err_buf) == null;
}

fn handleSshKeysRolesList(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SshKeysRolesListPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const server_id = parsed.value.server_id;
    const session = self.manager.get(server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    var roles: std.ArrayList(RolesMarkerEntry) = .empty;
    defer {
        for (roles.items) |*r| {
            self.allocator.free(r.name);
            self.allocator.free(r.forced_command);
        }
        roles.deinit(self.allocator);
    }
    if (!sshkeysRolesLoad(self, server_id, &roles)) return respondError(output, "failed to read the roles marker");

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"roles\":[") catch return output[0..0];
    var first = true;
    for (roles.items) |*role| {
        // Live state: the user must still exist; read the shell and home.
        var cmd_buf: [96]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "getent passwd {s}", .{role.name}) catch continue;
        var check = self.manager.execWait(server_id, cmd, sshkeys_exec_cap, sshkeys_exec_timeout_ns) catch continue;
        defer check.output.deinit(self.allocator);
        if (check.exit != 0) continue; // stale marker entry
        const passwd = std.mem.trim(u8, check.output.items, " \t\r\n");
        var tokens = std.mem.splitScalar(u8, passwd, ':');
        var fields: [16][]const u8 = undefined;
        var n: usize = 0;
        while (tokens.next()) |t| {
            if (n >= fields.len) break;
            fields[n] = t;
            n += 1;
        }
        if (n < 7) continue;
        const home = fields[n - 2];
        const shell = fields[n - 1];

        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.writeAll("{\"name\":") catch return output[0..0];
        json.writeJsonString(&writer, role.name) catch return output[0..0];
        writer.writeAll(",\"shell\":") catch return output[0..0];
        json.writeJsonString(&writer, shell) catch return output[0..0];
        writer.print(",\"read_only\":{s},\"policy\":", .{if (role.read_only) "true" else "false"}) catch return output[0..0];
        json.writeJsonString(&writer, if (role.read_only) "read-only-sftp" else "standard") catch return output[0..0];
        writer.writeAll(",\"users\":[") catch return output[0..0];
        // The people holding keys on this account (authorized_keys comments).
        var ak_buf: [512]u8 = undefined;
        const ak_cmd = std.fmt.bufPrint(&ak_buf, "cat {s}/.ssh/authorized_keys 2>/dev/null", .{home}) catch "";
        if (ak_cmd.len > 0) {
            var ak = self.manager.execWait(server_id, ak_cmd, sshkeys_exec_cap, sshkeys_exec_timeout_ns) catch null;
            if (ak) |*a| {
                defer a.output.deinit(self.allocator);
                var file = sshkeys.parse(self.allocator, a.output.items) catch null;
                if (file) |*f| {
                    defer f.deinit(self.allocator);
                    var k_first = true;
                    for (f.keys) |*k| {
                        if (!k.parsed) continue;
                        if (!k_first) writer.writeAll(",") catch return output[0..0];
                        k_first = false;
                        json.writeJsonString(&writer, k.comment) catch return output[0..0];
                    }
                }
            }
        }
        writer.writeAll("]}") catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

/// Runs one privileged command; returns false on non-zero exit (the
/// caller's error response is set).
fn sshkeysExec(self: *Context, output: []u8, err_response: *[]const u8, server_id: []const u8, cmd: []const u8, fail_msg: []const u8) bool {
    var check = self.manager.execWait(server_id, cmd, sshkeys_exec_cap, sshkeys_exec_timeout_ns) catch {
        err_response.* = respondError(output, "not connected");
        return false;
    };
    defer check.output.deinit(self.allocator);
    if (check.exit != 0) {
        err_response.* = respondError(output, fail_msg);
        return false;
    }
    return true;
}

/// Creates (or verifies) a role user: root check, capability-detected
/// forced command for read-only roles, `useradd -m -s /bin/bash -p ''`,
/// per-user 0700/0600 ssh setup, and the roles marker update. Idempotent:
/// an existing matching role verifies the user and returns null. Returns
/// a plain error message on failure. Callers audit (the same role may be
/// created from `sshkeys.roles.create` or an access onboard job).
fn sshkeysRoleEnsureCore(self: *Context, server_id: []const u8, name: []const u8, read_only: bool) ?[]const u8 {
    // User creation requires root (spec 08 §4.2: show the exact
    // privileged commands; stop when the authority is absent).
    var id_check = self.manager.execWait(server_id, "id -u", sshkeys_exec_cap, sshkeys_exec_timeout_ns) catch {
        return "not connected";
    };
    defer id_check.output.deinit(self.allocator);
    if (id_check.exit != 0 or std.mem.indexOf(u8, std.mem.trim(u8, id_check.output.items, " \t\r\n"), "0") == null) {
        return "roles require root access on the server";
    }

    var roles: std.ArrayList(RolesMarkerEntry) = .empty;
    defer {
        for (roles.items) |*r| {
            self.allocator.free(r.name);
            self.allocator.free(r.forced_command);
        }
        roles.deinit(self.allocator);
    }
    if (!sshkeysRolesLoad(self, server_id, &roles)) return "failed to read the roles marker";
    for (roles.items) |r| {
        if (std.mem.eql(u8, r.name, name)) {
            if (r.read_only != read_only) return "a user with this name already exists but is not the requested role type";
            // Idempotent: the role already exists; verify the user does too.
            var cmd_buf: [96]u8 = undefined;
            const cmd = std.fmt.bufPrint(&cmd_buf, "getent passwd {s}", .{name}) catch return "role user is missing";
            var check = self.manager.execWait(server_id, cmd, sshkeys_exec_cap, sshkeys_exec_timeout_ns) catch {
                return "not connected";
            };
            defer check.output.deinit(self.allocator);
            if (check.exit != 0) return "role user is missing";
            return null;
        }
    }

    // Capability-detect the SFTP subsystem for read-only roles before
    // creating anything (spec 08 §4.2).
    var forced_command: []const u8 = "";
    var forced_owned: ?[]u8 = null;
    defer if (forced_owned) |f| self.allocator.free(f);
    if (read_only) {
        var sub = self.manager.execWait(server_id, "sshd -T 2>/dev/null | grep -E '^subsystem sftp'", sshkeys_exec_cap, sshkeys_exec_timeout_ns) catch {
            return "not connected";
        };
        defer sub.output.deinit(self.allocator);
        if (sub.exit != 0) return "the server does not expose an SFTP subsystem";
        var tokens = std.mem.tokenizeAny(u8, std.mem.trim(u8, sub.output.items, " \t\r\n"), " \t");
        _ = tokens.next(); // "subsystem"
        _ = tokens.next(); // "sftp"
        const sftp_bin = tokens.next() orelse return "the server does not expose an SFTP subsystem";
        forced_owned = std.fmt.allocPrint(self.allocator, "{s} -R", .{sftp_bin}) catch return "out of memory";
        forced_command = forced_owned.?;
    }

    var useradd_buf: [160]u8 = undefined;
    // `-p ''` creates an unlocked account with an empty password field:
    // sshd refuses key auth for locked accounts, and password auth stays
    // refused (no PermitEmptyPasswords). Key access is the only way in.
    const useradd_cmd = std.fmt.bufPrint(&useradd_buf, "useradd -m -s /bin/bash -p '' {s}", .{name}) catch return "invalid role name";
    var created = self.manager.execWait(server_id, useradd_cmd, sshkeys_exec_cap, sshkeys_exec_timeout_ns) catch {
        return "not connected";
    };
    defer created.output.deinit(self.allocator);
    if (created.exit != 0) {
        // useradd exits 9 when the user exists; anything else is a failure.
        const out_text = std.mem.trim(u8, created.output.items, " \t\r\n");
        if (created.exit != 9 and std.mem.indexOf(u8, out_text, "already exists") == null) {
            return "useradd failed";
        }
        var cmd_buf: [96]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "getent passwd {s}", .{name}) catch return "useradd failed";
        var check = self.manager.execWait(server_id, cmd, sshkeys_exec_cap, sshkeys_exec_timeout_ns) catch {
            return "not connected";
        };
        defer check.output.deinit(self.allocator);
        if (check.exit != 0) return "useradd failed";
        return "a user with this name already exists but was not created by Oars";
    }

    // Per-user authorized_keys setup: 0700 .ssh, 0600 authorized_keys.
    var home_buf: [96]u8 = undefined;
    const home_cmd = std.fmt.bufPrint(&home_buf, "getent passwd {s} | awk -F: '{{print $6}}'", .{name}) catch return "out of memory";
    var home_check = self.manager.execWait(server_id, home_cmd, sshkeys_exec_cap, sshkeys_exec_timeout_ns) catch {
        return "not connected";
    };
    defer home_check.output.deinit(self.allocator);
    if (home_check.exit != 0) return "cannot resolve the new user's home";
    const home = std.mem.trim(u8, home_check.output.items, " \t\r\n");
    var setup_buf: [768]u8 = undefined;
    const setup_cmd = std.fmt.bufPrint(&setup_buf, "mkdir -p {s}/.ssh && chmod 700 {s}/.ssh && touch {s}/.ssh/authorized_keys && chmod 600 {s}/.ssh/authorized_keys && chown {s} {s}/.ssh {s}/.ssh/authorized_keys", .{ home, home, home, home, name, home, home }) catch return "out of memory";
    var setup_check = self.manager.execWait(server_id, setup_cmd, sshkeys_exec_cap, sshkeys_exec_timeout_ns) catch {
        return "not connected";
    };
    defer setup_check.output.deinit(self.allocator);
    if (setup_check.exit != 0) return "failed to set up the role user";

    // Record the role (with the forced command, for future key adds).
    roles.append(self.allocator, .{
        .name = self.allocator.dupe(u8, name) catch return "out of memory",
        .read_only = read_only,
        .forced_command = self.allocator.dupe(u8, forced_command) catch return "out of memory",
    }) catch return "out of memory";
    if (!sshkeysRolesSave(self, server_id, &roles)) return "failed to save the roles marker";
    return null;
}

fn handleSshKeysRolesCreate(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SshKeysRolesCreatePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (!validRoleName(payload.name)) return respondError(output, "invalid role name");
    if (std.mem.eql(u8, payload.name, "root")) return respondError(output, "invalid role name");

    const server_id = payload.server_id;
    if (sshkeysRoleEnsureCore(self, server_id, payload.name, payload.read_only)) |msg| {
        return respondError(output, msg);
    }
    var detail_buf: [128]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "name={s} read_only={s}", .{ payload.name, if (payload.read_only) "yes" else "no" }) catch "sshkeys.roles.create";
    sshkeysAudit(self, "sshkeys.roles.create", server_id, detail);
    return ok_json;
}

fn handleSshKeysRolesDelete(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SshKeysRolesDeletePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    const server_id = payload.server_id;
    const session = self.manager.get(server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    var roles: std.ArrayList(RolesMarkerEntry) = .empty;
    defer {
        for (roles.items) |*r| {
            self.allocator.free(r.name);
            self.allocator.free(r.forced_command);
        }
        roles.deinit(self.allocator);
    }
    if (!sshkeysRolesLoad(self, server_id, &roles)) return respondError(output, "failed to read the roles marker");
    var found = false;
    var i: usize = 0;
    while (i < roles.items.len) {
        if (std.mem.eql(u8, roles.items[i].name, payload.name)) {
            const removed = roles.orderedRemove(i);
            self.allocator.free(removed.name);
            self.allocator.free(removed.forced_command);
            found = true;
        } else {
            i += 1;
        }
    }
    if (!found) return respondError(output, "role not found");

    var err_response: []const u8 = "";
    var del_buf: [96]u8 = undefined;
    const del_cmd = std.fmt.bufPrint(&del_buf, "userdel {s}", .{payload.name}) catch return respondError(output, "invalid role name");
    // userdel leaves the home dir (spec 08 §5).
    if (!sshkeysExec(self, output, &err_response, server_id, del_cmd, "userdel failed")) return err_response;
    if (!sshkeysRolesSave(self, server_id, &roles)) return respondError(output, "failed to save the roles marker");
    var detail_buf: [128]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "name={s}", .{payload.name}) catch "sshkeys.roles.delete";
    sshkeysAudit(self, "sshkeys.roles.delete", server_id, detail);
    return ok_json;
}

/// Server-side deploy key (spec 08 §5): `~/.ssh/oars_deploy` ed25519 with
/// no passphrase, 0600, idempotent; authorized_keys is never touched.
fn handleSshKeysDeployKeyGenerate(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(SshKeysDeployKeyPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const server_id = parsed.value.server_id;
    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "mkdir -p ~/.ssh && chmod 700 ~/.ssh && (test -f ~/.ssh/{s} || ssh-keygen -q -t ed25519 -N '' -f ~/.ssh/{s} -C oars-deploy) && chmod 600 ~/.ssh/{s} && cat ~/.ssh/{s}.pub", .{ deploy_key_name, deploy_key_name, deploy_key_name, deploy_key_name }) catch return respondError(output, "out of memory");
    var check = self.manager.execWait(server_id, cmd, sshkeys_exec_cap, sshkeys_exec_timeout_ns) catch {
        return respondError(output, "not connected");
    };
    defer check.output.deinit(self.allocator);
    if (check.exit != 0) return respondError(output, "ssh-keygen failed on the server");
    const pub_key = std.mem.trim(u8, check.output.items, " \t\r\n");
    if (pub_key.len == 0) return respondError(output, "the deploy key could not be read");
    sshkeysAudit(self, "sshkeys.deployKey.generate", server_id, "path=~/.ssh/oars_deploy");
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"public_key\":") catch return output[0..0];
    json.writeJsonString(&writer, pub_key) catch return output[0..0];
    writer.writeAll(",\"path\":\"~/.ssh/oars_deploy\"}") catch return output[0..0];
    return writer.buffered();
}

// --- access management (spec 09) -------------------------------------------

const access_exec_cap: usize = 256 * 1024;
const access_exec_timeout_ns = 10 * std.time.ns_per_s;
/// Row budget for poll/export serialization (the dispatcher gives handlers
/// a 1 MB result buffer; rows beyond the budget are dropped, counts stay
/// honest — the frontend windows large tables).
const access_poll_budget: usize = 512 * 1024;

const AccessScanPayload = struct {
    server_ids: ?[]const []const u8 = null,
    full: bool = false,
};
const AccessPollPayload = struct { scan_id: []const u8 };
const AccessIdentitySavePayload = struct { identity: access.IdentityInput };
const AccessIdentityDeletePayload = struct { id: []const u8 };
const AccessOffboardGrant = struct {
    fingerprint: []const u8,
    server_id: []const u8,
    user: []const u8,
    expected_line_hash: []const u8,
};
const AccessOffboardPayload = struct {
    identity_id: []const u8,
    grants: []const AccessOffboardGrant,
};
const AccessOnboardGrant = struct {
    server_id: []const u8,
    user: []const u8,
    read_only: bool = false,
};
const AccessOnboardPayload = struct {
    identity_id: []const u8,
    public_key: []const u8,
    grants: []const AccessOnboardGrant,
};
const AccessRotateGrant = struct {
    server_id: []const u8,
    user: []const u8,
    expected_line_hash: []const u8,
};
const AccessRotatePayload = struct {
    identity_id: []const u8,
    old_fingerprint: []const u8,
    new_public_key: []const u8,
    grants: []const AccessRotateGrant,
};
const AccessJobPollPayload = struct { job_id: []const u8 };
const AccessExportPayload = struct { format: []const u8 = "csv" };

fn accessAudit(self: *Context, action: []const u8, server_id: []const u8, detail: []const u8) void {
    sshkeysAudit(self, action, server_id, detail);
}

fn accessFail(server: *access.ServerScan, self: *Context, msg: []const u8) void {
    server.phase = .@"error";
    if (server.@"error") |e| self.allocator.free(e);
    server.@"error" = self.allocator.dupe(u8, msg) catch null;
}

fn accessExec(self: *Context, server_id: []const u8, cmd: []const u8) ?sessions.ExecOutcome {
    return self.manager.execWait(server_id, cmd, access_exec_cap, access_exec_timeout_ns) catch null;
}

fn accessSetOptional(self: *Context, slot: *?[]const u8, value: []const u8) void {
    if (slot.*) |old| self.allocator.free(old);
    slot.* = self.allocator.dupe(u8, value) catch null;
}

/// Seeds the connected account into `accounts` (its home via `echo ~`),
/// for connected-only scans and full scans without root.
fn accessSeedConnected(self: *Context, server: *access.ServerScan) bool {
    const user = server.connected_user orelse return false;
    var home_check = accessExec(self, server.server_id, "echo ~") orelse return false;
    defer home_check.output.deinit(self.allocator);
    const home = std.mem.trim(u8, home_check.output.items, " \t\r\n");
    if (home.len == 0 or home[0] != '/') return false;
    server.accounts.append(self.allocator, .{
        .user = self.allocator.dupe(u8, user) catch return false,
        .home = self.allocator.dupe(u8, home) catch return false,
    }) catch return false;
    return true;
}

/// Advances one server one phase. Each phase runs the execs it needs
/// (bounded, synchronous) so a poll never blocks for long.
fn accessAdvance(self: *Context, scan: *access.Scan, server: *access.ServerScan) void {
    switch (server.phase) {
        .queued => {
            const session = self.manager.get(server.server_id);
            if (session == null) return accessFail(server, self, "not connected (connect to this server first)");
            switch (session.?.status.load(.acquire)) {
                .ready => server.phase = .identity,
                .needs_trust => return accessFail(server, self, "session is waiting for host-key trust"),
                .@"error" => return accessFail(server, self, "session is in the error state"),
                else => {}, // connecting/authenticating: retry on the next poll
            }
        },
        .connecting => {}, // not produced by the current plan; reserved
        .identity => {
            var who = accessExec(self, server.server_id, "whoami") orelse return accessFail(server, self, "not connected");
            defer who.output.deinit(self.allocator);
            if (who.exit != 0) return accessFail(server, self, "whoami failed");
            const user = std.mem.trim(u8, who.output.items, " \t\r\n");
            if (user.len == 0 or !access.safeUserName(user)) return accessFail(server, self, "cannot determine the connected user");
            accessSetOptional(self, &server.connected_user, user);
            var idc = accessExec(self, server.server_id, "id -u") orelse return accessFail(server, self, "not connected");
            defer idc.output.deinit(self.allocator);
            const uid = std.mem.trim(u8, idc.output.items, " \t\r\n");
            server.privileged = idc.exit == 0 and std.mem.eql(u8, uid, "0");
            if (server.privileged) {
                // Root is its own sudo authority; no probe needed.
                accessSetOptional(self, &server.sudo, access.sudo_yes);
                server.phase = if (scan.full) .enumerate else .read_accounts;
            } else {
                server.phase = .sudo_probe;
            }
        },
        .sudo_probe => {
            var probe = accessExec(self, server.server_id, "sudo -n -l 2>&1") orelse return accessFail(server, self, "not connected");
            defer probe.output.deinit(self.allocator);
            accessSetOptional(self, &server.sudo, access.parseSudoList(probe.exit, probe.output.items));
            if (scan.full) {
                if (!server.privileged) {
                    accessSetOptional(self, &server.coverage_reason, "cannot enumerate accounts without root");
                }
                server.phase = .enumerate;
            } else {
                server.phase = .read_accounts;
            }
        },
        .enumerate => {
            if (!server.privileged) {
                // Full scan without authority: the connected account only.
                if (!accessSeedConnected(self, server)) return accessFail(server, self, "cannot resolve the connected account's home");
                server.phase = .read_accounts;
                return;
            }
            const connected_user = server.connected_user orelse return accessFail(server, self, "cannot determine the connected user");
            var out = accessExec(self, server.server_id, "getent passwd") orelse return accessFail(server, self, "not connected");
            defer out.output.deinit(self.allocator);
            if (out.exit != 0) return accessFail(server, self, "cannot enumerate accounts");
            const entries = access.parsePasswd(self.allocator, out.output.items) catch null;
            defer if (entries) |list| {
                for (list) |*e| e.deinit(self.allocator);
                self.allocator.free(list);
            };
            const skipped = access.skippedAccounts(self.allocator, out.output.items) catch null;
            defer if (skipped) |list| {
                for (list) |n| self.allocator.free(n);
                self.allocator.free(list);
            };
            if (entries == null and skipped == null) {
                accessSetOptional(self, &server.coverage_reason, "cannot enumerate accounts");
            }
            // The connected account always leads the list (root is uid 0
            // and would be filtered out by the uid >= 1000 rule).
            if (!accessSeedConnected(self, server)) {
                accessSetOptional(self, &server.coverage_reason, "cannot resolve the connected account's home");
            }
            if (entries) |list| {
                for (list) |*e| {
                    if (std.mem.eql(u8, e.name, connected_user)) continue; // already seeded
                    server.accounts.append(self.allocator, .{
                        .user = self.allocator.dupe(u8, e.name) catch continue,
                        .home = self.allocator.dupe(u8, e.home) catch continue,
                    }) catch continue;
                }
            }
            if (skipped) |list| {
                for (list) |name| {
                    if (std.mem.eql(u8, name, connected_user)) continue;
                    server.accounts.append(self.allocator, .{
                        .user = self.allocator.dupe(u8, name) catch continue,
                        .home = self.allocator.dupe(u8, "") catch continue,
                        .skipped = true,
                    }) catch continue;
                }
            }
            server.next_account = 0;
            server.phase = .read_accounts;
        },
        .read_accounts => {
            if (server.accounts.items.len == 0) {
                // Connected-only scan: seed before reading.
                if (!accessSeedConnected(self, server)) return accessFail(server, self, "cannot resolve the connected account's home");
                return; // the next poll reads the seeded account
            }
            const i = server.next_account;
            if (i >= server.accounts.items.len) {
                server.phase = .sshd_config;
                return;
            }
            const acc = &server.accounts.items[i];
            server.next_account += 1;
            if (acc.skipped) return;
            if (acc.home.len == 0 or acc.home[0] != '/') {
                accessSetOptional(self, &acc.@"error", "cannot resolve the account's home");
                return;
            }
            var path_buf: [512]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, "{s}/.ssh/authorized_keys", .{acc.home}) catch {
                accessSetOptional(self, &acc.@"error", "cannot resolve the authorized_keys path");
                return;
            };
            const content = sshkeysRead(self, server.server_id, path);
            if (content) |c| {
                defer self.allocator.free(c);
                var file = sshkeys.parse(self.allocator, c) catch {
                    accessSetOptional(self, &acc.@"error", "authorized_keys could not be parsed");
                    return;
                };
                defer file.deinit(self.allocator);
                acc.key_count = file.keys.len;
                for (file.keys) |*k| {
                    if (!k.parsed) continue;
                    // One grant per (user, fingerprint); the first line's
                    // comment and hash are the stable snapshot.
                    var seen = false;
                    for (server.grants.items) |*g| {
                        if (std.mem.eql(u8, g.fingerprint, k.fingerprint_sha256) and std.mem.eql(u8, g.user, acc.user)) {
                            seen = true;
                            break;
                        }
                    }
                    if (seen) continue;
                    server.grants.append(self.allocator, .{
                        .fingerprint = self.allocator.dupe(u8, k.fingerprint_sha256) catch continue,
                        .user = self.allocator.dupe(u8, acc.user) catch continue,
                        .sudo = self.allocator.dupe(u8, "") catch continue,
                        .comment = self.allocator.dupe(u8, k.comment) catch continue,
                        .line_hash = self.allocator.dupe(u8, k.line_hash) catch continue,
                    }) catch continue;
                }
                acc.read = true;
            } else {
                // Missing file = an inspected, empty inventory.
                acc.read = true;
            }
            // Sudo status per account (spec 09 §5): the connected account
            // reuses the probe; others need a root-run policy query.
            if (std.mem.eql(u8, acc.user, server.connected_user orelse "")) {
                accessSetOptional(self, &acc.sudo, server.sudo orelse access.sudo_unknown);
            } else if (server.privileged and access.safeUserName(acc.user)) {
                var cmd_buf: [128]u8 = undefined;
                const cmd = std.fmt.bufPrint(&cmd_buf, "sudo -n -l -U {s} 2>&1", .{acc.user}) catch {
                    accessSetOptional(self, &acc.sudo, access.sudo_unknown);
                    return;
                };
                var sudo_out = accessExec(self, server.server_id, cmd) orelse {
                    accessSetOptional(self, &acc.sudo, access.sudo_unknown);
                    return;
                };
                defer sudo_out.output.deinit(self.allocator);
                accessSetOptional(self, &acc.sudo, access.parseSudoList(sudo_out.exit, sudo_out.output.items));
            } else {
                accessSetOptional(self, &acc.sudo, access.sudo_unknown);
            }
            // Grants pick up the account's resolved sudo status.
            for (server.grants.items) |*g| {
                if (std.mem.eql(u8, g.user, acc.user) and g.sudo.len == 0) {
                    self.allocator.free(g.sudo);
                    g.sudo = self.allocator.dupe(u8, acc.sudo orelse access.sudo_unknown) catch continue;
                }
            }
        },
        .sshd_config => {
            var out = accessExec(self, server.server_id, "grep -hE '^(AuthorizedKeysFile|AuthorizedKeysCommand|AuthorizedKeysCommandUser|AuthorizedKeysUserCA)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null") orelse return accessFail(server, self, "not connected");
            defer out.output.deinit(self.allocator);
            if (out.exit == 0) {
                var lines = std.mem.splitScalar(u8, out.output.items, '\n');
                while (lines.next()) |raw| {
                    const line = std.mem.trim(u8, raw, " \t\r");
                    if (line.len == 0) continue;
                    server.sources.append(self.allocator, self.allocator.dupe(u8, line) catch continue) catch continue;
                }
            }
            if (access.sshdSourcesForcePartial(server.sources.items)) {
                accessSetOptional(self, &server.coverage_reason, "dynamic or alternate AuthorizedKeys sources");
            }
            for (server.accounts.items) |*acc| {
                if (acc.skipped) continue;
                if (!acc.read) {
                    accessSetOptional(self, &server.coverage_reason, "some accounts could not be read");
                    break;
                }
            }
            if (server.coverage_reason == null) {
                accessSetOptional(self, &server.coverage, access.coverage_complete);
            } else {
                accessSetOptional(self, &server.coverage, access.coverage_partial);
            }
            server.done = true;
            server.phase = .done;
        },
        .done, .@"error" => {},
    }
}

fn accessServerExists(self: *Context, server_id: []const u8) bool {
    var loaded = self.store.loadParsed(self.io) catch return false;
    defer loaded.deinit(self.allocator);
    for (loaded.parsed.value) |s| {
        if (std.mem.eql(u8, s.id, server_id)) return true;
    }
    return false;
}

fn handleAccessScan(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessScanPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    var loaded = self.store.loadParsed(self.io) catch return respondError(output, "server registry is unreadable");
    defer loaded.deinit(self.allocator);
    const servers_all = loaded.parsed.value;

    // Resolve the target server ids (default: every saved server).
    var ids: std.ArrayList([]const u8) = .empty;
    defer {
        for (ids.items) |id| self.allocator.free(id);
        ids.deinit(self.allocator);
    }
    if (payload.server_ids) |list| {
        for (list) |id| {
            var found = false;
            for (servers_all) |s| {
                if (std.mem.eql(u8, s.id, id)) {
                    found = true;
                    break;
                }
            }
            if (!found) return respondError(output, "unknown server");
            try ids.append(self.allocator, try self.allocator.dupe(u8, id));
        }
    } else {
        for (servers_all) |s| {
            try ids.append(self.allocator, try self.allocator.dupe(u8, s.id));
        }
    }

    var scan = self.allocator.create(access.Scan) catch return respondError(output, "out of memory");
    errdefer {
        scan.deinit(self.allocator);
        self.allocator.destroy(scan);
    }
    scan.* = .{
        .id = std.fmt.allocPrint(self.allocator, "scan-{d}", .{self.access.next_scan_id}) catch return respondError(output, "out of memory"),
        .full = payload.full,
        .created_at_ns = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds),
        .servers = self.allocator.alloc(access.ServerScan, ids.items.len) catch return respondError(output, "out of memory"),
    };
    self.access.next_scan_id +%= 1;
    for (ids.items, 0..) |id, i| {
        var name: []const u8 = id;
        var host: []const u8 = "";
        for (servers_all) |s| {
            if (std.mem.eql(u8, s.id, id)) {
                name = s.name;
                host = s.host;
                break;
            }
        }
        scan.servers[i] = .{
            .server_id = self.allocator.dupe(u8, id) catch return respondError(output, "out of memory"),
            .name = self.allocator.dupe(u8, name) catch return respondError(output, "out of memory"),
            .host = self.allocator.dupe(u8, host) catch return respondError(output, "out of memory"),
        };
    }
    self.access.registerScan(scan);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"scan_id\":") catch return output[0..0];
    json.writeJsonString(&writer, scan.id) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn accessWriteGrantView(writer: anytype, g: *const access.GrantView) !void {
    try writer.writeAll("{\"fingerprint\":");
    try json.writeJsonString(writer, g.fingerprint);
    try writer.writeAll(",\"user\":");
    try json.writeJsonString(writer, g.user);
    try writer.writeAll(",\"sudo\":");
    try json.writeJsonString(writer, g.sudo);
    try writer.writeAll(",\"comment\":");
    try json.writeJsonString(writer, g.comment);
    try writer.writeAll(",\"line_hash\":");
    try json.writeJsonString(writer, g.line_hash);
    try writer.writeAll("}");
}

fn accessWriteServerView(writer: anytype, v: *const access.ServerView, budget: *usize) !void {
    try writer.writeAll("{\"server_id\":");
    try json.writeJsonString(writer, v.server_id);
    try writer.writeAll(",\"name\":");
    try json.writeJsonString(writer, v.name);
    try writer.writeAll(",\"host\":");
    try json.writeJsonString(writer, v.host);
    try writer.writeAll(",\"phase\":");
    try json.writeJsonString(writer, v.phase);
    if (v.@"error".len > 0) {
        try writer.writeAll(",\"error\":");
        try json.writeJsonString(writer, v.@"error");
    }
    if (v.connected_user.len > 0) {
        try writer.writeAll(",\"connected_user\":");
        try json.writeJsonString(writer, v.connected_user);
    }
    try writer.writeAll(",\"sudo\":");
    try json.writeJsonString(writer, v.sudo);
    try writer.writeAll(",\"coverage\":");
    try json.writeJsonString(writer, v.coverage);
    if (v.coverage_reason.len > 0) {
        try writer.writeAll(",\"coverage_reason\":");
        try json.writeJsonString(writer, v.coverage_reason);
    }
    try writer.writeAll(",\"accounts\":[");
    var first = true;
    for (v.accounts) |*a| {
        if (budget.* < 64) break;
        budget.* -= 64;
        if (!first) try writer.writeAll(",");
        first = false;
        try writer.writeAll("{\"user\":");
        try json.writeJsonString(writer, a.user);
        try writer.writeAll(",\"home\":");
        try json.writeJsonString(writer, a.home);
        try writer.writeAll(",\"skipped\":");
        try writer.writeAll(if (a.skipped) "true" else "false");
        try writer.writeAll(",\"read\":");
        try writer.writeAll(if (a.read) "true" else "false");
        if (a.@"error".len > 0) {
            try writer.writeAll(",\"error\":");
            try json.writeJsonString(writer, a.@"error");
        }
        try writer.writeAll(",\"sudo\":");
        try json.writeJsonString(writer, a.sudo);
        try writer.print(",\"key_count\":{d}", .{a.key_count});
        try writer.writeAll("}");
    }
    try writer.writeAll("],\"grants\":[");
    first = true;
    for (v.grants) |*g| {
        if (budget.* < 128) break;
        budget.* -= 128;
        if (!first) try writer.writeAll(",");
        first = false;
        try accessWriteGrantView(writer, g);
    }
    try writer.writeAll("],\"sources\":[");
    first = true;
    for (v.sources) |s| {
        if (!first) try writer.writeAll(",");
        first = false;
        try json.writeJsonString(writer, s);
    }
    try writer.writeAll("]}");
}

fn accessWritePerson(writer: anytype, p: *const access.Person) !void {
    try writer.writeAll("{\"identity_id\":");
    try json.writeJsonString(writer, p.identity_id);
    try writer.writeAll(",\"name\":");
    try json.writeJsonString(writer, p.name);
    try writer.writeAll(",\"fingerprints\":[");
    var first = true;
    for (p.fingerprints) |fp| {
        if (!first) try writer.writeAll(",");
        first = false;
        try json.writeJsonString(writer, fp);
    }
    try writer.writeAll("],\"grants\":[");
    first = true;
    for (p.grants) |*g| {
        if (!first) try writer.writeAll(",");
        first = false;
        try writer.writeAll("{\"fingerprint\":");
        try json.writeJsonString(writer, g.fingerprint);
        try writer.writeAll(",\"server_id\":");
        try json.writeJsonString(writer, g.server_id);
        try writer.writeAll(",\"server_name\":");
        try json.writeJsonString(writer, g.server_name);
        try writer.writeAll(",\"user\":");
        try json.writeJsonString(writer, g.user);
        try writer.writeAll(",\"sudo\":");
        try json.writeJsonString(writer, g.sudo);
        try writer.writeAll(",\"comment\":");
        try json.writeJsonString(writer, g.comment);
        try writer.writeAll(",\"line_hash\":");
        try json.writeJsonString(writer, g.line_hash);
        try writer.writeAll("}");
    }
    try writer.writeAll("]}");
}

fn handleAccessPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessPollPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const scan = self.access.scanById(parsed.value.scan_id) orelse return respondError(output, "unknown scan");

    for (scan.servers) |*server| {
        if (server.done or server.phase == .@"error") continue;
        accessAdvance(self, scan, server);
    }

    var all_done = true;
    var views: std.ArrayList(access.ServerView) = .empty;
    defer {
        for (views.items) |*v| v.deinit(self.allocator);
        views.deinit(self.allocator);
    }
    for (scan.servers) |*server| {
        if (!server.done and server.phase != .@"error") all_done = false;
        views.append(self.allocator, access.serverView(self.allocator, server) catch continue) catch continue;
    }

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"state\":") catch return output[0..0];
    json.writeJsonString(&writer, if (all_done) "done" else "scanning") catch return output[0..0];
    writer.writeAll(",\"servers\":[") catch return output[0..0];
    var budget: usize = access_poll_budget;
    var first = true;
    for (views.items) |*v| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        accessWriteServerView(&writer, v, &budget) catch return output[0..0];
    }
    writer.writeAll("],\"people\":[") catch return output[0..0];
    var server_count: usize = 0;
    var grant_count: usize = 0;
    var coverage: []const u8 = access.coverage_partial;
    if (all_done) {
        const identities = self.access.identities.list(self.io) catch {
            return respondError(output, "identity registry is unreadable");
        };
        defer {
            for (identities) |*i| i.deinit(self.allocator);
            self.allocator.free(identities);
        }
        const scans = [_]*access.Scan{scan};
        var map = access.buildMap(self.allocator, &scans, identities) catch return respondError(output, "out of memory");
        defer map.deinit(self.allocator);
        first = true;
        for (map.people) |*p| {
            if (budget < 128) break;
            budget -= 128;
            if (!first) writer.writeAll(",") catch return output[0..0];
            first = false;
            accessWritePerson(&writer, p) catch return output[0..0];
        }
        writer.writeAll("],\"unassigned\":[") catch return output[0..0];
        first = true;
        for (map.unassigned) |*u| {
            if (budget < 96) break;
            budget -= 96;
            if (!first) writer.writeAll(",") catch return output[0..0];
            first = false;
            writer.writeAll("{\"fingerprint\":") catch return output[0..0];
            json.writeJsonString(&writer, u.fingerprint) catch return output[0..0];
            writer.writeAll(",\"grants\":[") catch return output[0..0];
            var gfirst = true;
            for (u.grants) |*g| {
                if (!gfirst) writer.writeAll(",") catch return output[0..0];
                gfirst = false;
                try accessWritePersonGrant(&writer, g);
            }
            writer.writeAll("]}") catch return output[0..0];
        }
        server_count = map.server_count;
        grant_count = map.grant_count;
        coverage = map.coverage;
        writer.writeAll("],\"servers_count\":") catch return output[0..0];
        writer.print("{d},\"grants_count\":{d},\"coverage\":", .{ server_count, grant_count }) catch return output[0..0];
        json.writeJsonString(&writer, coverage) catch return output[0..0];
        writer.writeAll(",\"sync_errors\":[") catch return output[0..0];
        first = true;
        for (map.sync_errors) |*e| {
            if (!first) writer.writeAll(",") catch return output[0..0];
            first = false;
            writer.writeAll("{\"server_id\":") catch return output[0..0];
            json.writeJsonString(&writer, e.server_id) catch return output[0..0];
            writer.writeAll(",\"reason\":") catch return output[0..0];
            json.writeJsonString(&writer, e.reason) catch return output[0..0];
            writer.writeAll("}") catch return output[0..0];
        }
        writer.writeAll("]}") catch return output[0..0];
    } else {
        writer.writeAll("],\"unassigned\":[],\"servers_count\":0,\"grants_count\":0,\"coverage\":") catch return output[0..0];
        json.writeJsonString(&writer, coverage) catch return output[0..0];
        writer.writeAll(",\"sync_errors\":[]}") catch return output[0..0];
    }
    return writer.buffered();
}

fn accessWritePersonGrant(writer: anytype, g: *const access.PersonGrant) !void {
    try writer.writeAll("{\"fingerprint\":");
    try json.writeJsonString(writer, g.fingerprint);
    try writer.writeAll(",\"server_id\":");
    try json.writeJsonString(writer, g.server_id);
    try writer.writeAll(",\"server_name\":");
    try json.writeJsonString(writer, g.server_name);
    try writer.writeAll(",\"user\":");
    try json.writeJsonString(writer, g.user);
    try writer.writeAll(",\"sudo\":");
    try json.writeJsonString(writer, g.sudo);
    try writer.writeAll(",\"comment\":");
    try json.writeJsonString(writer, g.comment);
    try writer.writeAll(",\"line_hash\":");
    try json.writeJsonString(writer, g.line_hash);
    try writer.writeAll("}");
}

fn handleAccessIdentitiesList(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    _ = invocation;
    const self = contextOf(context);
    const identities = self.access.identities.list(self.io) catch {
        return respondError(output, "identity registry is unreadable");
    };
    defer {
        for (identities) |*i| i.deinit(self.allocator);
        self.allocator.free(identities);
    }
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"identities\":[") catch return output[0..0];
    var first = true;
    for (identities) |*i| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.writeAll("{\"id\":") catch return output[0..0];
        json.writeJsonString(&writer, i.id) catch return output[0..0];
        writer.writeAll(",\"name\":") catch return output[0..0];
        json.writeJsonString(&writer, i.name) catch return output[0..0];
        writer.writeAll(",\"fingerprints\":[") catch return output[0..0];
        var ffirst = true;
        for (i.fingerprints) |fp| {
            if (!ffirst) writer.writeAll(",") catch return output[0..0];
            ffirst = false;
            json.writeJsonString(&writer, fp) catch return output[0..0];
        }
        writer.print("],\"shared\":{s},\"created_at_ns\":{d}", .{ if (i.shared) "true" else "false", i.created_at_ns }) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

fn handleAccessIdentitiesSave(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessIdentitySavePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    var saved = self.access.identities.save(self.io, parsed.value.identity, @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds)) catch |err| {
        return respondError(output, switch (err) {
            error.MissingName, error.InvalidName => "invalid identity name",
            error.NoFingerprints => "at least one fingerprint is required",
            error.TooManyFingerprints => "too many fingerprints",
            error.InvalidFingerprint => "invalid fingerprint",
            error.DuplicateFingerprint => "duplicate fingerprint",
            error.FingerprintOwned => "a fingerprint can belong to at most one person unless it is marked shared",
            error.UnknownId => "unknown identity",
            else => "identity registry is unreadable",
        });
    };
    defer saved.deinit(self.allocator);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"identity\":{\"id\":") catch return output[0..0];
    json.writeJsonString(&writer, saved.id) catch return output[0..0];
    writer.writeAll(",\"name\":") catch return output[0..0];
    json.writeJsonString(&writer, saved.name) catch return output[0..0];
    writer.writeAll(",\"fingerprints\":[") catch return output[0..0];
    var first = true;
    for (saved.fingerprints) |fp| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        json.writeJsonString(&writer, fp) catch return output[0..0];
    }
    writer.print("],\"shared\":{s}", .{if (saved.shared) "true" else "false"}) catch return output[0..0];
    writer.writeAll("}}") catch return output[0..0];
    return writer.buffered();
}

fn handleAccessIdentitiesDelete(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessIdentityDeletePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    if (!(self.access.identities.delete(self.io, parsed.value.id) catch return respondError(output, "identity registry is unreadable"))) {
        return respondError(output, "unknown identity");
    }
    var detail_buf: [128]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "id={s}", .{parsed.value.id}) catch "access.identities.delete";
    sshkeysAudit(self, "access.identities.delete", "", detail);
    return ok_json;
}

fn accessNewJob(self: *Context, kind: access.JobKind, identity_id: []const u8) !*access.Job {
    const job = try self.allocator.create(access.Job);
    errdefer self.allocator.destroy(job);
    job.* = .{
        .id = try std.fmt.allocPrint(self.allocator, "job-{d}", .{self.access.next_job_id}),
        .kind = kind,
        .identity_id = try self.allocator.dupe(u8, identity_id),
        .created_at_ns = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds),
    };
    self.access.next_job_id +%= 1;
    return job;
}

fn accessIdentityHasFingerprint(identity: *const access.Identity, fingerprint: []const u8) bool {
    for (identity.fingerprints) |fp| {
        if (std.mem.eql(u8, fp, fingerprint)) return true;
    }
    return false;
}

fn handleAccessOffboard(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessOffboardPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.grants.len == 0) return respondError(output, "no grants selected");
    var identity = self.access.identities.find(self.io, payload.identity_id) catch {
        return respondError(output, "identity registry is unreadable");
    };
    defer if (identity) |*i| i.deinit(self.allocator);
    const id = identity orelse return respondError(output, "unknown identity");

    var job = accessNewJob(self, .offboard, payload.identity_id) catch return respondError(output, "out of memory");
    errdefer {
        job.deinit(self.allocator);
        self.allocator.destroy(job);
    }
    for (payload.grants) |g| {
        if (!accessIdentityHasFingerprint(&id, g.fingerprint)) return respondError(output, "fingerprint is not part of this identity");
        if (!access.safeUserName(g.user)) return respondError(output, "invalid user name");
        if (g.expected_line_hash.len == 0) return respondError(output, "missing line hash");
        if (!accessServerExists(self, g.server_id)) return respondError(output, "unknown server");
        job.items.append(self.allocator, .{
            .server_id = self.allocator.dupe(u8, g.server_id) catch return respondError(output, "out of memory"),
            .user = self.allocator.dupe(u8, g.user) catch return respondError(output, "out of memory"),
            .fingerprint = self.allocator.dupe(u8, g.fingerprint) catch return respondError(output, "out of memory"),
            .expected_line_hash = self.allocator.dupe(u8, g.expected_line_hash) catch return respondError(output, "out of memory"),
        }) catch return respondError(output, "out of memory");
    }
    self.access.registerJob(job);
    var detail_buf: [128]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "identity={s} items={d}", .{ payload.identity_id, payload.grants.len }) catch "access.offboard";
    sshkeysAudit(self, "access.offboard", "", detail);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job_id\":") catch return output[0..0];
    json.writeJsonString(&writer, job.id) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleAccessOnboard(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessOnboardPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.grants.len == 0) return respondError(output, "no grants selected");
    var identity = self.access.identities.find(self.io, payload.identity_id) catch {
        return respondError(output, "identity registry is unreadable");
    };
    defer if (identity) |*i| i.deinit(self.allocator);
    const id = identity orelse return respondError(output, "unknown identity");
    for (payload.grants) |g| {
        if (g.read_only and std.mem.eql(u8, g.user, "root")) return respondError(output, "read-only access to root is not supported");
    }

    const normalized = sshkeys.normalizePublicKey(self.allocator, payload.public_key, id.name) catch |err| {
        return respondError(output, switch (err) {
            error.Multiline => "public key must be a single line",
            else => "invalid public key",
        });
    };
    defer {
        self.allocator.free(normalized.line);
        self.allocator.free(normalized.fingerprint_sha256);
    }

    var job = accessNewJob(self, .onboard, payload.identity_id) catch return respondError(output, "out of memory");
    errdefer {
        job.deinit(self.allocator);
        self.allocator.destroy(job);
    }
    for (payload.grants) |g| {
        if (!access.safeUserName(g.user)) return respondError(output, "invalid user name");
        if (!accessServerExists(self, g.server_id)) return respondError(output, "unknown server");
        job.items.append(self.allocator, .{
            .server_id = self.allocator.dupe(u8, g.server_id) catch return respondError(output, "out of memory"),
            .user = self.allocator.dupe(u8, g.user) catch return respondError(output, "out of memory"),
            .fingerprint = self.allocator.dupe(u8, normalized.fingerprint_sha256) catch return respondError(output, "out of memory"),
            .public_key_line = self.allocator.dupe(u8, normalized.line) catch return respondError(output, "out of memory"),
            .read_only = g.read_only,
        }) catch return respondError(output, "out of memory");
    }
    self.access.registerJob(job);
    var detail_buf: [192]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "identity={s} fingerprint={s} items={d}", .{ payload.identity_id, normalized.fingerprint_sha256, payload.grants.len }) catch "access.onboard";
    sshkeysAudit(self, "access.onboard", "", detail);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job_id\":") catch return output[0..0];
    json.writeJsonString(&writer, job.id) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleAccessRotate(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessRotatePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.grants.len == 0) return respondError(output, "no grants selected");
    var identity = self.access.identities.find(self.io, payload.identity_id) catch {
        return respondError(output, "identity registry is unreadable");
    };
    defer if (identity) |*i| i.deinit(self.allocator);
    const id = identity orelse return respondError(output, "unknown identity");
    if (!accessIdentityHasFingerprint(&id, payload.old_fingerprint)) {
        return respondError(output, "the old fingerprint is not part of this identity");
    }
    const normalized = sshkeys.normalizePublicKey(self.allocator, payload.new_public_key, id.name) catch |err| {
        return respondError(output, switch (err) {
            error.Multiline => "public key must be a single line",
            else => "invalid public key",
        });
    };
    defer {
        self.allocator.free(normalized.line);
        self.allocator.free(normalized.fingerprint_sha256);
    }

    var job = accessNewJob(self, .rotate, payload.identity_id) catch return respondError(output, "out of memory");
    errdefer {
        job.deinit(self.allocator);
        self.allocator.destroy(job);
    }
    for (payload.grants) |g| {
        if (!access.safeUserName(g.user)) return respondError(output, "invalid user name");
        if (g.expected_line_hash.len == 0) return respondError(output, "missing line hash");
        if (!accessServerExists(self, g.server_id)) return respondError(output, "unknown server");
        job.items.append(self.allocator, .{
            .server_id = self.allocator.dupe(u8, g.server_id) catch return respondError(output, "out of memory"),
            .user = self.allocator.dupe(u8, g.user) catch return respondError(output, "out of memory"),
            .fingerprint = self.allocator.dupe(u8, payload.old_fingerprint) catch return respondError(output, "out of memory"),
            .expected_line_hash = self.allocator.dupe(u8, g.expected_line_hash) catch return respondError(output, "out of memory"),
            .public_key_line = self.allocator.dupe(u8, normalized.line) catch return respondError(output, "out of memory"),
        }) catch return respondError(output, "out of memory");
    }
    self.access.registerJob(job);
    var detail_buf: [192]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "identity={s} old={s} items={d}", .{ payload.identity_id, payload.old_fingerprint, payload.grants.len }) catch "access.rotate";
    sshkeysAudit(self, "access.rotate", "", detail);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job_id\":") catch return output[0..0];
    json.writeJsonString(&writer, job.id) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn accessItemError(self: *Context, item: *access.JobItem, msg: []const u8) void {
    item.state = .@"error";
    if (item.@"error") |e| self.allocator.free(e);
    item.@"error" = self.allocator.dupe(u8, msg) catch null;
}

fn accessAuditItem(self: *Context, action: []const u8, item: *const access.JobItem) void {
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "server={s} user={s} fingerprint={s}", .{ item.server_id, item.user, item.fingerprint }) catch action;
    sshkeysAudit(self, action, item.server_id, detail);
}

/// Executes one job item (one authorized_keys mutation). Idempotent by
/// fingerprint: offboard/rotate remove or replace only the matched line;
/// onboard skips a key that is already present.
fn accessRunItem(self: *Context, job: *access.Job, item: *access.JobItem) void {
    var msg: []const u8 = "";
    switch (job.kind) {
        .offboard, .rotate => {
            const path = sshkeysPathMsg(self, item.server_id, item.user, &msg) orelse return accessItemError(self, item, msg);
            defer self.allocator.free(path);
            const replacement: ?[]const u8 = if (job.kind == .rotate) item.public_key_line else null;
            var write_err_buf: [256]u8 = undefined;
            const rewritten = sshkeysRewriteCore(self, item.server_id, path, item.fingerprint, item.expected_line_hash, replacement, item.user, &msg, &write_err_buf) orelse return accessItemError(self, item, msg);
            defer self.allocator.free(rewritten);
            accessAuditItem(self, if (job.kind == .offboard) "access.offboard" else "access.rotate", item);
            item.state = .done;
        },
        .onboard => {
            // Read-only items create the role user first (the path
            // resolution below needs the account to exist).
            var options: ?[]const u8 = null;
            defer if (options) |o| self.allocator.free(o);
            if (item.read_only) {
                if (sshkeysRoleEnsureCore(self, item.server_id, item.user, true)) |emsg| return accessItemError(self, item, emsg);
                options = sshkeysRoleOptions(self, item.server_id, item.user);
                if (options == null) return accessItemError(self, item, "user is not a read-only role");
            }
            const path = sshkeysPathMsg(self, item.server_id, item.user, &msg) orelse return accessItemError(self, item, msg);
            defer self.allocator.free(path);
            if (sshkeysEnsureSshDir(self, item.server_id, path)) |emsg| return accessItemError(self, item, emsg);
            const content = sshkeysRead(self, item.server_id, path) orelse "";
            defer if (content.len > 0) self.allocator.free(content);
            if (content.len > 0) {
                var file = sshkeys.parse(self.allocator, content) catch return accessItemError(self, item, "failed to parse authorized_keys");
                defer file.deinit(self.allocator);
                for (file.keys) |*k| {
                    if (k.parsed and std.mem.eql(u8, k.fingerprint_sha256, item.fingerprint)) {
                        item.state = .done; // idempotent: already present
                        return;
                    }
                }
            }
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(self.allocator);
            if (content.len > 0) {
                out.appendSlice(self.allocator, content) catch return accessItemError(self, item, "out of memory");
                if (content[content.len - 1] != '\n') out.append(self.allocator, '\n') catch return accessItemError(self, item, "out of memory");
            }
            if (options) |o| {
                out.appendSlice(self.allocator, o) catch return accessItemError(self, item, "out of memory");
                out.append(self.allocator, ' ') catch return accessItemError(self, item, "out of memory");
            }
            out.appendSlice(self.allocator, item.public_key_line) catch return accessItemError(self, item, "out of memory");
            out.append(self.allocator, '\n') catch return accessItemError(self, item, "out of memory");
            const mode = sshkeysMode(self, item.server_id, path);
            var write_err_buf: [256]u8 = undefined;
            if (sshkeysWrite(self, item.server_id, path, out.items, mode, item.user, &write_err_buf)) |emsg| return accessItemError(self, item, emsg);
            accessAuditItem(self, "access.onboard", item);
            item.state = .done;
        },
    }
}

fn handleAccessJobPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessJobPollPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const job = self.access.jobById(parsed.value.job_id) orelse return respondError(output, "unknown job");

    // One mutation per poll keeps every handler invocation bounded.
    for (job.items.items) |*item| {
        if (item.state != .queued) continue;
        accessRunItem(self, job, item);
        break;
    }

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"state\":") catch return output[0..0];
    json.writeJsonString(&writer, if (job.finished()) "done" else "running") catch return output[0..0];
    writer.writeAll(",\"results\":[") catch return output[0..0];
    var first = true;
    for (job.items.items) |*item| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.writeAll("{\"server_id\":") catch return output[0..0];
        json.writeJsonString(&writer, item.server_id) catch return output[0..0];
        writer.writeAll(",\"user\":") catch return output[0..0];
        json.writeJsonString(&writer, item.user) catch return output[0..0];
        writer.writeAll(",\"state\":") catch return output[0..0];
        json.writeJsonString(&writer, item.state.jsonName()) catch return output[0..0];
        if (item.@"error") |e| {
            writer.writeAll(",\"error\":") catch return output[0..0];
            json.writeJsonString(&writer, e) catch return output[0..0];
        }
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

fn handleAccessExport(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessExportPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const format = parsed.value.format;
    if (!std.mem.eql(u8, format, "csv") and !std.mem.eql(u8, format, "json")) {
        return respondError(output, "invalid format");
    }
    const scan = self.access.lastFinishedScan() orelse return respondError(output, "no completed scan yet");
    const identities = self.access.identities.list(self.io) catch {
        return respondError(output, "identity registry is unreadable");
    };
    defer {
        for (identities) |*i| i.deinit(self.allocator);
        self.allocator.free(identities);
    }
    const scans = [_]*access.Scan{scan};
    var map = access.buildMap(self.allocator, &scans, identities) catch return respondError(output, "out of memory");
    defer map.deinit(self.allocator);
    const content = if (std.mem.eql(u8, format, "json"))
        access.exportJson(self.allocator, &map) catch return respondError(output, "out of memory")
    else
        access.exportCsv(self.allocator, &map) catch return respondError(output, "out of memory");
    defer self.allocator.free(content);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"format\":") catch return output[0..0];
    json.writeJsonString(&writer, format) catch return output[0..0];
    writer.writeAll(",\"content\":") catch return output[0..0];
    json.writeJsonString(&writer, content) catch return respondError(output, "export too large for one response; narrow the fleet");
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

test "logs scan command is marker-escaped for busybox and GNU printf" {
    // busybox printf errors on bare %B-style directives and prints nothing
    // (verified live); `%%` escapes work on both busybox and GNU. The find
    // `-printf` directives are a separate format and keep single %.
    try std.testing.expect(std.mem.indexOf(u8, logs_scan_prefix, "%%BEGIN_DATE%%") != null);
    try std.testing.expect(std.mem.indexOf(u8, logs_scan_prefix, "%%BEGIN_SCAN%%") != null);
    // The busybox fallback exists and is joined with `||` (not `;`): a find
    // without -printf fails over instead of emitting two streams.
    try std.testing.expect(std.mem.indexOf(u8, logs_scan_middle, "|| find") != null);
    try std.testing.expect(std.mem.indexOf(u8, logs_scan_middle, "; find") == null);
    try std.testing.expect(std.mem.indexOf(u8, logs_scan_suffix, "-print0") != null);
    try std.testing.expect(std.mem.indexOf(u8, logs_scan_suffix, "stat -c") != null);
    try std.testing.expect(std.mem.indexOf(u8, logs_scan_suffix, "|| printf '0 0 0") != null);
}

// --- backups (spec 10) ------------------------------------------------------

const backup_exec_cap: usize = 256 * 1024;
const backup_exec_timeout_ns = 20 * std.time.ns_per_s;
/// Per-run log bytes in history responses (stored history keeps the full
/// 200 KB budget; responses stay well under the 1 MB result buffer).
const backup_response_log_cap: usize = 32 * 1024;

const BackupJobsListPayload = struct { server_id: []const u8 };
const BackupCredentials = struct {
    access_key: []const u8 = "",
    secret_key: []const u8 = "",
};
const BackupJobsSavePayload = struct {
    job: backup.JobInput,
    schedule_credentials: ?BackupCredentials = null,
};
const BackupJobsDeletePayload = struct {
    server_id: []const u8,
    job_id: []const u8,
};
const BackupTestPayload = struct {
    job: backup.JobInput,
    credentials: ?BackupCredentials = null,
};
const BackupRunPayload = struct {
    server_id: []const u8,
    job_id: []const u8,
    credentials: ?BackupCredentials = null,
};
const BackupPollPayload = struct {
    run_id: []const u8,
    log_cursor: ?u64 = null,
};
const BackupHistoryPayload = struct {
    server_id: []const u8,
    job_id: []const u8,
    limit: ?usize = null,
};
const BackupInstallPayload = struct {
    server_id: []const u8,
    what: []const u8,
    dry_run: bool = false,
};
const BackupCronStatusPayload = struct { server_id: []const u8 };

fn backupAudit(self: *Context, action: []const u8, server_id: []const u8, detail: []const u8) void {
    sshkeysAudit(self, action, server_id, detail);
}

/// Returns null when the session is ready, otherwise the error response
/// the caller must return verbatim (empty result slices become
/// `"result":null` in the envelope, so callers must never swallow it).
fn backupSessionReady(self: *Context, output: []u8, server_id: []const u8) ?[]const u8 {
    const session = self.manager.get(server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    return null;
}

fn backupExec(self: *Context, server_id: []const u8, cmd: []const u8) ?sessions.ExecOutcome {
    return self.manager.execWait(server_id, cmd, backup_exec_cap, backup_exec_timeout_ns) catch null;
}

/// Runs a command and returns true when it exited 0.
fn backupCheck(self: *Context, server_id: []const u8, cmd: []const u8) bool {
    var out = backupExec(self, server_id, cmd) orelse return false;
    defer out.output.deinit(self.allocator);
    return out.exit == 0;
}

fn backupRcloneInstalled(self: *Context, server_id: []const u8) bool {
    return backupCheck(self, server_id, "command -v rclone >/dev/null 2>&1");
}

/// The scheduled-run staging dir for a job.
fn backupStateDir(allocator: std.mem.Allocator, job_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ backup.state_dir, job_id });
}

fn backupJobToJson(writer: anytype, job: *const backup.Job) !void {
    try writer.writeAll("{\"id\":");
    try json.writeJsonString(writer, job.id);
    try writer.writeAll(",\"server_id\":");
    try json.writeJsonString(writer, job.server_id);
    try writer.writeAll(",\"name\":");
    try json.writeJsonString(writer, job.name);
    try writer.writeAll(",\"source_path\":");
    try json.writeJsonString(writer, job.source_path);
    try writer.writeAll(",\"destination\":{\"type\":");
    try json.writeJsonString(writer, job.destination.type);
    try writer.writeAll(",\"provider\":");
    try json.writeJsonString(writer, job.destination.provider);
    try writer.writeAll(",\"bucket\":");
    try json.writeJsonString(writer, job.destination.bucket);
    try writer.writeAll(",\"prefix\":");
    try json.writeJsonString(writer, job.destination.prefix);
    try writer.writeAll(",\"endpoint\":");
    try json.writeJsonString(writer, job.destination.endpoint);
    try writer.writeAll(",\"region\":");
    try json.writeJsonString(writer, job.destination.region);
    try writer.print(",\"use_iam\":{s},\"storage_class\":", .{if (job.destination.use_iam) "true" else "false"});
    try json.writeJsonString(writer, job.destination.storage_class);
    try writer.writeAll("},\"transfer\":");
    try json.writeJsonString(writer, job.transfer.jsonName());
    try writer.writeAll(",\"schedule\":{\"mode\":");
    try json.writeJsonString(writer, job.schedule.mode);
    try writer.writeAll(",\"interval_unit\":");
    try json.writeJsonString(writer, job.schedule.interval_unit);
    try writer.print(",\"interval_every\":{d},\"expr\":", .{job.schedule.interval_every});
    try json.writeJsonString(writer, job.schedule.expr);
    try writer.print(",\"enabled\":{s}}}", .{if (job.schedule.enabled) "true" else "false"});
    try writer.print(",\"created_at_ns\":{d},\"updated_at_ns\":{d}}}", .{ job.created_at_ns, job.updated_at_ns });
}

/// Reads the current crontab (empty when none exists). Owned.
fn backupCrontabGet(self: *Context, server_id: []const u8) ?[]u8 {
    var out = backupExec(self, server_id, "crontab -l 2>/dev/null") orelse return null;
    defer out.output.deinit(self.allocator);
    return self.allocator.dupe(u8, out.output.items) catch null;
}

/// Installs a crontab from content (the content is generated by Oars and
/// contains no quotes).
fn backupCrontabSet(self: *Context, server_id: []const u8, content: []const u8) bool {
    var cmd_buf: [64 * 1024]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "printf '%s' '{s}' | crontab -", .{content}) catch return false;
    return backupCheck(self, server_id, cmd);
}

/// The five-field expression for a job's schedule.
fn backupScheduleExpr(allocator: std.mem.Allocator, job: *const backup.Job) ![]u8 {
    if (std.mem.eql(u8, job.schedule.mode, "custom")) return allocator.dupe(u8, job.schedule.expr);
    return backup.intervalToCronExpr(allocator, job.schedule.interval_unit, job.schedule.interval_every);
}

/// The shell-quoted rclone invocation for a job (no stats flags — the
/// wrapper and the manual runner add their own).
fn backupRcloneInvocation(self: *Context, job: *const backup.Job, remote: []const u8, config_path: []const u8) ![]u8 {
    const transfer = job.transfer.jsonName();
    const src = try shellquote.quote(self.allocator, job.source_path);
    defer self.allocator.free(src);
    const dest = try backup.destinationArg(self.allocator, job, remote);
    defer self.allocator.free(dest);
    const dest_q = try shellquote.quote(self.allocator, dest);
    defer self.allocator.free(dest_q);
    const cfg_q = try shellquote.quote(self.allocator, config_path);
    defer self.allocator.free(cfg_q);
    return std.fmt.allocPrint(self.allocator, "rclone {s} {s} {s} --config {s}", .{ transfer, src, dest_q, cfg_q });
}

/// Writes the job's remote config section to `path` (0600, secrets in the
/// file only — never argv or audit). Write-failure text is formatted into
/// `write_err_buf` (owned by the outermost caller; see sshkeysWrite).
fn backupWriteConfig(self: *Context, server_id: []const u8, job: *const backup.Job, remote: []const u8, path: []const u8, credentials: ?BackupCredentials, write_err_buf: []u8) ?[]const u8 {
    const section = backup.remoteConfigSection(self.allocator, job, remote, if (credentials) |c| c.access_key else null, if (credentials) |c| c.secret_key else null) catch return "out of memory";
    defer self.allocator.free(section);
    if (std.mem.eql(u8, path, backup.remote_config_path)) {
        // Merge into the dedicated config; never touch other sections.
        const existing = sshkeysRead(self, server_id, path) orelse "";
        defer if (existing.len > 0) self.allocator.free(existing);
        const merged = backup.configMergeSection(self.allocator, existing, remote, section) catch return "out of memory";
        defer self.allocator.free(merged);
        if (sshkeysWrite(self, server_id, path, merged, 0o600, null, write_err_buf)) |msg| return msg;
    } else {
        if (sshkeysWrite(self, server_id, path, section, 0o600, null, write_err_buf)) |msg| return msg;
    }
    return null;
}

/// Enables a job's unattended schedule: dedicated config, run wrapper,
/// crontab line (idempotent). `credentials` are copied into the config
/// on the server — the documented remote-secret disclosure (spec 10 §8).
fn backupInstallSchedule(self: *Context, output: []u8, job: *const backup.Job, credentials: ?BackupCredentials, write_err_buf: []u8) ?[]const u8 {
    _ = output;
    var mkdir_buf: [512]u8 = undefined;
    const mkdir = std.fmt.bufPrint(&mkdir_buf, "mkdir -p ~/.config/oars && chmod 700 ~/.config/oars && mkdir -p {s}/{s} && chmod 700 {s}/{s}", .{ backup.state_dir, job.id, backup.state_dir, job.id }) catch return "out of memory";
    if (!backupCheck(self, job.server_id, mkdir)) return "failed to prepare the server state directories";

    const remote = backup.remoteName(self.allocator, job.id) catch return "out of memory";
    defer self.allocator.free(remote);
    if (backupWriteConfig(self, job.server_id, job, remote, backup.remote_config_path, credentials, write_err_buf)) |msg| return msg;

    const invocation = backupRcloneInvocation(self, job, remote, backup.remote_config_path) catch return "out of memory";
    defer self.allocator.free(invocation);
    const script = backup.wrapperScript(self.allocator, job.id, invocation) catch return "out of memory";
    defer self.allocator.free(script);
    var wrapper_path_buf: [512]u8 = undefined;
    const wrapper_path = std.fmt.bufPrint(&wrapper_path_buf, "{s}/{s}/run.sh", .{ backup.state_dir, job.id }) catch return "out of memory";
    if (sshkeysWrite(self, job.server_id, wrapper_path, script, 0o700, null, write_err_buf)) |msg| return msg;

    const expr = backupScheduleExpr(self.allocator, job) catch return "out of memory";
    defer self.allocator.free(expr);
    var line_buf: [1024]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buf, "{s} /bin/sh {s}", .{ expr, wrapper_path }) catch return "out of memory";
    const escaped = backup.escapePercent(self.allocator, line) catch return "out of memory";
    defer self.allocator.free(escaped);
    const existing = backupCrontabGet(self, job.server_id) orelse return "cannot read the crontab";
    defer self.allocator.free(existing);
    const edited = backup.crontabAdd(self.allocator, existing, job.id, escaped) catch return "out of memory";
    defer self.allocator.free(edited.content);
    if (edited.changed and !backupCrontabSet(self, job.server_id, edited.content)) return "failed to install the crontab entry";
    return null;
}

/// Removes a job's crontab lines (idempotent).
fn backupRemoveSchedule(self: *Context, job_id: []const u8, server_id: []const u8) ?[]const u8 {
    const existing = backupCrontabGet(self, server_id) orelse return null; // no crontab → nothing to remove
    defer self.allocator.free(existing);
    const edited = backup.crontabRemove(self.allocator, existing, job_id) catch return "out of memory";
    defer self.allocator.free(edited.content);
    if (edited.changed and !backupCrontabSet(self, server_id, edited.content)) return "failed to update the crontab";
    return null;
}

const BackupStatusFile = struct {
    job_id: []const u8 = "",
    ts: []const u8 = "",
    exit: []const u8 = "",
    started_at: []const u8 = "",
    finished_at: []const u8 = "",
};

/// Imports completed scheduled runs staged on the server (the wrapper
/// writes `<ts>.status` + `<ts>.log`; cron may have run while Oars was
/// closed). Idempotent: history dedupes by run id and files are removed
/// after a successful import.
fn backupImportStaged(self: *Context, server_id: []const u8, job_id: []const u8) void {
    const state_dir = backupStateDir(self.allocator, job_id) catch return;
    defer self.allocator.free(state_dir);
    var ls_buf: [1024]u8 = undefined;
    const ls_cmd = std.fmt.bufPrint(&ls_buf, "ls {s} 2>/dev/null", .{state_dir}) catch return;
    var ls = backupExec(self, server_id, ls_cmd) orelse return;
    defer ls.output.deinit(self.allocator);
    var lines = std.mem.splitScalar(u8, ls.output.items, '\n');
    while (lines.next()) |raw| {
        const name = std.mem.trim(u8, raw, " \t\r");
        if (!std.mem.endsWith(u8, name, ".status")) continue;
        const ts = name[0 .. name.len - 7];
        var cat_buf: [1024]u8 = undefined;
        const status_path = std.fmt.bufPrint(&cat_buf, "{s}/{s}.status", .{ state_dir, ts }) catch continue;
        var status_out = backupExec(self, server_id, status_path) orelse continue;
        defer status_out.output.deinit(self.allocator);
        const parsed = std.json.parseFromSlice(BackupStatusFile, self.allocator, status_out.output.items, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch continue;
        defer parsed.deinit();
        const st = parsed.value;
        const exit = std.fmt.parseInt(i32, std.mem.trim(u8, st.exit, " \t\r\n"), 10) catch continue;
        const started = std.fmt.parseInt(i64, std.mem.trim(u8, st.started_at, " \t\r\n"), 10) catch continue;
        const finished = std.fmt.parseInt(i64, std.mem.trim(u8, st.finished_at, " \t\r\n"), 10) catch continue;
        if (exit < 0) continue;

        var log_buf: [1024]u8 = undefined;
        const log_path = std.fmt.bufPrint(&log_buf, "{s}/{s}.log", .{ state_dir, ts }) catch continue;
        var log_out = backupExec(self, server_id, log_path) orelse continue;
        defer log_out.output.deinit(self.allocator);
        const summary = backup.lastStatsFromLog(self.allocator, log_out.output.items);
        var id_buf: [128]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buf, "sched-{s}-{s}", .{ job_id, ts }) catch continue;
        var record = backup.RunRecord{
            .id = self.allocator.dupe(u8, id) catch continue,
            .job_id = self.allocator.dupe(u8, job_id) catch continue,
            .server_id = self.allocator.dupe(u8, server_id) catch continue,
            .source = self.allocator.dupe(u8, "scheduled") catch continue,
            .status = if (exit == 0) (if (summary.stats.files_done == 0) .no_changes else .success) else .failed,
            .started_at_ns = started * std.time.ns_per_s,
            .finished_at_ns = finished * std.time.ns_per_s,
            .bytes_done = summary.stats.bytes_done,
            .bytes_total = summary.stats.bytes_total,
            .files_done = summary.stats.files_done,
            .files_total = summary.stats.files_total,
        };
        var failed = false;
        record.trimLog(self.allocator, log_out.output.items) catch {
            failed = true;
        };
        if (summary.@"error".len > 0) {
            record.@"error" = self.allocator.dupe(u8, summary.@"error") catch null;
        } else if (exit != 0) {
            var err_buf: [64]u8 = undefined;
            const msg = std.fmt.bufPrint(&err_buf, "rclone exited {d}", .{exit}) catch "rclone failed";
            record.@"error" = self.allocator.dupe(u8, msg) catch null;
        }
        if (!failed) self.backup.history.append(self.io, &record, @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds)) catch {};
        record.deinit(self.allocator);
        // Consumed: remove the staged pair (a failed import leaves them
        // for the next connection — history dedupes by id).
        var rm_buf: [2048]u8 = undefined;
        const rm_cmd = std.fmt.bufPrint(&rm_buf, "rm -f {s}/{s}.status {s}/{s}.log", .{ state_dir, ts, state_dir, ts }) catch continue;
        _ = backupCheck(self, server_id, rm_cmd);
    }
}

fn handleBackupJobsList(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(BackupJobsListPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const server_id = parsed.value.server_id;
    const connected = self.manager.get(server_id) != null and self.manager.get(server_id).?.status.load(.acquire) == .ready;

    const jobs = self.backup.jobs.listForServer(self.io, server_id) catch {
        return respondError(output, "job registry is unreadable");
    };
    defer {
        for (jobs) |*j| j.deinit(self.allocator);
        self.allocator.free(jobs);
    }
    if (connected) {
        for (jobs) |*j| backupImportStaged(self, server_id, j.id);
    }

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"jobs\":[") catch return output[0..0];
    var first = true;
    for (jobs) |*j| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        backupJobToJson(&writer, j) catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

fn handleBackupJobsSave(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(BackupJobsSavePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    const now = @as(i64, @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds));
    var saved = self.backup.jobs.save(self.io, payload.job, if (payload.schedule_credentials) |_| "x" else null, now) catch |err| {
        return respondError(output, switch (err) {
            error.MissingName, error.InvalidName => "invalid job name",
            error.MissingServer => "missing server",
            error.MissingSource, error.InvalidSource => "invalid source path",
            error.InvalidDestination => "invalid destination",
            error.InvalidProvider => "unsupported provider",
            error.InvalidBucket => "invalid bucket name",
            error.InvalidEndpoint => "invalid endpoint",
            error.InvalidRegion => "invalid region",
            error.InvalidStorageClass => "storage class not supported by this provider",
            error.IamRequiresAws => "IAM role access is only supported on AWS",
            error.InvalidTransfer => "invalid transfer type",
            error.InvalidSchedule => "invalid schedule",
            error.InvalidCronExpr => "invalid cron expression",
            error.EnabledScheduleNeedsCredentials => "credentials are required to enable an unattended schedule (they are copied into the server's rclone config, mode 0600; rclone obscuring is not encryption)",
            error.UnknownId => "unknown job",
            else => "job registry is unreadable",
        });
    };
    defer saved.deinit(self.allocator);

    if (backupSessionReady(self, output, saved.server_id)) |err| return err;
    if (saved.schedule.enabled and !std.mem.eql(u8, saved.schedule.mode, "manual")) {
        var write_err_buf: [256]u8 = undefined;
        if (backupInstallSchedule(self, output, &saved, payload.schedule_credentials, &write_err_buf)) |msg| return respondError(output, msg);
    } else {
        if (backupRemoveSchedule(self, saved.id, saved.server_id)) |msg| return respondError(output, msg);
    }
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "job={s} schedule={s}", .{ saved.id, if (saved.schedule.enabled) "enabled" else "disabled" }) catch "backup.jobs.save";
    backupAudit(self, "backup.jobs.save", saved.server_id, detail);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job\":") catch return output[0..0];
    backupJobToJson(&writer, &saved) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleBackupJobsDelete(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(BackupJobsDeletePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (!(self.backup.jobs.delete(self.io, payload.job_id) catch return respondError(output, "job registry is unreadable"))) {
        return respondError(output, "unknown job");
    }
    if (backupSessionReady(self, output, payload.server_id) == null) {
        if (backupRemoveSchedule(self, payload.job_id, payload.server_id)) |msg| return respondError(output, msg);
    }
    var detail_buf: [128]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "job={s}", .{payload.job_id}) catch "backup.jobs.delete";
    backupAudit(self, "backup.jobs.delete", payload.server_id, detail);
    return ok_json;
}

/// The capability test (spec 10 §5): real list/write/read/delete on one
/// unique sentinel in the job's exact bucket/prefix; sync jobs must also
/// prove destination delete authority. A failed cleanup is reported with
/// the leftover object path and never marked passed.
fn handleBackupTest(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(BackupTestPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    backup.validate(payload.job, if (payload.credentials) |_| "x" else null) catch |err| {
        return respondError(output, switch (err) {
            error.InvalidProvider => "unsupported provider",
            error.InvalidBucket => "invalid bucket name",
            error.InvalidEndpoint => "invalid endpoint",
            error.InvalidRegion => "invalid region",
            error.InvalidStorageClass => "storage class not supported by this provider",
            error.IamRequiresAws => "IAM role access is only supported on AWS",
            error.MissingSource, error.InvalidSource => "invalid source path",
            else => "invalid job",
        });
    };
    const server_id = payload.job.server_id;
    if (backupSessionReady(self, output, server_id)) |err| return err;
    if (!backupRcloneInstalled(self, server_id)) return respondError(output, "rclone is not installed on this server; install it first");
    if (std.mem.eql(u8, payload.job.destination.type, "local")) {
        return respondError(output, "local destinations are an Oars+ feature and are not implemented yet");
    }

    var job = backup.Job{
        .id = backup.dupOrLiteral(self.allocator, "test") catch return respondError(output, "out of memory"),
        .server_id = backup.dupOrLiteral(self.allocator, server_id) catch return respondError(output, "out of memory"),
        .name = backup.dupOrLiteral(self.allocator, "test") catch return respondError(output, "out of memory"),
        .source_path = backup.dupOrLiteral(self.allocator, payload.job.source_path) catch return respondError(output, "out of memory"),
        .destination = .{
            .type = backup.dupOrLiteral(self.allocator, payload.job.destination.type) catch return respondError(output, "out of memory"),
            .provider = backup.dupOrLiteral(self.allocator, payload.job.destination.provider) catch return respondError(output, "out of memory"),
            .bucket = backup.dupOrLiteral(self.allocator, payload.job.destination.bucket) catch return respondError(output, "out of memory"),
            .prefix = backup.dupOrLiteral(self.allocator, payload.job.destination.prefix) catch return respondError(output, "out of memory"),
            .endpoint = backup.dupOrLiteral(self.allocator, payload.job.destination.endpoint) catch return respondError(output, "out of memory"),
            .region = backup.dupOrLiteral(self.allocator, payload.job.destination.region) catch return respondError(output, "out of memory"),
            .use_iam = payload.job.destination.use_iam,
            .storage_class = backup.dupOrLiteral(self.allocator, payload.job.destination.storage_class) catch return respondError(output, "out of memory"),
        },
        .transfer = backup.Transfer.fromJsonName(payload.job.transfer) orelse .copy,
        // Own the schedule defaults: `Schedule.mode` defaults to the
        // comptime literal "manual", which deinit must never free.
        .schedule = .{
            .mode = backup.dupOrLiteral(self.allocator, "manual") catch return respondError(output, "out of memory"),
            .interval_unit = backup.dupOrLiteral(self.allocator, "hours") catch return respondError(output, "out of memory"),
            .expr = "",
        },
    };
    defer job.deinit(self.allocator);

    const remote = backup.remoteName(self.allocator, "test") catch return respondError(output, "out of memory");
    defer self.allocator.free(remote);
    var ts_buf: [64]u8 = undefined;
    const ts = std.fmt.bufPrint(&ts_buf, "{d}", .{std.Io.Timestamp.now(self.io, .real).nanoseconds}) catch return respondError(output, "out of memory");
    var cfg_buf: [256]u8 = undefined;
    const cfg = std.fmt.bufPrint(&cfg_buf, "/tmp/oars-rclone-test-{s}.conf", .{ts}) catch return respondError(output, "out of memory");
    var sentinel_buf: [256]u8 = undefined;
    const sentinel = std.fmt.bufPrint(&sentinel_buf, "/tmp/oars-sentinel-{s}", .{ts}) catch return respondError(output, "out of memory");
    const sentinel_name = std.fmt.bufPrint(&sentinel_buf, "oars-sentinel-{s}", .{ts}) catch return respondError(output, "out of memory");

    var write_err_buf: [256]u8 = undefined;
    if (backupWriteConfig(self, server_id, &job, remote, cfg, payload.credentials, &write_err_buf)) |msg| return respondError(output, msg);
    defer _ = backupCheck(self, server_id, std.fmt.bufPrint(&ts_buf, "rm -f {s}", .{cfg}) catch "rm -f /tmp/oars-rclone-test.conf");

    const dest = backup.destinationArg(self.allocator, &job, remote) catch return respondError(output, "out of memory");
    defer self.allocator.free(dest);
    // The sentinel lives at remote:bucket/prefix/oars-sentinel-<ts> — a
    // bare local path would make the whole test pass vacuously.
    const object_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dest, sentinel_name }) catch return respondError(output, "out of memory");
    defer self.allocator.free(object_path);
    const dest_q = shellquote.quote(self.allocator, dest) catch return respondError(output, "out of memory");
    defer self.allocator.free(dest_q);
    const obj_q = shellquote.quote(self.allocator, object_path) catch return respondError(output, "out of memory");
    defer self.allocator.free(obj_q);
    const cfg_q = shellquote.quote(self.allocator, cfg) catch return respondError(output, "out of memory");
    defer self.allocator.free(cfg_q);
    const sentinel_q = shellquote.quote(self.allocator, sentinel) catch return respondError(output, "out of memory");
    defer self.allocator.free(sentinel_q);

    var cmd_buf: [2048]u8 = undefined;
    // 1. list the exact bucket/prefix.
    const list_cmd = std.fmt.bufPrint(&cmd_buf, "rclone lsf {s} --max-depth 1 --config {s}", .{ dest_q, cfg_q }) catch return respondError(output, "out of memory");
    if (!backupCheck(self, server_id, list_cmd)) return respondError(output, "list: the bucket or prefix is not readable");
    // 2. write the sentinel.
    const write_cmd = std.fmt.bufPrint(&cmd_buf, "printf '%s' 'oars-test-{s}' > {s} && rclone copyto {s} {s} --config {s}", .{ ts, sentinel_q, sentinel_q, obj_q, cfg_q }) catch return respondError(output, "out of memory");
    if (!backupCheck(self, server_id, write_cmd)) return respondError(output, "write: the bucket/prefix rejects objects");
    // 3. read/stat the sentinel from the bucket/prefix.
    const read_cmd = std.fmt.bufPrint(&cmd_buf, "rclone lsf {s} --include 'oars-sentinel-{s}*' --config {s}", .{ dest_q, ts, cfg_q }) catch return respondError(output, "out of memory");
    if (!backupCheck(self, server_id, read_cmd)) return respondError(output, "read: the sentinel object cannot be read");
    // 4. delete: sync must prove destination delete authority (the
    //    prefix-level delete op); copy only needs its own cleanup.
    const delete_ok = if (job.transfer == .sync)
        backupCheck(self, server_id, std.fmt.bufPrint(&cmd_buf, "rclone delete {s} --include 'oars-sentinel-{s}*' --config {s}", .{ dest_q, ts, cfg_q }) catch "false")
    else
        backupCheck(self, server_id, std.fmt.bufPrint(&cmd_buf, "rclone deletefile {s} --config {s}", .{ obj_q, cfg_q }) catch "false");
    if (!delete_ok) {
        return respondError(output, "delete: the bucket/prefix rejects deletes; the sentinel object may be left behind");
    }
    // 5. verify cleanup.
    const verify = backupCheck(self, server_id, std.fmt.bufPrint(&cmd_buf, "rclone lsf {s} --config {s}", .{ dest_q, cfg_q }) catch "true");
    var verify_out = backupExec(self, server_id, std.fmt.bufPrint(&cmd_buf, "rclone lsf {s} --config {s}", .{ dest_q, cfg_q }) catch "true");
    var leftover = false;
    if (verify_out) |*vo| {
        defer vo.output.deinit(self.allocator);
        leftover = std.mem.indexOf(u8, vo.output.items, sentinel_name) != null;
    }
    if (!verify or leftover) {
        return respondError(output, "cleanup verification failed; the sentinel object may be left behind in the bucket/prefix");
    }
    _ = backupCheck(self, server_id, std.fmt.bufPrint(&cmd_buf, "rm -f {s}", .{sentinel}) catch "true");
    backupAudit(self, "backup.test", server_id, "bucket/prefix capability test");
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"checks\":{\"list\":true,\"write\":true,\"read\":true,\"delete\":") catch return output[0..0];
    writer.writeAll(if (delete_ok) "true" else "false") catch return output[0..0];
    writer.writeAll("}}") catch return output[0..0];
    return writer.buffered();
}

fn handleBackupRun(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(BackupRunPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (backupSessionReady(self, output, payload.server_id)) |err| return err;
    var job = (self.backup.jobs.find(self.io, payload.job_id) catch {
        return respondError(output, "job registry is unreadable");
    }) orelse return respondError(output, "unknown job");
    defer job.deinit(self.allocator);
    if (!std.mem.eql(u8, job.server_id, payload.server_id)) return respondError(output, "job not found on this server");
    if (std.mem.eql(u8, job.destination.type, "local")) {
        return respondError(output, "local destinations are an Oars+ feature and are not implemented yet");
    }
    if (!backupRcloneInstalled(self, payload.server_id)) return respondError(output, "rclone is not installed on this server; install it first");
    if (!job.destination.use_iam and payload.credentials == null) {
        return respondError(output, "credentials are required for a manual run (stored in Keychain as backup:<job_id>)");
    }
    self.backup.runs.lock();
    const busy = self.backup.runs.runningForServer(payload.server_id) != null;
    self.backup.runs.unlock();
    if (busy) return respondError(output, "a backup run is already in progress on this server");
    var src_buf: [2048]u8 = undefined;
    const src_q = shellquote.quote(self.allocator, job.source_path) catch return respondError(output, "out of memory");
    defer self.allocator.free(src_q);
    const src_cmd = std.fmt.bufPrint(&src_buf, "test -d {s} || test -f {s}", .{ src_q, src_q }) catch return respondError(output, "out of memory");
    if (!backupCheck(self, payload.server_id, src_cmd)) return respondError(output, "the source path does not exist on the server");

    const remote = backup.remoteName(self.allocator, job.id) catch return respondError(output, "out of memory");
    defer self.allocator.free(remote);
    var ts_buf: [64]u8 = undefined;
    const ts = std.fmt.bufPrint(&ts_buf, "{d}", .{std.Io.Timestamp.now(self.io, .real).nanoseconds}) catch return respondError(output, "out of memory");
    var cfg_buf: [256]u8 = undefined;
    const cfg = std.fmt.bufPrint(&cfg_buf, "/tmp/oars-rclone-run-{s}.conf", .{ts}) catch return respondError(output, "out of memory");
    var write_err_buf: [256]u8 = undefined;
    if (backupWriteConfig(self, payload.server_id, &job, remote, cfg, payload.credentials, &write_err_buf)) |msg| return respondError(output, msg);

    const invocation_cmd = backupRcloneInvocation(self, &job, remote, cfg) catch return respondError(output, "out of memory");
    defer self.allocator.free(invocation_cmd);
    var full_buf: [4096]u8 = undefined;
    // rclone's --use-json-log lines go to stderr; the exec channel
    // captures stdout only, so merge the streams or the run log stays
    // empty and no stats are ever parsed.
    const full = std.fmt.bufPrint(&full_buf, "{s} --use-json-log --stats 1s --stats-log-level NOTICE 2>&1", .{invocation_cmd}) catch return respondError(output, "out of memory");
    const channel = self.manager.execTracked(payload.server_id, full, "backup", null, &.{}) catch {
        _ = backupCheck(self, payload.server_id, std.fmt.bufPrint(&ts_buf, "rm -f {s}", .{cfg}) catch "true");
        return respondError(output, "not connected");
    };

    self.backup.runs.lock();
    defer self.backup.runs.unlock();
    var run = self.backup.runs.start(job.id, payload.server_id, "manual", @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds)) catch {
        _ = backupCheck(self, payload.server_id, std.fmt.bufPrint(&ts_buf, "rm -f {s}", .{cfg}) catch "true");
        return respondError(output, "out of memory");
    };
    run.channel = channel;
    run.temp_config = self.allocator.dupe(u8, cfg) catch "";
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "job={s}", .{job.id}) catch "backup.run";
    backupAudit(self, "backup.run", payload.server_id, detail);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"run_id\":") catch return output[0..0];
    json.writeJsonString(&writer, run.record.id) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn backupRunToJson(writer: anytype, run: *const backup.RunRecord) !void {
    try writer.writeAll("{\"id\":");
    try json.writeJsonString(writer, run.id);
    try writer.writeAll(",\"job_id\":");
    try json.writeJsonString(writer, run.job_id);
    try writer.writeAll(",\"server_id\":");
    try json.writeJsonString(writer, run.server_id);
    try writer.writeAll(",\"source\":");
    try json.writeJsonString(writer, run.source);
    try writer.writeAll(",\"status\":");
    try json.writeJsonString(writer, run.status.jsonName());
    try writer.print(",\"started_at_ns\":{d},\"finished_at_ns\":{d}", .{ run.started_at_ns, run.finished_at_ns });
    try writer.print(",\"bytes_done\":{d},\"bytes_total\":{d},\"files_done\":{d},\"files_total\":{d}", .{ run.bytes_done, run.bytes_total, run.files_done, run.files_total });
    try writer.writeAll(",\"error\":");
    try json.writeJsonString(writer, run.@"error" orelse "");
    try writer.writeAll(",\"log\":");
    const log = run.log orelse "";
    const capped_log = if (log.len > backup_response_log_cap) log[log.len - backup_response_log_cap ..] else log;
    try json.writeJsonString(writer, capped_log);
    try writer.writeAll("}");
}

fn handleBackupPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(BackupPollPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    self.backup.runs.lock();
    defer self.backup.runs.unlock();
    const run = self.backup.runs.byId(payload.run_id) orelse {
        return respondError(output, "unknown run");
    };
    const cursor = payload.log_cursor orelse 0;
    var delta: []u8 = &.{};
    var new_cursor: u64 = cursor;
    var dropped: u64 = 0;
    var eof = false;
    var exit: ?i32 = null;
    var final_log: []u8 = &.{};
    defer if (delta.len > 0) self.allocator.free(delta);
    defer if (final_log.len > 0) self.allocator.free(final_log);

    if (!run.finalized) {
        if (run.channel) |ch| {
            const polls = self.manager.pollChannels(run.record.server_id, &.{.{ .id = ch, .pos = cursor }}, false, backup_exec_cap, 1024 * 1024) catch null;
            if (polls) |list| {
                defer {
                    for (list) |*poll| poll.deinit(self.allocator);
                    self.allocator.free(list);
                }
                for (list) |*poll| {
                    if (poll.id != ch) continue;
                    // poll.data dies with the poll list below; the
                    // response (and the finalize rewind) needs it alive.
                    delta = self.allocator.dupe(u8, poll.data) catch &.{};
                    new_cursor = poll.cursor;
                    dropped = poll.gap;
                    eof = poll.eof;
                    exit = poll.exit_status;
                }
                var lines = std.mem.splitScalar(u8, delta, '\n');
                while (lines.next()) |line| {
                    const trimmed = std.mem.trim(u8, line, " \t\r");
                    if (trimmed.len == 0) continue;
                    switch (backup.parseJsonLogLine(self.allocator, trimmed)) {
                        .stats => |s| {
                            run.record.bytes_done = s.bytes_done;
                            run.record.bytes_total = s.bytes_total;
                            run.record.files_done = s.files_done;
                            run.record.files_total = s.files_total;
                            run.speed_bps = s.speed_bps;
                            run.eta_sec = s.eta_sec;
                        },
                        .@"error" => |msg| {
                            if (run.record.@"error") |e| self.allocator.free(e);
                            run.record.@"error" = self.allocator.dupe(u8, msg) catch null;
                        },
                        .other => {},
                    }
                }
            }
        }
        if (eof) {
            // Finalize: capture the bounded log, map the exit status.
            const ch = run.channel orelse 0;
            run.finalized = true;
            run.channel = null;
            run.record.finished_at_ns = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds);
            if (exit) |code| {
                if (code == 0) {
                    run.record.status = if (run.record.files_done == 0) .no_changes else .success;
                } else {
                    run.record.status = .failed;
                    if (run.record.@"error" == null) {
                        var err_buf: [64]u8 = undefined;
                        const msg = std.fmt.bufPrint(&err_buf, "rclone exited {d}", .{code}) catch "rclone failed";
                        run.record.@"error" = self.allocator.dupe(u8, msg) catch null;
                    }
                }
            } else {
                run.record.status = .failed;
            }
            const polls = self.manager.pollChannels(run.record.server_id, &.{}, true, backup_exec_cap, backup_exec_cap) catch null;
            if (polls) |list| {
                defer {
                    for (list) |*poll| poll.deinit(self.allocator);
                    self.allocator.free(list);
                }
                for (list) |*poll| {
                    if (poll.id == ch and poll.data.len > 0) {
                        // The channel is gone (nulled above); the rewind
                        // replays the retained buffer — copy it now.
                        final_log = self.allocator.dupe(u8, poll.data) catch &.{};
                        break;
                    }
                }
            }
            if (final_log.len == 0) final_log = self.allocator.dupe(u8, delta) catch &.{};
            run.record.trimLog(self.allocator, if (final_log.len > 0) final_log else delta) catch {};
            self.backup.history.append(self.io, &run.record, @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds)) catch {};
            if (run.temp_config.len > 0) {
                var rm_buf: [512]u8 = undefined;
                const rm_cmd = std.fmt.bufPrint(&rm_buf, "rm -f {s}", .{run.temp_config}) catch "true";
                _ = backupCheck(self, run.record.server_id, rm_cmd);
                self.allocator.free(run.temp_config);
                run.temp_config = "";
            }
            self.backup.runs.evictCompleted();
        }
    }

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"status\":") catch return output[0..0];
    json.writeJsonString(&writer, run.record.status.jsonName()) catch return output[0..0];
    writer.print(",\"bytes_done\":{d},\"bytes_total\":{d},\"files_done\":{d},\"files_total\":{d},\"speed_bps\":{d},\"eta_sec\":{d},\"log_cursor\":{d},\"dropped\":{d},\"log_delta\":", .{ run.record.bytes_done, run.record.bytes_total, run.record.files_done, run.record.files_total, run.speed_bps, run.eta_sec, new_cursor, dropped }) catch return output[0..0];
    json.writeJsonString(&writer, delta) catch return output[0..0];
    writer.writeAll(",\"error\":") catch return output[0..0];
    json.writeJsonString(&writer, run.record.@"error" orelse "") catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleBackupHistory(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(BackupHistoryPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    const connected = self.manager.get(payload.server_id) != null and self.manager.get(payload.server_id).?.status.load(.acquire) == .ready;
    if (connected) backupImportStaged(self, payload.server_id, payload.job_id);
    const limit = payload.limit orelse 20;
    const runs = self.backup.history.listForJob(self.io, payload.job_id, limit) catch {
        return respondError(output, "run history is unreadable");
    };
    defer {
        for (runs) |*r| r.deinit(self.allocator);
        self.allocator.free(runs);
    }
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"runs\":[") catch return output[0..0];
    var first = true;
    for (runs) |*r| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        backupRunToJson(&writer, r) catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

fn backupInstallPlan(self: *Context, server_id: []const u8, what: []const u8) ?[]const u8 {
    var os_out = backupExec(self, server_id, "cat /etc/os-release 2>/dev/null") orelse return null;
    defer os_out.output.deinit(self.allocator);
    const os = os_out.output.items;
    const alpine = std.mem.indexOf(u8, os, "ID=alpine") != null;
    const debian = std.mem.indexOf(u8, os, "ID=debian") != null or std.mem.indexOf(u8, os, "ID=ubuntu") != null;
    if (std.mem.eql(u8, what, "rclone")) {
        if (alpine) return "apk add rclone";
        if (debian) return "apt-get update && apt-get install -y rclone";
        return "manual: download the rclone binary for this OS from rclone.org and place it on PATH";
    }
    if (std.mem.eql(u8, what, "cron")) {
        if (alpine) return "apk add cronie && crond -b";
        if (debian) return "apt-get install -y cron && service cron start";
        return "manual: install and start the system cron daemon";
    }
    return "unknown component";
}

fn handleBackupInstall(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(BackupInstallPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (backupSessionReady(self, output, payload.server_id)) |err| return err;
    if (!std.mem.eql(u8, payload.what, "rclone") and !std.mem.eql(u8, payload.what, "cron")) {
        return respondError(output, "unknown component");
    }
    const already = if (std.mem.eql(u8, payload.what, "rclone"))
        backupRcloneInstalled(self, payload.server_id)
    else
        backupCheck(self, payload.server_id, "command -v crontab >/dev/null 2>&1 && command -v crond >/dev/null 2>&1");
    if (already) {
        var writer = std.Io.Writer.fixed(output);
        writer.writeAll("{\"ok\":true,\"action\":\"already_installed\",\"plan\":\"\"}") catch return output[0..0];
        return writer.buffered();
    }
    const plan = backupInstallPlan(self, payload.server_id, payload.what) orelse return respondError(output, "cannot detect the server OS");
    if (payload.dry_run) {
        var writer = std.Io.Writer.fixed(output);
        writer.writeAll("{\"ok\":true,\"action\":\"install\",\"plan\":") catch return output[0..0];
        json.writeJsonString(&writer, plan) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
        return writer.buffered();
    }
    if (std.mem.startsWith(u8, plan, "manual")) {
        return respondError(output, "no tested adapter for this server; follow the manual instructions in the plan");
    }
    var idc = backupExec(self, payload.server_id, "id -u") orelse return respondError(output, "not connected");
    defer idc.output.deinit(self.allocator);
    if (idc.exit != 0 or std.mem.indexOf(u8, std.mem.trim(u8, idc.output.items, " \t\r\n"), "0") == null) {
        return respondError(output, "installing components requires root access on the server");
    }
    if (!backupCheck(self, payload.server_id, plan)) return respondError(output, "installation failed");
    backupAudit(self, "backup.install", payload.server_id, payload.what);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"action\":\"installed\",\"plan\":") catch return output[0..0];
    json.writeJsonString(&writer, plan) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleBackupCronStatus(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(BackupCronStatusPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const server_id = parsed.value.server_id;
    if (backupSessionReady(self, output, server_id)) |err| return err;
    const rclone = backupRcloneInstalled(self, server_id);
    const cron_installed = backupCheck(self, server_id, "command -v crontab >/dev/null 2>&1 && command -v crond >/dev/null 2>&1");
    const cron_running = backupCheck(self, server_id, "pgrep -x crond >/dev/null 2>&1 || pgrep -f 'crond -b' >/dev/null 2>&1");
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"rclone\":{s},\"cron_installed\":{s},\"cron_running\":{s}}}", .{ if (rclone) "true" else "false", if (cron_installed) "true" else "false", if (cron_running) "true" else "false" }) catch return output[0..0];
    return writer.buffered();
}

// --- AI terminal (spec 11) ------------------------------------------------
//
// The AI call itself is frontend-side (spec 11 §6). Zig adds: the
// context bundle (monitor cache + one light probe, cached ≤ 5 s), the
// provider config store (ai.json — the key stays in the frontend
// Keychain under `ai:<base_url>`), and audit-filtered run history.

const ai_exec_cap: usize = 256 * 1024;
const ai_exec_timeout_ns = 20 * std.time.ns_per_s;

const AiContextPayloadIn = struct { server_id: []const u8 };
const AiProviderGetPayload = struct {};
const AiProviderSetPayload = struct { provider: ai.ProviderInput };
const AiHistoryPayload = struct {
    server_id: []const u8,
    limit: ?usize = null,
};

const AiHistoryEntry = struct {
    ts: i64,
    action: []const u8,
    detail: []const u8 = "",
};

/// Honest "no sample yet" state for the monitor part of the bundle.
const ai_empty_snapshot = monitor.Snapshot{ .probe_error = "no sample yet" };

const AiContextBundle = struct {
    ok: bool = true,
    os: []const u8,
    hostname: []const u8,
    uptime_sec: u64,
    load: struct {
        utilization_pct: ?f32,
        load_1: f32,
        load_5: f32,
        load_15: f32,
        cores: u32,
    },
    mem: monitor.MemInfo,
    disk: monitor.DiskInfo,
    top_processes: []monitor.Process,
    active_logs: []ai.LogInfo,
    probe_error: ?[]const u8 = null,
};

/// Runs the light context probe (OS, hostname, log mtimes), caches the
/// result ≤ 5 s, and returns the cache entry (owned by the cache).
fn aiProbeOrCache(self: *Context, server_id: []const u8, now_ns: i128) ?*ai.ContextCache.CacheEntry {
    if (self.ai.cache.fresh(server_id, now_ns)) |entry| return entry;

    const paths = self.logs.pathsFor(self.io, server_id) catch return null;
    defer {
        for (paths) |p| self.allocator.free(p);
        self.allocator.free(paths);
    }
    const cmd = ai.buildProbeCommand(self.allocator, paths) catch return null;
    defer self.allocator.free(cmd);
    var outcome = self.manager.execWait(server_id, cmd, ai_exec_cap, ai_exec_timeout_ns) catch return null;
    defer outcome.output.deinit(self.allocator);
    const parsed = ai.parseProbeOutput(self.allocator, outcome.output.items) catch return null;
    defer self.allocator.free(parsed.logs);
    const active_logs = ai.buildActiveLogs(self.allocator, parsed.logs, paths, ai.max_active_logs) catch return null;
    errdefer {
        for (active_logs) |*l| l.deinit(self.allocator);
        self.allocator.free(active_logs);
    }
    const sid_owned = self.allocator.dupe(u8, server_id) catch return null;
    errdefer self.allocator.free(sid_owned);
    const os_owned = if (parsed.os.len == 0) "" else (self.allocator.dupe(u8, parsed.os) catch return null);
    errdefer if (os_owned.len > 0) self.allocator.free(os_owned);
    const host_owned = if (parsed.hostname.len == 0) "" else (self.allocator.dupe(u8, parsed.hostname) catch return null);
    errdefer if (host_owned.len > 0) self.allocator.free(host_owned);
    var entry = ai.ContextCache.CacheEntry{
        .server_id = sid_owned,
        .os = os_owned,
        .hostname = host_owned,
        .active_logs = active_logs,
        .ts_ns = now_ns,
    };
    self.ai.cache.put(entry) catch {
        entry.deinit(self.allocator);
        return null;
    };
    return self.ai.cache.fresh(server_id, now_ns) orelse unreachable;
}

/// The context bundle (spec 11 §5): monitor cache snapshot + one light
/// probe (OS/hostname/log mtimes), the probe part cached ≤ 5 s.
fn handleAiContext(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AiContextPayloadIn, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const server_id = parsed.value.server_id;

    const session = self.manager.get(server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");

    const now = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    const probe = aiProbeOrCache(self, server_id, now) orelse return respondError(output, "context probe failed");

    session.monitor_cache.lock();
    defer session.monitor_cache.unlock();
    const snap = session.monitor_cache.current() orelse &ai_empty_snapshot;
    // Refresh-if-stale: enqueue one monitor probe when the cache is
    // stale and none is running (same contract as oars.monitor.poll).
    if (now - session.monitor_last_probe_ns.load(.acquire) >= session.monitor_interval_ns and
        !session.monitor_probe_active.load(.acquire))
    {
        session.monitor_force.store(true, .release);
    }

    var writer = std.Io.Writer.fixed(output);
    const bundle = AiContextBundle{
        .os = probe.os,
        .hostname = probe.hostname,
        .uptime_sec = snap.cpu.uptime_sec,
        .load = .{
            .utilization_pct = snap.cpu.utilization_pct,
            .load_1 = snap.cpu.load_1,
            .load_5 = snap.cpu.load_5,
            .load_15 = snap.cpu.load_15,
            .cores = snap.cpu.cores,
        },
        .mem = snap.mem,
        .disk = snap.disk,
        .top_processes = snap.processes,
        .active_logs = probe.active_logs,
        .probe_error = snap.probe_error,
    };
    std.json.Stringify.value(bundle, .{}, &writer) catch return output[0..0];
    return writer.buffered();
}

fn handleAiProviderGet(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AiProviderGetPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const provider = self.ai.provider.get(self.io) catch return respondError(output, "provider config is unreadable");
    defer if (provider) |p| {
        var owned = p;
        owned.deinit(self.allocator);
    };
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"provider\":") catch return output[0..0];
    if (provider) |p| {
        std.json.Stringify.value(p, .{}, &writer) catch return output[0..0];
    } else {
        writer.writeAll("null") catch return output[0..0];
    }
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleAiProviderSet(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AiProviderSetPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const now = @as(i64, @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds));
    var saved = self.ai.provider.set(self.io, parsed.value.provider, now) catch |err| {
        return respondError(output, switch (err) {
            error.InvalidAdapter => "unsupported adapter",
            error.InvalidBaseUrl => "the base URL must be https:// (http:// is allowed only for localhost providers)",
            error.InvalidModel => "invalid model name",
            error.InvalidCapabilities => "invalid capabilities",
            else => "provider config is unreadable",
        });
    };
    defer saved.deinit(self.allocator);
    var detail_buf: [128]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "adapter={s} model={s}", .{ saved.adapter.jsonName(), saved.model }) catch "ai.provider.set";
    sshkeysAudit(self, "ai.provider.set", "-", detail);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"provider\":") catch return output[0..0];
    std.json.Stringify.value(saved, .{}, &writer) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

/// Approved-run history: the audit-filtered `ssh.exec` entries for the
/// server, newest first (spec 11 §5; full history is spec 15).
fn handleAiHistory(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AiHistoryPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    const limit = @min(payload.limit orelse ai.history_default_limit, ai.history_max_limit);
    const entries = self.audit.read(self.io, payload.server_id, "ssh.exec", limit) catch {
        return respondError(output, "audit log is unreadable");
    };
    defer {
        for (entries) |*e| e.deinit(self.allocator);
        self.allocator.free(entries);
    }
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"runs\":[") catch return output[0..0];
    var first = true;
    for (entries) |*e| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.print("{{\"ts\":{d},\"action\":", .{e.ts}) catch return output[0..0];
        json.writeJsonString(&writer, e.type) catch return output[0..0];
        writer.writeAll(",\"detail\":") catch return output[0..0];
        json.writeJsonString(&writer, e.detail) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

// --- spec 15: history + audit ----------------------------------------------

const history_default_limit: usize = 50;
const history_max_limit: usize = 500;

const HistoryRecordPayload = struct {
    operation_id: []const u8,
    server_id: []const u8,
    kind: []const u8,
    command: []const u8,
    exit: ?i32 = null,
    duration_ms: ?i64 = null,
    output_snippet: ?[]const u8 = null,
};

/// Internal write API (spec 15 §5): features that do not go through the
/// exec channel record their operations here; completion updates the same
/// record by operation_id. The command is pattern-redacted at write time.
fn handleHistoryRecord(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(HistoryRecordPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.operation_id.len == 0) return respondError(output, "operation_id is required");
    if (payload.server_id.len == 0) return respondError(output, "server_id is required");
    if (payload.kind.len == 0) return respondError(output, "kind is required");
    const redacted = history.redact(self.allocator, payload.command, &.{}) catch {
        return respondError(output, "out of memory");
    };
    defer self.allocator.free(redacted.text);
    self.history.record(self.io, .{
        .id = "",
        .operation_id = payload.operation_id,
        .ts = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds),
        .server_id = payload.server_id,
        .kind = payload.kind,
        .command = redacted.text,
        .exit = payload.exit,
        .duration_ms = payload.duration_ms,
        .output_snippet = payload.output_snippet orelse "",
        .redacted = redacted.redacted,
    }) catch {
        return respondError(output, "history log is unreadable");
    };
    return ok_json;
}

const HistoryListPayload = struct {
    server_id: ?[]const u8 = null,
    q: ?[]const u8 = null,
    limit: ?usize = null,
};

fn handleHistoryList(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(HistoryListPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    const limit = @min(payload.limit orelse history_default_limit, history_max_limit);
    const entries = self.history.list(self.io, payload.server_id, payload.q, limit) catch {
        return respondError(output, "history log is unreadable");
    };
    defer {
        for (entries) |*e| e.deinit(self.allocator);
        self.allocator.free(entries);
    }
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"entries\":[") catch return output[0..0];
    var first = true;
    for (entries) |*e| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.writeAll("{\"id\":") catch return output[0..0];
        json.writeJsonString(&writer, e.id) catch return output[0..0];
        writer.writeAll(",\"operation_id\":") catch return output[0..0];
        json.writeJsonString(&writer, e.operation_id) catch return output[0..0];
        writer.print(",\"ts\":{d},\"server_id\":", .{e.ts}) catch return output[0..0];
        json.writeJsonString(&writer, e.server_id) catch return output[0..0];
        writer.writeAll(",\"kind\":") catch return output[0..0];
        json.writeJsonString(&writer, e.kind) catch return output[0..0];
        writer.writeAll(",\"command\":") catch return output[0..0];
        json.writeJsonString(&writer, e.command) catch return output[0..0];
        writer.writeAll(",\"exit\":") catch return output[0..0];
        if (e.exit) |exit| {
            writer.print("{d}", .{exit}) catch return output[0..0];
        } else {
            writer.writeAll("null") catch return output[0..0];
        }
        writer.writeAll(",\"duration_ms\":") catch return output[0..0];
        if (e.duration_ms) |ms| {
            writer.print("{d}", .{ms}) catch return output[0..0];
        } else {
            writer.writeAll("null") catch return output[0..0];
        }
        writer.writeAll(",\"output_snippet\":") catch return output[0..0];
        json.writeJsonString(&writer, e.output_snippet) catch return output[0..0];
        writer.writeAll(",\"redacted\":") catch return output[0..0];
        writer.writeAll(if (e.redacted) "true" else "false") catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

const HistoryReplayPayload = struct {
    entry_id: []const u8,
};

/// Re-runs a stored command through the exec path (spec 15 §13: the
/// environment may have changed since capture, so the frontend confirms).
/// A redacted command is refused — the redaction marker must never be
/// executed as shell text; structured secret re-entry is frontend work.
/// The re-run itself is recorded as a fresh, chainable history entry by
/// the exec capture hook.
fn handleHistoryReplay(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(HistoryReplayPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    var entry = (self.history.get(self.io, payload.entry_id) catch {
        return respondError(output, "history log is unreadable");
    }) orelse return respondError(output, "unknown history entry");
    defer entry.deinit(self.allocator);
    if (entry.redacted) {
        return respondError(output, "this command contains redacted secrets; re-enter its secret fields to replay it");
    }
    const channel_id = self.manager.execTracked(entry.server_id, entry.command, "exec", null, &.{}) catch |err| {
        return respondError(output, switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "replay failed",
        });
    };
    var detail_buf: [256]u8 = undefined;
    const cmd = if (entry.command.len > ai.audit_cmd_cap) entry.command[0..ai.audit_cmd_cap] else entry.command;
    const detail = std.fmt.bufPrint(&detail_buf, "cmd={s} (replayed from {s})", .{ cmd, entry.id }) catch "ssh.exec";
    sshkeysAudit(self, "ssh.exec", entry.server_id, detail);
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel_id}) catch return output[0..0];
    return writer.buffered();
}

const AuditListPayload = struct {
    q: ?[]const u8 = null,
    type: ?[]const u8 = null,
    limit: ?usize = null,
};

fn handleAuditList(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AuditListPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    const limit = @min(payload.limit orelse history_default_limit, history_max_limit);
    const entries = self.audit.list(self.io, payload.q, payload.type, limit) catch {
        return respondError(output, "audit log is unreadable");
    };
    defer {
        for (entries) |*e| e.deinit(self.allocator);
        self.allocator.free(entries);
    }
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"entries\":[") catch return output[0..0];
    var first = true;
    for (entries) |*e| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.writeAll("{\"id\":") catch return output[0..0];
        json.writeJsonString(&writer, e.id) catch return output[0..0];
        writer.writeAll(",\"operation_id\":") catch return output[0..0];
        json.writeJsonString(&writer, e.operation_id) catch return output[0..0];
        writer.print(",\"ts\":{d},\"type\":", .{e.ts}) catch return output[0..0];
        json.writeJsonString(&writer, e.type) catch return output[0..0];
        writer.writeAll(",\"target\":") catch return output[0..0];
        json.writeJsonString(&writer, e.target) catch return output[0..0];
        writer.writeAll(",\"commands\":") catch return output[0..0];
        json.writeJsonString(&writer, e.commands) catch return output[0..0];
        writer.writeAll(",\"result\":") catch return output[0..0];
        json.writeJsonString(&writer, e.result) catch return output[0..0];
        writer.writeAll(",\"detail\":") catch return output[0..0];
        json.writeJsonString(&writer, e.detail) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

const AuditClearPayload = struct {
    confirm: []const u8 = "",
};

/// Type-to-confirm clear (spec 15 §5: `{confirm: "CLEAR"}`).
fn handleAuditClear(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AuditClearPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.confirm, "CLEAR")) {
        return respondError(output, "type CLEAR to confirm");
    }
    self.audit.clear(self.io) catch {
        return respondError(output, "audit log could not be cleared");
    };
    return ok_json;
}

// --- vault (spec 17) ---------------------------------------------------------

const VaultExportPayload = struct {
    path: []const u8,
    password: ?[]const u8 = null,
    sections: ?[]const []const u8 = null,
};

const VaultImportPayload = struct {
    path: []const u8,
    password: ?[]const u8 = null,
};

const VaultImportConfirmPayload = struct {
    path: []const u8,
    password: ?[]const u8 = null,
    keep_local: ?[]const []const u8 = null,
    import_as_new: ?[]const []const u8 = null,
};

fn vaultAllSections(self: *Context, buf: []vault.Section) usize {
    var n: usize = 0;
    buf[n] = .{ .name = "servers", .path = self.store.path, .jsonl = false };
    n += 1;
    buf[n] = .{ .name = "logs", .path = self.logs.path, .jsonl = false };
    n += 1;
    buf[n] = .{ .name = "scripts", .path = self.scripts.path, .jsonl = false };
    n += 1;
    buf[n] = .{ .name = "apps", .path = self.apps.path, .jsonl = false };
    n += 1;
    buf[n] = .{ .name = "deploy_runs", .path = self.deploy_history.path, .jsonl = false };
    n += 1;
    buf[n] = .{ .name = "access_identities", .path = self.access.identities.path, .jsonl = false };
    n += 1;
    buf[n] = .{ .name = "backup_jobs", .path = self.backup.jobs.path, .jsonl = false };
    n += 1;
    buf[n] = .{ .name = "backup_runs", .path = self.backup.history.path, .jsonl = false };
    n += 1;
    buf[n] = .{ .name = "ai_provider", .path = self.ai.provider.path, .jsonl = false };
    n += 1;
    buf[n] = .{ .name = "history", .path = self.history.path, .jsonl = true };
    n += 1;
    buf[n] = .{ .name = "audit", .path = self.audit.path, .jsonl = true };
    n += 1;
    return n;
}

fn vaultFilteredSections(self: *Context, requested: ?[]const []const u8, buf: []vault.Section, is_encrypted: bool) usize {
    var all: [12]vault.Section = undefined;
    const all_n = vaultAllSections(self, &all);
    if (requested == null or requested.?.len == 0) {
        // Plain export by default excludes history-like sections (spec 17 §8:
        // best-effort redaction cannot prove arbitrary text is clean).
        if (!is_encrypted) {
            var n: usize = 0;
            for (all[0..all_n]) |s| {
                if (s.jsonl) continue;
                if (std.mem.eql(u8, s.name, "deploy_runs")) continue;
                if (std.mem.eql(u8, s.name, "backup_runs")) continue;
                buf[n] = s;
                n += 1;
            }
            return n;
        }
        @memcpy(buf[0..all_n], all[0..all_n]);
        return all_n;
    }
    var n: usize = 0;
    for (requested.?) |name| {
        for (all[0..all_n]) |s| {
            if (std.mem.eql(u8, s.name, name)) {
                buf[n] = s;
                n += 1;
                break;
            }
        }
    }
    return n;
}

fn vaultLoadPayloadForImport(self: *Context, path: []const u8, password: ?[]const u8) !vault.Payload {
    // Try encrypted path first when a password is supplied; otherwise plain.
    // For robustness, if the file starts with the vault magic, treat it as
    // encrypted regardless of whether a password was supplied (and then fail
    // with AuthFailed if the password is missing/wrong).
    const content = std.Io.Dir.cwd().readFileAlloc(self.io, path, self.allocator, .limited(vault.max_file_bytes)) catch {
        return error.FileMissing;
    };
    defer self.allocator.free(content);
    if (content.len >= 9 and std.mem.eql(u8, content[0..9], vault.magic)) {
        // Encrypted vault — needs a password.
        const pw = password orelse return error.AuthFailed;
        const plain = try vault.readVaultFile(self.io, self.allocator, path, pw);
        defer self.allocator.free(plain);
        return vault.parsePayload(self.allocator, plain);
    } else {
        // Plain JSON.
        if (password != null and password.?.len > 0) {
            // If a password was supplied but the file is plain, treat the
            // password as extraneous — plain files are not encrypted.
        }
        return vault.parsePayload(self.allocator, content);
    }
}

fn vaultErrorString(err: anyerror) []const u8 {
    return switch (err) {
        error.PasswordTooShort => "password must be at least 12 characters",
        error.AuthFailed => "wrong password or corrupt file",
        error.UnsupportedVersion => "unsupported vault version",
        error.NotAVault => "not a vault file",
        error.TooLarge => "file too large",
        error.InvalidJson => "invalid vault JSON",
        error.DuplicateId => "duplicate id in vault section",
        error.RecordWithoutId => "record without id",
        error.FileMissing => "vault file not found",
        error.WriteFailed => "failed to write vault file",
        error.KdfFailed => "key derivation failed",
        error.SealFailed => "encryption failed",
        error.OutOfMemory => "out of memory",
        else => "vault operation failed",
    };
}

fn handleVaultExport(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(VaultExportPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.path.len == 0) return respondError(output, "path is required");
    const is_encrypted = payload.password != null and payload.password.?.len > 0;
    if (is_encrypted and payload.password.?.len < vault.min_password_len) {
        return respondError(output, vaultErrorString(error.PasswordTooShort));
    }
    var sections_buf: [12]vault.Section = undefined;
    const n = vaultFilteredSections(self, payload.sections, &sections_buf, is_encrypted);
    var vault_payload = vault.buildPayload(self.io, self.allocator, sections_buf[0..n]) catch |err| {
        return respondError(output, vaultErrorString(err));
    };
    defer vault_payload.deinit(self.allocator);
    if (is_encrypted) {
        const plain = vault.serializePayload(self.allocator, &vault_payload) catch {
            return respondError(output, "out of memory");
        };
        defer self.allocator.free(plain);
        vault.writeVaultFile(self.io, self.allocator, payload.path, payload.password.?, plain) catch |err| {
            return respondError(output, vaultErrorString(err));
        };
    } else {
        const plain = vault.serializePayload(self.allocator, &vault_payload) catch {
            return respondError(output, "out of memory");
        };
        defer self.allocator.free(plain);
        // Atomic write — same pattern as vault/store.
        const cwd = std.Io.Dir.cwd();
        if (std.fs.path.dirname(payload.path)) |dir| {
            cwd.createDirPath(self.io, dir) catch {
                return respondError(output, "failed to write vault file");
            };
        }
        var file = cwd.createFile(self.io, payload.path, .{}) catch {
            return respondError(output, "failed to write vault file");
        };
        defer file.close(self.io);
        file.writeStreamingAll(self.io, plain) catch {
            return respondError(output, "failed to write vault file");
        };
        file.sync(self.io) catch {
            return respondError(output, "failed to write vault file");
        };
    }
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"exported\":{d},\"sections\":{d}}}", .{ vault_payload.sections.count(), n }) catch return output[0..0];
    return writer.buffered();
}

fn handleVaultImport(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(VaultImportPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.path.len == 0) return respondError(output, "path is required");
    var vault_payload = vaultLoadPayloadForImport(self, payload.path, payload.password) catch |err| {
        return respondError(output, vaultErrorString(err));
    };
    defer vault_payload.deinit(self.allocator);
    var sections_buf: [12]vault.Section = undefined;
    const n = vaultAllSections(self, &sections_buf);
    var preview = vault.previewImport(self.io, self.allocator, &vault_payload, sections_buf[0..n]) catch |err| {
        return respondError(output, vaultErrorString(err));
    };
    defer preview.deinit(self.allocator);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"preview\":{\"reports\":[") catch return output[0..0];
    var first_report = true;
    for (preview.reports.items) |*r| {
        if (!first_report) writer.writeAll(",") catch return output[0..0];
        first_report = false;
        writer.writeAll("{\"name\":") catch return output[0..0];
        json.writeJsonString(&writer, r.name) catch return output[0..0];
        writer.print(",\"incoming\":{d},\"new\":{d},\"updated\":{d},\"conflicts\":[", .{ r.incoming, r.new, r.updated }) catch return output[0..0];
        var first_c = true;
        for (r.conflicts.items) |*c| {
            if (!first_c) writer.writeAll(",") catch return output[0..0];
            first_c = false;
            writer.writeAll("{\"key\":") catch return output[0..0];
            json.writeJsonString(&writer, c.key) catch return output[0..0];
            writer.writeAll(",\"reason\":") catch return output[0..0];
            json.writeJsonString(&writer, c.reason) catch return output[0..0];
            writer.writeAll("}") catch return output[0..0];
        }
        writer.writeAll("]}") catch return output[0..0];
    }
    writer.writeAll("],\"errors\":[") catch return output[0..0];
    var first_err = true;
    for (preview.errors.items) |*e| {
        if (!first_err) writer.writeAll(",") catch return output[0..0];
        first_err = false;
        writer.writeAll("{\"key\":") catch return output[0..0];
        json.writeJsonString(&writer, e.key) catch return output[0..0];
        writer.writeAll(",\"reason\":") catch return output[0..0];
        json.writeJsonString(&writer, e.reason) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]}}") catch return output[0..0];
    return writer.buffered();
}

fn handleVaultImportConfirm(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(VaultImportConfirmPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.path.len == 0) return respondError(output, "path is required");
    var vault_payload = vaultLoadPayloadForImport(self, payload.path, payload.password) catch |err| {
        return respondError(output, vaultErrorString(err));
    };
    defer vault_payload.deinit(self.allocator);
    var sections_buf: [12]vault.Section = undefined;
    const n = vaultAllSections(self, &sections_buf);
    const opts = vault.ImportOptions{
        .keep_local = payload.keep_local orelse &.{},
        .import_as_new = payload.import_as_new orelse &.{},
    };
    var result = vault.applyImport(self.io, self.allocator, &vault_payload, sections_buf[0..n], opts) catch |err| {
        return respondError(output, vaultErrorString(err));
    };
    defer result.deinit(self.allocator);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"result\":{\"notes\":[") catch return output[0..0];
    var first = true;
    for (result.notes.items) |note| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        json.writeJsonString(&writer, note) catch return output[0..0];
    }
    writer.writeAll("]}}") catch return output[0..0];
    return writer.buffered();
}

/// `oars.agent.list` `{path?}` → `{ok, identities:[{type, fingerprint_sha256, comment}]}`.
/// A missing agent is NOT a failure (spec 18 §5): `{ok:true, identities:[], error:"no agent"}`.
/// A stale or foreign socket is an explicit error with a hint — never a
/// directory scan fallback (spec 18 §8/§13).
fn handleAgentList(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self: *Context = @ptrCast(@alignCast(context));
    const parsed = std.json.parseFromSlice(struct {
        path: ?[]const u8 = null,
    }, self.allocator, invocation.request.payload, .{ .allocate = .alloc_always, .max_value_len = 4096 }) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();

    const path = agent.resolveSocket(self.allocator, parsed.value.path) catch {
        // Spec 18 §5: a missing agent is NOT a failure — the UI shows an
        // empty identity list with a hint.
        var writer = std.Io.Writer.fixed(output);
        const Resp = struct { ok: bool, identities: []const []const u8, @"error": []const u8 };
        std.json.Stringify.value(Resp{ .ok = true, .identities = &.{}, .@"error" = "no agent" }, .{}, &writer) catch return error.BufferTooSmall;
        return writer.buffered();
    };
    defer self.allocator.free(path);
    agent.validateSocket(path) catch |err| {
        // A missing socket is the same "no agent" shape (not a failure);
        // a present-but-wrong path is an explicit error with a hint.
        if (err == error.NoAgent) {
            var writer = std.Io.Writer.fixed(output);
            const Resp = struct { ok: bool, identities: []const []const u8, @"error": []const u8 };
            std.json.Stringify.value(Resp{ .ok = true, .identities = &.{}, .@"error" = "no agent" }, .{}, &writer) catch return error.BufferTooSmall;
            return writer.buffered();
        }
        return respondError(output, switch (err) {
            error.NotASocket => "the agent path is not a socket",
            error.NotOwned => "the agent socket is not owned by the current user",
            else => "no agent",
        });
    };

    // Identity listing needs a libssh2 session container, but no SSH
    // connection: libssh2_agent_connect talks to the local socket only.
    const raw = ssh.c.libssh2_session_init_ex(null, null, null, null) orelse {
        return respondError(output, "could not initialize the SSH library");
    };
    defer _ = ssh.c.libssh2_session_free(raw);
    var agent_conn = agent.Agent.init(raw) catch {
        return respondError(output, "could not connect to the SSH agent");
    };
    defer agent_conn.deinit();
    const identities = agent_conn.listIdentities(self.allocator) catch {
        return respondError(output, "could not list agent identities");
    };
    defer {
        for (identities) |*id| id.deinit(self.allocator);
        self.allocator.free(identities);
    }

    var writer = std.Io.Writer.fixed(output);
    std.json.Stringify.value(.{ .ok = true, .identities = identities }, .{}, &writer) catch return error.BufferTooSmall;
    return writer.buffered();
}

/// `oars.agent.forward` `{server_id, on}` → `{ok}`. Enabling requests
/// auth-agent forwarding on a NEW shell channel (the old one is
/// closed) and registers the local proxy; disabling closes the
/// forwarding shell and reopens without the request. Audited when
/// enabled (spec 18 §5/§8); refusal rolls the toggle back off.
fn handleAgentForward(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self: *Context = @ptrCast(@alignCast(context));
    const parsed = std.json.parseFromSlice(struct {
        server_id: []const u8,
        on: bool,
    }, self.allocator, invocation.request.payload, .{ .allocate = .alloc_always, .max_value_len = 4096 }) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();

    const outcome = self.allocator.create(sessions.ForwardSetOutcome) catch return respondError(output, "out of memory");
    outcome.* = .{ .allocator = self.allocator };
    self.manager.setForwarding(parsed.value.server_id, parsed.value.on, outcome) catch |err| {
        self.allocator.destroy(outcome);
        return respondError(output, switch (err) {
            error.NoSession => "no session for this server",
            error.NotReady => "server is not connected",
            else => "could not toggle agent forwarding",
        });
    };
    const deadline = std.Io.Timestamp.now(self.io, .real).nanoseconds + 20 * std.time.ns_per_s;
    outcome.wait(self.io, deadline);
    // On a deadline the op keeps the outcome (its eventual set frees it);
    // otherwise it is destroyed after the result is read.
    if (!outcome.isDone() and !outcome.abandon()) return respondError(output, "timed out waiting for the server");
    defer self.allocator.destroy(outcome);
    if (!outcome.ok) {
        return respondError(output, outcome.message());
    }
    if (parsed.value.on) {
        self.audit.append(self.io, "agent.forward.enable", parsed.value.server_id, "agent forwarding enabled") catch {
            return respondError(output, "audit failed");
        };
    }
    var writer = std.Io.Writer.fixed(output);
    std.json.Stringify.value(.{ .ok = true }, .{}, &writer) catch return error.BufferTooSmall;
    return writer.buffered();
}
