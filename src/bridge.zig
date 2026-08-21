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
const preflight = @import("preflight.zig");
const sshkeys = @import("sshkeys.zig");
const keygen = @import("keygen.zig");
const access = @import("access.zig");
const keyjobs = @import("keyjobs.zig");
const sshd_policy = @import("sshd_policy.zig");
const backup = @import("backup.zig");
const vault = @import("vault.zig");
const agent = @import("agent.zig");
const ssh = @import("ssh.zig");

pub const allowed_origins = [_][]const u8{ "zero://app", "http://127.0.0.1:5173" };

const handler_count = 118;

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
    keys: keyjobs.Registry,
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
            .{ .name = "oars.deploy.apps.secretPresence", .context = self, .invoke_fn = handleDeployAppsSecretPresence },
            .{ .name = "oars.deploy.apps.delete", .context = self, .invoke_fn = handleDeployAppsDelete },
            .{ .name = "oars.deploy.key.generate", .context = self, .invoke_fn = handleDeployKeyGenerate },
            .{ .name = "oars.deploy.hostTrust", .context = self, .invoke_fn = handleDeployHostTrust },
            .{ .name = "oars.deploy.preflight", .context = self, .invoke_fn = handleDeployPreflight },
            .{ .name = "oars.deploy.preflightPoll", .context = self, .invoke_fn = handleDeployPreflightPoll },
            .{ .name = "oars.deploy.preflightCancel", .context = self, .invoke_fn = handleDeployPreflightCancel },
            .{ .name = "oars.deploy.run", .context = self, .invoke_fn = handleDeployRun },
            .{ .name = "oars.deploy.poll", .context = self, .invoke_fn = handleDeployPoll },
            .{ .name = "oars.deploy.cancel", .context = self, .invoke_fn = handleDeployCancel },
            .{ .name = "oars.deploy.history", .context = self, .invoke_fn = handleDeployHistory },
            .{ .name = "oars.sshkeys.inspect", .context = self, .invoke_fn = handleSshKeysInspect },
            .{ .name = "oars.sshkeys.snapshot", .context = self, .invoke_fn = handleSshKeysSnapshot },
            .{ .name = "oars.sshkeys.snapshotPoll", .context = self, .invoke_fn = handleSshKeysSnapshotPoll },
            .{ .name = "oars.sshkeys.snapshotCancel", .context = self, .invoke_fn = handleSshKeysSnapshotCancel },
            .{ .name = "oars.sshkeys.add", .context = self, .invoke_fn = handleSshKeysAdd },
            .{ .name = "oars.sshkeys.revoke", .context = self, .invoke_fn = handleSshKeysRevoke },
            .{ .name = "oars.sshkeys.rotate", .context = self, .invoke_fn = handleSshKeysRotate },
            .{ .name = "oars.sshkeys.rotateCommit", .context = self, .invoke_fn = handleSshKeysRotateCommit },
            .{ .name = "oars.sshkeys.jobPoll", .context = self, .invoke_fn = handleSshKeysJobPoll },
            .{ .name = "oars.sshkeys.jobCancel", .context = self, .invoke_fn = handleSshKeysJobCancel },
            .{ .name = "oars.sshkeys.localGenerate", .context = self, .invoke_fn = handleSshKeysLocalGenerate },
            .{ .name = "oars.sshkeys.roles.plan", .context = self, .invoke_fn = handleSshKeysRolesPlan },
            .{ .name = "oars.sshkeys.roles.commit", .context = self, .invoke_fn = handleSshKeysRolesCommit },
            .{ .name = "oars.sshkeys.deployKeys.generate", .context = self, .invoke_fn = handleSshKeysDeployKeysGenerate },
            .{ .name = "oars.sshkeys.deployKeys.delete", .context = self, .invoke_fn = handleSshKeysDeployKeysDelete },
            .{ .name = "oars.access.scan", .context = self, .invoke_fn = handleAccessScan },
            .{ .name = "oars.access.scanCancel", .context = self, .invoke_fn = handleAccessScanCancel },
            .{ .name = "oars.access.poll", .context = self, .invoke_fn = handleAccessPoll },
            .{ .name = "oars.access.key.inspect", .context = self, .invoke_fn = handleAccessKeyInspect },
            .{ .name = "oars.access.identities.list", .context = self, .invoke_fn = handleAccessIdentitiesList },
            .{ .name = "oars.access.identities.save", .context = self, .invoke_fn = handleAccessIdentitiesSave },
            .{ .name = "oars.access.identities.delete", .context = self, .invoke_fn = handleAccessIdentitiesDelete },
            .{ .name = "oars.access.offboard", .context = self, .invoke_fn = handleAccessOffboard },
            .{ .name = "oars.access.onboard", .context = self, .invoke_fn = handleAccessOnboard },
            .{ .name = "oars.access.rotate", .context = self, .invoke_fn = handleAccessRotate },
            .{ .name = "oars.access.jobPoll", .context = self, .invoke_fn = handleAccessJobPoll },
            .{ .name = "oars.access.jobCancel", .context = self, .invoke_fn = handleAccessJobCancel },
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
            .{ .name = "oars.deploy.apps.secretPresence", .origins = &allowed_origins },
            .{ .name = "oars.deploy.apps.delete", .origins = &allowed_origins },
            .{ .name = "oars.deploy.key.generate", .origins = &allowed_origins },
            .{ .name = "oars.deploy.hostTrust", .origins = &allowed_origins },
            .{ .name = "oars.deploy.preflight", .origins = &allowed_origins },
            .{ .name = "oars.deploy.preflightPoll", .origins = &allowed_origins },
            .{ .name = "oars.deploy.preflightCancel", .origins = &allowed_origins },
            .{ .name = "oars.deploy.run", .origins = &allowed_origins },
            .{ .name = "oars.deploy.poll", .origins = &allowed_origins },
            .{ .name = "oars.deploy.cancel", .origins = &allowed_origins },
            .{ .name = "oars.deploy.history", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.inspect", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.snapshot", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.snapshotPoll", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.snapshotCancel", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.add", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.revoke", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.rotate", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.rotateCommit", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.jobPoll", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.jobCancel", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.localGenerate", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.roles.plan", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.roles.commit", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.deployKeys.generate", .origins = &allowed_origins },
            .{ .name = "oars.sshkeys.deployKeys.delete", .origins = &allowed_origins },
            .{ .name = "oars.access.scan", .origins = &allowed_origins },
            .{ .name = "oars.access.scanCancel", .origins = &allowed_origins },
            .{ .name = "oars.access.poll", .origins = &allowed_origins },
            .{ .name = "oars.access.key.inspect", .origins = &allowed_origins },
            .{ .name = "oars.access.identities.list", .origins = &allowed_origins },
            .{ .name = "oars.access.identities.save", .origins = &allowed_origins },
            .{ .name = "oars.access.identities.delete", .origins = &allowed_origins },
            .{ .name = "oars.access.offboard", .origins = &allowed_origins },
            .{ .name = "oars.access.onboard", .origins = &allowed_origins },
            .{ .name = "oars.access.rotate", .origins = &allowed_origins },
            .{ .name = "oars.access.jobPoll", .origins = &allowed_origins },
            .{ .name = "oars.access.jobCancel", .origins = &allowed_origins },
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

// --- one-click deployment (spec 07) ------------------------------------------

// --- preflight (spec 07: read-only, bounded, expiring, capped) --------------

const DeployPreflightPayload = struct { server_id: []const u8, app_id: []const u8 };
const DeployPreflightPollPayload = struct { preflight_id: u32 };
const DeployPreflightCancelPayload = struct { preflight_id: u32 };

/// Builds the DeployPreflight bridge shape for a given preflight record.
/// Redacted commands / configs are already on the record; this serializes them verbatim.
fn deployPreflightJson(_: *Context, writer: *std.Io.Writer, pf: *preflight.Preflight) !void {
    writer.writeAll("{\"ok\":true,\"preflight\":{") catch return;
    writer.print("\"id\":{d}", .{pf.id}) catch return;
    writer.writeAll(",\"app_id\":") catch return;
    json.writeJsonString(writer, pf.app_id) catch return;
    writer.writeAll(",\"server_id\":") catch return;
    json.writeJsonString(writer, pf.server_id) catch return;
    writer.print(",\"created_at_ms\":{d}", .{pf.created_at_ms}) catch return;
    writer.print(",\"expires_at_ms\":{d}", .{pf.expires_at_ms}) catch return;
    writer.print(",\"app_revision\":{d}", .{pf.app_revision}) catch return;
    writer.print(",\"target_fingerprint\":\"{x}\"", .{pf.target_fingerprint}) catch return;
    writer.writeAll(",\"status\":") catch return;
    json.writeJsonString(writer, pf.status.jsonName()) catch return;
    if (pf.error_text.len > 0) {
        writer.writeAll(",\"error\":") catch return;
        json.writeJsonString(writer, pf.error_text) catch return;
    }
    writer.writeAll(",\"facts\":{") catch return;
    writer.writeAll("\"os\":") catch return;
    json.writeJsonString(writer, pf.facts.os_pretty) catch return;
    writer.writeAll(",\"arch\":") catch return;
    json.writeJsonString(writer, pf.facts.arch) catch return;
    writer.writeAll(",\"libc\":") catch return;
    json.writeJsonString(writer, pf.facts.libc) catch return;
    writer.writeAll(",\"user\":") catch return;
    json.writeJsonString(writer, pf.facts.user) catch return;
    writer.writeAll(",\"home\":") catch return;
    json.writeJsonString(writer, pf.facts.home) catch return;
    writer.writeAll(",\"privilege\":") catch return;
    json.writeJsonString(writer, pf.facts.privilege.jsonName()) catch return;
    writer.writeAll(",\"repository_commit\":") catch return;
    json.writeJsonString(writer, pf.facts.repo.remote_commit) catch return;
    writer.writeAll(",\"lockfiles\":") catch return;
    json.writeJsonString(writer, pf.facts.repo.lockfiles) catch return;
    writer.writeAll(",\"git_host_fingerprints\":") catch return;
    json.writeJsonString(writer, pf.facts.repo.scanned_host_fingerprints) catch return;
    writer.writeAll(",\"ports\":") catch return;
    var ports_buf: [96]u8 = undefined;
    const app_port = if (pf.app.runtime.type == .node or pf.app.runtime.type == .next)
        std.fmt.bufPrint(&ports_buf, "{d}={s}; 80={s}; 443={s}", .{ pf.app.app_port, if (pf.facts.ports.app_port_in_use) "in-use" else if (pf.facts.ports.port_probe_ran) "free" else "unknown", pf.facts.ports.http_listener, pf.facts.ports.https_listener }) catch "unknown"
    else
        std.fmt.bufPrint(&ports_buf, "80={s}; 443={s}", .{ pf.facts.ports.http_listener, pf.facts.ports.https_listener }) catch "unknown";
    json.writeJsonString(writer, app_port) catch return;
    writer.writeAll("}") catch return;
    writer.writeAll(",\"blockers\":[") catch return;
    for (pf.blockers.items, 0..) |b, i| {
        if (i > 0) writer.writeAll(",") catch return;
        writer.writeAll("{\"id\":") catch return;
        json.writeJsonString(writer, b.id) catch return;
        writer.writeAll(",\"message\":") catch return;
        json.writeJsonString(writer, b.message) catch return;
        writer.writeAll("}") catch return;
    }
    writer.writeAll("],\"warnings\":[") catch return;
    for (pf.warnings.items, 0..) |w, i| {
        if (i > 0) writer.writeAll(",") catch return;
        writer.writeAll("{\"id\":") catch return;
        json.writeJsonString(writer, w.id) catch return;
        writer.writeAll(",\"message\":") catch return;
        json.writeJsonString(writer, w.message) catch return;
        writer.writeAll("}") catch return;
    }
    writer.writeAll("],\"approvals\":[") catch return;
    for (pf.approvals.items, 0..) |a, i| {
        if (i > 0) writer.writeAll(",") catch return;
        writer.writeAll("{\"id\":") catch return;
        json.writeJsonString(writer, a.id) catch return;
        writer.writeAll(",\"label\":") catch return;
        json.writeJsonString(writer, a.label) catch return;
        writer.writeAll(",\"detail\":") catch return;
        json.writeJsonString(writer, a.detail) catch return;
        writer.writeAll("}") catch return;
    }
    writer.writeAll("]") catch return;
    writer.writeAll(",\"configs\":{") catch return;
    writer.writeAll("\"env\":") catch return;
    json.writeJsonString(writer, pf.env_preview) catch return;
    writer.writeAll(",\"pm2\":") catch return;
    json.writeJsonString(writer, pf.pm2_preview) catch return;
    writer.writeAll(",\"nginx\":") catch return;
    json.writeJsonString(writer, pf.nginx_preview) catch return;
    writer.writeAll("}") catch return;
    writer.writeAll(",\"steps\":[") catch return;
    for (pf.steps.items, 0..) |*s, i| {
        if (i > 0) writer.writeAll(",") catch return;
        writer.writeAll("{") catch return;
        writer.writeAll("\"id\":") catch return;
        json.writeJsonString(writer, s.id) catch return;
        writer.writeAll(",\"label\":") catch return;
        json.writeJsonString(writer, s.label) catch return;
        writer.writeAll(",\"mutation\":") catch return;
        json.writeJsonString(writer, s.class.jsonName()) catch return;
        writer.writeAll(",\"command\":") catch return;
        json.writeJsonString(writer, s.command) catch return;
        writer.print(",\"skipped\":{s}", .{if (s.skipped) "true" else "false"}) catch return;
        writer.writeAll(",\"files\":[") catch return;
        for (s.file_writes, 0..) |f, j| {
            if (j > 0) writer.writeAll(",") catch return;
            writer.writeAll("{\"path\":") catch return;
            json.writeJsonString(writer, f.path) catch return;
            writer.print(",\"mode\":{d}", .{f.mode}) catch return;
            writer.writeAll("}") catch return;
        }
        writer.writeAll("],\"guards\":[") catch return;
        for (s.guards, 0..) |g, j| {
            if (j > 0) writer.writeAll(",") catch return;
            json.writeJsonString(writer, g) catch return;
        }
        writer.writeAll("]") catch return;
        writer.writeAll(",\"rollback\":") catch return;
        json.writeJsonString(writer, s.rollback) catch return;
        writer.writeAll("}") catch return;
    }
    writer.writeAll("]") catch return;
    if (pf.facts.repo.remote_commit.len > 0) {
        writer.writeAll(",\"commit\":") catch return;
        json.writeJsonString(writer, pf.facts.repo.remote_commit) catch return;
    }
    writer.writeAll("}}") catch return;
}

fn handleDeployPreflight(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeployPreflightPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const now_ms = deployNowMs(self.io);
    self.manager.preflights.lock();
    self.manager.preflights.expire(now_ms);
    const at_capacity = self.manager.preflights.list.items.len >= deploy.max_uncommitted_preflights;
    self.manager.preflights.unlock();
    if (at_capacity) return respondError(output, "preflight limit reached");
    var owned_opt = self.apps.find(self.io, parsed.value.app_id) catch {
        return respondError(output, "app registry is unreadable");
    };
    defer if (owned_opt) |*a| deploy.deinit(self.allocator, a);
    const app = owned_opt orelse return respondError(output, "app not found");
    if (!std.mem.eql(u8, app.server_id, parsed.value.server_id)) return respondError(output, "app not found on this server");
    const session = self.manager.get(parsed.value.server_id) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");
    const probes = preflight.buildProbes(self.allocator, &app) catch return respondError(output, "failed to build preflight probes");
    defer for (probes) |probe| self.allocator.free(probe);
    var record = preflight.Preflight{
        .id = 0,
        .server_id = self.allocator.dupe(u8, app.server_id) catch return respondError(output, "out of memory"),
        .app_id = self.allocator.dupe(u8, app.id) catch return respondError(output, "out of memory"),
        .app = deploy.clone(self.allocator, app) catch return respondError(output, "out of memory"),
        .app_revision = app.revision,
        .created_at_ms = now_ms,
        .expires_at_ms = now_ms + preflight.preflight_ttl_ms,
    };
    var record_owned = true;
    defer if (record_owned) record.deinit(self.allocator);
    for (0..preflight.probe_count) |i| {
        const outcome = self.allocator.create(preflight.ProbeOutcome) catch return respondError(output, "out of memory");
        outcome.* = preflight.ProbeOutcome.init(self.allocator);
        record.probe_outcomes[i] = outcome;
        self.manager.enqueuePreflightProbe(app.server_id, @tagName(@as(preflight.ProbeId, @enumFromInt(i))), probes[i], preflight.probe_timeout_ns, outcome) catch {
            return respondError(output, "could not start the preflight probes");
        };
    }
    self.manager.preflights.lock();
    const id = self.manager.preflights.add(record) catch {
        self.manager.preflights.unlock();
        return respondError(output, "preflight limit reached");
    };
    record_owned = false;
    const pf = self.manager.preflights.get(id).?;
    var writer = std.Io.Writer.fixed(output);
    deployPreflightJson(self, &writer, pf) catch {
        self.manager.preflights.unlock();
        return output[0..0];
    };
    self.manager.preflights.unlock();
    var detail_buf: [64]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "preflight={d}", .{id}) catch "preflight";
    self.audit.append(self.io, "deploy.preflight", parsed.value.server_id, detail) catch {};
    return writer.buffered();
}

fn collectDeployPreflight(self: *Context, pf: *preflight.Preflight) void {
    if (pf.status != .gathering) return;
    var all_done = true;
    for (0..preflight.probe_count) |i| {
        const outcome = pf.probe_outcomes[i] orelse continue;
        if (!outcome.isDone()) {
            all_done = false;
            continue;
        }
        if (!outcome.ok) {
            pf.status = .failed;
            if (pf.error_text.len == 0) {
                pf.error_text = self.allocator.dupe(u8, outcome.message()) catch &.{};
            }
        } else {
            pf.outputs[i] = self.allocator.dupe(u8, outcome.data.items) catch &.{};
        }
        pf.probe_outcomes[i] = null;
        outcome.deinit();
        self.allocator.destroy(outcome);
    }
    if (!all_done or pf.status == .failed) return;
    preflight.parseSystem(self.allocator, pf.outputs[0], &pf.facts) catch {
        pf.status = .failed;
        pf.error_text = self.allocator.dupe(u8, "invalid system probe response") catch &.{};
        return;
    };
    preflight.parseTools(self.allocator, pf.outputs[1], &pf.facts) catch {
        pf.status = .failed;
        pf.error_text = self.allocator.dupe(u8, "invalid tools probe response") catch &.{};
        return;
    };
    preflight.parseRepo(self.allocator, pf.outputs[2], &pf.facts) catch {
        pf.status = .failed;
        pf.error_text = self.allocator.dupe(u8, "invalid repository probe response") catch &.{};
        return;
    };
    preflight.parsePorts(self.allocator, pf.outputs[3], &pf.facts) catch {
        pf.status = .failed;
        pf.error_text = self.allocator.dupe(u8, "invalid port and DNS probe response") catch &.{};
        return;
    };
    preflight.parseRuntime(self.allocator, pf.outputs[4], &pf.facts) catch {
        pf.status = .failed;
        pf.error_text = self.allocator.dupe(u8, "invalid Node release probe response") catch &.{};
        return;
    };
    preflight.derive(self.allocator, pf) catch {
        pf.status = .failed;
        pf.error_text = self.allocator.dupe(u8, "failed to derive the deployment plan") catch &.{};
    };
}

fn handleDeployPreflightPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeployPreflightPollPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const now_ms = deployNowMs(self.io);
    self.manager.preflights.lock();
    const pf = self.manager.preflights.get(parsed.value.preflight_id) orelse {
        self.manager.preflights.unlock();
        return respondError(output, "unknown preflight");
    };
    defer self.manager.preflights.unlock();
    if (now_ms >= pf.expires_at_ms) {
        _ = self.manager.preflights.remove(parsed.value.preflight_id);
        return respondError(output, "stale_preflight");
    }
    collectDeployPreflight(self, pf);
    var writer = std.Io.Writer.fixed(output);
    deployPreflightJson(self, &writer, pf) catch return output[0..0];
    return writer.buffered();
}

fn handleDeployPreflightCancel(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeployPreflightCancelPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    self.manager.preflights.lock();
    if (self.manager.preflights.get(parsed.value.preflight_id) == null) {
        self.manager.preflights.unlock();
        return respondError(output, "unknown preflight");
    }
    _ = self.manager.preflights.remove(parsed.value.preflight_id);
    self.manager.preflights.unlock();
    var detail_buf: [64]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "preflight={d}", .{parsed.value.preflight_id}) catch "preflight canceled";
    self.audit.append(self.io, "deploy.preflightCancel", "", detail) catch {};
    return ok_json;
}

// --- tests -----------------------------------------------------------------

const deploy_poll_data_budget: usize = 256 * 1024;
const DeployAppsListPayload = struct { server_id: []const u8 };
const DeployAppsSavePayload = struct { app: deploy.AppInput };
const DeployAppsSecretPresencePayload = struct { app_id: []const u8, names: []const []const u8, present: bool };
const DeployAppsDeletePayload = struct {
    server_id: []const u8,
    app_id: []const u8,
};
const DeployKeyPayload = struct { server_id: []const u8, app_id: []const u8 };
const DeployHostTrustPayload = struct { preflight_id: u32, accept: bool };
const DeployRunPayload = struct {
    server_id: ?[]const u8 = null,
    app_id: ?[]const u8 = null,
    preflight_id: ?u32 = null,
    approvals: ?[][]const u8 = null,
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
        .queued, .running, .cancel_requested => false,
        else => true,
    };
}

test "deploy cancellation remains pollable until termination is verified" {
    try std.testing.expect(!deployTerminal(.cancel_requested));
    try std.testing.expect(deployTerminal(.canceled));
    try std.testing.expect(deployTerminal(.failed));
    try std.testing.expect(deployTerminal(.done));
}

test "deployment SSH setup is queued as one scoped command" {
    const allocator = std.testing.allocator;
    const generated = try deployKeyGenerateCommand(allocator, "app one", "'github.com'", true);
    defer allocator.free(generated);
    try std.testing.expect(std.mem.indexOf(u8, generated, "ssh-keyscan -T 5 'github.com'") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated, preflight.github_known_hosts[0]) != null);
    try std.testing.expect(std.mem.indexOf(u8, generated, "grep -Fqx") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated, "mv -f \"$VERIFIED\" \"$KH\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, generated, "@public") != null);

    const trusted = try deployWriteKnownHostsCommand(allocator, "app one", "host ssh-ed25519 AAAA");
    defer allocator.free(trusted);
    try std.testing.expect(std.mem.indexOf(u8, trusted, "APP_ID='app one'") != null);
    try std.testing.expect(std.mem.indexOf(u8, trusted, "chmod 600 \"$TMP\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, trusted, "mv -f \"$TMP\" \"$KH\"") != null);
}

/// Wire timestamps are integer milliseconds (NEXT-SPEC bridge contract);
/// epoch nanoseconds do not survive the JS number round trip.
fn deployNowMs(io: std.Io) i64 {
    return @intCast(@divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_ms));
}

/// The initiating action for history: "update" once the app has a
/// completed run on record, "deploy" before the first success.
fn deployAction(self: *Context, server_id: []const u8, app_id: []const u8) []const u8 {
    var loaded = self.deploy_history.loadParsed(self.io) catch return "deploy";
    defer loaded.deinit(self.allocator);
    for (loaded.parsed.value) |rec| {
        if (std.mem.eql(u8, rec.server_id, server_id) and std.mem.eql(u8, rec.app_id, app_id) and rec.status == .done) return "update";
    }
    return "deploy";
}

fn deploySaveError(err: anyerror) []const u8 {
    return switch (err) {
        error.MissingId => "missing app id",
        error.MissingServer => "missing server",
        error.ServerMismatch => "an application cannot move to another server",
        error.MissingName => "app name is required",
        error.InvalidName => "invalid app name",
        error.MissingFolder => "deploy folder is required",
        error.InvalidFolder => "invalid deploy folder",
        error.InvalidRepo => "invalid repository URL",
        error.InvalidTransport => "invalid repository transport",
        error.UnsupportedTransport => "unsupported transport (public HTTPS or SSH only)",
        error.InvalidBranch => "invalid branch",
        error.InvalidNodeVersion => "invalid Node.js version line",
        error.InvalidAppType => "invalid app type",
        error.InvalidPackageManager => "invalid package manager",
        error.InvalidCommand => "invalid install/build/start command",
        error.MissingEntry => "a process entry or start command is required for this app type",
        error.InvalidEntry => "invalid process entry path",
        error.MissingBuildFolder => "a build folder is required for this app type",
        error.InvalidBuildFolder => "invalid build folder",
        error.InvalidEnvVar => "invalid environment variable",
        error.DuplicateEnvVar => "duplicate environment variable",
        error.TooManyEnvVars => "too many environment variables",
        error.InvalidDomain => "invalid domain",
        error.TooManyDomains => "too many domains",
        error.DuplicateDomain => "duplicate domain",
        error.EmailRequired => "an email is required when SSL is enabled",
        error.InvalidEmail => "invalid certificate email",
        error.InvalidPort => "invalid app port",
        error.TooManyApps => "application limit reached (500 total, 100 per server)",
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
    const now_ns = std.Io.Timestamp.now(self.io, .real).nanoseconds;
    var owned_id: ?[]const u8 = null;
    defer if (owned_id) |o| self.allocator.free(o);
    if (input.id == null) {
        owned_id = servers.makeId(self.allocator, now_ns) catch return respondError(output, "out of memory");
        input.id = owned_id;
    }
    var saved = self.apps.saveApp(self.io, input, deployNowMs(self.io)) catch |err| {
        return respondError(output, deploySaveError(err));
    };
    defer deploy.deinit(self.allocator, &saved);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"app\":") catch return output[0..0];
    std.json.Stringify.value(saved, .{}, &writer) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleDeployAppsSecretPresence(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeployAppsSecretPresencePayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    var saved = self.apps.setSecretPresence(self.io, parsed.value.app_id, parsed.value.names, parsed.value.present, deployNowMs(self.io)) catch |err| return respondError(output, deploySaveError(err));
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

fn deployWriteKnownHostsCommand(allocator: std.mem.Allocator, app_id: []const u8, keys: []const u8) ![]u8 {
    const q_id = try shellquote.quote(allocator, app_id);
    defer allocator.free(q_id);
    const q_keys = try shellquote.quote(allocator, keys);
    defer allocator.free(q_keys);
    return std.fmt.allocPrint(allocator, "APP_ID={s}; KEYS={s}; DIR=\"$HOME/.config/oars/deploy/$APP_ID\"; KH=\"$DIR/known_hosts\"; umask 077; mkdir -p \"$DIR\" && chmod 700 \"$DIR\" || exit 1; TMP=\"$KH.oars.$$\"; trap 'rm -f \"$TMP\"' EXIT HUP INT TERM; printf '%s\\n' \"$KEYS\" > \"$TMP\" && chmod 600 \"$TMP\" && mv -f \"$TMP\" \"$KH\"", .{ q_id, q_keys });
}

fn deployKeyGenerateCommand(allocator: std.mem.Allocator, app_id: []const u8, scan_target: []const u8, verify_github: bool) ![]u8 {
    const q_id = try shellquote.quote(allocator, app_id);
    defer allocator.free(q_id);
    var command: std.ArrayList(u8) = .empty;
    errdefer command.deinit(allocator);
    try command.appendSlice(allocator, "APP_ID=");
    try command.appendSlice(allocator, q_id);
    try command.appendSlice(allocator, "; DIR=\"$HOME/.config/oars/deploy/$APP_ID\"; KEY=\"$DIR/id_ed25519\"; KH=\"$DIR/known_hosts\"; umask 077; mkdir -p \"$DIR\" && chmod 700 \"$DIR\" || exit 1; [ -f \"$KEY\" ] || ssh-keygen -q -t ed25519 -N '' -f \"$KEY\" -C \"oars-deploy-$APP_ID\" || exit 1; chmod 600 \"$KEY\"; ");
    if (verify_github) {
        try command.appendSlice(allocator, "SCAN=\"$DIR/.scan.$$\"; VERIFIED=\"$DIR/.verified.$$\"; trap 'rm -f \"$SCAN\" \"$VERIFIED\"' EXIT HUP INT TERM; ssh-keyscan -T 5 ");
        try command.appendSlice(allocator, scan_target);
        try command.appendSlice(allocator, " 2>/dev/null | head -8 > \"$SCAN\"; : > \"$VERIFIED\"; ");
        for (preflight.github_known_hosts) |published| {
            const q_published = try shellquote.quote(allocator, published);
            defer allocator.free(q_published);
            try command.appendSlice(allocator, "PUBLISHED=");
            try command.appendSlice(allocator, q_published);
            try command.appendSlice(allocator, "; grep -Fqx \"$PUBLISHED\" \"$SCAN\" && printf '%s\\n' \"$PUBLISHED\" >> \"$VERIFIED\"; ");
        }
        try command.appendSlice(allocator, "[ -s \"$VERIFIED\" ] || { echo \"github.com's scanned host key does not match GitHub's published entries\"; exit 1; }; chmod 600 \"$VERIFIED\" && mv -f \"$VERIFIED\" \"$KH\" || exit 1; ");
    }
    try command.appendSlice(allocator, "echo '@public'; cat \"$KEY.pub\"");
    return command.toOwnedSlice(allocator);
}

/// Generates the exact per-app key consumed by deployment preflight. For
/// github.com, the same explicit action also installs only a scanned key that
/// matches GitHub's published known-host entries.
fn handleDeployKeyGenerate(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeployKeyPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    var app_opt = self.apps.find(self.io, parsed.value.app_id) catch return respondError(output, "app registry is unreadable");
    defer if (app_opt) |*app| deploy.deinit(self.allocator, app);
    const app = app_opt orelse return respondError(output, "app not found");
    if (!std.mem.eql(u8, app.server_id, parsed.value.server_id)) return respondError(output, "app not found on this server");
    if (app.repo.transport != .ssh) return respondError(output, "this application does not use SSH repository access");

    const host = preflight.repoHost(self.allocator, app.repo.url) catch return respondError(output, "invalid repository host");
    defer self.allocator.free(host);
    const scan_target = preflight.sshKeyscanTarget(self.allocator, app.repo.url) catch return respondError(output, "invalid repository host");
    defer self.allocator.free(scan_target);
    const command = deployKeyGenerateCommand(self.allocator, app.id, scan_target, std.mem.eql(u8, host, "github.com")) catch return respondError(output, "out of memory");
    defer self.allocator.free(command);
    self.audit.append(self.io, "deploy.key.generate", app.server_id, app.id) catch return respondError(output, "audit failed");
    const channel = self.manager.execTracked(app.server_id, command, "deploy", "generate per-app deployment SSH key", &.{}) catch return respondError(output, "not connected");
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel}) catch return output[0..0];
    return writer.buffered();
}

/// Commits a non-GitHub host key only after the UI shows its SHA-256
/// fingerprint and the user approves that exact preflight snapshot.
fn handleDeployHostTrust(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeployHostTrustPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    if (!parsed.value.accept) return respondError(output, "host-key approval is required");
    self.manager.preflights.lock();
    const pf = self.manager.preflights.get(parsed.value.preflight_id) orelse {
        self.manager.preflights.unlock();
        return respondError(output, "unknown preflight");
    };
    var can_trust = false;
    for (pf.approvals.items) |approval| {
        if (std.mem.eql(u8, approval.id, "git-host-key")) can_trust = true;
    }
    if (!can_trust or pf.facts.repo.scanned_host_keys.len == 0 or pf.facts.repo.scanned_host_fingerprints.len == 0) {
        self.manager.preflights.unlock();
        return respondError(output, "this preflight has no independently verified host-key approval");
    }
    const server_id = self.allocator.dupe(u8, pf.server_id) catch {
        self.manager.preflights.unlock();
        return respondError(output, "out of memory");
    };
    defer self.allocator.free(server_id);
    const app_id = self.allocator.dupe(u8, pf.app_id) catch {
        self.manager.preflights.unlock();
        return respondError(output, "out of memory");
    };
    defer self.allocator.free(app_id);
    const keys = self.allocator.dupe(u8, pf.facts.repo.scanned_host_keys) catch {
        self.manager.preflights.unlock();
        return respondError(output, "out of memory");
    };
    defer self.allocator.free(keys);
    self.manager.preflights.unlock();

    const command = deployWriteKnownHostsCommand(self.allocator, app_id, keys) catch return respondError(output, "out of memory");
    defer self.allocator.free(command);
    self.audit.append(self.io, "deploy.hostTrust", server_id, app_id) catch return respondError(output, "audit failed");
    const channel = self.manager.execTracked(server_id, command, "deploy", "store approved deployment Git host keys", &.{}) catch return respondError(output, "not connected");
    self.manager.preflights.lock();
    _ = self.manager.preflights.remove(parsed.value.preflight_id);
    self.manager.preflights.unlock();
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"channel\":{d}}}", .{channel}) catch return output[0..0];
    return writer.buffered();
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
fn handleDeployRunFromPreflight(self: *Context, invocation_id: []const u8, output: []u8, pf_id: u32, approvals: ?[][]const u8, secret_values: ?[]const deploy.SecretValue) []const u8 {
    const now_ms = deployNowMs(self.io);
    self.manager.preflights.lock();
    const pf = self.manager.preflights.get(pf_id) orelse {
        self.manager.preflights.unlock();
        return respondError(output, "unknown preflight");
    };
    if (now_ms >= pf.expires_at_ms) {
        _ = self.manager.preflights.remove(pf_id);
        self.manager.preflights.unlock();
        return respondError(output, "stale_preflight");
    }
    collectDeployPreflight(self, pf);
    if (pf.status == .gathering) {
        self.manager.preflights.unlock();
        return respondError(output, "preflight still running");
    }
    if (pf.status == .failed) {
        self.manager.preflights.unlock();
        return respondError(output, if (pf.error_text.len > 0) pf.error_text else "preflight failed");
    }
    if (pf.status == .blocked or pf.blockers.items.len > 0) {
        self.manager.preflights.unlock();
        return respondError(output, "preflight has blockers");
    }
    // Guard: frozen app revision still current.
    const app_opt_const = self.apps.find(self.io, pf.app_id) catch {
        self.manager.preflights.unlock();
        return respondError(output, "app registry is unreadable");
    };
    if (app_opt_const == null) {
        self.manager.preflights.unlock();
        return respondError(output, "app not found");
    }
    var app = app_opt_const.?;
    defer deploy.deinit(self.allocator, &app);
    if (app.revision != pf.app_revision) {
        self.manager.preflights.unlock();
        return respondError(output, "stale_preflight");
    }
    // Require approvals if the preflight demanded them (privileged/nginx etc.).
    if (pf.approvals.items.len > 0) {
        const got = approvals orelse {
            self.manager.preflights.unlock();
            return respondError(output, "missing required approval");
        };
        for (pf.approvals.items) |need| {
            var ok = false;
            for (got) |g| if (std.mem.eql(u8, g, need.id)) {
                ok = true;
                break;
            };
            if (!ok) {
                self.manager.preflights.unlock();
                return respondError(output, "missing required approval");
            }
        }
    }
    var values: std.ArrayList(deploy.SecretValue) = .empty;
    defer values.deinit(self.allocator);
    if (secret_values) |svs| {
        var seen: std.StringHashMap(void) = .init(self.allocator);
        defer seen.deinit();
        for (svs) |sv| {
            if (seen.contains(sv.name)) {
                self.manager.preflights.unlock();
                return respondError(output, "duplicate secret variable");
            }
            seen.put(sv.name, {}) catch {
                self.manager.preflights.unlock();
                return respondError(output, "out of memory");
            };
            var declared = false;
            for (app.env_vars) |v| if (v.secret and std.mem.eql(u8, v.name, sv.name)) {
                declared = true;
                break;
            };
            if (!declared) {
                self.manager.preflights.unlock();
                return respondError(output, "unknown secret variable");
            }
            values.append(self.allocator, sv) catch {
                self.manager.preflights.unlock();
                return respondError(output, "out of memory");
            };
        }
        for (app.env_vars) |v| if (v.secret and !seen.contains(v.name)) {
            self.manager.preflights.unlock();
            return respondError(output, "missing required secret");
        };
    } else {
        for (app.env_vars) |v| if (v.secret) {
            self.manager.preflights.unlock();
            return respondError(output, "missing required secret");
        };
    }
    const server_id_dup = self.allocator.dupe(u8, pf.server_id) catch {
        self.manager.preflights.unlock();
        return respondError(output, "out of memory");
    };
    const node_release = self.allocator.dupe(u8, pf.facts.node_version) catch {
        self.manager.preflights.unlock();
        self.allocator.free(server_id_dup);
        return respondError(output, "out of memory");
    };
    defer self.allocator.free(node_release);
    const commit = self.allocator.dupe(u8, pf.facts.repo.remote_commit) catch {
        self.manager.preflights.unlock();
        self.allocator.free(server_id_dup);
        return respondError(output, "out of memory");
    };
    defer self.allocator.free(commit);
    const node_interpreter = std.fmt.allocPrint(self.allocator, "{s}/.local/share/oars/node/{s}/bin/node", .{ pf.facts.home, pf.facts.node_version }) catch {
        self.manager.preflights.unlock();
        self.allocator.free(server_id_dup);
        return respondError(output, "out of memory");
    };
    defer self.allocator.free(node_interpreter);
    // Take the frozen plan (removes the preflight — single commit).
    const frozen_plan = self.manager.preflights.takePlan(pf_id);
    self.manager.preflights.unlock();
    if (frozen_plan.len == 0) return respondError(output, "preflight has no plan");
    defer {
        for (frozen_plan) |*ps| {
            self.allocator.free(ps.label);
            ps.deinit(self.allocator);
        }
        self.allocator.free(frozen_plan);
    }
    defer self.allocator.free(server_id_dup);

    const session = self.manager.get(server_id_dup) orelse return respondError(output, "not connected");
    if (session.status.load(.acquire) != .ready) return respondError(output, "session not ready");

    // Admission before audit + remote work (capacity is an Oars decision).
    self.manager.deploys.lock();
    defer self.manager.deploys.unlock();
    var gate_same_folder: usize = 0;
    var gate_total: usize = 0;
    for (self.manager.deploys.list.items) |*r| {
        const s = r.status;
        if (s == .queued or s == .running or s == .cancel_requested) {
            gate_total += 1;
            if (std.mem.eql(u8, r.server_id, server_id_dup) and std.mem.eql(u8, r.app.folder, app.folder)) gate_same_folder += 1;
        }
    }
    if (gate_same_folder >= 1) return respondError(output, "another deployment already owns this server folder");
    if (gate_total >= deploy.max_active_runs_total) return respondError(output, "too many active deploys (8)");

    if (deployAudit(self, output, "deploy.run", app.server_id, &app, frozen_plan)) |resp| return resp;
    const run_id = self.manager.deploys.start(app.server_id, &app, frozen_plan, values.items, deployAction(self, app.server_id, app.id), commit, node_release, node_interpreter, self.io, now_ms) catch {
        return respondError(output, "out of memory");
    };
    self.audit.append(self.io, "deploy.run", app.server_id, invocation_id) catch {};
    var writer = std.Io.Writer.fixed(output);
    writer.print("{{\"ok\":true,\"run_id\":{d}}}", .{run_id}) catch return output[0..0];
    return writer.buffered();
}

fn handleDeployRun(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(DeployRunPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;

    // A deployment can start only from one completed, reviewed preflight.
    if (payload.preflight_id) |pf_id| {
        return handleDeployRunFromPreflight(self, invocation.request.id, output, pf_id, payload.approvals, payload.secret_values);
    }
    return respondError(output, "a completed preflight is required");
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

/// Queues the file write that a step needs. The bytes travel over stdin and
/// are cleared by the worker; secret values never enter command text or block
/// the bridge thread. Nginx is staged under the app folder for the reviewed
/// privileged transaction in `buildPlan`.
fn deployStartStepFile(self: *Context, run: *deploy.Run, step: *deploy.Step) ?[]const u8 {
    var path: ?[]u8 = null;
    var content: ?[]u8 = null;
    var secret_bearing = false;
    defer if (path) |p| self.allocator.free(p);
    defer if (content) |bytes| {
        if (secret_bearing) std.crypto.secureZero(u8, bytes);
        self.allocator.free(bytes);
    };

    switch (step.id) {
        .install, .build => {
            if (run.env_written) {
                step.prepared = true;
                return null;
            }
            path = deploy.envFilePath(self.allocator, run.app.folder) catch return "out of memory";
            content = deploy.envFile(self.allocator, &run.app, run.secrets.items) catch return "out of memory";
            secret_bearing = true;
        },
        .pm2 => {
            if (run.app.runtime.type != .node and run.app.runtime.type != .next) {
                step.prepared = true;
                return null;
            }
            path = deploy.pm2EcosystemPath(self.allocator, run.app.folder) catch return "out of memory";
            content = deploy.ecosystemFileForInterpreter(self.allocator, &run.app, run.secrets.items, run.node_interpreter) catch return "out of memory";
            secret_bearing = true;
        },
        .nginx => {
            path = std.fmt.allocPrint(self.allocator, "{s}/.oars-nginx.{s}", .{ run.app.folder, run.app.id }) catch return "out of memory";
            content = deploy.nginxConfig(self.allocator, &run.app) catch return "out of memory";
        },
        else => {
            step.prepared = true;
            return null;
        },
    }
    const quoted = shellquote.quote(self.allocator, path.?) catch return "out of memory";
    defer self.allocator.free(quoted);
    const mode = if (step.id == .nginx) "0600" else "0600";
    const command = std.fmt.allocPrint(self.allocator, "DEST={s}; DIR=$(dirname -- \"$DEST\"); umask 077; mkdir -p \"$DIR\" || exit 1; TMP=\"$DEST.oars.$$\"; trap 'rm -f \"$TMP\"' EXIT HUP INT TERM; cat > \"$TMP\" && chmod {s} \"$TMP\" && mv -f \"$TMP\" \"$DEST\"", .{ quoted, mode }) catch return "out of memory";
    defer self.allocator.free(command);
    step.prepare_channel = self.manager.execWithInput(run.server_id, command, content.?) catch return "failed to queue the configuration write";
    return null;
}

fn deployCaptureChannel(run: *deploy.Run, step: *deploy.Step, allocator: std.mem.Allocator, poll: *const sessions.ChannelPoll) void {
    const start = poll.cursor -| poll.data.len;
    const eof = poll.eof and poll.pending <= poll.data.len;
    run.captureOutput(allocator, step, poll.data, start, poll.cursor, eof);
    step.capture_cursor = poll.cursor;
    if (step.output_chunks.items.len == 0) step.output_floor = poll.cursor;
    step.stream_eof = eof;
}

/// Poll-driven step engine: starts the next step on each call, advances
/// on channel EOF, writes each step's config file first, and marks the
/// run done/failed/canceled/interrupted exactly once (appending the
/// history record).
fn deployPollStep(self: *Context, run: *deploy.Run, now_ms: i64) void {
    while (run.currentStep()) |step| {
        if (run.status == .cancel_requested) {
            if (step.prepare_channel) |prepare_ch| {
                const writes = self.manager.pollChannels(run.server_id, &.{.{ .id = prepare_ch, .pos = 0 }}, false, 8 * 1024, 8 * 1024) catch return;
                defer {
                    for (writes) |*poll| poll.deinit(self.allocator);
                    self.allocator.free(writes);
                }
                for (writes) |*write| {
                    if (write.id != prepare_ch or !write.eof) continue;
                    self.manager.closeChannel(run.server_id, prepare_ch) catch {};
                    step.prepare_channel = null;
                    run.canceled = true;
                    step.state = .canceled;
                    run.status = .canceled;
                    run.finished_at_ms = now_ms;
                    self.deploy_history.append(self.io, run, now_ms);
                    return;
                }
                return;
            }
            if (step.cancel_channel) |cancel_ch| {
                const checks = self.manager.pollChannels(run.server_id, &.{.{ .id = cancel_ch, .pos = 0 }}, false, 8 * 1024, 8 * 1024) catch return;
                defer {
                    for (checks) |*poll| poll.deinit(self.allocator);
                    self.allocator.free(checks);
                }
                for (checks) |*check| {
                    if (check.id != cancel_ch or !check.eof) continue;
                    self.manager.closeChannel(run.server_id, cancel_ch) catch {};
                    step.cancel_channel = null;
                    if (check.exit_status == 0 and std.mem.indexOf(u8, check.data, "ok") != null) {
                        run.canceled = true;
                        step.termination_verified = true;
                    } else {
                        step.state = .cancel_requested;
                        step.@"error" = "termination could not be verified; the process may still be running";
                    }
                    return;
                }
            }
            // Keep the original channel observable. If it reaches EOF after
            // the request, the process-group wrapper itself has exited.
            if (step.channel) |ch| {
                const polls = self.manager.pollChannels(run.server_id, &.{.{ .id = ch, .pos = step.capture_cursor }}, false, 64 * 1024, 64 * 1024) catch return;
                defer {
                    for (polls) |*poll| poll.deinit(self.allocator);
                    self.allocator.free(polls);
                }
                for (polls) |*poll| {
                    if (poll.id != ch) continue;
                    deployCaptureChannel(run, step, self.allocator, poll);
                    if (!step.stream_eof and !(step.termination_verified and poll.pending <= poll.data.len)) continue;
                    self.manager.closeChannel(run.server_id, ch) catch {};
                    run.canceled = true;
                    step.state = .canceled;
                    run.status = .canceled;
                    run.finished_at_ms = now_ms;
                    self.deploy_history.append(self.io, run, now_ms);
                    return;
                }
            }
            return;
        }
        if (run.canceled) {
            step.state = .canceled;
            run.status = .canceled;
            run.finished_at_ms = now_ms;
            self.deploy_history.append(self.io, run, now_ms);
            return;
        }
        if (step.channel) |ch| {
            const polls = self.manager.pollChannels(run.server_id, &.{.{ .id = ch, .pos = step.capture_cursor }}, false, 64 * 1024, 64 * 1024) catch {
                step.@"error" = "session lost";
                step.state = .failed;
                run.status = .interrupted;
                run.finished_at_ms = now_ms;
                self.deploy_history.append(self.io, run, now_ms);
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
                deployCaptureChannel(run, step, self.allocator, poll);
                eof = step.stream_eof;
                exit = poll.exit_status;
            }
            if (!eof) return;
            self.manager.closeChannel(run.server_id, ch) catch {};
            step.exit = exit;
            if (exit != 0) {
                step.state = .failed;
                step.@"error" = "command failed";
                run.status = .failed;
                run.finished_at_ms = now_ms;
                self.deploy_history.append(self.io, run, now_ms);
                return;
            }
            step.state = .success;
            run.step_index += 1;
            continue;
        }
        if (!step.prepared) {
            if (step.prepare_channel) |prepare_ch| {
                const writes = self.manager.pollChannels(run.server_id, &.{.{ .id = prepare_ch, .pos = 0 }}, false, 16 * 1024, 16 * 1024) catch return;
                defer {
                    for (writes) |*poll| poll.deinit(self.allocator);
                    self.allocator.free(writes);
                }
                for (writes) |*write| {
                    if (write.id != prepare_ch or !write.eof) continue;
                    self.manager.closeChannel(run.server_id, prepare_ch) catch {};
                    step.prepare_channel = null;
                    if (write.exit_status != 0) {
                        step.state = .failed;
                        step.@"error" = "configuration write failed";
                        run.status = .failed;
                        run.finished_at_ms = now_ms;
                        self.deploy_history.append(self.io, run, now_ms);
                        return;
                    }
                    step.prepared = true;
                    if (step.id == .install or step.id == .build) {
                        run.env_written = true;
                        if (run.app.runtime.type != .node and run.app.runtime.type != .next) run.zeroSecrets();
                    } else if (step.id == .pm2) {
                        run.zeroSecrets();
                    }
                    break;
                }
                if (!step.prepared) return;
            } else {
                if (deployStartStepFile(self, run, step)) |msg| {
                    step.state = .failed;
                    step.@"error" = msg;
                    run.status = .failed;
                    run.finished_at_ms = now_ms;
                    self.deploy_history.append(self.io, run, now_ms);
                    return;
                }
                if (!step.prepared) return;
            }
        }
        if (step.command.len == 0) {
            step.state = .skipped;
            run.step_index += 1;
            continue;
        }
        const wrapped = if (step.cancel_token != null and step.cancel_ctrl != null)
            deploy.wrapWithProcessGroup(self.allocator, step.command, step.cancel_token.?, step.cancel_ctrl.?) catch step.command
        else
            step.command;
        defer if (wrapped.ptr != step.command.ptr) self.allocator.free(wrapped);
        const channel = self.manager.execTracked(run.server_id, wrapped, "deploy", null, &.{}) catch {
            step.@"error" = "session lost";
            step.state = .failed;
            run.status = .interrupted;
            run.finished_at_ms = now_ms;
            self.deploy_history.append(self.io, run, now_ms);
            return;
        };
        if (run.status == .queued) run.status = .running;
        step.channel = channel;
        step.state = .running;
        return;
    }
    if (run.status != .done) {
        run.status = .done;
        run.finished_at_ms = now_ms;
        self.deploy_history.append(self.io, run, now_ms);
    }
}

const DeployStepDelta = struct {
    data: []u8,
    cursor: u64,
    gap: u64,
    eof: bool,

    fn deinit(self: *DeployStepDelta, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

/// Reads masked retained chunks for one view. The cursor stays in the raw
/// SSH byte space, while each stored chunk is already masked. If a caller
/// supplies a cursor inside a masked chunk, that partial chunk is reported as
/// a gap because raw byte offsets cannot be mapped into the shorter redacted
/// text safely.
fn deployStepDelta(allocator: std.mem.Allocator, step: *const deploy.Step, cursor: u64, budget: usize) !DeployStepDelta {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var next = cursor;
    var gap: u64 = 0;
    if (next < step.output_floor) {
        gap += step.output_floor - next;
        next = step.output_floor;
    }
    for (step.output_chunks.items) |chunk| {
        if (chunk.end <= next) continue;
        if (next > chunk.start) {
            gap += chunk.end - next;
            next = chunk.end;
            continue;
        }
        if (next < chunk.start) {
            gap += chunk.start - next;
            next = chunk.start;
        }
        if (chunk.data.len > budget -| out.items.len) break;
        try out.appendSlice(allocator, chunk.data);
        next = chunk.end;
    }
    return .{
        .data = try out.toOwnedSlice(allocator),
        .cursor = next,
        .gap = gap,
        .eof = step.stream_eof and next >= step.capture_cursor,
    };
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
    defer self.manager.deploys.unlock();

    const now_ms = deployNowMs(self.io);
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
            run.finished_at_ms = now_ms;
            self.deploy_history.append(self.io, run, now_ms);
        } else {
            deployPollStep(self, run, now_ms);
        }
    }

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"run_id\":") catch return output[0..0];
    writer.print("{d}", .{run.id}) catch return output[0..0];
    writer.writeAll(",\"status\":") catch return output[0..0];
    json.writeJsonString(&writer, run.status.jsonName()) catch return output[0..0];
    writer.print(",\"started_at_ms\":{d},\"finished_at_ms\":", .{run.started_at_ms}) catch return output[0..0];
    if (run.finished_at_ms) |finished| writer.print("{d}", .{finished}) catch return output[0..0] else writer.writeAll("null") catch return output[0..0];
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
            var delta = deployStepDelta(self.allocator, step, cursor, budget) catch return output[0..0];
            defer delta.deinit(self.allocator);
            budget = budget -| delta.data.len;
            writer.print(",\"cursor\":{d},\"gap\":{d},\"eof\":{s},\"data\":", .{ delta.cursor, delta.gap, if (delta.eof) "true" else "false" }) catch return output[0..0];
            json.writeJsonString(&writer, delta.data) catch return output[0..0];
        }
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]") catch return output[0..0];
    writer.print(",\"done\":{s}}}", .{if (deployTerminal(run.status)) "true" else "false"}) catch return output[0..0];
    if (deployTerminal(run.status)) run.zeroSecrets();
    self.manager.deploys.evictFinished();
    return writer.buffered();
}

/// Requests cancellation and queues a token-bound process-group verifier.
/// The run stays `cancel_requested` until remote termination is proven.
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
    if (run.status == .done or run.status == .failed or run.status == .canceled or run.status == .interrupted) {
        self.manager.deploys.unlock();
        return ok_json;
    }
    run.status = .cancel_requested;
    const server_id = try self.allocator.dupe(u8, run.server_id);
    defer self.allocator.free(server_id);
    var tok: ?[]u8 = null;
    defer if (tok) |value| self.allocator.free(value);
    var ctrl: ?[]u8 = null;
    defer if (ctrl) |value| self.allocator.free(value);
    var ch: ?u32 = null;
    var preparing = false;
    if (run.currentStep()) |step| {
        step.state = .cancel_requested;
        if (step.cancel_token) |value| tok = self.allocator.dupe(u8, value) catch null;
        if (step.cancel_ctrl) |value| ctrl = self.allocator.dupe(u8, value) catch null;
        ch = step.channel;
        preparing = step.prepare_channel != null;
        if (ch == null and !preparing) {
            run.canceled = true;
            run.status = .canceled;
            step.state = .canceled;
            run.finished_at_ms = deployNowMs(self.io);
            run.zeroSecrets();
            self.deploy_history.append(self.io, run, run.finished_at_ms.?);
        }
    }
    self.manager.deploys.unlock();
    if (ch == null and !preparing) {
        self.audit.append(self.io, "deploy.cancel", server_id, "run canceled before the next step started") catch {};
        return ok_json;
    }
    if (preparing) {
        self.audit.append(self.io, "deploy.cancel", server_id, "cancel requested; waiting for the in-flight configuration write to close") catch {};
        return ok_json;
    }
    // Queue verified termination on the session worker. The poll path keeps
    // `cancel_requested` until this channel proves the exact process group is
    // gone; this handler never waits on the network.
    if (tok != null and ctrl != null) {
        const cmd = deploy.cancelCommand(self.allocator, ctrl.?, tok.?) catch null;
        if (cmd) |c| {
            defer self.allocator.free(c);
            if (self.manager.execTracked(server_id, c, "deploy", null, &.{})) |cancel_ch| {
                self.manager.deploys.lock();
                if (self.manager.deploys.get(parsed.value.run_id)) |rr| {
                    if (rr.currentStep()) |step| step.cancel_channel = cancel_ch;
                }
                self.manager.deploys.unlock();
                self.audit.append(self.io, "deploy.cancel", server_id, "cancel requested; process verification is running") catch {};
                return ok_json;
            } else |_| {}
        }
    }
    self.audit.append(self.io, "deploy.cancel", server_id, "cancel requested; termination could not be started") catch {};
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

/// The shared read/parse/guard/rewrite/write path used by spec 09 access
/// jobs (spec 08 mutations run through the keyjobs drivers instead).
/// Returns the rewritten content on success; `msg` carries a static or
/// `write_err_buf`-backed reason otherwise.
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

const sshkeys_disabled_password_hash = "$6$oars-disabled$lpNdEPf3.DwtukqfRj4YY0/dfZbbT9NpQRWqiqapBqjNgUKbnotVRGvSJ9sJaEd7f2wrX4L.NTvtpFwcRj21ws";

fn sshkeysRoleCreateCommand(buffer: []u8, name: []const u8) ![]const u8 {
    // useradd's lock marker also blocks public-key authentication on some sshd
    // configurations. A valid SHA-512-crypt-shaped value with no known
    // preimage keeps the account unlocked without enabling password login.
    return std.fmt.bufPrint(buffer, "useradd -m -s /bin/bash {s} && usermod -p '{s}' {s}", .{ name, sshkeys_disabled_password_hash, name });
}

/// Creates (or verifies) a role user for spec 09 access onboard jobs:
/// root check, capability-detected forced command for read-only roles,
/// an unlocked account with password login disabled, per-user 0700/0600 SSH
/// setup, and the roles marker update. Idempotent: an existing matching role
/// verifies the user and returns null. Spec 08 role management runs through
/// the plan/commit job drivers instead.
fn sshkeysRoleEnsureCore(self: *Context, server_id: []const u8, name: []const u8, read_only: bool) ?[]const u8 {
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

    var useradd_buf: [320]u8 = undefined;
    const useradd_cmd = sshkeysRoleCreateCommand(&useradd_buf, name) catch return "invalid role name";
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

    roles.append(self.allocator, .{
        .name = self.allocator.dupe(u8, name) catch return "out of memory",
        .read_only = read_only,
        .forced_command = self.allocator.dupe(u8, forced_command) catch return "out of memory",
    }) catch return "out of memory";
    if (!sshkeysRolesSave(self, server_id, &roles)) return "failed to save the roles marker";
    return null;
}

// --- ssh key management (spec 08, worker-driven) -----------------------------
//
// Every SSH/SFTP step below runs on the keyjobs coordinator thread (or the
// local job worker for ssh-keygen); bridge handlers only validate, freeze a
// bounded request into a snapshot/job record, register it, and serialize
// locked state. Poll calls never advance an operation (specs README).

const keys_exec_cap: usize = 256 * 1024;
const keys_exec_timeout_ns = 15 * std.time.ns_per_s;
const keys_sftp_wait_ns = 25 * std.time.ns_per_s;
const keys_verify_wait_ns = 20 * std.time.ns_per_s;
const keys_max_id_text: usize = 128;
const keys_max_path_text: usize = 4096;
const keys_max_comment_text: usize = 256;
const keys_max_key_text: usize = sshkeys.max_key_line_bytes;
const keys_max_passphrase_text: usize = 1024;
const deploy_manifest_file = "oars_deploy_keys.json";
const deploy_key_prefix = "oars_deploy_";

const KeysInspectPayload = struct { public_key: []const u8, comment: ?[]const u8 = null };
const KeysAccountPayload = struct { kind: []const u8, name: ?[]const u8 = null };
const KeysSnapshotPayload = struct { server_id: []const u8, account: KeysAccountPayload };
const KeysSnapshotIdPayload = struct { snapshot_id: []const u8 };
const KeysJobIdPayload = struct { job_id: []const u8 };
const KeysAddPayload = struct {
    operation_id: []const u8,
    snapshot_id: []const u8,
    source_path: []const u8,
    file_sha256: []const u8,
    public_key: []const u8,
    comment: ?[]const u8 = null,
};
const KeysRevokePayload = struct {
    operation_id: []const u8,
    snapshot_id: []const u8,
    source_path: []const u8,
    file_sha256: []const u8,
    fingerprint: []const u8,
    line_hash: []const u8,
    confirm_fingerprint: ?[]const u8 = null,
};
const KeysRotatePayload = struct {
    operation_id: []const u8,
    snapshot_id: []const u8,
    source_path: []const u8,
    file_sha256: []const u8,
    old_fingerprint: []const u8,
    line_hash: []const u8,
    new_public_key: []const u8,
};
/// Flattened union (the frontend sends `{kind, ...}`): dispatch on `kind`.
const KeysVerificationPayload = struct {
    kind: []const u8,
    path: ?[]const u8 = null,
    passphrase: ?[]const u8 = null,
    confirm_fingerprint: ?[]const u8 = null,
};
const KeysRotateCommitPayload = struct { job_id: []const u8, verification: KeysVerificationPayload };
const KeysLocalGeneratePayload = struct {
    operation_id: []const u8,
    destination: []const u8,
    comment: ?[]const u8 = null,
    passphrase: ?[]const u8 = null,
};
const KeysRolesPlanPayload = struct {
    server_id: []const u8,
    name: []const u8,
    kind: []const u8,
    action: []const u8,
};
const KeysRolesCommitPayload = struct {
    operation_id: []const u8,
    plan_id: []const u8,
    public_key: ?[]const u8 = null,
};
const KeysDeployGeneratePayload = struct {
    operation_id: []const u8,
    server_id: []const u8,
    repository_label: []const u8,
    comment: ?[]const u8 = null,
};
const KeysDeployDeletePayload = struct {
    operation_id: []const u8,
    server_id: []const u8,
    deploy_key_id: []const u8,
    confirm_fingerprint: []const u8,
};

fn keysValidId(text: []const u8) bool {
    return text.len > 0 and text.len <= keys_max_id_text;
}

fn keysValidHash(text: []const u8) bool {
    if (text.len != 64) return false;
    for (text) |ch| {
        if (!std.ascii.isHex(ch)) return false;
    }
    return true;
}

fn keysValidFingerprint(text: []const u8) bool {
    return std.mem.startsWith(u8, text, "SHA256:") and text.len > 7 and text.len <= 128;
}

fn keysValidPath(text: []const u8) bool {
    return text.len > 0 and text.len <= keys_max_path_text and
        std.mem.indexOfAny(u8, text, "\r\n") == null;
}

fn keysEnsureStarted(self: *Context) void {
    self.keys.ensureStarted(self.io, .{
        .context = self,
        .drive_snapshot = keysDriveSnapshot,
        .drive_job = keysDriveJob,
        .drive_local_job = keysDriveLocalJob,
    });
}

fn keysNowMs(self: *Context) i64 {
    return @intCast(@divTrunc(std.Io.Timestamp.now(self.io, .real).nanoseconds, std.time.ns_per_ms));
}

// --- serializers (fixed writer; overflow fails the response) ---------------

fn keysWriteSource(writer: *std.Io.Writer, source: *const keyjobs.Source) !void {
    try writer.writeAll("{\"path\":");
    try json.writeJsonString(writer, source.path);
    try writer.writeAll(",\"kind\":");
    try json.writeJsonString(writer, source.kind);
    try writer.writeAll(",\"status\":");
    try json.writeJsonString(writer, source.status.jsonName());
    if (source.file_sha256) |hash| {
        try writer.writeAll(",\"file_sha256\":");
        try json.writeJsonString(writer, hash);
    }
    if (source.mode) |mode| {
        try writer.print(",\"mode\":{d}", .{mode});
    }
    if (source.owner) |owner| {
        try writer.writeAll(",\"owner\":");
        try json.writeJsonString(writer, owner);
    }
    if (source.@"error") |err| {
        try writer.writeAll(",\"error\":");
        try json.writeJsonString(writer, err);
    }
    try writer.writeAll("}");
}

fn keysWriteKeyEntry(writer: *std.Io.Writer, key: *const keyjobs.KeyEntry) !void {
    try writer.writeAll("{\"source_path\":");
    try json.writeJsonString(writer, key.source_path);
    try writer.print(",\"line_index\":{d}", .{key.line_index});
    try writer.writeAll(",\"line_hash\":");
    try json.writeJsonString(writer, key.line_hash);
    try writer.print(",\"parsed\":{s}", .{if (key.parsed) "true" else "false"});
    if (key.options.len > 0) {
        try writer.writeAll(",\"options\":");
        try json.writeJsonString(writer, key.options);
    }
    if (key.key_type.len > 0) {
        try writer.writeAll(",\"type\":");
        try json.writeJsonString(writer, key.key_type);
    }
    if (key.key.len > 0) {
        try writer.writeAll(",\"key\":");
        try json.writeJsonString(writer, key.key);
    }
    if (key.comment.len > 0) {
        try writer.writeAll(",\"comment\":");
        try json.writeJsonString(writer, key.comment);
    }
    if (key.fingerprint_sha256.len > 0) {
        try writer.writeAll(",\"fingerprint_sha256\":");
        try json.writeJsonString(writer, key.fingerprint_sha256);
    }
    if (key.bits) |bits| {
        try writer.print(",\"bits\":{d}", .{bits});
    }
    if (key.raw.len > 0) {
        try writer.writeAll(",\"raw\":");
        try json.writeJsonString(writer, key.raw);
    }
    if (key.@"error".len > 0) {
        try writer.writeAll(",\"error\":");
        try json.writeJsonString(writer, key.@"error");
    }
    if (key.policy_level.len > 0) {
        try writer.writeAll(",\"policy_assessment\":{\"level\":");
        try json.writeJsonString(writer, key.policy_level);
        try writer.writeAll(",\"detail\":");
        try json.writeJsonString(writer, key.policy_detail);
        try writer.writeAll("}");
    }
    try writer.writeAll("}");
}

fn keysWriteRoleEntry(writer: *std.Io.Writer, role: *const keyjobs.RoleEntry) !void {
    try writer.writeAll("{\"name\":");
    try json.writeJsonString(writer, role.name);
    try writer.writeAll(",\"kind\":");
    try json.writeJsonString(writer, role.kind);
    if (role.home) |home| {
        try writer.writeAll(",\"home\":");
        try json.writeJsonString(writer, home);
    }
    if (role.shell) |shell| {
        try writer.writeAll(",\"shell\":");
        try json.writeJsonString(writer, shell);
    }
    try writer.writeAll(",\"policy_state\":");
    try json.writeJsonString(writer, role.policy_state.jsonName());
    try writer.writeAll(",\"key_fingerprints\":[");
    for (role.key_fingerprints, 0..) |fp, i| {
        if (i > 0) try writer.writeAll(",");
        try json.writeJsonString(writer, fp);
    }
    try writer.writeAll("]}");
}

fn keysWriteDeployKeyEntry(writer: *std.Io.Writer, entry: *const keyjobs.DeployKeyEntry) !void {
    try writer.writeAll("{\"deploy_key_id\":");
    try json.writeJsonString(writer, entry.id);
    try writer.writeAll(",\"repository_label\":");
    try json.writeJsonString(writer, entry.repository_label);
    try writer.writeAll(",\"path\":");
    try json.writeJsonString(writer, entry.path);
    try writer.writeAll(",\"fingerprint\":");
    try json.writeJsonString(writer, entry.fingerprint);
    if (entry.created_at_ms != 0) {
        try writer.print(",\"created_at_ms\":{d}", .{entry.created_at_ms});
    }
    try writer.writeAll("}");
}

fn keysPrivilegeJson(privilege: []const u8) []const u8 {
    if (std.mem.eql(u8, privilege, "root")) return "root";
    if (std.mem.eql(u8, privilege, "sudo_n")) return "sudo_n";
    return "none";
}

/// The snapshot poll response body. The caller holds the registry lock,
/// so a driver never mutates a field mid-read.
fn keysSnapshotPollWrite(self: *Context, writer: *std.Io.Writer, snap: *keyjobs.Snapshot) !void {
    _ = self;
    try writer.writeAll("{\"ok\":true,\"state\":");
    try json.writeJsonString(writer, snap.state.jsonName());
    try writer.writeAll(",\"server_id\":");
    try json.writeJsonString(writer, snap.server_id);
    try writer.writeAll(",\"account\":{\"kind\":");
    try json.writeJsonString(writer, if (snap.account_kind == .managed_role) "managed_role" else "connected");
    if (snap.account_name) |name| {
        try writer.writeAll(",\"name\":");
        try json.writeJsonString(writer, name);
    }
    try writer.writeAll("}");
    try writer.writeAll(",\"scope\":");
    try json.writeJsonString(writer, snap.scope);
    try writer.print(",\"created_at_ms\":{d}", .{@divTrunc(snap.created_at_ns, std.time.ns_per_ms)});
    if (snap.finished_at_ns) |finished| {
        try writer.print(",\"finished_at_ms\":{d}", .{@divTrunc(finished, std.time.ns_per_ms)});
    }
    try writer.writeAll(",\"coverage\":");
    try json.writeJsonString(writer, if (snap.coverage.len > 0) snap.coverage else "partial");
    try writer.writeAll(",\"capabilities\":{\"privilege\":");
    try json.writeJsonString(writer, keysPrivilegeJson(snap.privilege));
    try writer.print(",\"sftp_read_only\":{s}}}", .{if (snap.sftp_read_only) "true" else "false"});
    try writer.writeAll(",\"sources\":[");
    for (snap.sources.items, 0..) |*source, i| {
        if (i > 0) try writer.writeAll(",");
        try keysWriteSource(writer, source);
    }
    try writer.writeAll("],\"keys\":[");
    for (snap.keys.items, 0..) |*key, i| {
        if (i > 0) try writer.writeAll(",");
        try keysWriteKeyEntry(writer, key);
    }
    try writer.writeAll("],\"roles\":[");
    for (snap.roles.items, 0..) |*role, i| {
        if (i > 0) try writer.writeAll(",");
        try keysWriteRoleEntry(writer, role);
    }
    try writer.writeAll("],\"deploy_keys\":[");
    for (snap.deploy_keys.items, 0..) |*entry, i| {
        if (i > 0) try writer.writeAll(",");
        try keysWriteDeployKeyEntry(writer, entry);
    }
    try writer.writeAll("],\"warnings\":[");
    for (snap.warnings.items, 0..) |warning, i| {
        if (i > 0) try writer.writeAll(",");
        try json.writeJsonString(writer, warning);
    }
    try writer.writeAll("]}");
}

/// The job poll response body. The caller holds the registry lock.
fn keysJobPollWrite(self: *Context, writer: *std.Io.Writer, job: *keyjobs.Job) !void {
    _ = self;
    try writer.writeAll("{\"ok\":true,\"state\":");
    try json.writeJsonString(writer, job.state.jsonName());
    try writer.writeAll(",\"steps\":[");
    for (job.steps, 0..) |*step, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("{\"id\":");
        try json.writeJsonString(writer, step.id);
        try writer.writeAll(",\"state\":");
        try json.writeJsonString(writer, step.state.jsonName());
        if (step.@"error") |err| {
            try writer.writeAll(",\"error\":");
            try json.writeJsonString(writer, err);
        }
        try writer.writeAll("}");
    }
    try writer.writeAll("]");
    if (job.result_json) |result| {
        // Built by the driver from already-escaped values; never carries
        // secrets (passphrases are excluded at construction).
        try writer.writeAll(",\"result\":");
        try writer.writeAll(result);
    }
    try writer.writeAll("}");
}

// --- remote helpers (coordinator thread: bounded blocking is fine here) -----

fn keysExec(self: *Context, server_id: []const u8, cmd: []const u8) ?sessions.ExecOutcome {
    return self.manager.execWaitTracked(server_id, cmd, "sshkeys", null, &.{}, keys_exec_cap, keys_exec_timeout_ns) catch null;
}

fn keysSessionReady(self: *Context, server_id: []const u8) bool {
    const session = self.manager.get(server_id) orelse return false;
    return session.status.load(.acquire) == .ready;
}

/// Bounded wait on one SFTP outcome. Returns false when the wait timed
/// out and the op kept the outcome (its eventual set frees it); the
/// caller must not touch the outcome after false.
fn keysSftpWait(self: *Context, outcome: *sessions.SftpOutcome) bool {
    const deadline = std.Io.Timestamp.now(self.io, .real).nanoseconds + keys_sftp_wait_ns;
    outcome.wait(self.io, deadline);
    if (outcome.isDone()) return true;
    return outcome.abandon(); // true: completed in the race window
}

const KeysReadStatus = enum { readable, missing, denied, timeout, too_large, transport_error };

const KeysReadResult = struct {
    status: KeysReadStatus,
    /// Owned content; set only for `.readable`.
    content: ?[]u8 = null,
    detail_buf: [256]u8 = undefined,
    detail_len: usize = 0,

    fn detail(self: *const KeysReadResult) []const u8 {
        return self.detail_buf[0..self.detail_len];
    }

    fn withDetail(self: *KeysReadResult, msg: []const u8) KeysReadResult {
        const n = @min(msg.len, self.detail_buf.len);
        @memcpy(self.detail_buf[0..n], msg[0..n]);
        self.detail_len = n;
        return self.*;
    }
};

fn keysSourceStatus(status: KeysReadStatus) keyjobs.SourceStatus {
    return switch (status) {
        .readable => .readable,
        .missing => .missing,
        .denied => .denied,
        .timeout => .timeout,
        .too_large => .too_large,
        .transport_error => .transport_error,
    };
}

/// Typed SFTP read of one source file: missing, denied, timeout,
/// too_large, and transport failures stay distinct so a read failure can
/// never look like an empty file (spec 08 corrected contract).
fn keysReadTyped(self: *Context, server_id: []const u8, path: []const u8, max_bytes: usize) KeysReadResult {
    const stat_out = self.allocator.create(sessions.SftpOutcome) catch return .{ .status = .transport_error };
    stat_out.* = .{ .allocator = self.allocator };
    self.manager.sftpStat(server_id, path, stat_out) catch {
        self.allocator.destroy(stat_out);
        var result = KeysReadResult{ .status = .transport_error };
        return result.withDetail("not connected");
    };
    if (!keysSftpWait(self, stat_out)) return .{ .status = .timeout };
    defer self.allocator.destroy(stat_out);
    defer if (stat_out.json) |j| self.allocator.free(j);
    if (!stat_out.ok) {
        var result = KeysReadResult{ .status = switch (stat_out.fx) {
            ssh.c.LIBSSH2_FX_NO_SUCH_FILE => .missing,
            ssh.c.LIBSSH2_FX_PERMISSION_DENIED => .denied,
            else => .transport_error,
        } };
        return result.withDetail(stat_out.message());
    }

    var content: std.ArrayList(u8) = .empty;
    defer content.deinit(self.allocator);
    var offset: u64 = 0;
    while (true) {
        const read_out = self.allocator.create(sessions.SftpOutcome) catch return .{ .status = .transport_error };
        read_out.* = .{ .allocator = self.allocator };
        self.manager.sftpRead(server_id, path, offset, sshkeys_read_chunk, read_out) catch {
            self.allocator.destroy(read_out);
            return .{ .status = .transport_error };
        };
        if (!keysSftpWait(self, read_out)) return .{ .status = .timeout };
        defer self.allocator.destroy(read_out);
        defer if (read_out.json) |j| self.allocator.free(j);
        if (!read_out.ok) {
            var result = KeysReadResult{ .status = switch (read_out.fx) {
                ssh.c.LIBSSH2_FX_NO_SUCH_FILE => .missing,
                ssh.c.LIBSSH2_FX_PERMISSION_DENIED => .denied,
                else => .transport_error,
            } };
            return result.withDetail(read_out.message());
        }
        const payload = read_out.json orelse return .{ .status = .transport_error };
        const parsed = std.json.parseFromSlice(struct {
            ok: bool,
            base64: []const u8 = "",
            eof: bool = false,
        }, self.allocator, payload, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch return .{ .status = .transport_error };
        defer parsed.deinit();
        if (!parsed.value.ok) return .{ .status = .transport_error };
        const size = std.base64.standard.Decoder.calcSizeForSlice(parsed.value.base64) catch return .{ .status = .transport_error };
        if (content.items.len + size > max_bytes) return .{ .status = .too_large };
        const decoded = self.allocator.alloc(u8, size) catch return .{ .status = .transport_error };
        defer self.allocator.free(decoded);
        std.base64.standard.Decoder.decode(decoded, parsed.value.base64) catch return .{ .status = .transport_error };
        content.appendSlice(self.allocator, decoded) catch return .{ .status = .transport_error };
        offset += decoded.len;
        if (parsed.value.eof) break;
    }
    return .{ .status = .readable, .content = content.toOwnedSlice(self.allocator) catch null };
}

/// Typed read through `sudo -n` for files the connected account cannot
/// open (role homes, the root-owned roles manifest).
fn keysPrivilegedRead(self: *Context, server_id: []const u8, path: []const u8, max_bytes: usize) KeysReadResult {
    const quoted = shellquote.quote(self.allocator, path) catch return .{ .status = .transport_error };
    defer self.allocator.free(quoted);
    const stat_cmd = std.fmt.allocPrint(self.allocator, "sudo -n stat -c '%a' {s} 2>&1", .{quoted}) catch return .{ .status = .transport_error };
    defer self.allocator.free(stat_cmd);
    var stat_check = self.manager.execWait(server_id, stat_cmd, keys_exec_cap, keys_exec_timeout_ns) catch {
        return .{ .status = .transport_error, .detail_len = 0 };
    };
    defer stat_check.output.deinit(self.allocator);
    if (stat_check.exit != 0) {
        const text = stat_check.output.items;
        if (std.mem.indexOf(u8, text, "No such file") != null) return .{ .status = .missing };
        var result = KeysReadResult{ .status = .denied };
        const trimmed = std.mem.trim(u8, text, " \t\r\n");
        return result.withDetail(if (trimmed.len > 0) trimmed else "sudo -n stat failed");
    }
    const cat_cmd = std.fmt.allocPrint(self.allocator, "sudo -n cat {s}", .{quoted}) catch return .{ .status = .transport_error };
    defer self.allocator.free(cat_cmd);
    var read = self.manager.execWait(server_id, cat_cmd, max_bytes + 1, keys_exec_timeout_ns) catch {
        return .{ .status = .transport_error };
    };
    defer read.output.deinit(self.allocator);
    if (read.output.items.len > max_bytes or read.limited) return .{ .status = .too_large };
    if (read.exit != 0) {
        const text = std.mem.trim(u8, read.output.items, " \t\r\n");
        if (std.mem.indexOf(u8, text, "No such file") != null) return .{ .status = .missing };
        var result = KeysReadResult{ .status = .denied };
        return result.withDetail(if (text.len > 0) text else "sudo -n cat failed");
    }
    return .{ .status = .readable, .content = self.allocator.dupe(u8, read.output.items) catch null };
}

const KeysStatMeta = struct {
    mode: ?u32 = null,
    owner: ?[]u8 = null, // owned
};

/// Mode and owner from `stat -c '%a|%U'` (busybox-compatible); null
/// fields when the probe fails. Metadata is informational only.
fn keysStatMeta(self: *Context, server_id: []const u8, path: []const u8, privileged: bool) KeysStatMeta {
    const quoted = shellquote.quote(self.allocator, path) catch return .{};
    defer self.allocator.free(quoted);
    const cmd = std.fmt.allocPrint(self.allocator, "{s}stat -c '%a|%U' {s}", .{ if (privileged) "sudo -n " else "", quoted }) catch return .{};
    defer self.allocator.free(cmd);
    var check = self.manager.execWait(server_id, cmd, keys_exec_cap, keys_exec_timeout_ns) catch return .{};
    defer check.output.deinit(self.allocator);
    if (check.exit != 0) return .{};
    const text = std.mem.trim(u8, check.output.items, " \t\r\n");
    const split = std.mem.indexOfScalar(u8, text, '|') orelse return .{};
    var meta = KeysStatMeta{};
    meta.mode = std.fmt.parseInt(u32, text[0..split], 8) catch null;
    if (split + 1 < text.len) meta.owner = self.allocator.dupe(u8, text[split + 1 ..]) catch null;
    return meta;
}

/// The one atomic writer for spec 08 (and the base spec 09 helpers):
const KeysWriteGuard = union(enum) {
    unguarded,
    missing,
    sha256: []const u8,
};

/// sftpSave stages beside the destination with the frozen whole-file
/// identity as its guard, posix-renames, then this wrapper repairs
/// mode/owner and re-reads so the returned hash is what the server
/// actually holds. The worker hashes up to the authorized_keys 4 MiB cap and
/// distinguishes an absent source from an existing empty file.
fn keysWriteAtomic(
    self: *Context,
    server_id: []const u8,
    path: []const u8,
    content: []const u8,
    guard: KeysWriteGuard,
    mode: ?u32,
    owner: ?[]const u8,
    err_buf: []u8,
    out_hash: *?[]u8,
) ?[]const u8 {
    out_hash.* = null;
    const out = self.allocator.create(sessions.SftpOutcome) catch return "out of memory";
    out.* = .{ .allocator = self.allocator };
    const expected: ?sessions.SftpExpectedIdentity = switch (guard) {
        .unguarded => null,
        .missing => .{ .missing = true, .max_hash_bytes = sshkeys.max_keys_file_bytes },
        .sha256 => |sha| .{ .sha256 = sha, .max_hash_bytes = sshkeys.max_keys_file_bytes },
    };
    self.manager.sftpSave(server_id, path, content, expected, out) catch |err| {
        self.allocator.destroy(out);
        return switch (err) {
            error.NoSession => "not connected",
            error.NotReady => "session not ready",
            else => "failed to queue the write",
        };
    };
    if (!keysSftpWait(self, out)) return "timed out writing the file";
    defer self.allocator.destroy(out);
    defer if (out.json) |j| self.allocator.free(j);
    if (!out.ok) return std.fmt.bufPrint(err_buf, "{s}", .{out.message()}) catch "failed to write the file";
    if (mode) |m| {
        const chmod_out = self.allocator.create(sessions.SftpOutcome) catch return "out of memory";
        chmod_out.* = .{ .allocator = self.allocator };
        self.manager.sftpChmod(server_id, path, m, chmod_out) catch {
            self.allocator.destroy(chmod_out);
            return "failed to set file permissions";
        };
        if (!keysSftpWait(self, chmod_out)) return "failed to set file permissions";
        defer self.allocator.destroy(chmod_out);
        defer if (chmod_out.json) |j| self.allocator.free(j);
        if (!chmod_out.ok) return "failed to set file permissions";
    }
    if (owner) |o| {
        const quoted_owner = shellquote.quote(self.allocator, o) catch return "out of memory";
        defer self.allocator.free(quoted_owner);
        const quoted_path = shellquote.quote(self.allocator, path) catch return "out of memory";
        defer self.allocator.free(quoted_path);
        const cmd = std.fmt.allocPrint(self.allocator, "chown {s} {s}", .{ quoted_owner, quoted_path }) catch return "out of memory";
        defer self.allocator.free(cmd);
        var check = keysExec(self, server_id, cmd) orelse return "failed to set file ownership";
        defer check.output.deinit(self.allocator);
        if (check.exit != 0) return "failed to set file ownership";
    }
    // Re-read: the returned hash describes the file the server holds.
    const read = keysReadTyped(self, server_id, path, sshkeys.max_keys_file_bytes + 1);
    if (read.status != .readable) return "the write could not be verified; refresh the snapshot";
    const reread = read.content.?;
    defer self.allocator.free(reread);
    if (!std.mem.eql(u8, reread, content)) return "the file changed during the write; refresh and review again";
    out_hash.* = sshkeys.fileSha256(self.allocator, reread) catch return "out of memory";
    return null;
}

/// Atomic privileged write through `sudo -n sh -c`: stage beside the
/// destination, set owner/mode, `mv -f` (rename is atomic on one
/// filesystem). The content travels on stdin, never in argv.
fn keysPrivilegedWrite(self: *Context, server_id: []const u8, path: []const u8, content: []const u8, guard: KeysWriteGuard, mode: u32, owner: ?[]const u8, err_buf: []u8) ?[]const u8 {
    const quoted_path = shellquote.quote(self.allocator, path) catch return "out of memory";
    defer self.allocator.free(quoted_path);
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(self.allocator);
    script.appendSlice(self.allocator, "set -e; umask 077; d=$(dirname ") catch return "out of memory";
    script.appendSlice(self.allocator, quoted_path) catch return "out of memory";
    script.appendSlice(self.allocator, "); t=$(mktemp \"$d/.oars-write.XXXXXX\"); trap 'rm -f \"$t\"' EXIT HUP INT TERM; cat > \"$t\"; chmod ") catch return "out of memory";
    var mode_buf: [8]u8 = undefined;
    const mode_text = std.fmt.bufPrint(&mode_buf, "{o}", .{mode}) catch return "out of memory";
    script.appendSlice(self.allocator, mode_text) catch return "out of memory";
    script.appendSlice(self.allocator, " \"$t\"; ") catch return "out of memory";
    if (owner) |o| {
        const quoted_owner = shellquote.quote(self.allocator, o) catch return "out of memory";
        defer self.allocator.free(quoted_owner);
        script.appendSlice(self.allocator, "chown ") catch return "out of memory";
        script.appendSlice(self.allocator, quoted_owner) catch return "out of memory";
        script.appendSlice(self.allocator, " \"$t\"; ") catch return "out of memory";
    }
    switch (guard) {
        .unguarded => {},
        .missing => {
            script.appendSlice(self.allocator, "if [ -e ") catch return "out of memory";
            script.appendSlice(self.allocator, quoted_path) catch return "out of memory";
            script.appendSlice(self.allocator, " ]; then exit 73; fi; ") catch return "out of memory";
        },
        .sha256 => |sha| {
            const quoted_sha = shellquote.quote(self.allocator, sha) catch return "out of memory";
            defer self.allocator.free(quoted_sha);
            script.appendSlice(self.allocator, "a=$(sha256sum ") catch return "out of memory";
            script.appendSlice(self.allocator, quoted_path) catch return "out of memory";
            script.appendSlice(self.allocator, " 2>/dev/null) || exit 73; [ \"${a%% *}\" = ") catch return "out of memory";
            script.appendSlice(self.allocator, quoted_sha) catch return "out of memory";
            script.appendSlice(self.allocator, " ] || exit 73; ") catch return "out of memory";
        },
    }
    script.appendSlice(self.allocator, "mv -f \"$t\" ") catch return "out of memory";
    script.appendSlice(self.allocator, quoted_path) catch return "out of memory";
    script.appendSlice(self.allocator, "; trap - EXIT HUP INT TERM") catch return "out of memory";
    const quoted_script = shellquote.quote(self.allocator, script.items) catch return "out of memory";
    defer self.allocator.free(quoted_script);
    const cmd = std.fmt.allocPrint(self.allocator, "sudo -n sh -c {s}", .{quoted_script}) catch return "out of memory";
    defer self.allocator.free(cmd);
    var check = self.manager.execWaitTrackedWithInput(server_id, cmd, content, "sshkeys", null, &.{}, keys_exec_cap, keys_exec_timeout_ns) catch {
        return "not connected";
    };
    defer check.output.deinit(self.allocator);
    if (check.exit != 0) {
        if (check.exit == 73) return "conflict: the source changed after it was reviewed; refresh and review again";
        const text = std.mem.trim(u8, check.output.items, " \t\r\n");
        return std.fmt.bufPrint(err_buf, "privileged write failed: {s}", .{text[0..@min(text.len, 120)]}) catch "privileged write failed";
    }
    return null;
}

/// Creates `<dir>` with 0700 owned by `owner` through the available
/// privilege path (role homes).
fn keysPrivilegedEnsureDir(self: *Context, server_id: []const u8, dir: []const u8, owner: []const u8, privilege: KeysPrivilege) ?[]const u8 {
    const quoted_dir = shellquote.quote(self.allocator, dir) catch return "out of memory";
    defer self.allocator.free(quoted_dir);
    const quoted_owner = shellquote.quote(self.allocator, owner) catch return "out of memory";
    defer self.allocator.free(quoted_owner);
    const script = std.fmt.allocPrint(self.allocator, "mkdir -p {s} && chmod 700 {s} && chown {s} {s}", .{ quoted_dir, quoted_dir, quoted_owner, quoted_dir }) catch return "out of memory";
    defer self.allocator.free(script);
    const cmd = if (privilege == .sudo_n) blk: {
        const quoted_script = shellquote.quote(self.allocator, script) catch return "out of memory";
        defer self.allocator.free(quoted_script);
        break :blk std.fmt.allocPrint(self.allocator, "sudo -n sh -c {s}", .{quoted_script}) catch return "out of memory";
    } else script_blk: {
        break :script_blk self.allocator.dupe(u8, script) catch return "out of memory";
    };
    defer self.allocator.free(cmd);
    var check = keysExec(self, server_id, cmd) orelse return "not connected";
    defer check.output.deinit(self.allocator);
    if (check.exit != 0) return "failed to create the ssh directory";
    return null;
}

const KeysAccountFacts = struct {
    user: []u8,
    uid: ?u32,
    home: []u8,
    shell: []u8,

    fn deinit(self: *KeysAccountFacts, allocator: std.mem.Allocator) void {
        allocator.free(self.user);
        allocator.free(self.home);
        allocator.free(self.shell);
    }
};

/// passwd facts for the connected login or a named account, via
/// `getent passwd` (busybox-compatible). Null when the account or the
/// session is unavailable.
fn keysAccountFacts(self: *Context, server_id: []const u8, account_name: ?[]const u8) ?KeysAccountFacts {
    if (!keysSessionReady(self, server_id)) return null;
    const user = if (account_name) |name|
        self.allocator.dupe(u8, name) catch return null
    else blk: {
        const session = self.manager.get(server_id) orelse return null;
        break :blk self.allocator.dupe(u8, session.server.user) catch return null;
    };
    var user_transferred = false;
    defer if (!user_transferred) self.allocator.free(user);
    const quoted = shellquote.quote(self.allocator, user) catch return null;
    defer self.allocator.free(quoted);
    const cmd = std.fmt.allocPrint(self.allocator, "getent passwd {s}", .{quoted}) catch return null;
    defer self.allocator.free(cmd);
    var check = keysExec(self, server_id, cmd) orelse return null;
    defer check.output.deinit(self.allocator);
    if (check.exit != 0) return null;
    // name:x:uid:gid:gecos:home:shell — home is second-to-last even
    // when gecos contains colons.
    var tokens = std.mem.splitScalar(u8, std.mem.trim(u8, check.output.items, " \t\r\n"), ':');
    var all: [16][]const u8 = undefined;
    var n: usize = 0;
    while (tokens.next()) |t| {
        if (n >= all.len) return null;
        all[n] = t;
        n += 1;
    }
    if (n < 4) return null;
    const home = all[n - 2];
    if (home.len == 0 or home[0] != '/') return null;
    const home_copy = self.allocator.dupe(u8, home) catch return null;
    const shell_copy = self.allocator.dupe(u8, all[n - 1]) catch {
        self.allocator.free(home_copy);
        return null;
    };
    user_transferred = true;
    return .{
        .user = user,
        .uid = std.fmt.parseInt(u32, all[2], 10) catch null,
        .home = home_copy,
        .shell = shell_copy,
    };
}

const KeysPrivilege = enum { root, sudo_n, none };

fn keysPrivilegeName(privilege: KeysPrivilege) []const u8 {
    return switch (privilege) {
        .root => "root",
        .sudo_n => "sudo_n",
        .none => "none",
    };
}

fn keysProbePrivilege(self: *Context, server_id: []const u8) KeysPrivilege {
    var id_check = keysExec(self, server_id, "id -u") orelse return .none;
    defer id_check.output.deinit(self.allocator);
    if (id_check.exit == 0 and std.mem.eql(u8, std.mem.trim(u8, id_check.output.items, " \t\r\n"), "0")) return .root;
    var sudo_check = keysExec(self, server_id, "sudo -n true") orelse return .none;
    defer sudo_check.output.deinit(self.allocator);
    if (sudo_check.exit == 0) return .sudo_n;
    return .none;
}

const KeysConnTuple = struct {
    client_addr: []u8,
    local_addr: []u8,
    local_port: []u8,
    host: []u8,
    valid: bool,

    fn deinit(self: *KeysConnTuple, allocator: std.mem.Allocator) void {
        allocator.free(self.client_addr);
        allocator.free(self.local_addr);
        allocator.free(self.local_port);
        allocator.free(self.host);
    }
};

/// The live connection tuple used as `sshd -T -C` criteria (the same
/// probe as the spec 09 scan). Invalid when SSH_CONNECTION/hostname
/// could not be read; callers fall back to the conventional source and
/// mark the view partial.
fn keysConnectionTuple(self: *Context, server_id: []const u8) KeysConnTuple {
    var check = keysExec(self, server_id, "printf '%s\\n%s\\n' \"$SSH_CONNECTION\" \"$(hostname -f 2>/dev/null || hostname)\"") orelse return keysInvalidTuple(self);
    defer check.output.deinit(self.allocator);
    var lines = std.mem.splitScalar(u8, check.output.items, '\n');
    const tuple = std.mem.trim(u8, lines.next() orelse "", " \t\r");
    const host = std.mem.trim(u8, lines.next() orelse "", " \t\r");
    var fields = std.mem.tokenizeAny(u8, tuple, " \t");
    const client_addr = fields.next() orelse return keysInvalidTuple(self);
    _ = fields.next(); // client port is not an sshd -C criterion
    const local_addr = fields.next() orelse return keysInvalidTuple(self);
    const local_port = fields.next() orelse return keysInvalidTuple(self);
    if (host.len == 0) return keysInvalidTuple(self);
    var result = KeysConnTuple{
        .client_addr = self.allocator.dupe(u8, client_addr) catch return keysInvalidTuple(self),
        .local_addr = @constCast(""),
        .local_port = @constCast(""),
        .host = @constCast(""),
        .valid = true,
    };
    errdefer result.deinit(self.allocator);
    result.local_addr = self.allocator.dupe(u8, local_addr) catch return keysInvalidTuple(self);
    result.local_port = self.allocator.dupe(u8, local_port) catch return keysInvalidTuple(self);
    result.host = self.allocator.dupe(u8, host) catch return keysInvalidTuple(self);
    return result;
}

fn keysInvalidTuple(self: *Context) KeysConnTuple {
    return .{
        .client_addr = self.allocator.dupe(u8, "127.0.0.1") catch @constCast(""),
        .local_addr = self.allocator.dupe(u8, "127.0.0.1") catch @constCast(""),
        .local_port = self.allocator.dupe(u8, "22") catch @constCast(""),
        .host = self.allocator.dupe(u8, "localhost") catch @constCast(""),
        .valid = false,
    };
}

/// `sshd -T -C` through the available privilege path. Null when the
/// effective policy cannot be evaluated (no privilege, no sshd binary,
/// or a parse failure) — callers then show the conventional single
/// source and label the view partial.
/// The raw output is returned through `raw_out` (owned) for the SFTP
/// subsystem scan.
fn keysEffectivePolicy(self: *Context, server_id: []const u8, facts: *const KeysAccountFacts, privilege: KeysPrivilege, tuple: *const KeysConnTuple, raw_out: *?[]u8) ?sshd_policy.EffectiveSshdPolicy {
    raw_out.* = null;
    if (privilege == .none or !tuple.valid) return null;
    const criteria = std.fmt.allocPrint(self.allocator, "user={s},addr={s},laddr={s},lport={s},host={s}", .{ facts.user, tuple.client_addr, tuple.local_addr, tuple.local_port, tuple.host }) catch return null;
    defer self.allocator.free(criteria);
    const quoted = shellquote.quote(self.allocator, criteria) catch return null;
    defer self.allocator.free(quoted);
    const cmd = std.fmt.allocPrint(self.allocator, "LC_ALL=C {s}sshd -T -C {s} 2>&1", .{ if (privilege == .sudo_n) "sudo -n " else "", quoted }) catch return null;
    defer self.allocator.free(cmd);
    var check = keysExec(self, server_id, cmd) orelse return null;
    defer check.output.deinit(self.allocator);
    if (check.exit != 0) return null;
    var policy = sshd_policy.parseEffectiveSshdPolicy(self.allocator, check.output.items, facts.user, facts.uid, facts.home) catch return null;
    errdefer policy.deinit(self.allocator);
    raw_out.* = self.allocator.dupe(u8, check.output.items) catch null;
    return policy;
}

const KeysSftpCapability = struct {
    read_only: bool = false,
    /// The exact forced command for read-only role keys (owned).
    forced_command: []u8 = &.{},

    fn deinit(self: *KeysSftpCapability, allocator: std.mem.Allocator) void {
        allocator.free(self.forced_command);
    }
};

/// The server's SFTP subsystem from the `sshd -T` output plus a live
/// check that read-only mode (`-R`) is accepted: internal-sftp needs
/// OpenSSH >= 8.5 (checked through `ssh -V`); a binary subsystem is
/// probed with `-R` and rejected on an option error (spec 08 §13).
fn keysDetectSftpCapability(self: *Context, server_id: []const u8, policy_output: ?[]const u8) KeysSftpCapability {
    const raw = policy_output orelse return .{};
    var subsystem: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (!std.mem.startsWith(u8, line, "subsystem ")) continue;
        var tokens = std.mem.tokenizeAny(u8, line["subsystem ".len..], " \t");
        const name = tokens.next() orelse continue;
        if (!std.mem.eql(u8, name, "sftp")) continue;
        subsystem = tokens.next();
        break;
    }
    const value = subsystem orelse return .{};
    if (std.mem.eql(u8, value, "internal-sftp")) {
        var ver = keysExec(self, server_id, "ssh -V 2>&1") orelse return .{};
        defer ver.output.deinit(self.allocator);
        const text = std.mem.trim(u8, ver.output.items, " \t\r\n");
        const prefix = "OpenSSH_";
        const start = std.mem.indexOf(u8, text, prefix) orelse return .{};
        const rest = text[start + prefix.len ..];
        const dot = std.mem.indexOfScalar(u8, rest, '.') orelse return .{};
        const major = std.fmt.parseInt(u32, rest[0..dot], 10) catch return .{};
        var minor_end = dot + 1;
        while (minor_end < rest.len and std.ascii.isDigit(rest[minor_end])) minor_end += 1;
        const minor = std.fmt.parseInt(u32, rest[dot + 1 .. minor_end], 10) catch return .{};
        if (major < 8 or (major == 8 and minor < 5)) return .{};
        return .{
            .read_only = true,
            .forced_command = self.allocator.dupe(u8, "internal-sftp -R") catch &.{},
        };
    }
    // Binary subsystem: probe that -R is accepted (an option error means
    // the build is too old for read-only mode).
    const quoted = shellquote.quote(self.allocator, value) catch return .{};
    defer self.allocator.free(quoted);
    const cmd = std.fmt.allocPrint(self.allocator, "{s} -R </dev/null 2>&1 | head -c 512", .{quoted}) catch return .{};
    defer self.allocator.free(cmd);
    var probe = keysExec(self, server_id, cmd) orelse return .{};
    defer probe.output.deinit(self.allocator);
    const text = probe.output.items;
    if (std.mem.indexOf(u8, text, "llegal option") != null or
        std.mem.indexOf(u8, text, "nknown option") != null or
        std.mem.indexOf(u8, text, "nvalid option") != null) return .{};
    return .{
        .read_only = true,
        .forced_command = std.fmt.allocPrint(self.allocator, "{s} -R", .{value}) catch &.{},
    };
}

// --- remote manifests (roles + deploy keys) ---------------------------------
//
// Both manifests are owner-only versioned JSON documents written
// atomically. Corrupt content is quarantined (renamed aside) instead of
// being treated as empty; a missing manifest is simply empty.

const RolesManifestEntry = struct {
    name: []u8,
    /// "standard_ssh" | "read_only_sftp"
    kind: []u8,
    forced_command: []u8,
    created_at_ms: i64 = 0,

    fn deinit(self: *RolesManifestEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.kind);
        allocator.free(self.forced_command);
    }
};

const RolesManifestRead = union(enum) {
    ok: []RolesManifestEntry,
    missing,
    corrupt,
    unreadable,
};

fn keysRolesManifestEntriesDeinit(allocator: std.mem.Allocator, entries: []RolesManifestEntry) void {
    for (entries) |*entry| entry.deinit(allocator);
    allocator.free(entries);
}

/// Parses the versioned roles manifest; the legacy bare-array format
/// (`[{name, read_only, forced_command}]`) is migrated in memory and
/// rewritten as versioned on the next save.
fn keysParseRolesManifest(allocator: std.mem.Allocator, content: []const u8) ?[]RolesManifestEntry {
    const Versioned = struct {
        version: u32 = 0,
        roles: []struct {
            name: []const u8,
            kind: []const u8 = "standard_ssh",
            forced_command: []const u8 = "",
            created_at_ms: i64 = 0,
        } = &.{},
    };
    var entries: std.ArrayList(RolesManifestEntry) = .empty;
    errdefer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit(allocator);
    }
    if (std.json.parseFromSlice(Versioned, allocator, content, .{ .ignore_unknown_fields = true, .allocate = .alloc_always })) |parsed| {
        defer parsed.deinit();
        if (parsed.value.version != 1) return null;
        for (parsed.value.roles) |role| {
            if (!validRoleName(role.name)) return null;
            const standard = std.mem.eql(u8, role.kind, "standard_ssh");
            const read_only = std.mem.eql(u8, role.kind, "read_only_sftp");
            if (!standard and !read_only) return null;
            if (read_only and role.forced_command.len == 0) return null;
            const kind = if (read_only) "read_only_sftp" else "standard_ssh";
            entries.append(allocator, .{
                .name = allocator.dupe(u8, role.name) catch return null,
                .kind = allocator.dupe(u8, kind) catch return null,
                .forced_command = allocator.dupe(u8, role.forced_command) catch return null,
                .created_at_ms = role.created_at_ms,
            }) catch return null;
        }
        return entries.toOwnedSlice(allocator) catch null;
    } else |_| {}
    // Legacy migration path.
    const Legacy = []struct {
        name: []const u8,
        read_only: bool,
        forced_command: []const u8 = "",
    };
    const parsed = std.json.parseFromSlice(Legacy, allocator, content, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch return null;
    defer parsed.deinit();
    for (parsed.value) |role| {
        if (!validRoleName(role.name)) return null;
        entries.append(allocator, .{
            .name = allocator.dupe(u8, role.name) catch return null,
            .kind = allocator.dupe(u8, if (role.read_only) "read_only_sftp" else "standard_ssh") catch return null,
            .forced_command = allocator.dupe(u8, role.forced_command) catch return null,
        }) catch return null;
    }
    return entries.toOwnedSlice(allocator) catch null;
}

test "roles manifest rejects unknown or incomplete policy kinds" {
    const allocator = std.testing.allocator;
    try std.testing.expect(keysParseRolesManifest(allocator, "{\"version\":1,\"roles\":[{\"name\":\"reports\",\"kind\":\"future_policy\"}]}") == null);
    try std.testing.expect(keysParseRolesManifest(allocator, "{\"version\":1,\"roles\":[{\"name\":\"reports\",\"kind\":\"read_only_sftp\",\"forced_command\":\"\"}]}") == null);
}

fn keysSerializeRolesManifest(allocator: std.mem.Allocator, entries: []const RolesManifestEntry) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try out.writer.writeAll("{\"version\":1,\"roles\":[");
    for (entries, 0..) |entry, i| {
        if (i > 0) try out.writer.writeAll(",");
        try out.writer.writeAll("{\"name\":");
        try json.writeJsonString(&out.writer, entry.name);
        try out.writer.writeAll(",\"kind\":");
        try json.writeJsonString(&out.writer, entry.kind);
        try out.writer.writeAll(",\"forced_command\":");
        try json.writeJsonString(&out.writer, entry.forced_command);
        try out.writer.print(",\"created_at_ms\":{d}}}", .{entry.created_at_ms});
    }
    try out.writer.writeAll("]}");
    return out.toOwnedSlice();
}

fn keysRolesManifestRead(self: *Context, server_id: []const u8, privilege: KeysPrivilege) RolesManifestRead {
    if (privilege == .none) return .unreadable;
    const read = if (privilege == .root)
        keysReadTyped(self, server_id, roles_marker_path, 256 * 1024)
    else
        keysPrivilegedRead(self, server_id, roles_marker_path, 256 * 1024);
    switch (read.status) {
        .missing => return .missing,
        .readable => {},
        else => return .unreadable,
    }
    const content = read.content orelse return .unreadable;
    defer self.allocator.free(content);
    if (std.mem.trim(u8, content, " \t\r\n").len == 0) return .missing;
    const entries = keysParseRolesManifest(self.allocator, content) orelse return .corrupt;
    return .{ .ok = entries };
}

fn keysRolesManifestWrite(self: *Context, server_id: []const u8, privilege: KeysPrivilege, entries: []const RolesManifestEntry) ?[]const u8 {
    const content = keysSerializeRolesManifest(self.allocator, entries) catch return "out of memory";
    defer self.allocator.free(content);
    var err_buf: [256]u8 = undefined;
    if (privilege == .root) {
        var hash: ?[]u8 = null;
        defer if (hash) |h| self.allocator.free(h);
        // The manifest is Oars-owned: no frozen-identity guard, last
        // writer inside a job wins, and the driver re-reads on verify.
        return keysWriteAtomic(self, server_id, roles_marker_path, content, .unguarded, 0o600, null, &err_buf, &hash);
    }
    return keysPrivilegedWrite(self, server_id, roles_marker_path, content, .unguarded, 0o600, null, &err_buf);
}

/// Renames a corrupt manifest aside (best effort); the corrupt bytes are
/// preserved for inspection instead of being treated as an empty file.
fn keysQuarantine(self: *Context, server_id: []const u8, path: []const u8, privilege: KeysPrivilege) void {
    if (privilege == .none) return;
    const quoted = shellquote.quote(self.allocator, path) catch return;
    defer self.allocator.free(quoted);
    const dest = std.fmt.allocPrint(self.allocator, "{s}.corrupt-{d}", .{ path, @divTrunc(std.Io.Timestamp.now(self.io, .real).nanoseconds, std.time.ns_per_s) }) catch return;
    defer self.allocator.free(dest);
    const quoted_dest = shellquote.quote(self.allocator, dest) catch return;
    defer self.allocator.free(quoted_dest);
    const cmd = std.fmt.allocPrint(self.allocator, "{s}mv -f {s} {s}", .{ if (privilege == .sudo_n) "sudo -n " else "", quoted, quoted_dest }) catch return;
    defer self.allocator.free(cmd);
    var check = keysExec(self, server_id, cmd) orelse return;
    check.output.deinit(self.allocator);
}

fn keysDeployManifestPath(self: *Context, home: []const u8) ?[]u8 {
    return std.fmt.allocPrint(self.allocator, "{s}/.ssh/{s}", .{ home, deploy_manifest_file }) catch null;
}

const DeployManifestRead = union(enum) {
    ok: []keyjobs.DeployKeyEntry,
    missing,
    corrupt,
    unreadable,
};

fn keysDeployEntriesDeinit(allocator: std.mem.Allocator, entries: []keyjobs.DeployKeyEntry) void {
    for (entries) |*entry| entry.deinit(allocator);
    allocator.free(entries);
}

fn keysParseDeployManifest(allocator: std.mem.Allocator, content: []const u8) ?[]keyjobs.DeployKeyEntry {
    const Versioned = struct {
        version: u32 = 0,
        keys: []struct {
            id: []const u8,
            repository_label: []const u8,
            path: []const u8,
            fingerprint: []const u8,
            comment: []const u8 = "",
            created_at_ms: i64 = 0,
        } = &.{},
    };
    const parsed = std.json.parseFromSlice(Versioned, allocator, content, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch return null;
    defer parsed.deinit();
    if (parsed.value.version != 1) return null;
    var entries: std.ArrayList(keyjobs.DeployKeyEntry) = .empty;
    errdefer {
        for (entries.items) |*entry| entry.deinit(allocator);
        entries.deinit(allocator);
    }
    for (parsed.value.keys) |key| {
        if (!std.mem.startsWith(u8, key.id, "dk-") or key.id.len > 32) return null;
        if (!keysValidFingerprint(key.fingerprint)) return null;
        entries.append(allocator, .{
            .id = allocator.dupe(u8, key.id) catch return null,
            .repository_label = allocator.dupe(u8, key.repository_label) catch return null,
            .path = allocator.dupe(u8, key.path) catch return null,
            .fingerprint = allocator.dupe(u8, key.fingerprint) catch return null,
            .comment = allocator.dupe(u8, key.comment) catch return null,
            .created_at_ms = key.created_at_ms,
        }) catch return null;
    }
    return entries.toOwnedSlice(allocator) catch null;
}

fn keysSerializeDeployManifest(allocator: std.mem.Allocator, entries: []const keyjobs.DeployKeyEntry) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try out.writer.writeAll("{\"version\":1,\"keys\":[");
    for (entries, 0..) |entry, i| {
        if (i > 0) try out.writer.writeAll(",");
        try out.writer.writeAll("{\"id\":");
        try json.writeJsonString(&out.writer, entry.id);
        try out.writer.writeAll(",\"repository_label\":");
        try json.writeJsonString(&out.writer, entry.repository_label);
        try out.writer.writeAll(",\"path\":");
        try json.writeJsonString(&out.writer, entry.path);
        try out.writer.writeAll(",\"fingerprint\":");
        try json.writeJsonString(&out.writer, entry.fingerprint);
        try out.writer.writeAll(",\"comment\":");
        try json.writeJsonString(&out.writer, entry.comment);
        try out.writer.print(",\"created_at_ms\":{d}}}", .{entry.created_at_ms});
    }
    try out.writer.writeAll("]}");
    return out.toOwnedSlice();
}

fn keysDeployManifestRead(self: *Context, server_id: []const u8, home: []const u8) DeployManifestRead {
    const path = keysDeployManifestPath(self, home) orelse return .unreadable;
    defer self.allocator.free(path);
    const read = keysReadTyped(self, server_id, path, 256 * 1024);
    switch (read.status) {
        .missing => return .missing,
        .readable => {},
        else => return .unreadable,
    }
    const content = read.content orelse return .unreadable;
    defer self.allocator.free(content);
    if (std.mem.trim(u8, content, " \t\r\n").len == 0) return .missing;
    const entries = keysParseDeployManifest(self.allocator, content) orelse return .corrupt;
    return .{ .ok = entries };
}

fn keysDeployManifestWrite(self: *Context, server_id: []const u8, home: []const u8, entries: []const keyjobs.DeployKeyEntry) ?[]const u8 {
    const path = keysDeployManifestPath(self, home) orelse return "out of memory";
    defer self.allocator.free(path);
    const content = keysSerializeDeployManifest(self.allocator, entries) catch return "out of memory";
    defer self.allocator.free(content);
    var err_buf: [256]u8 = undefined;
    var hash: ?[]u8 = null;
    defer if (hash) |h| self.allocator.free(h);
    return keysWriteAtomic(self, server_id, path, content, .unguarded, 0o600, null, &err_buf, &hash);
}

// --- snapshot driver (coordinator thread) ------------------------------------

/// Accumulates the lists a snapshot swaps into the registry at the end.
/// On any abort the builder frees what it gathered; on success ownership
/// moves to the registry through `snapshotSwap`.
const KeysSnapshotBuilder = struct {
    sources: std.ArrayList(keyjobs.Source) = .empty,
    keys: std.ArrayList(keyjobs.KeyEntry) = .empty,
    roles: std.ArrayList(keyjobs.RoleEntry) = .empty,
    deploy_keys: std.ArrayList(keyjobs.DeployKeyEntry) = .empty,
    warnings: std.ArrayList([]u8) = .empty,

    fn deinit(self: *KeysSnapshotBuilder, allocator: std.mem.Allocator) void {
        for (self.sources.items) |*s| s.deinit(allocator);
        self.sources.deinit(allocator);
        for (self.keys.items) |*k| k.deinit(allocator);
        self.keys.deinit(allocator);
        for (self.roles.items) |*r| r.deinit(allocator);
        self.roles.deinit(allocator);
        for (self.deploy_keys.items) |*d| d.deinit(allocator);
        self.deploy_keys.deinit(allocator);
        for (self.warnings.items) |w| allocator.free(w);
        self.warnings.deinit(allocator);
    }

    fn warn(self: *KeysSnapshotBuilder, allocator: std.mem.Allocator, text: []const u8) void {
        if (self.warnings.items.len >= keyjobs.max_warnings) return;
        const owned = allocator.dupe(u8, text) catch return;
        self.warnings.append(allocator, owned) catch allocator.free(owned);
    }

    fn warnFmt(self: *KeysSnapshotBuilder, allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) void {
        if (self.warnings.items.len >= keyjobs.max_warnings) return;
        const owned = std.fmt.allocPrint(allocator, fmt, args) catch return;
        self.warnings.append(allocator, owned) catch allocator.free(owned);
    }
};

fn keysFinishSnapshot(registry: *keyjobs.Registry, snap: *keyjobs.Snapshot, state: keyjobs.SnapshotState) void {
    registry.snapshotFinish(snap, state, "", "partial", "none", false, "", null);
}

/// Reads one static source into the builder: the typed status, the
/// frozen whole-file hash (missing sources report the empty-file hash so
/// clients always echo a usable identity), stat metadata, and the parsed
/// key rows. Returns false when the status blocks mutation.
fn keysSnapshotReadSource(self: *Context, builder: *KeysSnapshotBuilder, server_id: []const u8, path: []const u8, privileged: bool) bool {
    const path_copy = self.allocator.dupe(u8, path) catch return false;
    const kind_copy = self.allocator.dupe(u8, "static") catch {
        self.allocator.free(path_copy);
        return false;
    };
    var source = keyjobs.Source{ .path = path_copy, .kind = kind_copy };
    var read = if (privileged)
        keysPrivilegedRead(self, server_id, path, sshkeys.max_keys_file_bytes)
    else
        keysReadTyped(self, server_id, path, sshkeys.max_keys_file_bytes);
    source.status = keysSourceStatus(read.status);
    if (read.detail().len > 0 and read.status != .readable and read.status != .missing) {
        source.@"error" = self.allocator.dupe(u8, read.detail()) catch null;
    }
    switch (read.status) {
        .missing => {
            source.file_sha256 = sshkeys.fileSha256(self.allocator, "") catch null;
        },
        .readable => blk: {
            const content = read.content orelse {
                source.status = .transport_error;
                break :blk;
            };
            defer self.allocator.free(content);
            source.file_sha256 = sshkeys.fileSha256(self.allocator, content) catch null;
            const meta = keysStatMeta(self, server_id, path, privileged);
            source.mode = meta.mode;
            source.owner = meta.owner;
            var file = sshkeys.parse(self.allocator, content) catch {
                source.status = .parse_error;
                source.@"error" = self.allocator.dupe(u8, "the file could not be parsed") catch null;
                break :blk;
            };
            defer file.deinit(self.allocator);
            var count: usize = 0;
            for (file.keys) |*k| {
                if (count >= keyjobs.max_keys_per_source) {
                    builder.warnFmt(self.allocator, "{s}: only the first {d} keys are shown", .{ path, keyjobs.max_keys_per_source });
                    break;
                }
                const entry = keyjobs.keyEntryFromParsed(self.allocator, path, k) catch continue;
                builder.keys.append(self.allocator, entry) catch continue;
                count += 1;
            }
        },
        else => {},
    }
    const allows = keyjobs.statusAllowsMutation(source.status);
    builder.sources.append(self.allocator, source) catch {
        source.deinit(self.allocator);
        return false;
    };
    return allows;
}

/// Verifies one manifest role against the live server: account, home,
/// shell, key source, and — for read-only roles — the exact restrictive
/// options on every installed key.
fn keysSnapshotVerifyRole(self: *Context, builder: *KeysSnapshotBuilder, server_id: []const u8, entry: *const RolesManifestEntry, privilege: KeysPrivilege) void {
    const name_copy = self.allocator.dupe(u8, entry.name) catch return;
    const kind_copy = self.allocator.dupe(u8, entry.kind) catch {
        self.allocator.free(name_copy);
        return;
    };
    var role = keyjobs.RoleEntry{
        .name = name_copy,
        .kind = kind_copy,
        .forced_command = self.allocator.dupe(u8, entry.forced_command) catch &.{},
    };
    defer builder.roles.append(self.allocator, role) catch role.deinit(self.allocator);

    var facts = keysAccountFacts(self, server_id, entry.name) orelse {
        role.policy_state = .stale; // the account behind the policy is gone
        return;
    };
    defer facts.deinit(self.allocator);
    role.home = self.allocator.dupe(u8, facts.home) catch null;
    role.shell = self.allocator.dupe(u8, facts.shell) catch null;
    if (privilege == .none) {
        role.policy_state = .unreadable;
        return;
    }
    const source_path = std.fmt.allocPrint(self.allocator, "{s}/.ssh/authorized_keys", .{facts.home}) catch return;
    defer self.allocator.free(source_path);
    const read = if (privilege == .root)
        keysReadTyped(self, server_id, source_path, sshkeys.max_keys_file_bytes)
    else
        keysPrivilegedRead(self, server_id, source_path, sshkeys.max_keys_file_bytes);
    switch (read.status) {
        .missing => {
            role.policy_state = .verified; // no keys installed yet
            return;
        },
        .readable => {},
        else => {
            role.policy_state = .unreadable;
            return;
        },
    }
    const content = read.content orelse {
        role.policy_state = .unreadable;
        return;
    };
    defer self.allocator.free(content);
    var file = sshkeys.parse(self.allocator, content) catch {
        role.policy_state = .unreadable;
        return;
    };
    defer file.deinit(self.allocator);
    const read_only = std.mem.eql(u8, entry.kind, "read_only_sftp");
    var fingerprints: std.ArrayList([]u8) = .empty;
    defer {
        for (fingerprints.items) |fp| self.allocator.free(fp);
        fingerprints.deinit(self.allocator);
    }
    var drifted = false;
    for (file.keys) |*k| {
        if (!k.parsed) {
            drifted = true; // a row Oars did not write and cannot reason about
            continue;
        }
        const fp = self.allocator.dupe(u8, k.fingerprint_sha256) catch continue;
        fingerprints.append(self.allocator, fp) catch {
            self.allocator.free(fp);
            continue;
        };
        if (read_only and !keyjobs.verifyReadOnlyKeyOptions(k.options, entry.forced_command)) drifted = true;
    }
    role.key_fingerprints = fingerprints.toOwnedSlice(self.allocator) catch &.{};
    role.policy_state = if (drifted) .drifted else .verified;
}

fn keysDriveSnapshot(context: *anyopaque, registry: *keyjobs.Registry, snap: *keyjobs.Snapshot) void {
    const self = contextOf(context);
    const allocator = self.allocator;
    const server_id = snap.server_id;

    var builder = KeysSnapshotBuilder{};
    defer builder.deinit(allocator);

    if (snap.cancel_requested.load(.acquire)) {
        keysFinishSnapshot(registry, snap, .canceled);
        return;
    }
    if (!keysSessionReady(self, server_id)) {
        builder.warn(allocator, "not connected; start an SSH session and refresh");
        registry.snapshotSwap(snap, builder.sources, builder.keys, builder.roles, builder.deploy_keys, builder.warnings);
        builder.sources = .empty;
        builder.keys = .empty;
        builder.roles = .empty;
        builder.deploy_keys = .empty;
        builder.warnings = .empty;
        keysFinishSnapshot(registry, snap, .partial);
        return;
    }

    var facts = keysAccountFacts(self, server_id, snap.account_name) orelse {
        if (snap.account_name) |name| {
            builder.warnFmt(allocator, "account {s} was not found on the server", .{name});
        } else {
            builder.warn(allocator, "the connected account could not be resolved");
        }
        registry.snapshotSwap(snap, builder.sources, builder.keys, builder.roles, builder.deploy_keys, builder.warnings);
        builder.sources = .empty;
        builder.keys = .empty;
        builder.roles = .empty;
        builder.deploy_keys = .empty;
        builder.warnings = .empty;
        keysFinishSnapshot(registry, snap, .partial);
        return;
    };
    defer facts.deinit(allocator);

    const privilege = keysProbePrivilege(self, server_id);
    var tuple = keysConnectionTuple(self, server_id);
    defer tuple.deinit(allocator);
    if (!tuple.valid) builder.warn(allocator, "the live SSH connection tuple was unavailable; effective policy could not be matched");

    if (snap.cancel_requested.load(.acquire)) {
        keysFinishSnapshot(registry, snap, .canceled);
        return;
    }

    var policy_raw: ?[]u8 = null;
    defer if (policy_raw) |raw| allocator.free(raw);
    var policy = keysEffectivePolicy(self, server_id, &facts, privilege, &tuple, &policy_raw);
    defer if (policy) |*p| p.deinit(allocator);

    const scope: []const u8 = if (policy != null) "effective_policy" else "single_source_fallback";
    if (policy == null) {
        if (privilege == .none) {
            builder.warn(allocator, "effective SSH policy needs root or approved sudo -n; showing only the conventional authorized_keys source");
        } else {
            builder.warn(allocator, "sshd -T could not be evaluated; showing only the conventional authorized_keys source");
        }
    }

    var capability = if (policy_raw != null) keysDetectSftpCapability(self, server_id, policy_raw) else KeysSftpCapability{};
    defer capability.deinit(allocator);

    // Static sources: effective-policy paths, or the conventional file as
    // the labeled fallback.
    var all_static_ok = true;
    var source_count: usize = 0;
    if (policy) |*p| {
        for (p.static_sources) |path| {
            if (source_count >= keyjobs.max_sources_per_snapshot) {
                builder.warnFmt(allocator, "only the first {d} static sources are shown", .{keyjobs.max_sources_per_snapshot});
                all_static_ok = false;
                break;
            }
            // Role homes are 0700 role-owned: reading them needs privilege.
            const privileged = snap.account_kind == .managed_role and privilege != .none;
            if (snap.account_kind == .managed_role and privilege == .none) {
                const denied_path = allocator.dupe(u8, path) catch break;
                const denied_kind = allocator.dupe(u8, "static") catch {
                    allocator.free(denied_path);
                    break;
                };
                var source = keyjobs.Source{
                    .path = denied_path,
                    .kind = denied_kind,
                    .status = .denied,
                    .@"error" = allocator.dupe(u8, "reading a role source requires root or approved sudo -n") catch null,
                };
                builder.sources.append(allocator, source) catch source.deinit(allocator);
                all_static_ok = false;
                source_count += 1;
                continue;
            }
            if (!keysSnapshotReadSource(self, &builder, server_id, path, privileged)) all_static_ok = false;
            source_count += 1;
        }
        for (p.dynamic_sources) |dyn| {
            const label = std.fmt.allocPrint(allocator, "{s} {s}", .{ dyn.key, dyn.value }) catch continue;
            var source = keyjobs.Source{
                .path = label,
                .kind = allocator.dupe(u8, dyn.kind) catch {
                    allocator.free(label);
                    continue;
                },
                // Informational row: Oars cannot inventory or edit this
                // source; the UI renders the kind, never this status.
                .status = .readable,
            };
            builder.sources.append(allocator, source) catch {
                source.deinit(allocator);
                continue;
            };
        }
        for (p.warnings) |warning| builder.warnFmt(allocator, "sshd policy: {s}", .{warning});
        if (p.pubkey_authentication == false) builder.warn(allocator, "public-key authentication is disabled for this account in the effective sshd policy");
    } else {
        const fallback_path = std.fmt.allocPrint(allocator, "{s}/.ssh/authorized_keys", .{facts.home}) catch {
            keysFinishSnapshot(registry, snap, .partial);
            return;
        };
        defer allocator.free(fallback_path);
        const privileged = snap.account_kind == .managed_role and privilege != .none;
        if (!keysSnapshotReadSource(self, &builder, server_id, fallback_path, privileged)) all_static_ok = false;
    }

    if (snap.cancel_requested.load(.acquire)) {
        keysFinishSnapshot(registry, snap, .canceled);
        return;
    }

    // Server-level roles: verified against the live accounts on every
    // snapshot (spec 08 fail-closed roles).
    var dynamic_count: usize = 0;
    if (policy) |*p| dynamic_count = p.dynamic_sources.len;
    switch (keysRolesManifestRead(self, server_id, privilege)) {
        .ok => |entries| {
            defer keysRolesManifestEntriesDeinit(allocator, entries);
            for (entries) |*entry| {
                keysSnapshotVerifyRole(self, &builder, server_id, entry, privilege);
            }
        },
        .missing => {},
        .corrupt => {
            builder.warn(allocator, "the role policy manifest is corrupt; managed roles cannot be trusted until an approved repair or cleanup moves it aside");
        },
        .unreadable => {
            if (privilege == .none) {
                builder.warn(allocator, "managed roles cannot be verified without root or approved sudo -n");
            } else {
                builder.warn(allocator, "the role policy manifest could not be read");
            }
        },
    }

    // Deploy keys live in the connected account's home; role snapshots
    // skip them.
    if (snap.account_kind == .connected) {
        switch (keysDeployManifestRead(self, server_id, facts.home)) {
            .ok => |entries| {
                defer allocator.free(entries);
                for (entries) |*entry| {
                    const copy = keyjobs.DeployKeyEntry{
                        .id = allocator.dupe(u8, entry.id) catch continue,
                        .repository_label = allocator.dupe(u8, entry.repository_label) catch continue,
                        .path = allocator.dupe(u8, entry.path) catch continue,
                        .fingerprint = allocator.dupe(u8, entry.fingerprint) catch continue,
                        .comment = allocator.dupe(u8, entry.comment) catch continue,
                        .created_at_ms = entry.created_at_ms,
                    };
                    builder.deploy_keys.append(allocator, copy) catch {
                        var mutable = copy;
                        mutable.deinit(allocator);
                        continue;
                    };
                }
                for (entries) |*entry| entry.deinit(allocator);
            },
            .missing => {},
            .corrupt => {
                builder.warn(allocator, "the deploy-key manifest is corrupt; deploy identities cannot be managed until an approved cleanup moves it aside");
            },
            .unreadable => builder.warn(allocator, "the deploy-key manifest could not be read"),
        }
    }

    const pubkey_auth: ?bool = if (policy) |*p| p.pubkey_authentication else null;
    const complete = policy != null and all_static_ok and tuple.valid and dynamic_count == 0;
    const state: keyjobs.SnapshotState = if (policy != null and all_static_ok) .done else .partial;
    registry.snapshotSwap(snap, builder.sources, builder.keys, builder.roles, builder.deploy_keys, builder.warnings);
    builder.sources = .empty;
    builder.keys = .empty;
    builder.roles = .empty;
    builder.deploy_keys = .empty;
    builder.warnings = .empty;
    registry.snapshotFinish(
        snap,
        state,
        scope,
        if (complete) "complete" else "partial",
        keysPrivilegeName(privilege),
        capability.read_only,
        capability.forced_command,
        pubkey_auth,
    );
}

// --- job drivers (coordinator / local worker thread) -------------------------

fn keysJobKindDetail(job: *keyjobs.Job, buf: []u8) []const u8 {
    return keyjobs.kindDetail(job, buf);
}

/// The terminal audit row for a job. Exactly one row per job: drivers
/// transition to a terminal state only through keysJobFinish, and
/// handler-side cancels of queued/waiting jobs audit at the call site.
fn keysJobAuditTerminal(self: *Context, job: *keyjobs.Job, state: keyjobs.JobState) void {
    var kind_buf: [256]u8 = undefined;
    const kind_detail = keysJobKindDetail(job, &kind_buf);
    var detail_buf: [384]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "state={s} {s}", .{ state.jsonName(), kind_detail }) catch state.jsonName();
    const target = if (job.server_id.len > 0) job.server_id else "local";
    self.audit.append(self.io, job.kind.auditName(), target, detail) catch {};
}

fn keysJobFinish(self: *Context, registry: *keyjobs.Registry, job: *keyjobs.Job, step_index: usize, step_state: keyjobs.StepState, msg: ?[]const u8, state: keyjobs.JobState) void {
    registry.jobSetStep(job, step_index, step_state, msg);
    registry.jobSetState(job, state);
    keysJobAuditTerminal(self, job, state);
}

/// Cooperative cancel between steps; finishes the job and returns true.
fn keysJobCancelDrive(self: *Context, registry: *keyjobs.Registry, job: *keyjobs.Job, step_index: usize) bool {
    if (!job.cancel_requested.load(.acquire)) return false;
    keysJobFinish(self, registry, job, step_index, .canceled, null, .canceled);
    return true;
}

/// Builds `{"name":"value",...}` with every value escaped. Result
/// fragments never carry secrets.
fn keysBuildAddResult(self: *Context, fingerprint: []const u8, idempotent: bool) ?[]u8 {
    var out: std.Io.Writer.Allocating = .init(self.allocator);
    errdefer out.deinit();
    out.writer.writeAll("{\"fingerprint\":") catch return null;
    json.writeJsonString(&out.writer, fingerprint) catch return null;
    out.writer.print(",\"idempotent\":{s}}}", .{if (idempotent) "true" else "false"}) catch return null;
    return out.toOwnedSlice() catch null;
}

fn keysBuildResult(self: *Context, fields: []const [2][]const u8) ?[]u8 {
    var out: std.Io.Writer.Allocating = .init(self.allocator);
    errdefer out.deinit();
    out.writer.writeAll("{") catch return null;
    for (fields, 0..) |field, i| {
        if (i > 0) out.writer.writeAll(",") catch return null;
        json.writeJsonString(&out.writer, field[0]) catch return null;
        out.writer.writeAll(":") catch return null;
        json.writeJsonString(&out.writer, field[1]) catch return null;
    }
    out.writer.writeAll("}") catch return null;
    return out.toOwnedSlice() catch null;
}

/// True when a role-account job must use the sudo write path: root uses
/// SFTP directly (with the identity guard); sudo_n needs sudo sh.
fn keysJobPrivileged(job: *const keyjobs.Job, privilege: KeysPrivilege) bool {
    return job.account_name != null and privilege == .sudo_n;
}

fn keysJobReadSource(self: *Context, server_id: []const u8, path: []const u8, privileged: bool) KeysReadResult {
    return if (privileged)
        keysPrivilegedRead(self, server_id, path, sshkeys.max_keys_file_bytes)
    else
        keysReadTyped(self, server_id, path, sshkeys.max_keys_file_bytes);
}

/// Writes one authorized_keys source through the one atomic writer. Both the
/// SFTP and sudo paths compare the frozen whole-file identity immediately
/// before atomic replacement.
fn keysJobWriteSource(
    self: *Context,
    server_id: []const u8,
    path: []const u8,
    content: []const u8,
    guard: KeysWriteGuard,
    mode: ?u32,
    owner: ?[]const u8,
    privileged: bool,
    err_buf: []u8,
    out_hash: *?[]u8,
) ?[]const u8 {
    if (privileged) {
        const err = keysPrivilegedWrite(self, server_id, path, content, guard, mode orelse 0o600, owner, err_buf);
        if (err) |e| return e;
        out_hash.* = sshkeys.fileSha256(self.allocator, content) catch null;
        return null;
    }
    return keysWriteAtomic(self, server_id, path, content, guard, mode, owner, err_buf, out_hash);
}

fn keysEnsureDirFor(self: *Context, server_id: []const u8, path: []const u8, account: ?[]const u8, privilege: KeysPrivilege) ?[]const u8 {
    if (account == null) return sshkeysEnsureSshDir(self, server_id, path);
    const dir = std.fs.path.dirname(path) orelse return "invalid path";
    return keysPrivilegedEnsureDir(self, server_id, dir, account.?, privilege);
}

/// The frozen source at job start: a fresh typed read, the whole-file
/// hash comparison against the client's frozen identity, and a parse.
/// `parsed` borrows `content`; keep both alive together.
const KeysSourceState = struct {
    content: []u8,
    parsed: sshkeys.ParsedFile,
    /// Frozen source identity for the atomic writer. Hash slices borrow the
    /// job payload and remain valid for the job lifetime.
    guard: KeysWriteGuard,
};

/// check_source for add/revoke/rotate. On failure the step and job are
/// finished inside and null is returned.
fn keysJobCheckSource(self: *Context, registry: *keyjobs.Registry, job: *keyjobs.Job, privileged: bool) ?KeysSourceState {
    var read = keysJobReadSource(self, job.server_id, job.source_path, privileged);
    switch (read.status) {
        .missing => {
            const empty_sha = sshkeys.fileSha256(self.allocator, "") catch {
                keysJobFinish(self, registry, job, 0, .@"error", "out of memory", .partial);
                return null;
            };
            defer self.allocator.free(empty_sha);
            if (!std.mem.eql(u8, empty_sha, job.file_sha256)) {
                keysJobFinish(self, registry, job, 0, .conflict, "the source appeared since the snapshot; refresh and review again", .partial);
                return null;
            }
            const content = self.allocator.dupe(u8, "") catch {
                keysJobFinish(self, registry, job, 0, .@"error", "out of memory", .partial);
                return null;
            };
            const parsed = sshkeys.parse(self.allocator, content) catch {
                self.allocator.free(content);
                keysJobFinish(self, registry, job, 0, .@"error", "out of memory", .partial);
                return null;
            };
            return .{ .content = content, .parsed = parsed, .guard = .missing };
        },
        .readable => {},
        .denied => {
            keysJobFinish(self, registry, job, 0, .@"error", "permission denied reading the source; no mutation is allowed", .partial);
            return null;
        },
        .timeout => {
            keysJobFinish(self, registry, job, 0, .@"error", "the source read timed out; no mutation was made", .partial);
            return null;
        },
        .too_large => {
            keysJobFinish(self, registry, job, 0, .@"error", "the source exceeds the 4 MiB limit; no mutation is allowed", .partial);
            return null;
        },
        .transport_error => {
            const detail = if (read.detail().len > 0) read.detail() else "the source could not be read";
            keysJobFinish(self, registry, job, 0, .@"error", detail, .partial);
            return null;
        },
    }
    const content = read.content orelse {
        keysJobFinish(self, registry, job, 0, .@"error", "the source could not be read", .partial);
        return null;
    };
    var content_transferred = false;
    defer if (!content_transferred) self.allocator.free(content);
    const sha = sshkeys.fileSha256(self.allocator, content) catch {
        keysJobFinish(self, registry, job, 0, .@"error", "out of memory", .partial);
        return null;
    };
    defer self.allocator.free(sha);
    if (!std.mem.eql(u8, sha, job.file_sha256)) {
        keysJobFinish(self, registry, job, 0, .conflict, "the file changed since the snapshot; refresh and review again", .partial);
        return null;
    }
    const parsed = sshkeys.parse(self.allocator, content) catch {
        keysJobFinish(self, registry, job, 0, .@"error", "the file could not be parsed; no mutation is allowed", .partial);
        return null;
    };
    content_transferred = true;
    return .{ .content = content, .parsed = parsed, .guard = .{ .sha256 = job.file_sha256 } };
}

/// Finds the reviewed line: fingerprint plus exact line hash (the line
/// index is not stable after an external edit).
fn keysJobFindTarget(parsed: *const sshkeys.ParsedFile, fingerprint: []const u8, line_hash: []const u8) ?sshkeys.Key {
    for (parsed.keys) |*k| {
        if (!k.parsed) continue;
        if (std.mem.eql(u8, k.fingerprint_sha256, fingerprint) and std.mem.eql(u8, k.line_hash, line_hash)) return k.*;
    }
    return null;
}

/// Probes the session, privilege, and role-write authority shared by the
/// source-mutation drivers. Returns false after finishing the job.
fn keysJobRemotePreamble(self: *Context, registry: *keyjobs.Registry, job: *keyjobs.Job, step_index: usize, privilege_out: *KeysPrivilege) bool {
    if (!keysSessionReady(self, job.server_id)) {
        keysJobFinish(self, registry, job, step_index, .@"error", "not connected", .partial);
        return false;
    }
    const privilege = keysProbePrivilege(self, job.server_id);
    privilege_out.* = privilege;
    if (job.account_name != null and privilege == .none) {
        keysJobFinish(self, registry, job, step_index, .@"error", "writing a role source requires root or approved sudo -n", .partial);
        return false;
    }
    return true;
}

fn keysDriveJobAdd(self: *Context, registry: *keyjobs.Registry, job: *keyjobs.Job) void {
    const p = &job.payload.add;
    registry.jobSetStep(job, 0, .running, null);
    if (keysJobCancelDrive(self, registry, job, 0)) return;
    var privilege: KeysPrivilege = .none;
    if (!keysJobRemotePreamble(self, registry, job, 0, &privilege)) return;
    const privileged = keysJobPrivileged(job, privilege);
    var state = keysJobCheckSource(self, registry, job, privileged) orelse return;
    defer self.allocator.free(state.content);
    defer state.parsed.deinit(self.allocator);
    if (sshkeys.findByFingerprint(&state.parsed, p.fingerprint) != null) {
        registry.jobSetStep(job, 0, .done, null);
        registry.jobSetStep(job, 1, .done, null);
        if (keysBuildAddResult(self, p.fingerprint, true)) |fragment| {
            registry.jobSetResult(job, fragment);
        }
        keysJobFinish(self, registry, job, 2, .done, null, .done);
        return;
    }
    registry.jobSetStep(job, 0, .done, null);

    registry.jobSetStep(job, 1, .running, null);
    if (keysJobCancelDrive(self, registry, job, 1)) return;
    const new_content = sshkeys.appendLine(self.allocator, state.content, p.normalized_line) catch {
        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(new_content);
    if (state.content.len == 0) {
        if (keysEnsureDirFor(self, job.server_id, job.source_path, job.account_name, privilege)) |err| {
            keysJobFinish(self, registry, job, 1, .@"error", err, .partial);
            return;
        }
    }
    const meta = keysStatMeta(self, job.server_id, job.source_path, privileged);
    defer if (meta.owner) |o| self.allocator.free(o);
    const mode: u32 = meta.mode orelse 0o600;
    var err_buf: [256]u8 = undefined;
    var new_hash: ?[]u8 = null;
    defer if (new_hash) |h| self.allocator.free(h);
    if (keysJobWriteSource(self, job.server_id, job.source_path, new_content, state.guard, mode, job.account_name, privileged, &err_buf, &new_hash)) |err| {
        keysJobFinish(self, registry, job, 1, .@"error", err, .partial);
        return;
    }
    registry.jobSetStep(job, 1, .done, null);

    registry.jobSetStep(job, 2, .running, null);
    const verify = keysJobReadSource(self, job.server_id, job.source_path, privileged);
    if (verify.status != .readable) {
        keysJobFinish(self, registry, job, 2, .@"error", "the write could not be verified; refresh the snapshot", .partial);
        return;
    }
    const verified = verify.content.?;
    defer self.allocator.free(verified);
    var verify_file = sshkeys.parse(self.allocator, verified) catch {
        keysJobFinish(self, registry, job, 2, .@"error", "the written file could not be parsed; refresh the snapshot", .partial);
        return;
    };
    defer verify_file.deinit(self.allocator);
    if (sshkeys.findByFingerprint(&verify_file, p.fingerprint) == null) {
        keysJobFinish(self, registry, job, 2, .@"error", "the new key was not found after the write; refresh the snapshot", .partial);
        return;
    }
    if (keysBuildAddResult(self, p.fingerprint, false)) |fragment| {
        registry.jobSetResult(job, fragment);
    }
    keysJobFinish(self, registry, job, 2, .done, null, .done);
}

fn keysDriveJobRevoke(self: *Context, registry: *keyjobs.Registry, job: *keyjobs.Job) void {
    const p = &job.payload.revoke;
    registry.jobSetStep(job, 0, .running, null);
    if (keysJobCancelDrive(self, registry, job, 0)) return;
    var privilege: KeysPrivilege = .none;
    if (!keysJobRemotePreamble(self, registry, job, 0, &privilege)) return;
    const privileged = keysJobPrivileged(job, privilege);
    var state = keysJobCheckSource(self, registry, job, privileged) orelse return;
    defer self.allocator.free(state.content);
    defer state.parsed.deinit(self.allocator);
    const target = keysJobFindTarget(&state.parsed, p.fingerprint, p.line_hash) orelse {
        if (sshkeys.findByFingerprint(&state.parsed, p.fingerprint) != null) {
            keysJobFinish(self, registry, job, 0, .conflict, "the reviewed line changed; refresh and review again", .partial);
        } else {
            keysJobFinish(self, registry, job, 0, .conflict, "the reviewed key is no longer in the source; refresh the snapshot", .partial);
        }
        return;
    };
    registry.jobSetStep(job, 0, .done, null);

    registry.jobSetStep(job, 1, .running, null);
    if (keysJobCancelDrive(self, registry, job, 1)) return;
    const new_content = sshkeys.rewrite(self.allocator, &state.parsed, target.line_index, null) catch {
        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(new_content);
    var err_buf: [256]u8 = undefined;
    var new_hash: ?[]u8 = null;
    defer if (new_hash) |h| self.allocator.free(h);
    if (keysJobWriteSource(self, job.server_id, job.source_path, new_content, state.guard, null, job.account_name, privileged, &err_buf, &new_hash)) |err| {
        keysJobFinish(self, registry, job, 1, .@"error", err, .partial);
        return;
    }
    registry.jobSetStep(job, 1, .done, null);

    registry.jobSetStep(job, 2, .running, null);
    const verify = keysJobReadSource(self, job.server_id, job.source_path, privileged);
    if (verify.status != .readable) {
        keysJobFinish(self, registry, job, 2, .@"error", "the write could not be verified; refresh the snapshot", .partial);
        return;
    }
    const verified = verify.content.?;
    defer self.allocator.free(verified);
    var verify_file = sshkeys.parse(self.allocator, verified) catch {
        keysJobFinish(self, registry, job, 2, .@"error", "the written file could not be parsed; refresh the snapshot", .partial);
        return;
    };
    defer verify_file.deinit(self.allocator);
    if (sshkeys.findByFingerprint(&verify_file, p.fingerprint) != null) {
        keysJobFinish(self, registry, job, 2, .@"error", "the key is still present after the write; refresh the snapshot", .partial);
        return;
    }
    keysJobFinish(self, registry, job, 2, .done, null, .done);
}

/// Staged rotation: the new key is appended and verified while the old
/// key stays usable, then the job waits for an explicit commit
/// (rotateCommit) before the old line is removed. Cancel or failure
/// before the commit leaves both keys in place.
fn keysDriveJobRotate(self: *Context, registry: *keyjobs.Registry, job: *keyjobs.Job) void {
    if (job.verification != null) {
        keysDriveJobRotateCommit(self, registry, job);
        return;
    }
    const p = &job.payload.rotate;
    registry.jobSetStep(job, 0, .running, null);
    if (keysJobCancelDrive(self, registry, job, 0)) return;
    var privilege: KeysPrivilege = .none;
    if (!keysJobRemotePreamble(self, registry, job, 0, &privilege)) return;
    const privileged = keysJobPrivileged(job, privilege);
    var state = keysJobCheckSource(self, registry, job, privileged) orelse return;
    defer self.allocator.free(state.content);
    defer state.parsed.deinit(self.allocator);
    if (keysJobFindTarget(&state.parsed, p.old_fingerprint, p.line_hash) == null) {
        keysJobFinish(self, registry, job, 0, .conflict, "the reviewed line changed; refresh and review again", .partial);
        return;
    }
    registry.jobSetStep(job, 0, .done, null);

    registry.jobSetStep(job, 1, .running, null);
    if (keysJobCancelDrive(self, registry, job, 1)) return;
    const staged = sshkeys.appendLine(self.allocator, state.content, p.new_line) catch {
        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(staged);
    var err_buf: [256]u8 = undefined;
    var staged_write_hash: ?[]u8 = null;
    defer if (staged_write_hash) |h| self.allocator.free(h);
    if (keysJobWriteSource(self, job.server_id, job.source_path, staged, state.guard, null, job.account_name, privileged, &err_buf, &staged_write_hash)) |err| {
        keysJobFinish(self, registry, job, 1, .@"error", err, .partial);
        return;
    }
    registry.jobSetStep(job, 1, .done, null);

    registry.jobSetStep(job, 2, .running, null);
    const verify = keysJobReadSource(self, job.server_id, job.source_path, privileged);
    if (verify.status != .readable) {
        keysJobFinish(self, registry, job, 2, .@"error", "the staged file could not be re-read; both keys may be present", .partial);
        return;
    }
    const staged_content = verify.content.?;
    defer self.allocator.free(staged_content);
    var staged_file = sshkeys.parse(self.allocator, staged_content) catch {
        keysJobFinish(self, registry, job, 2, .@"error", "the staged file could not be parsed; both keys may be present", .partial);
        return;
    };
    defer staged_file.deinit(self.allocator);
    if (sshkeys.findByFingerprint(&staged_file, p.new_fingerprint) == null or
        sshkeys.findByFingerprint(&staged_file, p.old_fingerprint) == null)
    {
        keysJobFinish(self, registry, job, 2, .@"error", "the staged file does not hold both keys; review the source before retrying", .partial);
        return;
    }
    const staged_sha = sshkeys.fileSha256(self.allocator, staged_content) catch {
        keysJobFinish(self, registry, job, 2, .@"error", "out of memory", .partial);
        return;
    };
    registry.jobSetStagedHash(job, staged_sha);
    registry.jobSetStep(job, 2, .done, null);

    // Park until rotateCommit supplies the verification. Not terminal:
    // no audit row yet.
    registry.jobSetStep(job, 3, .waiting, null);
    registry.jobSetState(job, .waiting_for_verification);
}

fn keysDriveJobRotateCommit(self: *Context, registry: *keyjobs.Registry, job: *keyjobs.Job) void {
    const p = &job.payload.rotate;
    const verification = &job.verification.?;
    registry.jobSetStep(job, 3, .running, null);
    if (keysJobCancelDrive(self, registry, job, 3)) return;
    var err_buf: [256]u8 = undefined;
    const verification_error = keysVerifyNewKey(self, job, verification, &err_buf);
    // The verification secret is no longer needed after the fresh auth
    // attempt. Clear it before any subsequent remote write or retained state.
    registry.jobClearSecrets(job);
    if (verification_error) |err| {
        // Both keys remain on the server.
        keysJobFinish(self, registry, job, 3, .@"error", err, .partial);
        return;
    }
    registry.jobSetStep(job, 3, .done, null);

    registry.jobSetStep(job, 4, .running, null);
    if (keysJobCancelDrive(self, registry, job, 4)) return;
    if (!keysSessionReady(self, job.server_id)) {
        keysJobFinish(self, registry, job, 4, .@"error", "not connected; the old key was retained", .partial);
        return;
    }
    const privilege = keysProbePrivilege(self, job.server_id);
    if (job.account_name != null and privilege == .none) {
        keysJobFinish(self, registry, job, 4, .@"error", "writing a role source requires root or approved sudo -n; the old key was retained", .partial);
        return;
    }
    const privileged = keysJobPrivileged(job, privilege);
    const read = keysJobReadSource(self, job.server_id, job.source_path, privileged);
    if (read.status != .readable) {
        keysJobFinish(self, registry, job, 4, .@"error", "the source could not be re-read; the old key was retained", .partial);
        return;
    }
    const content = read.content.?;
    defer self.allocator.free(content);
    const current_sha = sshkeys.fileSha256(self.allocator, content) catch {
        keysJobFinish(self, registry, job, 4, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(current_sha);
    const staged_sha = job.staged_file_sha256 orelse {
        keysJobFinish(self, registry, job, 4, .@"error", "the staged state was lost; refresh and rotate again", .partial);
        return;
    };
    if (!std.mem.eql(u8, current_sha, staged_sha)) {
        keysJobFinish(self, registry, job, 4, .conflict, "the file changed after staging; the old key was retained", .partial);
        return;
    }
    var parsed = sshkeys.parse(self.allocator, content) catch {
        keysJobFinish(self, registry, job, 4, .@"error", "the file could not be parsed; the old key was retained", .partial);
        return;
    };
    defer parsed.deinit(self.allocator);
    const target = keysJobFindTarget(&parsed, p.old_fingerprint, p.line_hash) orelse {
        keysJobFinish(self, registry, job, 4, .conflict, "the old line changed after staging; the old key was retained", .partial);
        return;
    };
    const new_content = sshkeys.rewrite(self.allocator, &parsed, target.line_index, null) catch {
        keysJobFinish(self, registry, job, 4, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(new_content);
    const guard: KeysWriteGuard = .{ .sha256 = staged_sha };
    var write_hash: ?[]u8 = null;
    defer if (write_hash) |h| self.allocator.free(h);
    if (keysJobWriteSource(self, job.server_id, job.source_path, new_content, guard, null, job.account_name, privileged, &err_buf, &write_hash)) |err| {
        keysJobFinish(self, registry, job, 4, .@"error", err, .partial);
        return;
    }
    registry.jobSetStep(job, 4, .done, null);

    registry.jobSetStep(job, 5, .running, null);
    const verify = keysJobReadSource(self, job.server_id, job.source_path, privileged);
    if (verify.status != .readable) {
        keysJobFinish(self, registry, job, 5, .@"error", "the final file could not be verified; refresh the snapshot", .partial);
        return;
    }
    const verified = verify.content.?;
    defer self.allocator.free(verified);
    var verify_file = sshkeys.parse(self.allocator, verified) catch {
        keysJobFinish(self, registry, job, 5, .@"error", "the final file could not be parsed; refresh the snapshot", .partial);
        return;
    };
    defer verify_file.deinit(self.allocator);
    if (sshkeys.findByFingerprint(&verify_file, p.new_fingerprint) == null or
        sshkeys.findByFingerprint(&verify_file, p.old_fingerprint) != null)
    {
        keysJobFinish(self, registry, job, 5, .@"error", "the final file does not match the rotation; refresh the snapshot", .partial);
        return;
    }
    if (keysBuildResult(self, &.{.{ "new_fingerprint", p.new_fingerprint }})) |fragment| {
        registry.jobSetResult(job, fragment);
    }
    keysJobFinish(self, registry, job, 5, .done, null, .done);
}

/// The rotation verification: a temporary key-auth session as the target
/// account with the host fingerprint copied from the main session (no
/// new trust prompt). Reaching `ready` proves the new key signs in;
/// forced-command accounts authenticate the same way.
fn keysVerifyNewKey(self: *Context, job: *keyjobs.Job, verification: *const keyjobs.RotateVerification, err_buf: []u8) ?[]const u8 {
    switch (verification.*) {
        .external_confirmation => |*v| {
            const p = &job.payload.rotate;
            if (!std.mem.eql(u8, v.confirm_fingerprint, p.new_fingerprint)) {
                return "the typed fingerprint does not match the staged key; both keys remain";
            }
            return null;
        },
        .local_private_key => |*v| {
            const base = self.manager.get(job.server_id) orelse return "not connected";
            if (base.status.load(.acquire) != .ready) return "session not ready";
            const temp_id = std.fmt.allocPrint(self.allocator, "keys-verify-{s}", .{job.id}) catch return "out of memory";
            defer self.allocator.free(temp_id);
            const account = job.account_name orelse base.server.user;
            const temp_server = servers.Server{
                .id = temp_id,
                .name = temp_id,
                .host = base.server.host,
                .port = base.server.port,
                .user = account,
                .auth_method = .key,
                .key_path = v.path,
                .key_has_passphrase = v.passphrase != null,
                .host_fingerprint = base.server.host_fingerprint,
                .via_server_id = base.server.via_server_id,
            };
            self.manager.disconnect(temp_id); // clear any stale record
            _ = self.manager.connect(temp_server, null, v.passphrase) catch {
                return "the verification connection could not be started; both keys remain";
            };
            defer self.manager.disconnect(temp_id);
            const deadline = std.Io.Timestamp.now(self.io, .real).nanoseconds + keys_verify_wait_ns;
            while (std.Io.Timestamp.now(self.io, .real).nanoseconds < deadline) {
                const session = self.manager.get(temp_id) orelse return "the verification connection was lost; both keys remain";
                const status = session.status.load(.acquire);
                if (status == .ready) return null;
                if (status == .closed or status == .@"error" or status == .needs_trust) {
                    const text = session.errorText();
                    return std.fmt.bufPrint(err_buf, "the new key could not sign in as {s} ({s}); both keys remain", .{ account, if (text.len > 0) text else status.jsonName() }) catch "the new key could not sign in; both keys remain";
                }
                std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(50), .awake) catch return "interrupted; both keys remain";
            }
            return "verification timed out; both keys remain";
        },
    }
}

// --- capability probes -------------------------------------------------------

/// internal-sftp gained read-only mode (-R) in OpenSSH 8.5; detect the
/// server version through the local `ssh -V` banner (spec 08 §13 lists
/// this as an assumption: the ssh client and sshd ship together on the
/// supported servers).
fn keysOpensshAllowsInternalReadOnly(self: *Context, server_id: []const u8) bool {
    var ver = keysExec(self, server_id, "ssh -V 2>&1") orelse return false;
    defer ver.output.deinit(self.allocator);
    const text = std.mem.trim(u8, ver.output.items, " \t\r\n");
    const prefix = "OpenSSH_";
    const start = std.mem.indexOf(u8, text, prefix) orelse return false;
    const rest = text[start + prefix.len ..];
    const dot = std.mem.indexOfScalar(u8, rest, '.') orelse return false;
    const major = std.fmt.parseInt(u32, rest[0..dot], 10) catch return false;
    var minor_end = dot + 1;
    while (minor_end < rest.len and std.ascii.isDigit(rest[minor_end])) minor_end += 1;
    const minor = std.fmt.parseInt(u32, rest[dot + 1 .. minor_end], 10) catch return false;
    return major > 8 or (major == 8 and minor >= 5);
}

/// A binary SFTP subsystem is probed with `-R`: an option-error line
/// means the build is too old for read-only mode. Leading characters of
/// the diagnostic are matched loosely ("illegal"/"unknown"/"invalid").
fn keysBinarySubsystemAllowsReadOnly(self: *Context, server_id: []const u8, binary: []const u8) bool {
    const quoted = shellquote.quote(self.allocator, binary) catch return false;
    defer self.allocator.free(quoted);
    const cmd = std.fmt.allocPrint(self.allocator, "{s} -R </dev/null 2>&1 | head -c 512", .{quoted}) catch return false;
    defer self.allocator.free(cmd);
    var probe = keysExec(self, server_id, cmd) orelse return false;
    defer probe.output.deinit(self.allocator);
    const text = probe.output.items;
    if (std.mem.indexOf(u8, text, "llegal option") != null or
        std.mem.indexOf(u8, text, "nknown option") != null or
        std.mem.indexOf(u8, text, "nvalid option") != null) return false;
    return true;
}

/// Confirms the exact frozen forced command still works on this server
/// before a read-only role is created or repaired against it.
fn keysProbeForcedCommand(self: *Context, server_id: []const u8, forced_command: []const u8) bool {
    if (!std.mem.endsWith(u8, forced_command, " -R")) return false;
    const subsystem = forced_command[0 .. forced_command.len - " -R".len];
    if (subsystem.len == 0) return false;
    if (std.mem.eql(u8, subsystem, "internal-sftp")) {
        return keysOpensshAllowsInternalReadOnly(self, server_id);
    }
    return keysBinarySubsystemAllowsReadOnly(self, server_id, subsystem);
}

fn keysChmod(self: *Context, server_id: []const u8, path: []const u8, mode: u32) bool {
    const out = self.allocator.create(sessions.SftpOutcome) catch return false;
    out.* = .{ .allocator = self.allocator };
    self.manager.sftpChmod(server_id, path, mode, out) catch {
        self.allocator.destroy(out);
        return false;
    };
    if (!keysSftpWait(self, out)) return false;
    defer self.allocator.destroy(out);
    defer if (out.json) |j| self.allocator.free(j);
    return out.ok;
}

/// Removes one file; a missing file counts as removed (idempotent
/// deploy-key deletion).
fn keysRmFile(self: *Context, server_id: []const u8, path: []const u8) bool {
    const out = self.allocator.create(sessions.SftpOutcome) catch return false;
    out.* = .{ .allocator = self.allocator };
    self.manager.sftpRm(server_id, path, false, 0, out) catch {
        self.allocator.destroy(out);
        return false;
    };
    if (!keysSftpWait(self, out)) return false;
    defer self.allocator.destroy(out);
    defer if (out.json) |j| self.allocator.free(j);
    if (out.ok) return true;
    return out.fx == ssh.c.LIBSSH2_FX_NO_SUCH_FILE;
}

fn keysRunPlanCommand(self: *Context, server_id: []const u8, privilege: KeysPrivilege, command: []const u8) ?sessions.ExecOutcome {
    if (privilege == .sudo_n) {
        // The approved role-create command is compound; quote it as one shell
        // program so every segment runs under sudo rather than only the first.
        const quoted = shellquote.quote(self.allocator, command) catch return null;
        defer self.allocator.free(quoted);
        const cmd = std.fmt.allocPrint(self.allocator, "sudo -n sh -c {s}", .{quoted}) catch return null;
        defer self.allocator.free(cmd);
        return keysExec(self, server_id, cmd);
    }
    return keysExec(self, server_id, command);
}

// --- role job drivers --------------------------------------------------------

fn keysDriveJobRole(self: *Context, registry: *keyjobs.Registry, job: *keyjobs.Job) void {
    registry.jobSetStep(job, 0, .running, null);
    if (keysJobCancelDrive(self, registry, job, 0)) return;
    if (!keysSessionReady(self, job.server_id)) {
        keysJobFinish(self, registry, job, 0, .@"error", "not connected", .partial);
        return;
    }
    const privilege = keysProbePrivilege(self, job.server_id);
    if (privilege == .none) {
        keysJobFinish(self, registry, job, 0, .@"error", "root or approved sudo -n is no longer available; nothing was changed", .partial);
        return;
    }
    registry.jobSetStep(job, 0, .done, null);
    switch (job.kind) {
        .role_create => keysDriveJobRoleCreate(self, registry, job, privilege),
        .role_repair => keysDriveJobRoleRepair(self, registry, job, privilege),
        .role_delete => keysDriveJobRoleDelete(self, registry, job, privilege),
        else => unreachable,
    }
}

/// Moves a parsed manifest slice into an owned list.
fn keysAdoptRolesEntries(self: *Context, list: *std.ArrayList(RolesManifestEntry), found: []RolesManifestEntry) void {
    for (found) |*entry| {
        list.append(self.allocator, entry.*) catch {
            entry.deinit(self.allocator);
            continue;
        };
    }
    self.allocator.free(found);
}

fn keysDriveJobRoleCreate(self: *Context, registry: *keyjobs.Registry, job: *keyjobs.Job, privilege: KeysPrivilege) void {
    const p = &job.payload.role;
    const read_only = std.mem.eql(u8, p.kind, "read_only_sftp");

    registry.jobSetStep(job, 1, .running, null);
    if (read_only) {
        if (p.forced_command.len == 0) {
            keysJobFinish(self, registry, job, 1, .@"error", "the read-only SFTP capability was not detected in the snapshot; take a fresh snapshot", .partial);
            return;
        }
        if (!keysProbeForcedCommand(self, job.server_id, p.forced_command)) {
            keysJobFinish(self, registry, job, 1, .@"error", "read-only SFTP is not available on this server; nothing was changed", .partial);
            return;
        }
    }
    registry.jobSetStep(job, 1, .done, null);

    registry.jobSetStep(job, 2, .running, null);
    if (keysJobCancelDrive(self, registry, job, 2)) return;
    if (keysAccountFacts(self, job.server_id, p.name)) |existing| {
        var facts = existing;
        facts.deinit(self.allocator);
        keysJobFinish(self, registry, job, 2, .conflict, "an account with this name already exists and is not Oars-managed", .partial);
        return;
    }
    for (p.commands) |command| {
        var check = keysRunPlanCommand(self, job.server_id, privilege, command) orelse {
            keysJobFinish(self, registry, job, 2, .@"error", "not connected", .partial);
            return;
        };
        const exit = check.exit;
        var tail_buf: [128]u8 = undefined;
        const out_text = std.mem.trim(u8, check.output.items, " \t\r\n");
        const tail = std.fmt.bufPrint(&tail_buf, "{s}", .{out_text[0..@min(out_text.len, 100)]}) catch "";
        check.output.deinit(self.allocator);
        if (exit != 0) {
            var msg_buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "account creation failed ({s}); check the account state before retrying", .{tail}) catch "account creation failed; check the account state before retrying";
            keysJobFinish(self, registry, job, 2, .@"error", msg, .partial);
            return;
        }
    }
    registry.jobSetStep(job, 2, .done, null);

    registry.jobSetStep(job, 3, .running, null);
    if (keysJobCancelDrive(self, registry, job, 3)) return;
    if (p.first_key_line) |line| {
        var facts = keysAccountFacts(self, job.server_id, p.name) orelse {
            keysJobFinish(self, registry, job, 3, .@"error", "the new account could not be resolved", .partial);
            return;
        };
        defer facts.deinit(self.allocator);
        const source_path = std.fmt.allocPrint(self.allocator, "{s}/.ssh/authorized_keys", .{facts.home}) catch {
            keysJobFinish(self, registry, job, 3, .@"error", "out of memory", .partial);
            return;
        };
        defer self.allocator.free(source_path);
        if (keysEnsureDirFor(self, job.server_id, source_path, p.name, privilege)) |err| {
            keysJobFinish(self, registry, job, 3, .@"error", err, .partial);
            return;
        }
        const content = std.fmt.allocPrint(self.allocator, "{s}\n", .{line}) catch {
            keysJobFinish(self, registry, job, 3, .@"error", "out of memory", .partial);
            return;
        };
        defer self.allocator.free(content);
        var err_buf: [256]u8 = undefined;
        var hash: ?[]u8 = null;
        defer if (hash) |h| self.allocator.free(h);
        if (keysJobWriteSource(self, job.server_id, source_path, content, .missing, 0o600, p.name, privilege == .sudo_n, &err_buf, &hash)) |err| {
            keysJobFinish(self, registry, job, 3, .@"error", err, .partial);
            return;
        }
    }
    registry.jobSetStep(job, 3, .done, null);

    registry.jobSetStep(job, 4, .running, null);
    if (keysJobCancelDrive(self, registry, job, 4)) return;
    var entries: std.ArrayList(RolesManifestEntry) = .empty;
    defer {
        for (entries.items) |*entry| entry.deinit(self.allocator);
        entries.deinit(self.allocator);
    }
    switch (keysRolesManifestRead(self, job.server_id, privilege)) {
        .ok => |found| keysAdoptRolesEntries(self, &entries, found),
        .missing => {},
        .corrupt => keysQuarantine(self, job.server_id, roles_marker_path, privilege),
        .unreadable => {
            keysJobFinish(self, registry, job, 4, .@"error", "the role policy manifest could not be read", .partial);
            return;
        },
    }
    entries.append(self.allocator, .{
        .name = self.allocator.dupe(u8, p.name) catch {
            keysJobFinish(self, registry, job, 4, .@"error", "out of memory", .partial);
            return;
        },
        .kind = self.allocator.dupe(u8, p.kind) catch {
            keysJobFinish(self, registry, job, 4, .@"error", "out of memory", .partial);
            return;
        },
        .forced_command = self.allocator.dupe(u8, p.forced_command) catch {
            keysJobFinish(self, registry, job, 4, .@"error", "out of memory", .partial);
            return;
        },
        .created_at_ms = keysNowMs(self),
    }) catch {
        keysJobFinish(self, registry, job, 4, .@"error", "out of memory", .partial);
        return;
    };
    if (keysRolesManifestWrite(self, job.server_id, privilege, entries.items)) |err| {
        keysJobFinish(self, registry, job, 4, .@"error", err, .partial);
        return;
    }
    registry.jobSetStep(job, 4, .done, null);

    registry.jobSetStep(job, 5, .running, null);
    var verify_facts = keysAccountFacts(self, job.server_id, p.name) orelse {
        keysJobFinish(self, registry, job, 5, .@"error", "the account could not be verified after creation", .partial);
        return;
    };
    defer verify_facts.deinit(self.allocator);
    if (p.first_key_line) |line| {
        const source_path = std.fmt.allocPrint(self.allocator, "{s}/.ssh/authorized_keys", .{verify_facts.home}) catch {
            keysJobFinish(self, registry, job, 5, .@"error", "out of memory", .partial);
            return;
        };
        defer self.allocator.free(source_path);
        // The fingerprint of the key we installed, from the frozen line.
        var line_file = sshkeys.parse(self.allocator, line) catch {
            keysJobFinish(self, registry, job, 5, .@"error", "the installed key line could not be parsed", .partial);
            return;
        };
        defer line_file.deinit(self.allocator);
        if (line_file.keys.len != 1 or !line_file.keys[0].parsed) {
            keysJobFinish(self, registry, job, 5, .@"error", "the installed key line could not be parsed", .partial);
            return;
        }
        const fingerprint = line_file.keys[0].fingerprint_sha256;
        const read = keysJobReadSource(self, job.server_id, source_path, privilege == .sudo_n);
        if (read.status != .readable) {
            keysJobFinish(self, registry, job, 5, .@"error", "the installed key could not be verified", .partial);
            return;
        }
        const content = read.content.?;
        defer self.allocator.free(content);
        var parsed = sshkeys.parse(self.allocator, content) catch {
            keysJobFinish(self, registry, job, 5, .@"error", "the installed key could not be verified", .partial);
            return;
        };
        defer parsed.deinit(self.allocator);
        const found = sshkeys.findByFingerprint(&parsed, fingerprint) orelse {
            keysJobFinish(self, registry, job, 5, .@"error", "the installed key was not found after the write", .partial);
            return;
        };
        if (read_only and !keyjobs.verifyReadOnlyKeyOptions(found.options, p.forced_command)) {
            keysJobFinish(self, registry, job, 5, .@"error", "the installed key does not carry the exact read-only policy", .partial);
            return;
        }
    }
    keysJobFinish(self, registry, job, 5, .done, null, .done);
}

fn keysDriveJobRoleRepair(self: *Context, registry: *keyjobs.Registry, job: *keyjobs.Job, privilege: KeysPrivilege) void {
    const p = &job.payload.role;
    const read_only = std.mem.eql(u8, p.kind, "read_only_sftp");

    registry.jobSetStep(job, 1, .running, null);
    if (keysJobCancelDrive(self, registry, job, 1)) return;
    var facts = keysAccountFacts(self, job.server_id, p.name) orelse {
        keysJobFinish(self, registry, job, 1, .@"error", "the account no longer exists; delete the role instead", .partial);
        return;
    };
    defer facts.deinit(self.allocator);
    const source_path = std.fmt.allocPrint(self.allocator, "{s}/.ssh/authorized_keys", .{facts.home}) catch {
        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(source_path);
    const privileged = privilege == .sudo_n;
    if (read_only) {
        if (p.forced_command.len == 0 or !keysProbeForcedCommand(self, job.server_id, p.forced_command)) {
            keysJobFinish(self, registry, job, 1, .@"error", "read-only SFTP is not available on this server; no repair was made", .partial);
            return;
        }
        const read = keysJobReadSource(self, job.server_id, source_path, privileged);
        switch (read.status) {
            .missing => {}, // no keys: only the manifest needs repair
            .readable => {
                var current = read.content.?;
                defer self.allocator.free(current);
                // The write guard names the file as it was read, before
                // any repair rewrite replaces the in-memory content.
                const original_sha = sshkeys.fileSha256(self.allocator, current) catch {
                    keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
                    return;
                };
                defer self.allocator.free(original_sha);
                // Re-apply the exact role options to every divergent key,
                // one rewrite at a time so untouched lines keep their
                // bytes. Malformed rows fail closed.
                while (true) {
                    var parsed = sshkeys.parse(self.allocator, current) catch {
                        keysJobFinish(self, registry, job, 1, .@"error", "the role source could not be parsed; no repair was made", .partial);
                        return;
                    };
                    defer parsed.deinit(self.allocator);
                    var malformed = false;
                    var target_index: ?usize = null;
                    var target_rest: []const u8 = "";
                    for (parsed.keys) |*k| {
                        if (!k.parsed) {
                            malformed = true;
                            break;
                        }
                        if (!keyjobs.verifyReadOnlyKeyOptions(k.options, p.forced_command)) {
                            target_index = k.line_index;
                            target_rest = if (k.comment.len > 0)
                                std.fmt.allocPrint(self.allocator, "{s} {s} {s}", .{ k.key_type, k.key, k.comment }) catch ""
                            else
                                std.fmt.allocPrint(self.allocator, "{s} {s}", .{ k.key_type, k.key }) catch "";
                            break;
                        }
                    }
                    if (malformed) {
                        keysJobFinish(self, registry, job, 1, .@"error", "the role source has rows Oars cannot parse; repair them by hand first", .partial);
                        return;
                    }
                    const index = target_index orelse break;
                    if (target_rest.len == 0) {
                        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
                        return;
                    }
                    defer self.allocator.free(target_rest);
                    const options = keyjobs.readOnlyRoleOptions(self.allocator, p.forced_command) catch {
                        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
                        return;
                    };
                    defer self.allocator.free(options);
                    const new_line = std.fmt.allocPrint(self.allocator, "{s} {s}", .{ options, target_rest }) catch {
                        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
                        return;
                    };
                    defer self.allocator.free(new_line);
                    const rewritten = sshkeys.rewrite(self.allocator, &parsed, index, new_line) catch {
                        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
                        return;
                    };
                    self.allocator.free(current);
                    current = rewritten;
                }
                var err_buf: [256]u8 = undefined;
                var hash: ?[]u8 = null;
                defer if (hash) |h| self.allocator.free(h);
                if (keysJobWriteSource(self, job.server_id, source_path, current, .{ .sha256 = original_sha }, 0o600, p.name, privileged, &err_buf, &hash)) |err| {
                    keysJobFinish(self, registry, job, 1, .@"error", err, .partial);
                    return;
                }
            },
            else => {
                keysJobFinish(self, registry, job, 1, .@"error", "the role source could not be read; no repair was made", .partial);
                return;
            },
        }
    }

    var entries: std.ArrayList(RolesManifestEntry) = .empty;
    defer {
        for (entries.items) |*entry| entry.deinit(self.allocator);
        entries.deinit(self.allocator);
    }
    switch (keysRolesManifestRead(self, job.server_id, privilege)) {
        .ok => |found| keysAdoptRolesEntries(self, &entries, found),
        .missing => {},
        .corrupt => keysQuarantine(self, job.server_id, roles_marker_path, privilege),
        .unreadable => {
            keysJobFinish(self, registry, job, 1, .@"error", "the role policy manifest could not be read", .partial);
            return;
        },
    }
    var replaced = false;
    for (entries.items) |*entry| {
        if (!std.mem.eql(u8, entry.name, p.name)) continue;
        self.allocator.free(entry.kind);
        entry.kind = self.allocator.dupe(u8, p.kind) catch {
            keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
            return;
        };
        self.allocator.free(entry.forced_command);
        entry.forced_command = self.allocator.dupe(u8, p.forced_command) catch {
            keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
            return;
        };
        replaced = true;
    }
    if (!replaced) {
        entries.append(self.allocator, .{
            .name = self.allocator.dupe(u8, p.name) catch {
                keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
                return;
            },
            .kind = self.allocator.dupe(u8, p.kind) catch {
                keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
                return;
            },
            .forced_command = self.allocator.dupe(u8, p.forced_command) catch {
                keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
                return;
            },
            .created_at_ms = keysNowMs(self),
        }) catch {
            keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
            return;
        };
    }
    if (keysRolesManifestWrite(self, job.server_id, privilege, entries.items)) |err| {
        keysJobFinish(self, registry, job, 1, .@"error", err, .partial);
        return;
    }
    registry.jobSetStep(job, 1, .done, null);

    registry.jobSetStep(job, 2, .running, null);
    if (read_only) {
        const verify = keysJobReadSource(self, job.server_id, source_path, privileged);
        if (verify.status == .readable) {
            const content = verify.content.?;
            defer self.allocator.free(content);
            var parsed = sshkeys.parse(self.allocator, content) catch {
                keysJobFinish(self, registry, job, 2, .@"error", "the repaired source could not be parsed", .partial);
                return;
            };
            defer parsed.deinit(self.allocator);
            for (parsed.keys) |*k| {
                if (k.parsed and !keyjobs.verifyReadOnlyKeyOptions(k.options, p.forced_command)) {
                    keysJobFinish(self, registry, job, 2, .@"error", "a key still lacks the exact read-only policy", .partial);
                    return;
                }
            }
        }
    }
    keysJobFinish(self, registry, job, 2, .done, null, .done);
}

fn keysDriveJobRoleDelete(self: *Context, registry: *keyjobs.Registry, job: *keyjobs.Job, privilege: KeysPrivilege) void {
    const p = &job.payload.role;

    registry.jobSetStep(job, 1, .running, null);
    if (keysJobCancelDrive(self, registry, job, 1)) return;
    for (p.commands) |command| {
        var check = keysRunPlanCommand(self, job.server_id, privilege, command) orelse {
            keysJobFinish(self, registry, job, 1, .@"error", "not connected", .partial);
            return;
        };
        const exit = check.exit;
        check.output.deinit(self.allocator);
        if (exit != 0) {
            // Tolerate an already-removed account; anything else fails.
            if (keysAccountFacts(self, job.server_id, p.name)) |existing| {
                var facts = existing;
                facts.deinit(self.allocator);
                keysJobFinish(self, registry, job, 1, .@"error", "account deletion failed", .partial);
                return;
            }
        }
    }
    registry.jobSetStep(job, 1, .done, null);

    registry.jobSetStep(job, 2, .running, null);
    var entries: std.ArrayList(RolesManifestEntry) = .empty;
    defer {
        for (entries.items) |*entry| entry.deinit(self.allocator);
        entries.deinit(self.allocator);
    }
    switch (keysRolesManifestRead(self, job.server_id, privilege)) {
        .ok => |found| keysAdoptRolesEntries(self, &entries, found),
        .missing => {},
        .corrupt => keysQuarantine(self, job.server_id, roles_marker_path, privilege),
        .unreadable => {
            keysJobFinish(self, registry, job, 2, .@"error", "the role policy manifest could not be read; the account is already deleted", .partial);
            return;
        },
    }
    var i: usize = 0;
    while (i < entries.items.len) {
        if (std.mem.eql(u8, entries.items[i].name, p.name)) {
            const removed = entries.orderedRemove(i);
            var mutable = removed;
            mutable.deinit(self.allocator);
        } else {
            i += 1;
        }
    }
    if (keysRolesManifestWrite(self, job.server_id, privilege, entries.items)) |err| {
        keysJobFinish(self, registry, job, 2, .@"error", err, .partial);
        return;
    }
    registry.jobSetStep(job, 2, .done, null);
    keysJobFinish(self, registry, job, 2, .done, null, .done);
}

// --- deploy-key job drivers ----------------------------------------------------

fn keysDriveJobDeployGenerate(self: *Context, registry: *keyjobs.Registry, job: *keyjobs.Job) void {
    const p = &job.payload.deploy_generate;
    registry.jobSetStep(job, 0, .running, null);
    if (keysJobCancelDrive(self, registry, job, 0)) return;
    if (!keysSessionReady(self, job.server_id)) {
        keysJobFinish(self, registry, job, 0, .@"error", "not connected", .partial);
        return;
    }
    var facts = keysAccountFacts(self, job.server_id, null) orelse {
        keysJobFinish(self, registry, job, 0, .@"error", "the connected account could not be resolved", .partial);
        return;
    };
    defer facts.deinit(self.allocator);
    var entries: std.ArrayList(keyjobs.DeployKeyEntry) = .empty;
    defer {
        for (entries.items) |*entry| entry.deinit(self.allocator);
        entries.deinit(self.allocator);
    }
    switch (keysDeployManifestRead(self, job.server_id, facts.home)) {
        .ok => |found| {
            for (found) |*entry| {
                entries.append(self.allocator, entry.*) catch {
                    entry.deinit(self.allocator);
                    continue;
                };
            }
            self.allocator.free(found);
        },
        .missing => {},
        .corrupt => {
            if (keysDeployManifestPath(self, facts.home)) |path| {
                defer self.allocator.free(path);
                keysQuarantine(self, job.server_id, path, .root);
            }
        },
        .unreadable => {
            keysJobFinish(self, registry, job, 0, .@"error", "the deploy-key manifest could not be read", .partial);
            return;
        },
    }
    if (entries.items.len >= keyjobs.max_deploy_manifest_entries) {
        keysJobFinish(self, registry, job, 0, .@"error", "the deploy-key manifest is full (64 entries); delete one first", .partial);
        return;
    }
    registry.jobSetStep(job, 0, .done, null);

    registry.jobSetStep(job, 1, .running, null);
    if (keysJobCancelDrive(self, registry, job, 1)) return;
    const deploy_id = keyjobs.randomId(self.allocator, self.io, "dk") catch {
        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(deploy_id);
    const key_path = std.fmt.allocPrint(self.allocator, "{s}/.ssh/{s}{s}", .{ facts.home, deploy_key_prefix, deploy_id }) catch {
        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(key_path);
    if (sshkeysEnsureSshDir(self, job.server_id, key_path)) |err| {
        keysJobFinish(self, registry, job, 1, .@"error", err, .partial);
        return;
    }
    const comment_text = if (p.comment) |c|
        self.allocator.dupe(u8, c) catch {
            keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
            return;
        }
    else
        std.fmt.allocPrint(self.allocator, "oars-deploy:{s}", .{p.repository_label}) catch {
            keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
            return;
        };
    defer self.allocator.free(comment_text);
    const quoted_path = shellquote.quote(self.allocator, key_path) catch {
        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(quoted_path);
    const quoted_comment = shellquote.quote(self.allocator, comment_text) catch {
        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(quoted_comment);
    // No passphrase: deploy keys sign unattended Git pulls. The private
    // key stays on the server at 0600; authorized_keys is never touched.
    const gen_cmd = std.fmt.allocPrint(self.allocator, "ssh-keygen -q -t ed25519 -N '' -f {s} -C {s}", .{ quoted_path, quoted_comment }) catch {
        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(gen_cmd);
    var gen = keysExec(self, job.server_id, gen_cmd) orelse {
        keysJobFinish(self, registry, job, 1, .@"error", "not connected", .partial);
        return;
    };
    const gen_exit = gen.exit;
    gen.output.deinit(self.allocator);
    if (gen_exit != 0) {
        keysJobFinish(self, registry, job, 1, .@"error", "ssh-keygen failed on the server", .partial);
        return;
    }
    if (!keysChmod(self, job.server_id, key_path, 0o600)) {
        keysJobFinish(self, registry, job, 1, .@"error", "could not set the private key to mode 0600", .partial);
        return;
    }
    const pub_path = std.fmt.allocPrint(self.allocator, "{s}.pub", .{key_path}) catch {
        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(pub_path);
    _ = keysChmod(self, job.server_id, pub_path, 0o644);
    const pub_read = keysReadTyped(self, job.server_id, pub_path, 16 * 1024);
    if (pub_read.status != .readable) {
        keysJobFinish(self, registry, job, 1, .@"error", "the public key could not be read after generation", .partial);
        return;
    }
    const pub_raw = pub_read.content.?;
    defer self.allocator.free(pub_raw);
    const public_key = std.mem.trim(u8, pub_raw, " \t\r\n");
    var pub_file = sshkeys.parse(self.allocator, public_key) catch {
        keysJobFinish(self, registry, job, 1, .@"error", "the generated public key could not be parsed", .partial);
        return;
    };
    defer pub_file.deinit(self.allocator);
    if (pub_file.keys.len != 1 or !pub_file.keys[0].parsed) {
        keysJobFinish(self, registry, job, 1, .@"error", "the generated public key could not be parsed", .partial);
        return;
    }
    const fingerprint = self.allocator.dupe(u8, pub_file.keys[0].fingerprint_sha256) catch {
        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(fingerprint);
    registry.jobSetStep(job, 1, .done, null);

    registry.jobSetStep(job, 2, .running, null);
    if (keysJobCancelDrive(self, registry, job, 2)) return;
    entries.append(self.allocator, .{
        .id = self.allocator.dupe(u8, deploy_id) catch {
            keysJobFinish(self, registry, job, 2, .@"error", "out of memory", .partial);
            return;
        },
        .repository_label = self.allocator.dupe(u8, p.repository_label) catch {
            keysJobFinish(self, registry, job, 2, .@"error", "out of memory", .partial);
            return;
        },
        .path = self.allocator.dupe(u8, key_path) catch {
            keysJobFinish(self, registry, job, 2, .@"error", "out of memory", .partial);
            return;
        },
        .fingerprint = self.allocator.dupe(u8, fingerprint) catch {
            keysJobFinish(self, registry, job, 2, .@"error", "out of memory", .partial);
            return;
        },
        .comment = self.allocator.dupe(u8, comment_text) catch {
            keysJobFinish(self, registry, job, 2, .@"error", "out of memory", .partial);
            return;
        },
        .created_at_ms = keysNowMs(self),
    }) catch {
        keysJobFinish(self, registry, job, 2, .@"error", "out of memory", .partial);
        return;
    };
    if (keysDeployManifestWrite(self, job.server_id, facts.home, entries.items)) |err| {
        keysJobFinish(self, registry, job, 2, .@"error", err, .partial);
        return;
    }
    registry.jobSetStep(job, 2, .done, null);

    registry.jobSetStep(job, 3, .running, null);
    const verify = keysReadTyped(self, job.server_id, key_path, 16 * 1024);
    if (verify.status != .readable) {
        keysJobFinish(self, registry, job, 3, .@"error", "the private key could not be verified after generation", .partial);
        return;
    }
    if (verify.content) |c| self.allocator.free(c);
    if (keysBuildResult(self, &.{
        .{ "deploy_key_id", deploy_id },
        .{ "public_key", public_key },
        .{ "private_path", key_path },
        .{ "fingerprint", fingerprint },
    })) |fragment| {
        registry.jobSetResult(job, fragment);
    }
    keysJobFinish(self, registry, job, 3, .done, null, .done);
}

fn keysDriveJobDeployDelete(self: *Context, registry: *keyjobs.Registry, job: *keyjobs.Job) void {
    const p = &job.payload.deploy_delete;
    registry.jobSetStep(job, 0, .running, null);
    if (keysJobCancelDrive(self, registry, job, 0)) return;
    if (!keysSessionReady(self, job.server_id)) {
        keysJobFinish(self, registry, job, 0, .@"error", "not connected", .partial);
        return;
    }
    var facts = keysAccountFacts(self, job.server_id, null) orelse {
        keysJobFinish(self, registry, job, 0, .@"error", "the connected account could not be resolved", .partial);
        return;
    };
    defer facts.deinit(self.allocator);
    var entries: std.ArrayList(keyjobs.DeployKeyEntry) = .empty;
    defer {
        for (entries.items) |*entry| entry.deinit(self.allocator);
        entries.deinit(self.allocator);
    }
    switch (keysDeployManifestRead(self, job.server_id, facts.home)) {
        .ok => |found| {
            for (found) |*entry| {
                entries.append(self.allocator, entry.*) catch {
                    entry.deinit(self.allocator);
                    continue;
                };
            }
            self.allocator.free(found);
        },
        .missing => {},
        .corrupt => {
            keysJobFinish(self, registry, job, 0, .@"error", "the deploy-key manifest is corrupt; take a snapshot to quarantine it first", .partial);
            return;
        },
        .unreadable => {
            keysJobFinish(self, registry, job, 0, .@"error", "the deploy-key manifest could not be read", .partial);
            return;
        },
    }
    var target_index: ?usize = null;
    for (entries.items, 0..) |*entry, i| {
        if (std.mem.eql(u8, entry.id, p.deploy_key_id)) {
            target_index = i;
            break;
        }
    }
    const index = target_index orelse {
        keysJobFinish(self, registry, job, 0, .conflict, "the deploy key is no longer in the manifest; refresh the snapshot", .partial);
        return;
    };
    if (!std.mem.eql(u8, entries.items[index].fingerprint, p.confirm_fingerprint)) {
        keysJobFinish(self, registry, job, 0, .conflict, "the typed fingerprint does not match the deploy key", .partial);
        return;
    }
    const key_path = self.allocator.dupe(u8, entries.items[index].path) catch {
        keysJobFinish(self, registry, job, 0, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(key_path);
    registry.jobSetStep(job, 0, .done, null);

    registry.jobSetStep(job, 1, .running, null);
    if (keysJobCancelDrive(self, registry, job, 1)) return;
    const pub_path = std.fmt.allocPrint(self.allocator, "{s}.pub", .{key_path}) catch {
        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(pub_path);
    // authorized_keys is never part of deploy-key deletion.
    if (!keysRmFile(self, job.server_id, key_path) or !keysRmFile(self, job.server_id, pub_path)) {
        keysJobFinish(self, registry, job, 1, .@"error", "the key files could not be removed", .partial);
        return;
    }
    registry.jobSetStep(job, 1, .done, null);

    registry.jobSetStep(job, 2, .running, null);
    const removed = entries.orderedRemove(index);
    var mutable = removed;
    mutable.deinit(self.allocator);
    if (keysDeployManifestWrite(self, job.server_id, facts.home, entries.items)) |err| {
        keysJobFinish(self, registry, job, 2, .@"error", err, .partial);
        return;
    }
    registry.jobSetStep(job, 2, .done, null);
    keysJobFinish(self, registry, job, 2, .done, null, .done);
}

// --- local generation (local job worker) ---------------------------------------

fn keysKeygenErrorText(err: keygen.KeygenError) []const u8 {
    return switch (err) {
        error.InvalidDestination => "the destination path is not usable",
        error.DestinationMissing => "the destination directory does not exist",
        error.DestinationExists => "the destination already exists; nothing was overwritten",
        error.SshKeygenMissing => "OpenSSH ssh-keygen is not installed on this machine",
        error.PtyFailed => "could not create a private terminal for ssh-keygen",
        error.SpawnFailed => "ssh-keygen could not be started",
        error.UnexpectedOutput => "ssh-keygen produced unexpected output; aborted",
        error.PromptFailed => "the ssh-keygen passphrase prompt failed",
        error.GenerationFailed => "ssh-keygen failed",
        error.VerifyFailed => "the generated key could not be verified",
        error.InstallFailed => "the key could not be installed at the destination",
        error.Timeout => "ssh-keygen timed out",
        error.Canceled => "canceled",
        error.OutOfMemory => "out of memory",
    };
}

fn keysDriveLocalJob(context: *anyopaque, registry: *keyjobs.Registry, job: *keyjobs.Job) void {
    const self = contextOf(context);
    const p = &job.payload.local_generate;
    registry.jobSetStep(job, 0, .running, null);
    const generated = keygen.generate(self.io, self.allocator, .{
        .destination = p.destination,
        .comment = p.comment,
        .passphrase = p.passphrase,
        .cancel = &job.cancel_requested,
    }) catch |err| {
        if (err == error.Canceled) {
            keysJobFinish(self, registry, job, 0, .canceled, null, .canceled);
        } else {
            keysJobFinish(self, registry, job, 0, .@"error", keysKeygenErrorText(err), .partial);
        }
        return;
    };
    defer self.allocator.free(generated.public_key);
    defer self.allocator.free(generated.private_path);
    defer self.allocator.free(generated.fingerprint_sha256);
    registry.jobSetStep(job, 0, .done, null);

    registry.jobSetStep(job, 1, .running, null);
    if (keysJobCancelDrive(self, registry, job, 1)) return;
    // keygen already verified OpenSSH readability and mode 0600 before
    // the no-clobber install. The keychain account is only a name: the
    // frontend stores the passphrase itself when the user opted in.
    const keychain_account = std.fmt.allocPrint(self.allocator, "localkey:{s}", .{generated.fingerprint_sha256}) catch {
        keysJobFinish(self, registry, job, 1, .@"error", "out of memory", .partial);
        return;
    };
    defer self.allocator.free(keychain_account);
    if (keysBuildResult(self, &.{
        .{ "public_key", generated.public_key },
        .{ "private_path", generated.private_path },
        .{ "fingerprint", generated.fingerprint_sha256 },
        .{ "keychain_account", keychain_account },
    })) |fragment| {
        registry.jobSetResult(job, fragment);
    }
    keysJobFinish(self, registry, job, 1, .done, null, .done);
}

// --- driver dispatch -----------------------------------------------------------

fn keysDriveJob(context: *anyopaque, registry: *keyjobs.Registry, job: *keyjobs.Job) void {
    const self = contextOf(context);
    switch (job.kind) {
        .add => keysDriveJobAdd(self, registry, job),
        .revoke => keysDriveJobRevoke(self, registry, job),
        .rotate => keysDriveJobRotate(self, registry, job),
        .role_create, .role_repair, .role_delete => keysDriveJobRole(self, registry, job),
        .deploy_generate => keysDriveJobDeployGenerate(self, registry, job),
        .deploy_delete => keysDriveJobDeployDelete(self, registry, job),
        .local_generate => {}, // claimed by the local worker instead
    }
}

// --- handlers (spec 08) --------------------------------------------------------

const keys_empty_file_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn keysNowNs(self: *Context) i128 {
    return std.Io.Timestamp.now(self.io, .real).nanoseconds;
}

// The find helpers below assume the caller holds the registry lock; the
// returned pointers are only valid until the lock is released.

fn keysFindSnapshotLocked(self: *Context, id: []const u8) ?*keyjobs.Snapshot {
    for (self.keys.snapshots.items) |snap| {
        if (std.mem.eql(u8, snap.id, id)) return snap;
    }
    return null;
}

fn keysFindJobLocked(self: *Context, id: []const u8) ?*keyjobs.Job {
    for (self.keys.jobs.items) |job| {
        if (std.mem.eql(u8, job.id, id)) return job;
    }
    return null;
}

fn keysLastCompletedSnapshotLocked(self: *Context, server_id: []const u8) ?*keyjobs.Snapshot {
    var best: ?*keyjobs.Snapshot = null;
    for (self.keys.snapshots.items) |snap| {
        if (!std.mem.eql(u8, snap.server_id, server_id)) continue;
        if (snap.state != .done and snap.state != .partial) continue;
        if (best == null or snap.created_at_ns > best.?.created_at_ns) best = snap;
    }
    return best;
}

fn keysFindSource(snap: *keyjobs.Snapshot, path: []const u8) ?*keyjobs.Source {
    for (snap.sources.items) |*source| {
        if (std.mem.eql(u8, source.path, path)) return source;
    }
    return null;
}

fn keysFindRole(snap: *keyjobs.Snapshot, name: []const u8) ?*keyjobs.RoleEntry {
    for (snap.roles.items) |*role| {
        if (std.mem.eql(u8, role.name, name)) return role;
    }
    return null;
}

fn keysFindKey(snap: *keyjobs.Snapshot, source_path: []const u8, fingerprint: []const u8) ?*keyjobs.KeyEntry {
    for (snap.keys.items) |*key| {
        if (!key.parsed) continue;
        if (std.mem.eql(u8, key.source_path, source_path) and std.mem.eql(u8, key.fingerprint_sha256, fingerprint)) return key;
    }
    return null;
}

/// Validates the frozen source identity for a mutation. Returns a static
/// error message, or null when the source may be mutated through it.
fn keysValidateSourceLocked(snap: *keyjobs.Snapshot, source_path: []const u8, file_sha256: []const u8) ?[]const u8 {
    const source = keysFindSource(snap, source_path) orelse return "the source is not part of the snapshot; take a fresh snapshot";
    if (!std.mem.eql(u8, source.kind, "static")) return "only static authorized_keys files can be changed";
    if (!keyjobs.statusAllowsMutation(source.status)) return "the source could not be read; resolve the source error before changing it";
    const frozen = source.file_sha256 orelse keys_empty_file_sha256;
    if (!std.mem.eql(u8, frozen, file_sha256)) return "the source changed since the snapshot; refresh and review again";
    return null;
}

/// Builds a job record with every owned field duped. Ownership of
/// `payload` moves to the job; on failure everything is released here.
fn keysNewJob(
    self: *Context,
    kind: keyjobs.JobKind,
    operation_id: []const u8,
    server_id: []const u8,
    account_name: ?[]const u8,
    source_path: []const u8,
    file_sha256: []const u8,
    payload: keyjobs.JobPayload,
) !*keyjobs.Job {
    const job = try self.allocator.create(keyjobs.Job);
    errdefer self.allocator.destroy(job);
    var payload_owned = payload;
    errdefer payload_owned.deinit(self.allocator);
    const now = keysNowNs(self);
    const id = try keyjobs.randomId(self.allocator, self.io, "job");
    errdefer self.allocator.free(id);
    const operation_id_owned = try self.allocator.dupe(u8, operation_id);
    errdefer self.allocator.free(operation_id_owned);
    const server_id_owned = try self.allocator.dupe(u8, server_id);
    errdefer self.allocator.free(server_id_owned);
    const account_name_owned: ?[]u8 = if (account_name) |n| try self.allocator.dupe(u8, n) else null;
    errdefer if (account_name_owned) |n| self.allocator.free(n);
    const source_path_owned = try self.allocator.dupe(u8, source_path);
    errdefer self.allocator.free(source_path_owned);
    const file_sha256_owned = try self.allocator.dupe(u8, file_sha256);
    errdefer self.allocator.free(file_sha256_owned);
    const step_names = kind.steps();
    const steps = try self.allocator.alloc(keyjobs.Step, step_names.len);
    errdefer self.allocator.free(steps);
    for (steps, 0..) |*step, i| step.* = .{ .id = step_names[i] };
    job.* = .{
        .id = id,
        .operation_id = operation_id_owned,
        .server_id = server_id_owned,
        .kind = kind,
        .account_name = account_name_owned,
        .source_path = source_path_owned,
        .file_sha256 = file_sha256_owned,
        .payload = payload_owned,
        .created_at_ns = now,
        .steps = steps,
        .touched_ns = now,
    };
    return job;
}

fn keysNewSnapshot(self: *Context, server_id: []const u8, account_kind: keyjobs.AccountKind, account_name: ?[]const u8) !*keyjobs.Snapshot {
    const snap = try self.allocator.create(keyjobs.Snapshot);
    errdefer self.allocator.destroy(snap);
    const now = keysNowNs(self);
    const id = try keyjobs.randomId(self.allocator, self.io, "snap");
    errdefer self.allocator.free(id);
    const server_id_owned = try self.allocator.dupe(u8, server_id);
    errdefer self.allocator.free(server_id_owned);
    const account_name_owned: ?[]u8 = if (account_name) |n| try self.allocator.dupe(u8, n) else null;
    errdefer if (account_name_owned) |n| self.allocator.free(n);
    snap.* = .{
        .id = id,
        .server_id = server_id_owned,
        .account_kind = account_kind,
        .account_name = account_name_owned,
        .created_at_ns = now,
        .touched_ns = now,
    };
    return snap;
}

fn keysNewPlan(
    self: *Context,
    server_id: []const u8,
    name: []const u8,
    kind: []const u8,
    action: keyjobs.RolePlanAction,
    privilege: []const u8,
    forced_command: []const u8,
    home: ?[]const u8,
    commands: []const []const u8,
    effects: []const []const u8,
) !*keyjobs.RolePlan {
    const plan = try self.allocator.create(keyjobs.RolePlan);
    errdefer self.allocator.destroy(plan);
    const id = try keyjobs.randomId(self.allocator, self.io, "plan");
    errdefer self.allocator.free(id);
    const server_id_owned = try self.allocator.dupe(u8, server_id);
    errdefer self.allocator.free(server_id_owned);
    const name_owned = try self.allocator.dupe(u8, name);
    errdefer self.allocator.free(name_owned);
    const kind_owned = try self.allocator.dupe(u8, kind);
    errdefer self.allocator.free(kind_owned);
    const privilege_owned = try self.allocator.dupe(u8, privilege);
    errdefer self.allocator.free(privilege_owned);
    const forced_owned = try self.allocator.dupe(u8, forced_command);
    errdefer self.allocator.free(forced_owned);
    const home_owned: ?[]u8 = if (home) |h| try self.allocator.dupe(u8, h) else null;
    errdefer if (home_owned) |h| self.allocator.free(h);
    const commands_owned = try self.allocator.alloc([]u8, commands.len);
    var commands_filled: usize = 0;
    errdefer {
        for (commands_owned[0..commands_filled]) |c| self.allocator.free(c);
        self.allocator.free(commands_owned);
    }
    for (commands, 0..) |c, i| {
        commands_owned[i] = try self.allocator.dupe(u8, c);
        commands_filled += 1;
    }
    const effects_owned = try self.allocator.alloc([]u8, effects.len);
    var effects_filled: usize = 0;
    errdefer {
        for (effects_owned[0..effects_filled]) |e| self.allocator.free(e);
        self.allocator.free(effects_owned);
    }
    for (effects, 0..) |e, i| {
        effects_owned[i] = try self.allocator.dupe(u8, e);
        effects_filled += 1;
    }
    const now_ms: i128 = keysNowMs(self);
    plan.* = .{
        .id = id,
        .server_id = server_id_owned,
        .name = name_owned,
        .kind = kind_owned,
        .action = action,
        .privilege = privilege_owned,
        .forced_command = forced_owned,
        .home = home_owned,
        .commands = commands_owned,
        .effects = effects_owned,
        .created_at_ms = now_ms,
        .expires_at_ms = now_ms + keyjobs.plan_ttl_ms,
    };
    return plan;
}

/// One admission audit row per mutation, written when the job is
/// registered. The terminal row comes from the driver (or from
/// handleSshKeysJobCancel for a job that never started).
fn keysAuditAdmission(self: *Context, job: *keyjobs.Job) void {
    var kind_buf: [256]u8 = undefined;
    const kind_text = keyjobs.kindDetail(job, &kind_buf);
    var detail_buf: [320]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "admitted {s}", .{kind_text}) catch "admitted";
    const target = if (job.server_id.len > 0) job.server_id else "local";
    self.audit.append(self.io, job.kind.auditName(), target, detail) catch {};
}

/// Idempotent re-admission: a repeated operation_id returns the existing
/// job (with the fingerprint the original response carried, when the
/// kind defines one).
fn keysRespondExistingJob(output: []u8, match: *const keyjobs.Registry.OperationMatch, fingerprint_field: ?[]const u8) []const u8 {
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job_id\":") catch return output[0..0];
    json.writeJsonString(&writer, match.id) catch return output[0..0];
    if (fingerprint_field) |field| {
        if (match.fingerprint) |fp| {
            writer.writeAll(",") catch return output[0..0];
            json.writeJsonString(&writer, field) catch return output[0..0];
            writer.writeAll(":") catch return output[0..0];
            json.writeJsonString(&writer, fp) catch return output[0..0];
        }
    }
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

// Payload builders. These return real errors, so their errdefers release
// every field on failure; on success ownership moves to the job.

fn keysAddPayload(self: *Context, normalized_line: []const u8, fingerprint: []const u8) !keyjobs.JobPayload {
    const line = try self.allocator.dupe(u8, normalized_line);
    errdefer self.allocator.free(line);
    const fp = try self.allocator.dupe(u8, fingerprint);
    errdefer self.allocator.free(fp);
    return .{ .add = .{ .normalized_line = line, .fingerprint = fp } };
}

fn keysRevokePayload(self: *Context, fingerprint: []const u8, line_hash: []const u8) !keyjobs.JobPayload {
    const fp = try self.allocator.dupe(u8, fingerprint);
    errdefer self.allocator.free(fp);
    const hash = try self.allocator.dupe(u8, line_hash);
    errdefer self.allocator.free(hash);
    return .{ .revoke = .{ .fingerprint = fp, .line_hash = hash } };
}

fn keysRotatePayload(self: *Context, old_fingerprint: []const u8, line_hash: []const u8, new_line: []const u8, new_fingerprint: []const u8, old_options: []const u8) !keyjobs.JobPayload {
    const old_fp = try self.allocator.dupe(u8, old_fingerprint);
    errdefer self.allocator.free(old_fp);
    const hash = try self.allocator.dupe(u8, line_hash);
    errdefer self.allocator.free(hash);
    const line = try self.allocator.dupe(u8, new_line);
    errdefer self.allocator.free(line);
    const new_fp = try self.allocator.dupe(u8, new_fingerprint);
    errdefer self.allocator.free(new_fp);
    const options = try self.allocator.dupe(u8, old_options);
    errdefer self.allocator.free(options);
    return .{ .rotate = .{
        .old_fingerprint = old_fp,
        .line_hash = hash,
        .new_line = line,
        .new_fingerprint = new_fp,
        .old_options = options,
    } };
}

fn keysLocalGeneratePayloadBuild(self: *Context, destination: []const u8, comment: ?[]const u8, passphrase: ?[]const u8) !keyjobs.JobPayload {
    const dest = try self.allocator.dupe(u8, destination);
    errdefer self.allocator.free(dest);
    const comment_owned: ?[]u8 = if (comment) |c| try self.allocator.dupe(u8, c) else null;
    errdefer if (comment_owned) |c| self.allocator.free(c);
    const passphrase_owned: ?[]u8 = if (passphrase) |pp| try self.allocator.dupe(u8, pp) else null;
    errdefer if (passphrase_owned) |pp| {
        std.crypto.secureZero(u8, pp);
        self.allocator.free(pp);
    };
    return .{ .local_generate = .{
        .destination = dest,
        .comment = comment_owned,
        .passphrase = passphrase_owned,
        .remember_passphrase = false,
    } };
}

fn keysDeployGeneratePayload(self: *Context, repository_label: []const u8, comment: ?[]const u8) !keyjobs.JobPayload {
    const label = try self.allocator.dupe(u8, repository_label);
    errdefer self.allocator.free(label);
    const comment_owned: ?[]u8 = if (comment) |c| try self.allocator.dupe(u8, c) else null;
    errdefer if (comment_owned) |c| self.allocator.free(c);
    return .{ .deploy_generate = .{ .repository_label = label, .comment = comment_owned } };
}

fn keysDeployDeletePayload(self: *Context, deploy_key_id: []const u8, confirm_fingerprint: []const u8) !keyjobs.JobPayload {
    const id = try self.allocator.dupe(u8, deploy_key_id);
    errdefer self.allocator.free(id);
    const confirm = try self.allocator.dupe(u8, confirm_fingerprint);
    errdefer self.allocator.free(confirm);
    return .{ .deploy_delete = .{ .deploy_key_id = id, .confirm_fingerprint = confirm } };
}

fn keysLocalKeyVerification(self: *Context, path: []const u8, passphrase: ?[]const u8) !keyjobs.RotateVerification {
    const path_owned = try self.allocator.dupe(u8, path);
    errdefer self.allocator.free(path_owned);
    const passphrase_owned: ?[]u8 = if (passphrase) |pp| try self.allocator.dupe(u8, pp) else null;
    errdefer if (passphrase_owned) |pp| {
        std.crypto.secureZero(u8, pp);
        self.allocator.free(pp);
    };
    return .{ .local_private_key = .{ .path = path_owned, .passphrase = passphrase_owned } };
}

fn handleSshKeysInspect(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysInspectPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.public_key.len == 0 or payload.public_key.len > keys_max_key_text) return respondError(output, "invalid public key");
    if (payload.comment) |comment| {
        if (comment.len > keys_max_comment_text) return respondError(output, "comment is too long");
    }
    const normalized = sshkeys.normalizePublicKey(self.allocator, payload.public_key, payload.comment) catch |err| return respondError(output, switch (err) {
        error.Multiline => "public key must be a single line",
        else => "invalid public key",
    });
    defer {
        self.allocator.free(normalized.line);
        self.allocator.free(normalized.fingerprint_sha256);
    }
    var file = sshkeys.parse(self.allocator, normalized.line) catch return respondError(output, "invalid public key");
    defer file.deinit(self.allocator);
    if (file.keys.len != 1 or !file.keys[0].parsed) return respondError(output, "invalid public key");
    const key = &file.keys[0];
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"normalized_public_key\":") catch return output[0..0];
    json.writeJsonString(&writer, normalized.line) catch return output[0..0];
    writer.writeAll(",\"fingerprint\":") catch return output[0..0];
    json.writeJsonString(&writer, normalized.fingerprint_sha256) catch return output[0..0];
    writer.writeAll(",\"key_type\":") catch return output[0..0];
    json.writeJsonString(&writer, key.key_type) catch return output[0..0];
    if (key.bits) |bits| {
        writer.print(",\"bits\":{d}", .{bits}) catch return output[0..0];
    }
    writer.writeAll(",\"comment\":") catch return output[0..0];
    json.writeJsonString(&writer, key.comment) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleSshKeysSnapshot(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysSnapshotPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    const payload = parsed.value;
    if (!keysValidId(payload.server_id)) return respondError(output, "invalid server_id");
    var kind: keyjobs.AccountKind = .connected;
    var name: ?[]const u8 = null;
    if (std.mem.eql(u8, payload.account.kind, "managed_role")) {
        const role_name = payload.account.name orelse return respondError(output, "a role account name is required");
        if (!access.safeUserName(role_name)) return respondError(output, "invalid role account name");
        kind = .managed_role;
        name = role_name;
    } else if (!std.mem.eql(u8, payload.account.kind, "connected")) {
        return respondError(output, "unknown account kind");
    }
    const snap = keysNewSnapshot(self, payload.server_id, kind, name) catch return respondError(output, "out of memory");
    keysEnsureStarted(self);
    self.keys.registerSnapshot(snap) catch |err| {
        snap.deinit(self.allocator);
        return respondError(output, switch (err) {
            error.TooManyActive => "too many active snapshots; wait for one to finish",
            else => "out of memory",
        });
    };
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"snapshot_id\":") catch return output[0..0];
    json.writeJsonString(&writer, snap.id) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleSshKeysSnapshotPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysSnapshotIdPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    self.keys.lock();
    defer self.keys.unlock();
    const snap = keysFindSnapshotLocked(self, parsed.value.snapshot_id) orelse return respondError(output, "unknown snapshot");
    snap.touched_ns = keysNowNs(self);
    var writer = std.Io.Writer.fixed(output);
    keysSnapshotPollWrite(self, &writer, snap) catch return respondError(output, "response too large");
    return writer.buffered();
}

fn handleSshKeysSnapshotCancel(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysSnapshotIdPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    _ = self.keys.snapshotCancelById(parsed.value.snapshot_id) orelse return respondError(output, "unknown snapshot");
    return ok_json;
}

fn handleSshKeysAdd(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysAddPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    const payload = parsed.value;
    if (!keysValidId(payload.operation_id)) return respondError(output, "operation_id is required");
    if (!keysValidId(payload.snapshot_id)) return respondError(output, "invalid snapshot_id");
    if (!keysValidPath(payload.source_path)) return respondError(output, "invalid source path");
    if (!keysValidHash(payload.file_sha256)) return respondError(output, "invalid file hash");
    if (payload.public_key.len == 0 or payload.public_key.len > keys_max_key_text) return respondError(output, "invalid public key");
    if (payload.comment) |comment| {
        if (comment.len > keys_max_comment_text) return respondError(output, "comment is too long");
    }
    const normalized = sshkeys.normalizePublicKey(self.allocator, payload.public_key, payload.comment) catch |err| return respondError(output, switch (err) {
        error.Multiline => "public key must be a single line",
        else => "invalid public key",
    });
    defer {
        self.allocator.free(normalized.line);
        self.allocator.free(normalized.fingerprint_sha256);
    }
    if (self.keys.operationLookup(payload.operation_id)) |existing| {
        var match = existing;
        defer match.deinit(self.allocator);
        if (match.kind != .add) return respondError(output, "operation_id was already used for a different operation");
        return keysRespondExistingJob(output, &match, "fingerprint");
    }

    // Snapshot-side validation happens under one lock; every value the
    // job needs is copied out before the lock is released.
    var server_id: []u8 = undefined;
    var account_name: ?[]u8 = null;
    var role_options: ?[]u8 = null;
    {
        self.keys.lock();
        defer self.keys.unlock();
        const snap = keysFindSnapshotLocked(self, payload.snapshot_id) orelse return respondError(output, "unknown snapshot; take a fresh snapshot");
        if (snap.state != .done and snap.state != .partial) return respondError(output, "the snapshot did not complete; take a fresh snapshot");
        snap.touched_ns = keysNowNs(self);
        if (keysValidateSourceLocked(snap, payload.source_path, payload.file_sha256)) |msg| return respondError(output, msg);

        const forced: ?[]const u8 = blk: {
            if (snap.account_kind != .managed_role) break :blk null;
            const role = keysFindRole(snap, snap.account_name.?) orelse return respondError(output, "the managed role is missing from the snapshot; refresh");
            if (role.policy_state != .verified) return respondError(output, "the role policy is not verified; repair the role before installing keys");
            if (std.mem.eql(u8, role.kind, "read_only_sftp")) break :blk role.forced_command;
            break :blk null;
        };
        server_id = self.allocator.dupe(u8, snap.server_id) catch return respondError(output, "out of memory");
        account_name = if (snap.account_name) |n| self.allocator.dupe(u8, n) catch {
            self.allocator.free(server_id);
            return respondError(output, "out of memory");
        } else null;
        role_options = if (forced) |cmd| keyjobs.readOnlyRoleOptions(self.allocator, cmd) catch {
            self.allocator.free(server_id);
            if (account_name) |n| self.allocator.free(n);
            return respondError(output, "out of memory");
        } else null;
    }
    defer self.allocator.free(server_id);
    defer if (account_name) |n| self.allocator.free(n);
    defer if (role_options) |o| self.allocator.free(o);

    const final_line: []const u8 = if (role_options) |opts|
        std.fmt.allocPrint(self.allocator, "{s} {s}", .{ opts, normalized.line }) catch return respondError(output, "out of memory")
    else
        normalized.line;
    defer if (role_options != null) self.allocator.free(final_line);
    const payload_union = keysAddPayload(self, final_line, normalized.fingerprint_sha256) catch return respondError(output, "out of memory");
    const job = keysNewJob(self, .add, payload.operation_id, server_id, account_name, payload.source_path, payload.file_sha256, payload_union) catch return respondError(output, "out of memory");
    keysEnsureStarted(self);
    self.keys.registerJob(job) catch |err| {
        job.deinit(self.allocator);
        return respondError(output, switch (err) {
            error.TooManyActive => "too many active jobs; finish or cancel one before starting another",
            else => "out of memory",
        });
    };
    keysAuditAdmission(self, job);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job_id\":") catch return output[0..0];
    json.writeJsonString(&writer, job.id) catch return output[0..0];
    writer.writeAll(",\"fingerprint\":") catch return output[0..0];
    json.writeJsonString(&writer, normalized.fingerprint_sha256) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleSshKeysRevoke(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysRevokePayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    const payload = parsed.value;
    if (!keysValidId(payload.operation_id)) return respondError(output, "operation_id is required");
    if (!keysValidId(payload.snapshot_id)) return respondError(output, "invalid snapshot_id");
    if (!keysValidPath(payload.source_path)) return respondError(output, "invalid source path");
    if (!keysValidHash(payload.file_sha256)) return respondError(output, "invalid file hash");
    if (!keysValidFingerprint(payload.fingerprint)) return respondError(output, "invalid fingerprint");
    if (!keysValidHash(payload.line_hash)) return respondError(output, "invalid line hash");
    if (payload.confirm_fingerprint) |confirm| {
        if (!keysValidFingerprint(confirm)) return respondError(output, "invalid confirmation fingerprint");
        if (!std.mem.eql(u8, confirm, payload.fingerprint)) return respondError(output, "the confirmation fingerprint does not match the reviewed key");
    }
    if (self.keys.operationLookup(payload.operation_id)) |existing| {
        var match = existing;
        defer match.deinit(self.allocator);
        if (match.kind != .revoke) return respondError(output, "operation_id was already used for a different operation");
        return keysRespondExistingJob(output, &match, null);
    }

    var server_id: []u8 = undefined;
    var account_name: ?[]u8 = null;
    {
        self.keys.lock();
        defer self.keys.unlock();
        const snap = keysFindSnapshotLocked(self, payload.snapshot_id) orelse return respondError(output, "unknown snapshot; take a fresh snapshot");
        if (snap.state != .done and snap.state != .partial) return respondError(output, "the snapshot did not complete; take a fresh snapshot");
        snap.touched_ns = keysNowNs(self);
        if (keysValidateSourceLocked(snap, payload.source_path, payload.file_sha256)) |msg| return respondError(output, msg);
        // Revoke stays available when the role policy drifted: removing a
        // key never widens access.
        const key = keysFindKey(snap, payload.source_path, payload.fingerprint) orelse return respondError(output, "the reviewed key is no longer in the source; refresh the snapshot");
        if (!std.mem.eql(u8, key.line_hash, payload.line_hash)) return respondError(output, "the reviewed line changed; refresh and review again");
        server_id = self.allocator.dupe(u8, snap.server_id) catch return respondError(output, "out of memory");
        account_name = if (snap.account_name) |n| self.allocator.dupe(u8, n) catch {
            self.allocator.free(server_id);
            return respondError(output, "out of memory");
        } else null;
    }
    defer self.allocator.free(server_id);
    defer if (account_name) |n| self.allocator.free(n);

    const payload_union = keysRevokePayload(self, payload.fingerprint, payload.line_hash) catch return respondError(output, "out of memory");
    const job = keysNewJob(self, .revoke, payload.operation_id, server_id, account_name, payload.source_path, payload.file_sha256, payload_union) catch return respondError(output, "out of memory");
    keysEnsureStarted(self);
    self.keys.registerJob(job) catch |err| {
        job.deinit(self.allocator);
        return respondError(output, switch (err) {
            error.TooManyActive => "too many active jobs; finish or cancel one before starting another",
            else => "out of memory",
        });
    };
    keysAuditAdmission(self, job);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job_id\":") catch return output[0..0];
    json.writeJsonString(&writer, job.id) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleSshKeysRotate(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysRotatePayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    const payload = parsed.value;
    if (!keysValidId(payload.operation_id)) return respondError(output, "operation_id is required");
    if (!keysValidId(payload.snapshot_id)) return respondError(output, "invalid snapshot_id");
    if (!keysValidPath(payload.source_path)) return respondError(output, "invalid source path");
    if (!keysValidHash(payload.file_sha256)) return respondError(output, "invalid file hash");
    if (!keysValidFingerprint(payload.old_fingerprint)) return respondError(output, "invalid fingerprint");
    if (!keysValidHash(payload.line_hash)) return respondError(output, "invalid line hash");
    if (payload.new_public_key.len == 0 or payload.new_public_key.len > keys_max_key_text) return respondError(output, "invalid public key");
    const normalized = sshkeys.normalizePublicKey(self.allocator, payload.new_public_key, null) catch |err| return respondError(output, switch (err) {
        error.Multiline => "public key must be a single line",
        else => "invalid public key",
    });
    defer {
        self.allocator.free(normalized.line);
        self.allocator.free(normalized.fingerprint_sha256);
    }
    if (std.mem.eql(u8, normalized.fingerprint_sha256, payload.old_fingerprint)) return respondError(output, "the new key is the same as the old key");
    if (self.keys.operationLookup(payload.operation_id)) |existing| {
        var match = existing;
        defer match.deinit(self.allocator);
        if (match.kind != .rotate) return respondError(output, "operation_id was already used for a different operation");
        return keysRespondExistingJob(output, &match, "new_fingerprint");
    }

    var server_id: []u8 = undefined;
    var account_name: ?[]u8 = null;
    var role_options: ?[]u8 = null;
    var old_options: []u8 = undefined;
    {
        self.keys.lock();
        defer self.keys.unlock();
        const snap = keysFindSnapshotLocked(self, payload.snapshot_id) orelse return respondError(output, "unknown snapshot; take a fresh snapshot");
        if (snap.state != .done and snap.state != .partial) return respondError(output, "the snapshot did not complete; take a fresh snapshot");
        snap.touched_ns = keysNowNs(self);
        if (keysValidateSourceLocked(snap, payload.source_path, payload.file_sha256)) |msg| return respondError(output, msg);
        const old_key = keysFindKey(snap, payload.source_path, payload.old_fingerprint) orelse return respondError(output, "the reviewed key is no longer in the source; refresh the snapshot");
        if (!std.mem.eql(u8, old_key.line_hash, payload.line_hash)) return respondError(output, "the reviewed line changed; refresh and review again");
        if (keysFindKey(snap, payload.source_path, normalized.fingerprint_sha256) != null) return respondError(output, "the new key is already present in the source");
        const forced: ?[]const u8 = blk: {
            if (snap.account_kind != .managed_role) break :blk null;
            const role = keysFindRole(snap, snap.account_name.?) orelse return respondError(output, "the managed role is missing from the snapshot; refresh");
            if (role.policy_state != .verified) return respondError(output, "the role policy is not verified; repair the role before installing keys");
            if (std.mem.eql(u8, role.kind, "read_only_sftp")) break :blk role.forced_command;
            break :blk null;
        };
        server_id = self.allocator.dupe(u8, snap.server_id) catch return respondError(output, "out of memory");
        account_name = if (snap.account_name) |n| self.allocator.dupe(u8, n) catch {
            self.allocator.free(server_id);
            return respondError(output, "out of memory");
        } else null;
        role_options = if (forced) |cmd| keyjobs.readOnlyRoleOptions(self.allocator, cmd) catch {
            self.allocator.free(server_id);
            if (account_name) |n| self.allocator.free(n);
            return respondError(output, "out of memory");
        } else null;
        old_options = self.allocator.dupe(u8, old_key.options) catch {
            self.allocator.free(server_id);
            if (account_name) |n| self.allocator.free(n);
            if (role_options) |o| self.allocator.free(o);
            return respondError(output, "out of memory");
        };
    }
    defer self.allocator.free(server_id);
    defer if (account_name) |n| self.allocator.free(n);
    defer if (role_options) |o| self.allocator.free(o);
    defer self.allocator.free(old_options);

    // The replacement line carries the old key's exact options (or the
    // role's required ones), so a rotation never silently widens access.
    const prefix: ?[]const u8 = if (role_options) |opts| opts else if (old_options.len > 0) old_options else null;
    const new_line: []const u8 = if (prefix) |opts|
        std.fmt.allocPrint(self.allocator, "{s} {s}", .{ opts, normalized.line }) catch return respondError(output, "out of memory")
    else
        normalized.line;
    defer if (prefix != null) self.allocator.free(new_line);
    const payload_union = keysRotatePayload(self, payload.old_fingerprint, payload.line_hash, new_line, normalized.fingerprint_sha256, old_options) catch return respondError(output, "out of memory");
    const job = keysNewJob(self, .rotate, payload.operation_id, server_id, account_name, payload.source_path, payload.file_sha256, payload_union) catch return respondError(output, "out of memory");
    keysEnsureStarted(self);
    self.keys.registerJob(job) catch |err| {
        job.deinit(self.allocator);
        return respondError(output, switch (err) {
            error.TooManyActive => "too many active jobs; finish or cancel one before starting another",
            else => "out of memory",
        });
    };
    keysAuditAdmission(self, job);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job_id\":") catch return output[0..0];
    json.writeJsonString(&writer, job.id) catch return output[0..0];
    writer.writeAll(",\"new_fingerprint\":") catch return output[0..0];
    json.writeJsonString(&writer, normalized.fingerprint_sha256) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleSshKeysRotateCommit(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysRotateCommitPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer {
        // Scrub the passphrase copy inside the parsed payload before the
        // arena is released.
        if (parsed.value.verification.passphrase) |pp| {
            if (pp.len > 0) std.crypto.secureZero(u8, @constCast(pp));
        }
        parsed.deinit();
    }
    const payload = parsed.value;
    if (!keysValidId(payload.job_id)) return respondError(output, "invalid job_id");
    var verification: keyjobs.RotateVerification = undefined;
    if (std.mem.eql(u8, payload.verification.kind, "local_private_key")) {
        const path = payload.verification.path orelse return respondError(output, "a private key path is required");
        if (!keysValidPath(path)) return respondError(output, "invalid private key path");
        if (payload.verification.passphrase) |pp| {
            if (pp.len > keys_max_passphrase_text) return respondError(output, "passphrase is too long");
        }
        verification = keysLocalKeyVerification(self, path, payload.verification.passphrase) catch return respondError(output, "out of memory");
    } else if (std.mem.eql(u8, payload.verification.kind, "external_confirmation")) {
        const confirm = payload.verification.confirm_fingerprint orelse return respondError(output, "a confirmation fingerprint is required");
        if (!keysValidFingerprint(confirm)) return respondError(output, "invalid confirmation fingerprint");
        verification = .{ .external_confirmation = .{ .confirm_fingerprint = self.allocator.dupe(u8, confirm) catch return respondError(output, "out of memory") } };
    } else {
        return respondError(output, "unknown verification kind");
    }
    if (!self.keys.jobSubmitVerificationById(payload.job_id, verification)) {
        var rejected = verification;
        rejected.deinit(self.allocator);
        return respondError(output, "the job is not waiting for verification");
    }
    return ok_json;
}

fn handleSshKeysJobPoll(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysJobIdPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    self.keys.lock();
    defer self.keys.unlock();
    const job = keysFindJobLocked(self, parsed.value.job_id) orelse return respondError(output, "unknown job");
    job.touched_ns = keysNowNs(self);
    var writer = std.Io.Writer.fixed(output);
    keysJobPollWrite(self, &writer, job) catch return respondError(output, "response too large");
    return writer.buffered();
}

fn handleSshKeysJobCancel(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysJobIdPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    var info = self.keys.jobCancelById(parsed.value.job_id) orelse return respondError(output, "unknown job");
    defer info.deinit(self.allocator);
    if (info.transitioned) {
        // A queued or waiting job never reaches a driver, so the terminal
        // audit row is written here (exactly once).
        var detail_buf: [320]u8 = undefined;
        const detail = std.fmt.bufPrint(&detail_buf, "state=canceled {s}", .{info.detail}) catch "state=canceled";
        const target = if (info.server_id.len > 0) info.server_id else "local";
        self.audit.append(self.io, info.kind.auditName(), target, detail) catch {};
    }
    return ok_json;
}

fn handleSshKeysLocalGenerate(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysLocalGeneratePayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer {
        if (parsed.value.passphrase) |pp| {
            if (pp.len > 0) std.crypto.secureZero(u8, @constCast(pp));
        }
        parsed.deinit();
    }
    const payload = parsed.value;
    if (!keysValidId(payload.operation_id)) return respondError(output, "operation_id is required");
    if (!keysValidPath(payload.destination) or !std.fs.path.isAbsolute(payload.destination)) return respondError(output, "an absolute destination path is required");
    if (payload.comment) |comment| {
        if (comment.len > keys_max_comment_text) return respondError(output, "comment is too long");
    }
    if (payload.passphrase) |pp| {
        if (pp.len > keys_max_passphrase_text) return respondError(output, "passphrase is too long");
    }
    if (self.keys.operationLookup(payload.operation_id)) |existing| {
        var match = existing;
        defer match.deinit(self.allocator);
        if (match.kind != .local_generate) return respondError(output, "operation_id was already used for a different operation");
        return keysRespondExistingJob(output, &match, null);
    }
    // server_id stays empty: the job runs on the local worker and audits
    // against "local". remember_passphrase is always false here; the
    // frontend writes the Keychain entry itself with the keychain_account
    // from the job result.
    const payload_union = keysLocalGeneratePayloadBuild(self, payload.destination, payload.comment, payload.passphrase) catch return respondError(output, "out of memory");
    const job = keysNewJob(self, .local_generate, payload.operation_id, "", null, "", "", payload_union) catch return respondError(output, "out of memory");
    keysEnsureStarted(self);
    self.keys.registerJob(job) catch |err| {
        job.deinit(self.allocator);
        return respondError(output, switch (err) {
            error.TooManyActive => "too many active jobs; finish or cancel one before starting another",
            else => "out of memory",
        });
    };
    keysAuditAdmission(self, job);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job_id\":") catch return output[0..0];
    json.writeJsonString(&writer, job.id) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleSshKeysRolesPlan(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysRolesPlanPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    const payload = parsed.value;
    if (!keysValidId(payload.server_id)) return respondError(output, "invalid server_id");
    if (!access.safeUserName(payload.name)) return respondError(output, "invalid account name");
    const read_only = std.mem.eql(u8, payload.kind, "read_only_sftp");
    if (!read_only and !std.mem.eql(u8, payload.kind, "standard_ssh")) return respondError(output, "unknown role kind");
    var action: keyjobs.RolePlanAction = undefined;
    if (std.mem.eql(u8, payload.action, "create")) {
        action = .create;
    } else if (std.mem.eql(u8, payload.action, "repair")) {
        action = .repair;
    } else if (std.mem.eql(u8, payload.action, "delete")) {
        action = .delete;
    } else {
        return respondError(output, "unknown role action");
    }

    // Everything the plan freezes comes from the latest completed
    // snapshot; the values are copied out under one lock.
    var privilege: []u8 = undefined;
    var forced_command: []u8 = &.{};
    var home: ?[]u8 = null;
    {
        self.keys.lock();
        defer self.keys.unlock();
        const snap = keysLastCompletedSnapshotLocked(self, payload.server_id) orelse return respondError(output, "take a snapshot before planning role changes");
        snap.touched_ns = keysNowNs(self);
        if (!std.mem.eql(u8, snap.privilege, "root") and !std.mem.eql(u8, snap.privilege, "sudo_n")) return respondError(output, "root or approved sudo -n is required for role changes");
        const existing = keysFindRole(snap, payload.name);
        var forced_source: []const u8 = "";
        var home_source: ?[]const u8 = null;
        switch (action) {
            .create => {
                if (existing != null) return respondError(output, "this account is already Oars-managed");
                if (read_only) {
                    if (!snap.sftp_read_only or snap.sftp_forced_command.len == 0) return respondError(output, "read-only SFTP is not available on this server");
                    forced_source = snap.sftp_forced_command;
                }
            },
            .repair => {
                const role = existing orelse return respondError(output, "the role is not Oars-managed");
                if (!std.mem.eql(u8, role.kind, payload.kind)) return respondError(output, "the role kind does not match the managed policy");
                if (role.policy_state == .verified) return respondError(output, "the role policy is already verified");
                if (read_only) forced_source = role.forced_command;
                home_source = role.home;
            },
            .delete => {
                const role = existing orelse return respondError(output, "the role is not Oars-managed");
                if (!std.mem.eql(u8, role.kind, payload.kind)) return respondError(output, "the role kind does not match the managed policy");
                home_source = role.home;
            },
        }
        privilege = self.allocator.dupe(u8, snap.privilege) catch return respondError(output, "out of memory");
        forced_command = self.allocator.dupe(u8, forced_source) catch {
            self.allocator.free(privilege);
            return respondError(output, "out of memory");
        };
        home = if (home_source) |h| self.allocator.dupe(u8, h) catch {
            self.allocator.free(privilege);
            self.allocator.free(forced_command);
            return respondError(output, "out of memory");
        } else null;
    }
    defer self.allocator.free(privilege);
    defer self.allocator.free(forced_command);
    defer if (home) |h| self.allocator.free(h);

    // Account names pass safeUserName ([a-z0-9_-] only), so the plan
    // commands need no shell quoting.
    var cmd_buf: [384]u8 = undefined;
    var commands: [1][]const u8 = undefined;
    var command_count: usize = 0;
    var effect_bufs: [3][256]u8 = undefined;
    var effects: [3][]const u8 = undefined;
    var effect_count: usize = 0;
    var create_home_buf: [128]u8 = undefined;
    switch (action) {
        .create => {
            commands[0] = sshkeysRoleCreateCommand(&cmd_buf, payload.name) catch return respondError(output, "out of memory");
            command_count = 1;
            home = blk: {
                if (home) |h| break :blk h;
                const text = std.fmt.bufPrint(&create_home_buf, "/home/{s}", .{payload.name}) catch return respondError(output, "out of memory");
                break :blk self.allocator.dupe(u8, text) catch return respondError(output, "out of memory");
            };
            effects[0] = std.fmt.bufPrint(&effect_bufs[0], "Create the account '{s}' with a home directory; password login stays disabled", .{payload.name}) catch return respondError(output, "out of memory");
            if (read_only) {
                effects[1] = std.fmt.bufPrint(&effect_bufs[1], "Force every key for '{s}' to read-only SFTP with restrict and a forced command", .{payload.name}) catch return respondError(output, "out of memory");
            } else {
                effects[1] = std.fmt.bufPrint(&effect_bufs[1], "Install the first approved key in {s}/.ssh/authorized_keys (mode 0600)", .{home.?}) catch return respondError(output, "out of memory");
            }
            effects[2] = std.fmt.bufPrint(&effect_bufs[2], "Record '{s}' in the Oars role policy manifest", .{payload.name}) catch return respondError(output, "out of memory");
            effect_count = 3;
        },
        .repair => {
            effects[0] = std.fmt.bufPrint(&effect_bufs[0], "Re-verify the account, home, shell, and key source for '{s}'", .{payload.name}) catch return respondError(output, "out of memory");
            if (read_only) {
                effects[1] = std.fmt.bufPrint(&effect_bufs[1], "Reapply the approved forced read-only SFTP options to every parsed key for '{s}'", .{payload.name}) catch return respondError(output, "out of memory");
                effects[2] = std.fmt.bufPrint(&effect_bufs[2], "Rewrite the Oars role policy entry for '{s}'", .{payload.name}) catch return respondError(output, "out of memory");
                effect_count = 3;
            } else {
                effects[1] = std.fmt.bufPrint(&effect_bufs[1], "Rewrite the Oars role policy entry for '{s}'", .{payload.name}) catch return respondError(output, "out of memory");
                effect_count = 2;
            }
        },
        .delete => {
            commands[0] = std.fmt.bufPrint(&cmd_buf, "userdel {s}", .{payload.name}) catch return respondError(output, "out of memory");
            command_count = 1;
            effects[0] = std.fmt.bufPrint(&effect_bufs[0], "Delete the account '{s}'; the home directory is left on disk", .{payload.name}) catch return respondError(output, "out of memory");
            effects[1] = std.fmt.bufPrint(&effect_bufs[1], "Remove '{s}' from the Oars role policy manifest", .{payload.name}) catch return respondError(output, "out of memory");
            effect_count = 2;
        },
    }

    const plan = keysNewPlan(self, payload.server_id, payload.name, payload.kind, action, privilege, forced_command, home, commands[0..command_count], effects[0..effect_count]) catch return respondError(output, "out of memory");
    self.keys.registerPlan(plan) catch |err| {
        plan.deinit(self.allocator);
        return respondError(output, switch (err) {
            error.TooManyActive => "too many role plans; commit or discard one first",
            else => "out of memory",
        });
    };
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"plan_id\":") catch return output[0..0];
    json.writeJsonString(&writer, plan.id) catch return output[0..0];
    writer.print(",\"expires_at_ms\":{d}", .{plan.expires_at_ms}) catch return output[0..0];
    writer.writeAll(",\"account\":") catch return output[0..0];
    json.writeJsonString(&writer, plan.name) catch return output[0..0];
    if (plan.home) |plan_home| {
        writer.writeAll(",\"home\":") catch return output[0..0];
        json.writeJsonString(&writer, plan_home) catch return output[0..0];
    }
    writer.writeAll(",\"commands\":[") catch return output[0..0];
    for (plan.commands, 0..) |command, i| {
        if (i > 0) writer.writeAll(",") catch return output[0..0];
        json.writeJsonString(&writer, command) catch return output[0..0];
    }
    writer.writeAll("],\"effects\":[") catch return output[0..0];
    for (plan.effects, 0..) |effect, i| {
        if (i > 0) writer.writeAll(",") catch return output[0..0];
        json.writeJsonString(&writer, effect) catch return output[0..0];
    }
    writer.writeAll("]}") catch return output[0..0];
    return writer.buffered();
}

/// Builds the owned role payload from a committed plan (every slice
/// duped; the plan itself is released by the caller).
fn keysRolePayloadFromPlan(self: *Context, plan: *const keyjobs.RolePlan, first_key_line: ?[]const u8) !keyjobs.JobPayload {
    const name = try self.allocator.dupe(u8, plan.name);
    errdefer self.allocator.free(name);
    const kind = try self.allocator.dupe(u8, plan.kind);
    errdefer self.allocator.free(kind);
    const privilege = try self.allocator.dupe(u8, plan.privilege);
    errdefer self.allocator.free(privilege);
    const forced = try self.allocator.dupe(u8, plan.forced_command);
    errdefer self.allocator.free(forced);
    const home: ?[]u8 = if (plan.home) |h| try self.allocator.dupe(u8, h) else null;
    errdefer if (home) |h| self.allocator.free(h);
    const commands = try self.allocator.alloc([]u8, plan.commands.len);
    var commands_filled: usize = 0;
    errdefer {
        for (commands[0..commands_filled]) |c| self.allocator.free(c);
        self.allocator.free(commands);
    }
    for (plan.commands, 0..) |c, i| {
        commands[i] = try self.allocator.dupe(u8, c);
        commands_filled += 1;
    }
    const first_key: ?[]u8 = if (first_key_line) |line| try self.allocator.dupe(u8, line) else null;
    errdefer if (first_key) |k| self.allocator.free(k);
    return .{ .role = .{
        .name = name,
        .kind = kind,
        .privilege = privilege,
        .forced_command = forced,
        .home = home,
        .commands = commands,
        .first_key_line = first_key,
    } };
}

fn handleSshKeysRolesCommit(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysRolesCommitPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    const payload = parsed.value;
    if (!keysValidId(payload.operation_id)) return respondError(output, "operation_id is required");
    if (!keysValidId(payload.plan_id)) return respondError(output, "invalid plan_id");
    if (payload.public_key) |public_key| {
        if (public_key.len == 0 or public_key.len > keys_max_key_text) return respondError(output, "invalid public key");
    }
    if (self.keys.operationLookup(payload.operation_id)) |existing| {
        var match = existing;
        defer match.deinit(self.allocator);
        switch (match.kind) {
            .role_create, .role_repair, .role_delete => return keysRespondExistingJob(output, &match, null),
            else => return respondError(output, "operation_id was already used for a different operation"),
        }
    }
    const plan = self.keys.takePlan(payload.plan_id) orelse return respondError(output, "unknown or expired plan; preview again");
    defer plan.deinit(self.allocator);
    if (plan.expired(keysNowMs(self))) return respondError(output, "the plan expired; preview again");

    var first_key_line: ?[]u8 = null;
    defer if (first_key_line) |line| self.allocator.free(line);
    if (plan.action == .create) {
        const public_key = payload.public_key orelse return respondError(output, "the first approved key is required to create a role");
        const normalized = sshkeys.normalizePublicKey(self.allocator, public_key, null) catch |err| return respondError(output, switch (err) {
            error.Multiline => "public key must be a single line",
            else => "invalid public key",
        });
        defer {
            self.allocator.free(normalized.line);
            self.allocator.free(normalized.fingerprint_sha256);
        }
        first_key_line = if (plan.forced_command.len > 0) blk: {
            const opts = keyjobs.readOnlyRoleOptions(self.allocator, plan.forced_command) catch return respondError(output, "out of memory");
            defer self.allocator.free(opts);
            break :blk std.fmt.allocPrint(self.allocator, "{s} {s}", .{ opts, normalized.line }) catch return respondError(output, "out of memory");
        } else self.allocator.dupe(u8, normalized.line) catch return respondError(output, "out of memory");
    }

    const job_kind: keyjobs.JobKind = switch (plan.action) {
        .create => .role_create,
        .repair => .role_repair,
        .delete => .role_delete,
    };
    const payload_union = keysRolePayloadFromPlan(self, plan, first_key_line) catch return respondError(output, "out of memory");
    const job = keysNewJob(self, job_kind, payload.operation_id, plan.server_id, plan.name, "", "", payload_union) catch return respondError(output, "out of memory");
    keysEnsureStarted(self);
    self.keys.registerJob(job) catch |err| {
        job.deinit(self.allocator);
        return respondError(output, switch (err) {
            error.TooManyActive => "too many active jobs; finish or cancel one before starting another",
            else => "out of memory",
        });
    };

    // The approved plan commands are recorded once at admission.
    var joined: []u8 = &.{};
    defer if (joined.len > 0) self.allocator.free(joined);
    if (plan.commands.len > 0) {
        var total: usize = 4 * (plan.commands.len - 1);
        for (plan.commands) |command| total += command.len;
        const buf = self.allocator.alloc(u8, total) catch return respondError(output, "out of memory");
        var pos: usize = 0;
        for (plan.commands, 0..) |command, i| {
            if (i > 0) {
                @memcpy(buf[pos..][0..4], " && ");
                pos += 4;
            }
            @memcpy(buf[pos..][0..command.len], command);
            pos += command.len;
        }
        std.debug.assert(pos == buf.len);
        joined = buf;
        self.history.record(self.io, .{
            .id = "",
            .operation_id = payload.operation_id,
            .ts = @intCast(keysNowNs(self)),
            .server_id = plan.server_id,
            .kind = "sshkeys",
            .command = joined,
            .exit = null,
            .duration_ms = null,
            .output_snippet = "",
            .redacted = false,
        }) catch {};
    }
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "name={s} kind={s} action={s}", .{ plan.name, plan.kind, @tagName(plan.action) }) catch "role plan";
    self.audit.appendFull(self.io, payload.operation_id, job_kind.auditName(), plan.server_id, joined, "admitted", detail) catch {};

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job_id\":") catch return output[0..0];
    json.writeJsonString(&writer, job.id) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleSshKeysDeployKeysGenerate(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysDeployGeneratePayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    const payload = parsed.value;
    if (!keysValidId(payload.operation_id)) return respondError(output, "operation_id is required");
    if (!keysValidId(payload.server_id)) return respondError(output, "invalid server_id");
    const label = std.mem.trim(u8, payload.repository_label, " \t");
    if (label.len == 0 or label.len > 256) return respondError(output, "a repository label of 1-256 characters is required");
    if (std.mem.indexOfAny(u8, label, "\r\n") != null) return respondError(output, "the repository label must be a single line");
    if (payload.comment) |comment| {
        if (comment.len > keys_max_comment_text) return respondError(output, "comment is too long");
    }
    if (self.keys.operationLookup(payload.operation_id)) |existing| {
        var match = existing;
        defer match.deinit(self.allocator);
        if (match.kind != .deploy_generate) return respondError(output, "operation_id was already used for a different operation");
        return keysRespondExistingJob(output, &match, null);
    }
    const payload_union = keysDeployGeneratePayload(self, label, payload.comment) catch return respondError(output, "out of memory");
    const job = keysNewJob(self, .deploy_generate, payload.operation_id, payload.server_id, null, "", "", payload_union) catch return respondError(output, "out of memory");
    keysEnsureStarted(self);
    self.keys.registerJob(job) catch |err| {
        job.deinit(self.allocator);
        return respondError(output, switch (err) {
            error.TooManyActive => "too many active jobs; finish or cancel one before starting another",
            else => "out of memory",
        });
    };
    keysAuditAdmission(self, job);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job_id\":") catch return output[0..0];
    json.writeJsonString(&writer, job.id) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleSshKeysDeployKeysDelete(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(KeysDeployDeletePayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    const payload = parsed.value;
    if (!keysValidId(payload.operation_id)) return respondError(output, "operation_id is required");
    if (!keysValidId(payload.server_id)) return respondError(output, "invalid server_id");
    if (!std.mem.startsWith(u8, payload.deploy_key_id, "dk-") or payload.deploy_key_id.len > 32) return respondError(output, "invalid deploy key id");
    if (!keysValidFingerprint(payload.confirm_fingerprint)) return respondError(output, "invalid confirmation fingerprint");
    if (self.keys.operationLookup(payload.operation_id)) |existing| {
        var match = existing;
        defer match.deinit(self.allocator);
        if (match.kind != .deploy_delete) return respondError(output, "operation_id was already used for a different operation");
        return keysRespondExistingJob(output, &match, null);
    }
    const payload_union = keysDeployDeletePayload(self, payload.deploy_key_id, payload.confirm_fingerprint) catch return respondError(output, "out of memory");
    const job = keysNewJob(self, .deploy_delete, payload.operation_id, payload.server_id, null, "", "", payload_union) catch return respondError(output, "out of memory");
    keysEnsureStarted(self);
    self.keys.registerJob(job) catch |err| {
        job.deinit(self.allocator);
        return respondError(output, switch (err) {
            error.TooManyActive => "too many active jobs; finish or cancel one before starting another",
            else => "out of memory",
        });
    };
    keysAuditAdmission(self, job);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job_id\":") catch return output[0..0];
    json.writeJsonString(&writer, job.id) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

// --- access management (spec 09) -------------------------------------------

const access_exec_cap: usize = 256 * 1024;
const access_exec_timeout_ns = 10 * std.time.ns_per_s;
const AccessScanPayload = struct {
    server_ids: ?[]const []const u8 = null,
    scope: []const u8 = "connected_accounts",
    approved_sensitive_read: bool = false,
};
const AccessPollPayload = struct { scan_id: []const u8, people_offset: usize = 0, unassigned_offset: usize = 0, limit: usize = 50 };
const AccessScanCancelPayload = struct { scan_id: []const u8 };
const AccessKeyInspectPayload = struct { public_key: []const u8 };
const AccessIdentitySavePayload = struct { identity: access.IdentityInput };
const AccessIdentityDeletePayload = struct { id: []const u8, expected_revision: ?u64 = null, confirm_name: []const u8 = "" };
const AccessOffboardGrant = struct {
    fingerprint: []const u8,
    server_id: []const u8,
    user: []const u8,
    line_hash: []const u8,
    source_path: []const u8 = "",
    file_sha256: []const u8 = "",
};
const AccessOffboardPayload = struct {
    identity_id: []const u8,
    grants: []const AccessOffboardGrant,
    operation_id: []const u8 = "",
    scan_id: []const u8 = "",
    identity_revision: ?u64 = null,
    confirm_name: []const u8 = "",
};
const AccessOnboardTarget = struct { kind: []const u8, name: []const u8 };
const AccessOnboardGrant = struct { server_id: []const u8, target: AccessOnboardTarget };
const AccessOnboardPayload = struct {
    identity_id: []const u8,
    public_key: []const u8,
    grants: []const AccessOnboardGrant,
    operation_id: []const u8 = "",
    identity_revision: ?u64 = null,
};
const AccessRotateGrant = struct {
    server_id: []const u8,
    user: []const u8,
    line_hash: []const u8,
    source_path: []const u8 = "",
    file_sha256: []const u8 = "",
};
const AccessRotatePayload = struct {
    identity_id: []const u8,
    old_fingerprint: []const u8,
    new_public_key: []const u8,
    grants: []const AccessRotateGrant,
    operation_id: []const u8 = "",
    scan_id: []const u8 = "",
    identity_revision: ?u64 = null,
};
const AccessJobPollPayload = struct { job_id: []const u8 };
const AccessJobCancelPayload = struct { job_id: []const u8 };
const AccessExportPayload = struct { format: []const u8 = "csv", cursor: usize = 0, limit: usize = 0, path: []const u8 = "", scan_id: []const u8 = "" };

fn accessAudit(self: *Context, action: []const u8, server_id: []const u8, detail: []const u8) void {
    sshkeysAudit(self, action, server_id, detail);
}

fn accessFail(server: *access.ServerScan, self: *Context, msg: []const u8) void {
    server.phase = .@"error";
    if (server.@"error") |e| self.allocator.free(e);
    server.@"error" = self.allocator.dupe(u8, msg) catch null;
}

fn accessQueueExec(self: *Context, server: *access.ServerScan, cmd: []const u8, kind: access.PendingKind, account_index: usize) bool {
    const outcome = self.allocator.create(sessions.AccessExecOutcome) catch return false;
    outcome.* = .{ .allocator = self.allocator };
    self.manager.enqueueAccessExec(server.server_id, cmd, access_exec_timeout_ns, access_exec_cap, outcome) catch {
        self.allocator.destroy(outcome);
        return false;
    };
    if (server.pending) |*p| {
        if (p.sudo_user.len > 0) self.allocator.free(p.sudo_user);
        if (p.sftp_path.len > 0) self.allocator.free(p.sftp_path);
    }
    server.pending = .{ .kind = kind, .account_index = account_index, .outcome = outcome };
    return true;
}

fn accessClearPending(self: *Context, server: *access.ServerScan, exit: ?i32, data: []const u8) void {
    _ = exit;
    _ = data;
    if (server.pending) |pend| {
        switch (pend.kind) {
            .read_sftp, .read_sftp_data => {
                const raw: *sessions.SftpOutcome = @ptrCast(@alignCast(pend.outcome.?));
                if (raw.abandon()) {
                    if (raw.json) |j| self.allocator.free(j);
                    self.allocator.destroy(raw);
                }
            },
            else => {
                const raw: *sessions.AccessExecOutcome = @ptrCast(@alignCast(pend.outcome.?));
                if (raw.abandon()) {
                    raw.data.deinit(self.allocator);
                    self.allocator.destroy(raw);
                }
            },
        }
        if (pend.sudo_user.len > 0) self.allocator.free(pend.sudo_user);
        if (pend.sftp_path.len > 0) self.allocator.free(pend.sftp_path);
        server.pending = null;
    }
}

fn accessQueueSftpRead(self: *Context, server: *access.ServerScan, acc_index: usize, path: []const u8) bool {
    const out = self.allocator.create(sessions.SftpOutcome) catch return false;
    out.* = .{ .allocator = self.allocator };
    // Stat first so the consumer can distinguish a missing file from denied,
    // timeout, and transport failures before it queues content reads.
    self.manager.sftpStat(server.server_id, path, out) catch {
        self.allocator.destroy(out);
        return false;
    };
    if (server.pending) |*p| {
        if (p.sudo_user.len > 0) self.allocator.free(p.sudo_user);
        if (p.sftp_path.len > 0) self.allocator.free(p.sftp_path);
    }
    const owned_path = self.allocator.dupe(u8, path) catch {
        if (out.abandon()) self.allocator.destroy(out);
        return false;
    };
    server.pending = .{ .kind = .read_sftp, .account_index = acc_index, .sftp_path = owned_path, .outcome = out };
    return true;
}

fn accessQueueSftpData(self: *Context, server: *access.ServerScan, acc_index: usize, path: []const u8) bool {
    const out = self.allocator.create(sessions.SftpOutcome) catch return false;
    out.* = .{ .allocator = self.allocator };
    self.manager.sftpRead(server.server_id, path, @intCast(server.read_buffer.items.len), 64 * 1024, out) catch {
        self.allocator.destroy(out);
        return false;
    };
    const owned_path = self.allocator.dupe(u8, path) catch {
        if (out.abandon()) self.allocator.destroy(out);
        return false;
    };
    server.pending = .{ .kind = .read_sftp_data, .account_index = acc_index, .sftp_path = owned_path, .outcome = out };
    return true;
}

/// Reads a static key source through approved non-interactive sudo. SFTP uses
/// the connected account's permissions, so it cannot inspect another user's
/// mode-0600 authorized_keys file even after a full-account scan was approved.
fn accessQueuePrivilegedRead(self: *Context, server: *access.ServerScan, acc_index: usize, path: []const u8) bool {
    const quoted_path = shellquote.quote(self.allocator, path) catch return false;
    defer self.allocator.free(quoted_path);
    const command = std.fmt.allocPrint(self.allocator, "LC_ALL=C sudo -n cat -- {s} 2>&1", .{quoted_path}) catch return false;
    defer self.allocator.free(command);
    const out = self.allocator.create(sessions.AccessExecOutcome) catch return false;
    out.* = .{ .allocator = self.allocator };
    self.manager.enqueueAccessExec(server.server_id, command, access_exec_timeout_ns, sshkeys.max_keys_file_bytes + 1, out) catch {
        self.allocator.destroy(out);
        return false;
    };
    const owned_path = self.allocator.dupe(u8, path) catch {
        if (out.abandon()) self.allocator.destroy(out);
        return false;
    };
    server.pending = .{ .kind = .read_privileged, .account_index = acc_index, .sftp_path = owned_path, .outcome = out };
    return true;
}

fn accessQueueSudoProbeU(self: *Context, server: *access.ServerScan, acc_index: usize, user: []const u8) bool {
    const quoted_user = shellquote.quote(self.allocator, user) catch return false;
    defer self.allocator.free(quoted_user);
    var cmd_buf: [192]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "LC_ALL=C sudo -n -ll -U {s} 2>&1", .{quoted_user}) catch return false;
    const out = self.allocator.create(sessions.AccessExecOutcome) catch return false;
    out.* = .{ .allocator = self.allocator };
    self.manager.enqueueAccessExec(server.server_id, cmd, access_exec_timeout_ns, access_exec_cap, out) catch {
        self.allocator.destroy(out);
        return false;
    };
    if (server.pending) |*p| {
        if (p.sudo_user.len > 0) self.allocator.free(p.sudo_user);
        if (p.sftp_path.len > 0) self.allocator.free(p.sftp_path);
    }
    const owned_user = self.allocator.dupe(u8, user) catch {
        if (out.abandon()) self.allocator.destroy(out);
        return false;
    };
    server.pending = .{ .kind = .sudo_probe_u, .account_index = acc_index, .sudo_user = owned_user, .outcome = out };
    return true;
}

fn accessSetOptional(self: *Context, slot: *?[]const u8, value: []const u8) void {
    if (slot.*) |old| self.allocator.free(old);
    slot.* = self.allocator.dupe(u8, value) catch null;
}

fn accessMarkPartial(self: *Context, server: *access.ServerScan, reason: []const u8) void {
    if (server.coverage_reason) |old| {
        if (std.mem.indexOf(u8, old, reason) != null) return;
        const combined = std.fmt.allocPrint(self.allocator, "{s}; {s}", .{ old, reason }) catch return;
        self.allocator.free(old);
        server.coverage_reason = combined;
        return;
    }
    accessSetOptional(self, &server.coverage_reason, reason);
}

fn accessAppendSourceFact(self: *Context, server: *access.ServerScan, user: []const u8, fact: []const u8) void {
    const owned = std.fmt.allocPrint(self.allocator, "{s}: {s}", .{ user, fact }) catch return;
    server.sources.append(self.allocator, owned) catch self.allocator.free(owned);
}

fn accessQueueEffectivePolicy(self: *Context, server: *access.ServerScan, acc_index: usize) bool {
    if (acc_index >= server.accounts.items.len) return false;
    const account = &server.accounts.items[acc_index];
    const client_addr = server.client_addr orelse "127.0.0.1";
    const local_addr = server.local_addr orelse "127.0.0.1";
    const local_port = server.local_port orelse "22";
    const connection_host = server.connection_host orelse "localhost";
    if (!server.connection_context_valid) accessMarkPartial(self, server, "the live SSH connection tuple was unavailable");
    const criteria = std.fmt.allocPrint(
        self.allocator,
        "user={s},addr={s},laddr={s},lport={s},host={s}",
        .{ account.user, client_addr, local_addr, local_port, connection_host },
    ) catch return false;
    defer self.allocator.free(criteria);
    const quoted = shellquote.quote(self.allocator, criteria) catch return false;
    defer self.allocator.free(quoted);
    const elevate = !server.privileged and std.mem.eql(u8, server.sudo orelse access.sudo_unknown, access.sudo_yes);
    const command = std.fmt.allocPrint(
        self.allocator,
        "LC_ALL=C {s}sshd -T -C {s} 2>&1",
        .{ if (elevate) "sudo -n " else "", quoted },
    ) catch return false;
    defer self.allocator.free(command);
    return accessQueueExec(self, server, command, .sshd_config, acc_index);
}

fn accessContinueAccountSources(self: *Context, server: *access.ServerScan, acc_index: usize) void {
    if (acc_index >= server.accounts.items.len) return;
    const account = &server.accounts.items[acc_index];
    if (account.pubkey_authentication == false) {
        account.read = true;
        accessFinishAccountPolicy(self, server, acc_index);
        server.next_account = acc_index + 1;
        server.phase = .read_accounts;
        return;
    }
    if (account.next_source < account.static_sources.items.len) {
        const path = account.static_sources.items[account.next_source];
        account.next_source += 1;
        const elevate = !server.privileged and std.mem.eql(u8, server.sudo orelse access.sudo_unknown, access.sudo_yes);
        const queued = if (elevate)
            accessQueuePrivilegedRead(self, server, acc_index, path)
        else
            accessQueueSftpRead(self, server, acc_index, path);
        if (!queued) {
            accessSetOptional(self, &account.@"error", "static key source could not be queued");
            accessContinueAccountSources(self, server, acc_index);
        }
        return;
    }
    account.read = account.@"error" == null;
    accessFinishAccountPolicy(self, server, acc_index);
    server.next_account = acc_index + 1;
    server.phase = .read_accounts;
}

fn accessFinishAccountPolicy(self: *Context, server: *access.ServerScan, acc_index: usize) void {
    if (acc_index >= server.accounts.items.len) return;
    const account = &server.accounts.items[acc_index];
    if (std.mem.eql(u8, account.user, server.connected_user orelse "")) {
        accessSetOptional(self, &account.sudo, server.sudo orelse access.sudo_unknown);
    } else if ((server.privileged or std.mem.eql(u8, server.sudo orelse access.sudo_unknown, access.sudo_yes)) and access.safeUserName(account.user)) {
        if (accessQueueSudoProbeU(self, server, acc_index, account.user)) return;
        accessSetOptional(self, &account.sudo, access.sudo_unknown);
    } else {
        accessSetOptional(self, &account.sudo, access.sudo_unknown);
    }
    for (server.grants.items) |*grant| {
        if (!std.mem.eql(u8, grant.user, account.user) or grant.sudo.len != 0) continue;
        self.allocator.free(grant.sudo);
        grant.sudo = self.allocator.dupe(u8, account.sudo orelse access.sudo_unknown) catch continue;
    }
}

fn accessFinishAccountRead(self: *Context, server: *access.ServerScan, acc_index: usize, path: []const u8) void {
    if (acc_index >= server.accounts.items.len) return;
    const account = &server.accounts.items[acc_index];
    var file = sshkeys.parse(self.allocator, server.read_buffer.items) catch {
        accessSetOptional(self, &account.@"error", "authorized_keys could not be parsed");
        accessFinishAccountPolicy(self, server, acc_index);
        return;
    };
    defer file.deinit(self.allocator);
    account.key_count += file.keys.len;
    account.read = true;
    var file_sha: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(server.read_buffer.items);
    hasher.final(&file_sha);
    const sha_hex = std.fmt.bytesToHex(file_sha, .lower);
    for (file.keys) |*key| {
        if (!key.parsed) continue;
        if (access.hasCertificateAuthorityOption(key.options)) {
            accessAppendSourceFact(self, server, account.user, "cert-authority line requires certificate evaluation");
            accessMarkPartial(self, server, "certificate-authority grants were not evaluated as direct person grants");
            continue;
        }
        var seen = false;
        for (server.grants.items) |*grant| {
            if (std.mem.eql(u8, grant.fingerprint, key.fingerprint_sha256) and
                std.mem.eql(u8, grant.user, account.user) and
                std.mem.eql(u8, grant.source_path, path))
            {
                seen = true;
                break;
            }
        }
        if (seen) continue;
        server.grants.append(self.allocator, .{
            .fingerprint = self.allocator.dupe(u8, key.fingerprint_sha256) catch continue,
            .user = self.allocator.dupe(u8, account.user) catch continue,
            .sudo = self.allocator.dupe(u8, "") catch continue,
            .comment = self.allocator.dupe(u8, key.comment) catch continue,
            .line_hash = self.allocator.dupe(u8, key.line_hash) catch continue,
            .source_path = self.allocator.dupe(u8, path) catch continue,
            .file_sha256 = self.allocator.dupe(u8, &sha_hex) catch continue,
            .options = self.allocator.dupe(u8, key.options) catch continue,
        }) catch continue;
    }
    accessContinueAccountSources(self, server, acc_index);
}

fn accessFinishServerScan(self: *Context, server: *access.ServerScan) void {
    for (server.accounts.items) |*account| {
        if (account.skipped) continue;
        if (!account.policy_evaluated) accessMarkPartial(self, server, "some accounts did not receive effective SSH policy evaluation");
        if (!account.read or account.@"error" != null) accessMarkPartial(self, server, "some account key sources could not be read");
    }
    accessSetOptional(self, &server.coverage, if (server.coverage_reason == null) access.coverage_complete else access.coverage_partial);
    server.done = true;
    server.phase = .done;
}

/// Advances one server one phase. Worker-owned execs are queued and
/// consumed on the next poll so the bridge thread never blocks on the
/// network (spec 09 § worker ownership). Each poll either queues one
/// exec or consumes one completed outcome.
fn accessAdvance(self: *Context, scan: *access.Scan, server: *access.ServerScan) void {
    // Consume any in-flight worker exec before advancing.
    if (server.pending) |pend| {
        // SFTP kinds use SftpOutcome; everything else uses AccessExecOutcome.
        if (pend.kind == .read_sftp or pend.kind == .read_sftp_data) {
            const sraw: *sessions.SftpOutcome = @ptrCast(@alignCast(pend.outcome.?));
            if (!sraw.isDone()) return;
            // handled in the big switch below; fall through without snapshotting exec data.
        } else {
            const raw: *sessions.AccessExecOutcome = @ptrCast(@alignCast(pend.outcome.?));
            if (!raw.isDone()) return;
        }
        // Snapshot exec output for the exec kinds (SFTP handler below re-reads its own outcome).
        var exit: ?i32 = null;
        var data_buf: [256 * 1024]u8 = undefined;
        var cap: usize = 0;
        var data: []const u8 = &.{};
        if (pend.kind != .read_sftp and pend.kind != .read_sftp_data and pend.kind != .read_privileged) {
            const raw2: *sessions.AccessExecOutcome = @ptrCast(@alignCast(pend.outcome.?));
            exit = raw2.exit;
            const data_len = raw2.data.items.len;
            cap = @min(data_len, data_buf.len);
            if (cap > 0) @memcpy(data_buf[0..cap], raw2.data.items[0..cap]);
            data = data_buf[0..cap];
        }

        switch (pend.kind) {
            .identity_whoami => {
                const user_trim = std.mem.trim(u8, data, " \t\r\n");
                var user_copy: [64]u8 = undefined;
                const ulen = @min(user_trim.len, user_copy.len);
                if (ulen > 0) @memcpy(user_copy[0..ulen], user_trim[0..ulen]);
                const user = user_copy[0..ulen];
                accessClearPending(self, server, exit, data);
                if (exit == null or exit.? != 0) return accessFail(server, self, "whoami failed");
                if (user.len == 0 or !access.safeUserName(user)) return accessFail(server, self, "cannot determine the connected user");
                accessSetOptional(self, &server.connected_user, user);
                if (!accessQueueExec(self, server, "id -u", .identity_id_u, 0)) return accessFail(server, self, "not connected");
                return;
            },
            .identity_id_u => {
                const uid_trim = std.mem.trim(u8, data, " \t\r\n");
                const uid = if (exit != null and exit.? == 0) std.fmt.parseInt(u32, uid_trim, 10) catch null else null;
                server.connected_uid = uid;
                server.privileged = uid != null and uid.? == 0;
                accessClearPending(self, server, exit, data);
                if (!accessQueueExec(self, server, "printf '%s\\n%s\\n' \"$SSH_CONNECTION\" \"$(hostname -f 2>/dev/null || hostname)\"", .connection_tuple, 0)) return accessFail(server, self, "the live SSH connection tuple could not be requested");
                return;
            },
            .connection_tuple => {
                var lines = std.mem.splitScalar(u8, data, '\n');
                const tuple = std.mem.trim(u8, lines.next() orelse "", " \t\r");
                const connection_host = std.mem.trim(u8, lines.next() orelse "", " \t\r");
                var fields = std.mem.tokenizeAny(u8, tuple, " \t");
                const client_addr = fields.next();
                _ = fields.next(); // client port is not an sshd -C criterion.
                const local_addr = fields.next();
                const local_port = fields.next();
                if (client_addr != null and local_addr != null and local_port != null and connection_host.len > 0) {
                    accessSetOptional(self, &server.client_addr, client_addr.?);
                    accessSetOptional(self, &server.local_addr, local_addr.?);
                    accessSetOptional(self, &server.local_port, local_port.?);
                    accessSetOptional(self, &server.connection_host, connection_host);
                    server.connection_context_valid = true;
                } else {
                    accessMarkPartial(self, server, "the live SSH connection tuple was unavailable");
                }
                accessClearPending(self, server, exit, data);
                if (server.privileged) {
                    accessSetOptional(self, &server.sudo, access.sudo_yes);
                    server.phase = if (scan.full) .enumerate else .read_accounts;
                } else {
                    server.phase = .sudo_probe;
                }
                return;
            },
            .sudo_probe => {
                const sudo = access.parseSudoList(exit orelse 1, data);
                accessClearPending(self, server, exit, data);
                accessSetOptional(self, &server.sudo, sudo);
                if (scan.full) {
                    if (!server.privileged and !std.mem.eql(u8, sudo, access.sudo_yes)) accessSetOptional(self, &server.coverage_reason, "cannot enumerate accounts without root or full non-interactive sudo");
                    server.phase = .enumerate;
                } else {
                    server.phase = .read_accounts;
                }
                return;
            },
            .enumerate => {
                // getent passwd output is in `data`.
                var out = struct { exit: i32, output: std.ArrayList(u8) }{ .exit = exit orelse 1, .output = .empty };
                out.output.appendSlice(self.allocator, data) catch {};
                // Clear the completed worker outcome before the next phase is queued.
                const pending_exit = exit;
                accessClearPending(self, server, exit, data);
                if (pending_exit == null or pending_exit.? != 0) return accessFail(server, self, "cannot enumerate accounts");
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
                out.output.deinit(self.allocator);
                if (entries == null and skipped == null) accessSetOptional(self, &server.coverage_reason, "cannot enumerate accounts");
                const connected_user = server.connected_user orelse return accessFail(server, self, "cannot determine the connected user");
                const had_seed = blk: {
                    for (server.accounts.items) |a| if (std.mem.eql(u8, a.user, connected_user)) break :blk true;
                    break :blk false;
                };
                if (!had_seed) {
                    // Keep passwd entries; seed the connected account via echo ~ next tick.
                    if (entries) |list| {
                        for (list) |*e| {
                            if (std.mem.eql(u8, e.name, connected_user)) continue;
                            server.accounts.append(self.allocator, .{ .user = self.allocator.dupe(u8, e.name) catch continue, .home = self.allocator.dupe(u8, e.home) catch continue, .uid = e.uid }) catch continue;
                        }
                    }
                    if (skipped) |list| {
                        for (list) |name| {
                            if (std.mem.eql(u8, name, connected_user)) continue;
                            server.accounts.append(self.allocator, .{ .user = self.allocator.dupe(u8, name) catch continue, .home = self.allocator.dupe(u8, "") catch continue, .skipped = true }) catch continue;
                        }
                    }
                    if (!accessQueueExec(self, server, "echo ~", .seed_home, 0)) accessSetOptional(self, &server.coverage_reason, "cannot resolve the connected account's home");
                    return;
                }
                if (entries) |list| {
                    for (list) |*e| {
                        if (std.mem.eql(u8, e.name, connected_user)) continue;
                        server.accounts.append(self.allocator, .{ .user = self.allocator.dupe(u8, e.name) catch continue, .home = self.allocator.dupe(u8, e.home) catch continue, .uid = e.uid }) catch continue;
                    }
                }
                if (skipped) |list| {
                    for (list) |name| {
                        if (std.mem.eql(u8, name, connected_user)) continue;
                        server.accounts.append(self.allocator, .{ .user = self.allocator.dupe(u8, name) catch continue, .home = self.allocator.dupe(u8, "") catch continue, .skipped = true }) catch continue;
                    }
                }
                server.next_account = 0;
                server.phase = .read_accounts;
                return;
            },
            .sshd_config => {
                const acc_idx = pend.account_index;
                accessClearPending(self, server, exit, data);
                if (acc_idx >= server.accounts.items.len) return;
                const account = &server.accounts.items[acc_idx];
                account.policy_evaluated = true;
                if (exit != null and exit.? == 0) {
                    var policy = access.parseEffectiveSshdPolicy(self.allocator, data, account.user, account.uid, account.home) catch {
                        accessSetOptional(self, &account.@"error", "effective SSH key policy could not be parsed");
                        accessMarkPartial(self, server, "effective SSH key policy could not be parsed");
                        return accessContinueAccountSources(self, server, acc_idx);
                    };
                    defer policy.deinit(self.allocator);
                    account.pubkey_authentication = policy.pubkey_authentication;
                    for (policy.static_sources) |source| {
                        account.static_sources.append(self.allocator, self.allocator.dupe(u8, source) catch continue) catch continue;
                        accessAppendSourceFact(self, server, account.user, source);
                    }
                    for (policy.warnings) |warning| {
                        accessAppendSourceFact(self, server, account.user, warning);
                        accessMarkPartial(self, server, warning);
                    }
                    if (policy.pubkey_authentication == null) accessMarkPartial(self, server, "PubkeyAuthentication was not reported for an account");
                } else {
                    accessSetOptional(self, &account.@"error", "effective SSH key policy could not be evaluated");
                    accessMarkPartial(self, server, "effective SSH key policy could not be evaluated");
                    const fallback = std.fmt.allocPrint(self.allocator, "{s}/.ssh/authorized_keys", .{account.home}) catch null;
                    if (fallback) |path| {
                        account.static_sources.append(self.allocator, path) catch self.allocator.free(path);
                        accessAppendSourceFact(self, server, account.user, path);
                    }
                }
                server.phase = .read_accounts;
                accessContinueAccountSources(self, server, acc_idx);
                return;
            },
            .read_privileged => {
                const raw: *sessions.AccessExecOutcome = @ptrCast(@alignCast(pend.outcome.?));
                const acc_idx = pend.account_index;
                var path_copy: [512]u8 = undefined;
                const plen = @min(pend.sftp_path.len, path_copy.len);
                if (plen > 0) @memcpy(path_copy[0..plen], pend.sftp_path[0..plen]);
                const read_exit = raw.exit;
                const read_data = raw.data.items;
                var read_copy: ?[]u8 = null;
                if (read_exit != null and read_exit.? == 0 and read_data.len <= sshkeys.max_keys_file_bytes) {
                    read_copy = self.allocator.dupe(u8, read_data) catch null;
                }
                var message_copy: [256]u8 = undefined;
                const message = raw.message();
                const mlen = @min(message.len, message_copy.len);
                if (mlen > 0) @memcpy(message_copy[0..mlen], message[0..mlen]);
                const too_large = read_data.len > sshkeys.max_keys_file_bytes;
                accessClearPending(self, server, read_exit, &.{});
                defer if (read_copy) |bytes| self.allocator.free(bytes);
                if (acc_idx >= server.accounts.items.len) return;
                const account = &server.accounts.items[acc_idx];
                if (read_exit == null or read_exit.? != 0) {
                    const read_message = message_copy[0..mlen];
                    const missing = std.ascii.indexOfIgnoreCase(read_message, "no such file") != null or
                        std.ascii.indexOfIgnoreCase(read_message, "not found") != null;
                    if (!missing) accessSetOptional(self, &account.@"error", if (read_message.len > 0) read_message else "static key source could not be read with approved sudo");
                    accessContinueAccountSources(self, server, acc_idx);
                    return;
                }
                if (too_large or read_copy == null) {
                    accessSetOptional(self, &account.@"error", if (too_large) "static key source is too large" else "out of memory while reading the static key source");
                    accessContinueAccountSources(self, server, acc_idx);
                    return;
                }
                server.read_buffer.clearRetainingCapacity();
                server.read_buffer.appendSlice(self.allocator, read_copy.?) catch {
                    accessSetOptional(self, &account.@"error", "out of memory while reading the static key source");
                    accessContinueAccountSources(self, server, acc_idx);
                    return;
                };
                accessFinishAccountRead(self, server, acc_idx, path_copy[0..plen]);
                return;
            },
            .read_sftp => {
                const sftp_out: *sessions.SftpOutcome = @ptrCast(@alignCast(pend.outcome.?));
                const sftp_ok = sftp_out.ok;
                const sftp_fx = sftp_out.fx;
                const sftp_path = pend.sftp_path;
                const acc_idx = pend.account_index;
                var path_copy: [512]u8 = undefined;
                const plen = @min(sftp_path.len, path_copy.len);
                if (plen > 0) @memcpy(path_copy[0..plen], sftp_path[0..plen]);
                var msg_copy: [256]u8 = undefined;
                const raw_msg = sftp_out.message();
                const mlen = @min(raw_msg.len, msg_copy.len);
                if (mlen > 0) @memcpy(msg_copy[0..mlen], raw_msg[0..mlen]);
                accessClearPending(self, server, exit, data);
                if (acc_idx >= server.accounts.items.len) return;
                const acc2 = &server.accounts.items[acc_idx];
                if (!sftp_ok) {
                    const msg = msg_copy[0..mlen];
                    const missing = sftp_fx == ssh.c.LIBSSH2_FX_NO_SUCH_FILE or
                        std.ascii.indexOfIgnoreCase(msg, "no such file") != null or
                        std.ascii.indexOfIgnoreCase(msg, "not found") != null;
                    if (missing) {
                        accessContinueAccountSources(self, server, acc_idx);
                    } else {
                        accessSetOptional(self, &acc2.@"error", if (msg.len > 0) msg else "static key source could not be inspected");
                        accessContinueAccountSources(self, server, acc_idx);
                    }
                    return;
                }
                const remaining_path = path_copy[0..plen];
                server.read_buffer.clearRetainingCapacity();
                if (!accessQueueSftpData(self, server, acc_idx, remaining_path)) {
                    accessSetOptional(self, &acc2.@"error", "static key source could not be read");
                    accessContinueAccountSources(self, server, acc_idx);
                }
                return;
            },
            .read_sftp_data => {
                const sftp_out: *sessions.SftpOutcome = @ptrCast(@alignCast(pend.outcome.?));
                const sftp_path = pend.sftp_path;
                const acc_idx = pend.account_index;
                var path_copy: [512]u8 = undefined;
                const plen = @min(sftp_path.len, path_copy.len);
                if (plen > 0) @memcpy(path_copy[0..plen], sftp_path[0..plen]);
                var chunk: ?[]u8 = null;
                var eof = false;
                var read_error: ?[]const u8 = null;
                if (!sftp_out.ok or sftp_out.json == null) {
                    read_error = sftp_out.message();
                } else {
                    const parsed = std.json.parseFromSlice(struct { ok: bool, base64: []const u8 = "", eof: bool = false }, self.allocator, sftp_out.json.?, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch null;
                    if (parsed) |result| {
                        defer result.deinit();
                        const size = std.base64.standard.Decoder.calcSizeForSlice(result.value.base64) catch 0;
                        if (server.read_buffer.items.len + size > sshkeys.max_keys_file_bytes) {
                            read_error = "static key source is too large";
                        } else {
                            chunk = self.allocator.alloc(u8, size) catch null;
                            var decoded = chunk != null;
                            if (chunk) |bytes| std.base64.standard.Decoder.decode(bytes, result.value.base64) catch {
                                decoded = false;
                            };
                            if (!decoded) {
                                if (chunk) |bytes| self.allocator.free(bytes);
                                chunk = null;
                                read_error = "static key source could not be decoded";
                            } else {
                                eof = result.value.eof;
                            }
                        }
                    } else read_error = "static key source returned an invalid response";
                }
                var error_copy: [256]u8 = undefined;
                const err_len = if (read_error) |message| @min(message.len, error_copy.len) else 0;
                if (read_error) |message| if (err_len > 0) @memcpy(error_copy[0..err_len], message[0..err_len]);
                accessClearPending(self, server, exit, data);
                defer if (chunk) |bytes| self.allocator.free(bytes);
                if (acc_idx >= server.accounts.items.len) return;
                const acc2 = &server.accounts.items[acc_idx];
                if (err_len > 0) {
                    accessSetOptional(self, &acc2.@"error", error_copy[0..err_len]);
                    accessContinueAccountSources(self, server, acc_idx);
                    return;
                }
                server.read_buffer.appendSlice(self.allocator, chunk orelse &.{}) catch {
                    accessSetOptional(self, &acc2.@"error", "out of memory while reading the static key source");
                    accessContinueAccountSources(self, server, acc_idx);
                    return;
                };
                const remaining_path = path_copy[0..plen];
                if (!eof) {
                    if (!accessQueueSftpData(self, server, acc_idx, remaining_path)) {
                        accessSetOptional(self, &acc2.@"error", "static key source could not be read");
                        accessContinueAccountSources(self, server, acc_idx);
                    }
                    return;
                }
                accessFinishAccountRead(self, server, acc_idx, remaining_path);
                return;
            },
            .sudo_probe_u => {
                const u_trim = std.mem.trim(u8, data, " \t\r\n");
                _ = u_trim;
                const sudo = access.parseSudoList(exit orelse 1, data);
                const acc_idx = pend.account_index;
                accessClearPending(self, server, exit, data);
                if (acc_idx < server.accounts.items.len) {
                    const acc2 = &server.accounts.items[acc_idx];
                    accessSetOptional(self, &acc2.sudo, sudo);
                    for (server.grants.items) |*g| if (std.mem.eql(u8, g.user, acc2.user) and g.sudo.len == 0) {
                        self.allocator.free(g.sudo);
                        g.sudo = self.allocator.dupe(u8, sudo) catch continue;
                    };
                }
                return;
            },
            .seed_home => {
                const home = std.mem.trim(u8, data, " \t\r\n");
                const home_pending_exit = exit;
                accessClearPending(self, server, exit, data);
                if (home_pending_exit == null or home_pending_exit.? != 0 or home.len == 0 or home[0] != '/') return accessFail(server, self, "cannot resolve the connected account's home");
                const user2 = server.connected_user orelse return accessFail(server, self, "cannot determine the connected user");
                var already = false;
                for (server.accounts.items) |a| if (std.mem.eql(u8, a.user, user2)) {
                    already = true;
                    break;
                };
                if (!already) server.accounts.append(self.allocator, .{ .user = self.allocator.dupe(u8, user2) catch return accessFail(server, self, "out of memory"), .home = self.allocator.dupe(u8, home) catch return accessFail(server, self, "out of memory"), .uid = server.connected_uid }) catch return accessFail(server, self, "out of memory");
                if (server.phase == .enumerate) {
                    server.next_account = 0;
                    server.phase = .read_accounts;
                }
                // read_accounts with empty list will resume on the next tick.
                return;
            },
            else => {
                accessClearPending(self, server, exit, data);
                return;
            },
        }
    }
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
            if (!accessQueueExec(self, server, "whoami", .identity_whoami, 0)) return accessFail(server, self, "not connected");
            return;
        },
        .sudo_probe => {
            if (!accessQueueExec(self, server, "sudo -n -l 2>&1", .sudo_probe, 0)) return accessFail(server, self, "not connected");
            return;
        },
        .enumerate => {
            const can_enumerate = server.privileged or std.mem.eql(u8, server.sudo orelse access.sudo_unknown, access.sudo_yes);
            if (!can_enumerate) {
                if (server.connected_user == null) return accessFail(server, self, "cannot determine the connected user");
                // Non-privileged full scan: only the connected account.
                // Queue echo ~; result arrives next tick as .seed_home (see consume switch).
                // We leave .enumerate -> .read_accounts transition to the .seed_home handler or direct append below.
                // If already seeded, jump straight to read_accounts.
                for (server.accounts.items) |a| if (std.mem.eql(u8, a.user, server.connected_user.?)) {
                    server.phase = .read_accounts;
                    return;
                };
                if (!accessQueueExec(self, server, "echo ~", .seed_home, 0)) return accessFail(server, self, "not connected");
                return;
            }
            if (!accessQueueExec(self, server, if (server.privileged) "getent passwd" else "sudo -n getent passwd", .enumerate, 0)) return accessFail(server, self, "not connected");
            return;
        },
        .read_accounts => {
            if (server.accounts.items.len == 0) {
                const user2 = server.connected_user orelse return accessFail(server, self, "cannot determine the connected user");
                _ = user2;
                if (!accessQueueExec(self, server, "echo ~", .seed_home, 0)) return accessFail(server, self, "not connected");
                return;
            }
            const i = server.next_account;
            if (i >= server.accounts.items.len) {
                return accessFinishServerScan(self, server);
            }
            const acc = &server.accounts.items[i];
            if (acc.skipped) {
                server.next_account += 1;
                return;
            }
            if (acc.home.len == 0 or acc.home[0] != '/') {
                accessSetOptional(self, &acc.@"error", "cannot resolve the account's home");
                accessMarkPartial(self, server, "an account home could not be resolved");
                server.next_account += 1;
                return;
            }
            if (!acc.policy_evaluated and !accessQueueEffectivePolicy(self, server, i)) {
                accessSetOptional(self, &acc.@"error", "effective SSH key policy could not be queued");
                accessMarkPartial(self, server, "effective SSH key policy could not be queued");
                server.next_account += 1;
            }
            return;
        },
        .sshd_config => {
            server.phase = .read_accounts;
            return;
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

fn accessRegistryLock(registry: *access.Registry) void {
    while (!registry.mutex.tryLock()) std.atomic.spinLoopHint();
}

fn accessCloneJobItem(self: *Context, item: *const access.JobItem) !access.JobItem {
    const server_id = try self.allocator.dupe(u8, item.server_id);
    errdefer self.allocator.free(server_id);
    const user = try self.allocator.dupe(u8, item.user);
    errdefer self.allocator.free(user);
    const fingerprint = try self.allocator.dupe(u8, item.fingerprint);
    errdefer self.allocator.free(fingerprint);
    const expected_line_hash = try self.allocator.dupe(u8, item.expected_line_hash);
    errdefer self.allocator.free(expected_line_hash);
    const public_key_line = try self.allocator.dupe(u8, item.public_key_line);
    errdefer self.allocator.free(public_key_line);
    const new_fingerprint = try self.allocator.dupe(u8, item.new_fingerprint);
    errdefer self.allocator.free(new_fingerprint);
    const source_path = try self.allocator.dupe(u8, item.source_path);
    errdefer self.allocator.free(source_path);
    const file_sha256 = try self.allocator.dupe(u8, item.file_sha256);
    errdefer self.allocator.free(file_sha256);
    const operation_id = try self.allocator.dupe(u8, item.operation_id);
    errdefer self.allocator.free(operation_id);
    return .{
        .server_id = server_id,
        .user = user,
        .fingerprint = fingerprint,
        .expected_line_hash = expected_line_hash,
        .public_key_line = public_key_line,
        .new_fingerprint = new_fingerprint,
        .source_path = source_path,
        .file_sha256 = file_sha256,
        .operation_id = operation_id,
        .read_only = item.read_only,
        .state = .running,
    };
}

/// Called with the access registry lock held. Idle unfinished work is first
/// canceled so worker outcomes can be abandoned safely. Terminal records stay
/// pollable for thirty minutes, then leave the bounded registry.
fn accessExpireRegistryLocked(self: *Context, now_ns: i64) void {
    var scan_index: usize = 0;
    while (scan_index < self.access.scans.items.len) {
        const scan = self.access.scans.items[scan_index];
        const last_access = if (scan.last_access_ns > 0) scan.last_access_ns else scan.created_at_ns;
        if (!scan.canceled and scan.finished_at_ns == 0 and access.registryDeadlineReached(now_ns, last_access, access.registry_idle_expiry_ns)) {
            scan.canceled = true;
            scan.finished_at_ns = now_ns;
            for (scan.servers) |*server| {
                if (server.pending != null) accessClearPending(self, server, null, &.{});
                if (server.done or server.phase == .@"error") continue;
                server.phase = .@"error";
                accessSetOptional(self, &server.@"error", "scan expired after ten idle minutes");
                accessSetOptional(self, &server.coverage, access.coverage_partial);
                accessSetOptional(self, &server.coverage_reason, "scan expired before this server completed");
            }
        }
        if (access.registryDeadlineReached(now_ns, scan.finished_at_ns, access.registry_terminal_retention_ns)) {
            const expired = self.access.scans.orderedRemove(scan_index);
            expired.deinit(self.allocator);
            self.allocator.destroy(expired);
            continue;
        }
        scan_index += 1;
    }

    var job_index: usize = 0;
    while (job_index < self.access.jobs.items.len) {
        const job = self.access.jobs.items[job_index];
        const last_access = if (job.last_access_ns > 0) job.last_access_ns else job.created_at_ns;
        if (!job.finished() and access.registryDeadlineReached(now_ns, last_access, access.registry_idle_expiry_ns)) {
            for (job.items.items) |*item| {
                if (item.state == .queued) item.state = .canceled;
            }
        }
        if (job.finished() and job.finished_at_ns == 0) job.finished_at_ns = now_ns;
        if (access.registryDeadlineReached(now_ns, job.finished_at_ns, access.registry_terminal_retention_ns)) {
            const expired = self.access.jobs.orderedRemove(job_index);
            expired.deinit(self.allocator);
            self.allocator.destroy(expired);
            continue;
        }
        job_index += 1;
    }
}

fn accessCoordinatorMain(context: *anyopaque) void {
    const self: *Context = @ptrCast(@alignCast(context));
    while (!self.access.worker_stop.load(.acquire)) {
        var work: ?struct { job_id: []u8, item_index: usize, kind: access.JobKind, item: access.JobItem } = null;
        accessRegistryLock(self.access);
        const now_ns: i64 = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds);
        accessExpireRegistryLocked(self, now_ns);
        for (self.access.scans.items) |scan| {
            if (scan.canceled) continue;
            var terminal = true;
            for (scan.servers) |*server| {
                if (server.done or server.phase == .@"error") continue;
                terminal = false;
                accessAdvance(self, scan, server);
            }
            if (terminal and scan.finished_at_ns == 0) scan.finished_at_ns = now_ns;
        }
        outer: for (self.access.jobs.items) |job| {
            for (job.items.items, 0..) |*item, index| {
                if (item.state != .queued) continue;
                const cloned = accessCloneJobItem(self, item) catch {
                    accessItemError(self, item, "out of memory");
                    continue;
                };
                item.state = .running;
                work = .{
                    .job_id = self.allocator.dupe(u8, job.id) catch {
                        var owned = cloned;
                        owned.deinit(self.allocator);
                        accessItemError(self, item, "out of memory");
                        continue;
                    },
                    .item_index = index,
                    .kind = job.kind,
                    .item = cloned,
                };
                break :outer;
            }
        }
        self.access.mutex.unlock();

        if (work) |*pending| {
            var shadow = access.Job{ .id = "", .kind = pending.kind, .identity_id = "" };
            accessRunItem(self, &shadow, &pending.item);
            accessRegistryLock(self.access);
            if (self.access.jobById(pending.job_id)) |job| {
                if (pending.item_index < job.items.items.len) {
                    const target = &job.items.items[pending.item_index];
                    target.state = pending.item.state;
                    if (target.@"error") |old| self.allocator.free(old);
                    target.@"error" = if (pending.item.@"error") |message| self.allocator.dupe(u8, message) catch null else null;
                }
                if (job.finished() and job.finished_at_ns == 0) job.finished_at_ns = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds);
            }
            self.access.mutex.unlock();
            self.allocator.free(pending.job_id);
            pending.item.deinit(self.allocator);
        } else {
            std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(25), .awake) catch {};
        }
    }
}

fn accessEnsureCoordinator(self: *Context) !void {
    accessRegistryLock(self.access);
    defer self.access.mutex.unlock();
    if (self.access.worker != null) return;
    self.access.worker_stop.store(false, .release);
    self.access.worker_context = self;
    self.access.worker = try std.Thread.spawn(.{}, accessCoordinatorMain, .{self});
}

fn handleAccessScan(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessScanPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    const full = std.mem.eql(u8, payload.scope, "all_login_accounts");
    if (!std.mem.eql(u8, payload.scope, "connected_accounts") and
        !std.mem.eql(u8, payload.scope, "all_login_accounts")) return respondError(output, "invalid access scan scope");
    if (full and !payload.approved_sensitive_read) return respondError(output, "full-account scans require sensitive-read approval");

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
            var duplicate = false;
            for (ids.items) |existing| if (std.mem.eql(u8, existing, id)) {
                duplicate = true;
                break;
            };
            if (duplicate) continue;
            var found = false;
            for (servers_all) |s| {
                if (std.mem.eql(u8, s.id, id)) {
                    found = true;
                    break;
                }
            }
            if (!found) return respondError(output, "unknown server");
            try ids.append(self.allocator, try self.allocator.dupe(u8, id));
            if (ids.items.len > 256) return respondError(output, "an access scan supports at most 256 servers");
        }
    } else {
        for (servers_all) |s| {
            try ids.append(self.allocator, try self.allocator.dupe(u8, s.id));
        }
    }
    if (ids.items.len == 0 and payload.server_ids != null) return respondError(output, "select at least one server");

    var scan = self.allocator.create(access.Scan) catch return respondError(output, "out of memory");
    var registered = false;
    errdefer if (!registered) {
        scan.deinit(self.allocator);
        self.allocator.destroy(scan);
    };
    const scan_now_ns: i64 = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds);
    scan.* = .{
        .id = std.fmt.allocPrint(self.allocator, "scan-{d}", .{self.access.next_scan_id}) catch return respondError(output, "out of memory"),
        .full = full,
        .scope = if (full) "all_login_accounts" else "connected_accounts",
        .created_at_ns = scan_now_ns,
        .last_access_ns = scan_now_ns,
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
    try accessEnsureCoordinator(self);
    self.access.registerScan(scan) catch |err| return respondError(output, switch (err) {
        error.ScanCapacity => "too many active access scans; finish or cancel one before starting another",
        else => "out of memory",
    });
    registered = true;
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"scan_id\":") catch return output[0..0];
    json.writeJsonString(&writer, scan.id) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleAccessScanCancel(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessScanCancelPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    accessRegistryLock(self.access);
    defer self.access.mutex.unlock();
    const scan = self.access.scanById(parsed.value.scan_id) orelse return respondError(output, "unknown scan");
    scan.canceled = true;
    scan.finished_at_ns = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds);
    scan.last_access_ns = scan.finished_at_ns;
    for (scan.servers) |*server| {
        if (server.done or server.phase == .@"error") continue;
        if (server.pending != null) accessClearPending(self, server, null, &.{});
        server.phase = .@"error";
        accessSetOptional(self, &server.@"error", "scan canceled");
    }
    return ok_json;
}

fn handleAccessKeyInspect(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessKeyInspectPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    const normalized = sshkeys.normalizePublicKey(self.allocator, parsed.value.public_key, "") catch return respondError(output, "invalid public key");
    defer {
        self.allocator.free(normalized.line);
        self.allocator.free(normalized.fingerprint_sha256);
    }
    var key_type: []const u8 = "unknown";
    var tokens = std.mem.tokenizeAny(u8, normalized.line, " \t");
    if (tokens.next()) |value| key_type = value;
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"normalized_public_key\":") catch return output[0..0];
    json.writeJsonString(&writer, normalized.line) catch return output[0..0];
    writer.writeAll(",\"fingerprint\":") catch return output[0..0];
    json.writeJsonString(&writer, normalized.fingerprint_sha256) catch return output[0..0];
    writer.writeAll(",\"key_type\":") catch return output[0..0];
    json.writeJsonString(&writer, key_type) catch return output[0..0];
    writer.writeAll(",\"comment\":\"\"}") catch return output[0..0];
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
    try writer.writeAll(",\"source_path\":");
    try json.writeJsonString(writer, g.source_path);
    try writer.writeAll(",\"file_sha256\":");
    try json.writeJsonString(writer, g.file_sha256);
    try writer.writeAll("}");
}

fn accessWriteServerView(writer: anytype, v: *const access.ServerView) !void {
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
        try writer.writeAll(",\"source_path\":");
        try json.writeJsonString(writer, g.source_path);
        try writer.writeAll(",\"file_sha256\":");
        try json.writeJsonString(writer, g.file_sha256);
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
    accessRegistryLock(self.access);
    defer self.access.mutex.unlock();
    const scan = self.access.scanById(parsed.value.scan_id) orelse return respondError(output, "unknown scan");
    scan.last_access_ns = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds);

    var all_done = scan.canceled;
    if (!scan.canceled) all_done = true;
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
    writer.writeAll("{\"ok\":true,\"scan_id\":") catch return output[0..0];
    json.writeJsonString(&writer, scan.id) catch return output[0..0];
    writer.writeAll(",\"state\":") catch return output[0..0];
    json.writeJsonString(&writer, if (scan.canceled) "canceled" else if (all_done) "done" else "scanning") catch return output[0..0];
    writer.writeAll(",\"scope\":") catch return output[0..0];
    json.writeJsonString(&writer, scan.scope) catch return output[0..0];
    writer.print(",\"created_at_ms\":{d}", .{@divTrunc(scan.created_at_ns, std.time.ns_per_ms)}) catch return output[0..0];
    if (scan.finished_at_ns > 0) writer.print(",\"finished_at_ms\":{d}", .{@divTrunc(scan.finished_at_ns, std.time.ns_per_ms)}) catch return output[0..0];
    writer.writeAll(",\"servers\":[") catch return output[0..0];
    var first = true;
    for (views.items) |*v| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        accessWriteServerView(&writer, v) catch return output[0..0];
    }
    writer.writeAll("],\"people_page\":{") catch return output[0..0];
    var server_count: usize = 0;
    var grant_count: usize = 0;
    var coverage: []const u8 = access.coverage_partial;
    const limit = @max(@as(usize, 1), @min(parsed.value.limit, 100));
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
        const people_start = @min(parsed.value.people_offset, map.people.len);
        const people_end = @min(people_start + limit, map.people.len);
        writer.print("\"offset\":{d},\"limit\":{d},\"total\":{d},\"rows\":[", .{ people_start, limit, map.people.len }) catch return output[0..0];
        first = true;
        for (map.people[people_start..people_end]) |*p| {
            if (!first) writer.writeAll(",") catch return output[0..0];
            first = false;
            accessWritePerson(&writer, p) catch return output[0..0];
        }
        writer.writeAll("],\"has_more\":") catch return output[0..0];
        writer.writeAll(if (people_end < map.people.len) "true" else "false") catch return output[0..0];
        writer.writeAll("},\"unassigned_page\":{") catch return output[0..0];
        const unassigned_start = @min(parsed.value.unassigned_offset, map.unassigned.len);
        const unassigned_end = @min(unassigned_start + limit, map.unassigned.len);
        writer.print("\"offset\":{d},\"limit\":{d},\"total\":{d},\"rows\":[", .{ unassigned_start, limit, map.unassigned.len }) catch return output[0..0];
        first = true;
        for (map.unassigned[unassigned_start..unassigned_end]) |*u| {
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
        writer.writeAll("],\"has_more\":") catch return output[0..0];
        writer.writeAll(if (unassigned_end < map.unassigned.len) "true" else "false") catch return output[0..0];
        server_count = map.server_count;
        grant_count = map.grant_count;
        coverage = map.coverage;
        var key_count: usize = map.unassigned.len;
        for (map.people) |person| key_count += person.fingerprints.len;
        writer.writeAll("},\"metrics\":{") catch return output[0..0];
        writer.print("\"people\":{d},\"distinct_fingerprints\":{d},\"completed_servers\":{d},\"target_servers\":{d},\"observed_grants\":{d}", .{ map.people.len, key_count, server_count, scan.servers.len, grant_count }) catch return output[0..0];
        writer.writeAll("},\"coverage\":") catch return output[0..0];
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
        writer.writeAll("],\"source_warnings\":[") catch return output[0..0];
        first = true;
        for (scan.servers) |server| {
            if (server.coverage_reason) |reason| {
                if (!first) writer.writeAll(",") catch return output[0..0];
                first = false;
                writer.writeAll("{\"server_id\":") catch return output[0..0];
                json.writeJsonString(&writer, server.server_id) catch return output[0..0];
                writer.writeAll(",\"reason\":") catch return output[0..0];
                json.writeJsonString(&writer, reason) catch return output[0..0];
                writer.writeAll("}") catch return output[0..0];
            }
        }
        writer.writeAll("]}") catch return output[0..0];
    } else {
        writer.print("\"offset\":0,\"limit\":{d},\"total\":0,\"rows\":[],\"has_more\":false}},\"unassigned_page\":{{\"offset\":0,\"limit\":{d},\"total\":0,\"rows\":[],\"has_more\":false}},\"metrics\":{{\"people\":0,\"distinct_fingerprints\":0,\"completed_servers\":0,\"target_servers\":{d},\"observed_grants\":0}},\"coverage\":", .{ limit, limit, scan.servers.len }) catch return output[0..0];
        json.writeJsonString(&writer, coverage) catch return output[0..0];
        writer.writeAll(",\"sync_errors\":[],\"source_warnings\":[]}") catch return output[0..0];
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
    try writer.writeAll(",\"source_path\":");
    try json.writeJsonString(writer, g.source_path);
    try writer.writeAll(",\"file_sha256\":");
    try json.writeJsonString(writer, g.file_sha256);
    try writer.writeAll("}");
}

fn handleAccessIdentitiesList(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    _ = invocation;
    const self = contextOf(context);
    const loaded = self.access.identities.listWithRecovery(self.io) catch {
        return respondError(output, "identity registry is unreadable");
    };
    defer {
        for (loaded.identities) |*it| it.deinit(self.allocator);
        self.allocator.free(loaded.identities);
        if (loaded.recovery_error) |e| self.allocator.free(e);
        if (loaded.quarantined) |q| self.allocator.free(q);
    }
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"identities\":[") catch return output[0..0];
    var first = true;
    for (loaded.identities) |*it| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.writeAll("{\"id\":") catch return output[0..0];
        json.writeJsonString(&writer, it.id) catch return output[0..0];
        writer.writeAll(",\"name\":") catch return output[0..0];
        json.writeJsonString(&writer, it.name) catch return output[0..0];
        writer.writeAll(",\"fingerprints\":[") catch return output[0..0];
        var ffirst = true;
        for (it.fingerprints) |fp| {
            if (!ffirst) writer.writeAll(",") catch return output[0..0];
            ffirst = false;
            json.writeJsonString(&writer, fp) catch return output[0..0];
        }
        writer.writeAll("],\"bindings\":[") catch return output[0..0];
        var bfirst = true;
        for (it.bindings) |bd| {
            if (!bfirst) writer.writeAll(",") catch return output[0..0];
            bfirst = false;
            writer.writeAll("{\"fingerprint\":") catch return output[0..0];
            json.writeJsonString(&writer, bd.fingerprint) catch return output[0..0];
            writer.print(",\"shared\":{s}", .{if (bd.shared) "true" else "false"}) catch return output[0..0];
            writer.writeAll("}") catch return output[0..0];
        }
        writer.print("],\"shared\":{s},\"created_at_ms\":{d},\"revision\":{d}", .{ if (it.shared) "true" else "false", it.created_at_ms, it.revision }) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.writeAll("]") catch return output[0..0];
    if (loaded.recovery_error) |e| {
        writer.writeAll(",\"recovery_error\":") catch return output[0..0];
        json.writeJsonString(&writer, e) catch return output[0..0];
    }
    if (loaded.quarantined) |q| {
        writer.writeAll(",\"quarantined\":") catch return output[0..0];
        json.writeJsonString(&writer, q) catch return output[0..0];
    }
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn handleAccessIdentitiesSave(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessIdentitySavePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const now_ms: i64 = @divTrunc(@as(i64, @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds)), std.time.ns_per_ms);
    var saved = self.access.identities.save(self.io, parsed.value.identity, now_ms) catch |err| {
        return respondError(output, switch (err) {
            error.MissingName, error.InvalidName => "invalid identity name",
            error.NoFingerprints => "at least one fingerprint is required",
            error.TooManyFingerprints => "too many fingerprints",
            error.InvalidFingerprint => "invalid fingerprint",
            error.DuplicateFingerprint => "duplicate fingerprint",
            error.FingerprintOwned => "a fingerprint can belong to at most one person unless it is marked shared",
            error.UnknownId => "unknown identity",
            error.RevisionConflict => "identity was modified by another save; reload and retry",
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
    writer.writeAll("],\"bindings\":[") catch return output[0..0];
    var bfirst = true;
    for (saved.bindings) |bd| {
        if (!bfirst) writer.writeAll(",") catch return output[0..0];
        bfirst = false;
        writer.writeAll("{\"fingerprint\":") catch return output[0..0];
        json.writeJsonString(&writer, bd.fingerprint) catch return output[0..0];
        writer.print(",\"shared\":{s}", .{if (bd.shared) "true" else "false"}) catch return output[0..0];
        writer.writeAll("}") catch return output[0..0];
    }
    writer.print("],\"shared\":{s},\"created_at_ms\":{d},\"revision\":{d}", .{ if (saved.shared) "true" else "false", saved.created_at_ms, saved.revision }) catch return output[0..0];
    writer.writeAll("}}") catch return output[0..0];
    return writer.buffered();
}

fn handleAccessIdentitiesDelete(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessIdentityDeletePayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const expected_revision = parsed.value.expected_revision orelse return respondError(output, "identity revision is required");
    if (parsed.value.confirm_name.len == 0) return respondError(output, "confirmation name is required");
    var identity = self.access.identities.find(self.io, parsed.value.id) catch return respondError(output, "identity registry is unreadable");
    defer if (identity) |*item| item.deinit(self.allocator);
    const current = identity orelse return respondError(output, "unknown identity");
    if (!std.mem.eql(u8, parsed.value.confirm_name, current.name)) return respondError(output, "confirmation name does not match");
    const del_rev: ?u64 = expected_revision;
    const deleted = self.access.identities.delete(self.io, parsed.value.id, del_rev) catch |err| {
        return respondError(output, switch (err) {
            error.RevisionConflict => "identity was modified by another save; reload and retry",
            else => "identity registry is unreadable",
        });
    };
    if (!deleted) {
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
    const id = try std.fmt.allocPrint(self.allocator, "job-{d}", .{self.access.next_job_id});
    errdefer self.allocator.free(id);
    const owned_identity_id = try self.allocator.dupe(u8, identity_id);
    errdefer self.allocator.free(owned_identity_id);
    const operation_id = try self.allocator.dupe(u8, "");
    errdefer self.allocator.free(operation_id);
    const job_now_ns: i64 = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds);
    job.* = .{
        .id = id,
        .kind = kind,
        .identity_id = owned_identity_id,
        .operation_id = operation_id,
        .created_at_ns = job_now_ns,
        .last_access_ns = job_now_ns,
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

fn accessExistingOperationId(self: *Context, operation_id: []const u8) ?[]u8 {
    if (operation_id.len == 0) return null;
    accessRegistryLock(self.access);
    defer self.access.mutex.unlock();
    for (self.access.jobs.items) |job| {
        if (std.mem.eql(u8, job.operation_id, operation_id)) {
            return self.allocator.dupe(u8, job.id) catch null;
        }
    }
    return null;
}

fn accessRespondExistingJob(output: []u8, job_id: []const u8) []const u8 {
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job_id\":") catch return output[0..0];
    json.writeJsonString(&writer, job_id) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn accessFrozenGrantExists(
    self: *Context,
    scan_id: []const u8,
    server_id: []const u8,
    user: []const u8,
    fingerprint: []const u8,
    source_path: []const u8,
    line_hash: []const u8,
    file_sha256: []const u8,
) bool {
    if (scan_id.len == 0 or source_path.len == 0 or line_hash.len == 0 or file_sha256.len == 0) return false;
    accessRegistryLock(self.access);
    defer self.access.mutex.unlock();
    const scan = self.access.scanById(scan_id) orelse return false;
    scan.last_access_ns = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds);
    if (scan.canceled or scan.finished_at_ns == 0) return false;
    for (scan.servers) |server| {
        if (!std.mem.eql(u8, server.server_id, server_id)) continue;
        for (server.grants.items) |grant| {
            if (std.mem.eql(u8, grant.user, user) and
                std.mem.eql(u8, grant.fingerprint, fingerprint) and
                std.mem.eql(u8, grant.source_path, source_path) and
                std.mem.eql(u8, grant.line_hash, line_hash) and
                std.mem.eql(u8, grant.file_sha256, file_sha256)) return true;
        }
    }
    return false;
}

fn accessBindFingerprint(self: *Context, identity: *const access.Identity, fingerprint: []const u8) !void {
    if (accessIdentityHasFingerprint(identity, fingerprint)) return;
    if (identity.bindings.len >= access.max_identity_fingerprints) return error.TooManyFingerprints;
    var bindings = try self.allocator.alloc(access.IdentityBindingInput, identity.fingerprints.len + 1);
    defer self.allocator.free(bindings);
    for (identity.fingerprints, 0..) |existing, i| {
        bindings[i] = .{ .fingerprint = existing, .shared = identity.bindingShared(existing) };
    }
    bindings[identity.fingerprints.len] = .{ .fingerprint = fingerprint };
    const now_ms: i64 = @divTrunc(@as(i64, @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds)), std.time.ns_per_ms);
    var saved = try self.access.identities.save(self.io, .{
        .id = identity.id,
        .name = identity.name,
        .bindings = bindings,
        .expected_revision = identity.revision,
    }, now_ms);
    saved.deinit(self.allocator);
}

fn handleAccessOffboard(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessOffboardPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    const payload = parsed.value;
    if (payload.grants.len == 0) return respondError(output, "no grants selected");
    if (payload.grants.len > 256) return respondError(output, "an access job supports at most 256 items");
    if (payload.operation_id.len == 0) return respondError(output, "operation_id is required");
    if (payload.scan_id.len == 0) return respondError(output, "scan_id is required");
    const identity_revision = payload.identity_revision orelse return respondError(output, "identity revision is required");
    if (payload.confirm_name.len == 0) return respondError(output, "confirmation name is required");
    if (accessExistingOperationId(self, payload.operation_id)) |existing_job_id| {
        defer self.allocator.free(existing_job_id);
        return accessRespondExistingJob(output, existing_job_id);
    }
    var identity = self.access.identities.find(self.io, payload.identity_id) catch {
        return respondError(output, "identity registry is unreadable");
    };
    defer if (identity) |*i| i.deinit(self.allocator);
    const id = identity orelse return respondError(output, "unknown identity");
    if (identity_revision != id.revision) return respondError(output, "identity changed since the preview; refresh and retry");
    if (!std.mem.eql(u8, payload.confirm_name, id.name)) return respondError(output, "confirmation name does not match");
    var job = accessNewJob(self, .offboard, payload.identity_id) catch return respondError(output, "out of memory");
    errdefer {
        job.deinit(self.allocator);
        self.allocator.destroy(job);
    }
    const owned_operation_id = self.allocator.dupe(u8, payload.operation_id) catch return respondError(output, "out of memory");
    self.allocator.free(job.operation_id);
    job.operation_id = owned_operation_id;
    for (payload.grants) |g| {
        if (!accessIdentityHasFingerprint(&id, g.fingerprint)) return respondError(output, "fingerprint is not part of this identity");
        if (!access.safeUserName(g.user)) return respondError(output, "invalid user name");
        if (g.line_hash.len == 0 or g.source_path.len == 0 or g.file_sha256.len == 0) return respondError(output, "the frozen source, line hash, and file hash are required");
        if (!accessServerExists(self, g.server_id)) return respondError(output, "unknown server");
        if (!accessFrozenGrantExists(self, payload.scan_id, g.server_id, g.user, g.fingerprint, g.source_path, g.line_hash, g.file_sha256)) return respondError(output, "a selected grant no longer matches the completed scan; refresh and retry");
        job.items.append(self.allocator, .{
            .server_id = self.allocator.dupe(u8, g.server_id) catch return respondError(output, "out of memory"),
            .user = self.allocator.dupe(u8, g.user) catch return respondError(output, "out of memory"),
            .fingerprint = self.allocator.dupe(u8, g.fingerprint) catch return respondError(output, "out of memory"),
            .expected_line_hash = self.allocator.dupe(u8, g.line_hash) catch return respondError(output, "out of memory"),
            .public_key_line = self.allocator.dupe(u8, "") catch return respondError(output, "out of memory"),
            .new_fingerprint = self.allocator.dupe(u8, "") catch return respondError(output, "out of memory"),
            .source_path = self.allocator.dupe(u8, g.source_path) catch return respondError(output, "out of memory"),
            .file_sha256 = self.allocator.dupe(u8, g.file_sha256) catch return respondError(output, "out of memory"),
            .operation_id = self.allocator.dupe(u8, payload.operation_id) catch return respondError(output, "out of memory"),
        }) catch return respondError(output, "out of memory");
    }
    try accessEnsureCoordinator(self);
    self.access.registerJob(job) catch |err| return respondError(output, switch (err) {
        error.JobCapacity => "too many active access jobs; finish or cancel one before starting another",
        else => "out of memory",
    });
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
    if (payload.grants.len > 256) return respondError(output, "an access job supports at most 256 items");
    if (payload.operation_id.len == 0) return respondError(output, "operation_id is required");
    const identity_revision = payload.identity_revision orelse return respondError(output, "identity revision is required");
    if (accessExistingOperationId(self, payload.operation_id)) |existing_job_id| {
        defer self.allocator.free(existing_job_id);
        return accessRespondExistingJob(output, existing_job_id);
    }
    var identity = self.access.identities.find(self.io, payload.identity_id) catch {
        return respondError(output, "identity registry is unreadable");
    };
    defer if (identity) |*i| i.deinit(self.allocator);
    const id = identity orelse return respondError(output, "unknown identity");
    if (identity_revision != id.revision) return respondError(output, "identity changed since the preview; refresh and retry");
    for (payload.grants, 0..) |g, index| {
        if (!std.mem.eql(u8, g.target.kind, "account") and !std.mem.eql(u8, g.target.kind, "read_only_role")) return respondError(output, "invalid onboard target kind");
        if (!access.safeUserName(g.target.name)) return respondError(output, "invalid user name");
        if (std.mem.eql(u8, g.target.kind, "read_only_role") and std.mem.eql(u8, g.target.name, "root")) return respondError(output, "read-only access to root is not supported");
        for (payload.grants[index + 1 ..]) |other| {
            if (std.mem.eql(u8, g.server_id, other.server_id) and std.mem.eql(u8, g.target.kind, other.target.kind) and std.mem.eql(u8, g.target.name, other.target.name)) return respondError(output, "duplicate onboard target");
        }
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
    for (payload.grants) |g| {
        if (!accessServerExists(self, g.server_id)) return respondError(output, "unknown server");
    }

    accessBindFingerprint(self, &id, normalized.fingerprint_sha256) catch |err| return respondError(output, switch (err) {
        error.RevisionConflict => "identity changed since the preview; refresh and retry",
        error.FingerprintOwned => "the inspected fingerprint belongs to another identity",
        error.TooManyFingerprints => "the identity has too many fingerprints",
        else => "identity registry is unreadable",
    });

    var job = accessNewJob(self, .onboard, payload.identity_id) catch return respondError(output, "out of memory");
    errdefer {
        job.deinit(self.allocator);
        self.allocator.destroy(job);
    }
    const owned_operation_id = self.allocator.dupe(u8, payload.operation_id) catch return respondError(output, "out of memory");
    self.allocator.free(job.operation_id);
    job.operation_id = owned_operation_id;
    for (payload.grants) |g| {
        job.items.append(self.allocator, .{
            .server_id = self.allocator.dupe(u8, g.server_id) catch return respondError(output, "out of memory"),
            .user = self.allocator.dupe(u8, g.target.name) catch return respondError(output, "out of memory"),
            .fingerprint = self.allocator.dupe(u8, normalized.fingerprint_sha256) catch return respondError(output, "out of memory"),
            .expected_line_hash = self.allocator.dupe(u8, "") catch return respondError(output, "out of memory"),
            .public_key_line = self.allocator.dupe(u8, normalized.line) catch return respondError(output, "out of memory"),
            .new_fingerprint = self.allocator.dupe(u8, "") catch return respondError(output, "out of memory"),
            .read_only = std.mem.eql(u8, g.target.kind, "read_only_role"),
            .source_path = self.allocator.dupe(u8, "") catch return respondError(output, "out of memory"),
            .file_sha256 = self.allocator.dupe(u8, "") catch return respondError(output, "out of memory"),
            .operation_id = self.allocator.dupe(u8, payload.operation_id) catch return respondError(output, "out of memory"),
        }) catch return respondError(output, "out of memory");
    }
    try accessEnsureCoordinator(self);
    self.access.registerJob(job) catch |err| return respondError(output, switch (err) {
        error.JobCapacity => "too many active access jobs; finish or cancel one before starting another",
        else => "out of memory",
    });
    var detail_buf: [192]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "identity={s} fingerprint={s} items={d}", .{ payload.identity_id, normalized.fingerprint_sha256, payload.grants.len }) catch "access.onboard";
    sshkeysAudit(self, "access.onboard", "", detail);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job_id\":") catch return output[0..0];
    json.writeJsonString(&writer, job.id) catch return output[0..0];
    writer.writeAll(",\"fingerprint\":") catch return output[0..0];
    json.writeJsonString(&writer, normalized.fingerprint_sha256) catch return output[0..0];
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
    if (payload.grants.len > 256) return respondError(output, "an access job supports at most 256 items");
    if (payload.operation_id.len == 0) return respondError(output, "operation_id is required");
    if (payload.scan_id.len == 0) return respondError(output, "scan_id is required");
    const identity_revision = payload.identity_revision orelse return respondError(output, "identity revision is required");
    if (accessExistingOperationId(self, payload.operation_id)) |existing_job_id| {
        defer self.allocator.free(existing_job_id);
        return accessRespondExistingJob(output, existing_job_id);
    }
    var identity = self.access.identities.find(self.io, payload.identity_id) catch {
        return respondError(output, "identity registry is unreadable");
    };
    defer if (identity) |*i| i.deinit(self.allocator);
    const id = identity orelse return respondError(output, "unknown identity");
    if (identity_revision != id.revision) return respondError(output, "identity changed since the preview; refresh and retry");
    if (!accessIdentityHasFingerprint(&id, payload.old_fingerprint)) return respondError(output, "the old fingerprint is not part of this identity");
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
    if (std.mem.eql(u8, payload.old_fingerprint, normalized.fingerprint_sha256)) return respondError(output, "the new key must differ from the old key");
    for (payload.grants) |g| {
        if (!access.safeUserName(g.user)) return respondError(output, "invalid user name");
        if (g.line_hash.len == 0 or g.source_path.len == 0 or g.file_sha256.len == 0) return respondError(output, "the frozen source, line hash, and file hash are required");
        if (!accessServerExists(self, g.server_id)) return respondError(output, "unknown server");
        if (!accessFrozenGrantExists(self, payload.scan_id, g.server_id, g.user, payload.old_fingerprint, g.source_path, g.line_hash, g.file_sha256)) return respondError(output, "a selected grant no longer matches the completed scan; refresh and retry");
    }
    accessBindFingerprint(self, &id, normalized.fingerprint_sha256) catch |err| return respondError(output, switch (err) {
        error.RevisionConflict => "identity changed since the preview; refresh and retry",
        error.FingerprintOwned => "the inspected fingerprint belongs to another identity",
        error.TooManyFingerprints => "the identity has too many fingerprints",
        else => "identity registry is unreadable",
    });

    var job = accessNewJob(self, .rotate, payload.identity_id) catch return respondError(output, "out of memory");
    errdefer {
        job.deinit(self.allocator);
        self.allocator.destroy(job);
    }
    const owned_operation_id = self.allocator.dupe(u8, payload.operation_id) catch return respondError(output, "out of memory");
    self.allocator.free(job.operation_id);
    job.operation_id = owned_operation_id;
    for (payload.grants) |g| {
        job.items.append(self.allocator, .{
            .server_id = self.allocator.dupe(u8, g.server_id) catch return respondError(output, "out of memory"),
            .user = self.allocator.dupe(u8, g.user) catch return respondError(output, "out of memory"),
            .fingerprint = self.allocator.dupe(u8, payload.old_fingerprint) catch return respondError(output, "out of memory"),
            .expected_line_hash = self.allocator.dupe(u8, g.line_hash) catch return respondError(output, "out of memory"),
            .public_key_line = self.allocator.dupe(u8, normalized.line) catch return respondError(output, "out of memory"),
            .new_fingerprint = self.allocator.dupe(u8, normalized.fingerprint_sha256) catch return respondError(output, "out of memory"),
            .source_path = self.allocator.dupe(u8, g.source_path) catch return respondError(output, "out of memory"),
            .file_sha256 = self.allocator.dupe(u8, g.file_sha256) catch return respondError(output, "out of memory"),
            .operation_id = self.allocator.dupe(u8, payload.operation_id) catch return respondError(output, "out of memory"),
        }) catch return respondError(output, "out of memory");
    }
    try accessEnsureCoordinator(self);
    self.access.registerJob(job) catch |err| return respondError(output, switch (err) {
        error.JobCapacity => "too many active access jobs; finish or cancel one before starting another",
        else => "out of memory",
    });
    var detail_buf: [192]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "identity={s} old={s} items={d}", .{ payload.identity_id, payload.old_fingerprint, payload.grants.len }) catch "access.rotate";
    sshkeysAudit(self, "access.rotate", "", detail);
    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"job_id\":") catch return output[0..0];
    json.writeJsonString(&writer, job.id) catch return output[0..0];
    writer.writeAll(",\"new_fingerprint\":") catch return output[0..0];
    json.writeJsonString(&writer, normalized.fingerprint_sha256) catch return output[0..0];
    writer.writeAll("}") catch return output[0..0];
    return writer.buffered();
}

fn accessItemError(self: *Context, item: *access.JobItem, msg: []const u8) void {
    item.state = .@"error";
    if (item.@"error") |e| self.allocator.free(e);
    item.@"error" = self.allocator.dupe(u8, msg) catch null;
}

fn accessItemConflict(self: *Context, item: *access.JobItem, msg: []const u8) void {
    item.state = .conflict;
    if (item.@"error") |e| self.allocator.free(e);
    item.@"error" = self.allocator.dupe(u8, msg) catch null;
}

fn accessAuditItem(self: *Context, action: []const u8, item: *const access.JobItem) void {
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "server={s} user={s} fingerprint={s}", .{ item.server_id, item.user, item.fingerprint }) catch action;
    sshkeysAudit(self, action, item.server_id, detail);
}

/// Executes one job item. Rotation is add -> verify -> remove, so a failure
/// never removes the old key before the replacement is proven present.
fn accessRunItem(self: *Context, job: *access.Job, item: *access.JobItem) void {
    var msg: []const u8 = "";
    switch (job.kind) {
        .offboard => {
            if (item.source_path.len == 0 or item.source_path[0] != '/' or std.mem.indexOf(u8, item.source_path, "..") != null) return accessItemError(self, item, "source path is not the expected static source");
            const current = sshkeysRead(self, item.server_id, item.source_path) orelse return accessItemError(self, item, "key source could not be read");
            defer self.allocator.free(current);
            var current_sha: [32]u8 = undefined;
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(current);
            hasher.final(&current_sha);
            const current_hex = std.fmt.bytesToHex(current_sha, .lower);
            if (!std.mem.eql(u8, current_hex[0..], item.file_sha256)) return accessItemConflict(self, item, "authorized_keys changed since the preview; refresh and retry");
            var write_err_buf: [256]u8 = undefined;
            const rewritten = sshkeysRewriteCore(self, item.server_id, item.source_path, item.fingerprint, item.expected_line_hash, null, item.user, &msg, &write_err_buf) orelse {
                if (std.mem.indexOf(u8, msg, "changed since") != null) return accessItemConflict(self, item, msg);
                return accessItemError(self, item, msg);
            };
            defer self.allocator.free(rewritten);
            accessAuditItem(self, "access.offboard", item);
            item.state = .done;
        },
        .rotate => {
            if (item.source_path.len == 0 or item.source_path[0] != '/' or std.mem.indexOf(u8, item.source_path, "..") != null) return accessItemError(self, item, "source path is not the expected static source");
            const current = sshkeysRead(self, item.server_id, item.source_path) orelse return accessItemError(self, item, "key source could not be read");
            defer self.allocator.free(current);
            var current_sha: [32]u8 = undefined;
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(current);
            hasher.final(&current_sha);
            const current_hex = std.fmt.bytesToHex(current_sha, .lower);
            if (!std.mem.eql(u8, current_hex[0..], item.file_sha256)) return accessItemConflict(self, item, "authorized_keys changed since the preview; refresh and retry");

            var parsed_current = sshkeys.parse(self.allocator, current) catch return accessItemError(self, item, "failed to parse authorized_keys");
            defer parsed_current.deinit(self.allocator);
            const old_target = sshkeysFindTarget(&parsed_current, item.fingerprint, item.expected_line_hash) orelse return accessItemConflict(self, item, "the old key changed since the preview; refresh and retry");
            var replacement_present = false;
            for (parsed_current.keys) |*key| {
                if (key.parsed and std.mem.eql(u8, key.fingerprint_sha256, item.new_fingerprint)) {
                    replacement_present = true;
                    break;
                }
            }
            if (!replacement_present) {
                var staged: std.ArrayList(u8) = .empty;
                defer staged.deinit(self.allocator);
                staged.appendSlice(self.allocator, current) catch return accessItemError(self, item, "out of memory");
                if (current.len > 0 and current[current.len - 1] != '\n') staged.append(self.allocator, '\n') catch return accessItemError(self, item, "out of memory");
                if (old_target.options.len > 0) {
                    staged.appendSlice(self.allocator, old_target.options) catch return accessItemError(self, item, "out of memory");
                    staged.append(self.allocator, ' ') catch return accessItemError(self, item, "out of memory");
                }
                staged.appendSlice(self.allocator, item.public_key_line) catch return accessItemError(self, item, "out of memory");
                staged.append(self.allocator, '\n') catch return accessItemError(self, item, "out of memory");
                const mode = sshkeysMode(self, item.server_id, item.source_path);
                var add_error_buf: [256]u8 = undefined;
                if (sshkeysWrite(self, item.server_id, item.source_path, staged.items, mode, item.user, &add_error_buf)) |write_message| return accessItemError(self, item, write_message);
            }

            const verified = sshkeysRead(self, item.server_id, item.source_path) orelse return accessItemError(self, item, "the replacement key could not be verified");
            defer self.allocator.free(verified);
            var parsed_verified = sshkeys.parse(self.allocator, verified) catch return accessItemError(self, item, "the replacement key could not be verified");
            defer parsed_verified.deinit(self.allocator);
            var verified_present = false;
            for (parsed_verified.keys) |*key| {
                if (key.parsed and std.mem.eql(u8, key.fingerprint_sha256, item.new_fingerprint)) {
                    verified_present = true;
                    break;
                }
            }
            if (!verified_present) return accessItemError(self, item, "the replacement key could not be verified");

            var remove_error_buf: [256]u8 = undefined;
            const rewritten = sshkeysRewriteCore(self, item.server_id, item.source_path, item.fingerprint, item.expected_line_hash, null, item.user, &msg, &remove_error_buf) orelse {
                if (std.mem.indexOf(u8, msg, "changed since") != null) return accessItemConflict(self, item, msg);
                return accessItemError(self, item, msg);
            };
            defer self.allocator.free(rewritten);
            accessAuditItem(self, "access.rotate", item);
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
    accessRegistryLock(self.access);
    defer self.access.mutex.unlock();
    const job = self.access.jobById(parsed.value.job_id) orelse return respondError(output, "unknown job");
    job.last_access_ns = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds);

    var writer = std.Io.Writer.fixed(output);
    writer.writeAll("{\"ok\":true,\"state\":") catch return output[0..0];
    var has_error = false;
    var all_canceled = job.items.items.len > 0;
    var all_queued = job.items.items.len > 0;
    var any_canceled = false;
    for (job.items.items) |item| {
        if (item.state == .@"error" or item.state == .conflict) has_error = true;
        if (item.state != .canceled) all_canceled = false;
        if (item.state == .canceled) any_canceled = true;
        if (item.state != .queued) all_queued = false;
    }
    json.writeJsonString(&writer, if (all_canceled) "canceled" else if (all_queued) "queued" else if (job.finished() and (has_error or any_canceled)) "partial" else if (job.finished()) "done" else "running") catch return output[0..0];
    writer.writeAll(",\"results\":[") catch return output[0..0];
    var first = true;
    for (job.items.items) |*item| {
        if (!first) writer.writeAll(",") catch return output[0..0];
        first = false;
        writer.writeAll("{\"server_id\":") catch return output[0..0];
        json.writeJsonString(&writer, item.server_id) catch return output[0..0];
        writer.writeAll(",\"user\":") catch return output[0..0];
        json.writeJsonString(&writer, item.user) catch return output[0..0];
        writer.writeAll(",\"source_path\":") catch return output[0..0];
        json.writeJsonString(&writer, item.source_path) catch return output[0..0];
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

fn handleAccessJobCancel(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessJobCancelPayload, self.allocator, invocation.request.payload) catch return respondError(output, "invalid payload");
    defer parsed.deinit();
    accessRegistryLock(self.access);
    defer self.access.mutex.unlock();
    const job = self.access.jobById(parsed.value.job_id) orelse return respondError(output, "unknown job");
    job.last_access_ns = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds);
    for (job.items.items) |*item| {
        if (item.state == .queued) item.state = .canceled;
    }
    if (job.finished() and job.finished_at_ns == 0) job.finished_at_ns = job.last_access_ns;
    return ok_json;
}

fn handleAccessExport(context: *anyopaque, invocation: native_sdk.bridge.Invocation, output: []u8) anyerror![]const u8 {
    const self = contextOf(context);
    var parsed = parsePayload(AccessExportPayload, self.allocator, invocation.request.payload) catch {
        return respondError(output, "invalid payload");
    };
    defer parsed.deinit();
    accessRegistryLock(self.access);
    defer self.access.mutex.unlock();
    const format = parsed.value.format;
    if (!std.mem.eql(u8, format, "csv") and !std.mem.eql(u8, format, "json")) return respondError(output, "invalid format");
    if (parsed.value.scan_id.len == 0) return respondError(output, "scan_id is required");
    if (parsed.value.path.len == 0) return respondError(output, "an export path is required");
    const want_scan: ?*access.Scan = self.access.scanById(parsed.value.scan_id);
    const scan = want_scan orelse return respondError(output, "no completed scan yet");
    scan.last_access_ns = @intCast(std.Io.Timestamp.now(self.io, .real).nanoseconds);
    if (scan.canceled or scan.finished_at_ns == 0) return respondError(output, "the selected scan is not complete");
    const identities = self.access.identities.list(self.io) catch return respondError(output, "identity registry is unreadable");
    defer {
        for (identities) |*i| i.deinit(self.allocator);
        self.allocator.free(identities);
    }
    const scans = [_]*access.Scan{scan};
    var map = access.buildMap(self.allocator, &scans, identities) catch return respondError(output, "out of memory");
    defer map.deinit(self.allocator);
    // Pagination: cursor/limit slice by rows (csv lines excluding header, json items).
    const total_csv_rows = blk: {
        var n: usize = 0;
        for (map.people) |*p| n += p.grants.len;
        for (map.unassigned) |*u| n += u.grants.len;
        n += map.sync_errors.len;
        n += map.source_warnings.len;
        break :blk n;
    };
    // For json we export the full document; pagination only applies to csv file writes.
    const content = if (std.mem.eql(u8, format, "json"))
        access.exportJson(self.allocator, &map) catch return respondError(output, "out of memory")
    else
        access.exportCsv(self.allocator, &map) catch return respondError(output, "out of memory");
    defer self.allocator.free(content);
    // Atomic file write via the native save-dialog path.
    if (parsed.value.path.len > 0) {
        if (std.mem.indexOf(u8, parsed.value.path, "\x00") != null) return respondError(output, "invalid path");
        const dir = std.fs.path.dirname(parsed.value.path) orelse return respondError(output, "invalid path");
        // Use sibling temp + fsync + rename. Never fall back to truncating the
        // destination because that would make a failed audit export destructive.
        {
            var dir_io = std.Io.Dir.openDirAbsolute(self.io, dir, .{}) catch return respondError(output, "cannot open the export folder");
            defer dir_io.close(self.io);
            const tmp_name = std.fmt.allocPrint(self.allocator, ".{s}.oars-tmp", .{std.fs.path.basename(parsed.value.path)}) catch return respondError(output, "out of memory");
            defer self.allocator.free(tmp_name);
            {
                var f = dir_io.createFile(self.io, tmp_name, .{ .truncate = true, .read = false }) catch return respondError(output, "cannot write file");
                defer f.close(self.io);
                f.writeStreamingAll(self.io, content) catch return respondError(output, "cannot write file");
                f.sync(self.io) catch {};
            }
            dir_io.rename(tmp_name, dir_io, std.fs.path.basename(parsed.value.path), self.io) catch return respondError(output, "cannot write file");
        }
        var writer = std.Io.Writer.fixed(output);
        writer.writeAll("{\"ok\":true,\"format\":") catch return output[0..0];
        json.writeJsonString(&writer, format) catch return output[0..0];
        writer.writeAll(",\"path\":") catch return output[0..0];
        json.writeJsonString(&writer, parsed.value.path) catch return output[0..0];
        writer.print(",\"rows\":{d},\"formula_safe\":{s}}}", .{ total_csv_rows, if (std.mem.eql(u8, format, "csv")) "true" else "false" }) catch return output[0..0];
        return writer.buffered();
    }
    unreachable;
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
