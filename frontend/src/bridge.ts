import type {
  Server,
  ServerDraft,
  PollResult,
  MonitorSnapshot,
  LogSource,
  LogScanResult,
  LogReadResult,
  LogClearResult,
  RemotePath,
  LocalLsResult,
  SftpLsResult,
  SftpStatResult,
  SftpReadResult,
  SftpWriteResult,
  SftpSaveParams,
  SftpFolderSizeResult,
  SftpTransferSnapshot,
  SftpOpStart,
  VncStartResult,
  VncProbeResult,
  VncSetupResult,
  VncPollResult,
  ScriptsListResult,
  ScriptDraft,
  Script,
  ScriptRunVars,
  BroadcastPreview,
  BroadcastPollResult,
  AccessGrant,
  AccessScanResponse,
  AccessPollResponse,
  AccessIdentitiesListResponse,
  AccessIdentity,
  AccessJobPollResponse,
  AccessExportResponse,
  AccessKeyInspectResponse,
  AccessScope,
  GeneratedSshKey,
  SshKeyEntry,
  SshRole,
} from "./types";

// Typed bridge client over window.zero.

declare global {
  interface Window {
    zero?: {
      invoke(command: string, payload?: unknown): Promise<unknown>;
    };
  }
}

export class BridgeError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export async function invoke<T = unknown>(
  command: string,
  payload: unknown = {}
): Promise<T> {
  const zero = window.zero;
  if (!zero) throw new BridgeError("no_bridge", "Native bridge is not available");
  let result: any;
  try {
    result = await zero.invoke(command, payload);
  } catch (e: any) {
    throw new BridgeError(e?.code ?? "invoke_failed", e?.message ?? String(e));
  }
  // Our handlers resolve with an envelope when they hit a user-facing
  // error; the framework rejects for transport-level failures.
  if (result && typeof result === "object" && result.ok === false) {
    throw new BridgeError("command_failed", result.error ?? "command failed");
  }
  return result as T;
}

// Keychain-backed secrets (native-sdk.credentials, permission-gated).
// General credentials may be cached to avoid repeated prompts in unsigned
// debug builds. Deployment reads use the transient path below and never enter
// this process-lifetime cache.
const secretCache = new Map<string, string>();

export const vault = {
  service: "dev.native_sdk.oars",
  async set(account: string, secret: string): Promise<void> {
    await invoke("native-sdk.credentials.set", {
      service: this.service,
      account,
      secret,
    });
    secretCache.set(account, secret);
  },
  async get(account: string): Promise<string | null> {
    const cached = secretCache.get(account);
    if (cached !== undefined) return cached;
    const secret = await invoke<string | null>("native-sdk.credentials.get", {
      service: this.service,
      account,
    });
    if (typeof secret === "string") secretCache.set(account, secret);
    return secret;
  },
  // Transient deploy secrets: bypass cache, never store (prevents
  // deploy values from lingering in secretCache for the session).
  async deployTransientGet(account: string): Promise<string | null> {
    const secret = await invoke<string | null>("native-sdk.credentials.get", {
      service: this.service,
      account,
    });
    return secret;
  },
  async transientForget(account: string): Promise<void> {
    secretCache.delete(account);
  },
  async delete(account: string): Promise<void> {
    await invoke("native-sdk.credentials.delete", {
      service: this.service,
      account,
    });
    secretCache.delete(account);
  },
};

export async function pickFile(title: string, allowDirectories = false): Promise<string | null> {
  const result = await invoke<string[] | null>("native-sdk.dialog.openFile", {
    title,
    allowDirectories,
  });
  return result && result.length > 0 ? result[0] : null;
}

export async function pickDirectory(title: string, defaultPath?: string): Promise<string | null> {
  const result = await invoke<string[] | null>("native-sdk.dialog.openFile", {
    title,
    defaultPath,
    allowMultiple: false,
    allowDirectories: true,
  });
  return result && result.length > 0 ? result[0] : null;
}

// Native save dialog (native-sdk.dialog.saveFile). Resolves to the chosen
// path, or null when the user cancels. The caller owns the path: local
// files are only ever written by the SFTP transfer machinery, never by
// frontend code.
export async function pickSaveFile(
  title: string,
  defaultName?: string,
  defaultPath?: string,
): Promise<string | null> {
  const result = await invoke<string | null>("native-sdk.dialog.saveFile", {
    title,
    defaultName,
    defaultPath,
  });
  return result ?? null;
}

// --- Oars commands --------------------------------------------------------

export const api = {
  local: {
    ls: (path: string) => invoke<LocalLsResult>("oars.local.ls", { path }),
  },
  servers: {
    list: () => invoke<{ servers: Server[]; recovery_error?: string }>("oars.servers.list", {}),
    save: (server: ServerDraft) => invoke<{ server: Server }>("oars.servers.save", server),
    delete: (id: string) => invoke<{ ok: boolean }>("oars.servers.delete", { id }),
  },
  ssh: {
    connect: (serverId: string, password?: string, passphrase?: string) =>
      invoke("oars.ssh.connect", { server_id: serverId, password, passphrase }),
    disconnect: (serverId: string) => invoke("oars.ssh.disconnect", { server_id: serverId }),
    input: (serverId: string, data: string) => invoke("oars.ssh.input", { server_id: serverId, data }),
    exec: (serverId: string, command: string) => invoke<{ channel: number }>("oars.ssh.exec", { server_id: serverId, command }),
    closeChannel: (serverId: string, channel: number) => invoke("oars.ssh.closeChannel", { server_id: serverId, channel }),
    resize: (serverId: string, cols: number, rows: number) =>
      invoke("oars.ssh.resize", { server_id: serverId, cols, rows }),
    trust: (serverId: string, accept: boolean) => invoke("oars.ssh.trust", { server_id: serverId, accept }),
    retrust: (serverId: string, confirmName: string) =>
      invoke<{ server: Server }>("oars.ssh.retrust", { server_id: serverId, confirm_name: confirmName }),
    poll: (serverId: string, cursors?: Array<{ channel: number; cursor: number }>, rewind?: boolean) =>
      invoke<PollResult>("oars.ssh.poll", { server_id: serverId, cursors: cursors ?? null, rewind: rewind ?? false }),
  },
  monitor: {
    poll: (serverId: string) => invoke<MonitorSnapshot>("oars.monitor.poll", { server_id: serverId }),
    probe: (serverId: string) => invoke<{ ok: boolean }>("oars.monitor.probe", { server_id: serverId }),
    cleanDiskEstimate: (serverId: string, plan: "journal" | "apt") =>
      invoke<{ ok: boolean; channel: number }>("oars.monitor.cleanDiskEstimate", { server_id: serverId, plan }),
    cleanDisk: (serverId: string, plan: "journal" | "apt") =>
      invoke<{ ok: boolean; channel: number }>("oars.monitor.cleanDisk", { server_id: serverId, plan }),
    dropCaches: (serverId: string, level: 1 | 2 | 3 = 3) =>
      invoke<{ ok: boolean; channel: number }>("oars.monitor.dropCaches", { server_id: serverId, level }),
  },
  logs: {
    scan: (serverId: string) => invoke<LogScanResult>("oars.logs.scan", { server_id: serverId }),
    read: (serverId: string, path: string, lines: number) => invoke<LogReadResult>("oars.logs.read", { server_id: serverId, path, lines }),
    follow: (serverId: string, path: string) => invoke<{ ok: boolean; channel: number }>("oars.logs.follow", { server_id: serverId, path }),
    // `expected` is the exact identity preview from the selected LogSource
    // (spec 04 §5): size/mtime/mode. The backend refuses a mismatch.
    clear: (serverId: string, path: string, expected: { size: number; mtime: number; mode: number }) =>
      invoke<LogClearResult>("oars.logs.clear", { server_id: serverId, path, expected }),
    addSource: (serverId: string, path: string) => invoke<{ ok: boolean }>("oars.logs.addSource", { server_id: serverId, path }),
  },
  sftp: {
    // Whole-file download through the binary SFTP transfer machinery
    // (spec 04 §5 / spec 05 §5); `localPath` must come from pickSaveFile.
    download: (serverId: string, remotePath: RemotePath, localPath: string) =>
      invoke<SftpOpStart>("oars.sftp.download", { server_id: serverId, remote_path: remotePath, local_path: localPath }),
    uploadLocal: (serverId: string, localPath: string, remotePath: RemotePath) =>
      invoke<SftpOpStart>("oars.sftp.uploadLocal", { server_id: serverId, local_path: localPath, remote_path: remotePath }),
    poll: (serverId: string) => invoke<SftpTransferSnapshot>("oars.sftp.poll", { server_id: serverId }),
    cancel: (serverId: string, transferId: number) => invoke<{ ok: boolean }>("oars.sftp.cancel", { server_id: serverId, transfer_id: transferId }),
    ls: (serverId: string, path: RemotePath) => invoke<SftpLsResult>("oars.sftp.ls", { server_id: serverId, path }),
    stat: (serverId: string, path: RemotePath) => invoke<SftpStatResult>("oars.sftp.stat", { server_id: serverId, path }),
    read: (serverId: string, path: RemotePath, offset: number, max = 65536) =>
      invoke<SftpReadResult>("oars.sftp.read", { server_id: serverId, path, offset, max }),
    write: (serverId: string, path: RemotePath, offset: number, base64: string, transferId: number, total?: number) =>
      invoke<SftpWriteResult>("oars.sftp.write", { server_id: serverId, path, offset, base64, transfer_id: transferId, ...(total === undefined ? {} : { total }) }),
    save: (serverId: string, path: RemotePath, base64: string, expected?: SftpSaveParams) =>
      invoke<{ ok: boolean }>("oars.sftp.save", {
        server_id: serverId,
        path,
        base64,
        ...(expected?.expected_size === undefined ? {} : { expected_size: expected.expected_size }),
        ...(expected?.expected_mtime === undefined ? {} : { expected_mtime: expected.expected_mtime }),
        ...(expected?.expected_sha256 === undefined ? {} : { expected_sha256: expected.expected_sha256 }),
      }),
    mkdir: (serverId: string, path: RemotePath) => invoke<{ ok: boolean }>("oars.sftp.mkdir", { server_id: serverId, path }),
    rm: (serverId: string, path: RemotePath, recursive = false) =>
      invoke<SftpOpStart | { ok: boolean }>("oars.sftp.rm", { server_id: serverId, path, recursive }),
    rename: (serverId: string, from: RemotePath, to: RemotePath) =>
      invoke<{ ok: boolean }>("oars.sftp.rename", { server_id: serverId, from, to }),
    chmod: (serverId: string, path: RemotePath, mode: number) =>
      invoke<{ ok: boolean }>("oars.sftp.chmod", { server_id: serverId, path, mode }),
    unzip: (serverId: string, zipPath: RemotePath, destDir?: RemotePath) =>
      invoke<SftpOpStart>("oars.sftp.unzip", { server_id: serverId, zip_path: zipPath, ...(destDir ? { dest_dir: destDir } : {}), overwrite: false }),
    zipDownload: (serverId: string, paths: RemotePath[], localPath: string) =>
      invoke<SftpOpStart>("oars.sftp.zipDownload", { server_id: serverId, paths, local_path: localPath }),
    folderSize: (serverId: string, path: RemotePath) =>
      invoke<SftpFolderSizeResult>("oars.sftp.folderSize", { server_id: serverId, path }),
  },
  scripts: {
    list: () => invoke<ScriptsListResult>("oars.scripts.list", {}),
    validate: (body: string) => invoke<{ ok: boolean }>("oars.scripts.validate", { body }),
    save: (script: ScriptDraft) => invoke<{ ok: boolean; script: Script }>("oars.scripts.save", { script }),
    delete: (id: string) => invoke<{ ok: boolean }>("oars.scripts.delete", { id }),
    run: (serverId: string, scriptId: string, vars: ScriptRunVars) =>
      invoke<{ ok: boolean; channel: number }>("oars.scripts.run", { server_id: serverId, script_id: scriptId, vars }),
    // Two-phase safe broadcast (spec 06 §5): prepare freezes the exact
    // command; commit executes the frozen record; prepareCancel drops it.
    broadcastPrepare: (scriptId: string, serverIds: string[], vars: ScriptRunVars) =>
      invoke<BroadcastPreview>("oars.scripts.broadcastPrepare", { script_id: scriptId, server_ids: serverIds, vars }),
    broadcast: (previewId: number) =>
      invoke<{ ok: boolean; run_id: number }>("oars.scripts.broadcast", { preview_id: previewId }),
    broadcastPrepareCancel: (previewId: number) =>
      invoke<{ ok: boolean }>("oars.scripts.broadcastPrepareCancel", { preview_id: previewId }),
    broadcastPoll: (runId: number, cursors: Record<string, number>) =>
      invoke<BroadcastPollResult>("oars.scripts.broadcastPoll", { run_id: runId, cursors }),
    broadcastCancel: (runId: number) =>
      invoke<{ ok: boolean }>("oars.scripts.broadcastCancel", { run_id: runId }),
  },
  deploy: {
    list: (serverId: string) => invoke<{ ok: boolean; apps: import("./types").DeployApp[] }>("oars.deploy.apps.list", { server_id: serverId }),
    save: (app: import("./types").DeployAppInput) => invoke<{ ok: boolean; app: import("./types").DeployApp }>("oars.deploy.apps.save", { app }),
    secretPresence: (appId: string, names: string[], present: boolean) => invoke<{ ok: boolean; app: import("./types").DeployApp }>("oars.deploy.apps.secretPresence", { app_id: appId, names, present }),
    remove: (serverId: string, appId: string) => invoke<{ ok: boolean }>("oars.deploy.apps.delete", { server_id: serverId, app_id: appId }),
    keyGenerate: (serverId: string, appId: string) => invoke<{ ok: boolean; channel: number }>("oars.deploy.key.generate", { server_id: serverId, app_id: appId }),
    hostTrust: (preflightId: number) => invoke<{ ok: boolean; channel: number }>("oars.deploy.hostTrust", { preflight_id: preflightId, accept: true }),
    preflight: (serverId: string, appId: string) => invoke<{ ok: boolean; preflight: import("./types").DeployPreflight }>("oars.deploy.preflight", { server_id: serverId, app_id: appId }),
    preflightPoll: (preflightId: number) => invoke<{ ok: boolean; preflight: import("./types").DeployPreflight }>("oars.deploy.preflightPoll", { preflight_id: preflightId }),
    preflightCancel: (preflightId: number) => invoke<{ ok: boolean }>("oars.deploy.preflightCancel", { preflight_id: preflightId }),
    run: (payload: { preflight_id: number; approvals: string[]; secret_values: Array<{ name: string; value: string }> }) => invoke<{ ok: boolean; run_id: number }>("oars.deploy.run", payload),
    poll: (runId: number, cursors?: Record<string, number>) => invoke<import("./types").DeployPollResult>("oars.deploy.poll", { run_id: runId, cursors }),
    cancel: (runId: number) => invoke<{ ok: boolean }>("oars.deploy.cancel", { run_id: runId }),
    history: (serverId: string, appId: string, limit?: number) => invoke<{ ok: boolean; runs: import("./types").DeployHistoryRecord[] }>("oars.deploy.history", { server_id: serverId, app_id: appId, limit }),
  },
  sshkeys: {
    list: (serverId: string) => invoke<{ ok: boolean; keys: SshKeyEntry[] }>("oars.sshkeys.list", { server_id: serverId }),
    add: (serverId: string, public_key: string, comment?: string) => invoke<{ ok: boolean; fingerprint: string; line_hash: string }>("oars.sshkeys.add", { server_id: serverId, public_key, comment }),
    revoke: (serverId: string, fingerprint: string, expected_line_hash: string) => invoke<{ ok: boolean }>("oars.sshkeys.revoke", { server_id: serverId, fingerprint, expected_line_hash }),
    rotate: (serverId: string, fingerprint: string, expected_line_hash: string, new_public_key: string) => invoke<{ ok: boolean }>("oars.sshkeys.rotate", { server_id: serverId, fingerprint, expected_line_hash, new_public_key }),
    generate: (destination: string, comment?: string, passphrase?: string, remember_passphrase?: boolean) => invoke<GeneratedSshKey>("oars.sshkeys.generate", { destination, comment, passphrase, remember_passphrase }),
    rolesList: (serverId: string) => invoke<{ ok: boolean; roles: SshRole[] }>("oars.sshkeys.roles.list", { server_id: serverId }),
    rolesCreate: (serverId: string, name: string, read_only: boolean) => invoke<{ ok: boolean }>("oars.sshkeys.roles.create", { server_id: serverId, name, read_only }),
    rolesDelete: (serverId: string, name: string) => invoke<{ ok: boolean }>("oars.sshkeys.roles.delete", { server_id: serverId, name }),
    deployKey: (serverId: string) => invoke<{ ok: boolean; public_key: string; path: string }>("oars.sshkeys.deployKey.generate", { server_id: serverId }),
  },
  access: {
    scan: (params?: { serverIds?: string[]; scope?: AccessScope; approvedSensitiveRead?: boolean }) =>
      invoke<AccessScanResponse>("oars.access.scan", {
        ...(params?.serverIds ? { server_ids: params.serverIds } : {}),
        scope: params?.scope ?? "connected_accounts",
        ...(params?.approvedSensitiveRead ? { approved_sensitive_read: true } : {}),
      }),
    scanCancel: (scanId: string) => invoke<{ ok: boolean }>("oars.access.scanCancel", { scan_id: scanId }),
    poll: (scanId: string, opts?: { peopleOffset?: number; unassignedOffset?: number; limit?: number }) =>
      invoke<AccessPollResponse>("oars.access.poll", { scan_id: scanId, people_offset: opts?.peopleOffset ?? 0, unassigned_offset: opts?.unassignedOffset ?? 0, limit: opts?.limit ?? 100 }),
    keyInspect: (publicKey: string) => invoke<AccessKeyInspectResponse>("oars.access.key.inspect", { public_key: publicKey }),
    identitiesList: () => invoke<AccessIdentitiesListResponse>("oars.access.identities.list", {}),
    identitiesSave: (p: { id?: string; name: string; fingerprints: string[]; revision?: number; bindings?: Array<{ fingerprint: string; shared?: boolean }> }) =>
      invoke<{ ok: boolean; identity: AccessIdentity }>("oars.access.identities.save", {
        identity: {
          ...(p.id != null ? { id: p.id } : {}),
          name: p.name,
          fingerprints: p.fingerprints,
          ...(p.revision != null ? { expected_revision: p.revision } : {}),
          ...(p.bindings ? { bindings: p.bindings } : {}),
        },
      }),
    identitiesDelete: (id: string, expectedRevision: number, confirmName: string) =>
      invoke<{ ok: boolean }>("oars.access.identities.delete", { id, expected_revision: expectedRevision, confirm_name: confirmName }),
    offboard: (identityId: string, grants: AccessGrant[], opts: { operationId: string; scanId: string; identityRevision: number; confirmName: string }) =>
      invoke<{ ok: boolean; job_id: string }>("oars.access.offboard", {
        identity_id: identityId,
        grants: grants.map((grant) => ({ server_id: grant.server_id, user: grant.user, fingerprint: grant.fingerprint, line_hash: grant.line_hash, source_path: grant.source_path, file_sha256: grant.file_sha256 })),
        operation_id: opts.operationId,
        scan_id: opts.scanId,
        identity_revision: opts.identityRevision,
        confirm_name: opts.confirmName,
      }),
    onboard: (identityId: string, public_key: string, grants: Array<{ server_id: string; target: { kind: "account" | "read_only_role"; name: string } }>, opts: { operationId: string; identityRevision: number }) =>
      invoke<{ ok: boolean; job_id: string; fingerprint?: string }>("oars.access.onboard", { identity_id: identityId, public_key, grants, operation_id: opts.operationId, identity_revision: opts.identityRevision }),
    rotate: (identityId: string, old_fingerprint: string, grants: AccessGrant[], new_public_key: string, opts: { operationId: string; scanId: string; identityRevision: number }) =>
      invoke<{ ok: boolean; job_id: string; new_fingerprint?: string }>("oars.access.rotate", { identity_id: identityId, old_fingerprint, grants: grants.map((grant) => ({ server_id: grant.server_id, user: grant.user, line_hash: grant.line_hash, source_path: grant.source_path, file_sha256: grant.file_sha256 })), new_public_key, operation_id: opts.operationId, scan_id: opts.scanId, identity_revision: opts.identityRevision }),
    jobPoll: (jobId: string) => invoke<AccessJobPollResponse>("oars.access.jobPoll", { job_id: jobId }),
    jobCancel: (jobId: string) => invoke<{ ok: boolean }>("oars.access.jobCancel", { job_id: jobId }),
    export: (params: { format: "csv" | "json"; scanId: string; path: string }) =>
      invoke<AccessExportResponse>("oars.access.export", {
        format: params.format,
        scan_id: params.scanId,
        path: params.path,
      }),
  },
  backup: {
    list: (serverId?: string) => invoke<any>("oars.backup.jobs.list", serverId ? { server_id: serverId } : {}),
    save: (job: any) => invoke<any>("oars.backup.jobs.save", { job }),
    remove: (serverId: string, jobId: string) => invoke<any>("oars.backup.jobs.delete", { server_id: serverId, job_id: jobId }),
    test: (serverId: string, jobId: string) => invoke<any>("oars.backup.test", { server_id: serverId, job_id: jobId }),
    run: (serverId: string, jobId: string) => invoke<any>("oars.backup.run", { server_id: serverId, job_id: jobId }),
    poll: (runId: number) => invoke<any>("oars.backup.poll", { run_id: runId }),
    history: (serverId: string, jobId: string) => invoke<any>("oars.backup.history", { server_id: serverId, job_id: jobId }),
    install: (serverId: string) => invoke<any>("oars.backup.install", { server_id: serverId }),
    cronStatus: (serverId: string) => invoke<any>("oars.backup.cronStatus", { server_id: serverId }),
  },
  ai: {
    context: (serverId: string) => invoke<any>("oars.ai.context", { server_id: serverId }),
    providerGet: () => invoke<any>("oars.ai.provider.get", {}),
    providerSet: (provider: any) => invoke<any>("oars.ai.provider.set", { provider }),
    history: (serverId?: string) => invoke<any>("oars.ai.history", serverId ? { server_id: serverId } : {}),
  },
  vnc: {
    start: (serverId: string, opts?: { host?: string; port?: number }) =>
      invoke<VncStartResult>("oars.vnc.start", { server_id: serverId, host: opts?.host, port: opts?.port }),
    stop: (serverId: string, tunnelId: number) =>
      invoke<{ ok: boolean }>("oars.vnc.stop", { server_id: serverId, tunnel_id: tunnelId }),
    probe: (serverId: string, display?: number) => invoke<VncProbeResult>("oars.vnc.probe", { server_id: serverId, display }),
    setup: (serverId: string, opts?: { display?: number; dry_run?: boolean; password?: string; installDesktop?: boolean }) =>
      invoke<VncSetupResult>("oars.vnc.setup", {
        server_id: serverId,
        display: opts?.display,
        dry_run: opts?.dry_run,
        ...(opts?.password === undefined ? {} : { password: opts.password }),
        ...(opts?.installDesktop === undefined ? {} : { install_desktop: opts.installDesktop }),
      }),
    poll: (serverId: string, tunnelId: number) =>
      invoke<VncPollResult>("oars.vnc.poll", { server_id: serverId, tunnel_id: tunnelId }),
  },
  history: {
    record: (entry: any) => invoke<any>("oars.history.record", entry),
    list: (filter?: any) => invoke<any>("oars.history.list", filter ?? {}),
    replay: (id: string) => invoke<any>("oars.history.replay", { id }),
    auditList: () => invoke<any>("oars.audit.list", {}),
    auditClear: () => invoke<any>("oars.audit.clear", {}),
  },
  vault: {
    export: (password: string) => invoke<any>("oars.vault.export", { password }),
    import: (payload: any) => invoke<any>("oars.vault.import", payload),
    importConfirm: (token: string, confirm: boolean) => invoke<any>("oars.vault.importConfirm", { token, confirm }),
  },
  agent: {
    list: () => invoke<any>("oars.agent.list", {}),
    forward: (serverId: string, enable: boolean) => invoke<any>("oars.agent.forward", { server_id: serverId, enable }),
  },
};
