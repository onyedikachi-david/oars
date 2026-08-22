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
  SshAccountRef,
  SshInspectResponse,
  SshJobPollResponse,
  SshRoleKind,
  SshRolePlanAction,
  SshRolePlanResponse,
  SshRotateVerification,
  SshSnapshotPollResponse,
  SshSnapshotStartResponse,
  BackupJob,
  BackupJobInput,
  BackupCredentials,
  BackupJobsListResult,
  BackupJobSaveResult,
  BackupTestResult,
  BackupRunStartResult,
  BackupHistoryResult,
  BackupPollResult,
  BackupInstallResult,
  BackupCronStatusResult,
  AiContextBundle,
  AiProviderGetResult,
  AiProviderSetResult,
  AiProviderInput,
  AiHistoryResult,
  HistoryEntry,
  HistoryRecordInput,
  HistoryListFilter,
  HistoryListResult,
  AuditListFilter,
  AuditListResult,
  VaultExportParams,
  VaultExportResult,
  VaultImportParams,
  VaultImportResult,
  VaultImportConfirmParams,
  VaultImportConfirmResult,
  AgentIdentity,
  AgentListResult,
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
  let result: unknown;
  try {
    result = await zero.invoke(command, payload);
  } catch (e: unknown) {
    const err = e as { code?: string; message?: string } | null | undefined;
    throw new BridgeError(err?.code ?? "invoke_failed", err?.message ?? String(e));
  }
  // Our handlers resolve with an envelope when they hit a user-facing
  // error; the framework rejects for transport-level failures.
  if (result && typeof result === "object" && (result as { ok?: boolean }).ok === false) {
    throw new BridgeError("command_failed", (result as { error?: string }).error ?? "command failed");
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
  // Backup credentials are transient and must never linger in the
  // in-process cache. Real backup secret handling (no-cache account
  // `backup:<job_id>`) lands with the backup controller in the next
  // incremental commit.
  async backupTransientGet(account: string): Promise<string | null> {
    const secret = await invoke<string | null>("native-sdk.credentials.get", {
      service: this.service,
      account,
    });
    return secret;
  },
  async backupSet(account: string, secret: string): Promise<void> {
    await invoke("native-sdk.credentials.set", {
      service: this.service,
      account,
      secret,
    });
    // Do not cache backup secrets in-process.
  },
  async delete(account: string): Promise<void> {
    await invoke("native-sdk.credentials.delete", {
      service: this.service,
      account,
    });
    secretCache.delete(account);
  },
  clearCache(): void {
    secretCache.clear();
  },
  evictServer(serverId: string): void {
    const prefix1 = `server:${serverId}:`;
    const prefix2 = `vnc:${serverId}`;
    for (const key of Array.from(secretCache.keys())) {
      if (key.startsWith(prefix1) || key === prefix2 || key.startsWith(prefix2 + ":")) {
        secretCache.delete(key);
      }
    }
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
    rm: ((serverId: string, path: RemotePath, recursive = false) =>
      invoke<SftpOpStart | { ok: boolean }>("oars.sftp.rm", { server_id: serverId, path, recursive })) as {
      (serverId: string, path: RemotePath, recursive: true): Promise<SftpOpStart>;
      (serverId: string, path: RemotePath, recursive?: false): Promise<{ ok: boolean }>;
      (serverId: string, path: RemotePath, recursive?: boolean): Promise<SftpOpStart | { ok: boolean }>;
    },
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
    inspect: (publicKey: string, comment?: string) =>
      invoke<SshInspectResponse>("oars.sshkeys.inspect", { public_key: publicKey, ...(comment === undefined ? {} : { comment }) }),
    snapshot: (serverId: string, account: SshAccountRef) =>
      invoke<SshSnapshotStartResponse>("oars.sshkeys.snapshot", { server_id: serverId, account }),
    snapshotPoll: (snapshotId: string) =>
      invoke<SshSnapshotPollResponse>("oars.sshkeys.snapshotPoll", { snapshot_id: snapshotId }),
    snapshotCancel: (snapshotId: string) =>
      invoke<{ ok: boolean }>("oars.sshkeys.snapshotCancel", { snapshot_id: snapshotId }),
    add: (p: { operationId: string; snapshotId: string; sourcePath: string; fileSha256: string; publicKey: string; comment?: string }) =>
      invoke<{ ok: boolean; job_id: string; fingerprint: string }>("oars.sshkeys.add", {
        operation_id: p.operationId, snapshot_id: p.snapshotId, source_path: p.sourcePath,
        file_sha256: p.fileSha256, public_key: p.publicKey,
        ...(p.comment === undefined ? {} : { comment: p.comment }),
      }),
    revoke: (p: { operationId: string; snapshotId: string; sourcePath: string; fileSha256: string; fingerprint: string; lineHash: string; confirmFingerprint?: string }) =>
      invoke<{ ok: boolean; job_id: string }>("oars.sshkeys.revoke", {
        operation_id: p.operationId, snapshot_id: p.snapshotId, source_path: p.sourcePath,
        file_sha256: p.fileSha256, fingerprint: p.fingerprint, line_hash: p.lineHash,
        ...(p.confirmFingerprint === undefined ? {} : { confirm_fingerprint: p.confirmFingerprint }),
      }),
    rotate: (p: { operationId: string; snapshotId: string; sourcePath: string; fileSha256: string; oldFingerprint: string; lineHash: string; newPublicKey: string }) =>
      invoke<{ ok: boolean; job_id: string; new_fingerprint: string }>("oars.sshkeys.rotate", {
        operation_id: p.operationId, snapshot_id: p.snapshotId, source_path: p.sourcePath,
        file_sha256: p.fileSha256, old_fingerprint: p.oldFingerprint, line_hash: p.lineHash,
        new_public_key: p.newPublicKey,
      }),
    rotateCommit: (jobId: string, verification: SshRotateVerification) =>
      invoke<{ ok: boolean }>("oars.sshkeys.rotateCommit", { job_id: jobId, verification }),
    jobPoll: (jobId: string) =>
      invoke<SshJobPollResponse>("oars.sshkeys.jobPoll", { job_id: jobId }),
    jobCancel: (jobId: string) =>
      invoke<{ ok: boolean }>("oars.sshkeys.jobCancel", { job_id: jobId }),
    // The passphrase is a sensitive payload: it crosses the bridge once and
    // is never cached, logged, or echoed by the frontend.
    localGenerate: (p: { operationId: string; destination: string; comment?: string; passphrase?: string }) =>
      invoke<{ ok: boolean; job_id: string }>("oars.sshkeys.localGenerate", {
        operation_id: p.operationId, destination: p.destination,
        ...(p.comment === undefined ? {} : { comment: p.comment }),
        ...(p.passphrase === undefined ? {} : { passphrase: p.passphrase }),
      }),
    rolesPlan: (serverId: string, name: string, kind: SshRoleKind, action: SshRolePlanAction) =>
      invoke<SshRolePlanResponse>("oars.sshkeys.roles.plan", { server_id: serverId, name, kind, action }),
    rolesCommit: (operationId: string, planId: string, publicKey?: string) =>
      invoke<{ ok: boolean; job_id: string }>("oars.sshkeys.roles.commit", {
        operation_id: operationId, plan_id: planId,
        ...(publicKey === undefined ? {} : { public_key: publicKey }),
      }),
    deployKeysGenerate: (p: { operationId: string; serverId: string; repositoryLabel: string; comment?: string }) =>
      invoke<{ ok: boolean; job_id: string }>("oars.sshkeys.deployKeys.generate", {
        operation_id: p.operationId, server_id: p.serverId, repository_label: p.repositoryLabel,
        ...(p.comment === undefined ? {} : { comment: p.comment }),
      }),
    deployKeysDelete: (p: { operationId: string; serverId: string; deployKeyId: string; confirmFingerprint: string }) =>
      invoke<{ ok: boolean; job_id: string }>("oars.sshkeys.deployKeys.delete", {
        operation_id: p.operationId, server_id: p.serverId, deploy_key_id: p.deployKeyId,
        confirm_fingerprint: p.confirmFingerprint,
      }),
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
    list: (serverId?: string) =>
      invoke<BackupJobsListResult>("oars.backup.jobs.list", serverId ? { server_id: serverId } : {}),
    save: (job: BackupJobInput, scheduleCredentials?: BackupCredentials) =>
      invoke<BackupJobSaveResult>("oars.backup.jobs.save", {
        job,
        ...(scheduleCredentials ? { schedule_credentials: scheduleCredentials } : {}),
      }),
    remove: (serverId: string, jobId: string) =>
      invoke<{ ok: boolean }>("oars.backup.jobs.delete", { server_id: serverId, job_id: jobId }),
    test: (jobOrServerId: BackupJobInput | string, credentialsOrJobId?: BackupCredentials | string) => {
      if (typeof jobOrServerId === "string") {
        return invoke<BackupTestResult>("oars.backup.test", {
          server_id: jobOrServerId,
          job_id: credentialsOrJobId as string,
        });
      }
      return invoke<BackupTestResult>("oars.backup.test", {
        job: jobOrServerId,
        ...(credentialsOrJobId ? { credentials: credentialsOrJobId as BackupCredentials } : {}),
      });
    },
    run: (serverId: string, jobId: string, credentials?: BackupCredentials) =>
      invoke<BackupRunStartResult>("oars.backup.run", {
        server_id: serverId,
        job_id: jobId,
        ...(credentials ? { credentials } : {}),
      }),
    poll: (runId: string | number, logCursor?: number) =>
      invoke<BackupPollResult>("oars.backup.poll", {
        run_id: String(runId),
        ...(logCursor !== undefined ? { log_cursor: logCursor } : {}),
      }),
    history: (serverId: string, jobId: string, limit?: number) =>
      invoke<BackupHistoryResult>("oars.backup.history", {
        server_id: serverId,
        job_id: jobId,
        ...(limit !== undefined ? { limit } : {}),
      }),
    install: (serverId: string, what: "rclone" | "cron" = "rclone", dryRun = false) =>
      invoke<BackupInstallResult>("oars.backup.install", {
        server_id: serverId,
        what,
        dry_run: dryRun,
      }),
    cronStatus: (serverId: string) =>
      invoke<BackupCronStatusResult>("oars.backup.cronStatus", { server_id: serverId }),
  },
  ai: {
    context: (serverId: string) =>
      invoke<AiContextBundle>("oars.ai.context", { server_id: serverId }),
    providerGet: () =>
      invoke<AiProviderGetResult>("oars.ai.provider.get", {}),
    providerSet: (provider: AiProviderInput) =>
      invoke<AiProviderSetResult>("oars.ai.provider.set", { provider }),
    history: (serverId?: string, limit?: number) =>
      invoke<AiHistoryResult>("oars.ai.history", {
        ...(serverId ? { server_id: serverId } : {}),
        ...(limit !== undefined ? { limit } : {}),
      }),
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
    record: (entry: HistoryRecordInput) =>
      invoke<{ ok: boolean }>("oars.history.record", entry),
    list: (filter?: HistoryListFilter) =>
      invoke<HistoryListResult>("oars.history.list", filter ?? {}),
    replay: (idOrEntryId: string) =>
      invoke<{ ok: boolean; channel: number }>("oars.history.replay", { entry_id: idOrEntryId }),
    auditList: (filter?: AuditListFilter) =>
      invoke<AuditListResult>("oars.audit.list", filter ?? {}),
    auditClear: () =>
      invoke<{ ok: boolean }>("oars.audit.clear", { confirm: "CLEAR" }),
  },
  vault: {
    export: (paramsOrPassword: VaultExportParams | string) => {
      const payload = typeof paramsOrPassword === "string" ? { password: paramsOrPassword } : paramsOrPassword;
      return invoke<VaultExportResult>("oars.vault.export", payload);
    },
    import: (params: VaultImportParams) =>
      invoke<VaultImportResult>("oars.vault.import", params),
    importConfirm: (paramsOrToken: VaultImportConfirmParams | string, confirm?: boolean) => {
      const payload = typeof paramsOrToken === "string" ? { token: paramsOrToken, confirm: Boolean(confirm) } : paramsOrToken;
      return invoke<VaultImportConfirmResult>("oars.vault.importConfirm", payload);
    },
  },
  agent: {
    list: (path?: string) =>
      invoke<AgentListResult>("oars.agent.list", { ...(path ? { path } : {}) }),
    forward: (serverId: string, onOrEnable: boolean) =>
      invoke<{ ok: boolean }>("oars.agent.forward", { server_id: serverId, on: onOrEnable }),
  },
};
