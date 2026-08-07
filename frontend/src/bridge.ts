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
// Secrets are cached in memory for the app's lifetime: on unsigned
// (debug) builds macOS re-prompts for Keychain access on every read,
// so each item is fetched at most once per run.
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

// --- Oars commands --------------------------------------------------------

export const api = {
  servers: {
    list: () => invoke<{ servers: Server[] }>("oars.servers.list", {}),
    save: (server: ServerDraft) => invoke<{ server: Server }>("oars.servers.save", server),
    delete: (id: string) => invoke<{ ok: boolean }>("oars.servers.delete", { id }),
  },
  ssh: {
    connect: (serverId: string, password?: string, passphrase?: string) =>
      invoke("oars.ssh.connect", { server_id: serverId, password, passphrase }),
    disconnect: (serverId: string) => invoke("oars.ssh.disconnect", { server_id: serverId }),
    input: (serverId: string, data: string) => invoke("oars.ssh.input", { server_id: serverId, data }),
    exec: (serverId: string, command: string) => invoke<{ channel: number }>("oars.ssh.exec", { server_id: serverId, command }),
    resize: (serverId: string, cols: number, rows: number) =>
      invoke("oars.ssh.resize", { server_id: serverId, cols, rows }),
    trust: (serverId: string, accept: boolean) => invoke("oars.ssh.trust", { server_id: serverId, accept }),
    poll: (serverId: string, rewind: boolean) =>
      invoke<PollResult>("oars.ssh.poll", { server_id: serverId, rewind }),
  },
  monitor: {
    poll: (serverId: string) => invoke<MonitorSnapshot>("oars.monitor.poll", { server_id: serverId }),
  },
  logs: {
    scan: (serverId: string) => invoke<{ sources: LogSource[]; partial: boolean; reason: string }>("oars.logs.scan", { server_id: serverId }),
    read: (serverId: string, path: string, lines: number) => invoke<LogReadResult>("oars.logs.read", { server_id: serverId, path, lines }),
    follow: (serverId: string, path: string) => invoke<{ channel: number }>("oars.logs.follow", { server_id: serverId, path }),
    clear: (serverId: string, path: string) => invoke<{ ok: boolean }>("oars.logs.clear", { server_id: serverId, path }),
    addSource: (serverId: string, path: string) => invoke<{ ok: boolean }>("oars.logs.addSource", { server_id: serverId, path }),
  },
  sftp: {
    ls: (serverId: string, path: string) => invoke<{ entries: Array<{ name: { utf8?: string; base64?: string }; display: string; kind: string; size: number; mtime: number; mode: string; uid: number; gid: number; link_target: string | null }> }>("oars.sftp.ls", { server_id: serverId, path: { utf8: path } }),
    mkdir: (serverId: string, path: string) => invoke<{ ok: boolean }>("oars.sftp.mkdir", { server_id: serverId, path: { utf8: path } }),
    rm: (serverId: string, path: string) => invoke<{ ok: boolean }>("oars.sftp.rm", { server_id: serverId, path: { utf8: path } }),
    rename: (serverId: string, from: string, to: string) => invoke<{ ok: boolean }>("oars.sftp.rename", { server_id: serverId, from: { utf8: from }, to: { utf8: to } }),
    stat: (serverId: string, path: string) => invoke<any>("oars.sftp.stat", { server_id: serverId, path: { utf8: path } }),
  },
  scripts: {
    list: () => invoke<{ scripts: Array<{ id: string; name: string; description: string; tags: string[]; color: string; body: string; run_count: number; last_run_at: number | null; variables: Array<{ name: string; secret: boolean }> }> }>("oars.scripts.list", {}),
    save: (script: { id?: string; name: string; description?: string; tags?: string[]; color?: string; body: string }) => invoke<{ script: any }>("oars.scripts.save", { script }),
    delete: (id: string) => invoke<{ ok: boolean }>("oars.scripts.delete", { id }),
    run: (serverId: string, scriptId: string, vars: Record<string, { value: string; secret: boolean }>) => invoke<{ channel: number }>("oars.scripts.run", { server_id: serverId, script_id: scriptId, vars }),
  },
  deploy: {
    list: (serverId: string) => invoke<{ ok: boolean; apps: any[] }>("oars.deploy.apps.list", { server_id: serverId }),
    save: (app: any) => invoke<{ ok: boolean; app: any }>("oars.deploy.apps.save", { app }),
    remove: (serverId: string, appId: string) => invoke<{ ok: boolean }>("oars.deploy.apps.delete", { server_id: serverId, app_id: appId }),
    run: (serverId: string, appId: string, secret_values: Array<{ name: string; value: string }>) => invoke<{ ok: boolean; run_id: number }>("oars.deploy.run", { server_id: serverId, app_id: appId, secret_values }),
    poll: (runId: number, cursors?: Record<string, number>) => invoke<any>("oars.deploy.poll", { run_id: runId, cursors }),
    cancel: (runId: number) => invoke<{ ok: boolean }>("oars.deploy.cancel", { run_id: runId }),
    history: (serverId: string, appId: string, limit?: number) => invoke<{ ok: boolean; runs: any[] }>("oars.deploy.history", { server_id: serverId, app_id: appId, limit }),
  },
  sshkeys: {
    list: (serverId: string) => invoke<{ ok: boolean; keys: any[] }>("oars.sshkeys.list", { server_id: serverId }),
    add: (serverId: string, public_key: string, comment?: string) => invoke<any>("oars.sshkeys.add", { server_id: serverId, public_key, comment }),
    revoke: (serverId: string, fingerprint: string, expected_line_hash: string) => invoke<any>("oars.sshkeys.revoke", { server_id: serverId, fingerprint, expected_line_hash }),
    rotate: (serverId: string, fingerprint: string, expected_line_hash: string, new_public_key: string) => invoke<any>("oars.sshkeys.rotate", { server_id: serverId, fingerprint, expected_line_hash, new_public_key }),
    generate: (destination: string, comment?: string, passphrase?: string, remember_passphrase?: boolean) => invoke<any>("oars.sshkeys.generate", { destination, comment, passphrase, remember_passphrase }),
    rolesList: (serverId: string) => invoke<any>("oars.sshkeys.roles.list", { server_id: serverId }),
    rolesCreate: (serverId: string, name: string, read_only: boolean) => invoke<any>("oars.sshkeys.roles.create", { server_id: serverId, name, read_only }),
    rolesDelete: (serverId: string, name: string) => invoke<any>("oars.sshkeys.roles.delete", { server_id: serverId, name }),
    deployKey: (serverId: string) => invoke<any>("oars.sshkeys.deployKey.generate", { server_id: serverId }),
  },
  access: {
    scan: (serverIds?: string[]) => invoke<any>("oars.access.scan", serverIds ? { server_ids: serverIds } : {}),
    poll: (scanId: number) => invoke<any>("oars.access.poll", { scan_id: scanId }),
    identitiesList: () => invoke<any>("oars.access.identities.list", {}),
    identitiesSave: (p: { id?: string; name: string; fingerprints: string[] }) => invoke<any>("oars.access.identities.save", p),
    identitiesDelete: (id: string) => invoke<any>("oars.access.identities.delete", { id }),
    offboard: (identityId: string, grants: any[]) => invoke<any>("oars.access.offboard", { identity_id: identityId, grants }),
    onboard: (identityId: string, public_key: string, grants: any[]) => invoke<any>("oars.access.onboard", { identity_id: identityId, public_key, grants }),
    rotate: (identityId: string, old_fingerprint: string, grants: any[], new_public_key: string) => invoke<any>("oars.access.rotate", { identity_id: identityId, old_fingerprint, grants, new_public_key }),
    jobPoll: (jobId: number) => invoke<any>("oars.access.jobPoll", { job_id: jobId }),
    export: (format: "csv" | "json") => invoke<any>("oars.access.export", { format }),
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
    start: (serverId: string) => invoke<any>("oars.vnc.start", { server_id: serverId }),
    stop: (serverId: string) => invoke<any>("oars.vnc.stop", { server_id: serverId }),
    probe: (serverId: string) => invoke<any>("oars.vnc.probe", { server_id: serverId }),
    setup: (serverId: string) => invoke<any>("oars.vnc.setup", { server_id: serverId }),
    poll: (serverId: string) => invoke<any>("oars.vnc.poll", { server_id: serverId }),
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
