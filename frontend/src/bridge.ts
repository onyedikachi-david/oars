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
};
