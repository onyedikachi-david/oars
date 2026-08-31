import { vi } from "vitest";
import type {
  Server,
  LogSource,
  DeployApp,
  DeployPreflight,
  RemotePath,
  SftpLsResult,
  SftpStatResult,
  SftpReadResult,
  SftpWriteResult,
  SftpTransferSnapshot,
  DeployPollResult,
  SftpEntry,
} from "../types";
import { bytesToBase64, base64ToBytes } from "../sftp-path";

export interface MockBridgeState {
  servers: Server[];
  vaultSecrets: Map<string, string>;
  sftpFiles: Map<
    string,
    {
      content: Uint8Array;
      mode: number;
      mtime: number;
      isDir?: boolean;
    }
  >;
  logSources: LogSource[];
  logLines: Map<string, string[]>;
  sshChannels: Map<
    number,
    {
      chunks: Array<{ text: string; gap?: boolean }>;
      cursor: number;
      eof: boolean;
      dropped?: number;
    }
  >;
  deployApps: DeployApp[];
  preflights: Map<number, DeployPreflight>;
  deployRuns: Map<
    number,
    {
      status: string;
      done: boolean;
      steps: Array<{
        channel: number;
        cursor: number;
        output: string;
        gap?: boolean;
        state: string;
      }>;
    }
  >;
  sftpTransfers: Map<
    number,
    {
      id: number;
      kind: "upload" | "download" | "unzip" | "zip_download";
      local_path: string;
      remote_path: RemotePath;
      bytes: number;
      total: number;
      status: "queued" | "running" | "done" | "failed" | "canceled";
      error?: string;
    }
  >;
}

export function getDefaultDeployPreflight(id = 1, appId = "app-1", serverId = "srv-prod"): DeployPreflight {
  return {
    id,
    app_id: appId,
    server_id: serverId,
    created_at_ms: Date.now(),
    expires_at_ms: Date.now() + 600000,
    app_revision: 1,
    target_fingerprint: 12345,
    status: "ready",
    facts: {
      os: "Ubuntu 22.04 LTS",
      arch: "x86_64",
      libc: "glibc",
      user: "ubuntu",
      home: "/home/ubuntu",
      privilege: "root",
      repository_commit: "abc123456789",
      lockfiles: "package-lock.json",
      git_host_fingerprints: "SHA256:github-key",
      ports: "3000/tcp open",
    },
    blockers: [],
    warnings: [],
    approvals: [],
    configs: { env: "NODE_ENV=production", pm2: "", nginx: "" },
    steps: [
      {
        id: "s1",
        label: "Pull repository",
        mutation: "Git clone",
        command: "git pull",
        skipped: false,
        files: [],
        guards: [],
        rollback: "",
      },
    ],
    commit: "abc123456789",
  };
}

export function createDefaultState(): MockBridgeState {
  return {
    servers: [
      {
        id: "srv-prod",
        name: "Production App Server",
        host: "prod.internal",
        user: "ubuntu",
        port: 22,
        auth_method: "key",
        key_path: "~/.ssh/id_ed25519",
        key_has_passphrase: false,
        host_fingerprint: "SHA256:abc123",
        group: "",
        tags: [],
        via_server_id: null,
        created_at: 0,
        updated_at: 0,
      },
    ],
    vaultSecrets: new Map(),
    sftpFiles: new Map(),
    logSources: [
      {
        path: "/var/log/nginx/access.log",
        name: "access.log",
        group: "web",
        size: 10240,
        mtime_epoch: 1700000000,
        mode: 0o644,
        readable: true,
        age_sec: 120,
      },
      {
        path: "/var/log/syslog",
        name: "syslog",
        group: "system",
        size: 51200,
        mtime_epoch: 1700000000,
        mode: 0o640,
        readable: true,
        age_sec: 120,
      },
    ],
    logLines: new Map([
      ["/var/log/nginx/access.log", ["GET / 200", "GET /assets/app.js 200", "POST /api/login 200"]],
      ["/var/log/syslog", ["systemd[1]: Started Oars Daemon", "kernel: [0.000000] Linux version 6.5.0"]],
    ]),
    sshChannels: new Map(),
    deployApps: [
      {
        id: "app-1",
        server_id: "srv-prod",
        name: "Web API",
        environment: "production",
        folder: "web-api",
        repo: {
          url: "git@github.com:org/repo.git",
          transport: "ssh",
          branch: "main",
        },
        runtime: {
          node_version: "20",
          type: "node",
          package_manager: "npm",
          install: "npm install",
          build: "npm run build",
          entry: "index.js",
          args: "",
          start_command: "npm start",
          build_folder: "dist",
        },
        env_vars: [
          { name: "NODE_ENV", secret: false, value: "production", has_value: true },
          { name: "APP_SECRET", secret: true, value: "", has_value: false },
        ],
        domains: ["api.example.com"],
        ssl: true,
        email: "admin@example.com",
        app_port: 3000,
        revision: 1,
        created_at_ms: 1700000000000,
        updated_at_ms: 1700000000000,
      },
    ],
    preflights: new Map(),
    deployRuns: new Map(),
    sftpTransfers: new Map(),
  };
}

export class MockBridge {
  private queue = new Map<string, unknown[]>();
  private handlers = new Map<string, (payload: any) => any>();
  private spies = new Map<string, ReturnType<typeof vi.fn>>();
  private nextChannelId = 100;
  private nextPreflightId = 1;
  private nextRunId = 1;
  private nextTransferId = 1;

  public state: MockBridgeState = createDefaultState();

  constructor() {
    this.setupDefaultHandlers();
  }

  public queueResponse(command: string, response: unknown) {
    const list = this.queue.get(command) ?? [];
    list.push(response);
    this.queue.set(command, list);
  }

  public setHandler(command: string, handler: (payload: any) => any) {
    this.handlers.set(command, handler);
  }

  public spyOn(command: string) {
    let spy = this.spies.get(command);
    if (!spy) {
      spy = vi.fn();
      this.spies.set(command, spy);
    }
    return spy;
  }

  public simulateError(command: string, code: string, message: string) {
    this.setHandler(command, () => {
      const err = new Error(message) as any;
      err.code = code;
      throw err;
    });
  }

  public reset() {
    this.queue.clear();
    this.handlers.clear();
    this.spies.clear();
    this.state = createDefaultState();
    this.setupDefaultHandlers();
  }

  public install() {
    (window as any).zero = {
      invoke: (command: string, payload?: unknown) => this.invoke(command, payload),
    };
  }

  public uninstall() {
    if (typeof window !== "undefined") {
      delete (window as any).zero;
    }
  }

  public async invoke(command: string, payload: unknown = {}): Promise<unknown> {
    const spy = this.spies.get(command);
    if (spy) {
      (spy as unknown as (value: unknown) => void)(payload);
    }

    const queued = this.queue.get(command);
    if (queued && queued.length > 0) {
      return queued.shift();
    }

    const handler = this.handlers.get(command);
    if (handler) {
      return handler(payload);
    }

    throw new Error(`Unhandled mock RPC command: ${command}`);
  }

  // --- Helpers for Files, Deploy, Logs ---

  public setVirtualFile(path: string, content: string | Uint8Array, mode = 0o644, mtime = Math.floor(Date.now() / 1000), isDir = false) {
    const bytes = typeof content === "string" ? new TextEncoder().encode(content) : content;
    const normalized = path.startsWith("/") ? path : `/${path}`;
    this.state.sftpFiles.set(normalized, {
      content: bytes,
      mode,
      mtime,
      isDir,
    });
  }

  public getVirtualFile(path: string) {
    const normalized = path.startsWith("/") ? path : `/${path}`;
    return this.state.sftpFiles.get(normalized);
  }

  public addLogSource(source: LogSource, lines: string[] = []) {
    this.state.logSources.push(source);
    this.state.logLines.set(source.path, lines);
  }

  public simulateDeployRunStep(
    runId: number,
    stepIndex: number,
    data: string,
    state: "running" | "done" | "failed" = "running",
    isTerminalDone = false
  ) {
    const run = this.state.deployRuns.get(runId);
    if (!run) return;
    if (run.steps[stepIndex]) {
      run.steps[stepIndex].output += data;
      run.steps[stepIndex].cursor += data.length;
      run.steps[stepIndex].state = state;
    }
    run.done = isTerminalDone;
    if (isTerminalDone) run.status = state === "failed" ? "failed" : "done";
  }

  public simulateLogStreamData(channelId: number, data: string, isEof = false, dropped = 0) {
    const chan = this.state.sshChannels.get(channelId);
    if (chan) {
      chan.chunks.push({ text: data });
      chan.cursor += data.length;
      chan.eof = isEof;
      chan.dropped = dropped;
    }
  }

  private setupDefaultHandlers() {
    // 1. native-sdk.credentials
    this.setHandler("native-sdk.credentials.get", (p: { account: string }) => {
      return this.state.vaultSecrets.get(p.account) ?? null;
    });
    this.setHandler("native-sdk.credentials.set", (p: { account: string; secret: string }) => {
      this.state.vaultSecrets.set(p.account, p.secret);
      return { ok: true };
    });
    this.setHandler("native-sdk.credentials.delete", (p: { account: string }) => {
      this.state.vaultSecrets.delete(p.account);
      return { ok: true };
    });

    // 2. native-sdk.dialog
    this.setHandler("native-sdk.dialog.openFile", () => ["/mock/selected/path.txt"]);
    this.setHandler("native-sdk.dialog.saveFile", () => "/mock/saved/file.tar.gz");

    // 3. oars.local
    this.setHandler("oars.local.ls", () => ({
      path: "/local",
      entries: [
        { name: "app.ts", kind: "file", size: 1024, mtime: 1700000000, mode: 0o644, is_dir: false },
        { name: "dist", kind: "dir", size: 4096, mtime: 1700000000, mode: 0o755, is_dir: true },
      ],
    }));

    // 4. oars.servers
    this.setHandler("oars.servers.list", () => ({
      servers: this.state.servers,
    }));
    this.setHandler("oars.servers.save", (server: Server) => {
      const idx = this.state.servers.findIndex((s) => s.id === server.id);
      if (idx >= 0) this.state.servers[idx] = server;
      else this.state.servers.push(server);
      return { server };
    });
    this.setHandler("oars.servers.delete", ({ id }: { id: string }) => {
      this.state.servers = this.state.servers.filter((s) => s.id !== id);
      return { ok: true };
    });

    // 5. oars.ssh
    this.setHandler("oars.ssh.connect", () => ({ ok: true }));
    this.setHandler("oars.ssh.disconnect", () => ({ ok: true }));
    this.setHandler("oars.ssh.input", () => ({ ok: true }));
    this.setHandler("oars.ssh.exec", () => {
      const channel = ++this.nextChannelId;
      this.state.sshChannels.set(channel, { chunks: [], cursor: 0, eof: false });
      return { channel };
    });
    this.setHandler("oars.ssh.closeChannel", ({ channel }: { channel: number }) => {
      this.state.sshChannels.delete(channel);
      return { ok: true };
    });
    this.setHandler("oars.ssh.resize", () => ({ ok: true }));
    this.setHandler("oars.ssh.trust", () => ({ ok: true }));
    this.setHandler("oars.ssh.retrust", (p: { server_id: string }) => ({
      server: this.state.servers.find((s) => s.id === p.server_id) || this.state.servers[0],
    }));
    this.setHandler("oars.ssh.poll", (p: { server_id: string; cursors: Array<{ channel: number; cursor: number }> | null }) => {
      const responses: Array<{ id: number; data: string; cursor: number; eof: boolean; exit?: number; dropped?: number }> = [];
      if (p.cursors) {
        for (const req of p.cursors) {
          const chan = this.state.sshChannels.get(req.channel);
          if (chan) {
            const unread = chan.chunks.map((c) => c.text).join("");
            chan.chunks = [];
            responses.push({
              id: req.channel,
              data: unread,
              cursor: chan.cursor,
              eof: chan.eof,
              dropped: chan.dropped ?? 0,
              exit: chan.eof ? 0 : undefined,
            });
          }
        }
      }
      return {
        ok: true,
        status: "ready",
        connection_id: 1,
        channels: responses,
      };
    });

    // 6. oars.ai — production wire shapes with no browser-side credential value.
    const aiProvider = {
      id: "aip-0123456789abcdef",
      name: "Mock provider",
      adapter: "openai_responses" as const,
      tool_mode: "structured_result" as const,
      base_url: "https://api.openai.com/v1",
      model: "gpt-test",
      instruction_role: null,
      structured_output: null,
      revision: 1,
      tested_at_ms: null,
      test_status: "untested" as const,
    };
    const aiProposal = {
      id: "aiprop-0123456789abcdef",
      turn_id: "air-0123456789abcdef",
      revision: 1,
      server_id: this.state.servers[0].id,
      provider_id: aiProvider.id,
      provider_revision: 1,
      context_hash: "a".repeat(64),
      command: "uptime",
      command_sha256: "b".repeat(64),
      explanation: "Read the current uptime.",
      model_destructive: false,
      local_destructive: false,
      needs_sudo: false,
      created_at_ms: 1700000000000,
      expires_at_ms: 1700000600000,
      state: "awaiting_approval" as const,
    };
    this.setHandler("oars.ai.provider.list", () => ({ ok: true, providers: [] }));
    this.setHandler("oars.ai.provider.save", () => ({ ok: true, provider: aiProvider }));
    this.setHandler("oars.ai.provider.delete", () => ({ ok: true }));
    this.setHandler("oars.ai.provider.test", (p: { operation_id: string }) => ({ ok: true, operation_id: p.operation_id, state: "queued" }));
    this.setHandler("oars.ai.provider.testPoll", (p: { operation_id: string }) => ({ ok: true, stream_id: p.operation_id, cursor: 0, dropped: 0, finished: true, state: "passed", events: [] }));
    this.setHandler("oars.ai.provider.testCancel", () => ({ ok: true, state: "canceled" }));
    this.setHandler("oars.ai.credential.configure", () => ({ ok: true, status: "configured" }));
    this.setHandler("oars.ai.credential.status", () => ({ ok: true, status: "missing" }));
    this.setHandler("oars.ai.credential.delete", () => ({ ok: true, status: "missing" }));
    this.setHandler("oars.ai.context.get", () => ({ ok: true, state: "missing", context: null, stale: true }));
    this.setHandler("oars.ai.context.refresh", (p: { operation_id: string }) => ({ ok: true, operation_id: p.operation_id, state: "queued" }));
    this.setHandler("oars.ai.context.poll", (p: { operation_id: string }) => ({ ok: true, stream_id: p.operation_id, cursor: 0, dropped: 0, finished: true, state: "ready", events: [] }));
    this.setHandler("oars.ai.context.cancel", () => ({ ok: true, state: "canceled" }));
    this.setHandler("oars.ai.thread.list", () => ({ ok: true, threads: [] }));
    this.setHandler("oars.ai.thread.get", (p: { thread_id: string }) => ({
      ok: true,
      thread: {
        id: p.thread_id,
        revision: 1,
        server_id: this.state.servers[0].id,
        provider_id: aiProvider.id,
        adapter: aiProvider.adapter,
        model: aiProvider.model,
        title: "Mock AI thread",
        created_at_ms: 1700000000000,
        updated_at_ms: 1700000000000,
      },
      turns: [],
      turns_start: 0,
      turn_count: 0,
      active_proposal: null,
    }));
    this.setHandler("oars.ai.thread.delete", () => ({ ok: true }));
    this.setHandler("oars.ai.turn.start", () => ({ ok: true, thread_id: "ait-0123456789abcdef", turn_id: "air-0123456789abcdef", state: "queued" }));
    this.setHandler("oars.ai.turn.poll", (p: { turn_id: string }) => ({ ok: true, stream_id: p.turn_id, cursor: 0, dropped: 0, finished: true, state: "completed", events: [] }));
    this.setHandler("oars.ai.turn.cancel", () => ({ ok: true, state: "canceled" }));
    this.setHandler("oars.ai.turn.summarize", () => ({ ok: true, thread_id: "ait-0123456789abcdef", turn_id: "air-summary-00000001", state: "queued" }));
    this.setHandler("oars.ai.proposal.edit", (p: { command: string; expected_revision: number }) => ({ ok: true, proposal: { ...aiProposal, command: p.command, revision: p.expected_revision + 1 } }));
    this.setHandler("oars.ai.proposal.run", () => ({ ok: true, execution_id: "aiexec-0123456789abcdef", connection_id: 1, channel: ++this.nextChannelId, state: "executing" }));
    this.setHandler("oars.ai.proposal.cancel", () => ({ ok: true, state: "canceled" }));

    // 7. oars.monitor
    this.setHandler("oars.monitor.poll", () => ({
      timestamp: Date.now(),
      cpu: { user: 10, system: 5, idle: 85, count: 4, model: "AMD EPYC" },
      memory: { total: 16000000000, used: 4000000000, available: 12000000000, swap_total: 0, swap_used: 0 },
      disks: [{ mount: "/", fs: "/dev/sda1", total: 100000000000, used: 25000000000, free: 75000000000 }],
      network: { rx_bytes_sec: 1024, tx_bytes_sec: 2048 },
      processes: [
        { pid: 1, name: "systemd", user: "root", cpu_percent: 0.1, mem_bytes: 12000000, status: "R" },
        { pid: 101, name: "node", user: "ubuntu", cpu_percent: 1.5, mem_bytes: 85000000, status: "S" },
      ],
      system: { hostname: "srv-prod", os: "Linux", uptime: 86400, load_1: 0.5, load_5: 0.3, load_15: 0.1 },
    }));
    this.setHandler("oars.monitor.probe", () => ({ ok: true }));
    this.setHandler("oars.monitor.cleanDiskEstimate", () => ({ ok: true, channel: ++this.nextChannelId }));
    this.setHandler("oars.monitor.cleanDisk", () => ({ ok: true, channel: ++this.nextChannelId }));
    this.setHandler("oars.monitor.dropCaches", () => ({ ok: true, channel: ++this.nextChannelId }));

    // 7. oars.logs
    this.setHandler("oars.logs.scan", () => ({
      sources: this.state.logSources.map((s) => ({
        ...s,
        name: s.name ?? s.path.split("/").pop() ?? s.path,
        age_sec: s.age_sec ?? 120,
      })),
      partial: false,
      reason: "",
    }));
    this.setHandler("oars.logs.read", (p: { path: string; lines: number }) => {
      const lines = this.state.logLines.get(p.path) ?? ["Sample log entry 1", "Sample log entry 2"];
      return {
        lines: lines.slice(-p.lines),
        limited: lines.length > p.lines,
        binary: false,
      };
    });
    this.setHandler("oars.logs.follow", (p: { path: string }) => {
      const channel = ++this.nextChannelId;
      this.state.sshChannels.set(channel, {
        chunks: [{ text: `Initial stream line for ${p.path}\n` }],
        cursor: 30,
        eof: false,
      });
      return { ok: true, channel };
    });
    this.setHandler("oars.logs.clear", (p: { path: string; expected: { size: number; mtime: number } }) => {
      const src = this.state.logSources.find((s) => s.path === p.path);
      if (src && (src.size !== p.expected.size || src.mtime_epoch !== p.expected.mtime)) {
        return { ok: false, error: "file changed since preview" };
      }
      if (src) {
        src.size = 0;
        src.mtime_epoch = Math.floor(Date.now() / 1000);
      }
      this.state.logLines.set(p.path, []);
      return { ok: true, before: 1024, after: 0 };
    });
    this.setHandler("oars.logs.addSource", (p: { path: string }) => {
      this.state.logSources.push({
        path: p.path,
        group: "custom",
        name: p.path.split("/").pop() ?? p.path,
        size: 0,
        mtime_epoch: Math.floor(Date.now() / 1000),
        age_sec: 0,
        mode: 0o644,
        readable: true,
      });
      return { ok: true };
    });

    // 8. oars.sftp
    this.setHandler("oars.sftp.ls", (p: { path: RemotePath }) => {
      const rawPath = typeof p.path === "string" ? p.path : (p.path as any)?.utf8 ?? (p.path as any)?.raw ?? "/";
      const entries: SftpEntry[] = [];
      const prefix = rawPath === "/" ? "/" : rawPath.endsWith("/") ? rawPath : `${rawPath}/`;
      for (const [filePath, file] of this.state.sftpFiles.entries()) {
        if (filePath.startsWith(prefix)) {
          const rest = filePath.slice(prefix.length);
          if (rest.length > 0 && !rest.includes("/")) {
            entries.push({
              name: { utf8: rest },
              display: rest,
              kind: file.isDir ? "dir" : "file",
              size: file.content.length,
              mtime: file.mtime,
              mode: file.isDir ? "drwxr-xr-x" : "-rw-r--r--",
              uid: 1000,
              gid: 1000,
              link_target: null,
            });
          }
        }
      }
      return { ok: true, entries, truncated: false } as SftpLsResult;
    });

    this.setHandler("oars.sftp.stat", (p: { path: RemotePath }) => {
      const rawPath = typeof p.path === "string" ? p.path : (p.path as any)?.utf8 ?? (p.path as any)?.raw ?? "/";
      const file = this.state.sftpFiles.get(rawPath);
      if (!file) throw new Error("File not found");
      const leaf = rawPath.split("/").pop() || "";
      return {
        ok: true,
        entry: {
          name: { utf8: leaf },
          display: leaf,
          kind: file.isDir ? "dir" : "file",
          size: file.content.length,
          mtime: file.mtime,
          mode: file.isDir ? "drwxr-xr-x" : "-rw-r--r--",
          uid: 1000,
          gid: 1000,
          link_target: null,
        },
      } as SftpStatResult;
    });

    this.setHandler("oars.sftp.read", (p: { path: RemotePath; offset: number; max?: number }) => {
      const rawPath = typeof p.path === "string" ? p.path : (p.path as any)?.utf8 ?? (p.path as any)?.raw ?? "/";
      const file = this.state.sftpFiles.get(rawPath);
      if (!file) throw new Error(`sftp.read: file not found: ${rawPath}`);
      const max = p.max ?? 65536;
      const offset = p.offset ?? 0;
      const slice = file.content.subarray(offset, Math.min(file.content.length, offset + max));
      const eof = offset + slice.length >= file.content.length;
      const base64 = bytesToBase64(slice);
      return {
        ok: true,
        base64,
        eof,
        bytes: slice.length,
      } as SftpReadResult;
    });

    this.setHandler("oars.sftp.write", (p: { path: RemotePath; offset: number; base64: string; transfer_id: number; total?: number }) => {
      const rawPath = typeof p.path === "string" ? p.path : (p.path as any)?.utf8 ?? (p.path as any)?.raw ?? "/";
      let file = this.state.sftpFiles.get(rawPath);
      if (!file) {
        file = { content: new Uint8Array(p.total ?? 0), mode: 0o644, mtime: Math.floor(Date.now() / 1000) };
        this.state.sftpFiles.set(rawPath, file);
      }
      const chunk = base64ToBytes(p.base64);
      if (file.content.length < p.offset + chunk.length) {
        const next = new Uint8Array(p.offset + chunk.length);
        next.set(file.content);
        file.content = next;
      }
      return { ok: true, written: p.offset + chunk.length, done: p.offset + chunk.length >= (p.total ?? file.content.length) } as SftpWriteResult;
    });

    this.setHandler("oars.sftp.save", (p: { path: RemotePath; base64: string; expected_size?: number; expected_mtime?: number }) => {
      const rawPath = typeof p.path === "string" ? p.path : (p.path as any)?.utf8 ?? (p.path as any)?.raw ?? "/";
      const file = this.state.sftpFiles.get(rawPath);
      if (file && p.expected_size !== undefined && file.content.length !== p.expected_size) {
        return { ok: false, error: "conflict: file modified remotely" };
      }
      const bytes = base64ToBytes(p.base64);
      this.state.sftpFiles.set(rawPath, {
        content: bytes,
        mode: file?.mode ?? 0o644,
        mtime: Math.floor(Date.now() / 1000),
      });
      return { ok: true };
    });

    this.setHandler("oars.sftp.download", (p: { remote_path: RemotePath; local_path: string }) => {
      const id = ++this.nextTransferId;
      this.state.sftpTransfers.set(id, {
        id,
        kind: "download",
        local_path: p.local_path,
        remote_path: p.remote_path,
        bytes: 0,
        total: 1048576,
        status: "running",
      });
      return { ok: true, op_id: id };
    });

    this.setHandler("oars.sftp.poll", () => {
      const active = Array.from(this.state.sftpTransfers.values());
      for (const t of active) {
        if (t.status === "running") {
          t.bytes = t.total;
          t.status = "done";
        }
      }
      return {
        ok: true,
        transfers: active.map((t) => ({
          id: t.id,
          kind: t.kind,
          local_path: t.local_path,
          path: typeof t.remote_path === "string" ? t.remote_path : (t.remote_path as any).utf8 ?? (t.remote_path as any).raw,
          bytes: t.bytes,
          total: t.total,
          status: t.status,
          error: t.error ?? "",
        })),
      } as SftpTransferSnapshot;
    });

    this.setHandler("oars.sftp.cancel", (p: { transfer_id: number }) => {
      const t = this.state.sftpTransfers.get(p.transfer_id);
      if (t) t.status = "canceled";
      return { ok: true };
    });

    this.setHandler("oars.sftp.mkdir", (p: { path: RemotePath }) => {
      const rawPath = typeof p.path === "string" ? p.path : (p.path as any)?.utf8 ?? (p.path as any)?.raw ?? "/";
      this.setVirtualFile(rawPath, new Uint8Array(0), 0o755, Math.floor(Date.now() / 1000), true);
      return { ok: true };
    });

    this.setHandler("oars.sftp.rm", (p: { path: RemotePath }) => {
      const rawPath = typeof p.path === "string" ? p.path : (p.path as any)?.utf8 ?? (p.path as any)?.raw ?? "/";
      this.state.sftpFiles.delete(rawPath);
      return { ok: true };
    });

    this.setHandler("oars.sftp.rename", (p: { from: RemotePath; to: RemotePath }) => {
      const rawFrom = typeof p.from === "string" ? p.from : (p.from as any)?.utf8 ?? (p.from as any)?.raw ?? "";
      const rawTo = typeof p.to === "string" ? p.to : (p.to as any)?.utf8 ?? (p.to as any)?.raw ?? "";
      const existing = this.state.sftpFiles.get(rawFrom);
      if (existing) {
        this.state.sftpFiles.delete(rawFrom);
        this.state.sftpFiles.set(rawTo, existing);
      }
      return { ok: true };
    });

    this.setHandler("oars.sftp.chmod", (p: { path: RemotePath; mode: number }) => {
      const rawPath = typeof p.path === "string" ? p.path : (p.path as any)?.utf8 ?? (p.path as any)?.raw ?? "";
      const file = this.state.sftpFiles.get(rawPath);
      if (file) file.mode = p.mode;
      return { ok: true };
    });

    this.setHandler("oars.sftp.unzip", () => ({ ok: true, op_id: ++this.nextTransferId }));
    this.setHandler("oars.sftp.zipDownload", () => ({ ok: true, op_id: ++this.nextTransferId }));
    this.setHandler("oars.sftp.folderSize", () => ({ ok: true, size: 1048576 }));

    // 9. oars.scripts
    this.setHandler("oars.scripts.list", () => ({
      scripts: [
        {
          id: "scr-1",
          name: "System Health Check",
          description: "Inspect cpu and disk stats",
          body: "echo 'Health OK'",
          color: "#d97757",
          created_at: 1700000000000,
          updated_at: 1700000000000,
          run_count: 5,
          last_run_at: Date.now() - 3600000,
          variables: [],
          tags: ["health"],
        },
      ],
    }));
    this.setHandler("oars.scripts.validate", () => ({ ok: true }));
    this.setHandler("oars.scripts.save", (p: any) => ({ ok: true, script: p.script }));
    this.setHandler("oars.scripts.delete", () => ({ ok: true }));
    this.setHandler("oars.scripts.run", () => ({ ok: true, channel: ++this.nextChannelId }));
    this.setHandler("oars.scripts.broadcastPrepare", () => ({ preview_id: 1, servers: [], summary: "OK" }));
    this.setHandler("oars.scripts.broadcast", () => ({ ok: true, run_id: 1 }));
    this.setHandler("oars.scripts.broadcastPrepareCancel", () => ({ ok: true }));
    this.setHandler("oars.scripts.broadcastPoll", () => ({ done: true, servers: [] }));
    this.setHandler("oars.scripts.broadcastCancel", () => ({ ok: true }));

    // 10. oars.deploy
    this.setHandler("oars.deploy.apps.list", () => ({
      ok: true,
      apps: this.state.deployApps,
    }));
    this.setHandler("oars.deploy.apps.save", (p: { app: DeployApp }) => {
      const idx = this.state.deployApps.findIndex((a) => a.id === p.app.id);
      if (idx >= 0) this.state.deployApps[idx] = p.app;
      else this.state.deployApps.push(p.app);
      return { ok: true, app: p.app };
    });
    this.setHandler("oars.deploy.apps.secretPresence", (p: { app_id: string }) => {
      const app = this.state.deployApps.find((a) => a.id === p.app_id);
      return { ok: true, app };
    });
    this.setHandler("oars.deploy.apps.delete", (p: { app_id: string }) => {
      this.state.deployApps = this.state.deployApps.filter((a) => a.id !== p.app_id);
      return { ok: true };
    });
    this.setHandler("oars.deploy.key.generate", () => {
      const channel = ++this.nextChannelId;
      this.state.sshChannels.set(channel, {
        chunks: [{ text: "@public\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGenKey123 deploy-key\n@end\n" }],
        cursor: 80,
        eof: true,
      });
      return { ok: true, channel };
    });
    this.setHandler("oars.deploy.hostTrust", () => {
      const channel = ++this.nextChannelId;
      this.state.sshChannels.set(channel, {
        chunks: [{ text: "Host trusted\n" }],
        cursor: 13,
        eof: true,
      });
      return { ok: true, channel };
    });
    this.setHandler("oars.deploy.preflight", (p: { server_id: string; app_id: string }) => {
      const id = ++this.nextPreflightId;
      const preflight = getDefaultDeployPreflight(id, p.app_id, p.server_id);
      this.state.preflights.set(id, preflight);
      return { ok: true, preflight };
    });
    this.setHandler("oars.deploy.preflightPoll", (p: { preflight_id: number }) => {
      const preflight = this.state.preflights.get(p.preflight_id) ?? getDefaultDeployPreflight(p.preflight_id);
      return { ok: true, preflight };
    });
    this.setHandler("oars.deploy.preflightCancel", () => ({ ok: true }));
    this.setHandler("oars.deploy.run", () => {
      const runId = ++this.nextRunId;
      this.state.deployRuns.set(runId, {
        status: "running",
        done: false,
        steps: [
          { channel: 1, cursor: 0, output: "Cloning repo...\nDone\n", state: "done" },
          { channel: 2, cursor: 0, output: "Installing deps...\n", state: "running" },
        ],
      });
      return { ok: true, run_id: runId };
    });
    this.setHandler("oars.deploy.poll", (p: { run_id: number }) => {
      const run = this.state.deployRuns.get(p.run_id);
      if (!run) {
        return {
          ok: true,
          run_id: p.run_id,
          status: "done",
          started_at_ms: Date.now(),
          finished_at_ms: Date.now(),
          canceled: false,
          done: true,
          steps: [],
        } as DeployPollResult;
      }
      return {
        ok: true,
        run_id: p.run_id,
        status: run.status,
        done: run.done,
        started_at_ms: Date.now() - 5000,
        finished_at_ms: run.done ? Date.now() : null,
        canceled: run.status === "canceled",
        steps: run.steps.map((s, idx) => ({
          id: `step-${idx + 1}`,
          label: `Step ${idx + 1}`,
          state: (s.state as any) ?? "running",
          channel: s.channel,
          cursor: s.cursor,
          data: s.output,
          gap: s.gap ? 10 : undefined,
          eof: run.done,
        })),
      } as DeployPollResult;
    });
    this.setHandler("oars.deploy.cancel", (p: { run_id: number }) => {
      const run = this.state.deployRuns.get(p.run_id);
      if (run) {
        run.status = "canceled";
        run.done = true;
      }
      return { ok: true };
    });
    this.setHandler("oars.deploy.history", () => ({
      ok: true,
      runs: [
        {
          id: 1,
          app_id: "app-1",
          server_id: "srv-prod",
          status: "done",
          action: "deploy",
          commit: "abc1234",
          started_at_ms: 1700000000000,
          finished_at_ms: 1700000030000,
          output: "Build output",
          truncated: false,
          steps: [
            { id: "s1", state: "success", exit: 0, error: "" },
          ],
        },
      ],
    }));

    // 11. oars.sshkeys
    this.setHandler("oars.sshkeys.inspect", () => ({ parsed: true, type: "ssh-ed25519", bits: 256, fingerprint_sha256: "SHA256:test" }));
    this.setHandler("oars.sshkeys.snapshot", () => ({ ok: true, snapshot_id: "snap-1" }));
    this.setHandler("oars.sshkeys.snapshotPoll", () => ({ ok: true, finished: true, snapshot: { sources: [], keys: [] } }));
    this.setHandler("oars.sshkeys.snapshotCancel", () => ({ ok: true }));
    this.setHandler("oars.sshkeys.add", () => ({ ok: true, job_id: "job-1", fingerprint: "SHA256:add" }));
    this.setHandler("oars.sshkeys.revoke", () => ({ ok: true, job_id: "job-2" }));
    this.setHandler("oars.sshkeys.rotate", () => ({ ok: true, job_id: "job-3", new_fingerprint: "SHA256:new" }));
    this.setHandler("oars.sshkeys.rotateCommit", () => ({ ok: true }));
    this.setHandler("oars.sshkeys.jobPoll", () => ({ ok: true, state: "done", finished: true, steps: [] }));
    this.setHandler("oars.sshkeys.jobCancel", () => ({ ok: true }));
    this.setHandler("oars.sshkeys.localGenerate", () => ({ ok: true, job_id: "job-loc" }));
    this.setHandler("oars.sshkeys.roles.plan", () => ({ ok: true, plan_id: "plan-1", steps: [] }));
    this.setHandler("oars.sshkeys.roles.commit", () => ({ ok: true, job_id: "job-role" }));
    this.setHandler("oars.sshkeys.deployKeys.generate", () => ({ ok: true, job_id: "job-dk" }));
    this.setHandler("oars.sshkeys.deployKeys.delete", () => ({ ok: true, job_id: "job-dk-del" }));

    // 12. oars.access
    this.setHandler("oars.access.scan", () => ({ ok: true, scan_id: "scan-1" }));
    this.setHandler("oars.access.scanCancel", () => ({ ok: true }));
    this.setHandler("oars.access.poll", () => ({ ok: true, finished: true, people: [], unassigned: [] }));
    this.setHandler("oars.access.key.inspect", () => ({ ok: true, fingerprint: "SHA256:acc" }));
    this.setHandler("oars.access.identities.list", () => ({ ok: true, identities: [] }));
    this.setHandler("oars.access.identities.save", (p: any) => ({ ok: true, identity: p.identity }));
    this.setHandler("oars.access.identities.delete", () => ({ ok: true }));
    this.setHandler("oars.access.offboard", () => ({ ok: true, job_id: "job-off" }));
    this.setHandler("oars.access.onboard", () => ({ ok: true, job_id: "job-on" }));
    this.setHandler("oars.access.rotate", () => ({ ok: true, job_id: "job-rot" }));
    this.setHandler("oars.access.jobPoll", () => ({ ok: true, state: "done", finished: true, steps: [] }));
    this.setHandler("oars.access.jobCancel", () => ({ ok: true }));
    this.setHandler("oars.access.export", () => ({ ok: true, exported_bytes: 100 }));

    // 13. oars.backup
    const backupJob = {
      id: "backup-job-1",
      server_id: "srv-prod",
      revision: 1,
      name: "Mock backup",
      source_path: "/srv/data",
      destination: {
        type: "s3",
        provider: "aws",
        bucket: "mock-backups",
        prefix: "daily",
        endpoint: "",
        region: "us-east-1",
        credential_mode: "aws_runtime",
        storage_class: "",
      },
      transfer: "copy",
      schedule: { mode: "manual", enabled: false },
      created_at_ms: 1_700_000_000_000,
      updated_at_ms: 1_700_000_000_000,
    };
    this.setHandler("oars.backup.jobs.list", () => ({ ok: true, jobs: [] }));
    this.setHandler("oars.backup.status", () => ({ ok: true, status: null, stale: true }));
    this.setHandler("oars.backup.refresh", () => ({ ok: true, operation_id: "backup-refresh-1" }));
    this.setHandler("oars.backup.jobs.plan", () => ({
      ok: true,
      plan_id: "backup-plan-1",
      expires_at_ms: 1_700_000_300_000,
      job: backupJob,
      requires_connection_test: false,
      requires_remote_secret: false,
      effects: [],
      warnings: [],
    }));
    this.setHandler("oars.backup.jobs.save", () => ({ ok: true, operation_id: "backup-save-1", job_id: backupJob.id }));
    this.setHandler("oars.backup.jobs.deletePlan", () => ({ ok: true, plan_id: "backup-delete-plan-1", expires_at_ms: 1_700_000_300_000, job_name: backupJob.name, effects: [], leftovers: [] }));
    this.setHandler("oars.backup.jobs.delete", () => ({ ok: true, operation_id: "backup-delete-1" }));
    this.setHandler("oars.backup.operationPoll", () => ({ ok: true, operation_id: "backup-refresh-1", kind: "refresh", state: "done", steps: [], started_at_ms: 1_700_000_000_000, finished_at_ms: 1_700_000_000_100 }));
    this.setHandler("oars.backup.operationCancel", () => ({ ok: true }));
    this.setHandler("oars.backup.test.plan", () => ({ ok: true, test_plan_id: "backup-test-plan-1", expires_at_ms: 1_700_000_300_000, remote_object: "daily/sentinel", checks: ["list", "write", "read", "delete", "cleanup_verify"], mutates: true }));
    this.setHandler("oars.backup.test", () => ({ ok: true, operation_id: "backup-test-1" }));
    this.setHandler("oars.backup.run", () => ({ ok: true, run_id: "backup-run-1" }));
    this.setHandler("oars.backup.poll", () => ({ ok: true, run_id: "backup-run-1", status: "no_changes", phase: "finished", bytes_done: 0, bytes_total: 0, files_done: 0, files_total: 0, speed_bps: 0, eta_sec: 0, started_at_ms: 1_700_000_000_000, finished_at_ms: 1_700_000_000_100, log_cursor: 0, log_delta: "", dropped: 0, cleanup_state: "complete" }));
    this.setHandler("oars.backup.cancel", () => ({ ok: true }));
    this.setHandler("oars.backup.history", () => ({ ok: true, runs: [] }));
    this.setHandler("oars.backup.historyLog", () => ({ ok: true, cursor: 0, delta: "", eof: true, dropped: 0 }));
    this.setHandler("oars.backup.install.plan", () => ({ ok: true, plan_id: "backup-install-plan-1", expires_at_ms: 1_700_000_300_000, target: "ubuntu", privilege: "sudo", commands: ["sudo apt-get install -y rclone"], effects: ["rclone"], rollback: [], manual: false }));
    this.setHandler("oars.backup.install", () => ({ ok: true, operation_id: "backup-install-1" }));

    // 14. oars.ai
    this.setHandler("oars.ai.provider.list", () => ({ ok: true, providers: [] }));
    this.setHandler("oars.ai.provider.save", ({ provider }) => ({
      ok: true,
      provider: { ...(provider as Record<string, unknown>), id: "aip-fixture", revision: 1, tested_at_ms: null, test_status: "untested", instruction_role: null, structured_output: null },
    }));
    this.setHandler("oars.ai.provider.delete", () => ({ ok: true }));
    this.setHandler("oars.ai.provider.test", ({ operation_id }) => ({ ok: true, operation_id, state: "queued" }));
    this.setHandler("oars.ai.provider.testPoll", ({ operation_id, cursor = 0 }) => ({ ok: true, stream_id: operation_id, cursor, dropped: 0, finished: true, state: "passed", events: [] }));
    this.setHandler("oars.ai.provider.testCancel", () => ({ ok: true, state: "canceled" }));
    this.setHandler("oars.ai.credential.configure", () => ({ ok: true, status: "configured" }));
    this.setHandler("oars.ai.credential.status", () => ({ ok: true, status: "missing" }));
    this.setHandler("oars.ai.credential.delete", () => ({ ok: true, status: "missing" }));
    this.setHandler("oars.ai.context.get", () => ({ ok: true, state: "missing", context: null, stale: true }));
    this.setHandler("oars.ai.context.refresh", ({ operation_id }) => ({ ok: true, operation_id, state: "running" }));
    this.setHandler("oars.ai.context.poll", ({ operation_id, cursor = 0 }) => ({ ok: true, stream_id: operation_id, cursor, dropped: 0, finished: true, state: "ready", events: [] }));
    this.setHandler("oars.ai.context.cancel", () => ({ ok: true, state: "canceled" }));

    // 15. oars.vnc
    this.setHandler("oars.vnc.start", () => ({ ok: true, tunnel_id: 1, port: 5900, local_port: 59000, websocket_port: 6080 }));
    this.setHandler("oars.vnc.stop", () => ({ ok: true }));
    this.setHandler("oars.vnc.probe", () => ({ ok: true, desktop_installed: true, desktop_surface_running: true, desktop_panel_running: true }));
    this.setHandler("oars.vnc.setup", () => ({ ok: true, channel: 1 }));
    this.setHandler("oars.vnc.poll", () => ({ ok: true, state: "open", tunnel_id: 1 }));

    // 16. oars.history & oars.audit
    this.setHandler("oars.history.record", () => ({ ok: true }));
    this.setHandler("oars.history.list", () => ({ entries: [], total: 0 }));
    this.setHandler("oars.history.replay", () => ({ ok: true, channel: 1 }));
    this.setHandler("oars.audit.list", () => ({ entries: [], total: 0 }));
    this.setHandler("oars.audit.clear", () => ({ ok: true }));

    // 17. oars.vault
    this.setHandler("oars.vault.export", () => ({ ok: true, payload: "encrypted-vault" }));
    this.setHandler("oars.vault.import", () => ({ ok: true, token: "tok-1", items_count: 5 }));
    this.setHandler("oars.vault.importConfirm", () => ({ ok: true, imported: 5 }));

    // 18. oars.agent
    this.setHandler("oars.agent.list", () => ({ ok: true, agents: [] }));
    this.setHandler("oars.agent.forward", () => ({ ok: true }));
  }
}

export const mockBridge = new MockBridge();

export function createMockFile(name: string, content: string | Uint8Array = "test content", type = "text/plain"): File {
  const bytes = typeof content === "string" ? new TextEncoder().encode(content) : content;
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return new File([buffer], name, { type, lastModified: Date.now() });
}
