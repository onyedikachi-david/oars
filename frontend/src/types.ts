// Shared types for the Oars bridge protocol.

export type AuthMethod = "password" | "key" | "agent";

export interface Server {
  id: string;
  name: string;
  host: string;
  port: number;
  user: string;
  auth_method: AuthMethod;
  key_path: string;
  key_has_passphrase: boolean;
  host_fingerprint: string | null;
  group: string;
  tags: string[];
  via_server_id: string | null;
  created_at: number;
  updated_at: number;
}

export interface ServerDraft {
  id?: string;
  name: string;
  host: string;
  port: number;
  user: string;
  auth_method: AuthMethod;
  key_path?: string;
  key_has_passphrase?: boolean;
  group?: string;
  tags?: string[];
  via_server_id?: string | null;
}

export type SessionStatus =
  | "connecting"
  | "needs_trust"
  | "authenticating"
  | "ready"
  | "closed"
  | "error";

export interface ChannelInfo {
  id: number;
  kind: "shell" | "exec" | "log";
  command: string;
  cursor: number;
  dropped: number;
  pending: number;
  eof: boolean;
  exit: number | null;
  data: string;
}

export interface PollResult {
  ok: boolean;
  status: SessionStatus;
  error?: string;
  trust?: { pending: boolean; algorithm?: string; fingerprint?: string };
  channels: ChannelInfo[];
}

export const STATUS_LABEL: Record<SessionStatus, string> = {
  connecting: "Connecting…",
  needs_trust: "Verify host key",
  authenticating: "Authenticating…",
  ready: "Connected",
  closed: "Disconnected",
  error: "Error",
};

export interface MonitorSnapshot {
  ok: boolean;
  ts: number;
  status?: string;
  cpu: {
    utilization_pct: number | null;
    cpu_warming: boolean;
    load_1: number;
    load_5: number;
    load_15: number;
    uptime_sec: number;
    cores: number;
  } | null;
  mem: {
    used_bytes: number;
    total_bytes: number;
    available_bytes: number;
    swap_used_bytes: number;
    swap_total_bytes: number;
  } | null;
  disk: {
    used_bytes: number;
    total_bytes: number;
    available_bytes: number;
  } | null;
  processes: Array<{ pid: number; name: string; cpu: number | null; mem: number | null }>;
  probe_error: string | null;
}

export interface LogSource {
  path: string;
  group: string;
  name: string;
  size: number;
  mtime_epoch: number;
  age_sec: number;
  mode: number;
  readable: boolean;
}

export interface LogReadResult {
  ok: boolean;
  path: string;
  lines: string[];
  limited: boolean;
  binary: boolean;
}

export interface LogScanResult {
  ok: boolean;
  sources: LogSource[];
  partial: boolean;
  reason: string;
}

export interface LogClearResult {
  ok: boolean;
  before_size: number;
  after_size: number;
}

export type SftpTransferStatus = "queued" | "running" | "done" | "failed" | "canceled";
export type SftpTransferKind = "upload" | "download" | "rm" | "unzip" | "zip_download";

/**
 * `RemotePath = {utf8:string}|{base64:string}` (spec 05 §5): the base64
 * form carries raw server bytes; `display` text is UI-only and must never
 * be used to rebuild an operation path.
 */
export type RemotePath =
  | { utf8: string; base64?: never }
  | { utf8?: never; base64: string };

export type SftpEntryKind = "file" | "dir" | "symlink" | "other";

export interface LocalEntry {
  name: string;
  path: string;
  kind: SftpEntryKind;
  size: number;
  mtime: number;
}

export interface LocalLsResult {
  ok: boolean;
  entries: LocalEntry[];
  truncated: boolean;
}

export interface SftpEntry {
  name: RemotePath;
  display: string;
  kind: SftpEntryKind;
  size: number;
  mtime: number;
  mode: string;
  uid: number;
  gid: number;
  link_target: string | null;
}

export interface SftpLsResult {
  ok: boolean;
  entries: SftpEntry[];
  truncated: boolean;
}

export interface SftpStatResult {
  ok: boolean;
  entry: SftpEntry;
}

export interface SftpReadResult {
  ok: boolean;
  base64: string;
  eof: boolean;
}

export interface SftpWriteResult {
  ok: boolean;
  written: number;
  done: boolean;
}

export interface SftpSaveParams {
  expected_size?: number;
  expected_mtime?: number;
  /** Hex-encoded SHA-256 of the content the editor opened. */
  expected_sha256?: string;
}

export interface SftpFolderSizeResult {
  ok: boolean;
  size: number;
}

export interface SftpTransfer {
  id: number;
  kind: SftpTransferKind;
  path: string;
  bytes: number;
  total: number;
  status: SftpTransferStatus;
  error: string;
}

export interface SftpTransferSnapshot {
  ok: boolean;
  transfers: SftpTransfer[];
}

export interface SftpOpStart {
  ok: boolean;
  op_id: number;
}

export interface VncStartResult {
  ok: boolean;
  tunnel_id: number;
  ws_port: number;
  token: string;
}

export interface VncProbeResult {
  ok: boolean;
  x11vnc: boolean;
  tigervnc: boolean;
  desktop_installed: boolean;
  window_manager_running: boolean;
  desktop_surface_running: boolean;
  desktop_panel_running: boolean;
  desktop_running: boolean;
  desktop_name: string;
  setup_state: "idle" | "installing" | "installed" | "ready" | "failed";
  listening: Array<{ port: number; process: string }>;
}

export interface VncSetupResult {
  ok: boolean;
  action: "install" | "configure" | "manual";
  plan: string;
  hint: string;
  executed: boolean;
  desktop_action: "none" | "install" | "start" | "running" | "manual";
  desktop_name: string;
}

export interface VncPollResult {
  ok: boolean;
  state: "listening" | "handshake" | "connected" | "closing" | "closed";
  bytes_up: number;
  bytes_down: number;
  error: string;
}
