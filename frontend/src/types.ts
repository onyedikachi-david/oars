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
  kind: "shell" | "exec";
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
}
