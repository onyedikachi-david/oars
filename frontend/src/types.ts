// Shared types for the Oars bridge protocol.

export interface Server {
  id: string;
  name: string;
  host: string;
  port: number;
  user: string;
  auth_method: "password" | "key";
  key_path: string;
  key_has_passphrase: boolean;
  host_fingerprint: string | null;
  group: string;
  created_at: number;
  updated_at: number;
}

export interface ServerDraft {
  id?: string;
  name: string;
  host: string;
  port: number;
  user: string;
  auth_method: "password" | "key";
  key_path?: string;
  key_has_passphrase?: boolean;
  group?: string;
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
  trust?: { pending: boolean; fingerprint?: string };
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
