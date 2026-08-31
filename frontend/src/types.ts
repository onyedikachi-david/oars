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

export interface ProcessSample {
  pid: number;
  name: string;
  cpu: number | null;
  mem: number | null;
}

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
  processes: ProcessSample[];
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

// --- access (spec 09, NEXT-SPEC bridge contract §8) -------------------------
export interface AccessAccount {
  user: string;
  home: string;
  skipped: boolean;
  read: boolean;
  error?: string;
  sudo: AccessSudoPolicy;
  key_count: number;
}
export type AccessScope = "connected_accounts" | "all_login_accounts";
export type AccessCoverage = "complete" | "partial";
export type AccessSudoPolicy = "none" | "limited" | "full" | "unknown";
export interface AccessGrant { fingerprint: string; server_id: string; server_name: string; user: string; sudo: AccessSudoPolicy; comment: string; line_hash: string; source_path: string; file_sha256: string; }
export interface AccessServerView {
  server_id: string; name: string; host: string; phase: string; error?: string;
  connected_user?: string; sudo: AccessSudoPolicy; coverage: AccessCoverage; coverage_reason?: string;
  accounts: AccessAccount[]; sources: string[];
}
export interface AccessScanResponse { ok: boolean; scan_id: string; }
export interface AccessPage<T> { offset: number; limit: number; total: number; rows: T[]; has_more: boolean; }
export interface AccessPollResponse {
  ok: boolean; scan_id: string; state: "scanning" | "done" | "canceled"; scope: AccessScope;
  created_at_ms: number; finished_at_ms?: number; servers: AccessServerView[];
  people_page: AccessPage<AccessPerson>; unassigned_page: AccessPage<AccessUnassigned>;
  metrics: { people: number; distinct_fingerprints: number; completed_servers: number; target_servers: number; observed_grants: number };
  coverage: AccessCoverage; sync_errors: Array<{ server_id: string; reason: string }>;
  source_warnings: Array<{ server_id: string; reason: string }>;
}
export interface AccessPerson { identity_id: string; name: string; fingerprints: string[]; grants: AccessGrant[]; }
export interface AccessUnassigned { fingerprint: string; grants: AccessGrant[]; }
export interface AccessIdentity { id: string; name: string; fingerprints: string[]; bindings: Array<{ fingerprint: string; shared: boolean }>; revision: number; created_at_ms: number; shared: boolean; }
export interface AccessIdentitiesListResponse { ok: boolean; identities: AccessIdentity[]; revision?: number; recovery_error?: string; quarantined?: string; }
export interface AccessJobPollResponse {
  ok: boolean; state: "queued" | "running" | "done" | "partial" | "canceled"; results: Array<{ server_id: string; user: string; source_path: string; state: "queued" | "running" | "done" | "conflict" | "error" | "canceled"; error?: string }>;
}
export interface AccessExportResponse { ok: boolean; format: "csv" | "json"; path: string; rows: number; formula_safe: boolean; }
export interface AccessKeyInspectResponse { ok: boolean; normalized_public_key: string; fingerprint: string; key_type: string; comment: string; }

export interface SshKeyEntry {
  source_path: string;
  line_index: number;
  line_hash: string;
  parsed: boolean;
  options?: string;
  type?: string;
  key?: string;
  comment?: string;
  fingerprint_sha256?: string;
  bits?: number;
  raw?: string;
  error?: string;
  // Backend-typed assessment; the UI never infers safety from options alone.
  policy_assessment?: SshPolicyAssessment;
}

export type SshPolicyLevel = "standard" | "restricted" | "role_forced" | "weak";
export interface SshPolicyAssessment { level: SshPolicyLevel; detail: string; }

export type SshAccountKind = "connected" | "managed_role";
export interface SshAccountRef { kind: SshAccountKind; name?: string; }

export type SshSourceKind = "static" | "dynamic" | "certificate";
export type SshSourceStatus = "missing" | "readable" | "denied" | "timeout" | "too_large" | "transport_error" | "parse_error";
export interface SshSource {
  path: string;
  kind: SshSourceKind;
  status: SshSourceStatus;
  file_sha256?: string;
  mode?: number;
  owner?: string;
  error?: string;
}

export type SshRoleKind = "standard_ssh" | "read_only_sftp";
export type SshRolePolicyState = "verified" | "missing" | "corrupt" | "stale" | "unreadable" | "drifted";
export interface SshRole {
  name: string;
  kind: SshRoleKind;
  home?: string;
  shell?: string;
  policy_state: SshRolePolicyState;
  // Exact key fingerprints installed for this role. Comments are never used
  // as identity (the old comment-based `users` field is gone).
  key_fingerprints: string[];
}

export interface SshDeployKey {
  deploy_key_id: string;
  repository_label: string;
  path: string;
  fingerprint: string;
  created_at_ms?: number;
}

export type SshPrivilege = "root" | "sudo_n" | "none";
export interface SshCapabilities { privilege: SshPrivilege; sftp_read_only: boolean; }

export type SshSnapshotState = "queued" | "running" | "done" | "partial" | "canceled";
export type SshSnapshotCoverage = "complete" | "partial";
export interface SshSnapshotStartResponse { ok: boolean; snapshot_id: string; }
export interface SshSnapshotPollResponse {
  ok: boolean;
  state: SshSnapshotState;
  server_id: string;
  account: SshAccountRef;
  scope: string;
  created_at_ms: number;
  finished_at_ms?: number;
  coverage: SshSnapshotCoverage;
  capabilities: SshCapabilities;
  sources: SshSource[];
  keys: SshKeyEntry[];
  roles: SshRole[];
  deploy_keys: SshDeployKey[];
  warnings: string[];
}

export type SshJobState = "queued" | "running" | "waiting_for_verification" | "done" | "partial" | "canceled";
export type SshJobStepState = "queued" | "running" | "waiting" | "done" | "conflict" | "error" | "canceled";
export interface SshJobStep { id: string; state: SshJobStepState; error?: string; }
// Job result payloads are union-typed across the mutation kinds; every field
// is optional and the consuming flow reads only the fields its kind defines.
export interface SshJobResult {
  public_key?: string;
  private_path?: string;
  fingerprint?: string;
  keychain_account?: string;
  deploy_key_id?: string;
  new_fingerprint?: string;
  idempotent?: boolean;
}
export interface SshJobPollResponse { ok: boolean; state: SshJobState; steps: SshJobStep[]; result?: SshJobResult; }

export interface SshInspectResponse {
  ok: boolean;
  normalized_public_key: string;
  fingerprint: string;
  key_type: string;
  bits?: number;
  comment: string;
}

export type SshRolePlanAction = "create" | "repair" | "delete";
export interface SshRolePlanResponse {
  ok: boolean;
  plan_id: string;
  expires_at_ms: number;
  account: string;
  home?: string;
  commands: string[];
  effects: string[];
}

export type SshRotateVerification =
  | { kind: "local_private_key"; path: string; passphrase?: string }
  | { kind: "external_confirmation"; confirm_fingerprint: string };


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

// --- scripts (spec 06) ------------------------------------------------------
//
// Timestamp wire unit: the backend stores real-time nanoseconds but sends
// scripts as integer milliseconds, which stay safe in JavaScript numbers.

/** Stored variable definition (spec 06 §7). `secret_default` marks the
 *  editor's input mode; run-time secrets come in the run payload. */
export interface ScriptVariable {
  name: string;
  label: string;
  secret_default: boolean;
}

export interface Script {
  id: string;
  name: string;
  description: string;
  tags: string[];
  color: string;
  body: string;
  variables: ScriptVariable[];
  /** Integer milliseconds since epoch, converted by the backend before JSON serialization. */
  created_at: number;
  updated_at: number;
  run_count: number;
  last_run_at: number | null;
}

/** The complete save payload: the editor must send the full draft on
 *  every save, or stored variables are erased (spec 06 — no data loss). */
export interface ScriptDraft {
  id?: string;
  name: string;
  description: string;
  tags: string[];
  color: string;
  body: string;
  variables: ScriptVariable[];
}

/** Run-time values, separate from stored definitions. `secret` may only
 *  PROMOTE a value: the stored `secret_default` is the minimum policy and
 *  the backend refuses demotion. Never persisted. */
export interface ScriptRunVars {
  [name: string]: { value: string; secret: boolean };
}

export interface ScriptsListResult {
  ok: boolean;
  scripts: Script[];
  recovery_error?: string;
}

export type BroadcastStatus =
  | "queued"
  | "checking"
  | "running"
  | "done"
  | "failed"
  | "canceled"
  | "skipped";

export interface BroadcastServerResult {
  server_id: string;
  status: BroadcastStatus;
  exit: number | null;
  error: string;
  cursor?: number;
  gap?: number;
  eof?: boolean;
  data?: string;
}

export interface BroadcastPollResult {
  ok: boolean;
  run_id: number;
  script_name: string;
  canceled: boolean;
  done: boolean;
  servers: BroadcastServerResult[];
}

/** Two-phase broadcast step 1 (spec 06 §5): the exact command the commit
 *  will submit, frozen at prepare time. `command` is the full exec string
 *  (`bash -c '<expanded>'`); show `redacted_command` by default when
 *  secrets exist. */
export interface BroadcastPreview {
  ok: boolean;
  preview_id: number;
  script_id: string;
  script_name: string;
  command: string;
  redacted_command: string;
  servers: Array<{ server_id: string }>;
  destructive: boolean;
  /** Integer milliseconds since epoch, converted by the backend before JSON serialization. */
  expires_at: number;
}

// --- deploy (spec 07, NEXT-SPEC bridge contract) -----------------------------
export type DeployEnvironment = "development" | "staging" | "production";
export type DeployTransport = "https" | "ssh";
export type DeployAppType = "node" | "react" | "next" | "static";
export type DeployPackageManager = "auto" | "npm" | "pnpm" | "yarn";
export interface DeployRepo { url: string; transport: DeployTransport; branch: string; }
export interface DeployRuntime {
  node_version: string; type: DeployAppType; package_manager: DeployPackageManager;
  install: string; build: string; entry: string; args: string; start_command: string; build_folder: string;
}
export interface DeployEnvVar { name: string; secret: boolean; value: string; has_value: boolean; }
export interface DeployApp {
  id: string; server_id: string; name: string; environment: DeployEnvironment;
  folder: string; repo: DeployRepo; runtime: DeployRuntime; env_vars: DeployEnvVar[];
  domains: string[]; ssl: boolean; email: string; app_port: number;
  revision: number; created_at_ms: number; updated_at_ms: number;
}
export interface DeployAppInput {
  id?: string; server_id: string; name: string; environment: DeployEnvironment;
  folder: string; repo: DeployRepo; runtime: DeployRuntime; env_vars: DeployEnvVar[];
  domains: string[]; ssl: boolean; email: string; app_port: number;
}
export type DeployStepState = "pending" | "running" | "cancel_requested" | "canceled" | "success" | "failed" | "skipped";
export type DeployRunStatus = "queued" | "running" | "cancel_requested" | "canceled" | "done" | "failed" | "interrupted";
export interface DeployIssue { id: string; message: string; }
export interface DeployApproval { id: string; label: string; detail: string; }
export interface DeployPreflightFacts {
  os: string; arch: string; libc: string; user: string; home: string; privilege: string;
  repository_commit: string; lockfiles: string; git_host_fingerprints: string; ports: string;
}
export interface DeployPreflightStep { id: string; label: string; mutation: string; command: string; skipped: boolean; files: Array<{ path: string; mode: number }>; guards: string[]; rollback: string; }
export interface DeployPreflight {
  id: number; app_id: string; server_id: string; created_at_ms: number; expires_at_ms: number;
  app_revision: number; target_fingerprint: number;
  status: "gathering" | "ready" | "blocked" | "failed";
  error?: string; facts: DeployPreflightFacts; blockers: DeployIssue[]; warnings: DeployIssue[]; approvals: DeployApproval[];
  configs: { env: string; pm2: string; nginx: string }; steps: DeployPreflightStep[]; commit?: string;
}
export interface DeployStep { id: string; label: string; state: DeployStepState; channel?: number; exit?: number | null; error?: string; cursor?: number; gap?: number; eof?: boolean; data?: string; }
export interface DeployPollResult { ok: boolean; run_id: number; status: DeployRunStatus; started_at_ms: number; finished_at_ms: number | null; canceled: boolean; done: boolean; steps: DeployStep[]; }
export interface DeployHistoryRecord { id: number; server_id: string; app_id: string; status: DeployRunStatus; action: string; commit: string; started_at_ms: number; finished_at_ms: number | null; output: string; truncated: boolean; steps: Array<{ id: string; state: DeployStepState; exit: number | null; error: string }>; }

// ============================================================================
// Spec 10: Backups (oars.backup.*)
// ============================================================================

export type BackupProvider = "aws" | "r2" | "b2_s3" | "wasabi" | "minio" | "spaces";
export type BackupTransfer = "copy" | "sync";
export type BackupCredentialMode = "access_key" | "aws_runtime";
export type BackupIntervalUnit = "hours" | "days";

export interface BackupDestination {
  type: "s3";
  provider: BackupProvider;
  bucket: string;
  prefix: string;
  endpoint: string;
  region: string;
  credential_mode: BackupCredentialMode;
  storage_class: string;
}

export type BackupSchedule =
  | { mode: "manual"; enabled: false }
  | { mode: "interval"; enabled: boolean; every: number; unit: BackupIntervalUnit; anchor_epoch_sec: number }
  | { mode: "custom"; enabled: boolean; expr: string };

export interface BackupCapabilityProof {
  id: string;
  expires_at_ms: number;
  binding_sha256: string;
}

export interface BackupJob {
  id: string;
  server_id: string;
  revision: number;
  name: string;
  source_path: string;
  destination: BackupDestination;
  transfer: BackupTransfer;
  schedule: BackupSchedule;
  capability_proof?: BackupCapabilityProof;
  created_at_ms: number;
  updated_at_ms: number;
}

export interface BackupJobDraft {
  id?: string;
  server_id: string;
  name: string;
  source_path: string;
  destination: BackupDestination;
  transfer: BackupTransfer;
  schedule: BackupSchedule;
}

export interface BackupCredentials {
  access_key: string;
  secret_key: string;
}

export type BackupErrorCode =
  | "invalid_payload" | "invalid_job" | "invalid_credentials"
  | "not_connected" | "session_not_ready" | "unsupported_target"
  | "rclone_missing" | "cron_missing" | "cron_stopped"
  | "source_missing" | "source_unreadable" | "source_too_large"
  | "plan_expired" | "conflict" | "busy" | "not_found"
  | "permission_denied" | "timeout" | "transport_error"
  | "capability_failed" | "cleanup_failed" | "store_corrupt"
  | "canceled" | "interrupted" | "internal";

export interface BackupFailureDetail {
  step?: string;
  path?: string;
  remote_object?: string;
}

export interface BackupFailure {
  ok: false;
  code: BackupErrorCode;
  error: string;
  retryable: boolean;
  detail?: BackupFailureDetail;
}

export interface BackupJobsListResult {
  ok: true;
  jobs: BackupJob[];
  recovery_error?: string;
}

export interface BackupStatusResult {
  ok: true;
  status: BackupServerStatus | null;
  stale: boolean;
  recovery_error?: string;
}

export interface BackupOperationAdmission {
  ok: true;
  operation_id: string;
}

export interface BackupSaveAdmission extends BackupOperationAdmission {
  job_id: string;
}

export interface BackupRunAdmission {
  ok: true;
  run_id: string;
}

export interface BackupPlanResult {
  ok: true;
  plan_id: string;
  expires_at_ms: number;
  job: BackupJob;
  requires_connection_test: boolean;
  requires_remote_secret: boolean;
  effects: string[];
  warnings: string[];
  schedule_preview?: { timezone: string; crontab_block: string };
}

export interface BackupDeletePlanResult {
  ok: true;
  plan_id: string;
  expires_at_ms: number;
  job_name: string;
  effects: string[];
  leftovers: string[];
}

export type BackupCheckName = "list" | "write" | "read" | "delete" | "cleanup_verify";
export type BackupCheckState = "passed" | "failed";

export interface BackupTestPlanResult {
  ok: true;
  test_plan_id: string;
  expires_at_ms: number;
  remote_object: string;
  checks: ["list", "write", "read", "delete", "cleanup_verify"];
  mutates: true;
}

export interface BackupTestOperationResult {
  checks: Record<BackupCheckName, BackupCheckState>;
  capability_proof?: BackupCapabilityProof;
  leftover_remote_object?: string;
}

export interface BackupCleanupRequiredResult {
  cleanup: "required";
  retry_action: "operationCancel";
  needs_credentials: boolean;
  job_id?: string;
}

export interface BackupCleanupCompleteResult {
  cleanup: "complete";
  remote_object?: string;
}

export interface BackupRefreshOperationResult {
  status: BackupServerStatus;
  imported: number;
  warnings: number;
}

export interface BackupJobOperationResult {
  job_id: string;
}

export interface BackupInstallOperationResult {
  target: string;
  what: BackupInstallTarget;
  partial_effects: boolean;
}

export type BackupOperationState = "queued" | "running" | "done" | "partial" | "failed" | "canceled";
export type BackupStepState = "pending" | "running" | "done" | "conflict" | "failed" | "cancel_requested" | "canceled" | "skipped";
export type BackupOperationKind = "refresh" | "test" | "save" | "delete" | "install" | "cleanup";

export interface BackupOperationStep {
  id: string;
  state: BackupStepState;
  error?: BackupFailure;
}

interface BackupOperationBase {
  ok: true;
  operation_id: string;
  state: BackupOperationState;
  steps: BackupOperationStep[];
  started_at_ms: number;
  finished_at_ms?: number;
  error?: BackupFailure;
}

export type BackupOperation =
  | (BackupOperationBase & { kind: "refresh"; result?: BackupRefreshOperationResult })
  | (BackupOperationBase & { kind: "test"; result?: BackupTestOperationResult | BackupCleanupRequiredResult })
  | (BackupOperationBase & { kind: "save" | "delete"; result?: BackupJobOperationResult | BackupCleanupRequiredResult })
  | (BackupOperationBase & { kind: "install"; result?: BackupInstallOperationResult })
  | (BackupOperationBase & { kind: "cleanup"; result?: BackupCleanupRequiredResult | BackupCleanupCompleteResult | BackupJobOperationResult });

export interface BackupServerStatus {
  observed_at_ms: number;
  os: string;
  arch: string;
  user: string;
  home: string;
  timezone: string;
  rclone_path: string;
  rclone_version: string;
  crontab_implementation: string;
  cron_installed: boolean;
  cron_running: boolean;
  service_manager: string;
  scheduler_supported: boolean;
  process_groups: boolean;
  target: string;
  privilege: string;
  warnings: string[];
}

export type BackupRunStatus =
  | "queued" | "preparing" | "running" | "cancel_requested"
  | "success" | "no_changes" | "failed" | "canceled" | "interrupted" | "partial" | "skipped_overlap";

export type BackupRunPhase = "queued" | "preparing" | "running" | "cancel_requested" | "finished";
export type BackupCleanupState = "pending" | "complete" | "failed";

export interface BackupPollResult {
  ok: true;
  run_id: string;
  status: BackupRunStatus;
  phase: BackupRunPhase;
  bytes_done: number;
  bytes_total: number;
  files_done: number;
  files_total: number;
  speed_bps: number;
  eta_sec: number;
  started_at_ms: number;
  finished_at_ms?: number;
  log_cursor: number;
  log_delta: string;
  dropped: number;
  cleanup_state: BackupCleanupState;
  error?: BackupFailure;
}

export interface BackupRunSummary {
  run_id: string;
  job_id: string;
  server_id: string;
  source: "manual" | "scheduled";
  status: BackupRunStatus;
  bytes_done: number;
  bytes_total: number;
  files_done: number;
  files_total: number;
  started_at_ms: number;
  finished_at_ms?: number;
  error?: BackupFailure;
}

export interface BackupHistoryResult {
  ok: true;
  runs: BackupRunSummary[];
  recovery_error?: string;
}

export interface BackupHistoryLogResult {
  ok: true;
  cursor: number;
  delta: string;
  eof: boolean;
  dropped: number;
}

export type BackupInstallTarget = "rclone" | "cron" | "start_cron";

export interface BackupInstallPlanResult {
  ok: true;
  plan_id: string;
  expires_at_ms: number;
  target: string;
  privilege: string;
  commands: string[];
  effects: string[];
  rollback: string[];
  manual: boolean;
}

// ============================================================================
// Spec 11: AI Terminal (oars.ai.*)
// ============================================================================

export type AiAdapter = "openai_compatible" | "custom";
export type AiInstructionRole = "developer" | "system";

export interface AiCapabilities {
  instruction_role: AiInstructionRole;
  streaming: boolean;
  structured_output: boolean;
}

export interface AiProvider {
  adapter: AiAdapter;
  base_url: string;
  model: string;
  capabilities: AiCapabilities;
  updated_at_ns: number;
}

export interface AiProviderInput {
  adapter: AiAdapter;
  base_url: string;
  model: string;
  capabilities?: Partial<AiCapabilities>;
}

export interface AiLogInfo {
  path: string;
  last_write: number;
}

export interface AiContextBundle {
  ok: boolean;
  os: string;
  hostname: string;
  uptime_sec: number;
  load: {
    utilization_pct: number | null;
    load_1: number;
    load_5: number;
    load_15: number;
    cores: number;
  };
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
  top_processes: Array<{
    pid: number;
    name: string;
    cpu: number | null;
    mem: number | null;
  }>;
  active_logs: AiLogInfo[];
  probe_error: string | null;
}

export interface AiHistoryEntry {
  ts: number;
  action: string;
  detail: string;
}

export interface AiHistoryResult {
  ok: boolean;
  runs: AiHistoryEntry[];
}

export interface AiProviderGetResult {
  ok: boolean;
  provider: AiProvider | null;
}

export interface AiProviderSetResult {
  ok: boolean;
  provider: AiProvider;
}

// ============================================================================
// Spec 15: Command History & Audit Journal (oars.history.*, oars.audit.*)
// ============================================================================

export interface HistoryEntry {
  id: string;
  operation_id: string;
  ts: number;
  server_id: string;
  kind: string;
  command: string;
  exit: number | null;
  duration_ms: number | null;
  output_snippet: string;
  redacted: boolean;
}

export interface HistoryRecordInput {
  operation_id: string;
  server_id: string;
  kind: string;
  command: string;
  exit?: number | null;
  duration_ms?: number | null;
  output_snippet?: string;
}

export interface HistoryListFilter {
  server_id?: string;
  q?: string;
  limit?: number;
}

export interface HistoryListResult {
  ok: boolean;
  entries: HistoryEntry[];
}

export interface AuditEntry {
  id: string;
  operation_id: string;
  ts: number;
  type: string;
  target: string;
  commands: string;
  result: string;
  detail: string;
}

export interface AuditListFilter {
  q?: string;
  type?: string;
  limit?: number;
}

export interface AuditListResult {
  ok: boolean;
  entries: AuditEntry[];
}

// ============================================================================
// Spec 17: Vault Export & Import (oars.vault.*)
// ============================================================================

export interface VaultExportParams {
  path: string;
  password?: string;
  sections?: string[];
}

export interface VaultExportResult {
  ok: boolean;
  exported: number;
  sections: number;
}

export interface VaultConflict {
  key: string;
  reason: string;
}

export interface VaultSectionReport {
  name: string;
  incoming: number;
  new: number;
  updated: number;
  conflicts: VaultConflict[];
}

export interface VaultPreview {
  reports: VaultSectionReport[];
  errors: VaultConflict[];
}

export interface VaultImportParams {
  path: string;
  password?: string;
}

export interface VaultImportResult {
  ok: boolean;
  preview: VaultPreview;
}

export interface VaultImportConfirmParams {
  path: string;
  password?: string;
  keep_local?: string[];
  import_as_new?: string[];
}

export interface VaultImportConfirmResult {
  ok: boolean;
  result: {
    notes: string[];
  };
}

// ============================================================================
// Spec 18: SSH Agent (oars.agent.*)
// ============================================================================

export interface AgentIdentity {
  kind: string;
  fingerprint_sha256: string;
  comment: string;
}

export interface AgentListResult {
  ok: boolean;
  identities: AgentIdentity[];
  error?: string;
}
