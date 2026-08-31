import { useEffect, useMemo, useRef, useSyncExternalStore } from "react";
import { api, BridgeError, vault } from "./bridge";
import type {
  BackupCredentials,
  BackupDeletePlanResult,
  BackupErrorCode,
  BackupFailure,
  BackupFailureDetail,
  BackupHistoryLogResult,
  BackupInstallPlanResult,
  BackupInstallTarget,
  BackupJob,
  BackupJobDraft,
  BackupOperation,
  BackupOperationAdmission,
  BackupPlanResult,
  BackupPollResult,
  BackupRunStatus,
  BackupSaveAdmission,
  BackupServerStatus,
  BackupTestPlanResult,
} from "./types";

export type BackupErrorScope =
  | "jobs"
  | "status"
  | "refresh"
  | "mutation"
  | "run"
  | "history"
  | "history_log"
  | "credentials";

export interface BackupUiError {
  scope: BackupErrorScope;
  message: string;
  retryable: boolean;
  code?: BackupErrorCode;
  detail?: BackupFailureDetail;
}

export interface BackupHistoryState {
  runs: import("./types").BackupRunSummary[];
  loading: boolean;
  loaded: boolean;
  error: BackupUiError | null;
}

export interface BackupHistoryLogState {
  text: string;
  cursor: number;
  eof: boolean;
  dropped: number;
  loading: boolean;
  error: BackupUiError | null;
}

export interface BackupRunState {
  runId: string;
  jobId: string;
  snapshot: BackupPollResult | null;
  log: string;
  cursor: number;
  active: boolean;
  cancelRequested: boolean;
  error: BackupUiError | null;
}

export interface BackupControllerState {
  serverId: string;
  connected: boolean;
  jobs: BackupJob[];
  jobsLoading: boolean;
  jobsLoaded: boolean;
  status: BackupServerStatus | null;
  statusStale: boolean;
  statusLoading: boolean;
  refreshing: boolean;
  refreshOperation: BackupOperation | null;
  mutationOperation: BackupOperation | null;
  run: BackupRunState | null;
  histories: Readonly<Record<string, BackupHistoryState>>;
  historyLogs: Readonly<Record<string, BackupHistoryLogState>>;
  errors: Readonly<Partial<Record<BackupErrorScope, BackupUiError>>>;
}

export interface BackupMutationTask {
  operationId: string;
  completion: Promise<BackupOperation>;
}

export interface BackupRunTask {
  runId: string;
}

export interface BackupCredentialStore {
  backupTransientGet(account: string): Promise<string | null>;
  backupSet(account: string, secret: string): Promise<void>;
  backupDelete(account: string): Promise<void>;
}

export type BackupCredentialErrorCode = "missing" | "invalid" | "locked";

export class BackupCredentialError extends Error {
  readonly code: BackupCredentialErrorCode;

  constructor(code: BackupCredentialErrorCode, message: string) {
    super(message);
    this.name = "BackupCredentialError";
    this.code = code;
  }
}

export class BackupOperationError extends Error {
  readonly operation: BackupOperation;

  constructor(operation: BackupOperation) {
    super(operation.error?.error ?? `The ${operation.kind} operation ended as ${operation.state}.`);
    this.name = "BackupOperationError";
    this.operation = operation;
  }
}

export function backupCredentialAccount(jobId: string): string {
  return `backup:${jobId}`;
}

export function backupPendingCredentialAccount(jobId: string, planId: string): string {
  return `backup-pending:${jobId}:${planId}`;
}

function objectProperty(value: unknown, key: string): unknown {
  if (typeof value !== "object" || value === null) return undefined;
  return Reflect.get(value, key);
}

export function parseBackupCredentials(raw: string): BackupCredentials {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error: unknown) {
    const detail = error instanceof Error ? ` ${error.message}` : "";
    throw new BackupCredentialError("invalid", `The saved backup credentials are unreadable.${detail}`);
  }
  const accessKey = objectProperty(parsed, "access_key");
  const secretKey = objectProperty(parsed, "secret_key");
  if (typeof accessKey !== "string" || typeof secretKey !== "string" || accessKey.trim() === "" || secretKey.trim() === "") {
    throw new BackupCredentialError("invalid", "The saved backup credentials are incomplete. Enter both keys again.");
  }
  return { access_key: accessKey, secret_key: secretKey };
}

export function serializeBackupCredentials(credentials: BackupCredentials): string {
  return JSON.stringify(credentials);
}

export function credentialsFromFields(accessKey: string, secretKey: string): BackupCredentials {
  if (accessKey.trim() === "" || secretKey.trim() === "") {
    throw new BackupCredentialError("missing", "Enter both the access key and secret key.");
  }
  return { access_key: accessKey, secret_key: secretKey };
}

export async function loadBackupCredentialsAccount(
  account: string,
  store: BackupCredentialStore = vault,
): Promise<BackupCredentials> {
  let raw: string | null;
  try {
    raw = await store.backupTransientGet(account);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "The system credential store could not be opened.";
    throw new BackupCredentialError("locked", `Unlock Keychain and try again. ${message}`);
  }
  if (raw === null) {
    throw new BackupCredentialError("missing", "No saved credentials were found. Enter both keys to continue.");
  }
  return parseBackupCredentials(raw);
}

export function loadBackupCredentials(
  jobId: string,
  store: BackupCredentialStore = vault,
): Promise<BackupCredentials> {
  return loadBackupCredentialsAccount(backupCredentialAccount(jobId), store);
}

const BACKUP_ERROR_CODES: readonly BackupErrorCode[] = [
  "invalid_payload", "invalid_job", "invalid_credentials",
  "not_connected", "session_not_ready", "unsupported_target",
  "rclone_missing", "cron_missing", "cron_stopped",
  "source_missing", "source_unreadable", "source_too_large",
  "plan_expired", "conflict", "busy", "not_found",
  "permission_denied", "timeout", "transport_error",
  "capability_failed", "cleanup_failed", "store_corrupt",
  "canceled", "interrupted", "internal",
];

function isBackupErrorCode(value: string): value is BackupErrorCode {
  return BACKUP_ERROR_CODES.some((code) => code === value);
}

function humanMessage(code: BackupErrorCode | undefined, backendMessage: string): string {
  switch (code) {
    case "not_connected":
    case "session_not_ready":
      return "Connect to this server, then try again.";
    case "invalid_credentials":
      return "The storage credentials were not accepted. Check both keys and test the connection again.";
    case "plan_expired":
      return "This review expired. Review the latest changes before continuing.";
    case "conflict":
      return "This backup job changed elsewhere. Refresh it before trying again.";
    case "busy":
      return "Another backup operation is already running on this server. Wait for it to finish.";
    case "rclone_missing":
      return "Rclone is not installed on this server. Review an installation plan first.";
    case "cron_missing":
      return "Cron is not installed on this server. Review an installation plan before enabling a schedule.";
    case "cron_stopped":
      return "Cron is installed but stopped. Review the start plan before enabling a schedule.";
    case "source_missing":
      return "The source path no longer exists on the server.";
    case "source_unreadable":
    case "permission_denied":
      return "Oars cannot read the source or destination with the current server permissions.";
    case "source_too_large":
      return "The source is larger than this operation allows.";
    case "capability_failed":
      return "The connection test did not prove all required storage operations. Review the failed check.";
    case "cleanup_failed":
      return "Cleanup needs attention. Review the exact leftover path before continuing.";
    case "store_corrupt":
      return "Local backup records could not be read safely. The last good view is still shown.";
    case "timeout":
      return "The backup request timed out. The last confirmed state is still shown.";
    case "transport_error":
      return "The connection was interrupted. The last confirmed state is still shown.";
    case "canceled":
      return "The operation was canceled after cleanup finished.";
    case "interrupted":
      return "The operation was interrupted before completion. Review cleanup state before retrying.";
    case "unsupported_target":
      return "This server or destination is not supported for this operation.";
    case "invalid_payload":
    case "invalid_job":
      return `Review the backup details and try again. ${backendMessage}`;
    case "not_found":
      return "This backup record is no longer available. Refresh the server view.";
    case "internal":
      return `Oars could not complete the backup operation. ${backendMessage}`;
    default:
      return backendMessage || "The backup request could not be completed.";
  }
}

function humanizeBackupFailure(failure: BackupFailure, scope: BackupErrorScope): BackupUiError {
  return {
    scope,
    message: humanMessage(failure.code, failure.error),
    retryable: failure.retryable,
    code: failure.code,
    ...(failure.detail === undefined ? {} : { detail: failure.detail }),
  };
}

export function humanizeBackupError(error: unknown, scope: BackupErrorScope): BackupUiError {
  if (error instanceof BackupCredentialError) {
    return { scope: "credentials", message: error.message, retryable: true };
  }
  if (error instanceof BackupOperationError) {
    const failure = error.operation.error;
    return {
      scope,
      message: humanMessage(failure?.code, failure?.error ?? error.message),
      retryable: failure?.retryable ?? false,
      ...(failure === undefined ? {} : { code: failure.code }),
      ...(failure?.detail === undefined ? {} : { detail: failure.detail }),
    };
  }
  if (error instanceof BridgeError) {
    const code = isBackupErrorCode(error.code) ? error.code : undefined;
    return {
      scope,
      message: humanMessage(code, error.message),
      retryable: error.retryable,
      ...(code === undefined ? {} : { code }),
      ...(error.detail === undefined ? {} : { detail: error.detail }),
    };
  }
  const message = error instanceof Error ? error.message : "The backup request could not be completed.";
  return { scope, message, retryable: false };
}

export function isBackupOperationTerminal(operation: BackupOperation): boolean {
  return operation.state === "done" || operation.state === "partial" || operation.state === "failed" || operation.state === "canceled";
}

export function isBackupRunTerminal(status: BackupRunStatus): boolean {
  return status === "success" || status === "no_changes" || status === "failed" || status === "canceled" || status === "interrupted" || status === "partial" || status === "skipped_overlap";
}

export function createBackupOperationId(): string {
  if (typeof globalThis.crypto?.randomUUID !== "function") {
    throw new BridgeError<BackupErrorCode>("internal", "Secure operation IDs are unavailable in this environment.");
  }
  return globalThis.crypto.randomUUID();
}

export type BackupBridge = typeof api.backup;

type TimerName = "refresh" | "mutation" | "run";
type TimerHandle = ReturnType<typeof setTimeout>;
type Listener = () => void;

interface PendingMutation {
  operationId: string;
  generation: number;
  resolve: (operation: BackupOperation) => void;
  reject: (error: Error) => void;
}

const EMPTY_STATE = (serverId: string, connected: boolean): BackupControllerState => ({
  serverId,
  connected,
  jobs: [],
  jobsLoading: true,
  jobsLoaded: false,
  status: null,
  statusStale: true,
  statusLoading: true,
  refreshing: false,
  refreshOperation: null,
  mutationOperation: null,
  run: null,
  histories: {},
  historyLogs: {},
  errors: {},
});

export class BackupController {
  private state: BackupControllerState;
  private readonly listeners = new Set<Listener>();
  private readonly bridge: BackupBridge;
  private readonly operationId: () => string;
  private generation = 0;
  private abortController = new AbortController();
  private disposed = false;
  private started = false;
  private timers: Partial<Record<TimerName, TimerHandle>> = {};
  private refreshOperationId: string | null = null;
  private pendingMutation: PendingMutation | null = null;
  private readonly reconciledOperations = new Set<string>();
  private readonly reconciledRuns = new Set<string>();

  constructor(
    serverId: string,
    connected: boolean,
    bridge: BackupBridge = api.backup,
    operationId: () => string = createBackupOperationId,
  ) {
    this.state = EMPTY_STATE(serverId, connected);
    this.bridge = bridge;
    this.operationId = operationId;
  }

  getSnapshot = (): BackupControllerState => this.state;

  subscribe = (listener: Listener): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  start(): void {
    if (this.started || this.disposed) return;
    this.started = true;
    const generation = this.generation;
    void this.loadLocal(generation).then(() => {
      if (this.isCurrent(generation) && this.state.connected) void this.refresh();
    });
  }

  setContext(serverId: string, connected: boolean): void {
    if (this.disposed) return;
    if (serverId !== this.state.serverId) {
      this.invalidateAsyncWork("The backup view changed servers.");
      this.generation += 1;
      this.abortController = new AbortController();
      this.refreshOperationId = null;
      this.state = EMPTY_STATE(serverId, connected);
      this.emit();
      void this.loadLocal(this.generation).then(() => {
        if (this.isCurrent(this.generation) && this.state.connected) void this.refresh();
      });
      return;
    }
    this.setConnected(connected);
  }

  setConnected(connected: boolean): void {
    if (this.disposed || connected === this.state.connected) return;
    this.patch({ connected });
    if (!connected) {
      this.abortController.abort();
      this.abortController = new AbortController();
      this.generation += 1;
      this.clearAllTimers();
      if (this.pendingMutation !== null) this.pendingMutation.generation = this.generation;
      return;
    }
    if (!this.started) return;
    if (this.pendingMutation !== null) {
      this.pendingMutation.generation = this.generation;
      void this.pollMutation(this.pendingMutation.operationId, this.generation);
    }
    if (this.refreshOperationId !== null) void this.pollRefresh(this.refreshOperationId, this.generation);
    if (this.state.run?.active) void this.pollRun(this.state.run.runId, this.generation);
    void this.refresh();
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.abortController.abort();
    this.generation += 1;
    this.clearAllTimers();
    if (this.pendingMutation !== null) {
      this.pendingMutation.reject(new Error("The backup view closed before the operation finished."));
      this.pendingMutation = null;
    }
    this.listeners.clear();
  }

  clearError(scope: BackupErrorScope): void {
    if (this.state.errors[scope] === undefined) return;
    const errors = { ...this.state.errors };
    delete errors[scope];
    this.patch({ errors });
  }

  reportError(scope: BackupErrorScope, error: unknown): BackupUiError {
    const mapped = humanizeBackupError(error, scope);
    this.setError(mapped);
    return mapped;
  }

  async reload(): Promise<void> {
    const generation = this.generation;
    await this.loadLocal(generation);
  }

  async refresh(): Promise<void> {
    if (this.disposed || !this.state.connected || this.refreshOperationId !== null) return;
    const generation = this.generation;
    try {
      const admission = await this.bridge.refresh({ operation_id: this.operationId(), server_id: this.state.serverId });
      if (typeof admission.operation_id !== "string" || admission.operation_id === "") {
        throw new BridgeError<BackupErrorCode>("invalid_payload", "The refresh admission did not include an operation ID.");
      }
      if (!this.isCurrent(generation)) return;
      this.refreshOperationId = admission.operation_id;
      this.clearError("refresh");
      this.patch({ refreshing: true });
      await this.pollRefresh(admission.operation_id, generation);
    } catch (error: unknown) {
      if (!this.isCurrent(generation)) return;
      this.patch({ refreshing: false });
      this.setError(humanizeBackupError(error, "refresh"));
    }
  }

  planJob(job: BackupJobDraft, expectedRevision?: number): Promise<BackupPlanResult> {
    return this.bridge.jobsPlan({
      job,
      ...(expectedRevision === undefined ? {} : { expected_revision: expectedRevision }),
    });
  }

  planDelete(job: BackupJob): Promise<BackupDeletePlanResult> {
    return this.bridge.deletePlan({
      server_id: this.state.serverId,
      job_id: job.id,
      expected_revision: job.revision,
    });
  }

  planTest(jobPlanId: string): Promise<BackupTestPlanResult> {
    return this.bridge.testPlan({ job_plan_id: jobPlanId });
  }

  planInstall(what: BackupInstallTarget): Promise<BackupInstallPlanResult> {
    return this.bridge.installPlan({ server_id: this.state.serverId, what });
  }

  beginSave(payload: {
    planId: string;
    capabilityProofId?: string;
    scheduleCredentials?: BackupCredentials;
    approvedRemoteSecret: boolean;
    confirmJobName?: string;
  }): Promise<BackupMutationTask> {
    const operationId = this.operationId();
    return this.admitMutation(
      operationId,
      () => this.bridge.jobsSave({
        operation_id: operationId,
        plan_id: payload.planId,
        ...(payload.capabilityProofId === undefined ? {} : { capability_proof_id: payload.capabilityProofId }),
        ...(payload.scheduleCredentials === undefined ? {} : { schedule_credentials: payload.scheduleCredentials }),
        approved_remote_secret: payload.approvedRemoteSecret,
        ...(payload.confirmJobName === undefined ? {} : { confirm_job_name: payload.confirmJobName }),
      }),
    );
  }

  beginDelete(planId: string, confirmJobName: string): Promise<BackupMutationTask> {
    const operationId = this.operationId();
    return this.admitMutation(
      operationId,
      () => this.bridge.delete({ operation_id: operationId, plan_id: planId, confirm_job_name: confirmJobName }),
    );
  }

  beginTest(testPlanId: string, credentials?: BackupCredentials): Promise<BackupMutationTask> {
    const operationId = this.operationId();
    return this.admitMutation(
      operationId,
      () => this.bridge.test({
        operation_id: operationId,
        test_plan_id: testPlanId,
        ...(credentials === undefined ? {} : { credentials }),
      }),
    );
  }

  beginInstall(planId: string): Promise<BackupMutationTask> {
    const operationId = this.operationId();
    return this.admitMutation(
      operationId,
      () => this.bridge.install({ operation_id: operationId, plan_id: planId }),
    );
  }

  async cancelMutation(): Promise<void> {
    const operationId = this.pendingMutation?.operationId;
    if (operationId === undefined) return;
    try {
      await this.bridge.operationCancel({ operation_id: operationId });
      this.clearError("mutation");
    } catch (error: unknown) {
      this.setError(humanizeBackupError(error, "mutation"));
      throw error;
    }
  }

  async retryCleanup(operationId: string, credentials?: BackupCredentials): Promise<BackupMutationTask> {
    this.requireConnected();
    const operation = this.state.mutationOperation;
    if (operation?.operation_id !== operationId || operation.state !== "partial") {
      throw new BridgeError<BackupErrorCode>("invalid_payload", "Only a retained partial operation can retry cleanup.");
    }
    if (this.pendingMutation !== null) {
      throw new BridgeError<BackupErrorCode>("busy", "Another backup change is already active.", true);
    }
    const generation = this.generation;
    await this.bridge.operationCancel({
      operation_id: operationId,
      ...(credentials === undefined ? {} : { credentials }),
    });
    if (!this.isCurrent(generation)) throw new Error("The server changed before cleanup was admitted.");
    return this.trackMutation(operationId, generation);
  }

  async beginRun(
    job: BackupJob,
    credentials?: BackupCredentials,
    confirmJobName?: string,
  ): Promise<BackupRunTask> {
    this.requireConnected();
    if (this.state.run?.active) {
      throw new BridgeError<BackupErrorCode>("busy", "A backup run is already active in this view.", true);
    }
    const generation = this.generation;
    const admission = await this.bridge.run({
      operation_id: this.operationId(),
      server_id: this.state.serverId,
      job_id: job.id,
      expected_revision: job.revision,
      ...(credentials === undefined ? {} : { credentials }),
      ...(confirmJobName === undefined ? {} : { confirm_job_name: confirmJobName }),
    });
    if (!this.isCurrent(generation)) throw new Error("The server changed before the run was admitted.");
    const run: BackupRunState = {
      runId: admission.run_id,
      jobId: job.id,
      snapshot: null,
      log: "",
      cursor: 0,
      active: true,
      cancelRequested: false,
      error: null,
    };
    this.clearError("run");
    this.patch({ run });
    void this.pollRun(admission.run_id, generation);
    return { runId: admission.run_id };
  }

  async cancelRun(): Promise<void> {
    const run = this.state.run;
    if (run === null || !run.active) return;
    try {
      await this.bridge.cancel({ run_id: run.runId });
      if (this.state.run?.runId === run.runId) {
        this.patch({ run: { ...this.state.run, cancelRequested: true } });
      }
      this.clearError("run");
    } catch (error: unknown) {
      this.setError(humanizeBackupError(error, "run"));
      throw error;
    }
  }

  async retryRunCleanup(): Promise<void> {
    const run = this.state.run;
    if (run === null || run.active || run.snapshot?.cleanup_state !== "failed") return;
    const generation = this.generation;
    await this.bridge.cancel({ run_id: run.runId });
    if (!this.isCurrent(generation) || this.state.run?.runId !== run.runId) return;
    this.reconciledRuns.delete(run.runId);
    this.clearError("run");
    this.patch({ run: { ...this.state.run, active: true, cancelRequested: false, error: null } });
    void this.pollRun(run.runId, generation);
  }

  async loadHistory(jobId: string): Promise<void> {
    const generation = this.generation;
    const previous = this.state.histories[jobId] ?? { runs: [], loading: false, loaded: false, error: null };
    this.setHistory(jobId, { ...previous, loading: true, error: null });
    try {
      const result = await this.bridge.history({ server_id: this.state.serverId, job_id: jobId, limit: 20 });
      if (!this.isCurrent(generation)) return;
      const recoveryError: BackupUiError | null = result.recovery_error === undefined ? null : {
        scope: "history",
        message: `Some local backup history needs attention. ${result.recovery_error}`,
        retryable: false,
        code: "store_corrupt",
      };
      this.setHistory(jobId, { runs: result.runs, loading: false, loaded: true, error: recoveryError });
      if (recoveryError === null) this.clearError("history");
      else this.setError(recoveryError);
    } catch (error: unknown) {
      if (!this.isCurrent(generation)) return;
      const mapped = humanizeBackupError(error, "history");
      this.setHistory(jobId, { ...previous, loading: false, error: mapped });
      this.setError(mapped);
    }
  }

  async loadHistoryLog(runId: string, max = 32 * 1024): Promise<BackupHistoryLogResult | null> {
    const generation = this.generation;
    const previous = this.state.historyLogs[runId] ?? {
      text: "",
      cursor: 0,
      eof: false,
      dropped: 0,
      loading: false,
      error: null,
    };
    if (previous.loading || previous.eof) return null;
    this.setHistoryLog(runId, { ...previous, loading: true, error: null });
    try {
      const result = await this.bridge.historyLog({
        server_id: this.state.serverId,
        run_id: runId,
        cursor: previous.cursor,
        max,
      });
      if (!this.isCurrent(generation)) return null;
      this.setHistoryLog(runId, {
        text: previous.text + result.delta,
        cursor: result.cursor,
        eof: result.eof,
        dropped: previous.dropped + result.dropped,
        loading: false,
        error: null,
      });
      this.clearError("history_log");
      return result;
    } catch (error: unknown) {
      if (!this.isCurrent(generation)) return null;
      const mapped = humanizeBackupError(error, "history_log");
      this.setHistoryLog(runId, { ...previous, loading: false, error: mapped });
      this.setError(mapped);
      return null;
    }
  }

  private async loadLocal(generation: number): Promise<void> {
    await Promise.all([this.loadJobs(generation), this.loadStatus(generation)]);
  }

  private async loadJobs(generation: number): Promise<void> {
    this.patch({ jobsLoading: true });
    try {
      const result = await this.bridge.list({ server_id: this.state.serverId });
      if (!this.isCurrent(generation)) return;
      this.patch({ jobs: result.jobs, jobsLoading: false, jobsLoaded: true });
      if (result.recovery_error !== undefined) {
        this.setError({
          scope: "jobs",
          message: `Some local backup records need attention. ${result.recovery_error}`,
          retryable: false,
          code: "store_corrupt",
        });
      } else {
        this.clearError("jobs");
      }
      await Promise.all(result.jobs.map((job) => this.loadHistory(job.id)));
    } catch (error: unknown) {
      if (!this.isCurrent(generation)) return;
      this.patch({ jobsLoading: false, jobsLoaded: true });
      this.setError(humanizeBackupError(error, "jobs"));
    }
  }

  private async loadStatus(generation: number): Promise<void> {
    this.patch({ statusLoading: true });
    try {
      const result = await this.bridge.status({ server_id: this.state.serverId });
      if (result.status === undefined || typeof result.stale !== "boolean") {
        throw new BridgeError<BackupErrorCode>("invalid_payload", "The runtime status response was incomplete.");
      }
      if (!this.isCurrent(generation)) return;
      this.patch({ status: result.status, statusStale: result.stale, statusLoading: false });
      if (result.recovery_error === undefined) {
        this.clearError("status");
      } else {
        this.setError({
          scope: "status",
          message: `Some local backup state needs attention. ${result.recovery_error}`,
          retryable: false,
          code: "store_corrupt",
        });
      }
    } catch (error: unknown) {
      if (!this.isCurrent(generation)) return;
      this.patch({ statusLoading: false, statusStale: true });
      this.setError(humanizeBackupError(error, "status"));
    }
  }

  private async pollRefresh(operationId: string, generation: number): Promise<void> {
    if (!this.isCurrent(generation) || !this.state.connected) return;
    this.clearTimer("refresh");
    try {
      const operation = await this.bridge.operationPoll({ operation_id: operationId });
      if (!this.isCurrent(generation) || this.refreshOperationId !== operationId) return;
      this.patch({ refreshOperation: operation, refreshing: !isBackupOperationTerminal(operation) });
      this.clearError("refresh");
      if (!isBackupOperationTerminal(operation)) {
        this.schedule("refresh", () => this.pollRefresh(operationId, generation), 700);
        return;
      }
      this.refreshOperationId = null;
      if (operation.state === "done" || operation.state === "partial") {
        await this.reconcileOperation(operation, generation);
      }
      if (operation.state !== "done") this.setError(humanizeBackupError(new BackupOperationError(operation), "refresh"));
    } catch (error: unknown) {
      if (!this.isCurrent(generation) || this.refreshOperationId !== operationId) return;
      const mapped = humanizeBackupError(error, "refresh");
      this.setError(mapped);
      if (mapped.retryable) {
        this.patch({ refreshing: true });
        this.schedule("refresh", () => this.pollRefresh(operationId, generation), 1_200);
        return;
      }
      this.refreshOperationId = null;
      this.clearTimer("refresh");
      this.patch({ refreshing: false });
    }
  }

  private async admitMutation(
    operationId: string,
    admit: () => Promise<BackupOperationAdmission | BackupSaveAdmission>,
  ): Promise<BackupMutationTask> {
    this.requireConnected();
    if (this.pendingMutation !== null) {
      throw new BridgeError<BackupErrorCode>("busy", "Another backup change is already active.", true);
    }
    const generation = this.generation;
    const admission = await admit();
    if (!this.isCurrent(generation)) throw new Error("The server changed before the operation was admitted.");
    return this.trackMutation(admission.operation_id, generation);
  }

  private trackMutation(operationId: string, generation: number): BackupMutationTask {
    let resolveCompletion: (operation: BackupOperation) => void = () => undefined;
    let rejectCompletion: (error: Error) => void = () => undefined;
    const completion = new Promise<BackupOperation>((resolve, reject) => {
      resolveCompletion = resolve;
      rejectCompletion = reject;
    });
    this.pendingMutation = {
      operationId,
      generation,
      resolve: resolveCompletion,
      reject: rejectCompletion,
    };
    this.clearError("mutation");
    this.patch({ mutationOperation: null });
    void this.pollMutation(operationId, generation);
    return { operationId, completion };
  }

  private async pollMutation(operationId: string, generation: number): Promise<void> {
    if (!this.isCurrent(generation) || !this.state.connected) return;
    this.clearTimer("mutation");
    try {
      const operation = await this.bridge.operationPoll({ operation_id: operationId });
      if (!this.isCurrent(generation) || this.pendingMutation?.operationId !== operationId) return;
      this.patch({ mutationOperation: operation });
      this.clearError("mutation");
      if (!isBackupOperationTerminal(operation)) {
        this.schedule("mutation", () => this.pollMutation(operationId, generation), 700);
        return;
      }
      const pending = this.pendingMutation;
      this.pendingMutation = null;
      if (operation.state === "done" || operation.state === "partial") {
        await this.reconcileOperation(operation, generation);
      }
      if (operation.state === "done") {
        pending.resolve(operation);
      } else {
        const operationError = new BackupOperationError(operation);
        this.setError(humanizeBackupError(operationError, "mutation"));
        pending.reject(operationError);
      }
    } catch (error: unknown) {
      if (!this.isCurrent(generation) || this.pendingMutation?.operationId !== operationId) return;
      const mapped = humanizeBackupError(error, "mutation");
      this.setError(mapped);
      if (mapped.retryable) {
        this.schedule("mutation", () => this.pollMutation(operationId, generation), 1_200);
        return;
      }
      const pending = this.pendingMutation;
      this.pendingMutation = null;
      this.clearTimer("mutation");
      pending.reject(error instanceof Error ? error : new Error(mapped.message));
    }
  }

  private async pollRun(runId: string, generation: number): Promise<void> {
    if (!this.isCurrent(generation) || !this.state.connected || this.state.run?.runId !== runId) return;
    this.clearTimer("run");
    const previous = this.state.run;
    try {
      const snapshot = await this.bridge.poll({ run_id: runId, log_cursor: previous.cursor });
      if (!this.isCurrent(generation) || this.state.run?.runId !== runId) return;
      const run: BackupRunState = {
        ...this.state.run,
        snapshot,
        log: this.state.run.log + snapshot.log_delta,
        cursor: snapshot.log_cursor,
        active: !isBackupRunTerminal(snapshot.status),
        error: snapshot.error === undefined ? null : humanizeBackupFailure(snapshot.error, "run"),
      };
      this.patch({ run });
      this.clearError("run");
      if (run.active) {
        this.schedule("run", () => this.pollRun(runId, generation), 700);
        return;
      }
      if (!this.reconciledRuns.has(runId)) {
        this.reconciledRuns.add(runId);
        await this.loadHistory(run.jobId);
      }
    } catch (error: unknown) {
      if (!this.isCurrent(generation) || this.state.run?.runId !== runId) return;
      const mapped = humanizeBackupError(error, "run");
      this.setError(mapped);
      if (mapped.retryable) {
        this.patch({ run: { ...this.state.run, error: mapped } });
        this.schedule("run", () => this.pollRun(runId, generation), 1_200);
        return;
      }
      this.clearTimer("run");
      this.patch({ run: { ...this.state.run, active: false, error: mapped } });
    }
  }

  private async reconcileOperation(operation: BackupOperation, generation: number): Promise<void> {
    if (this.reconciledOperations.has(operation.operation_id)) return;
    this.reconciledOperations.add(operation.operation_id);
    await this.loadLocal(generation);
  }

  private requireConnected(): void {
    if (!this.state.connected) {
      throw new BridgeError<BackupErrorCode>("not_connected", "The selected server is disconnected.", true);
    }
  }

  private setHistory(jobId: string, history: BackupHistoryState): void {
    this.patch({ histories: { ...this.state.histories, [jobId]: history } });
  }

  private setHistoryLog(runId: string, log: BackupHistoryLogState): void {
    this.patch({ historyLogs: { ...this.state.historyLogs, [runId]: log } });
  }

  private setError(error: BackupUiError): void {
    this.patch({ errors: { ...this.state.errors, [error.scope]: error } });
  }

  private patch(patch: Partial<BackupControllerState>): void {
    if (this.disposed) return;
    this.state = { ...this.state, ...patch };
    this.emit();
  }

  private emit(): void {
    for (const listener of this.listeners) listener();
  }

  private isCurrent(generation: number): boolean {
    return !this.disposed && generation === this.generation && !this.abortController.signal.aborted;
  }

  private schedule(name: TimerName, task: () => Promise<void>, delay: number): void {
    this.clearTimer(name);
    this.timers[name] = setTimeout(() => {
      delete this.timers[name];
      void task();
    }, delay);
  }

  private clearTimer(name: TimerName): void {
    const timer = this.timers[name];
    if (timer === undefined) return;
    clearTimeout(timer);
    delete this.timers[name];
  }

  private clearAllTimers(): void {
    this.clearTimer("refresh");
    this.clearTimer("mutation");
    this.clearTimer("run");
  }

  private invalidateAsyncWork(reason: string): void {
    this.abortController.abort();
    this.clearAllTimers();
    if (this.pendingMutation !== null) {
      this.pendingMutation.reject(new Error(reason));
      this.pendingMutation = null;
    }
  }
}

interface SharedBackupController {
  controller: BackupController;
  consumers: Map<symbol, boolean>;
}

const backupControllers = new Map<string, SharedBackupController>();

function sharedBackupController(serverId: string): SharedBackupController {
  const existing = backupControllers.get(serverId);
  if (existing !== undefined) return existing;
  const entry: SharedBackupController = {
    controller: new BackupController(serverId, false),
    consumers: new Map(),
  };
  backupControllers.set(serverId, entry);
  return entry;
}

function syncSharedConnection(entry: SharedBackupController): void {
  entry.controller.setConnected(Array.from(entry.consumers.values()).some(Boolean));
}

export function useBackupState(serverId: string, connected: boolean): {
  controller: BackupController;
  state: BackupControllerState;
} {
  const entry = useMemo(() => sharedBackupController(serverId), [serverId]);
  const consumer = useRef<symbol | null>(null);
  const state = useSyncExternalStore(entry.controller.subscribe, entry.controller.getSnapshot, entry.controller.getSnapshot);

  useEffect(() => {
    const token = Symbol(serverId);
    consumer.current = token;
    entry.consumers.set(token, connected);
    syncSharedConnection(entry);
    entry.controller.start();
    return () => {
      consumer.current = null;
      entry.consumers.delete(token);
      if (entry.consumers.size === 0) {
        entry.controller.dispose();
        if (backupControllers.get(serverId) === entry) backupControllers.delete(serverId);
      } else {
        syncSharedConnection(entry);
      }
    };
  }, [entry, serverId]);

  useEffect(() => {
    const token = consumer.current;
    if (token === null || !entry.consumers.has(token)) return;
    entry.consumers.set(token, connected);
    syncSharedConnection(entry);
  }, [connected, entry]);

  return { controller: entry.controller, state };
}
