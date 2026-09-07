import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Archive,
  CheckCircle2,
  Clock3,
  Cloud,
  HardDrive,
  LoaderCircle,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
  Wrench,
  X,
  XCircle,
} from "lucide-react";
import { Button } from "./components/ui/button";
import { OarsSelect } from "./components/ui/select";
import { OarsLoadingState, OarsRefreshStatus } from "./components/OarsLoadingState";
import { ApplicationOverlay } from "./components/ApplicationPortal";
import { useModalFocus } from "./components/useModalFocus";
import type { BackupPreviewMode } from "./backup-preview";
import { vault } from "./bridge";
import {
  BackupCredentialError,
  BackupOperationError,
  backupCredentialAccount,
  backupPendingCredentialAccount,
  credentialsFromFields,
  humanizeBackupError,
  loadBackupCredentials,
  loadBackupCredentialsAccount,
  serializeBackupCredentials,
  useBackupState,
} from "./backup-state";
import type {
  BackupCapabilityProof,
  BackupCheckName,
  BackupCredentialMode,
  BackupCredentials,
  BackupDeletePlanResult,
  BackupInstallPlanResult,
  BackupInstallTarget,
  BackupIntervalUnit,
  BackupJob,
  BackupJobDraft,
  BackupOperation,
  BackupPlanResult,
  BackupProvider,
  BackupRunStatus,
  BackupSchedule,
  BackupTestPlanResult,
  BackupTransfer,
} from "./types";

const PROVIDERS: readonly { value: BackupProvider; label: string }[] = [
  { value: "aws", label: "AWS S3" },
  { value: "r2", label: "Cloudflare R2" },
  { value: "b2_s3", label: "Backblaze B2 S3" },
  { value: "wasabi", label: "Wasabi" },
  { value: "minio", label: "MinIO" },
  { value: "spaces", label: "DigitalOcean Spaces" },
];

const STORAGE_CLASSES: Record<BackupProvider, readonly { value: string; label: string }[]> = {
  aws: [
    { value: "", label: "Provider default" },
    { value: "STANDARD", label: "Standard" },
    { value: "STANDARD_IA", label: "Standard — infrequent access" },
    { value: "ONEZONE_IA", label: "One Zone — infrequent access" },
    { value: "INTELLIGENT_TIERING", label: "Intelligent-Tiering" },
  ],
  r2: [
    { value: "", label: "Provider default" },
    { value: "STANDARD", label: "Standard" },
    { value: "INFREQUENT_ACCESS", label: "Infrequent access" },
  ],
  b2_s3: [{ value: "", label: "Provider default" }],
  wasabi: [{ value: "", label: "Provider default" }],
  minio: [{ value: "", label: "Provider default" }],
  spaces: [{ value: "", label: "Provider default" }],
};

const PROVIDER_DEFAULTS: Record<BackupProvider, { endpoint: string; region: string; storageClass: string }> = {
  aws: { endpoint: "", region: "us-east-1", storageClass: "" },
  r2: { endpoint: "https://<account-id>.r2.cloudflarestorage.com", region: "auto", storageClass: "" },
  b2_s3: { endpoint: "https://s3.us-west-004.backblazeb2.com", region: "us-west-004", storageClass: "" },
  wasabi: { endpoint: "https://s3.us-east-1.wasabisys.com", region: "us-east-1", storageClass: "" },
  minio: { endpoint: "https://minio.example.com", region: "", storageClass: "" },
  spaces: { endpoint: "https://nyc3.digitaloceanspaces.com", region: "nyc3", storageClass: "" },
};

type ScheduleMode = "manual" | "interval" | "custom";

interface EditorDraft {
  id?: string;
  revision?: number;
  name: string;
  sourcePath: string;
  provider: BackupProvider;
  bucket: string;
  prefix: string;
  endpoint: string;
  region: string;
  credentialMode: BackupCredentialMode;
  storageClass: string;
  transfer: BackupTransfer;
  scheduleMode: ScheduleMode;
  scheduleEnabled: boolean;
  every: number;
  unit: BackupIntervalUnit;
  anchorEpochSec: number;
  expression: string;
  accessKey: string;
  secretKey: string;
}

interface DeleteFlow {
  job: BackupJob;
  plan: BackupDeletePlanResult;
  confirmation: string;
  busy: boolean;
}

interface RunFlow {
  job: BackupJob;
  confirmation: string;
  busy: boolean;
}

interface InstallFlow {
  what: BackupInstallTarget;
  plan: BackupInstallPlanResult;
  busy: boolean;
}

interface TestResultState {
  plan: BackupTestPlanResult;
  operation: BackupOperation | null;
  busy: boolean;
  cancelRequested: boolean;
}

type CredentialRecovery =
  | {
      kind: "promote_pending";
      jobId: string;
      account: string;
      pendingAccount: string;
      busy: boolean;
      message: string;
    }
  | {
      kind: "remove_pending" | "remove_obsolete" | "remove_deleted";
      jobId: string;
      account: string;
      busy: boolean;
      message: string;
    };

const CHECK_LABELS: Record<BackupCheckName, string> = {
  list: "List the selected prefix",
  write: "Write a unique sentinel",
  read: "Read and verify its content",
  delete: "Delete the exact sentinel",
  cleanup_verify: "Verify the sentinel is gone",
};

function isProvider(value: string): value is BackupProvider {
  return value === "aws" || value === "r2" || value === "b2_s3" || value === "wasabi" || value === "minio" || value === "spaces";
}

function isCredentialMode(value: string): value is BackupCredentialMode {
  return value === "access_key" || value === "aws_runtime";
}

function isTransfer(value: string): value is BackupTransfer {
  return value === "copy" || value === "sync";
}

function isScheduleMode(value: string): value is ScheduleMode {
  return value === "manual" || value === "interval" || value === "custom";
}

function isIntervalUnit(value: string): value is BackupIntervalUnit {
  return value === "hours" || value === "days";
}

function emptyDraft(): EditorDraft {
  return {
    name: "",
    sourcePath: "/var/www",
    provider: "aws",
    bucket: "",
    prefix: "",
    endpoint: PROVIDER_DEFAULTS.aws.endpoint,
    region: PROVIDER_DEFAULTS.aws.region,
    credentialMode: "access_key",
    storageClass: PROVIDER_DEFAULTS.aws.storageClass,
    transfer: "copy",
    scheduleMode: "manual",
    scheduleEnabled: false,
    every: 24,
    unit: "hours",
    anchorEpochSec: Math.floor(Date.now() / 1_000),
    expression: "0 2 * * *",
    accessKey: "",
    secretKey: "",
  };
}

function previewDraft(mode: BackupPreviewMode): EditorDraft {
  const draft = emptyDraft();
  const common = {
    ...draft,
    name: "Documents backup",
    sourcePath: "/home/deploy/documents",
    bucket: "oars-preview-backups",
    prefix: "production/documents",
    anchorEpochSec: 1_786_147_200,
  };
  if (mode === "editor-r2") {
    return {
      ...common,
      name: "R2 documents backup",
      provider: "r2",
      endpoint: "https://r2.preview.invalid",
      region: "auto",
      storageClass: "",
    };
  }
  if (mode === "editor-minio-http-warning") {
    return {
      ...common,
      name: "MinIO documents backup",
      provider: "minio",
      endpoint: "http://minio.preview.invalid:9000",
      region: "",
      storageClass: "",
    };
  }
  if (mode === "editor-aws-iam" || mode === "schedule-conflict") {
    return {
      ...common,
      name: mode === "schedule-conflict" ? "Scheduled documents backup" : "AWS runtime backup",
      credentialMode: "aws_runtime",
      ...(mode === "schedule-conflict"
        ? { scheduleMode: "interval" as const, scheduleEnabled: true }
        : {}),
    };
  }
  if (mode === "schedule-secret-disclosure") {
    return {
      ...common,
      name: "Scheduled documents backup",
      scheduleMode: "interval",
      scheduleEnabled: true,
    };
  }
  if (mode === "editor-aws-key") return { ...common, name: "AWS access-key backup" };
  return common;
}

function jobToDraft(job: BackupJob): EditorDraft {
  const schedule = job.schedule;
  return {
    id: job.id,
    revision: job.revision,
    name: job.name,
    sourcePath: job.source_path,
    provider: job.destination.provider,
    bucket: job.destination.bucket,
    prefix: job.destination.prefix,
    endpoint: job.destination.endpoint,
    region: job.destination.region,
    credentialMode: job.destination.credential_mode,
    storageClass: job.destination.storage_class,
    transfer: job.transfer,
    scheduleMode: schedule.mode,
    scheduleEnabled: schedule.enabled,
    every: schedule.mode === "interval" ? schedule.every : 24,
    unit: schedule.mode === "interval" ? schedule.unit : "hours",
    anchorEpochSec: schedule.mode === "interval" ? schedule.anchor_epoch_sec : Math.floor(Date.now() / 1_000),
    expression: schedule.mode === "custom" ? schedule.expr : "0 2 * * *",
    accessKey: "",
    secretKey: "",
  };
}

function clearSecrets(draft: EditorDraft): EditorDraft {
  return { ...draft, accessKey: "", secretKey: "" };
}

function zeroCredentials(credentials: BackupCredentials | undefined): void {
  if (credentials === undefined) return;
  credentials.access_key = "";
  credentials.secret_key = "";
}

function draftSchedule(draft: EditorDraft): BackupSchedule {
  if (draft.scheduleMode === "manual") return { mode: "manual", enabled: false };
  if (draft.scheduleMode === "interval") {
    return {
      mode: "interval",
      enabled: draft.scheduleEnabled,
      every: draft.every,
      unit: draft.unit,
      anchor_epoch_sec: draft.anchorEpochSec,
    };
  }
  return { mode: "custom", enabled: draft.scheduleEnabled, expr: draft.expression.trim() };
}

function toJobDraft(draft: EditorDraft, serverId: string): BackupJobDraft {
  return {
    ...(draft.id === undefined ? {} : { id: draft.id }),
    server_id: serverId,
    name: draft.name.trim(),
    source_path: draft.sourcePath.trim(),
    destination: {
      type: "s3",
      provider: draft.provider,
      bucket: draft.bucket.trim(),
      prefix: draft.prefix.trim().replace(/^\/+|\/+$/g, ""),
      endpoint: draft.endpoint.trim(),
      region: draft.provider === "r2" ? "auto" : draft.region.trim(),
      credential_mode: draft.credentialMode,
      storage_class: draft.storageClass,
    },
    transfer: draft.transfer,
    schedule: draftSchedule(draft),
  };
}

function validateDraft(draft: EditorDraft): string | null {
  if (draft.name.trim() === "") return "Enter a job name.";
  if (!draft.sourcePath.trim().startsWith("/")) return "Enter an absolute source path.";
  if (draft.bucket.trim() === "") return "Enter the destination bucket.";
  if (draft.provider !== "aws" && draft.endpoint.trim() === "") return "Enter the S3-compatible endpoint for this provider.";
  if ((draft.provider === "aws" || draft.provider === "wasabi" || draft.provider === "spaces" || draft.provider === "b2_s3") && draft.region.trim() === "") {
    return "Enter the provider region.";
  }
  if (draft.credentialMode === "aws_runtime" && draft.provider !== "aws") return "AWS runtime credentials are available only for AWS S3.";
  if (draft.scheduleMode === "interval") {
    const max = draft.unit === "hours" ? 168 : 365;
    if (!Number.isInteger(draft.every) || draft.every < 1 || draft.every > max) return `Choose an interval from 1 to ${max} ${draft.unit}.`;
  }
  if (draft.scheduleMode === "custom" && draft.expression.trim().split(/\s+/).length !== 5) return "Enter a five-field cron expression.";
  return null;
}

function humanSchedule(schedule: BackupSchedule): string {
  if (schedule.mode === "manual" || !schedule.enabled) return "Manual";
  if (schedule.mode === "interval") return `Every ${schedule.every} ${schedule.unit}`;
  return `Custom · ${schedule.expr}`;
}

function destinationLabel(job: BackupJob): string {
  const prefix = job.destination.prefix === "" ? "" : `/${job.destination.prefix}`;
  return `${job.destination.bucket}${prefix}`;
}

function providerLabel(provider: BackupProvider): string {
  return PROVIDERS.find((item) => item.value === provider)?.label ?? provider;
}

function runStatusLabel(status: BackupRunStatus): string {
  switch (status) {
    case "no_changes": return "No changes";
    case "cancel_requested": return "Cancel requested";
    case "success": return "Completed";
    case "partial": return "Cleanup needs attention";
    case "interrupted": return "Interrupted";
    case "preparing": return "Preparing";
    case "running": return "Running";
    case "queued": return "Queued";
    case "failed": return "Failed";
    case "canceled": return "Canceled";
    case "skipped_overlap": return "Skipped overlap";
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1_024) return `${bytes} B`;
  if (bytes < 1_048_576) return `${(bytes / 1_024).toFixed(1)} KB`;
  if (bytes < 1_073_741_824) return `${(bytes / 1_048_576).toFixed(1)} MB`;
  return `${(bytes / 1_073_741_824).toFixed(1)} GB`;
}

function formatDate(timestamp: number | undefined): string {
  if (timestamp === undefined) return "Still running";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(timestamp));
}

function formatElapsed(startedAtMs: number, finishedAtMs?: number): string {
  const elapsedSeconds = Math.max(0, Math.round(((finishedAtMs ?? Date.now()) - startedAtMs) / 1_000));
  if (elapsedSeconds < 60) return `${elapsedSeconds}s`;
  const minutes = Math.floor(elapsedSeconds / 60);
  const seconds = elapsedSeconds % 60;
  return `${minutes}m ${seconds}s`;
}

function phaseLabel(phase: string): string {
  const normalized = phase.replaceAll("_", " ");
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function cleanupRequirement(operation: BackupOperation): import("./types").BackupCleanupRequiredResult | null {
  const result = operation.result;
  if (result === undefined || !("cleanup" in result) || result.cleanup !== "required") return null;
  return result;
}

function operationLabel(operation: BackupOperation): string {
  const kind = operation.kind === "test" ? "Connection test" : operation.kind === "save" ? "Saving job" : operation.kind === "delete" ? "Deleting job" : operation.kind === "install" ? "Runtime change" : operation.kind === "cleanup" ? "Cleanup" : "Runtime refresh";
  if (operation.state === "queued") return `${kind} is queued`;
  if (operation.state === "running") return `${kind} is in progress`;
  if (operation.state === "done") return `${kind} completed`;
  if (operation.state === "partial") return `${kind} needs cleanup`;
  if (operation.state === "canceled") return `${kind} was canceled`;
  return `${kind} failed`;
}

function presentStatusText(value: string | undefined, fallback: string): string {
  return typeof value === "string" && value.trim() !== "" ? value : fallback;
}

function relevantRuntimeAction(status: import("./types").BackupServerStatus | null, hasSchedules: boolean): BackupInstallTarget | null {
  if (status === null || typeof status.rclone_path !== "string" || status.rclone_path.trim() === "") return "rclone";
  if (hasSchedules && status.cron_installed !== true) return "cron";
  if (hasSchedules && status.cron_running !== true) return "start_cron";
  return null;
}

export function BackupsTab({
  serverId,
  connected = true,
  previewMode = null,
}: {
  serverId: string;
  connected?: boolean;
  previewMode?: BackupPreviewMode | null;
}) {
  const { controller, state } = useBackupState(serverId, connected);
  const [editor, setEditor] = useState<EditorDraft | null>(null);
  const [jobPlan, setJobPlan] = useState<BackupPlanResult | null>(null);
  const [capabilityProof, setCapabilityProof] = useState<BackupCapabilityProof | null>(null);
  const [testResult, setTestResult] = useState<TestResultState | null>(null);
  const [remoteSecretApproved, setRemoteSecretApproved] = useState(false);
  const [syncScheduleConfirmation, setSyncScheduleConfirmation] = useState("");
  const [editorError, setEditorError] = useState<string | null>(null);
  const [editorBusy, setEditorBusy] = useState(false);
  const [deleteFlow, setDeleteFlow] = useState<DeleteFlow | null>(null);
  const [runFlow, setRunFlow] = useState<RunFlow | null>(null);
  const [installFlow, setInstallFlow] = useState<InstallFlow | null>(null);
  const [expandedJobId, setExpandedJobId] = useState<string | null>(null);
  const [openLogId, setOpenLogId] = useState<string | null>(null);
  const [planningAction, setPlanningAction] = useState<string | null>(null);
  const [credentialRecovery, setCredentialRecovery] = useState<CredentialRecovery | null>(null);
  const editorRef = useRef<EditorDraft | null>(null);
  const stagedCredentialAccounts = useRef(new Set<string>());
  const previewStarted = useRef(false);
  const previewMounted = useRef(true);

  useEffect(() => {
    previewMounted.current = true;
    return () => {
      previewMounted.current = false;
    };
  }, []);

  useEffect(() => {
    editorRef.current = editor;
  }, [editor]);

  const removeStagedAccount = useCallback(async (account: string, report = true) => {
    try {
      await vault.backupDelete(account);
      stagedCredentialAccounts.current.delete(account);
    } catch (error: unknown) {
      if (report) controller.reportError("credentials", error);
      else console.error("Could not remove temporary backup credentials", error);
    }
  }, [controller]);

  const cleanupStagedCredentials = useCallback(async (report = true) => {
    const accounts = Array.from(stagedCredentialAccounts.current);
    await Promise.all(accounts.map((account) => removeStagedAccount(account, report)));
  }, [removeStagedAccount]);

  const performCredentialRecovery = useCallback(async (recovery: CredentialRecovery): Promise<boolean> => {
    setCredentialRecovery({ ...recovery, busy: true });
    let credentials: BackupCredentials | undefined;
    try {
      if (recovery.kind === "promote_pending") {
        credentials = await loadBackupCredentialsAccount(recovery.pendingAccount);
        await vault.backupSet(recovery.account, serializeBackupCredentials(credentials));
        try {
          await vault.backupDelete(recovery.pendingAccount);
        } catch (error: unknown) {
          const mapped = humanizeBackupError(error, "credentials");
          setCredentialRecovery({
            kind: "remove_pending",
            jobId: recovery.jobId,
            account: recovery.pendingAccount,
            busy: false,
            message: `The replacement credentials are active, but their retained pending copy still needs removal. ${mapped.message}`,
          });
          return false;
        }
      } else {
        await vault.backupDelete(recovery.account);
      }
      controller.clearError("credentials");
      setCredentialRecovery(null);
      return true;
    } catch (error: unknown) {
      const mapped = humanizeBackupError(error, "credentials");
      const consequence = recovery.kind === "promote_pending"
        ? "The job was saved, but its replacement Keychain credentials are not active yet. The pending copy was retained."
        : recovery.kind === "remove_pending"
          ? "The replacement credentials are active, but their retained pending copy still needs removal."
          : recovery.kind === "remove_deleted"
            ? "The job was deleted, but its Keychain entry is still present."
            : "The job now uses AWS runtime credentials, but its obsolete Keychain entry is still present.";
      setCredentialRecovery({ ...recovery, busy: false, message: `${consequence} ${mapped.message}` });
      return false;
    } finally {
      if (credentials !== undefined) {
        credentials.access_key = "";
        credentials.secret_key = "";
      }
    }
  }, [controller]);

  const resetEditorState = useCallback(() => {
    if (editorRef.current !== null) editorRef.current = clearSecrets(editorRef.current);
    setEditor(null);
    setJobPlan(null);
    setCapabilityProof(null);
    setTestResult(null);
    setRemoteSecretApproved(false);
    setSyncScheduleConfirmation("");
    setEditorError(null);
    setEditorBusy(false);
  }, []);

  const closeEditor = useCallback(() => {
    void cleanupStagedCredentials().finally(resetEditorState);
  }, [cleanupStagedCredentials, resetEditorState]);

  useEffect(() => {
    resetEditorState();
    return () => {
      if (editorRef.current !== null) editorRef.current = clearSecrets(editorRef.current);
      const accounts = Array.from(stagedCredentialAccounts.current);
      stagedCredentialAccounts.current.clear();
      for (const account of accounts) {
        void vault.backupDelete(account).catch((error: unknown) => {
          console.error("Could not remove temporary backup credentials", error);
        });
      }
    };
  }, [resetEditorState, serverId]);

  const scheduledJobs = useMemo(() => state.jobs.some((job) => job.schedule.mode !== "manual" && job.schedule.enabled), [state.jobs]);
  const runtimeAction = relevantRuntimeAction(state.status, scheduledJobs);
  const visibleErrorKeys = new Set<string>();
  const visibleErrors = (["jobs", "status", "refresh", "mutation", "run", "history", "credentials"] as const)
    .map((scope) => state.errors[scope])
    .filter((error): error is import("./backup-state").BackupUiError => error !== undefined
      && !(error.scope === "run" && state.run?.error !== null && state.run?.error !== undefined)
      && !(error.scope === "mutation" && editor !== null && editorError === error.message))
    .filter((error) => {
      const key = error.code === "store_corrupt"
        ? `${error.code}:${error.message.replace(/^Some local backup (?:records need|history needs|state needs) attention\. /, "")}`
        : `${error.scope}:${error.code ?? "unknown"}:${error.message}`;
      if (visibleErrorKeys.has(key)) return false;
      visibleErrorKeys.add(key);
      return true;
    });

  const openCreate = () => {
    void cleanupStagedCredentials(false);
    setEditor(emptyDraft());
    setJobPlan(null);
    setCapabilityProof(null);
    setTestResult(null);
    setEditorError(null);
  };

  const openEdit = (job: BackupJob) => {
    void cleanupStagedCredentials(false);
    setEditor(jobToDraft(job));
    setJobPlan(null);
    setCapabilityProof(job.capability_proof ?? null);
    setTestResult(null);
    setEditorError(null);
  };

  const updateEditor = (next: EditorDraft) => {
    setEditor(next);
    setEditorError(null);
  };

  const handlePlan = async () => {
    if (editor === null) return;
    const validation = validateDraft(editor);
    if (validation !== null) {
      setEditorError(validation);
      return;
    }
    setEditorBusy(true);
    setEditorError(null);
    try {
      const plan = await controller.planJob(toJobDraft(editor, serverId), editor.revision);
      setJobPlan(plan);
      setCapabilityProof(plan.job.capability_proof ?? null);
      setEditor((current) => current === null ? null : clearSecrets(current));
    } catch (error: unknown) {
      setEditorError(humanizeBackupError(error, "mutation").message);
    } finally {
      setEditorBusy(false);
    }
  };

  const revealExistingCredentials = async () => {
    if (editor?.id === undefined) return;
    setEditorBusy(true);
    setEditorError(null);
    let credentials: BackupCredentials | undefined;
    try {
      credentials = await loadBackupCredentials(editor.id);
      const accessKey = credentials.access_key;
      const secretKey = credentials.secret_key;
      setEditor((current) => current === null ? null : { ...current, accessKey, secretKey });
    } catch (error: unknown) {
      setEditorError(humanizeBackupError(error, "credentials").message);
    } finally {
      if (credentials !== undefined) {
        credentials.access_key = "";
        credentials.secret_key = "";
      }
      setEditorBusy(false);
    }
  };

  const credentialSourceForPlan = async (plan: BackupPlanResult): Promise<{ credentials?: BackupCredentials; pendingAccount?: string }> => {
    if (plan.job.destination.credential_mode === "aws_runtime") return {};
    if (editor === null) throw new BackupCredentialError("missing", "Open the job review and enter storage credentials.");
    const hasEnteredCredentials = editor.accessKey !== "" || editor.secretKey !== "";
    if (hasEnteredCredentials) {
      const credentials = credentialsFromFields(editor.accessKey, editor.secretKey);
      try {
        if (editor.id === undefined) {
          const account = backupCredentialAccount(plan.job.id);
          await vault.backupSet(account, serializeBackupCredentials(credentials));
          stagedCredentialAccounts.current.add(account);
          return { credentials };
        }
        const pendingAccount = backupPendingCredentialAccount(plan.job.id, plan.plan_id);
        await vault.backupSet(pendingAccount, serializeBackupCredentials(credentials));
        stagedCredentialAccounts.current.add(pendingAccount);
        return { credentials, pendingAccount };
      } catch (error: unknown) {
        credentials.access_key = "";
        credentials.secret_key = "";
        throw error;
      }
    }
    const pendingAccount = backupPendingCredentialAccount(plan.job.id, plan.plan_id);
    if (stagedCredentialAccounts.current.has(pendingAccount)) {
      return { credentials: await loadBackupCredentialsAccount(pendingAccount), pendingAccount };
    }
    return { credentials: await loadBackupCredentials(plan.job.id) };
  };

  const handlePrepareTest = async () => {
    if (jobPlan === null) return;
    setEditorBusy(true);
    setEditorError(null);
    try {
      const plan = await controller.planTest(jobPlan.plan_id);
      setTestResult({ plan, operation: null, busy: false, cancelRequested: false });
    } catch (error: unknown) {
      setEditorError(humanizeBackupError(error, "mutation").message);
    } finally {
      setEditorBusy(false);
    }
  };

  const handleApproveTest = async () => {
    if (jobPlan === null || testResult === null) return;
    setTestResult({ ...testResult, busy: true, cancelRequested: false });
    setEditorError(null);
    let credentials: BackupCredentials | undefined;
    try {
      const source = await credentialSourceForPlan(jobPlan);
      credentials = source.credentials;
      const task = await controller.beginTest(testResult.plan.test_plan_id, credentials);
      zeroCredentials(credentials);
      setEditor((current) => current === null ? null : clearSecrets(current));
      const operation = await task.completion;
      setTestResult((current) => current === null ? null : { ...current, operation, busy: false });
      if (
        operation.kind === "test"
        && operation.result !== undefined
        && "capability_proof" in operation.result
        && operation.result.capability_proof !== undefined
        && operation.result.leftover_remote_object === undefined
      ) {
        setCapabilityProof(operation.result.capability_proof);
      }
    } catch (error: unknown) {
      const operation = error instanceof BackupOperationError ? error.operation : null;
      setTestResult((current) => current === null ? null : { ...current, operation, busy: false });
      setEditorError(humanizeBackupError(error, "mutation").message);
    } finally {
      zeroCredentials(credentials);
      setEditor((current) => current === null ? null : clearSecrets(current));
    }
  };

  const handleCancelTest = async () => {
    if (testResult?.busy !== true || testResult.cancelRequested) return;
    setEditorBusy(true);
    setEditorError(null);
    try {
      await controller.cancelMutation();
      setTestResult((current) => current === null ? null : { ...current, cancelRequested: true });
    } catch (error: unknown) {
      setEditorError(humanizeBackupError(error, "mutation").message);
    } finally {
      setEditorBusy(false);
    }
  };

  const handleSave = async () => {
    if (jobPlan === null || editor === null) return;
    if (jobPlan.requires_connection_test && capabilityProof === null) {
      setEditorError("Run and pass the connection test before saving this job.");
      return;
    }
    if (jobPlan.requires_remote_secret && !remoteSecretApproved) {
      setEditorError("Acknowledge the remote credential disclosure before saving this scheduled job.");
      return;
    }
    if (jobPlan.job.transfer === "sync" && jobPlan.job.schedule.mode !== "manual" && jobPlan.job.schedule.enabled && syncScheduleConfirmation !== jobPlan.job.name) {
      setEditorError("Type the exact job name to approve destination deletions for scheduled Sync runs.");
      return;
    }

    setEditorBusy(true);
    setEditorError(null);
    const plan = jobPlan;
    const isNew = editor.id === undefined;
    const previousCredentialMode = editor.id === undefined
      ? undefined
      : state.jobs.find((job) => job.id === editor.id)?.destination.credential_mode;
    let pendingAccount: string | undefined;
    let ownedStagedAccount: string | undefined;
    let credentials: BackupCredentials | undefined;
    let admitted = false;
    let committed = false;
    try {
      const source = await credentialSourceForPlan(plan);
      credentials = source.credentials;
      pendingAccount = source.pendingAccount;
      ownedStagedAccount = isNew && credentials !== undefined
        ? backupCredentialAccount(plan.job.id)
        : pendingAccount;
      const task = await controller.beginSave({
        planId: plan.plan_id,
        ...(capabilityProof === null ? {} : { capabilityProofId: capabilityProof.id }),
        ...(plan.requires_remote_secret && credentials !== undefined ? { scheduleCredentials: credentials } : {}),
        approvedRemoteSecret: plan.requires_remote_secret ? remoteSecretApproved : false,
        ...(plan.job.transfer === "sync" && plan.job.schedule.mode !== "manual" && plan.job.schedule.enabled
          ? { confirmJobName: syncScheduleConfirmation }
          : {}),
      });
      admitted = true;
      zeroCredentials(credentials);
      if (ownedStagedAccount !== undefined) stagedCredentialAccounts.current.delete(ownedStagedAccount);
      resetEditorState();
      await task.completion;
      committed = true;

      const primaryAccount = backupCredentialAccount(plan.job.id);
      if (isNew) {
        stagedCredentialAccounts.current.delete(primaryAccount);
      } else if (pendingAccount !== undefined) {
        stagedCredentialAccounts.current.delete(pendingAccount);
        await performCredentialRecovery({
          kind: "promote_pending",
          jobId: plan.job.id,
          account: primaryAccount,
          pendingAccount,
          busy: false,
          message: "Activating the replacement Keychain credentials.",
        });
      } else if (previousCredentialMode === "access_key" && plan.job.destination.credential_mode === "aws_runtime") {
        await performCredentialRecovery({
          kind: "remove_obsolete",
          jobId: plan.job.id,
          account: primaryAccount,
          busy: false,
          message: "Removing the obsolete Keychain credentials.",
        });
      }
    } catch (error: unknown) {
      if (!committed && ownedStagedAccount !== undefined) {
        await removeStagedAccount(ownedStagedAccount);
      }
      if (admitted) {
        controller.reportError("mutation", error);
      } else {
        setEditorError(humanizeBackupError(error, error instanceof BackupCredentialError ? "credentials" : "mutation").message);
      }
    } finally {
      zeroCredentials(credentials);
      setEditor((current) => current === null ? null : clearSecrets(current));
      setEditorBusy(false);
    }
  };

  const returnToEdit = async () => {
    await cleanupStagedCredentials();
    setJobPlan(null);
    setCapabilityProof(editor?.id === undefined ? null : capabilityProof);
    setTestResult(null);
    setRemoteSecretApproved(false);
    setSyncScheduleConfirmation("");
    setEditorError(null);
  };

  const openDelete = async (job: BackupJob) => {
    setPlanningAction(`delete:${job.id}`);
    try {
      const plan = await controller.planDelete(job);
      setDeleteFlow({ job, plan, confirmation: "", busy: false });
    } catch (error: unknown) {
      controller.reportError("mutation", error);
    } finally {
      setPlanningAction(null);
    }
  };

  const confirmDelete = async () => {
    if (deleteFlow === null || deleteFlow.confirmation !== deleteFlow.plan.job_name) return;
    setDeleteFlow({ ...deleteFlow, busy: true });
    try {
      const task = await controller.beginDelete(deleteFlow.plan.plan_id, deleteFlow.confirmation);
      const deletedJob = deleteFlow.job;
      setDeleteFlow(null);
      await task.completion;
      try {
        await vault.backupDelete(backupCredentialAccount(deletedJob.id));
      } catch (error: unknown) {
        const mapped = humanizeBackupError(error, "credentials");
        setCredentialRecovery({
          kind: "remove_deleted",
          jobId: deletedJob.id,
          account: backupCredentialAccount(deletedJob.id),
          busy: false,
          message: `The job was deleted, but its Keychain entry is still present. ${mapped.message}`,
        });
      }
    } catch (error: unknown) {
      controller.reportError("mutation", error);
      setDeleteFlow((current) => current === null ? null : { ...current, busy: false });
    }
  };

  const openRun = (job: BackupJob) => {
    setRunFlow({ job, confirmation: "", busy: false });
  };

  const confirmRun = async () => {
    if (runFlow === null) return;
    if (runFlow.job.transfer === "sync" && runFlow.confirmation !== runFlow.job.name) return;
    setRunFlow({ ...runFlow, busy: true });
    let credentials: BackupCredentials | undefined;
    try {
      credentials = runFlow.job.destination.credential_mode === "access_key"
        ? await loadBackupCredentials(runFlow.job.id)
        : undefined;
      await controller.beginRun(
        runFlow.job,
        credentials,
        runFlow.job.transfer === "sync" ? runFlow.confirmation : undefined,
      );
      setRunFlow(null);
    } catch (error: unknown) {
      controller.reportError(error instanceof BackupCredentialError ? "credentials" : "run", error);
      setRunFlow((current) => current === null ? null : { ...current, confirmation: "", busy: false });
    } finally {
      zeroCredentials(credentials);
    }
  };

  const openInstall = async (target: BackupInstallTarget) => {
    setPlanningAction(`install:${target}`);
    try {
      const plan = await controller.planInstall(target);
      setInstallFlow({ what: target, plan, busy: false });
    } catch (error: unknown) {
      controller.reportError("mutation", error);
    } finally {
      setPlanningAction(null);
    }
  };

  const confirmInstall = async () => {
    if (installFlow === null || installFlow.plan.manual) return;
    setInstallFlow({ ...installFlow, busy: true });
    try {
      const task = await controller.beginInstall(installFlow.plan.plan_id);
      setInstallFlow(null);
      await task.completion;
    } catch (error: unknown) {
      controller.reportError("mutation", error);
      setInstallFlow((current) => current === null ? null : { ...current, busy: false });
    }
  };

  const retryMutationCleanup = async (operation: BackupOperation) => {
    const requirement = cleanupRequirement(operation);
    if (requirement === null) return;
    setTestResult((current) => current?.operation?.operation_id === operation.operation_id
      ? { ...current, busy: true, cancelRequested: false }
      : current);
    setEditorError(null);
    let credentials: BackupCredentials | undefined;
    try {
      if (requirement.needs_credentials) {
        const jobId = requirement.job_id ?? jobPlan?.job.id;
        if (jobId === undefined) throw new BackupCredentialError("missing", "The cleanup operation did not identify the Keychain account to use.");
        const pendingAccount = jobPlan?.job.id === jobId
          ? backupPendingCredentialAccount(jobId, jobPlan.plan_id)
          : undefined;
        credentials = pendingAccount !== undefined && stagedCredentialAccounts.current.has(pendingAccount)
          ? await loadBackupCredentialsAccount(pendingAccount)
          : await loadBackupCredentials(jobId);
      }
      const task = await controller.retryCleanup(operation.operation_id, credentials);
      zeroCredentials(credentials);
      const completed = await task.completion;
      setTestResult((current) => current?.operation?.operation_id === operation.operation_id
        ? { ...current, operation: completed, busy: false, cancelRequested: false }
        : current);
    } catch (error: unknown) {
      const completed = error instanceof BackupOperationError ? error.operation : operation;
      setTestResult((current) => current?.operation?.operation_id === operation.operation_id
        ? { ...current, operation: completed, busy: false, cancelRequested: false }
        : current);
      setEditorError(humanizeBackupError(error, error instanceof BackupCredentialError ? "credentials" : "mutation").message);
      controller.reportError(error instanceof BackupCredentialError ? "credentials" : "mutation", error);
    } finally {
      zeroCredentials(credentials);
    }
  };

  useEffect(() => {
    if (
      previewMode === null
      || previewStarted.current
      || !state.jobsLoaded
      || state.statusLoading
    ) return;
    previewStarted.current = true;

    const start = async () => {
      try {
        if (previewMode === "refreshing") {
          await controller.refresh();
          return;
        }

        if (previewMode === "install-plan" || previewMode === "unsupported-target") {
          const plan = await controller.planInstall("rclone");
          if (previewMounted.current) setInstallFlow({ what: "rclone", plan, busy: false });
          return;
        }

        if (previewMode === "delete-partial-cleanup") {
          const job = state.jobs[0];
          if (job === undefined) return;
          const plan = await controller.planDelete(job);
          const task = await controller.beginDelete(plan.plan_id, plan.job_name);
          void task.completion.catch(() => undefined);
          return;
        }

        if (previewMode === "run-sync-confirm") {
          const job = state.jobs.find((candidate) => candidate.transfer === "sync");
          if (job !== undefined && previewMounted.current) setRunFlow({ job, confirmation: "", busy: false });
          return;
        }

        if (
          previewMode === "run-copy"
          || previewMode === "run-no-changes"
          || previewMode === "run-failed"
          || previewMode === "run-cancel-requested"
          || previewMode === "run-interrupted"
        ) {
          const job = state.jobs.find((candidate) => candidate.transfer === "copy");
          if (job === undefined) return;
          let credentials: BackupCredentials | undefined;
          try {
            credentials = job.destination.credential_mode === "access_key"
              ? await loadBackupCredentials(job.id)
              : undefined;
            await controller.beginRun(job, credentials);
            zeroCredentials(credentials);
          } finally {
            zeroCredentials(credentials);
          }
          return;
        }

        const editorModes: readonly BackupPreviewMode[] = [
          "editor-aws-key",
          "editor-aws-iam",
          "editor-r2",
          "editor-minio-http-warning",
        ];
        if (editorModes.includes(previewMode)) {
          if (previewMounted.current) setEditor(previewDraft(previewMode));
          return;
        }

        const plannedModes: readonly BackupPreviewMode[] = [
          "test-plan",
          "test-running",
          "test-cleanup-failed",
          "schedule-secret-disclosure",
          "schedule-conflict",
        ];
        if (!plannedModes.includes(previewMode)) return;

        const draft = previewDraft(previewMode);
        if (previewMounted.current) setEditor(draft);
        const plan = await controller.planJob(toJobDraft(draft, serverId), draft.revision);
        if (!previewMounted.current) return;
        setJobPlan(plan);
        setCapabilityProof(plan.job.capability_proof ?? null);
        setEditor(clearSecrets(draft));

        if (previewMode === "schedule-secret-disclosure") return;
        if (previewMode === "schedule-conflict") {
          setEditor(null);
          const task = await controller.beginSave({
            planId: plan.plan_id,
            approvedRemoteSecret: false,
          });
          void task.completion.catch(() => undefined);
          return;
        }

        const testPlan = await controller.planTest(plan.plan_id);
        if (!previewMounted.current) return;
        setTestResult({ plan: testPlan, operation: null, busy: previewMode !== "test-plan", cancelRequested: false });
        if (previewMode === "test-plan") return;

        let credentials: BackupCredentials | undefined;
        try {
          credentials = plan.job.destination.credential_mode === "access_key"
            ? await loadBackupCredentials(plan.job.id)
            : undefined;
          const task = await controller.beginTest(testPlan.test_plan_id, credentials);
          zeroCredentials(credentials);
          void task.completion.then((operation) => {
            if (previewMounted.current) setTestResult((current) => current === null ? null : { ...current, operation, busy: false });
          }).catch((error: unknown) => {
            if (!previewMounted.current) return;
            const operation = error instanceof BackupOperationError ? error.operation : null;
            setTestResult((current) => current === null ? null : { ...current, operation, busy: false });
            setEditorError(humanizeBackupError(error, "mutation").message);
          });
        } finally {
          zeroCredentials(credentials);
        }
      } catch (error: unknown) {
        if (previewMounted.current) controller.reportError("mutation", error);
      }
    };

    void start();
  }, [controller, previewMode, serverId, state.jobs, state.jobsLoaded, state.statusLoading]);

  const toggleHistory = async (jobId: string) => {
    if (expandedJobId === jobId) {
      setExpandedJobId(null);
      return;
    }
    setExpandedJobId(jobId);
    await controller.loadHistory(jobId);
  };

  const openHistoryLog = async (runId: string) => {
    setOpenLogId((current) => current === runId ? null : runId);
    if (openLogId !== runId) await controller.loadHistoryLog(runId);
  };

  if (state.jobsLoading && !state.jobsLoaded) {
    return <OarsLoadingState title="Loading backup jobs" detail="Oars is reading local jobs, cached runtime status, and recent run history." />;
  }

  return (
    <div className="backups-workspace">
      <header className="backups-commandbar">
        <div className="backups-commandbar-copy">
          <span className="backups-commandbar-icon"><Archive aria-hidden /></span>
          <div>
            <h2>Backup jobs</h2>
            <p>{connected ? "Protected copies and schedules for this server." : "Local backup records remain visible while this server is disconnected."}</p>
          </div>
        </div>
        <div className="backups-commandbar-actions">
          {state.jobsLoading || state.refreshing ? <OarsRefreshStatus label={state.refreshing ? "Checking server" : "Updating jobs"} /> : null}
          <Button variant="outline" size="sm" onClick={() => void controller.reload()} disabled={state.jobsLoading}>
            <RefreshCw className={state.jobsLoading ? "spin" : ""} aria-hidden /> Reload local
          </Button>
          <Button size="sm" aria-label="New backup job" onClick={openCreate}>
            <Plus aria-hidden /> Create job
          </Button>
        </div>
      </header>

      {!connected ? (
        <section className="backups-message backups-message-neutral" aria-live="polite">
          <Cloud aria-hidden />
          <div><strong>Server disconnected</strong><span>Jobs and run history are shown from the last local snapshot. Connect before testing, running, installing, or committing changes.</span></div>
        </section>
      ) : null}

      {visibleErrors.map((error) => (
        <section className="backups-message backups-message-error" role="alert" key={error.scope}>
          <AlertTriangle aria-hidden />
          <div>
            <strong>{error.scope === "credentials" ? "Credentials need attention" : error.scope === "run" ? "Run needs attention" : "Backup state needs attention"}</strong>
            <span>{error.message}</span>
            {error.detail?.path !== undefined ? <code>{error.detail.path}</code> : null}
            {error.detail?.remote_object !== undefined ? <code>{error.detail.remote_object}</code> : null}
          </div>
          {error.retryable ? <Button variant="ghost" size="sm" onClick={() => { controller.clearError(error.scope); void controller.reload(); }}>Try again</Button> : null}
        </section>
      ))}

      {credentialRecovery !== null ? (
        <section className="backups-message backups-message-warning" role="alert">
          <AlertTriangle aria-hidden />
          <div>
            <strong>{credentialRecovery.kind === "promote_pending" ? "Credential activation needs attention" : "Credential cleanup needs attention"}</strong>
            <span>{credentialRecovery.message}</span>
          </div>
          <Button variant="outline" size="sm" onClick={() => void performCredentialRecovery(credentialRecovery)} disabled={credentialRecovery.busy}>
            {credentialRecovery.busy ? <LoaderCircle className="spin" aria-hidden /> : <RefreshCw aria-hidden />}
            {credentialRecovery.kind === "promote_pending" ? "Retry credential activation" : "Retry credential cleanup"}
          </Button>
        </section>
      ) : null}

      <RuntimeAttention
        connected={connected}
        status={state.status}
        stale={state.statusStale}
        loading={state.statusLoading}
        hasSchedules={scheduledJobs}
        action={runtimeAction}
        actionBusy={planningAction?.startsWith("install:") ?? false}
        onRefresh={() => void controller.refresh()}
        onInstall={(target) => void openInstall(target)}
      />

      {state.mutationOperation !== null ? (
        <OperationPanel
          operation={state.mutationOperation}
          onCancel={() => void controller.cancelMutation()}
          onRetryCleanup={() => void retryMutationCleanup(state.mutationOperation!)}
        />
      ) : null}

      {state.run !== null ? (
        <RunPanel run={state.run} onCancel={() => void controller.cancelRun()} onRetryCleanup={() => void controller.retryRunCleanup()} />
      ) : null}

      <section className="backups-list" aria-labelledby="backup-jobs-heading">
        <div className="backups-list-heading">
          <div>
            <h3 id="backup-jobs-heading">Jobs</h3>
            <p>{state.jobs.length === 0 ? "No backup jobs are configured for this server." : `${state.jobs.length} ${state.jobs.length === 1 ? "job" : "jobs"} · last confirmed local state`}</p>
          </div>
          {state.status?.timezone !== undefined ? <span>Server time · {state.status.timezone}</span> : null}
        </div>

        {state.jobs.length === 0 ? (
          <div className="backups-empty">
            <HardDrive aria-hidden />
            <h3>No backup jobs yet</h3>
            <p>Create a protected S3 job, test real access, then review the exact save effects.</p>
            <Button onClick={openCreate}><Plus aria-hidden /> Create job</Button>
          </div>
        ) : (
          <div className="backups-table-wrap">
            <table className="backups-table">
              <thead>
                <tr><th>Job</th><th>Destination</th><th>Transfer</th><th>Schedule</th><th>Last backup</th><th><span className="sr-only">Actions</span></th></tr>
              </thead>
              <tbody>
                {state.jobs.map((job) => {
                  const history = state.histories[job.id];
                  const lastRun = history?.runs[0];
                  const expanded = expandedJobId === job.id;
                  return [
                    <tr key={job.id}>
                      <td data-label="Job">
                        <strong className="backups-job-name">{job.name}</strong>
                        <code className="backups-path">{job.source_path}</code>
                      </td>
                      <td data-label="Destination">
                        <strong>{destinationLabel(job)}</strong>
                        <span>{providerLabel(job.destination.provider)} · {job.destination.credential_mode === "aws_runtime" ? "AWS runtime" : "Saved keys"}</span>
                      </td>
                      <td data-label="Transfer"><span className={`backups-transfer backups-transfer-${job.transfer}`}>{job.transfer === "copy" ? "Copy" : "Sync"}</span></td>
                      <td data-label="Schedule"><span>{humanSchedule(job.schedule)}</span></td>
                      <td data-label="Last backup">
                        {history?.loading && lastRun === undefined ? <span>Loading…</span> : lastRun === undefined ? <span>Not run yet</span> : (
                          <><span className={`backups-run-status status-${lastRun.status}`}><i aria-hidden />{runStatusLabel(lastRun.status)}</span><small>{formatDate(lastRun.finished_at_ms)}</small></>
                        )}
                      </td>
                      <td className="backups-actions">
                        <Button size="xs" variant="outline" onClick={() => openRun(job)} disabled={!connected || state.run?.active === true || (credentialRecovery?.kind === "promote_pending" && credentialRecovery.jobId === job.id)}>Run now</Button>
                        <Button size="xs" variant="ghost" onClick={() => void toggleHistory(job.id)} aria-expanded={expanded}>{expanded ? "Hide runs" : "View runs"}</Button>
                        <Button size="xs" variant="ghost" onClick={() => openEdit(job)}>Edit</Button>
                        <Button size="icon-xs" variant="ghost" aria-label={`Delete ${job.name}`} onClick={() => void openDelete(job)} disabled={!connected || planningAction === `delete:${job.id}`}><Trash2 aria-hidden /></Button>
                      </td>
                    </tr>,
                    expanded ? (
                      <tr className="backups-history-row" key={`${job.id}:history`}>
                        <td colSpan={6}>
                          <HistoryList
                            history={history}
                            logs={state.historyLogs}
                            openLogId={openLogId}
                            onOpenLog={(runId) => void openHistoryLog(runId)}
                            onLoadMore={(runId) => void controller.loadHistoryLog(runId)}
                          />
                        </td>
                      </tr>
                    ) : null,
                  ];
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {editor !== null ? (
        <BackupEditModal
          draft={editor}
          plan={jobPlan}
          proof={capabilityProof}
          testResult={testResult}
          connected={connected}
          error={editorError}
          busy={editorBusy}
          remoteSecretApproved={remoteSecretApproved}
          syncScheduleConfirmation={syncScheduleConfirmation}
          onChange={updateEditor}
          onClose={closeEditor}
          onPlan={() => void handlePlan()}
          onBack={() => void returnToEdit()}
          onReveal={() => void revealExistingCredentials()}
          onPrepareTest={() => void handlePrepareTest()}
          onApproveTest={() => void handleApproveTest()}
          onCancelTest={() => void handleCancelTest()}
          onRetryTestCleanup={(operation) => void retryMutationCleanup(operation)}
          onRemoteSecretApproved={setRemoteSecretApproved}
          onSyncScheduleConfirmation={setSyncScheduleConfirmation}
          onSave={() => void handleSave()}
        />
      ) : null}

      {deleteFlow !== null ? (
        <DeleteDialog flow={deleteFlow} onChange={(confirmation) => setDeleteFlow({ ...deleteFlow, confirmation })} onClose={() => { if (!deleteFlow.busy) setDeleteFlow(null); }} onConfirm={() => void confirmDelete()} />
      ) : null}

      {runFlow !== null ? (
        <RunDialog flow={runFlow} onChange={(confirmation) => setRunFlow({ ...runFlow, confirmation })} onClose={() => { if (!runFlow.busy) setRunFlow(null); }} onConfirm={() => void confirmRun()} />
      ) : null}

      {installFlow !== null ? (
        <InstallDialog flow={installFlow} onClose={() => { if (!installFlow.busy) setInstallFlow(null); }} onConfirm={() => void confirmInstall()} />
      ) : null}
    </div>
  );
}

function RuntimeAttention({
  connected,
  status,
  stale,
  loading,
  hasSchedules,
  action,
  actionBusy,
  onRefresh,
  onInstall,
}: {
  connected: boolean;
  status: import("./types").BackupServerStatus | null;
  stale: boolean;
  loading: boolean;
  hasSchedules: boolean;
  action: BackupInstallTarget | null;
  actionBusy: boolean;
  onRefresh: () => void;
  onInstall: (target: BackupInstallTarget) => void;
}) {
  const rclonePath = typeof status?.rclone_path === "string" ? status.rclone_path.trim() : "";
  const warnings = Array.isArray(status?.warnings)
    ? status.warnings.filter((warning): warning is string => typeof warning === "string" && warning.trim() !== "")
    : [];
  const runtimeReady = status !== null
    && rclonePath !== ""
    && status.scheduler_supported === true
    && (!hasSchedules || (status.cron_installed === true && status.cron_running === true));
  const schedulerLabel = status === null
    ? "Unknown"
    : status.scheduler_supported === true
      ? status.cron_running === true ? "Cron running" : "Cron stopped"
      : "Unsupported";
  return (
    <section className="backups-runtime" aria-labelledby="backup-runtime-heading">
      <div className="backups-runtime-heading">
        <div>
          <h3 id="backup-runtime-heading">Runtime readiness</h3>
          <p>{stale ? "Showing the last observed server state." : "Observed from the selected server."}</p>
        </div>
        <span className={`backups-health ${runtimeReady ? "is-ready" : "is-attention"}`}><i aria-hidden />{runtimeReady ? "Ready" : status === null ? "Not checked" : "Needs attention"}</span>
      </div>
      <dl className="backups-runtime-facts">
        <div><dt>Rclone</dt><dd>{presentStatusText(status?.rclone_version, loading ? "Checking…" : "Not available")}</dd></div>
        <div><dt>Scheduler</dt><dd>{schedulerLabel}</dd></div>
        <div><dt>Crontab</dt><dd>{presentStatusText(status?.crontab_implementation, "Not observed")}</dd></div>
        <div><dt>Connected user</dt><dd>{presentStatusText(status?.user, "Not observed")}</dd></div>
        <div><dt>Server time</dt><dd>{presentStatusText(status?.timezone, "Not observed")}</dd></div>
        <div><dt>Warnings</dt><dd>{warnings.length === 0 ? "None reported" : `${warnings.length} ${warnings.length === 1 ? "warning" : "warnings"}`}</dd></div>
      </dl>
      {status !== null && status.scheduler_supported !== true ? <p className="backups-runtime-note"><AlertTriangle aria-hidden />This runtime does not currently report verified scheduler support.</p> : null}
      {warnings.map((warning, index) => <p className="backups-runtime-note" key={`${index}:${warning}`}><Clock3 aria-hidden />{warning}</p>)}
      {warnings.length > 0 ? (
        <div className="backups-cleanup-unavailable">
          <span>Resolve the named item on the server, then refresh runtime status.</span>
        </div>
      ) : null}
      <div className="backups-runtime-actions">
        <Button variant="outline" size="sm" onClick={onRefresh} disabled={!connected || loading}><RefreshCw className={loading ? "spin" : ""} aria-hidden /> Refresh runtime</Button>
        {action !== null ? <Button variant="secondary" size="sm" onClick={() => onInstall(action)} disabled={!connected || actionBusy}>{actionBusy ? <LoaderCircle className="spin" aria-hidden /> : <Wrench aria-hidden />}Review {action === "start_cron" ? "cron start" : `${action} install`}</Button> : null}
      </div>
    </section>
  );
}

function OperationPanel({
  operation,
  onCancel,
  onRetryCleanup,
}: {
  operation: BackupOperation;
  onCancel: () => void;
  onRetryCleanup: () => void;
}) {
  const active = operation.state === "queued" || operation.state === "running";
  const phase = operation.steps.find((step) => step.state === "running" || step.state === "cancel_requested")
    ?? operation.steps.find((step) => step.state === "pending")
    ?? operation.steps.at(-1);
  const canRetryCleanup = operation.state === "partial" && cleanupRequirement(operation)?.retry_action === "operationCancel";
  return (
    <section className={`backups-operation state-${operation.state}`} aria-live="polite" aria-label="Backup operation progress">
      <div className="backups-operation-icon">{active ? <LoaderCircle className="spin" aria-hidden /> : operation.state === "done" ? <CheckCircle2 aria-hidden /> : <AlertTriangle aria-hidden />}</div>
      <div>
        <strong>{operationLabel(operation)}</strong>
        <dl className="backups-operation-facts">
          <div><dt>Phase</dt><dd>{phaseLabel(phase?.id ?? operation.kind)}</dd></div>
          <div><dt>Elapsed</dt><dd>{formatElapsed(operation.started_at_ms, operation.finished_at_ms)}</dd></div>
        </dl>
        {operation.steps.length > 0 ? <ul>{operation.steps.map((step) => <li key={step.id}><span>{step.id}</span><b>{step.state.replaceAll("_", " ")}</b></li>)}</ul> : <p>Waiting for the server coordinator to publish the next step.</p>}
      </div>
      {active ? <Button variant="outline" size="sm" onClick={onCancel}>Request cancel</Button> : null}
      {canRetryCleanup ? <Button variant="outline" size="sm" onClick={onRetryCleanup}><Wrench aria-hidden />Retry cleanup</Button> : null}
    </section>
  );
}

function RunPanel({ run, onCancel, onRetryCleanup }: { run: import("./backup-state").BackupRunState; onCancel: () => void; onRetryCleanup: () => void }) {
  const snapshot = run.snapshot;
  const status = snapshot?.status ?? "queued";
  const progress = snapshot !== null && snapshot.bytes_total > 0 ? Math.min(100, (snapshot.bytes_done / snapshot.bytes_total) * 100) : 0;
  const runError = snapshot?.error?.error ?? run.error?.message;
  const runErrorDetail = snapshot?.error?.detail ?? run.error?.detail;
  const cancellationPending = run.cancelRequested || status === "cancel_requested";
  const cleanupFailed = snapshot?.cleanup_state === "failed";
  const cleanupLabel = snapshot?.cleanup_state === "complete"
    ? "Complete"
    : snapshot?.cleanup_state === "failed"
      ? "Failed"
      : "Pending";
  return (
    <section className={`backups-run state-${status}`} aria-live="polite" aria-label="Backup run progress">
      <header>
        <div>
          <span className={`backups-run-status status-${status}`}><i aria-hidden />{runStatusLabel(status)}</span>
          <h3>Backup run</h3>
          <p>{cancellationPending ? "Cancel requested. Oars is waiting for the process to stop and cleanup to finish." : snapshot === null ? "Waiting for the first server update." : `${formatBytes(snapshot.bytes_done)} of ${formatBytes(snapshot.bytes_total)} · ${snapshot.files_done} of ${snapshot.files_total} files`}</p>
        </div>
        {run.active ? <Button variant="outline" size="sm" onClick={onCancel} disabled={cancellationPending}>{cancellationPending ? "Cancel requested" : "Cancel run"}</Button> : null}
      </header>
      <div className="backups-progress" role="progressbar" aria-label="Backup transfer progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(progress)}><span style={{ transform: `scaleX(${progress / 100})` }} /></div>
      {snapshot !== null ? (
        <dl>
          <div><dt>Phase</dt><dd>{phaseLabel(snapshot.phase)}</dd></div>
          <div><dt>Elapsed</dt><dd>{formatElapsed(snapshot.started_at_ms, snapshot.finished_at_ms)}</dd></div>
          <div><dt>Speed</dt><dd>{formatBytes(snapshot.speed_bps)}/s</dd></div>
          <div><dt>ETA</dt><dd>{snapshot.eta_sec > 0 ? `${snapshot.eta_sec}s` : "—"}</dd></div>
          <div><dt>Cleanup</dt><dd>{cleanupLabel}</dd></div>
          <div><dt>Started</dt><dd>{formatDate(snapshot.started_at_ms)}</dd></div>
        </dl>
      ) : null}
      {runError !== undefined ? (
        <div className="backups-run-error" role="alert">
          <AlertTriangle aria-hidden />
          <span><strong>Run did not complete safely</strong>{runError}</span>
          {runErrorDetail?.path !== undefined ? <code>{runErrorDetail.path}</code> : null}
          {runErrorDetail?.remote_object !== undefined ? <code>{runErrorDetail.remote_object}</code> : null}
        </div>
      ) : null}
      {cleanupFailed ? (
        <div className="backups-cleanup-unavailable">
          <Button variant="outline" size="sm" onClick={onRetryCleanup}><Wrench aria-hidden />Retry cleanup</Button>
          <span>Retry removes only the exact retained temporary config or state path shown above.</span>
        </div>
      ) : null}
      {snapshot?.dropped ? <p className="backups-log-gap">{snapshot.dropped} bytes of earlier live output were dropped.</p> : null}
      {run.log !== "" ? <pre className="backups-log">{run.log}</pre> : null}
    </section>
  );
}

function HistoryList({
  history,
  logs,
  openLogId,
  onOpenLog,
  onLoadMore,
}: {
  history: import("./backup-state").BackupHistoryState | undefined;
  logs: Readonly<Record<string, import("./backup-state").BackupHistoryLogState>>;
  openLogId: string | null;
  onOpenLog: (runId: string) => void;
  onLoadMore: (runId: string) => void;
}) {
  if (history?.loading && !history.loaded) return <div className="backups-history-empty">Loading recent runs…</div>;
  if (history?.error !== null && history?.error !== undefined && history.runs.length === 0) return <div className="backups-history-error" role="alert">{history.error.message}</div>;
  if (history === undefined || history.runs.length === 0) return <div className="backups-history-empty">No completed runs yet.</div>;
  return (
    <div className="backups-history">
      {history.runs.map((run) => {
        const log = logs[run.run_id];
        const open = openLogId === run.run_id;
        return (
          <article key={run.run_id}>
            <button type="button" className="backups-history-summary" onClick={() => onOpenLog(run.run_id)} aria-expanded={open}>
              <span className={`backups-run-status status-${run.status}`}><i aria-hidden />{runStatusLabel(run.status)}</span>
              <strong>{formatBytes(run.bytes_done)} · {run.files_done} files</strong>
              <time>{formatDate(run.finished_at_ms)}</time>
              <span>{open ? "Hide log" : "View log"}</span>
            </button>
            {open ? (
              <div className="backups-history-log">
                {log?.dropped ? <p>{log.dropped} bytes of earlier output were dropped.</p> : null}
                {log?.error !== null && log?.error !== undefined ? <p role="alert">{log.error.message}</p> : null}
                <pre>{log?.text || (log?.loading ? "Loading run log…" : "No log output was recorded.")}</pre>
                {log !== undefined && !log.eof ? <Button variant="outline" size="xs" onClick={() => onLoadMore(run.run_id)} disabled={log.loading}>{log.loading ? "Loading…" : "Load more"}</Button> : null}
              </div>
            ) : null}
          </article>
        );
      })}
    </div>
  );
}

function BackupEditModal({
  draft,
  plan,
  proof,
  testResult,
  connected,
  error,
  busy,
  remoteSecretApproved,
  syncScheduleConfirmation,
  onChange,
  onClose,
  onPlan,
  onBack,
  onReveal,
  onPrepareTest,
  onApproveTest,
  onCancelTest,
  onRetryTestCleanup,
  onRemoteSecretApproved,
  onSyncScheduleConfirmation,
  onSave,
}: {
  draft: EditorDraft;
  plan: BackupPlanResult | null;
  proof: BackupCapabilityProof | null;
  testResult: TestResultState | null;
  connected: boolean;
  error: string | null;
  busy: boolean;
  remoteSecretApproved: boolean;
  syncScheduleConfirmation: string;
  onChange: (draft: EditorDraft) => void;
  onClose: () => void;
  onPlan: () => void;
  onBack: () => void;
  onReveal: () => void;
  onPrepareTest: () => void;
  onApproveTest: () => void;
  onCancelTest: () => void;
  onRetryTestCleanup: (operation: BackupOperation) => void;
  onRemoteSecretApproved: (approved: boolean) => void;
  onSyncScheduleConfirmation: (value: string) => void;
  onSave: () => void;
}) {
  const testBusy = testResult?.busy === true;
  const testCancelRequested = testResult?.cancelRequested === true;
  const operationBusy = busy || testBusy;
  const canClose = !busy && (!testBusy || testCancelRequested);
  const dialogRef = useModalFocus(onClose, plan === null ? "#backup-name" : "#backup-review-heading", canClose);
  const endpointRequired = draft.provider !== "aws";
  const httpWarning = draft.endpoint.startsWith("http://");
  const setProvider = (value: string) => {
    if (!isProvider(value)) return;
    const defaults = PROVIDER_DEFAULTS[value];
    onChange({
      ...draft,
      provider: value,
      endpoint: defaults.endpoint,
      region: defaults.region,
      storageClass: defaults.storageClass,
      credentialMode: value === "aws" ? draft.credentialMode : "access_key",
    });
  };
  const testOperation = testResult?.operation;
  const testResultPayload = testOperation?.kind === "test"
    && testOperation.result !== undefined
    && "checks" in testOperation.result
    ? testOperation.result
    : undefined;
  const testCleanupRequired = testOperation === undefined || testOperation === null ? null : cleanupRequirement(testOperation);
  const testChecks = testResult?.plan.checks.flatMap((check) => {
    const resultState = testResultPayload?.checks[check];
    const stepState = testOperation?.steps.find((step) => step.id === check)?.state;
    if (resultState === undefined && stepState === undefined) return [];
    return [{
      check,
      passed: resultState === "passed" || stepState === "done",
    }];
  }) ?? [];
  const testLeftover = testResultPayload?.leftover_remote_object ?? testOperation?.error?.detail?.remote_object ?? testOperation?.error?.detail?.path;
  const testPassed = testOperation?.kind === "test" && testOperation.state === "done" && testLeftover === undefined;
  const scheduleEnabled = plan?.job.schedule.mode !== "manual" && plan?.job.schedule.enabled === true;
  const canSave = connected
    && !operationBusy
    && plan !== null
    && (!plan.requires_connection_test || proof !== null)
    && (!plan.requires_remote_secret || remoteSecretApproved)
    && (!(plan.job.transfer === "sync" && scheduleEnabled) || syncScheduleConfirmation === plan.job.name);

  return (
    <ApplicationOverlay role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && canClose) onClose(); }}>
      <div ref={dialogRef} className="oars-modal backups-editor-modal" role="dialog" aria-modal="true" aria-labelledby="backup-edit-title" aria-describedby="backup-edit-desc">
        <header className="oars-modal-header">
          <div className="oars-modal-title-row">
            <span className="oars-modal-icon"><Archive aria-hidden /></span>
            <div>
              <h2 id="backup-edit-title">{draft.id === undefined ? "Create backup job" : "Edit backup job"}</h2>
              <p id="backup-edit-desc" className="oars-modal-subtitle">{plan === null ? "Define the source, destination, transfer behavior, and schedule before reviewing changes." : "Review the frozen plan, prove storage access when required, then approve the save."}</p>
            </div>
            <Button variant="ghost" size="icon-sm" aria-label="Close" onClick={onClose} disabled={!canClose}><X aria-hidden /></Button>
          </div>
        </header>

        <div className="oars-modal-body backups-editor-body">
          {error !== null ? <div className="oars-form-error" role="alert">{error}</div> : null}
          {!connected ? <div className="oars-callout">Connect this server before testing or saving. Your draft remains available.</div> : null}

          {plan === null ? (
            <>
              <section className="backups-form-section" aria-labelledby="backup-basics-heading">
                <div className="backups-form-heading"><div><h3 id="backup-basics-heading">Job and source</h3><p>Name this protected copy and choose one exact absolute source path.</p></div></div>
                <div className="backups-form-grid">
                  <div className="oars-field"><label htmlFor="backup-name">Name</label><input id="backup-name" value={draft.name} onChange={(event) => onChange({ ...draft, name: event.target.value })} maxLength={96} placeholder="Daily website" /></div>
                  <div className="oars-field"><label htmlFor="backup-source">Source path</label><input id="backup-source" className="backups-mono-input" value={draft.sourcePath} onChange={(event) => onChange({ ...draft, sourcePath: event.target.value })} maxLength={1_024} placeholder="/var/www" /></div>
                </div>
              </section>

              <section className="backups-form-section" aria-labelledby="backup-destination-heading">
                <div className="backups-form-heading"><div><h3 id="backup-destination-heading">S3 destination</h3><p>Provider fields stay explicit so the reviewed endpoint and bucket are never inferred.</p></div></div>
                <div className="backups-form-grid">
                  <div className="oars-field"><label htmlFor="backup-provider">Provider</label><OarsSelect id="backup-provider" value={draft.provider} onValueChange={setProvider} options={PROVIDERS} /></div>
                  <div className="oars-field"><label htmlFor="backup-bucket">Bucket</label><input id="backup-bucket" value={draft.bucket} onChange={(event) => onChange({ ...draft, bucket: event.target.value })} maxLength={255} /></div>
                  <div className="oars-field"><label htmlFor="backup-prefix">Prefix <span className="oars-inline-hint">Optional</span></label><input id="backup-prefix" className="backups-mono-input" value={draft.prefix} onChange={(event) => onChange({ ...draft, prefix: event.target.value })} maxLength={1_024} placeholder="backups/site" /></div>
                  <div className="oars-field"><label htmlFor="backup-endpoint">Endpoint {endpointRequired ? "" : <span className="oars-inline-hint">Optional</span>}</label><input id="backup-endpoint" className="backups-mono-input" value={draft.endpoint} onChange={(event) => onChange({ ...draft, endpoint: event.target.value })} maxLength={1_024} placeholder="https://s3.example.com" />{httpWarning ? <span className="oars-field-error"><AlertTriangle aria-hidden /> Plain HTTP exposes storage traffic. Use it only for a trusted private test endpoint.</span> : null}</div>
                  <div className="oars-field"><label htmlFor="backup-region">Region</label><input id="backup-region" value={draft.region} onChange={(event) => onChange({ ...draft, region: event.target.value })} disabled={draft.provider === "r2"} maxLength={128} /></div>
                  <div className="oars-field"><label htmlFor="backup-storage-class">Storage class</label><OarsSelect id="backup-storage-class" value={draft.storageClass} onValueChange={(value) => onChange({ ...draft, storageClass: value })} options={STORAGE_CLASSES[draft.provider]} /></div>
                </div>
              </section>

              <section className="backups-form-section" aria-labelledby="backup-behavior-heading">
                <div className="backups-form-heading"><div><h3 id="backup-behavior-heading">Credentials and transfer</h3><p>Runtime credentials stay on AWS. Saved keys live in Keychain and enter only the admitted operation.</p></div></div>
                <div className="backups-form-grid">
                  <div className="oars-field"><label htmlFor="backup-credential-mode">Credential mode</label><OarsSelect id="backup-credential-mode" value={draft.credentialMode} onValueChange={(value) => { if (isCredentialMode(value)) onChange({ ...draft, credentialMode: value }); }} options={[{ value: "access_key", label: "Access and secret key" }, { value: "aws_runtime", label: "AWS runtime / IAM", disabled: draft.provider !== "aws" }]} /></div>
                  <div className="oars-field"><label htmlFor="backup-transfer">Transfer behavior</label><OarsSelect id="backup-transfer" value={draft.transfer} onValueChange={(value) => { if (isTransfer(value)) onChange({ ...draft, transfer: value }); }} options={[{ value: "copy", label: "Copy — keep destination-only files" }, { value: "sync", label: "Sync — delete destination-only files" }]} /></div>
                </div>
                {draft.transfer === "sync" ? <div className="backups-warning"><AlertTriangle aria-hidden /><span><strong>Sync can delete destination data.</strong> Every manual run requires the exact job name. Enabling a schedule requires the same advance approval.</span></div> : null}
              </section>

              <section className="backups-form-section" aria-labelledby="backup-schedule-heading">
                <div className="backups-form-heading"><div><h3 id="backup-schedule-heading">Schedule</h3><p>Scheduled times use the server timezone reported after refresh.</p></div></div>
                <div className="backups-form-grid">
                  <div className="oars-field"><label htmlFor="backup-schedule-mode">Mode</label><OarsSelect id="backup-schedule-mode" value={draft.scheduleMode} onValueChange={(value) => { if (isScheduleMode(value)) onChange({ ...draft, scheduleMode: value, scheduleEnabled: value === "manual" ? false : draft.scheduleEnabled }); }} options={[{ value: "manual", label: "Manual only" }, { value: "interval", label: "Every few hours or days" }, { value: "custom", label: "Custom five-field cron" }]} /></div>
                  {draft.scheduleMode !== "manual" ? <label className="backups-enable"><input type="checkbox" checked={draft.scheduleEnabled} onChange={(event) => onChange({ ...draft, scheduleEnabled: event.target.checked })} /> Enable this schedule after save</label> : null}
                  {draft.scheduleMode === "interval" ? <><div className="oars-field"><label htmlFor="backup-every">Every</label><input id="backup-every" type="number" min={1} max={draft.unit === "hours" ? 168 : 365} value={draft.every} onChange={(event) => onChange({ ...draft, every: Number(event.target.value) })} /></div><div className="oars-field"><label htmlFor="backup-unit">Unit</label><OarsSelect id="backup-unit" value={draft.unit} onValueChange={(value) => { if (isIntervalUnit(value)) onChange({ ...draft, unit: value }); }} options={[{ value: "hours", label: "Hours" }, { value: "days", label: "Days" }]} /></div></> : null}
                  {draft.scheduleMode === "custom" ? <div className="oars-field backups-field-wide"><label htmlFor="backup-expression">Cron expression</label><input id="backup-expression" className="backups-mono-input" value={draft.expression} onChange={(event) => onChange({ ...draft, expression: event.target.value })} maxLength={128} /><span className="oars-hint">Five fields in the server&apos;s local timezone. Daylight saving changes can skip or repeat a time.</span></div> : null}
                </div>
              </section>
            </>
          ) : (
            <>
              <section className="backups-review" aria-labelledby="backup-review-heading" tabIndex={-1} id="backup-review-heading">
                <div className="backups-review-title"><div><span>Frozen review</span><h3>{plan.job.name}</h3></div><code>{plan.plan_id}</code></div>
                <dl>
                  <div><dt>Source</dt><dd><code>{plan.job.source_path}</code></dd></div>
                  <div><dt>Destination</dt><dd><code>{destinationLabel(plan.job)}</code></dd></div>
                  <div><dt>Transfer</dt><dd>{plan.job.transfer === "copy" ? "Copy keeps destination-only files" : "Sync deletes destination-only files"}</dd></div>
                  <div><dt>Schedule</dt><dd>{humanSchedule(plan.job.schedule)}</dd></div>
                </dl>
                {plan.effects.length > 0 ? <div className="backups-review-list"><strong>Changes after approval</strong><ul>{plan.effects.map((effect) => <li key={effect}>{effect}</li>)}</ul></div> : null}
                {plan.warnings.map((warning) => <div className="backups-warning" key={warning}><AlertTriangle aria-hidden /><span>{warning}</span></div>)}
                {plan.schedule_preview !== undefined ? <details className="backups-schedule-preview"><summary>Review generated schedule · {plan.schedule_preview.timezone}</summary><pre>{plan.schedule_preview.crontab_block}</pre></details> : null}
              </section>

              {plan.job.destination.credential_mode === "access_key" ? (
                <section className="backups-form-section" aria-labelledby="backup-credentials-heading">
                  <div className="backups-form-heading"><div><h3 id="backup-credentials-heading">Storage credentials</h3><p>Enter keys for this review, or explicitly reveal the existing Keychain entry.</p></div>{draft.id !== undefined ? <Button variant="outline" size="sm" onClick={onReveal} disabled={operationBusy}>Reveal saved keys</Button> : null}</div>
                  <div className="backups-form-grid"><div className="oars-field"><label htmlFor="backup-access-key">Access key</label><input id="backup-access-key" type="password" value={draft.accessKey} onChange={(event) => onChange({ ...draft, accessKey: event.target.value })} autoComplete="off" disabled={operationBusy} /></div><div className="oars-field"><label htmlFor="backup-secret-key">Secret key</label><input id="backup-secret-key" type="password" value={draft.secretKey} onChange={(event) => onChange({ ...draft, secretKey: event.target.value })} autoComplete="off" disabled={operationBusy} /></div></div>
                </section>
              ) : <div className="backups-disclosure"><ShieldCheck aria-hidden /><span><strong>AWS runtime credentials</strong>No static storage keys will be sent or stored for this job.</span></div>}

              <section className="backups-test-section" aria-labelledby="backup-test-heading">
                <div className="backups-form-heading"><div><h3 id="backup-test-heading">Connection test</h3><p>The test writes a unique sentinel, reads its exact content, deletes it, and verifies cleanup.</p></div>{proof !== null ? <span className="backups-proof"><CheckCircle2 aria-hidden />Proof ready</span> : null}</div>
                {testResult === null ? <Button variant="outline" onClick={onPrepareTest} disabled={!connected || operationBusy}>Review connection test</Button> : (
                  <div className="backups-test-plan">
                    <p>Oars will temporarily mutate this exact object:</p>
                    <code>{testResult.plan.remote_object}</code>
                    <ol>{testResult.plan.checks.map((check) => <li key={check}>{CHECK_LABELS[check]}</li>)}</ol>
                    {testResult.operation === null ? testResult.busy ? (
                      <div className="backups-test-cancel">
                        <Button variant="outline" onClick={onCancelTest} disabled={busy || testResult.cancelRequested}>{busy ? <LoaderCircle className="spin" aria-hidden /> : <XCircle aria-hidden />}{testResult.cancelRequested ? "Cancellation requested" : "Cancel connection test"}</Button>
                        <span>{testResult.cancelRequested ? "The request was accepted. You may close this review while the backend finishes interruption and cleanup." : "Cancel remains available while the protected test is running."}</span>
                      </div>
                    ) : <Button onClick={onApproveTest} disabled={!connected || operationBusy}><ShieldCheck aria-hidden />Approve and run test</Button> : (
                      <div className={`backups-test-result state-${testResult.operation.state}`}>
                        <strong>{testPassed ? "Connection proved" : operationLabel(testResult.operation)}</strong>
                        {testChecks.length > 0 ? <ul>{testChecks.map(({ check, passed }) => <li key={check}>{passed ? <CheckCircle2 aria-hidden /> : <XCircle aria-hidden />}<span>{CHECK_LABELS[check]}</span></li>)}</ul> : null}
                        {testLeftover !== undefined ? <p><AlertTriangle aria-hidden /><span>Cleanup could not remove the sentinel.<code>{testLeftover}</code></span></p> : null}
                        {testCleanupRequired?.retry_action === "operationCancel" ? <Button variant="outline" size="sm" onClick={() => onRetryTestCleanup(testResult.operation!)} disabled={operationBusy}><Wrench aria-hidden />Retry cleanup</Button> : null}
                      </div>
                    )}
                  </div>
                )}
              </section>

              {plan.requires_remote_secret ? <label className="backups-approval"><input type="checkbox" checked={remoteSecretApproved} onChange={(event) => onRemoteSecretApproved(event.target.checked)} /><span><strong>Approve unattended credential copy</strong>Scheduled runs need a mode-0600 remote rclone configuration. Rclone obscuring is reversible, not encryption.</span></label> : null}
              {plan.job.transfer === "sync" && scheduleEnabled ? <div className="oars-field"><label htmlFor="backup-sync-schedule-confirm">Type <strong>{plan.job.name}</strong> to approve scheduled destination deletions</label><input id="backup-sync-schedule-confirm" value={syncScheduleConfirmation} onChange={(event) => onSyncScheduleConfirmation(event.target.value)} autoComplete="off" /></div> : null}
            </>
          )}

          <footer className="oars-modal-actions oars-modal-footer">
            <div className="oars-modal-actions-left">{plan !== null ? <Button variant="ghost" onClick={onBack} disabled={operationBusy}>Edit details</Button> : null}</div>
            <div className="oars-modal-actions-right">
              <Button variant="ghost" onClick={onClose} disabled={!canClose}>Cancel</Button>
              {plan === null ? <Button onClick={onPlan} disabled={operationBusy}>{busy ? <LoaderCircle className="spin" aria-hidden /> : null}Review job</Button> : <Button onClick={onSave} disabled={!canSave}>{busy ? <LoaderCircle className="spin" aria-hidden /> : null}Save reviewed job</Button>}
            </div>
          </footer>
        </div>
      </div>
    </ApplicationOverlay>
  );
}

function DeleteDialog({ flow, onChange, onClose, onConfirm }: { flow: DeleteFlow; onChange: (value: string) => void; onClose: () => void; onConfirm: () => void }) {
  const dialogRef = useModalFocus(onClose, "#backup-delete-confirm", !flow.busy);
  return (
    <ApplicationOverlay role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !flow.busy) onClose(); }}>
      <div ref={dialogRef} className="oars-modal oars-modal-narrow" role="dialog" aria-modal="true" aria-labelledby="backup-delete-title" aria-describedby="backup-delete-desc">
        <header className="oars-modal-header"><div className="oars-modal-title-row"><span className="oars-modal-icon oars-modal-icon-danger"><Trash2 aria-hidden /></span><div><h2 id="backup-delete-title">Delete {flow.plan.job_name}?</h2><p id="backup-delete-desc" className="oars-modal-subtitle">Oars will remove the reviewed schedule and local job record. Destination objects are not deleted.</p></div><Button variant="ghost" size="icon-sm" aria-label="Close" onClick={onClose} disabled={flow.busy}><X aria-hidden /></Button></div></header>
        <div className="oars-modal-body">
          <div className="backups-review-list"><strong>Reviewed effects</strong><ul>{flow.plan.effects.map((effect) => <li key={effect}>{effect}</li>)}</ul></div>
          {flow.plan.leftovers.length > 0 ? <div className="backups-review-list"><strong>Preserved after deletion</strong><ul>{flow.plan.leftovers.map((leftover) => <li key={leftover}>{leftover}</li>)}</ul></div> : null}
          <div className="oars-field"><label htmlFor="backup-delete-confirm">Type <strong>{flow.plan.job_name}</strong> to confirm</label><input id="backup-delete-confirm" type="text" value={flow.confirmation} onChange={(event) => onChange(event.target.value)} autoComplete="off" /></div>
          <footer className="oars-modal-actions oars-modal-footer"><div className="oars-modal-actions-right"><Button variant="ghost" onClick={onClose} disabled={flow.busy}>Cancel</Button><Button variant="destructive" onClick={onConfirm} disabled={flow.busy || flow.confirmation !== flow.plan.job_name}>{flow.busy ? <LoaderCircle className="spin" aria-hidden /> : null}Delete reviewed job</Button></div></footer>
        </div>
      </div>
    </ApplicationOverlay>
  );
}

function RunDialog({ flow, onChange, onClose, onConfirm }: { flow: RunFlow; onChange: (value: string) => void; onClose: () => void; onConfirm: () => void }) {
  const needsName = flow.job.transfer === "sync";
  const dialogRef = useModalFocus(onClose, needsName ? "#backup-run-confirm" : "#backup-run-submit", !flow.busy);
  return (
    <ApplicationOverlay role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !flow.busy) onClose(); }}>
      <div ref={dialogRef} className="oars-modal oars-modal-narrow" role="dialog" aria-modal="true" aria-labelledby="backup-run-title" aria-describedby="backup-run-desc">
        <header className="oars-modal-header"><div className="oars-modal-title-row"><span className="oars-modal-icon"><Play aria-hidden /></span><div><h2 id="backup-run-title">Run {flow.job.name} now?</h2><p id="backup-run-desc" className="oars-modal-subtitle">Source <code>{flow.job.source_path}</code> will be transferred to <code>{destinationLabel(flow.job)}</code>.</p></div><Button variant="ghost" size="icon-sm" aria-label="Close" onClick={onClose} disabled={flow.busy}><X aria-hidden /></Button></div></header>
        <div className="oars-modal-body">
          {flow.job.transfer === "copy" ? <div className="backups-disclosure"><ShieldCheck aria-hidden /><span><strong>Copy keeps destination-only files</strong>Changed and new source files are uploaded. Files that exist only in the destination remain untouched.</span></div> : <div className="backups-warning"><AlertTriangle aria-hidden /><span><strong>Sync can delete destination-only files</strong>The destination will mirror the source after this run.</span></div>}
          {needsName ? <div className="oars-field"><label htmlFor="backup-run-confirm">Type <strong>{flow.job.name}</strong> to confirm</label><input id="backup-run-confirm" type="text" value={flow.confirmation} onChange={(event) => onChange(event.target.value)} autoComplete="off" /></div> : null}
          <footer className="oars-modal-actions oars-modal-footer"><div className="oars-modal-actions-right"><Button variant="ghost" onClick={onClose} disabled={flow.busy}>Cancel</Button><Button id="backup-run-submit" onClick={onConfirm} disabled={flow.busy || (needsName && flow.confirmation !== flow.job.name)}>{flow.busy ? <LoaderCircle className="spin" aria-hidden /> : <Play aria-hidden />}Run now</Button></div></footer>
        </div>
      </div>
    </ApplicationOverlay>
  );
}

function InstallDialog({ flow, onClose, onConfirm }: { flow: InstallFlow; onClose: () => void; onConfirm: () => void }) {
  const dialogRef = useModalFocus(onClose, flow.plan.manual ? "#backup-install-close" : "#backup-install-confirm", !flow.busy);
  const target = flow.what === "start_cron" ? "start cron" : `install ${flow.what}`;
  return (
    <ApplicationOverlay role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !flow.busy) onClose(); }}>
      <div ref={dialogRef} className="oars-modal oars-modal-narrow" role="dialog" aria-modal="true" aria-labelledby="backup-install-title" aria-describedby="backup-install-desc">
        <header className="oars-modal-header"><div className="oars-modal-title-row"><span className="oars-modal-icon"><Wrench aria-hidden /></span><div><h2 id="backup-install-title">Review {target}</h2><p id="backup-install-desc" className="oars-modal-subtitle">This frozen plan names the commands, privilege, effects, and rollback before any server mutation.</p></div><Button variant="ghost" size="icon-sm" aria-label="Close" onClick={onClose} disabled={flow.busy}><X aria-hidden /></Button></div></header>
        <div className="oars-modal-body">
          <dl className="backups-install-facts"><div><dt>Target</dt><dd>{flow.plan.target.replaceAll("_", " ")}</dd></div><div><dt>Privilege</dt><dd>{flow.plan.privilege}</dd></div></dl>
          <div className="backups-review-list"><strong>{flow.plan.manual ? "Manual instructions" : "Commands after approval"}</strong><ol>{flow.plan.commands.map((command) => <li key={command}><code>{command}</code></li>)}</ol></div>
          {flow.plan.effects.length > 0 ? <div className="backups-review-list"><strong>Expected effects</strong><ul>{flow.plan.effects.map((effect) => <li key={effect}>{effect}</li>)}</ul></div> : null}
          {flow.plan.rollback.length > 0 ? <div className="backups-review-list"><strong>Rollback</strong><ul>{flow.plan.rollback.map((step) => <li key={step}>{step}</li>)}</ul></div> : null}
          {flow.plan.manual ? <div className="backups-warning"><AlertTriangle aria-hidden /><span>Oars will not execute an unverified adapter. Follow the manual instructions on the server.</span></div> : null}
          <footer className="oars-modal-actions oars-modal-footer"><div className="oars-modal-actions-right"><Button id="backup-install-close" variant="ghost" onClick={onClose} disabled={flow.busy}>{flow.plan.manual ? "Close" : "Cancel"}</Button>{!flow.plan.manual ? <Button id="backup-install-confirm" onClick={onConfirm} disabled={flow.busy}>{flow.busy ? <LoaderCircle className="spin" aria-hidden /> : <Wrench aria-hidden />}Approve {target}</Button> : null}</div></footer>
        </div>
      </div>
    </ApplicationOverlay>
  );
}
