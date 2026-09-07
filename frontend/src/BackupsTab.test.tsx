// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BackupsTab } from "./BackupsTab";
import { ProtectionBackupsPanel } from "./App";
import type { BackupJob, BackupOperation, BackupPollResult, BackupServerStatus, Server } from "./types";

const PLANNED_JOB: BackupJob = {
  id: "job-planned",
  server_id: "server-one",
  revision: 1,
  name: "New protected job",
  source_path: "/var/www",
  destination: {
    type: "s3",
    provider: "aws",
    bucket: "archive-bucket",
    prefix: "",
    endpoint: "",
    region: "us-east-1",
    credential_mode: "access_key",
    storage_class: "",
  },
  transfer: "copy",
  schedule: { mode: "manual", enabled: false },
  created_at_ms: 1_750_000_000_000,
  updated_at_ms: 1_750_000_000_000,
};

const ACCESS_JOB: BackupJob = {
  ...PLANNED_JOB,
  id: "job-access",
  revision: 5,
  name: "Protected archive",
  updated_at_ms: 1_750_000_050_000,
};

const SYNC_JOB: BackupJob = {
  ...PLANNED_JOB,
  id: "job-sync",
  revision: 4,
  name: "Production mirror",
  destination: { ...PLANNED_JOB.destination, credential_mode: "aws_runtime" },
  transfer: "sync",
  updated_at_ms: 1_750_000_100_000,
};

const SCHEDULED_SYNC_JOB: BackupJob = {
  ...SYNC_JOB,
  schedule: { mode: "custom", enabled: true, expr: "0 2 * * *" },
};

const STATUS: BackupServerStatus = {
  observed_at_ms: 1_750_000_200_000,
  os: "Ubuntu 24.04",
  arch: "x86_64",
  user: "ubuntu",
  home: "/home/ubuntu",
  timezone: "UTC",
  rclone_path: "/usr/bin/rclone",
  rclone_version: "1.70.0",
  crontab_implementation: "crontab",
  cron_installed: true,
  cron_running: true,
  service_manager: "systemd",
  scheduler_supported: true,
  process_groups: true,
  target: "ubuntu",
  privilege: "sudo",
  warnings: [],
};

const SERVER: Server = {
  id: "server-one",
  name: "Production",
  host: "prod.internal",
  port: 22,
  user: "ubuntu",
  auth_method: "key",
  key_path: "~/.ssh/id_ed25519",
  key_has_passphrase: false,
  host_fingerprint: "SHA256:server",
  group: "production",
  tags: [],
  via_server_id: null,
  created_at: 1_750_000_000_000,
  updated_at: 1_750_000_000_000,
};

interface BridgeCall {
  command: string;
  payload: unknown;
}

function objectProperty(value: unknown, key: string): unknown {
  if (typeof value !== "object" || value === null) return undefined;
  return Reflect.get(value, key);
}

function stringProperty(value: unknown, key: string): string | undefined {
  const property = objectProperty(value, key);
  return typeof property === "string" ? property : undefined;
}

function operation(operationId: string, kind: BackupOperation["kind"]): BackupOperation {
  const base = {
    ok: true as const,
    operation_id: operationId,
    state: "done" as const,
    steps: [],
    started_at_ms: 1_750_000_000_000,
    finished_at_ms: 1_750_000_000_100,
  };
  if (kind === "refresh") return { ...base, kind, result: { status: STATUS, imported: 0, warnings: 0 } };
  if (kind === "test") return {
    ...base,
    kind,
    result: {
      checks: { list: "passed", write: "passed", read: "passed", delete: "passed", cleanup_verify: "passed" },
      capability_proof: { id: "proof-one", expires_at_ms: 1_750_000_300_000, binding_sha256: "binding" },
    },
  };
  if (kind === "save" || kind === "delete") return { ...base, kind, result: { job_id: PLANNED_JOB.id } };
  if (kind === "install") return { ...base, kind, result: { target: "ubuntu", what: "rclone", partial_effects: false } };
  return { ...base, kind, result: { cleanup: "complete" } };
}

function installBridge(options: {
  jobs?: BackupJob[];
  plannedJob?: BackupJob;
  status?: BackupServerStatus | null;
  failSave?: boolean;
  failRun?: boolean;
  failTest?: boolean;
  failCredentialSetAccount?: string;
  failCredentialDeleteAccount?: string;
  keepRefreshRunning?: boolean;
  keepTestRunning?: boolean;
  keepSaveRunning?: boolean;
  testCleanupFailed?: boolean;
  requiresRemoteSecret?: boolean;
  malformedStatus?: boolean;
  pollResult?: BackupPollResult;
  deleteEffects?: string[];
  installManual?: boolean;
  installTarget?: string;
  recoveryError?: string;
} = {}): { calls: BridgeCall[]; secrets: Map<string, string> } {
  const calls: BridgeCall[] = [];
  const secrets = new Map<string, string>();
  const operationKinds = new Map<string, BackupOperation["kind"]>();
  const plannedJob = options.plannedJob ?? PLANNED_JOB;
  let credentialSetFailures = options.failCredentialSetAccount === undefined ? 0 : 1;
  let credentialDeleteFailures = options.failCredentialDeleteAccount === undefined ? 0 : 1;
  let cleanupRetryAdmitted = false;
  let jobs = options.jobs ?? [];

  window.zero = {
    invoke: vi.fn(async (command: string, payload: unknown) => {
      calls.push({ command, payload });
      if (command === "native-sdk.credentials.get") {
        const account = stringProperty(payload, "account");
        return account === undefined ? null : secrets.get(account) ?? null;
      }
      if (command === "native-sdk.credentials.set") {
        const account = stringProperty(payload, "account");
        const secret = stringProperty(payload, "secret");
        if (account === options.failCredentialSetAccount && credentialSetFailures > 0) {
          credentialSetFailures -= 1;
          return { ok: false, code: "internal", error: "Keychain write failed", retryable: true };
        }
        if (account !== undefined && secret !== undefined) secrets.set(account, secret);
        return { ok: true };
      }
      if (command === "native-sdk.credentials.delete") {
        const account = stringProperty(payload, "account");
        if (account === options.failCredentialDeleteAccount && credentialDeleteFailures > 0) {
          credentialDeleteFailures -= 1;
          return { ok: false, code: "internal", error: "Keychain delete failed", retryable: true };
        }
        if (account !== undefined) secrets.delete(account);
        return { ok: true };
      }
      if (command === "oars.backup.jobs.list") return {
        ok: true,
        jobs,
        ...(options.recoveryError === undefined ? {} : { recovery_error: options.recoveryError }),
      };
      if (command === "oars.backup.status") return options.malformedStatus
        ? { ok: true, status: {}, stale: false }
        : {
            ok: true,
            status: options.status ?? null,
            stale: options.status === undefined,
            ...(options.recoveryError === undefined ? {} : { recovery_error: options.recoveryError }),
          };
      if (command === "oars.backup.refresh") {
        const operationId = stringProperty(payload, "operation_id") ?? "refresh-one";
        operationKinds.set(operationId, "refresh");
        return { ok: true, operation_id: operationId };
      }
      if (command === "oars.backup.jobs.plan") {
        return {
          ok: true,
          plan_id: "plan-one",
          expires_at_ms: 1_750_000_300_000,
          job: plannedJob,
          requires_connection_test: false,
          requires_remote_secret: options.requiresRemoteSecret ?? false,
          effects: ["Save the local job record"],
          warnings: [],
        };
      }
      if (command === "oars.backup.jobs.save") {
        if (options.failSave) return { ok: false, code: "conflict", error: "revision mismatch", retryable: true };
        const operationId = stringProperty(payload, "operation_id") ?? "save-one";
        operationKinds.set(operationId, "save");
        jobs = [plannedJob];
        return { ok: true, operation_id: operationId, job_id: plannedJob.id };
      }
      if (command === "oars.backup.jobs.deletePlan") {
        return {
          ok: true,
          plan_id: "delete-plan-one",
          expires_at_ms: 1_750_000_300_000,
          job_name: SYNC_JOB.name,
          effects: options.deleteEffects ?? ["Remove the Oars schedule and local job record"],
          leftovers: ["/home/ubuntu/.local/state/oars/backups/job-sync"],
        };
      }
      if (command === "oars.backup.jobs.delete") {
        const operationId = stringProperty(payload, "operation_id") ?? "delete-one";
        operationKinds.set(operationId, "delete");
        jobs = [];
        return { ok: true, operation_id: operationId };
      }
      if (command === "oars.backup.run") {
        if (options.failRun) return { ok: false, code: "busy", error: "another run is active", retryable: true };
        return { ok: true, run_id: "run-one" };
      }
      if (command === "oars.backup.poll") {
        return options.pollResult ?? {
          ok: true,
          run_id: "run-one",
          status: "no_changes",
          phase: "finished",
          bytes_done: 0,
          bytes_total: 0,
          files_done: 0,
          files_total: 0,
          speed_bps: 0,
          eta_sec: 0,
          started_at_ms: 1_750_000_000_000,
          finished_at_ms: 1_750_000_000_100,
          log_cursor: 0,
          log_delta: "",
          dropped: 0,
          cleanup_state: "complete",
        } satisfies BackupPollResult;
      }
      if (command === "oars.backup.history") return {
        ok: true,
        runs: [],
        ...(options.recoveryError === undefined ? {} : { recovery_error: options.recoveryError }),
      };
      if (command === "oars.backup.historyLog") return { ok: true, cursor: 0, delta: "", eof: true, dropped: 0 };
      if (command === "oars.backup.operationPoll") {
        const operationId = stringProperty(payload, "operation_id") ?? "refresh-one";
        const kind = operationKinds.get(operationId) ?? "refresh";
        if (kind === "test" && options.testCleanupFailed) {
          if (cleanupRetryAdmitted) {
            return {
              ok: true,
              operation_id: operationId,
              kind: "cleanup",
              state: "done",
              steps: [{ id: "cleanup", state: "done" }, { id: "cleanup_verify", state: "done" }],
              started_at_ms: 1_750_000_000_000,
              finished_at_ms: 1_750_000_000_200,
              result: { cleanup: "complete", remote_object: "archive-bucket/oars-sentinel" },
            };
          }
          return {
            ok: true,
            operation_id: operationId,
            kind: "test",
            state: "partial",
            steps: [{ id: "cleanup_verify", state: "failed", error: { ok: false, code: "cleanup_failed", error: "sentinel remains", retryable: true, detail: { remote_object: "archive-bucket/oars-sentinel" } } }],
            started_at_ms: 1_750_000_000_000,
            finished_at_ms: 1_750_000_000_100,
            result: { cleanup: "required", retry_action: "operationCancel", needs_credentials: true, job_id: plannedJob.id },
            error: { ok: false, code: "cleanup_failed", error: "sentinel remains", retryable: true, detail: { remote_object: "archive-bucket/oars-sentinel" } },
          };
        }
        if ((kind === "refresh" && options.keepRefreshRunning) || (kind === "test" && options.keepTestRunning) || (kind === "save" && options.keepSaveRunning)) {
          return { ...operation(operationId, kind), state: "running", finished_at_ms: undefined, result: undefined };
        }
        return operation(operationId, kind);
      }
      if (command === "oars.backup.operationCancel") {
        cleanupRetryAdmitted = true;
        return { ok: true };
      }
      if (command === "oars.backup.cancel") return { ok: true };
      if (command === "oars.backup.install.plan") {
        return {
          ok: true,
          plan_id: "install-one",
          expires_at_ms: 1_750_000_300_000,
          target: options.installTarget ?? "ubuntu",
          privilege: options.installManual ? "none" : "root",
          commands: options.installManual ? [] : ["apt-get install rclone"],
          effects: [options.installManual ? "Follow the target installation guide manually" : "Install rclone"],
          rollback: [],
          manual: options.installManual ?? false,
        };
      }
      if (command === "oars.backup.install") {
        const operationId = stringProperty(payload, "operation_id") ?? "install-one";
        operationKinds.set(operationId, "install");
        return { ok: true, operation_id: operationId };
      }
      if (command === "oars.backup.test.plan") {
        return { ok: true, test_plan_id: "test-one", expires_at_ms: 1_750_000_300_000, remote_object: "archive-bucket/oars-sentinel", checks: ["list", "write", "read", "delete", "cleanup_verify"], mutates: true };
      }
      if (command === "oars.backup.test") {
        if (options.failTest) return { ok: false, code: "invalid_credentials", error: "credentials rejected", retryable: false };
        const operationId = stringProperty(payload, "operation_id") ?? "test-one";
        operationKinds.set(operationId, "test");
        return { ok: true, operation_id: operationId };
      }
      throw new Error(`Unexpected bridge command: ${command}`);
    }),
  };
  return { calls, secrets };
}

function callsFor(calls: BridgeCall[], command: string): BridgeCall[] {
  return calls.filter((call) => call.command === command);
}

let uuidCounter = 0;

beforeEach(() => {
  uuidCounter = 0;
  vi.stubGlobal("crypto", { randomUUID: vi.fn(() => `00000000-0000-4000-8000-${String(++uuidCounter).padStart(12, "0")}`) });
});

afterEach(() => {
  cleanup();
  delete window.zero;
  delete document.documentElement.dataset.previewVariant;
  window.history.replaceState({}, "", "/");
  vi.unstubAllGlobals();
});

describe("BackupsTab protected workflows", () => {
  it("shows truthful disconnected and empty states without starting a refresh", async () => {
    const { calls } = installBridge();
    render(<BackupsTab serverId="server-one" connected={false} />);

    expect(await screen.findByText("No backup jobs yet")).toBeTruthy();
    expect(screen.getByText("Server disconnected")).toBeTruthy();
    expect(callsFor(calls, "oars.backup.refresh")).toHaveLength(0);
    expect(screen.getByRole("button", { name: "Refresh runtime" }).hasAttribute("disabled")).toBe(true);
  });

  it("plans before save and stores the backend-allocated job credentials before commit", async () => {
    const { calls, secrets } = installBridge();
    render(<BackupsTab serverId="server-one" connected />);
    await screen.findByText("No backup jobs yet");

    fireEvent.click(screen.getByRole("button", { name: "New backup job" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "New protected job" } });
    fireEvent.change(screen.getByLabelText("Bucket"), { target: { value: "archive-bucket" } });
    fireEvent.click(screen.getByRole("button", { name: "Review job" }));

    expect(await screen.findByText("Frozen review")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Access key"), { target: { value: "AKIA_TEST" } });
    fireEvent.change(screen.getByLabelText("Secret key"), { target: { value: "secret-value" } });
    fireEvent.click(screen.getByRole("button", { name: "Save reviewed job" }));

    await waitFor(() => expect(callsFor(calls, "oars.backup.jobs.save")).toHaveLength(1));
    const planIndex = calls.findIndex((call) => call.command === "oars.backup.jobs.plan");
    const keyIndex = calls.findIndex((call) => call.command === "native-sdk.credentials.set");
    const saveIndex = calls.findIndex((call) => call.command === "oars.backup.jobs.save");
    expect(planIndex).toBeGreaterThanOrEqual(0);
    expect(keyIndex).toBeGreaterThan(planIndex);
    expect(saveIndex).toBeGreaterThan(keyIndex);
    expect(secrets.has("backup:job-planned")).toBe(true);

    const savePayload = callsFor(calls, "oars.backup.jobs.save")[0].payload;
    expect(stringProperty(savePayload, "plan_id")).toBe("plan-one");
    expect(objectProperty(savePayload, "job")).toBeUndefined();
  });

  it("rolls back a new Keychain entry when save admission fails", async () => {
    const { calls, secrets } = installBridge({ failSave: true, requiresRemoteSecret: true });
    render(<BackupsTab serverId="server-one" connected />);
    await screen.findByText("No backup jobs yet");

    fireEvent.click(screen.getByRole("button", { name: "New backup job" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "New protected job" } });
    fireEvent.change(screen.getByLabelText("Bucket"), { target: { value: "archive-bucket" } });
    fireEvent.click(screen.getByRole("button", { name: "Review job" }));
    await screen.findByText("Frozen review");
    fireEvent.change(screen.getByLabelText("Access key"), { target: { value: "AKIA_TEST" } });
    fireEvent.change(screen.getByLabelText("Secret key"), { target: { value: "secret-value" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /Approve unattended credential copy/ }));
    fireEvent.click(screen.getByRole("button", { name: "Save reviewed job" }));

    expect(await screen.findByText("This backup job changed elsewhere. Refresh it before trying again.")).toBeTruthy();
    expect(screen.getByLabelText("Access key")).toHaveProperty("value", "");
    expect(screen.getByLabelText("Secret key")).toHaveProperty("value", "");
    await waitFor(() => expect(callsFor(calls, "native-sdk.credentials.delete").length).toBeGreaterThan(0));
    expect(secrets.has("backup:job-planned")).toBe(false);
    const scheduleCredentials = objectProperty(callsFor(calls, "oars.backup.jobs.save")[0].payload, "schedule_credentials");
    expect(stringProperty(scheduleCredentials, "access_key")).toBe("");
    expect(stringProperty(scheduleCredentials, "secret_key")).toBe("");
    expect(screen.queryByText(/^conflict:/i)).toBeNull();
  });

  it("requires exact Sync and delete confirmations and removes Keychain only after delete completes", async () => {
    const { calls } = installBridge({ jobs: [SYNC_JOB] });
    render(<BackupsTab serverId="server-one" connected />);
    expect(await screen.findByText("Production mirror")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Run now" }));
    const runDialog = screen.getByRole("dialog");
    const runButton = within(runDialog).getByRole("button", { name: "Run now" });
    expect(runButton.hasAttribute("disabled")).toBe(true);
    fireEvent.change(screen.getByLabelText(/Type Production mirror to confirm/), { target: { value: "Production mirror" } });
    expect(runButton.hasAttribute("disabled")).toBe(false);
    fireEvent.click(runButton);

    await waitFor(() => expect(callsFor(calls, "oars.backup.run")).toHaveLength(1));
    const runPayload = callsFor(calls, "oars.backup.run")[0].payload;
    expect(stringProperty(runPayload, "confirm_job_name")).toBe("Production mirror");

    fireEvent.click(screen.getByRole("button", { name: "Delete Production mirror" }));
    expect(await screen.findByRole("heading", { name: "Delete Production mirror?" })).toBeTruthy();
    expect(callsFor(calls, "oars.backup.jobs.deletePlan")).toHaveLength(1);
    const deleteButton = screen.getByRole("button", { name: "Delete reviewed job" });
    expect(deleteButton.hasAttribute("disabled")).toBe(true);
    fireEvent.change(screen.getByLabelText(/Type Production mirror to confirm/), { target: { value: "Production mirror" } });
    fireEvent.click(deleteButton);

    await waitFor(() => expect(callsFor(calls, "native-sdk.credentials.delete")).toHaveLength(1));
    const deleteAdmissionIndex = calls.findIndex((call) => call.command === "oars.backup.jobs.delete");
    const deletePollIndex = calls.findIndex((call, index) => index > deleteAdmissionIndex && call.command === "oars.backup.operationPoll");
    const keyDeleteIndex = calls.findIndex((call, index) => index > deleteAdmissionIndex && call.command === "native-sdk.credentials.delete");
    expect(deletePollIndex).toBeGreaterThan(deleteAdmissionIndex);
    expect(keyDeleteIndex).toBeGreaterThan(deletePollIndex);
  });

  it("sends the exact scheduled Sync approval in the reviewed save envelope", async () => {
    const { calls } = installBridge({ jobs: [SCHEDULED_SYNC_JOB], plannedJob: SCHEDULED_SYNC_JOB });
    render(<BackupsTab serverId="server-one" connected />);
    expect(await screen.findByText("Production mirror")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    fireEvent.click(screen.getByRole("button", { name: "Review job" }));
    expect(await screen.findByText("Frozen review")).toBeTruthy();

    const confirmation = screen.getByLabelText(/approve scheduled destination deletions/i);
    fireEvent.change(confirmation, { target: { value: "Production mirror" } });
    fireEvent.click(screen.getByRole("button", { name: "Save reviewed job" }));

    await waitFor(() => expect(callsFor(calls, "oars.backup.jobs.save")).toHaveLength(1));
    expect(stringProperty(callsFor(calls, "oars.backup.jobs.save")[0].payload, "confirm_job_name")).toBe("Production mirror");
  });

  it("zeros scheduled credentials immediately after save admission while the operation is still running", async () => {
    const { calls } = installBridge({ keepSaveRunning: true, requiresRemoteSecret: true });
    render(<BackupsTab serverId="server-one" connected />);
    await screen.findByText("No backup jobs yet");

    fireEvent.click(screen.getByRole("button", { name: "New backup job" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "New protected job" } });
    fireEvent.change(screen.getByLabelText("Bucket"), { target: { value: "archive-bucket" } });
    fireEvent.click(screen.getByRole("button", { name: "Review job" }));
    await screen.findByText("Frozen review");
    fireEvent.change(screen.getByLabelText("Access key"), { target: { value: "AKIA_TEST" } });
    fireEvent.change(screen.getByLabelText("Secret key"), { target: { value: "secret-value" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /Approve unattended credential copy/ }));
    fireEvent.click(screen.getByRole("button", { name: "Save reviewed job" }));

    await waitFor(() => expect(callsFor(calls, "oars.backup.jobs.save")).toHaveLength(1));
    const credentials = objectProperty(callsFor(calls, "oars.backup.jobs.save")[0].payload, "schedule_credentials");
    expect(stringProperty(credentials, "access_key")).toBe("");
    expect(stringProperty(credentials, "secret_key")).toBe("");
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("does not retry a protected run through a legacy payload after typed rejection", async () => {
    const { calls } = installBridge({ jobs: [SYNC_JOB], failRun: true });
    render(<BackupsTab serverId="server-one" connected />);
    expect(await screen.findByText("Production mirror")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Run now" }));
    const runDialog = screen.getByRole("dialog");
    fireEvent.change(within(runDialog).getByLabelText(/Type Production mirror to confirm/), { target: { value: "Production mirror" } });
    fireEvent.click(within(runDialog).getByRole("button", { name: "Run now" }));

    expect(await screen.findByText(/Another backup operation is already running/)).toBeTruthy();
    expect(callsFor(calls, "oars.backup.run")).toHaveLength(1);
    const payload = callsFor(calls, "oars.backup.run")[0].payload;
    expect(typeof stringProperty(payload, "operation_id")).toBe("string");
    expect(objectProperty(payload, "expected_revision")).toBe(4);
  });

  it("retains a pending replacement when Keychain promotion fails and retries safely", async () => {
    const plannedJob: BackupJob = { ...ACCESS_JOB, revision: 6, updated_at_ms: 1_750_000_200_000 };
    const { calls, secrets } = installBridge({
      jobs: [ACCESS_JOB],
      plannedJob,
      failCredentialSetAccount: "backup:job-access",
    });
    secrets.set("backup:job-access", JSON.stringify({ access_key: "OLD", secret_key: "old-secret" }));
    render(<BackupsTab serverId="server-one" connected />);
    expect(await screen.findByText("Protected archive")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    fireEvent.click(screen.getByRole("button", { name: "Review job" }));
    await screen.findByText("Frozen review");
    fireEvent.change(screen.getByLabelText("Access key"), { target: { value: "NEW" } });
    fireEvent.change(screen.getByLabelText("Secret key"), { target: { value: "new-secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Save reviewed job" }));

    expect(await screen.findByText("Credential activation needs attention")).toBeTruthy();
    const pendingAccount = "backup-pending:job-access:plan-one";
    expect(secrets.get("backup:job-access")).toContain("OLD");
    expect(secrets.get(pendingAccount)).toContain("NEW");
    const pendingDeletesBeforeRetry = callsFor(calls, "native-sdk.credentials.delete")
      .filter((call) => stringProperty(call.payload, "account") === pendingAccount);
    expect(pendingDeletesBeforeRetry).toHaveLength(0);

    fireEvent.click(screen.getByRole("button", { name: "Retry credential activation" }));
    await waitFor(() => expect(screen.queryByText("Credential activation needs attention")).toBeNull());
    expect(secrets.get("backup:job-access")).toContain("NEW");
    expect(secrets.has(pendingAccount)).toBe(false);
  });

  it("removes an obsolete primary credential only after an access-key job commits to AWS runtime", async () => {
    const runtimeJob: BackupJob = {
      ...ACCESS_JOB,
      revision: 6,
      destination: { ...ACCESS_JOB.destination, credential_mode: "aws_runtime" },
      updated_at_ms: 1_750_000_200_000,
    };
    const { calls, secrets } = installBridge({
      jobs: [ACCESS_JOB],
      plannedJob: runtimeJob,
      failCredentialDeleteAccount: "backup:job-access",
    });
    secrets.set("backup:job-access", JSON.stringify({ access_key: "OLD", secret_key: "old-secret" }));
    render(<BackupsTab serverId="server-one" connected />);
    expect(await screen.findByText("Protected archive")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    fireEvent.click(screen.getByRole("button", { name: "Review job" }));
    await screen.findByText("Frozen review");
    fireEvent.click(screen.getByRole("button", { name: "Save reviewed job" }));

    expect(await screen.findByText("Credential cleanup needs attention")).toBeTruthy();
    const saveIndex = calls.findIndex((call) => call.command === "oars.backup.jobs.save");
    const terminalIndex = calls.findIndex((call, index) => index > saveIndex && call.command === "oars.backup.operationPoll");
    const credentialDeleteIndex = calls.findIndex((call, index) => index > saveIndex && call.command === "native-sdk.credentials.delete");
    expect(terminalIndex).toBeGreaterThan(saveIndex);
    expect(credentialDeleteIndex).toBeGreaterThan(terminalIndex);
    expect(secrets.has("backup:job-access")).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "Retry credential cleanup" }));
    await waitFor(() => expect(secrets.has("backup:job-access")).toBe(false));
  });

  it("clears test secrets after admission rejection and never sends a legacy fallback", async () => {
    const { calls } = installBridge({ failTest: true });
    render(<BackupsTab serverId="server-one" connected />);
    await screen.findByText("No backup jobs yet");

    fireEvent.click(screen.getByRole("button", { name: "New backup job" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "New protected job" } });
    fireEvent.change(screen.getByLabelText("Bucket"), { target: { value: "archive-bucket" } });
    fireEvent.click(screen.getByRole("button", { name: "Review job" }));
    await screen.findByText("Frozen review");
    fireEvent.change(screen.getByLabelText("Access key"), { target: { value: "AKIA_TEST" } });
    fireEvent.change(screen.getByLabelText("Secret key"), { target: { value: "secret-value" } });
    fireEvent.click(screen.getByRole("button", { name: "Review connection test" }));
    await screen.findByText(/temporarily mutate this exact object/i);
    fireEvent.click(screen.getByRole("button", { name: "Approve and run test" }));

    expect(await screen.findByText(/storage credentials were not accepted/i)).toBeTruthy();
    expect(screen.getByLabelText("Access key")).toHaveProperty("value", "");
    expect(screen.getByLabelText("Secret key")).toHaveProperty("value", "");
    expect(callsFor(calls, "oars.backup.test")).toHaveLength(1);
    const credentials = objectProperty(callsFor(calls, "oars.backup.test")[0].payload, "credentials");
    expect(stringProperty(credentials, "access_key")).toBe("");
    expect(stringProperty(credentials, "secret_key")).toBe("");
  });

  it("zeros loaded run credentials after a typed admission rejection", async () => {
    const { calls, secrets } = installBridge({ jobs: [ACCESS_JOB], failRun: true });
    secrets.set("backup:job-access", JSON.stringify({ access_key: "AKIA_RUN", secret_key: "run-secret" }));
    render(<BackupsTab serverId="server-one" connected />);
    expect(await screen.findByText("Protected archive")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Run now" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Run now" }));

    expect(await screen.findByText(/Another backup operation is already running/)).toBeTruthy();
    const credentials = objectProperty(callsFor(calls, "oars.backup.run")[0].payload, "credentials");
    expect(stringProperty(credentials, "access_key")).toBe("");
    expect(stringProperty(credentials, "secret_key")).toBe("");
  });

  it("offers keyboard-reachable cancellation while a connection test is active", async () => {
    const { calls } = installBridge({ keepTestRunning: true });
    render(<BackupsTab serverId="server-one" connected />);
    await screen.findByText("No backup jobs yet");

    fireEvent.click(screen.getByRole("button", { name: "New backup job" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "New protected job" } });
    fireEvent.change(screen.getByLabelText("Bucket"), { target: { value: "archive-bucket" } });
    fireEvent.click(screen.getByRole("button", { name: "Review job" }));
    await screen.findByText("Frozen review");
    fireEvent.change(screen.getByLabelText("Access key"), { target: { value: "AKIA_TEST" } });
    fireEvent.change(screen.getByLabelText("Secret key"), { target: { value: "secret-value" } });
    fireEvent.click(screen.getByRole("button", { name: "Review connection test" }));
    await screen.findByText(/temporarily mutate this exact object/i);
    fireEvent.click(screen.getByRole("button", { name: "Approve and run test" }));

    const dialog = screen.getByRole("dialog");
    const cancelTest = await within(dialog).findByRole("button", { name: "Cancel connection test" });
    const credentials = objectProperty(callsFor(calls, "oars.backup.test")[0].payload, "credentials");
    expect(stringProperty(credentials, "access_key")).toBe("");
    expect(stringProperty(credentials, "secret_key")).toBe("");
    expect(within(dialog).getByRole("button", { name: "Close" }).hasAttribute("disabled")).toBe(true);
    cancelTest.focus();
    expect(document.activeElement).toBe(cancelTest);
    fireEvent.click(cancelTest);

    await waitFor(() => expect(callsFor(calls, "oars.backup.operationCancel")).toHaveLength(1));
    expect(await within(dialog).findByText(/request was accepted/i)).toBeTruthy();
    const close = within(dialog).getByRole("button", { name: "Close" });
    expect(close.hasAttribute("disabled")).toBe(false);
    fireEvent.click(close);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("retries an exact partial test cleanup with fresh Keychain credentials and clears them after admission", async () => {
    const { calls } = installBridge({ testCleanupFailed: true });
    render(<BackupsTab serverId="server-one" connected />);
    await screen.findByText("No backup jobs yet");

    fireEvent.click(screen.getByRole("button", { name: "New backup job" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "New protected job" } });
    fireEvent.change(screen.getByLabelText("Bucket"), { target: { value: "archive-bucket" } });
    fireEvent.click(screen.getByRole("button", { name: "Review job" }));
    await screen.findByText("Frozen review");
    fireEvent.change(screen.getByLabelText("Access key"), { target: { value: "AKIA_TEST" } });
    fireEvent.change(screen.getByLabelText("Secret key"), { target: { value: "secret-value" } });
    fireEvent.click(screen.getByRole("button", { name: "Review connection test" }));
    await screen.findByText(/temporarily mutate this exact object/i);
    fireEvent.click(screen.getByRole("button", { name: "Approve and run test" }));

    expect(await screen.findByText("archive-bucket/oars-sentinel")).toBeTruthy();
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).queryByRole("button", { name: "Cancel connection test" })).toBeNull();
    expect(within(dialog).getByRole("button", { name: "Close" }).hasAttribute("disabled")).toBe(false);
    expect(within(dialog).getAllByText("Verify the sentinel is gone")).toHaveLength(2);
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    const retry = within(dialog).getByRole("button", { name: "Retry cleanup" });
    expect(retry.hasAttribute("disabled")).toBe(false);
    fireEvent.click(retry);

    await waitFor(() => expect(callsFor(calls, "oars.backup.operationCancel")).toHaveLength(1));
    const credentials = objectProperty(callsFor(calls, "oars.backup.operationCancel")[0].payload, "credentials");
    expect(stringProperty(credentials, "access_key")).toBe("");
    expect(stringProperty(credentials, "secret_key")).toBe("");
    expect(await within(dialog).findByText("Cleanup completed")).toBeTruthy();
  });

  it("deduplicates one recovered-store fault across jobs, status, and history alerts", async () => {
    installBridge({
      jobs: [ACCESS_JOB],
      status: STATUS,
      recoveryError: "one partial import was quarantined",
    });
    render(<BackupsTab serverId="server-one" connected />);

    await screen.findByText("Protected archive");
    await waitFor(() => expect(screen.getAllByRole("alert").map((alert) => alert.textContent)).toEqual([
      "Backup state needs attentionSome local backup records need attention. one partial import was quarantined",
    ]));
  });

  it("renders flat runtime status defensively without inventing an unsupported cleanup mutation", async () => {
    installBridge({ status: { ...STATUS, warnings: ["A staged run could not be imported or cleaned"] } });
    render(<BackupsTab serverId="server-one" connected />);

    expect(await screen.findByText("1.70.0")).toBeTruthy();
    expect(screen.getByText("ubuntu")).toBeTruthy();
    expect(screen.getByText("crontab")).toBeTruthy();
    expect(screen.getByText("A staged run could not be imported or cleaned")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Retry cleanup" })).toBeNull();
    expect(screen.getByText(/Resolve the named item on the server/)).toBeTruthy();
  });

  it("marks runtime readiness as needing attention when an enabled schedule has stopped cron", async () => {
    installBridge({ jobs: [SCHEDULED_SYNC_JOB], status: { ...STATUS, cron_running: false } });
    render(<BackupsTab serverId="server-one" connected />);

    expect(await screen.findByText("Cron stopped")).toBeTruthy();
    expect(screen.getByText("Needs attention")).toBeTruthy();
    expect(screen.queryByText("Ready")).toBeNull();
  });

  it("shows the exact backend-reviewed effects before delete approval", async () => {
    installBridge({
      jobs: [SYNC_JOB],
      deleteEffects: ["Remove wrapper /exact/run.sh", "Remove only the marked crontab block"],
    });
    render(<BackupsTab serverId="server-one" connected />);
    expect(await screen.findByText("Production mirror")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Delete Production mirror" }));
    expect(await screen.findByText("Remove wrapper /exact/run.sh")).toBeTruthy();
    expect(screen.getByText("Remove only the marked crontab block")).toBeTruthy();
  });

  it("does not dereference missing fields in an incomplete cached status", async () => {
    installBridge({ malformedStatus: true });
    render(<BackupsTab serverId="server-one" connected />);

    expect(await screen.findByRole("heading", { name: "Runtime readiness" })).toBeTruthy();
    expect(screen.getByText("Not available")).toBeTruthy();
    expect(screen.getByText("Unsupported")).toBeTruthy();
    expect(screen.getByText("This runtime does not currently report verified scheduler support.")).toBeTruthy();
  });

  it("preserves terminal run failure detail and cleanup state", async () => {
    const failure: BackupPollResult = {
      ok: true,
      run_id: "run-one",
      status: "partial",
      phase: "finished",
      bytes_done: 512,
      bytes_total: 1_024,
      files_done: 1,
      files_total: 2,
      speed_bps: 0,
      eta_sec: 0,
      started_at_ms: 1_750_000_000_000,
      finished_at_ms: 1_750_000_001_000,
      log_cursor: 9,
      log_delta: "cleanup failed\n",
      dropped: 0,
      cleanup_state: "failed",
      error: {
        ok: false,
        code: "cleanup_failed",
        error: "Temporary backup state could not be removed.",
        retryable: true,
        detail: { path: "/home/ubuntu/.local/state/oars/backups/.manual/run-one" },
      },
    };
    const { calls } = installBridge({ jobs: [SYNC_JOB], pollResult: failure });
    render(<BackupsTab serverId="server-one" connected />);
    expect(await screen.findByText("Production mirror")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Run now" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText(/Type Production mirror to confirm/), { target: { value: "Production mirror" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Run now" }));

    expect(await screen.findByText("Temporary backup state could not be removed.")).toBeTruthy();
    expect(screen.getByText("/home/ubuntu/.local/state/oars/backups/.manual/run-one")).toBeTruthy();
    expect(screen.getByText("Failed")).toBeTruthy();
    expect(screen.getByText("Finished", { selector: "dd" })).toBeTruthy();
    expect(screen.getByText("1s", { selector: "dd" })).toBeTruthy();
    const retryCleanup = screen.getByRole("button", { name: "Retry cleanup" });
    expect(retryCleanup.hasAttribute("disabled")).toBe(false);
    fireEvent.click(retryCleanup);
    await waitFor(() => expect(callsFor(calls, "oars.backup.cancel")).toHaveLength(1));
  });

  it("shares one controller and poller across mounts until the final unmount", async () => {
    const { calls } = installBridge({ keepRefreshRunning: true });
    function SharedViews({ showFirst }: { showFirst: boolean }) {
      return <>{showFirst ? <BackupsTab key="first" serverId="server-one" connected /> : null}<BackupsTab key="second" serverId="server-one" connected /></>;
    }
    const view = render(<SharedViews showFirst />);

    await waitFor(() => expect(callsFor(calls, "oars.backup.operationPoll")).toHaveLength(1));
    expect(callsFor(calls, "oars.backup.jobs.list")).toHaveLength(1);
    expect(callsFor(calls, "oars.backup.refresh")).toHaveLength(1);

    view.rerender(<SharedViews showFirst={false} />);
    const pollsBeforeFirstUnmount = callsFor(calls, "oars.backup.operationPoll").length;
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 800));
    });
    expect(callsFor(calls, "oars.backup.operationPoll").length).toBeGreaterThan(pollsBeforeFirstUnmount);

    view.unmount();
    const pollsAfterFinalUnmount = callsFor(calls, "oars.backup.operationPoll").length;
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 800));
    });
    expect(callsFor(calls, "oars.backup.operationPoll")).toHaveLength(pollsAfterFinalUnmount);
  });
});

describe("ProtectionBackupsPanel", () => {
  it("turns the public backups query into an auto-selected R2 editor state", async () => {
    document.documentElement.dataset.previewVariant = "baseline";
    window.history.replaceState({}, "", "/preview.html?backups=editor-r2");
    const { calls } = installBridge({ status: STATUS });

    render(<ProtectionBackupsPanel servers={[SERVER]} statuses={new Map([[SERVER.id, "closed"]])} />);

    expect(await screen.findByRole("heading", { name: "Create backup job" })).toBeTruthy();
    const serverPicker = screen.getByLabelText("Backup server") as HTMLButtonElement;
    expect(serverPicker.textContent).toContain("Production");
    expect(serverPicker.textContent).toContain("Connected");
    expect(serverPicker.textContent).not.toContain("Offline");
    expect((screen.getByLabelText("Endpoint") as HTMLInputElement).value).toBe("https://r2.preview.invalid");
    expect(callsFor(calls, "oars.backup.jobs.list").length).toBeGreaterThanOrEqual(1);
  });

  it("opens the manual installation review from the public unsupported-target fixture", async () => {
    document.documentElement.dataset.previewVariant = "baseline";
    window.history.replaceState({}, "", "/preview.html?backups=unsupported-target");
    const { calls } = installBridge({ status: STATUS, installManual: true, installTarget: "unknown" });

    render(<ProtectionBackupsPanel servers={[SERVER]} statuses={new Map([[SERVER.id, "closed"]])} />);

    expect(await screen.findByRole("heading", { name: "Review install rclone" })).toBeTruthy();
    expect(screen.getByText("Oars will not execute an unverified adapter. Follow the manual instructions on the server.")).toBeTruthy();
    expect(callsFor(calls, "oars.backup.install.plan")).toHaveLength(1);
  });

  it("keeps only the disconnected preview server labeled Offline", async () => {
    document.documentElement.dataset.previewVariant = "baseline";
    window.history.replaceState({}, "", "/preview.html?backups=disconnected");
    installBridge();

    render(<ProtectionBackupsPanel servers={[SERVER]} statuses={new Map([[SERVER.id, "ready"]])} />);

    const serverPicker = await screen.findByLabelText("Backup server") as HTMLButtonElement;
    expect(serverPicker.textContent).toContain("Offline");
    expect(serverPicker.textContent).not.toContain("Connected");
    expect(await screen.findByText("Server disconnected")).toBeTruthy();
  });

  it("settles the public cleanup-failed test inside the modal and retries with fresh credentials", async () => {
    document.documentElement.dataset.previewVariant = "baseline";
    window.history.replaceState({}, "", "/preview.html?backups=test-cleanup-failed");
    const { calls, secrets } = installBridge({ status: STATUS, testCleanupFailed: true });
    secrets.set("backup:job-planned", JSON.stringify({
      version: 1,
      access_key: "AKIA_PREVIEW",
      secret_key: "preview-secret",
    }));

    render(<ProtectionBackupsPanel servers={[SERVER]} statuses={new Map([[SERVER.id, "closed"]])} />);

    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findAllByText("archive-bucket/oars-sentinel")).toHaveLength(2);
    expect(within(dialog).queryByRole("button", { name: "Cancel connection test" })).toBeNull();
    expect(within(dialog).getByRole("button", { name: "Close" }).hasAttribute("disabled")).toBe(false);
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    const retry = within(dialog).getByRole("button", { name: "Retry cleanup" });
    expect(retry.hasAttribute("disabled")).toBe(false);
    fireEvent.click(retry);

    await waitFor(() => expect(callsFor(calls, "oars.backup.operationCancel")).toHaveLength(1));
    expect(await within(dialog).findByText("Cleanup completed")).toBeTruthy();
  });

  it("does not operate on the first server until the user selects it", async () => {
    const user = userEvent.setup();
    const { calls } = installBridge();
    render(<ProtectionBackupsPanel servers={[SERVER]} statuses={new Map([[SERVER.id, "closed"]])} />);

    expect(screen.getByRole("heading", { name: "Select a server" })).toBeTruthy();
    expect(callsFor(calls, "oars.backup.jobs.list")).toHaveLength(0);

    await user.click(screen.getByRole("button", { name: "Open backups for Production" }));

    expect(await screen.findByText("Server disconnected")).toBeTruthy();
    expect(callsFor(calls, "oars.backup.jobs.list")).toHaveLength(1);
    expect(callsFor(calls, "oars.backup.refresh")).toHaveLength(0);
  });

  it("shows a dedicated no-server state", () => {
    installBridge();
    render(<ProtectionBackupsPanel servers={[]} statuses={new Map()} />);
    expect(screen.getByRole("heading", { name: "No servers available" })).toBeTruthy();
    expect(screen.getByRole("combobox", { name: "Backup server" }).hasAttribute("disabled")).toBe(true);
  });
});
