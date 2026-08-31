import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BackupController, humanizeBackupError, parseBackupCredentials, type BackupBridge } from "./backup-state";
import { BridgeError } from "./bridge";
import type {
  BackupHistoryResult,
  BackupJob,
  BackupJobsListResult,
  BackupOperation,
  BackupPollResult,
  BackupServerStatus,
  BackupStatusResult,
} from "./types";

const JOB: BackupJob = {
  id: "job-one",
  server_id: "server-one",
  revision: 3,
  name: "Daily site",
  source_path: "/srv/site",
  destination: {
    type: "s3",
    provider: "aws",
    bucket: "backups",
    prefix: "daily",
    endpoint: "",
    region: "us-east-1",
    credential_mode: "aws_runtime",
    storage_class: "",
  },
  transfer: "copy",
  schedule: { mode: "manual", enabled: false },
  created_at_ms: 1_750_000_000_000,
  updated_at_ms: 1_750_000_001_000,
};

const STATUS: BackupServerStatus = {
  observed_at_ms: 1_750_000_002_000,
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

const DONE_REFRESH: BackupOperation = {
  ok: true,
  operation_id: "refresh-one",
  kind: "refresh",
  state: "done",
  steps: [],
  started_at_ms: 1_750_000_000_000,
  finished_at_ms: 1_750_000_000_100,
};

const EMPTY_HISTORY: BackupHistoryResult = { ok: true, runs: [] };

function makeBridge(overrides: Partial<BackupBridge> = {}): BackupBridge {
  const bridge: BackupBridge = {
    list: async ({ server_id }) => ({ ok: true, jobs: server_id === JOB.server_id ? [JOB] : [] }),
    status: async () => ({ ok: true, status: STATUS, stale: false }),
    refresh: async () => ({ ok: true, operation_id: "refresh-one" }),
    jobsPlan: async () => ({
      ok: true,
      plan_id: "plan-one",
      expires_at_ms: 1_750_000_300_000,
      job: JOB,
      requires_connection_test: false,
      requires_remote_secret: false,
      effects: [],
      warnings: [],
    }),
    jobsSave: async () => ({ ok: true, operation_id: "save-one", job_id: JOB.id }),
    deletePlan: async () => ({ ok: true, plan_id: "delete-one", expires_at_ms: 1_750_000_300_000, job_name: JOB.name, effects: [], leftovers: [] }),
    delete: async () => ({ ok: true, operation_id: "delete-one" }),
    testPlan: async () => ({
      ok: true,
      test_plan_id: "test-plan-one",
      expires_at_ms: 1_750_000_300_000,
      remote_object: "backups/daily/oars-sentinel",
      checks: ["list", "write", "read", "delete", "cleanup_verify"],
      mutates: true,
    }),
    test: async () => ({ ok: true, operation_id: "test-one" }),
    run: async () => ({ ok: true, run_id: "run-one" }),
    poll: async () => ({
      ok: true,
      run_id: "run-one",
      status: "success",
      phase: "finished",
      bytes_done: 10,
      bytes_total: 10,
      files_done: 1,
      files_total: 1,
      speed_bps: 10,
      eta_sec: 0,
      started_at_ms: 1_750_000_000_000,
      finished_at_ms: 1_750_000_000_100,
      log_cursor: 0,
      log_delta: "",
      dropped: 0,
      cleanup_state: "complete",
    }),
    cancel: async () => ({ ok: true }),
    operationPoll: async () => DONE_REFRESH,
    operationCancel: async () => ({ ok: true }),
    history: async () => EMPTY_HISTORY,
    historyLog: async () => ({ ok: true, cursor: 0, delta: "", eof: true, dropped: 0 }),
    installPlan: async ({ what }) => ({ ok: true, plan_id: "install-one", expires_at_ms: 1_750_000_300_000, target: what, privilege: "root", commands: [], effects: [], rollback: [], manual: false }),
    install: async () => ({ ok: true, operation_id: "install-one" }),
    ...overrides,
  };
  return bridge;
}

async function flushPromises(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

describe("BackupController", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("ignores a stale list response after a server switch", async () => {
    let resolveOld: ((value: { ok: true; jobs: BackupJob[] }) => void) | undefined;
    const oldResponse = new Promise<{ ok: true; jobs: BackupJob[] }>((resolve) => {
      resolveOld = resolve;
    });
    const newJob: BackupJob = { ...JOB, id: "job-two", server_id: "server-two", name: "New server job" };
    const bridge = makeBridge({
      list: vi.fn(async ({ server_id }: { server_id: string }): Promise<BackupJobsListResult> => {
        if (server_id === "server-one") return oldResponse;
        return { ok: true, jobs: [newJob] };
      }),
      status: vi.fn(async (): Promise<BackupStatusResult> => ({ ok: true, status: STATUS, stale: false })),
    });
    const controller = new BackupController("server-one", false, bridge, () => "operation-one");

    controller.start();
    controller.setContext("server-two", false);
    await flushPromises();
    expect(controller.getSnapshot().jobs).toEqual([newJob]);

    resolveOld?.({ ok: true, jobs: [JOB] });
    await flushPromises();
    expect(controller.getSnapshot().serverId).toBe("server-two");
    expect(controller.getSnapshot().jobs).toEqual([newJob]);
    controller.dispose();
  });

  it("preserves the last good jobs when a later local read fails", async () => {
    let reads = 0;
    const bridge = makeBridge({
      list: vi.fn(async (): Promise<BackupJobsListResult> => {
        reads += 1;
        if (reads === 1) return { ok: true, jobs: [JOB] };
        throw new BridgeError("transport_error", "socket closed", true);
      }),
    });
    const controller = new BackupController(JOB.server_id, false, bridge, () => "operation-one");

    controller.start();
    await flushPromises();
    expect(controller.getSnapshot().jobs).toEqual([JOB]);

    await controller.reload();
    expect(controller.getSnapshot().jobs).toEqual([JOB]);
    expect(controller.getSnapshot().errors.jobs?.message).toContain("last confirmed state");
    controller.dispose();
  });

  it("keeps recovered status and history visible while surfacing store corruption", async () => {
    const recoveredRun = {
      run_id: "run-recovered",
      job_id: JOB.id,
      server_id: JOB.server_id,
      source: "scheduled" as const,
      status: "no_changes" as const,
      bytes_done: 0,
      bytes_total: 0,
      files_done: 0,
      files_total: 0,
      started_at_ms: 1_750_000_000_000,
      finished_at_ms: 1_750_000_000_100,
    };
    const bridge = makeBridge({
      status: vi.fn(async (): Promise<BackupStatusResult> => ({
        ok: true,
        status: STATUS,
        stale: true,
        recovery_error: "history store was quarantined",
      })),
      history: vi.fn(async (): Promise<BackupHistoryResult> => ({
        ok: true,
        runs: [recoveredRun],
        recovery_error: "one invalid line was quarantined",
      })),
    });
    const controller = new BackupController(JOB.server_id, false, bridge, () => "operation-one");

    controller.start();
    await flushPromises();

    expect(controller.getSnapshot().status).toEqual(STATUS);
    expect(controller.getSnapshot().statusStale).toBe(true);
    expect(controller.getSnapshot().errors.status).toMatchObject({ code: "store_corrupt", retryable: false });
    expect(controller.getSnapshot().histories[JOB.id]?.runs).toEqual([recoveredRun]);
    expect(controller.getSnapshot().histories[JOB.id]?.error).toMatchObject({ code: "store_corrupt", retryable: false });
    controller.dispose();
  });

  it("stops the refresh timer on dispose", async () => {
    const poll = vi.fn(async (): Promise<BackupOperation> => ({
      ...DONE_REFRESH,
      state: "running",
      finished_at_ms: undefined,
    }));
    const bridge = makeBridge({ operationPoll: poll });
    const controller = new BackupController(JOB.server_id, true, bridge, () => "refresh-one");

    await controller.reload();
    await controller.refresh();
    expect(poll).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(700);
    expect(poll).toHaveBeenCalledTimes(2);
    controller.dispose();
    await vi.advanceTimersByTimeAsync(5_000);
    expect(poll).toHaveBeenCalledTimes(2);
  });

  it("keeps the caller-owned run cursor and stops polling after terminal completion", async () => {
    const cursors: Array<number | undefined> = [];
    const snapshots: BackupPollResult[] = [
      {
        ok: true,
        run_id: "run-one",
        status: "running",
        phase: "running",
        bytes_done: 5,
        bytes_total: 10,
        files_done: 0,
        files_total: 1,
        speed_bps: 5,
        eta_sec: 1,
        started_at_ms: 1_750_000_000_000,
        log_cursor: 8,
        log_delta: "chunk-one",
        dropped: 0,
        cleanup_state: "pending",
      },
      {
        ok: true,
        run_id: "run-one",
        status: "no_changes",
        phase: "finished",
        bytes_done: 5,
        bytes_total: 10,
        files_done: 0,
        files_total: 1,
        speed_bps: 0,
        eta_sec: 0,
        started_at_ms: 1_750_000_000_000,
        finished_at_ms: 1_750_000_000_900,
        log_cursor: 17,
        log_delta: "chunk-two",
        dropped: 0,
        cleanup_state: "complete",
      },
    ];
    const poll = vi.fn(async ({ log_cursor }: { run_id: string; log_cursor?: number }) => {
      cursors.push(log_cursor);
      const next = snapshots.shift();
      if (next === undefined) throw new Error("unexpected extra poll");
      return next;
    });
    const history = vi.fn(async () => EMPTY_HISTORY);
    const bridge = makeBridge({ poll, history });
    const controller = new BackupController(JOB.server_id, true, bridge, () => "operation-one");

    await controller.beginRun(JOB);
    await flushPromises();
    expect(cursors).toEqual([0]);

    await vi.advanceTimersByTimeAsync(700);
    await flushPromises();
    expect(cursors).toEqual([0, 8]);
    expect(controller.getSnapshot().run?.log).toBe("chunk-onechunk-two");
    expect(controller.getSnapshot().run?.active).toBe(false);

    const callsAtTerminal = poll.mock.calls.length;
    await vi.advanceTimersByTimeAsync(5_000);
    expect(poll).toHaveBeenCalledTimes(callsAtTerminal);
    expect(history).toHaveBeenCalledTimes(1);
    controller.dispose();
  });

  it("retries a retryable refresh poll error and then settles", async () => {
    let attempts = 0;
    const poll = vi.fn(async (): Promise<BackupOperation> => {
      attempts += 1;
      if (attempts === 1) throw new BridgeError("transport_error", "connection reset", true);
      return DONE_REFRESH;
    });
    const controller = new BackupController(JOB.server_id, true, makeBridge({ operationPoll: poll }), () => "refresh-one");

    await controller.refresh();
    expect(controller.getSnapshot().refreshing).toBe(true);
    await vi.advanceTimersByTimeAsync(1_200);
    await flushPromises();

    expect(poll).toHaveBeenCalledTimes(2);
    expect(controller.getSnapshot().refreshing).toBe(false);
    controller.dispose();
  });

  it("stops refresh polling after a non-retryable error", async () => {
    const poll = vi.fn(async (): Promise<BackupOperation> => {
      throw new BridgeError("invalid_payload", "bad operation", false);
    });
    const controller = new BackupController(JOB.server_id, true, makeBridge({ operationPoll: poll }), () => "refresh-one");

    await controller.refresh();
    expect(poll).toHaveBeenCalledTimes(1);
    expect(controller.getSnapshot().refreshing).toBe(false);
    expect(controller.getSnapshot().errors.refresh?.retryable).toBe(false);

    await vi.advanceTimersByTimeAsync(5_000);
    expect(poll).toHaveBeenCalledTimes(1);
    controller.dispose();
  });

  it("settles a mutation after a non-retryable poll error", async () => {
    const poll = vi.fn(async (): Promise<BackupOperation> => {
      throw new BridgeError("not_found", "operation disappeared", false);
    });
    const controller = new BackupController(JOB.server_id, true, makeBridge({ operationPoll: poll }), () => "save-one");

    const task = await controller.beginSave({ planId: "plan-one", approvedRemoteSecret: false });
    const settled = task.completion.catch((error: unknown) => error);
    await flushPromises();

    expect(await settled).toBeInstanceOf(BridgeError);
    expect(controller.getSnapshot().errors.mutation?.retryable).toBe(false);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(poll).toHaveBeenCalledTimes(1);
    controller.dispose();
  });

  it("re-admits retained partial cleanup through operationCancel with fresh credentials", async () => {
    const partial: BackupOperation = {
      ok: true,
      operation_id: "save-one",
      kind: "save",
      state: "partial",
      steps: [{
        id: "cleanup",
        state: "failed",
        error: { ok: false, code: "cleanup_failed", error: "temporary config remains", retryable: true, detail: { path: "/tmp/oars.conf" } },
      }],
      started_at_ms: 1_750_000_000_000,
      finished_at_ms: 1_750_000_000_100,
      result: {
        cleanup: "required",
        retry_action: "operationCancel",
        needs_credentials: true,
        job_id: JOB.id,
      },
      error: { ok: false, code: "cleanup_failed", error: "temporary config remains", retryable: true, detail: { path: "/tmp/oars.conf" } },
    };
    const cleanupDone: BackupOperation = {
      ok: true,
      operation_id: "save-one",
      kind: "cleanup",
      state: "done",
      steps: [{ id: "cleanup", state: "done" }, { id: "cleanup_verify", state: "done" }],
      started_at_ms: 1_750_000_000_200,
      finished_at_ms: 1_750_000_000_300,
      result: { cleanup: "complete" },
    };
    const snapshots = [partial, cleanupDone];
    const operationPoll = vi.fn(async () => {
      const next = snapshots.shift();
      if (next === undefined) throw new Error("unexpected operation poll");
      return next;
    });
    const operationCancel = vi.fn(async () => ({ ok: true as const }));
    const controller = new BackupController(JOB.server_id, true, makeBridge({ operationPoll, operationCancel }), () => "save-one");

    const first = await controller.beginSave({ planId: "plan-one", approvedRemoteSecret: false });
    await expect(first.completion).rejects.toThrow();
    const credentials = { access_key: "AKIA_FRESH", secret_key: "fresh-secret" };
    const retry = await controller.retryCleanup("save-one", credentials);
    await expect(retry.completion).resolves.toMatchObject({ kind: "cleanup", state: "done" });

    expect(operationCancel).toHaveBeenCalledWith({ operation_id: "save-one", credentials });
    controller.dispose();
  });

  it("marks a run inactive and preserves its focused error after a non-retryable poll error", async () => {
    const poll = vi.fn(async (): Promise<BackupPollResult> => {
      throw new BridgeError("not_found", "run disappeared", false, { path: "/tmp/run-state" });
    });
    const controller = new BackupController(JOB.server_id, true, makeBridge({ poll }), () => "run-operation-one");

    await controller.beginRun(JOB);
    await flushPromises();

    expect(controller.getSnapshot().run?.active).toBe(false);
    expect(controller.getSnapshot().run?.error?.code).toBe("not_found");
    expect(controller.getSnapshot().run?.error?.detail?.path).toBe("/tmp/run-state");
    await vi.advanceTimersByTimeAsync(5_000);
    expect(poll).toHaveBeenCalledTimes(1);
    controller.dispose();
  });
});

describe("backup error and credential parsing", () => {
  it("maps typed bridge errors to human-first copy without leading with a code", () => {
    const mapped = humanizeBackupError(new BridgeError("conflict", "revision mismatch", true), "mutation");
    expect(mapped.code).toBe("conflict");
    expect(mapped.message).toBe("This backup job changed elsewhere. Refresh it before trying again.");
    expect(mapped.message.startsWith("conflict")).toBe(false);
  });

  it("accepts only complete production credential payloads", () => {
    expect(parseBackupCredentials('{"access_key":"AKIA","secret_key":"secret"}')).toEqual({ access_key: "AKIA", secret_key: "secret" });
    expect(() => parseBackupCredentials('{"access_key":"AKIA"}')).toThrow(/incomplete/i);
    expect(() => parseBackupCredentials("not-json")).toThrow(/unreadable/i);
  });
});
