import { describe, expect, it } from "vitest";
import {
  SshJobController,
  SshSnapshotController,
  accountKey,
  accountLabel,
  attentionItems,
  canMutateSource,
  canPlanRoles,
  duplicateFingerprint,
  formatMode,
  isDisconnectError,
  jobIsTerminal,
  jobStateLabel,
  jobStepLabel,
  keyFingerprint,
  keychainStoragePlan,
  newOperationId,
  policyLabel,
  revokeNeedsConfirmation,
  roleKindLabel,
  roleNeedsRepair,
  rolePolicyLabel,
  selectableAccounts,
  snapshotTimeText,
  sourceByPath,
  sourceStatusLabel,
  staticSources,
  stepStateLabel,
  type KeysTimers,
  type KeysTransport,
} from "./keys-state";
import type { SshJobPollResponse, SshKeyEntry, SshRole, SshSnapshotPollResponse, SshSource } from "./types";

function fakeTimers() {
  const pending = new Map<number, () => void>();
  let next = 1;
  const timers: KeysTimers = {
    set: (cb) => {
      const handle = next++;
      pending.set(handle, cb);
      return handle;
    },
    clear: (handle) => {
      pending.delete(handle);
    },
  };
  return {
    pending,
    timers,
    runNext() {
      const first = pending.entries().next().value as [number, () => void] | undefined;
      if (!first) return false;
      pending.delete(first[0]);
      first[1]();
      return true;
    },
  };
}

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

function makeSource(overrides: Partial<SshSource> = {}): SshSource {
  return {
    path: "/home/deploy/.ssh/authorized_keys",
    kind: "static",
    status: "readable",
    file_sha256: "a".repeat(64),
    mode: 0o600,
    owner: "deploy",
    ...overrides,
  };
}

function makeKey(overrides: Partial<SshKeyEntry> = {}): SshKeyEntry {
  return {
    source_path: "/home/deploy/.ssh/authorized_keys",
    line_index: 0,
    line_hash: "b".repeat(64),
    parsed: true,
    options: "",
    type: "ssh-ed25519",
    key: "AAAA",
    comment: "ada@workstation",
    fingerprint_sha256: "SHA256:aaa",
    bits: 256,
    policy_assessment: { level: "standard", detail: "No key-level restrictions" },
    ...overrides,
  };
}

function makeRole(overrides: Partial<SshRole> = {}): SshRole {
  return { name: "reports", kind: "read_only_sftp", policy_state: "verified", key_fingerprints: [], ...overrides };
}

function makeSnapshot(overrides: Partial<SshSnapshotPollResponse> = {}): SshSnapshotPollResponse {
  return {
    ok: true,
    state: "done",
    server_id: "prod-api",
    account: { kind: "connected" },
    scope: "effective_policy",
    created_at_ms: 1000,
    finished_at_ms: 2000,
    coverage: "complete",
    capabilities: { privilege: "root", sftp_read_only: true },
    sources: [makeSource()],
    keys: [makeKey()],
    roles: [],
    warnings: [],
    ...overrides,
    deploy_keys: overrides.deploy_keys ?? [],
  };
}

describe("disconnect detection", () => {
  it("recognizes connection-lost and disconnect messages", () => {
    expect(isDisconnectError(new Error("ssh: connection lost"))).toBe(true);
    expect(isDisconnectError(new Error("no active session"))).toBe(true);
    expect(isDisconnectError(new Error("not connected to server"))).toBe(true);
    expect(isDisconnectError(new Error("file not found"))).toBe(false);
  });
});

describe("SshSnapshotController", () => {
  it("keeps the last completed snapshot while polling a refresh", async () => {
    const { timers } = fakeTimers();
    let pollCount = 0;
    const transport: KeysTransport = {
      snapshot: async () => ({ ok: true, snapshot_id: "snap-1" }),
      snapshotPoll: async () => {
        pollCount++;
        if (pollCount === 1) {
          return makeSnapshot({ state: "done", finished_at_ms: 2000 });
        }
        return makeSnapshot({ state: "running", finished_at_ms: undefined });
      },
      jobPoll: async () => ({ ok: true, state: "done", finished: true, steps: [] } as any),
      jobCancel: async () => ({ ok: true }),
    };

    const ctrl = new SshSnapshotController(transport, 100, timers);
    await ctrl.start("prod-api", { kind: "connected" });
    await flush();

    expect(ctrl.current.lastCompleted?.finished_at_ms).toBe(2000);

    // Refresh
    await ctrl.refresh();
    await flush();

    expect(ctrl.current.polling).toBe(true);
    expect(ctrl.current.lastCompleted?.finished_at_ms).toBe(2000);

    ctrl.stop();
  });

  it("handles poll error by capturing error state and disconnected status", async () => {
    const { timers } = fakeTimers();
    const transport: KeysTransport = {
      snapshot: async () => ({ ok: true, snapshot_id: "snap-err" }),
      snapshotPoll: async () => {
        throw new Error("not connected to server");
      },
      jobPoll: async () => ({ ok: true } as any),
      jobCancel: async () => ({ ok: true }),
    };

    const ctrl = new SshSnapshotController(transport, 100, timers);
    await ctrl.start("prod-api", { kind: "connected" });
    await flush();

    expect(ctrl.current.polling).toBe(false);
    expect(ctrl.current.disconnected).toBe(true);
    expect(ctrl.current.error).toBe("not connected to server");

    ctrl.stop();
  });
});

describe("SshJobController", () => {
  it("polls steps until terminal done state", async () => {
    const { timers } = fakeTimers();
    let stepCount = 0;
    const transport: KeysTransport = {
      snapshot: async () => ({ ok: true, snapshot_id: "s" }),
      snapshotPoll: async () => makeSnapshot(),
      jobPoll: async () => {
        stepCount++;
        if (stepCount === 1) {
          return {
            ok: true,
            job_id: "job-1",
            state: "running",
            finished: false,
            steps: [{ id: "check_source", state: "done" }],
          } as SshJobPollResponse;
        }
        return {
          ok: true,
          job_id: "job-1",
          state: "done",
          finished: true,
          steps: [{ id: "check_source", state: "done" }, { id: "write", state: "done" }],
        } as SshJobPollResponse;
      },
      jobCancel: async () => ({ ok: true }),
    };

    const ctrl = new SshJobController(transport, 100, timers);
    ctrl.track("job-1", "Job label");
    await flush();

    expect(ctrl.current?.result.state).toBe("running");
    expect(jobIsTerminal(ctrl.current?.result.state ?? "queued")).toBe(false);

    ctrl.dismiss();
    expect(ctrl.current).toBeNull();
  });

  it("keeps polling after a cooperative cancel request until the backend is terminal", async () => {
    const clock = fakeTimers();
    let polls = 0;
    let cancelCalls = 0;
    const transport: KeysTransport = {
      snapshot: async () => ({ ok: true, snapshot_id: "s" }),
      snapshotPoll: async () => makeSnapshot(),
      jobPoll: async () => {
        polls += 1;
        return {
          ok: true,
          state: polls === 1 ? "running" : "done",
          steps: [{ id: "write", state: "done" }],
        } as SshJobPollResponse;
      },
      jobCancel: async () => {
        cancelCalls += 1;
        return { ok: true };
      },
    };

    const ctrl = new SshJobController(transport, 100, clock.timers);
    ctrl.track("job-cancel", "Cancelable job");
    await flush();

    await ctrl.cancelActive();
    expect(cancelCalls).toBe(1);
    expect(ctrl.current?.cancelRequested).toBe(true);
    expect(ctrl.current?.result.state).toBe("running");
    expect(ctrl.current?.polling).toBe(true);

    expect(clock.runNext()).toBe(true);
    await flush();
    expect(ctrl.current?.result.state).toBe("done");
    expect(ctrl.current?.cancelRequested).toBe(false);
    expect(ctrl.current?.polling).toBe(false);
  });

  it("cancels a staged rotation and resumes polling for the terminal state", async () => {
    let canceled = false;
    const transport: KeysTransport = {
      snapshot: async () => ({ ok: true, snapshot_id: "s" }),
      snapshotPoll: async () => makeSnapshot(),
      jobPoll: async () => ({
        ok: true,
        state: canceled ? "canceled" : "waiting_for_verification",
        steps: [{ id: "verify_access", state: canceled ? "canceled" : "waiting" }],
      }),
      jobCancel: async () => {
        canceled = true;
        return { ok: true };
      },
    };

    const ctrl = new SshJobController(transport);
    ctrl.track("job-staged", "Staged rotation");
    await flush();
    expect(ctrl.current?.result.state).toBe("waiting_for_verification");
    expect(ctrl.current?.polling).toBe(false);

    await ctrl.cancelActive();
    await flush();
    expect(ctrl.current?.result.state).toBe("canceled");
    expect(ctrl.current?.polling).toBe(false);
  });

  it("keeps the last authoritative state and retries after a poll transport error", async () => {
    const clock = fakeTimers();
    let polls = 0;
    const transport: KeysTransport = {
      snapshot: async () => ({ ok: true, snapshot_id: "s" }),
      snapshotPoll: async () => makeSnapshot(),
      jobPoll: async () => {
        polls += 1;
        if (polls === 1) throw new Error("Job polling transport failed");
        return { ok: true, state: "done", steps: [{ id: "write", state: "done" }] };
      },
      jobCancel: async () => ({ ok: true }),
    };

    let terminalNotified = false;
    const ctrl = new SshJobController(transport, 100, clock.timers);
    ctrl.onTerminal = () => {
      terminalNotified = true;
    };
    ctrl.track("job-failed", "Job label");
    await flush();

    expect(ctrl.current?.result.state).toBe("queued");
    expect(ctrl.current?.pollError).toBe("Job polling transport failed");
    expect(ctrl.current?.polling).toBe(true);
    expect(terminalNotified).toBe(false);

    expect(clock.runNext()).toBe(true);
    await flush();
    expect(ctrl.current?.result.state).toBe("done");
    expect(ctrl.current?.pollError).toBeNull();
    expect(terminalNotified).toBe(true);

    ctrl.dismiss();
  });
});

describe("source and account selection", () => {
  it("distinguishes an unreadable source from a genuinely empty one", () => {
    const denied = makeSource({ status: "denied", file_sha256: undefined, error: "Permission denied" });
    const empty = makeSource({ file_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" });
    expect(canMutateSource(denied)).toBe(false);
    expect(canMutateSource(empty)).toBe(true);
    const items = attentionItems(makeSnapshot({ sources: [denied, empty], keys: [] }));
    expect(items).toHaveLength(1);
    expect(items[0]?.title).toBe(denied.path);
    expect(items[0]?.detail).toBe("Permission denied");
    const silent = attentionItems(makeSnapshot({ sources: [makeSource({ status: "timeout", file_sha256: undefined })], keys: [] }));
    expect(silent[0]?.detail).toContain("unknown");
  });

  it("treats a missing source as creatable and dynamic sources as read-only", () => {
    expect(canMutateSource(makeSource({ status: "missing" }))).toBe(true);
    expect(canMutateSource(makeSource({ kind: "dynamic" }))).toBe(false);
    expect(canMutateSource(makeSource({ kind: "certificate" }))).toBe(false);
    expect(staticSources(makeSnapshot({ sources: [makeSource(), makeSource({ kind: "dynamic", path: "/usr/bin/query" })] }))).toHaveLength(1);
    expect(sourceStatusLabel(makeSource({ status: "missing" }))).toBe("Not created yet");
    expect(sourceStatusLabel(makeSource({ status: "readable" }))).toBe("Readable");
    expect(sourceStatusLabel(makeSource({ status: "denied" }))).toBe("Permission denied");
    expect(sourceStatusLabel(makeSource({ status: "too_large" }))).toBe("File too large");
    expect(sourceStatusLabel(makeSource({ status: "transport_error" }))).toBe("Transport error");
    expect(sourceStatusLabel(makeSource({ status: "parse_error" }))).toBe("Parse error");
    expect(sourceStatusLabel(makeSource({ kind: "dynamic" }))).toBe("Dynamic source");
    expect(sourceStatusLabel(makeSource({ kind: "certificate" }))).toBe("Certificate source");
  });

  it("offers only verified roles as selectable accounts", () => {
    const roles = [makeRole({ name: "reports" }), makeRole({ name: "drifted", policy_state: "drifted" }), makeRole({ name: "backup", kind: "standard_ssh" })];
    const accounts = selectableAccounts(roles);
    expect(accounts.map(accountLabel)).toEqual(["Connected login", "Role reports", "Role backup"]);
    expect(accountKey({ kind: "managed_role", name: "reports" })).toBe("role:reports");
    expect(accountKey({ kind: "managed_role" })).toBe("role:");
    expect(accountKey({ kind: "connected" })).toBe("connected");
  });

  it("finds sources by exact path", () => {
    const snapshot = makeSnapshot();
    expect(sourceByPath(snapshot, "/home/deploy/.ssh/authorized_keys")?.status).toBe("readable");
    expect(sourceByPath(snapshot, "/etc/elsewhere")).toBeNull();
  });
});

describe("key inspection and mutation guards", () => {
  it("generates unique operation ids", () => {
    const op1 = newOperationId();
    const op2 = newOperationId();
    expect(op1).toBeTruthy();
    expect(op2).toBeTruthy();
    expect(op1).not.toBe(op2);
  });

  it("detects a duplicate by source and fingerprint, ignoring malformed rows", () => {
    const keys = [makeKey(), makeKey({ parsed: false, fingerprint_sha256: undefined, line_index: 1 })];
    expect(duplicateFingerprint(keys, "/home/deploy/.ssh/authorized_keys", "SHA256:aaa")?.line_index).toBe(0);
    expect(duplicateFingerprint(keys, "/home/other/.ssh/authorized_keys", "SHA256:aaa")).toBeNull();
    expect(duplicateFingerprint(keys, "/home/deploy/.ssh/authorized_keys", "SHA256:missing")).toBeNull();
  });

  it("extracts key fingerprint and handles missing fingerprint", () => {
    expect(keyFingerprint(makeKey({ fingerprint_sha256: "SHA256:key123" }))).toBe("SHA256:key123");
    expect(keyFingerprint(makeKey({ fingerprint_sha256: undefined }))).toBe("Fingerprint unavailable");
  });

  it("requires typed confirmation for role keys and for the last direct key", () => {
    const roleKey = makeKey({ policy_assessment: { level: "role_forced", detail: "Forced" } });
    expect(revokeNeedsConfirmation(roleKey, { kind: "managed_role", name: "reports" }, [roleKey])).toBe(true);
    const onlyKey = makeKey();
    expect(revokeNeedsConfirmation(onlyKey, { kind: "connected" }, [onlyKey])).toBe(true);
    const secondKey = makeKey({ line_index: 1, line_hash: "c".repeat(64) });
    expect(revokeNeedsConfirmation(onlyKey, { kind: "connected" }, [onlyKey, secondKey])).toBe(false);
  });
});

describe("remembered passphrases", () => {
  const result = { keychain_account: "localkey:SHA256:aaa", public_key: "ssh-ed25519 AAAA" };

  it("stores only when the user opted in and a passphrase exists", () => {
    expect(keychainStoragePlan(true, "pw", result)).toEqual({ store: true, account: "localkey:SHA256:aaa", secret: "pw" });
    expect(keychainStoragePlan(false, "pw", result).store).toBe(false);
    expect(keychainStoragePlan(true, "", result).store).toBe(false);
    expect(keychainStoragePlan(true, "pw", undefined).store).toBe(false);
    expect(keychainStoragePlan(true, "pw", { public_key: "x" }).store).toBe(false);
  });
});

describe("labels and human-readable formatting", () => {
  it("formats all policy labels", () => {
    expect(policyLabel("standard")).toBe("Standard login");
    expect(policyLabel("restricted")).toBe("Restricted");
    expect(policyLabel("role_forced")).toBe("Role-forced");
    expect(policyLabel("weak")).toBe("Weak");
  });

  it("formats all role policy labels and role kinds", () => {
    expect(rolePolicyLabel("verified")).toBe("Verified");
    expect(rolePolicyLabel("missing")).toBe("Policy missing");
    expect(rolePolicyLabel("corrupt")).toBe("Policy corrupt");
    expect(rolePolicyLabel("stale")).toBe("Policy stale");
    expect(rolePolicyLabel("unreadable")).toBe("Policy unreadable");
    expect(rolePolicyLabel("drifted")).toBe("Drifted");

    expect(roleKindLabel(makeRole({ kind: "read_only_sftp" }))).toBe("Read-only SFTP");
    expect(roleKindLabel(makeRole({ kind: "standard_ssh" }))).toBe("Standard SSH");
  });

  it("formats all job state labels and step state labels", () => {
    expect(jobStateLabel("queued")).toBe("Queued");
    expect(jobStateLabel("running")).toBe("Running");
    expect(jobStateLabel("waiting_for_verification")).toBe("Waiting for verification");
    expect(jobStateLabel("done")).toBe("Done");
    expect(jobStateLabel("partial")).toBe("Finished with problems");
    expect(jobStateLabel("canceled")).toBe("Canceled");

    expect(stepStateLabel("queued")).toBe("Queued");
    expect(stepStateLabel("running")).toBe("Running");
    expect(stepStateLabel("waiting")).toBe("Waiting");
    expect(stepStateLabel("done")).toBe("Done");
    expect(stepStateLabel("conflict")).toBe("Conflict");
    expect(stepStateLabel("error")).toBe("Error");
    expect(stepStateLabel("canceled")).toBe("Canceled");
  });

  it("formats snapshot timestamp text", () => {
    expect(snapshotTimeText(undefined)).toBe("no completed snapshot");
    expect(snapshotTimeText(0)).toBe("no completed snapshot");
    expect(snapshotTimeText(1700000000000)).toBeTruthy();
  });
});

describe("role policy and attention items", () => {
  it("gates role changes on administrator rights", () => {
    expect(canPlanRoles(makeSnapshot())).toBe(true);
    expect(canPlanRoles(makeSnapshot({ capabilities: { privilege: "none", sftp_read_only: false } }))).toBe(false);
  });

  it("flags drifted roles and snapshot warnings in attention items", () => {
    const role = makeRole({ policy_state: "drifted" });
    expect(roleNeedsRepair(role)).toBe(true);
    expect(selectableAccounts([role])).toHaveLength(1);
    const snap = makeSnapshot({ roles: [role], keys: [makeKey({ parsed: false, line_index: 2 })], warnings: ["High CPU on server"] });
    const items = attentionItems(snap);
    expect(items.some((item) => item.id === "role:reports")).toBe(true);
    expect(items.some((item) => item.id === "warning:0")).toBe(true);
    expect(items.some((item) => item.id.startsWith("malformed:"))).toBe(true);
  });
});

describe("job presentation", () => {
  it("maps machine step ids to human labels", () => {
    expect(jobStepLabel("check_source")).toBe("Check the source file");
    expect(jobStepLabel("verify_access")).toBe("Verify the new key signs in");
    expect(jobStepLabel("delete_files")).toBe("Delete the key files");
    expect(jobStepLabel("custom_step")).toBe("custom step");
  });

  it("formats file modes in octal", () => {
    expect(formatMode(0o600)).toBe("0600");
    expect(formatMode(undefined)).toBeNull();
  });
});
