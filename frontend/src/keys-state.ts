// Pure state machinery for the per-server SSH Management tab (spec 08).
// No React, no direct bridge imports: the snapshot and job controllers take
// their transport and timers as injected dependencies so every rule here is
// unit-tested in keys-state.test.ts.

import type {
  SshAccountRef,
  SshJobPollResponse,
  SshJobResult,
  SshJobState,
  SshJobStepState,
  SshKeyEntry,
  SshPolicyLevel,
  SshRole,
  SshRolePolicyState,
  SshSnapshotPollResponse,
  SshSource,
  SshSourceStatus,
} from "./types";

export interface KeysTransport {
  snapshot(serverId: string, account: SshAccountRef): Promise<{ ok: boolean; snapshot_id: string }>;
  snapshotPoll(snapshotId: string): Promise<SshSnapshotPollResponse>;
  jobPoll(jobId: string): Promise<SshJobPollResponse>;
  jobCancel(jobId: string): Promise<unknown>;
}

export interface KeysTimers {
  set(cb: () => void, ms: number): number;
  clear(handle: number): void;
}

const defaultTimers: KeysTimers = {
  set: (cb, ms) => window.setTimeout(cb, ms),
  clear: (handle) => window.clearTimeout(handle),
};

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// The tab is not handed the app-level connection state, so a lost session is
// recognized from the bridge error text (see the KeysTab final-report note).
export function isDisconnectError(error: unknown): boolean {
  return /not.?connected|no (active )?(ssh )?session|connection (lost|closed|refused|failed)|disconnect/i.test(
    errorMessage(error),
  );
}

// Snapshot controller: exactly one poller. A refresh never discards the last
// completed snapshot; only a server or account change replaces the context.

export interface SnapshotView {
  serverId: string | null;
  account: SshAccountRef;
  polling: boolean;
  snapshotId: string | null;
  latest: SshSnapshotPollResponse | null;
  lastCompleted: SshSnapshotPollResponse | null;
  disconnected: boolean;
  error: string | null;
}

const idleSnapshotView: SnapshotView = {
  serverId: null,
  account: { kind: "connected" },
  polling: false,
  snapshotId: null,
  latest: null,
  lastCompleted: null,
  disconnected: false,
  error: null,
};

export class SshSnapshotController {
  private view: SnapshotView = idleSnapshotView;
  private generation = 0;
  private timer: number | null = null;
  private listener: (view: SnapshotView) => void = () => undefined;

  constructor(
    private transport: KeysTransport,
    private pollMs = 500,
    private timers: KeysTimers = defaultTimers,
  ) {}

  subscribe(listener: (view: SnapshotView) => void): void {
    this.listener = listener;
  }

  get current(): SnapshotView {
    return this.view;
  }

  private emit(): void {
    this.listener({ ...this.view });
  }

  private clearTimer(): void {
    if (this.timer !== null) this.timers.clear(this.timer);
    this.timer = null;
  }

  start(serverId: string, account: SshAccountRef): void {
    this.clearTimer();
    const generation = ++this.generation;
    const contextChanged =
      this.view.serverId !== serverId ||
      this.view.account.kind !== account.kind ||
      this.view.account.name !== account.name;
    this.view = {
      serverId,
      account,
      polling: true,
      snapshotId: null,
      latest: null,
      lastCompleted: contextChanged ? null : this.view.lastCompleted,
      disconnected: false,
      error: null,
    };
    this.emit();
    void this.begin(generation);
  }

  refresh(): void {
    if (this.view.serverId) this.start(this.view.serverId, this.view.account);
  }

  stop(): void {
    this.generation += 1;
    this.clearTimer();
    if (this.view.polling) {
      this.view = { ...this.view, polling: false };
      this.emit();
    }
  }

  private async begin(generation: number): Promise<void> {
    if (!this.view.serverId) return;
    try {
      const started = await this.transport.snapshot(this.view.serverId, this.view.account);
      if (this.generation !== generation) return;
      this.view = { ...this.view, snapshotId: started.snapshot_id };
      this.emit();
      await this.poll(generation);
    } catch (failure) {
      if (this.generation !== generation) return;
      this.view = {
        ...this.view,
        polling: false,
        disconnected: isDisconnectError(failure),
        error: errorMessage(failure),
      };
      this.emit();
    }
  }

  private async poll(generation: number): Promise<void> {
    const snapshotId = this.view.snapshotId;
    if (!snapshotId) return;
    try {
      const result = await this.transport.snapshotPoll(snapshotId);
      if (this.generation !== generation) return;
      const completed = result.state === "done" || result.state === "partial";
      this.view = {
        ...this.view,
        latest: result,
        lastCompleted: completed ? result : this.view.lastCompleted,
        polling: !completed && result.state !== "canceled",
        disconnected: false,
        error: null,
      };
      this.emit();
      if (this.view.polling) {
        this.timer = this.timers.set(() => void this.poll(generation), this.pollMs);
      }
    } catch (failure) {
      if (this.generation !== generation) return;
      this.view = {
        ...this.view,
        polling: false,
        disconnected: isDisconnectError(failure),
        error: errorMessage(failure),
      };
      this.emit();
    }
  }
}

// Job controller: exactly one active job poller. Polling observes state
// only; it never starts the next mutation. A job in
// `waiting_for_verification` is stable until the user commits, so the poller
// rests there and `track` resumes it afterwards.

export interface JobView {
  jobId: string;
  label: string;
  polling: boolean;
  cancelRequested: boolean;
  pollError: string | null;
  result: SshJobPollResponse;
}

export function jobIsTerminal(state: SshJobState): boolean {
  return state === "done" || state === "partial" || state === "canceled";
}

export class SshJobController {
  private view: JobView | null = null;
  private generation = 0;
  private timer: number | null = null;
  private listener: (view: JobView | null) => void = () => undefined;

  constructor(
    private transport: KeysTransport,
    private pollMs = 500,
    private timers: KeysTimers = defaultTimers,
  ) {}

  onTerminal: (view: JobView) => void = () => undefined;
  onWaiting: (view: JobView) => void = () => undefined;

  subscribe(listener: (view: JobView | null) => void): void {
    this.listener = listener;
  }

  get current(): JobView | null {
    return this.view;
  }

  private emit(): void {
    this.listener(this.view ? { ...this.view } : null);
  }

  private clearTimer(): void {
    if (this.timer !== null) this.timers.clear(this.timer);
    this.timer = null;
  }

  track(jobId: string, label: string): void {
    this.clearTimer();
    const generation = ++this.generation;
    this.view = { jobId, label, polling: true, cancelRequested: false, pollError: null, result: { ok: true, state: "queued", steps: [] } };
    this.emit();
    void this.poll(generation);
  }

  dismiss(): void {
    this.generation += 1;
    this.clearTimer();
    this.view = null;
    this.emit();
  }

  async cancelActive(): Promise<void> {
    const active = this.view;
    if (!active || active.cancelRequested) return;
    this.view = { ...active, cancelRequested: true };
    this.emit();
    try {
      await this.transport.jobCancel(active.jobId);
      // Cancellation is cooperative. Keep polling until the backend reports
      // whether the operation actually stopped or completed first. A staged
      // rotation rests without a timer, so explicitly resume it here.
      if (this.view?.jobId === active.jobId && !this.view.polling) {
        this.view = { ...this.view, polling: true };
        this.emit();
        void this.poll(this.generation);
      }
    } catch {
      if (this.view?.jobId === active.jobId) {
        this.view = { ...this.view, cancelRequested: false };
        this.emit();
      }
    }
  }

  stop(): void {
    this.dismiss();
  }

  private async poll(generation: number): Promise<void> {
    const active = this.view;
    if (!active) return;
    try {
      const result = await this.transport.jobPoll(active.jobId);
      if (this.generation !== generation || !this.view) return;
      const waiting = result.state === "waiting_for_verification";
      this.view = {
        ...this.view,
        polling: !jobIsTerminal(result.state) && !waiting,
        cancelRequested: jobIsTerminal(result.state) ? false : this.view.cancelRequested,
        pollError: null,
        result,
      };
      this.emit();
      if (jobIsTerminal(result.state)) {
        this.onTerminal({ ...this.view });
      } else if (waiting) {
        this.onWaiting({ ...this.view });
      } else {
        this.timer = this.timers.set(() => void this.poll(generation), this.pollMs);
      }
    } catch (failure) {
      if (this.generation !== generation || !this.view) return;
      this.view = {
        ...this.view,
        polling: true,
        pollError: errorMessage(failure),
      };
      this.emit();
      this.timer = this.timers.set(() => void this.poll(generation), this.pollMs);
    }
  }
}

// Pure view helpers.

export function newOperationId(): string {
  const cryptoApi = globalThis.crypto;
  if (typeof cryptoApi?.randomUUID === "function") return cryptoApi.randomUUID();
  return `op-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function accountLabel(account: SshAccountRef): string {
  if (account.kind === "managed_role") return account.name ? `Role ${account.name}` : "Managed role";
  return account.name ? `${account.name} (connected login)` : "Connected login";
}

export function accountKey(account: SshAccountRef): string {
  return account.kind === "managed_role" ? `role:${account.name ?? ""}` : "connected";
}

// Accounts the selector may offer: the connected login plus verified
// Oars-managed roles. Unverified or drifted roles fail closed (spec 08 §7).
export function selectableAccounts(roles: SshRole[]): SshAccountRef[] {
  const verified = roles
    .filter((role) => role.policy_state === "verified")
    .map((role): SshAccountRef => ({ kind: "managed_role", name: role.name }));
  return [{ kind: "connected" }, ...verified];
}

export function staticSources(snapshot: SshSnapshotPollResponse): SshSource[] {
  return snapshot.sources.filter((source) => source.kind === "static");
}

// Mutations are allowed only against an exact static source that was read
// (`readable`) or can be created safely (`missing`). Everything else blocks.
export function canMutateSource(source: SshSource): boolean {
  return source.kind === "static" && (source.status === "readable" || source.status === "missing");
}

export function sourceNeedsAttention(source: SshSource): boolean {
  return source.kind !== "static" || (source.status !== "readable" && source.status !== "missing");
}

export function sourceStatusLabel(source: SshSource): string {
  if (source.kind === "dynamic") return "Dynamic source";
  if (source.kind === "certificate") return "Certificate source";
  const labels: Record<SshSourceStatus, string> = {
    missing: "Not created yet",
    readable: "Readable",
    denied: "Permission denied",
    timeout: "Read timed out",
    too_large: "File too large",
    transport_error: "Transport error",
    parse_error: "Parse error",
  };
  return labels[source.status];
}

export interface AttentionItem {
  id: string;
  title: string;
  detail: string;
}

// Partial-view attention list: unreadable/dynamic/certificate sources,
// malformed rows, drifted roles, and backend warnings. A partial view never
// reports "no keys" for a source that was not read.
export function attentionItems(snapshot: SshSnapshotPollResponse): AttentionItem[] {
  const items: AttentionItem[] = [];
  for (const source of snapshot.sources) {
    if (!sourceNeedsAttention(source)) continue;
    const label = sourceStatusLabel(source);
    items.push({
      id: `source:${source.path}`,
      title: source.path,
      detail:
        source.error ??
        (source.kind === "static"
          ? `${label}. Keys in this file are unknown and no mutation is allowed against it.`
          : `${label}. Effective policy includes this source, but Oars cannot inventory or edit it.`),
    });
  }
  for (const key of snapshot.keys) {
    if (key.parsed) continue;
    items.push({
      id: `malformed:${key.source_path}:${key.line_index}`,
      title: `${key.source_path}, line ${key.line_index + 1}`,
      detail: key.error ?? "This row could not be parsed and cannot be changed safely.",
    });
  }
  for (const role of snapshot.roles) {
    if (role.policy_state === "verified") continue;
    items.push({
      id: `role:${role.name}`,
      title: `Role ${role.name}`,
      detail: `Policy is ${rolePolicyLabel(role.policy_state).toLowerCase()}; new keys cannot be installed until the policy is repaired.`,
    });
  }
  snapshot.warnings.forEach((warning, index) => {
    items.push({ id: `warning:${index}`, title: "Snapshot warning", detail: warning });
  });
  return items;
}

export function keyFingerprint(key: SshKeyEntry): string {
  return key.fingerprint_sha256 ?? "Fingerprint unavailable";
}

// Idempotent add detection: the same fingerprint in the exact account source.
export function duplicateFingerprint(keys: SshKeyEntry[], sourcePath: string, fingerprint: string): SshKeyEntry | null {
  return keys.find((key) => key.parsed && key.source_path === sourcePath && key.fingerprint_sha256 === fingerprint) ?? null;
}

// Typed-fingerprint rule for revoke: a role key, or the connected account's
// last observed direct key, needs the full fingerprint typed.
export function revokeNeedsConfirmation(key: SshKeyEntry, account: SshAccountRef, accountKeys: SshKeyEntry[]): boolean {
  if (account.kind === "managed_role") return true;
  const directKeys = accountKeys.filter((entry) => entry.parsed && entry.policy_assessment?.level !== "role_forced");
  return directKeys.length <= 1 && directKeys.some((entry) => entry.line_hash === key.line_hash);
}

export function policyLabel(level: SshPolicyLevel): string {
  const labels: Record<SshPolicyLevel, string> = {
    standard: "Standard login",
    restricted: "Restricted",
    role_forced: "Role-forced",
    weak: "Weak",
  };
  return labels[level];
}

export function rolePolicyLabel(state: SshRolePolicyState): string {
  const labels: Record<SshRolePolicyState, string> = {
    verified: "Verified",
    missing: "Policy missing",
    corrupt: "Policy corrupt",
    stale: "Policy stale",
    unreadable: "Policy unreadable",
    drifted: "Drifted",
  };
  return labels[state];
}

export function roleKindLabel(role: SshRole): string {
  return role.kind === "read_only_sftp" ? "Read-only SFTP" : "Standard SSH";
}

export function jobStateLabel(state: SshJobState): string {
  const labels: Record<SshJobState, string> = {
    queued: "Queued",
    running: "Running",
    waiting_for_verification: "Waiting for verification",
    done: "Done",
    partial: "Finished with problems",
    canceled: "Canceled",
  };
  return labels[state];
}

export function stepStateLabel(state: SshJobStepState): string {
  const labels: Record<SshJobStepState, string> = {
    queued: "Queued",
    running: "Running",
    waiting: "Waiting",
    done: "Done",
    conflict: "Conflict",
    error: "Error",
    canceled: "Canceled",
  };
  return labels[state];
}

export function snapshotTimeText(finishedAtMs: number | undefined): string {
  if (!finishedAtMs) return "no completed snapshot";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(finishedAtMs));
}

export function formatMode(mode: number | undefined): string | null {
  if (mode === undefined) return null;
  return (mode & 0o7777).toString(8).padStart(4, "0");
}

export function sourceByPath(snapshot: SshSnapshotPollResponse, path: string): SshSource | null {
  return snapshot.sources.find((source) => source.path === path) ?? null;
}

// Keychain writes happen only when the user opted in, a passphrase exists,
// and the job result named an account. The write itself can still fail
// (denied permission); the caller reports that failure without losing the
// generated key.
export interface KeychainPlan {
  store: boolean;
  account: string | null;
  secret: string | null;
}

export function keychainStoragePlan(remember: boolean, passphrase: string, result: SshJobResult | undefined): KeychainPlan {
  if (!remember || passphrase.length === 0 || !result?.keychain_account) {
    return { store: false, account: null, secret: null };
  }
  return { store: true, account: result.keychain_account, secret: passphrase };
}

// Human step labels for the job card (DESIGN.md §2: human language first).
const stepLabels: Record<string, string> = {
  check_source: "Check the source file",
  write: "Write the source file",
  verify: "Verify the result",
  stage: "Stage the new key",
  verify_staged: "Verify the staged file",
  verify_access: "Verify the new key signs in",
  remove_old: "Remove the old key",
  probe_privilege: "Check administrator rights",
  probe_capability: "Check read-only SFTP support",
  create_account: "Create the account",
  install_key: "Install the first key",
  write_policy: "Write the role policy",
  delete_account: "Delete the account",
  read_manifest: "Read the deploy-key manifest",
  generate: "Generate the key pair",
  write_manifest: "Write the deploy-key manifest",
  delete_files: "Delete the key files",
};

export function jobStepLabel(id: string): string {
  return stepLabels[id] ?? id.replace(/_/g, " ");
}

// Role changes need administrator rights from the snapshot.
export function canPlanRoles(snapshot: SshSnapshotPollResponse): boolean {
  return snapshot.capabilities.privilege !== "none";
}

export function roleNeedsRepair(role: SshRole): boolean {
  return role.policy_state !== "verified";
}
